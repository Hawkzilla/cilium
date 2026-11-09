// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include "common.h"
#include "pktgen.h"

#define ENABLE_IPV4
#define ENABLE_NODEPORT
#define ENABLE_HOST_ROUTING

#define CLIENT_IP v4_ext_one
#define CLIENT_PORT __bpf_htons(12345)
#define VIP v4_svc_one
#define NODEPORT __bpf_htons(30900)
#define BACKEND_IP v4_pod_one
#define BACKEND_PORT __bpf_htons(9090)
#define NODE_IFINDEX 24
#define POD_IFINDEX 25

/* Only the post-RevDNAT source address selects the node interface. */
#define fib_lookup mock_fib_lookup
long mock_fib_lookup(__maybe_unused struct __ctx_buff *ctx,
		    struct bpf_fib_lookup *params, __maybe_unused int plen,
		    __maybe_unused __u32 flags)
{
	if (!params)
		return BPF_FIB_LKUP_RET_BLACKHOLE;
	params->ifindex = params->ipv4_src == VIP ? NODE_IFINDEX : POD_IFINDEX;
	__bpf_memcpy_builtin(params->smac, (__u8 *)mac_three, ETH_ALEN);
	__bpf_memcpy_builtin(params->dmac, (__u8 *)mac_one, ETH_ALEN);
	return BPF_FIB_LKUP_RET_SUCCESS;
}

#define ctx_redirect mock_ctx_redirect
static __always_inline int
mock_ctx_redirect(const struct __sk_buff *ctx, int ifindex,
		  __u32 flags __maybe_unused)
{
	/* A local NodePort reply must leave via the node, before VLAN tagging. */
	if ((ifindex != NODE_IFINDEX && ifindex != POD_IFINDEX) || ctx->vlan_present)
		return CTX_ACT_DROP;
	return CTX_ACT_REDIRECT;
}

#include "lib/bpf_lxc.h"
#include "lib/lb.h"
#include "lib/policy.h"
#include "lib/clear.h"

ASSIGN_CONFIG(union v4addr, endpoint_ipv4, { .be32 = BACKEND_IP })

static __always_inline int build_packet(struct __ctx_buff *ctx, bool reply)
{
	struct pktgen builder;
	struct tcphdr *tcp;

	pktgen__init(&builder, ctx);
	tcp = pktgen__push_ipv4_tcp_packet(&builder, (__u8 *)mac_one,
					  (__u8 *)mac_three,
					  reply ? BACKEND_IP : CLIENT_IP,
					  reply ? CLIENT_IP : BACKEND_IP,
					  reply ? BACKEND_PORT : CLIENT_PORT,
					  reply ? CLIENT_PORT : BACKEND_PORT);
	if (!tcp)
		return TEST_ERROR;
	tcp->syn = 1;
	tcp->ack = reply;
	pktgen__finish(&builder);
	return 0;
}

/* Simulate a request already DNATed by nodeport_lb4 to a local backend. */
PKTGEN("tc", "01_raptor_nodeport_request")
int raptor_nodeport_request_pktgen(struct __ctx_buff *ctx)
{
	return build_packet(ctx, false);
}

SETUP("tc", "01_raptor_nodeport_request")
int raptor_nodeport_request_setup(struct __ctx_buff *ctx)
{
	struct ipv4_ct_tuple tuple = {
		.saddr = BACKEND_IP,
		.daddr = CLIENT_IP,
		.sport = CLIENT_PORT,
		.dport = BACKEND_PORT,
		.nexthdr = IPPROTO_TCP,
		.flags = TUPLE_F_OUT,
	};
	struct ct_state state = { .node_port = 1, .rev_nat_index = 22 };
	__s8 ext_err = 0;

	clear_map(&cilium_ct4_global);
	lb_v4_add_nodeport_service(VIP, NODEPORT, IPPROTO_TCP, 1, 22, 0);
	if (ct_create4(get_ct_map4(&tuple), NULL, &tuple, ctx, CT_EGRESS,
		       &state, &ext_err) < 0)
		return TEST_ERROR;
	policy_add_ingress_allow_all_entry();
	ctx_store_meta(ctx, CB_SRC_LABEL, WORLD_ID);
	return pod_receive_packet(ctx);
}

CHECK("tc", "01_raptor_nodeport_request")
int raptor_nodeport_request_check(const struct __ctx_buff *ctx)
{
	struct ipv4_ct_tuple tuple = {
		.saddr = BACKEND_IP,
		.daddr = CLIENT_IP,
		.sport = CLIENT_PORT,
		.dport = BACKEND_PORT,
		.nexthdr = IPPROTO_TCP,
		.flags = TUPLE_F_IN,
	};
	struct ct_entry *entry;
	void *data = (void *)(long)ctx_data(ctx);
	void *data_end = (void *)(long)ctx->data_end;

	test_init();
	if (data + sizeof(__u32) > data_end)
		test_fatal("missing status");
	assert(*(__u32 *)data == CTX_ACT_OK);
	entry = map_lookup_elem(get_ct_map4(&tuple), &tuple);
	if (!entry)
		test_fatal("missing ingress CT entry");
	assert(entry->node_port);
	test_finish();
}

/* A non-NodePort request must not gain the early-RevDNAT marker. */
PKTGEN("tc", "03_raptor_plain_request")
int raptor_plain_request_pktgen(struct __ctx_buff *ctx)
{
	return build_packet(ctx, false);
}

SETUP("tc", "03_raptor_plain_request")
int raptor_plain_request_setup(struct __ctx_buff *ctx)
{
	clear_map(&cilium_ct4_global);
	ctx_store_meta(ctx, CB_SRC_LABEL, WORLD_ID);
	return pod_receive_packet(ctx);
}

CHECK("tc", "03_raptor_plain_request")
int raptor_plain_request_check(const struct __ctx_buff *ctx)
{
	struct ipv4_ct_tuple tuple = {
		.saddr = BACKEND_IP,
		.daddr = CLIENT_IP,
		.sport = CLIENT_PORT,
		.dport = BACKEND_PORT,
		.nexthdr = IPPROTO_TCP,
		.flags = TUPLE_F_IN,
	};
	struct ct_entry *entry;
	void *data = (void *)(long)ctx_data(ctx);
	void *data_end = (void *)(long)ctx->data_end;

	test_init();
	if (data + sizeof(__u32) > data_end)
		test_fatal("missing status");
	assert(*(__u32 *)data == CTX_ACT_OK);
	entry = map_lookup_elem(get_ct_map4(&tuple), &tuple);
	if (!entry)
		test_fatal("missing ingress CT entry");
	assert(!entry->node_port);
	test_finish();
}

PKTGEN("tc", "02_raptor_nodeport_reply")
int raptor_nodeport_reply_pktgen(struct __ctx_buff *ctx)
{
	return build_packet(ctx, true);
}

SETUP("tc", "02_raptor_nodeport_reply")
int raptor_nodeport_reply_setup(struct __ctx_buff *ctx)
{
	return pod_send_packet(ctx);
}

CHECK("tc", "02_raptor_nodeport_reply")
int raptor_nodeport_reply_check(const struct __ctx_buff *ctx)
{
	void *data = (void *)(long)ctx_data(ctx);
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *eth = data + sizeof(__u32);
	struct iphdr *ip = (void *)(eth + 1);
	struct tcphdr *tcp = (void *)(ip + 1);

	test_init();
	if ((void *)(tcp + 1) > data_end)
		test_fatal("truncated reply");
	assert(*(__u32 *)data == CTX_ACT_REDIRECT);
	assert(ip->saddr == VIP);
	assert(ip->daddr == CLIENT_IP);
	assert(tcp->source == NODEPORT);
	assert(tcp->dest == CLIENT_PORT);
	assert(!ctx->vlan_present);
	test_finish();
}
