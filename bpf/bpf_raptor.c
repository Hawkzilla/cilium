// Copyright EasyStack. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License"). You may
// not use this file except in compliance with the License. A copy of the
// License is located at
//
// https://www.apache.org/licenses/LICENSE-2.0
//
// or in the "license" file accompanying this file. This file is distributed
// on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
// express or implied. See the License for the specific language governing
// permissions and limitations under the License.

#include <bpf/ctx/skb.h>
#include <linux/bpf.h>

#include "lib/common.h"
#include "lib/endian.h"
#include "lib/dbg.h"

#define TC_ACT_PIPE 3
#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86DD
#define ETH_ALEN 6
#define TC_ACT_OK 0
#define ETH_P_8021Q 0x8100


struct ip_mac_tag {
    __u8  mac[6];
    __u16 tag;
    int ifindex;
};

struct ipv6_key {
    __u8 addr[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, struct ip_mac_tag);
    __uint(max_entries, 256);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} raptor_ip_2_mac_map_v4 __section_maps_btf;

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct ipv6_key);
    __type(value, struct ip_mac_tag);
    __uint(max_entries, 256);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} raptor_ip_2_mac_map_v6 __section_maps_btf;

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 256);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} raptor_ip_2_gateway_map_v4 __section_maps_btf;


struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct ipv6_key);
    __type(value, struct ipv6_key);
    __uint(max_entries, 256);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} raptor_ip_2_gateway_map_v6 __section_maps_btf;


__section_entry
int raptor_from_trunk(struct __ctx_buff *skb)
{
    if (skb->vlan_present) {
        skb_vlan_pop(skb);
        ctx_change_type(skb, 0);
        return TC_ACT_PIPE;
    }

    return TC_ACT_PIPE;
}

__section_entry
int raptor_to_trunk(struct __ctx_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    struct iphdr *ipv4;
    struct ipv6hdr *ipv6;

    struct ip_mac_tag *src_mac_entry;
    struct ip_mac_tag *gw_mac_entry;

    __u32 *gw_v4_key;
    struct ipv6_key *gw_v6_key;

    __u32 src_ipv4;
    __u16 eth_proto;

    if ((void *)(eth + 1) > data_end)
        return TC_ACT_PIPE;

    eth_proto = bpf_ntohs(eth->h_proto);

    if (eth_proto == ETH_P_IP) {
        ipv4 = (void *)(eth + 1);
        if ((void *)(ipv4 + 1) > data_end)
            return TC_ACT_PIPE;

        src_ipv4 = bpf_ntohl(ipv4->saddr);

        src_mac_entry = map_lookup_elem(&raptor_ip_2_mac_map_v4, &src_ipv4);
        if (src_mac_entry) {
            if (skb->vlan_present)
                return TC_ACT_PIPE;

            __bpf_memcpy_builtin(eth->h_source, src_mac_entry->mac, ETH_ALEN);

            gw_v4_key = map_lookup_elem(&raptor_ip_2_gateway_map_v4, &src_ipv4);
            if (gw_v4_key) {
                gw_mac_entry = map_lookup_elem(&raptor_ip_2_mac_map_v4, gw_v4_key);
                if (gw_mac_entry) {
                    __bpf_memcpy_builtin(eth->h_dest, gw_mac_entry->mac, ETH_ALEN);
                    skb_vlan_push(skb, bpf_htons(ETH_P_8021Q), src_mac_entry->tag);
                }
            }
        }

        return TC_ACT_PIPE;
    }

    if (eth_proto == ETH_P_IPV6) {
        ipv6 = (void *)(eth + 1);
        if ((void *)(ipv6 + 1) > data_end)
            return TC_ACT_PIPE;

        src_mac_entry = map_lookup_elem(&raptor_ip_2_mac_map_v6, &ipv6->saddr);
        if (src_mac_entry) {
            if (skb->vlan_present)
                return TC_ACT_PIPE;

            __bpf_memcpy_builtin(eth->h_source, src_mac_entry->mac, ETH_ALEN);

            gw_v6_key = map_lookup_elem(&raptor_ip_2_gateway_map_v6, &ipv6->saddr);
            if (gw_v6_key) {
                gw_mac_entry = map_lookup_elem(&raptor_ip_2_mac_map_v6, gw_v6_key);
                if (gw_mac_entry) {
                    __bpf_memcpy_builtin(eth->h_dest, gw_mac_entry->mac, ETH_ALEN);
                }
                skb_vlan_push(skb, bpf_htons(ETH_P_8021Q), src_mac_entry->tag);
            }
        }

        return TC_ACT_PIPE;
    }

    return TC_ACT_PIPE;
}

BPF_LICENSE("Dual BSD/GPL");