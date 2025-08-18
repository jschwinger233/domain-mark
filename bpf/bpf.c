// +build ignore
// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)

#include "vmlinux.h"
#include <bpf_helpers.h>
#include <bpf_endian.h>

#define TC_ACT_OK   0

#define ETH_P_IP	bpf_htons(0x0800)
#define IPPROTO_UDP 17

#define SOL_SOCKET 1
#define SO_MARK 36

#define DNS_QR_BIT  0x8000

#define MAX_TYPE_A_ANSWERS 16


struct dns_hdr {
	u16 id;
	u16 flags;
	u16 qdcount;
	u16 ancount;
	u16 nscount;
	u16 arcount;
} __attribute__((packed));

struct dns_rr_a {
	u16 name;
	u16 type;
	u16 class_;
	u32 ttl;
	u16 rdlength;
	u32 addr;
} __attribute__((packed));

struct rdns_key {
	u32 addr;
};

struct rdns_val {
	u8 qlen;
	u8 qname[64];
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 8192);
	__type(key, struct rdns_key);
	__type(value, struct rdns_val);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} rdns SEC(".maps");

struct decision {
	u32 mark;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 1024);
	__type(key, struct rdns_key);
	__type(value, struct decision);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} decisions SEC(".maps");

SEC("tc/ingress_dns_parse")
int tc_ingress_dns_parse(struct __sk_buff *skb)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;

	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end)
		return TC_ACT_OK;

	if (eth->h_proto != ETH_P_IP)
		return TC_ACT_OK;

	struct iphdr *iph = (void *)(eth + 1);
	if ((void *)(iph + 1) > data_end)
		return TC_ACT_OK;

	if (iph->protocol != IPPROTO_UDP)
		return TC_ACT_OK;

	u32 ihl = (u32)iph->ihl * 4u;
	if (ihl < sizeof(*iph))
		return TC_ACT_OK;

	void *l4 = (void *)iph + ihl;
	if (l4 > data_end)
		return TC_ACT_OK;

	struct udphdr *uh = l4;
	if ((void *)(uh + 1) > data_end)
		return TC_ACT_OK;

	if (uh->source != bpf_htons(53))
		return TC_ACT_OK;

	struct dns_hdr *dh = (void *)(uh + 1);
	if ((void *)(dh + 1) > data_end)
		return TC_ACT_OK;

	u16 flags = bpf_ntohs(dh->flags);
	if ((flags & DNS_QR_BIT) == 0 || bpf_ntohs(dh->qdcount) != 1)
		return TC_ACT_OK;

	u8 *qname_ptr = (u8 *)(dh + 1);
	u32 qname_off = (void *)qname_ptr - (void *)data;

	struct rdns_val rv = {};

	u32 pkt_bytes = (u32)((u64)data_end - (u64)data);

	if (qname_off + 1 >= pkt_bytes)
		return TC_ACT_OK;

	u32 read_len = pkt_bytes - qname_off - 1;
	if (read_len > 63)
		read_len = 63;

	read_len++; // fuck you verifier
	if (bpf_skb_load_bytes(skb, qname_off, rv.qname, read_len) < 0)
		return TC_ACT_OK;

	for (int i=0; i<64; i++) {
		if (rv.qname[i] == 0) {
			rv.qlen = i;
			break;
		}
	}

	if (rv.qlen == 0)
		return TC_ACT_OK;

	u8 *cur = qname_ptr + rv.qlen + 1;
	if ((void *)(cur + 4) > data_end)
		return TC_ACT_OK;
	cur += 4;

	u16 an = bpf_ntohs(dh->ancount);
	if (an > MAX_TYPE_A_ANSWERS) an = MAX_TYPE_A_ANSWERS;

	struct rdns_key rk = {};
	for (int ai = 0; ai < MAX_TYPE_A_ANSWERS; ai++) {
		if (ai >= an)
			return TC_ACT_OK;

		struct dns_rr_a *rr = (struct dns_rr_a *)cur;

		if ((void *)(rr + 1) > data_end)
			return TC_ACT_OK;

		if (bpf_ntohs(rr->rdlength) != 4)
			return TC_ACT_OK;

		if (bpf_ntohs(rr->type) == 1 /* A */ && bpf_ntohs(rr->class_) == 1 /* IN */) {
			rk.addr = rr->addr;
			bpf_map_update_elem(&rdns, &rk, &rv, BPF_ANY);
		}

		cur += sizeof(*rr);
	}

	return TC_ACT_OK;
}

struct lpm_key {
	u32 prefixlen;
	u8  rev_qname[64];
};

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, 4096);
	__type(key, struct lpm_key);
	__type(value, u32);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} domain_lpm SEC(".maps");

static __always_inline void reverse_qname(u8 dst[64], const u8 src[64], u8 qlen)
{
	if (qlen == 0)
		return;
	if (qlen > 64)
		qlen = 64;

	u32 base = (u32)qlen - 1;

	for (int i = 0; i < 64; i++) {
		if ((u8)i > base)
			break;

		u8 s = src[i];

		u32 j = base - i;
		dst[j] = s;
	}
}

SEC("cgroup/connect4_domain_mark")
int cgroup_connect4_domain_mark(struct bpf_sock_addr *ctx)
{
	struct rdns_key rk = {};
	rk.addr = ctx->user_ip4;

	u32 mark;

	struct decision *rd = bpf_map_lookup_elem(&decisions, &rk);
	if (rd){
		mark = rd->mark;
		goto set_mark;
	}

	struct rdns_val *rv = bpf_map_lookup_elem(&rdns, &rk);
	if (!rv)
		return 1;

	struct lpm_key key = {};
	key.prefixlen = rv->qlen * 8;
	reverse_qname(key.rev_qname, rv->qname, rv->qlen);

	u32 *markp = bpf_map_lookup_elem(&domain_lpm, &key);
	if (!markp)
		return 1;

	mark = *markp;

	struct decision new_rd = {};
	new_rd.mark = mark;
	bpf_map_update_elem(&decisions, &rk, &new_rd, BPF_ANY);

set_mark:
	bpf_setsockopt(ctx, SOL_SOCKET, SO_MARK, &mark, sizeof(mark));
	return 1;
}

char _license[] SEC("license") = "Dual BSD/GPL";
