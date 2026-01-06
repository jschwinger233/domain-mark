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
#define RR_TYPE_A   1
#define RR_CLASS_IN 1

#define MAX_TYPE_A_ANSWERS 32

#define barrier() asm volatile("" ::: "memory")


struct dns_hdr {
	u16 id;
	u16 flags;
	u16 qdcount;
	u16 ancount;
	u16 nscount;
	u16 arcount;
} __attribute__((packed));

struct dns_rr {
	u16 name;
	u16 type;
	u16 class_;
	u32 ttl;
	u16 rdlength;
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

static __noinline u8 strstr(const u8 *s, u8 maxlen, u8 target)
{
	for (u8 i = 0; i < maxlen; i++) {
		if (s[i] == target)
			return i;
	}
	return 0;
}

struct rr_parse_ctx {
	void *data_end;
	u8 *cur;
	u16 an;
	struct rdns_val rv;
};

static __noinline int parse_rr_cb(u32 i, void *data)
{
	struct rr_parse_ctx *ctx = data;

	if (i >= ctx->an)
		return 1;

	struct dns_rr *rr = (struct dns_rr *)ctx->cur;
	if ((void *)(rr + 1) > ctx->data_end)
		return 1;

	if (bpf_ntohs(rr->type) == RR_TYPE_A &&
	    bpf_ntohs(rr->class_) == RR_CLASS_IN &&
	    bpf_ntohs(rr->rdlength) == 4) {
		u8 *rdata = (u8 *)(rr + 1);
		if (rdata + 4 > (u8 *)ctx->data_end)
			return 1;

		struct rdns_key rk = {};
		rk.addr = *((u32 *)rdata);
		bpf_map_update_elem(&rdns, &rk, &ctx->rv, BPF_ANY);
	}

	u16 rdlen = bpf_ntohs(rr->rdlength);
	if (rdlen > 64)
		return 1;

	ctx->cur += sizeof(*rr) + rdlen;
	return 0;
}

SEC("tc/ingress_dns_parse")
int tc_ingress_dns_parse(struct __sk_buff *skb)
{
	if (skb->protocol != bpf_htons(ETH_P_IP))
		return TC_ACT_OK;

	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;

	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end)
		return TC_ACT_OK;

	if (eth->h_proto != ETH_P_IP)
		return TC_ACT_OK;

	struct iphdr *ip = (void *)(eth + 1);
	if ((void *)(ip + 1) > data_end)
		return TC_ACT_OK;

	if (ip->protocol != IPPROTO_UDP)
		return TC_ACT_OK;

	struct udphdr *udp = (void *)ip + ip->ihl * 4;
	if ((void *)(udp + 1) > data_end)
		return TC_ACT_OK;

	if (udp->source != bpf_htons(53))
		return TC_ACT_OK;

	struct dns_hdr *dns = (struct dns_hdr *)(udp + 1);
	if ((void *)(dns + 1) > data_end)
		return TC_ACT_OK;

	if ((bpf_ntohs(dns->flags) & DNS_QR_BIT) == 0 || bpf_ntohs(dns->qdcount) != 1)
		return TC_ACT_OK;

	u8 *qname_ptr = (u8 *)(dns + 1);
	u32 qname_off = (void *)qname_ptr - (void *)data;

	struct rr_parse_ctx rr_ctx = {};

	u32 qname_len = sizeof(rr_ctx.rv.qname);
	if ((void *)(qname_ptr + qname_len) > (void *)data_end)
		qname_len = (u64)data_end - (u64)qname_ptr;

	if (qname_len > sizeof(rr_ctx.rv.qname))
		qname_len = sizeof(rr_ctx.rv.qname);

	if (qname_len == 0)
		return TC_ACT_OK;

	if (bpf_skb_load_bytes(skb, qname_off, rr_ctx.rv.qname, qname_len) < 0)
		return TC_ACT_OK;


	rr_ctx.rv.qlen = strstr(rr_ctx.rv.qname, 64, 0);
	if (rr_ctx.rv.qlen == 0)
		return TC_ACT_OK;

	u8 *cur = qname_ptr + rr_ctx.rv.qlen + 1;
	if ((void *)(cur + 4) > data_end)
		return TC_ACT_OK;
	cur += 4;

	u16 an = bpf_ntohs(dns->ancount);
	if (an > MAX_TYPE_A_ANSWERS) an = MAX_TYPE_A_ANSWERS;

	rr_ctx.data_end = data_end;
	rr_ctx.cur = cur;
	rr_ctx.an = an;
	bpf_loop(MAX_TYPE_A_ANSWERS, parse_rr_cb, &rr_ctx, 0);

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

static __noinline void reverse_qname(u8 dst[64], const u8 src[64], u8 qlen)
{
	if (qlen == 0)
		return;
	if (qlen > 64)
		qlen = 64;

	u8 base = qlen - 1;
	if (base > 64)
		return;

	for (u8 i = 0; i < 64; i++) {
		if (i > base) {
			dst[i] = 0;
			continue;
		}

		u8 s = src[i];

		barrier(); // fuck you verifier
		u8 j = base - i;
		if (j > 64)
			return;

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
	if (!rv) {
		struct lpm_key empty_key = {};
		u32 *default_markp = bpf_map_lookup_elem(&domain_lpm, &empty_key);
		if (default_markp && *default_markp) {
			mark = *default_markp;
			goto set_decision_and_mark;
		}
		return 1;
	}

	struct lpm_key key = {};
	key.prefixlen = rv->qlen * 8;
	reverse_qname(key.rev_qname, rv->qname, rv->qlen);

	u32 *markp = bpf_map_lookup_elem(&domain_lpm, &key);
	if (!markp)
		return 1;

	mark = *markp;

set_decision_and_mark:
	struct decision new_rd = {};
	new_rd.mark = mark;
	bpf_map_update_elem(&decisions, &rk, &new_rd, BPF_ANY);

set_mark:
	bpf_setsockopt(ctx, SOL_SOCKET, SO_MARK, &mark, sizeof(mark));
	return 1;
}

char _license[] SEC("license") = "Dual BSD/GPL";
