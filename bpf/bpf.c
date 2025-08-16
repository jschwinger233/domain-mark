// +build ignore
// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)

#include "vmlinux.h"
#include <bpf_helpers.h>
#include <bpf_endian.h>

/* tc actions */
#define TC_ACT_OK   0
#define TC_ACT_SHOT 2

/* EtherType / L4 */
#define ETH_P_IP    bpf_htons(0x0800)
#define IPPROTO_UDP 17

/* DNS */
#define DNS_QR_BIT  0x8000

#define MAX_TYPE_A_ANSWERS 16

struct dns_hdr {
	__be16 id;
	__be16 flags;
	__be16 qdcount;
	__be16 ancount;
	__be16 nscount;
	__be16 arcount;
} __attribute__((packed));

struct dns_rr_a {
	u16 name;
	u16 type;
	u16 class_;
	u32 ttl;
	u16 rdlength;
	u32 addr;
} __attribute__((packed));

SEC("tc/ingress_dns_parse")
int tc_ingress_dns_parse(struct __sk_buff *skb)
{
	void *data     = (void *)(long)skb->data;
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

	__u32 ihl = (__u32)iph->ihl * 4u;
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

	__u16 flags = bpf_ntohs(dh->flags);
	if ((flags & DNS_QR_BIT) == 0 || bpf_ntohs(dh->qdcount) != 1)
		return TC_ACT_OK;

	u8 *qname_ptr = (u8 *)(dh + 1);
	u32 qname_off = (void *)qname_ptr - (void *)data;

	u8 qname[64];
	u8 qname_len = 0;

	for (u8 i = 0; i < 64; i++) {
		bpf_skb_load_bytes(skb, qname_off+i, &qname[i], 1);

		if (qname[i] == 0) {
			qname_len = i;
			break;
		}
	}

	if (qname_len == 0)
		return TC_ACT_OK;

	u8 *cur = qname_ptr + qname_len + 1;
	if ((void *)(cur + 4) > data_end)
		return TC_ACT_OK;
	cur += 4;

	u16 an = bpf_ntohs(dh->ancount);
	if (an > MAX_TYPE_A_ANSWERS) an = MAX_TYPE_A_ANSWERS;

	for (int ai = 0; ai < MAX_TYPE_A_ANSWERS; ai++) {
		if (ai >= an)
			return TC_ACT_OK;

		struct dns_rr_a *rr = (struct dns_rr_a *)cur;

		if ((void *)(rr + 1) > data_end)
			return TC_ACT_OK;

		if (bpf_ntohs(rr->rdlength) != 4)
			return TC_ACT_OK;

		if (bpf_ntohs(rr->type) == 1 /* A */ && bpf_ntohs(rr->class_) == 1 /* IN */) {
			bpf_printk("A[%d]=%pI4 domain=%s\n", ai, &rr->addr, qname);
		}

		cur += sizeof(*rr);
	}

	return TC_ACT_OK;
}

char _license[] SEC("license") = "Dual BSD/GPL";

