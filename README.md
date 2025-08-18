# domain-mark

Domain-based packet marking, kernel-fast and daemon-free.

> Early access. This project is built for my personal use. Expect sharp edges and breaking changes.

## What it does (typical use)

Domain-based routing. You assign an fwmark to traffic by its destination domain (e.g. *.example.com) and then use Linux policy routing to steer those packets via a specific table, gateway, or interface.

```
# 1) Attach programs, pin links & maps (requires root); exits immediately
sudo ./domain-mark start

# 2) Add your domain→mark rules, mark *.example.com with 0x23
sudo ./domain-mark rule add example.com 0x23

# 3) Plug the mark into policy routing (example):
sudo ip rule add fwmark 0x23 priority 100 lookup 100
sudo ip route add default via 192.0.2.1 dev eth1 table 100

# 4) Inspect state
sudo ./domain-mark rule list
sudo ./domain-mark rdns       # reverse-DNS cache (IPv4 → domain)
sudo ./domain-mark decision   # show effective IP → mark decisions

# 5) Tear down
sudo ./domain-mark stop
```

## Why it’s different

- eBPF-based: Packet classification & marking happen in kernel space.
- Daemonless workflow: start attaches and exits; nothing keeps running.
- Blazing fast: No per-packet context switches; built to run at line rate.

## Current limitations

- IPv4 only. (A records)
- Simple DNS parsing only. Recognizes DNS responses in a fixed form:
  - Must be an A RR.
  - The name must be compressed (pointer form).

## How it works

1. Reverse-DNS cache: eBPF tracks DNS A answers and maps dst IPv4 → domain.
2. Rule map (LPM trie): Keys are reversed qname bytes with prefix length, letting *.example.com be expressed as a prefix.
3. Data path marking: tc/cgroup eBPF looks up the current destination IP in the cache, matches against the LPM rules, and writes skb->mark.

## CLI

```
Domain-based packet marking, kernel-fast and daemon-free.

Usage:
  domain-mark [command]

Available Commands:
  decision    Print decisions (ip mark)
  help        Help about any command
  rdns        Print reverse-DNS cache (ipv4 domain)
  rule        Manage domain→mark rules (LPM trie)
  start       Attach tc/cgroup programs, pin link & maps, then exit
  stop        Detach cgroup, remove tc filters, and unpin maps

```
