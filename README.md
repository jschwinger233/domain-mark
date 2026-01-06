# domain-route

Domain-based socket routing by interface index, kernel-fast and daemon-free.

> Early access. This project is built for my personal use. Expect sharp edges and breaking changes.

## What it does

`domain-route` steers outbound IPv4 connections to specific interfaces based on the destination domain:

- A tc ingress program watches DNS A responses and builds a reverse-DNS cache (IPv4 → domain).
- A cgroup/connect4 program matches the destination domain against a suffix rule set (LPM trie).
- The socket is bound to the selected interface via `SO_BINDTOIFINDEX`.

There is no long-running daemon. `start` attaches and exits; maps and links are pinned under `/sys/fs/bpf/domain-route`.

## Requirements

- Linux with eBPF, bpffs mounted at `/sys/fs/bpf`, and cgroup v2 mounted at `/sys/fs/cgroup`.
- `tc` (clsact) and root privileges (or equivalent capabilities).

## Typical use

```
# 1) Attach programs, pin links & maps (requires root); exits immediately
sudo ./domain-route start

# 2) Find an interface index (example uses `eth1` -> 3)
ip -o link show

# 3) Add your domain → ifindex rule (matches example.com and *.example.com)
sudo ./domain-route rule add example.com 3

# 4) Inspect state
sudo ./domain-route rule list
sudo ./domain-route rdns       # reverse-DNS cache (IPv4 → domain)
sudo ./domain-route decision   # effective IP → ifindex decisions

# 5) Tear down
sudo ./domain-route stop
```

## How matching works

Rules are suffix matches on DNS wire-format names. A rule for `example.com` matches
`example.com` and any subdomain (e.g. `www.example.com`). Domains are normalized to
lowercase and without a trailing dot.

## Current limitations

- IPv4 only.
- Only UDP DNS responses from source port 53 are parsed.
- Requires exactly one question (`qdcount == 1`).
- DNS answers must use compressed names (pointer form) to fit the fixed RR parser.
- Only A records are used (IPv4, 4-byte RDATA).
- Decisions are cached (LRU) by destination IP until evicted or `stop` is run.

## How it works (detail)

1. **Reverse-DNS cache:** tc ingress parses DNS A responses and records `dst IPv4 → qname`.
2. **Rule map:** a BPF LPM trie stores reversed qname bytes → interface index.
3. **Data path:** cgroup/connect4 looks up the destination IP, matches the LPM rule,
   caches the decision, and binds the socket to the chosen interface.

## CLI

```
Domain-based socket routing via interface index, kernel-fast and daemon-free.

Usage:
  domain-route [command]

Available Commands:
  decision    Print decisions (ip ifindex)
  help        Help about any command
  rdns        Print reverse-DNS cache (ipv4 domain)
  rule        Manage domain→ifindex rules (LPM trie)
  start       Attach tc/cgroup programs, pin link & maps, then exit
  stop        Detach cgroup, remove tc filters, and unpin maps
```

## Build

The repository includes a prebuilt eBPF object for x86. For a fresh build:

```
# Build the Go binary
go build ./...

# (Optional) Regenerate eBPF object (requires clang-19 + llvm, and bpf2go)
go generate ./bpf
```
