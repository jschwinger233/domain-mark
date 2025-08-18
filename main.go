package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/jschwinger233/linux-domain-routing/bpf"
	"github.com/spf13/cobra"
	"github.com/vishvananda/netlink"
)

const (
	pinBase       = "/sys/fs/bpf/domain-mark"
	pinLinksDir   = pinBase + "/links"
	pinCgroupLink = pinLinksDir + "/cgroup_connect4"

	tcProgName = "tc_ingress_dns_parse"
	tcPriority = 23333
)

func main() {
	root := &cobra.Command{
		Use:   "domain-mark",
		Short: "Domain routing rule & rDNS helpers backed by eBPF maps",
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {

			if err := os.MkdirAll(pinBase, 0o755); err != nil {
				return err
			}
			return os.MkdirAll(pinLinksDir, 0o755)
		},
	}

	start := &cobra.Command{
		Use:   "start",
		Short: "Attach tc/cgroup programs, pin link & maps, then exit",
		RunE:  startCmd,
	}

	stop := &cobra.Command{
		Use:   "stop",
		Short: "Detach cgroup, remove tc filters, and unpin maps",
		RunE:  stopCmd,
	}

	rule := &cobra.Command{Use: "rule", Short: "Manage domain→mark rules (LPM trie)"}
	rule.AddCommand(ruleListCmd(), ruleAddCmd(), ruleDelCmd())

	rdns := &cobra.Command{
		Use:   "rdns",
		Short: "Print reverse-DNS cache (ipv4 domain)",
		RunE:  rdnsCmd,
	}

	rdec := &cobra.Command{
		Use:   "decision",
		Short: "Print decisions (ip mark)",
		RunE:  decisionCmd,
	}

	root.AddCommand(start, stop, rule, rdns, rdec)
	root.CompletionOptions.HiddenDefaultCmd = true
	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}

func startCmd(_ *cobra.Command, _ []string) error {

	spec, err := bpf.LoadBpf()
	if err != nil {
		return fmt.Errorf("load BPF spec: %w", err)
	}

	objs := &bpf.BpfObjects{}
	opts := &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{PinPath: pinBase},
		Programs: ebpf.ProgramOptions{
			LogLevel: ebpf.LogLevelInstruction,
		},
	}
	if err := spec.LoadAndAssign(objs, opts); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			return fmt.Errorf("verifier:\n%+v", ve)
		}
		return fmt.Errorf("load objects: %w", err)
	}

	cgl, err := link.AttachCgroup(link.CgroupOptions{
		Path:    "/sys/fs/cgroup",
		Attach:  ebpf.AttachCGroupInet4Connect,
		Program: objs.CgroupConnect4DomainRoute,
	})
	if err != nil {
		return fmt.Errorf("attach cgroup inet4/connect: %w", err)
	}

	if err := cgl.Pin(pinCgroupLink); err != nil {
		_ = cgl.Close()
		return fmt.Errorf("pin cgroup link: %w", err)
	}
	_ = cgl.Close()
	fmt.Println("cgroup: attached & pinned at", pinCgroupLink)

	if err := attachTCAll(objs.TcIngressDnsParse); err != nil {
		return err
	}
	fmt.Println("tc: ingress attached on eligible interfaces")

	return nil
}

func attachTCAll(prog *ebpf.Program) error {
	links, err := netlink.LinkList()
	if err != nil {
		return fmt.Errorf("list links: %w", err)
	}
	for _, l := range links {
		attrs := l.Attrs()
		if l.Type() != "device" {
			continue
		}
		if attrs.Flags&net.FlagUp == 0 || attrs.Flags&net.FlagRunning == 0 {
			continue
		}
		if err := ensureClsact(l); err != nil {
			return fmt.Errorf("ensure clsact(%s): %w", attrs.Name, err)
		}
		if _, err := attachTC(prog, attrs.Index, true); err != nil {
			return fmt.Errorf("attach tc(%s): %w", attrs.Name, err)
		}
	}
	return nil
}

func stopCmd(_ *cobra.Command, _ []string) error {

	if err := detachCgroupPinned(); err != nil {
		return err
	}
	fmt.Println("cgroup: detached")

	if err := deleteTCAllByPriority(tcPriority, true); err != nil {
		return err
	}
	fmt.Println("tc: ingress filters removed")

	_ = os.Remove(filepath.Join(pinBase, "domain_lpm"))
	_ = os.Remove(filepath.Join(pinBase, "rdns"))
	_ = os.Remove(filepath.Join(pinBase, "routing_decisions"))
	fmt.Println("maps: unpinned (if existed)")

	return nil
}

func deleteTCAllByPriority(prio uint16, ingress bool) error {
	var parent uint32 = netlink.HANDLE_MIN_INGRESS
	if !ingress {
		parent = netlink.HANDLE_MIN_EGRESS
	}
	links, err := netlink.LinkList()
	if err != nil {
		return fmt.Errorf("list links: %w", err)
	}
	for _, l := range links {

		filters, err := netlink.FilterList(l, parent)
		if err != nil {
			continue
		}
		for _, flt := range filters {
			bf, ok := flt.(*netlink.BpfFilter)
			if !ok {
				continue
			}
			if bf.FilterAttrs.Priority == prio {

				_ = netlink.FilterDel(bf)
			}
		}
	}
	return nil
}

func detachCgroupPinned() error {
	if _, err := os.Stat(pinCgroupLink); err == nil {
		l, err := link.LoadPinnedLink(pinCgroupLink, nil)
		if err != nil {
			return fmt.Errorf("load pinned cgroup link: %w", err)
		}

		if err := l.Close(); err != nil {
			return fmt.Errorf("close cgroup link: %w", err)
		}
		if err := os.Remove(pinCgroupLink); err != nil {
			return fmt.Errorf("remove cgroup link pin: %w", err)
		}
	}
	return nil
}

func ruleListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List LPM domain→mark rules",
		RunE: func(_ *cobra.Command, _ []string) error {
			objs, closer, err := loadMapsOnly()
			if err != nil {
				return err
			}
			defer closer()

			iter := objs.DomainLpm.Iterate()
			var key bpf.BpfLpmKey
			var mark uint32
			for iter.Next(&key, &mark) {
				if key.Prefixlen == 0 {
					fmt.Printf("%-30s -> 0x%x\n", "default", mark)
					continue
				}
				n := int(key.Prefixlen / 8)
				if n < 0 || n > len(key.RevQname) {
					continue
				}
				wire := reverseBytes(key.RevQname[:n])
				name := dnsWireToDomain(wire)
				if name == "" {
					name = fmt.Sprintf("(bad:%x)", wire)
				}
				fmt.Printf("%-30s -> 0x%x\n", name, mark)
			}
			return iter.Err()
		},
	}
}

func ruleAddCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "add <domain> <mark>",
		Short: "Add/replace a domain→mark rule",
		Args:  cobra.ExactArgs(2),
		RunE: func(_ *cobra.Command, args []string) error {
			domain := args[0]
			mark, err := parseMark(args[1])
			if err != nil {
				return fmt.Errorf("parse mark: %w", err)
			}

			objs, closer, err := loadMapsOnly()
			if err != nil {
				return err
			}
			defer closer()

			if domain == "default" {
				var key bpf.BpfLpmKey
				key.Prefixlen = 0
				if err := objs.DomainLpm.Update(&key, &mark, ebpf.UpdateAny); err != nil {
					return fmt.Errorf("upsert default: %w", err)
				}
				fmt.Printf("default -> 0x%x\n", mark)
				return nil
			}

			wire, err := normalizeDomainToDNSBytes(domain)
			if err != nil {
				return err
			}
			rev := reverseBytes(wire)
			if len(rev) > 64 {
				return fmt.Errorf("reversed qname for %q is %d bytes; max supported is 64", domain, len(rev))
			}

			var key bpf.BpfLpmKey
			key.Prefixlen = uint32(len(rev) * 8)
			copy(key.RevQname[:], rev)

			if err := objs.DomainLpm.Update(&key, &mark, ebpf.UpdateAny); err != nil {
				return fmt.Errorf("DomainLpm.Update: %w", err)
			}
			fmt.Printf("%s -> 0x%x\n", domain, mark)
			return nil
		},
	}
}

func ruleDelCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "del <domain>",
		Short: "Delete a specific domain→mark rule (mark is ignored server-side, kept for CLI symmetry)",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			domain := args[0]

			objs, closer, err := loadMapsOnly()
			if err != nil {
				return err
			}
			defer closer()

			if domain == "default" {
				var key bpf.BpfLpmKey
				key.Prefixlen = 0
				if err := objs.DomainLpm.Delete(&key); err != nil {
					return fmt.Errorf("delete default: %w", err)
				}
				fmt.Println("deleted: default")
				return nil
			}

			wire, err := normalizeDomainToDNSBytes(domain)
			if err != nil {
				return err
			}
			rev := reverseBytes(wire)
			if len(rev) > 64 {
				return fmt.Errorf("reversed qname for %q is %d bytes; max supported is 64", domain, len(rev))
			}
			var key bpf.BpfLpmKey
			key.Prefixlen = uint32(len(rev) * 8)
			copy(key.RevQname[:], rev)

			if err := objs.DomainLpm.Delete(&key); err != nil {
				return fmt.Errorf("DomainLpm.Delete: %w", err)
			}
			fmt.Printf("deleted: %s\n", domain)
			return nil
		},
	}
}

func rdnsCmd(_ *cobra.Command, _ []string) error {
	objs, closer, err := loadMapsOnly()
	if err != nil {
		return err
	}
	defer closer()

	iter := objs.Rdns.Iterate()
	var k bpf.BpfRdnsKey
	var v bpf.BpfRdnsVal
	for iter.Next(&k, &v) {
		ip := ipv4FromU32(k.Addr)
		n := int(v.Qlen)
		if n < 0 || n > len(v.Qname) {
			fmt.Printf("%s <bad-qname>\n", ip)
			continue
		}
		name := dnsWireToDomain(v.Qname[:n])
		if name == "" {
			name = "<empty>"
		}
		fmt.Printf("%-15s  %s\n", ip, name)
	}
	return iter.Err()
}

func decisionCmd(_ *cobra.Command, _ []string) error {
	objs, closer, err := loadMapsOnly()
	if err != nil {
		return err
	}
	defer closer()

	iter := objs.RoutingDecisions.Iterate()
	var k bpf.BpfRdnsKey
	var v bpf.BpfRoutingDecision
	for iter.Next(&k, &v) {
		ip := ipv4FromU32(k.Addr)
		fmt.Printf("%-15s  0x%x\n", ip, v.Mark)
	}
	return iter.Err()
}

func loadMapsOnly() (*bpf.BpfObjects, func(), error) {
	spec, err := bpf.LoadBpf()
	if err != nil {
		return nil, nil, fmt.Errorf("load BPF spec: %w", err)
	}
	objs := &bpf.BpfObjects{}
	opts := &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{PinPath: pinBase},
	}
	if err := spec.LoadAndAssign(objs, opts); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			return nil, nil, fmt.Errorf("verifier:\n%+v", ve)
		}
		return nil, nil, fmt.Errorf("load objects: %w", err)
	}
	return objs, func() { objs.Close() }, nil
}

func normalizeDomainToDNSBytes(domain string) ([]byte, error) {
	d := strings.TrimSpace(strings.TrimSuffix(strings.ToLower(domain), "."))
	if d == "" {
		return nil, fmt.Errorf("empty domain")
	}
	parts := strings.Split(d, ".")
	var out []byte
	for _, p := range parts {
		if p == "" {
			return nil, fmt.Errorf("bad domain %q: empty label", domain)
		}
		if len(p) > 63 {
			return nil, fmt.Errorf("label %q too long (>63)", p)
		}
		out = append(out, byte(len(p)))
		out = append(out, []byte(p)...)
	}
	if len(out) > 255 {
		return nil, fmt.Errorf("encoded name too long (>255 bytes)")
	}
	return out, nil
}

func reverseBytes(b []byte) []byte {
	n := len(b)
	out := make([]byte, n)
	for i := 0; i < n; i++ {
		out[i] = b[n-1-i]
	}
	return out
}

func dnsWireToDomain(wire []byte) string {
	var parts []string
	for i := 0; i < len(wire); {
		l := int(wire[i])
		i++
		if l == 0 {
			break
		}
		if l <= 0 || l > 63 || i+l > len(wire) {
			return ""
		}
		parts = append(parts, string(wire[i:i+l]))
		i += l
	}
	return strings.Join(parts, ".")
}

func parseMark(s string) (uint32, error) {
	u, err := strconv.ParseUint(s, 0, 32)
	return uint32(u), err
}

func ipv4FromU32(be uint32) string {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], be)
	return net.IP(b[:]).String()
}
