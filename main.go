package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/jschwinger233/linux-domain-routing/bpf"
	"github.com/vishvananda/netlink"
)

func main() {
	spec, err := bpf.LoadBpf()
	if err != nil {
		log.Fatalf("failed to load BPF: %w", err)
	}

	objs := bpf.BpfObjects{}
	opts := ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			LogLevel: ebpf.LogLevelInstruction,
		},
	}
	if err = spec.LoadAndAssign(&objs, &opts); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			log.Fatalf("Verifier log:\n%+v\n", ve)
		}
		log.Fatalf("failed to load BPF objects: %w", err)
	}
	defer objs.Close()
	log.Printf("BPF objects loaded successfully")

	availableLinks := []netlink.Link{}
	links, err := netlink.LinkList()
	if err != nil {
		log.Fatalf("failed to list links: %v", err)
	}
	for _, link := range links {
		flags := link.Attrs().Flags
		if link.Type() == "device" && flags&net.FlagUp != 0 && flags&net.FlagRunning != 0 {
			availableLinks = append(availableLinks, link)
		}
	}

	for _, linkObj := range availableLinks {
		if err := ensureClsact(linkObj); err != nil {
			log.Fatalf("ensure clsact: %v", err)
		}

		filter, err := attachTC(objs.TcIngressDnsParse, linkObj.Attrs().Index, true)
		if err != nil {
			log.Fatalf("attach tc: %v", err)
		}
		defer netlink.FilterDel(filter)

		log.Printf("tc filter attached on %s\n", linkObj.Attrs().Name)
	}

	cg, err := link.AttachCgroup(link.CgroupOptions{
		Path:    "/sys/fs/cgroup",
		Attach:  ebpf.AttachCGroupInet4Connect,
		Program: objs.CgroupConnect4DomainRoute,
	})
	if err != nil {
		log.Fatalf("AttachCgroup: %v: %w", objs.CgroupConnect4DomainRoute.String(), err)
	}
	defer cg.Close()

	if len(os.Args) > 1 {
		for _, arg := range os.Args[1:] {
			domain, markStr, ok := strings.Cut(arg, ":")
			if !ok {
				log.Printf("bad arg %q (want domain:mark)", arg)
				return
			}
			mark, err := parseMark(markStr)
			if err != nil {
				log.Printf("parse mark %q: %v", markStr, err)
				return
			}

			if domain == "default" {
				var key bpf.BpfLpmKey
				key.Prefixlen = 0

				val := mark // u32 value

				if err := objs.DomainLpm.Update(&key, &val, ebpf.UpdateAny); err != nil {
					log.Fatalf("DomainLpm.Update %q → 0x%x: %v", domain, mark, err)
				}
				log.Printf("DomainLpm upsert: %q → mark 0x%x (prefixlen=%d bits)", domain, mark, key.Prefixlen)
				continue
			}

			wire, err := normalizeDomainToDNSBytes(domain)
			if err != nil {
				log.Printf("domain %q: %v", domain, err)
				return
			}
			rev := reverseBytes(wire)

			if len(rev) > 64 {
				log.Printf("reversed qname for %q is %d bytes; max supported is 64", domain, len(rev))
				return
			}

			var key bpf.BpfLpmKey
			key.Prefixlen = uint32(len(rev) * 8)
			copy(key.RevQname[:], rev)

			val := mark // u32 value

			if err := objs.DomainLpm.Update(&key, &val, ebpf.UpdateAny); err != nil {
				log.Fatalf("DomainLpm.Update %q → 0x%x: %v", domain, mark, err)
			}
			log.Printf("DomainLpm upsert: %q → mark 0x%x (prefixlen=%d bits)", domain, mark, key.Prefixlen)

		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	<-ctx.Done()
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

func parseMark(s string) (uint32, error) {
	u, err := strconv.ParseUint(s, 0, 32) // handles 0x… and decimal
	return uint32(u), err
}
