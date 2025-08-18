package main

import (
	"errors"
	"fmt"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func ensureClsact(l netlink.Link) error {
	qdiscs, err := netlink.QdiscList(l)
	if err != nil {
		return fmt.Errorf("query qdiscs: %w", err)
	}
	for _, q := range qdiscs {
		if q.Attrs().Parent == netlink.HANDLE_CLSACT {
			return nil
		}
	}

	cls := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: l.Attrs().Index,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
		QdiscType: "clsact",
	}
	if err := netlink.QdiscAdd(cls); err != nil &&
		!errors.Is(err, syscall.EEXIST) {
		return fmt.Errorf("add clsact: %w", err)
	}
	return nil
}

func attachTC(prog *ebpf.Program, linkIdx int, ingress bool) (*netlink.BpfFilter, error) {
	parent := netlink.HANDLE_MIN_INGRESS
	if !ingress {
		parent = netlink.HANDLE_MIN_EGRESS
	}

	fl := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: linkIdx,
			Parent:    uint32(parent),
			Priority:  tcPriority,
			Protocol:  unix.ETH_P_ALL,
		},
		Fd:           prog.FD(),
		Name:         "ingress_qname_parse",
		DirectAction: true,
	}

	if err := netlink.FilterReplace(fl); err != nil {
		return nil, fmt.Errorf("filter replace: %w", err)
	}
	return fl, nil
}
