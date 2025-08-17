package main

import (
	"context"
	"errors"
	"log"
	"net"
	"os"
	"os/signal"
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
		if link.Type() == "device" && flags&net.FlagLoopback == 0 && flags&net.FlagUp != 0 && flags&net.FlagRunning != 0 {
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

	//linkObj, err := netlink.LinkByName("enx58ef687e15eb")
	//if err != nil {
	//	log.Fatalf("failed to get wlp0s20f3 %v", err)
	//}
	//filter, err := attachTC(objs.TcEgressRedirect, linkObj.Attrs().Index, false)
	//if err != nil {
	//	log.Fatalf("failed to attach tc: %v", err)
	//}
	//defer netlink.FilterDel(filter)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	<-ctx.Done()
}
