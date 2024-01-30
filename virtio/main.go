package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"

	"github.com/akerouanton/fuse-tracer/bpf"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/sirupsen/logrus"
)

var progNames = []string{
	"trace_vp_vring_interrupt",
}

func main() {
	logrus.SetLevel(logrus.DebugLevel)

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		panic(err)
	}

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)

	collSpec, err := bpf.LoadFuse_tracer()
	if err != nil {
		panic(fmt.Errorf("could not load collection spec: %w", err))
	}

	// Load eBPF programs and maps into the kernel.
	coll, err := ebpf.NewCollectionWithOptions(collSpec, ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: "/sys/fs/bpf",
		},
	})
	if err != nil {
		panic(fmt.Errorf("could not load BPF objects from collection spec: %w", err))
	}

	attached := make(map[string]link.Link)

	for _, progName := range progNames {
		l, err := link.AttachTracing(link.TracingOptions{Program: coll.Programs[progName]})
		if err != nil {
			panic(err)
		}

		attached[progName] = l
	}

	_, cancel := context.WithCancel(context.Background())
	<-c
	cancel()

	for _, l := range attached {
		l.Close()
	}
}
