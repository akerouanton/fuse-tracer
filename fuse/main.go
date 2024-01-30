package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"slices"
	"strings"
	"time"

	"github.com/akerouanton/fuse-tracer/bpf"
	"github.com/akerouanton/fuse-tracer/kallsyms"
	"github.com/aybabtme/uniplot/histogram"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/fatih/structs"
	"github.com/sirupsen/logrus"
)

var traceFlag = flag.String("trace", "reqresp", "Trace Either: req, resp, reqresp")
var dumpFlag = flag.Bool("dump", false, "Dump requests / replies")
var hexFlag = flag.Bool("hex", false, "Show args in hex format")
var statsFlag = flag.Bool("stats", false, "Show requests / replies stats")
var histFlag = flag.Bool("hist", false, "Show histogram of request time")
var stackFlag = flag.Bool("stack", false, "Dump kernel stacktraces")
var connStateFlag = flag.Bool("conn-state", false, "Show fuse conn state")

type fuseOpStats struct {
	Count       int
	TotalTime   uint64
	NoStartTime int
}

var fuseOpsStats map[uint32]fuseOpStats
var fuseOpsHistData []float64

var progNames = []string{
	"trace_fuse_request",
	"trace_fuse_request_end",
	"trace_request_wait_answer",
}

func main() {
	flag.Parse()

	if !*dumpFlag && !*statsFlag && !*histFlag && !*stackFlag {
		panic("You need to specify either -dump, -stats, -hist or -stack")
	}

	logrus.SetLevel(logrus.DebugLevel)

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		panic(err)
	}

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)

	fuseOpsStats = make(map[uint32]fuseOpStats)
	fuseOpsHistData = []float64{}

	collSpec, err := bpf.LoadFuse_tracer()
	if err != nil {
		panic(fmt.Errorf("could not load collection spec: %w", err))
	}

	traceType := uint8(0)
	if *traceFlag == "req" {
		traceType = 1
	} else if *traceFlag == "resp" {
		traceType = 2
	} else {
		traceType = 3
	}
	if err := collSpec.RewriteConstants(map[string]interface{}{
		"trace_type": traceType,
	}); err != nil {
		panic(err)
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

	// Retrieve kallsyms *after* attaching the probe to have it included
	if *stackFlag {
		kallsyms.LoadKallsyms("/proc/kallsyms")
	}

	fuseEventsReader, err := ringbuf.NewReader(coll.Maps["fuse_req_events"])
	if err != nil {
		panic(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	go WatchFuseEvents(ctx, fuseEventsReader, coll.Maps["stacktraces"])

	<-c
	cancel()

	if *statsFlag {
		printOpsStats(coll.Maps["inflight_reqs"])
	}
	if *histFlag {
		printOpsHist()
	}
	if *connStateFlag {
		printConnStateFlag(coll.Maps["fc_state_map"])
	}

	for _, l := range attached {
		l.Close()
	}
}

func printOpsStats(inflightMap *ebpf.Map) {
	fmt.Print("\nStats:\n")

	totalCount := 0
	totalTime := 0
	totalNoStartTime := 0

	opcodes := make([]uint32, 0, len(fuseOpsStats))
	for opcode := range fuseOpsStats {
		opcodes = append(opcodes, opcode)
	}

	slices.Sort(opcodes)

	for _, opcode := range opcodes {
		stat := fuseOpsStats[opcode]

		fmt.Printf("    - %s: %d calls (total time: %.3fµs -- %d missing start times)\n",
			fuseOperation(opcode),
			stat.Count,
			float64(stat.TotalTime)/1e3,
			stat.NoStartTime)

		totalCount += stat.Count
		totalTime += int(stat.TotalTime)
		totalNoStartTime += stat.NoStartTime
	}

	fmt.Printf("    - Total: %d calls (total time: %.3fµs -- %d missing start times)\n",
		totalCount,
		float64(totalTime)/1e3,
		totalNoStartTime)
	fmt.Printf("    - Inflight requests: %d\n", countInflightReqs(inflightMap))
}

func countInflightReqs(inflightMap *ebpf.Map) int {
	inflightCount := 0
	inflightIter := inflightMap.Iterate()

	var k uint32
	var v interface{}
	for inflightIter.Next(&k, &v) {
		inflightCount++
	}

	return inflightCount
}

func printOpsHist() {
	fmt.Print("\nHistogram:\n")

	hist := histogram.Hist(10, fuseOpsHistData)
	if err := histogram.Fprintf(os.Stdout, hist, histogram.Linear(5), func(v float64) string {
		return time.Duration(v).String()
	}); err != nil {
		panic(err)
	}
}

func WatchFuseEvents(ctx context.Context, fuseEventsReader *ringbuf.Reader, stackReader *ebpf.Map) error {
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		record, err := fuseEventsReader.Read()
		if err != nil {
			if errors.Is(err, os.ErrClosed) {
				return nil
			}
			logrus.WithField("error", err).Error("error reading from fuse_events reader")
			continue
		}

		var fuseEvt bpf.Fuse_tracerFuseReqEvt
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &fuseEvt); err != nil {
			logrus.WithField("error", err).Error("could not parse fuse_req_evt")
			continue
		}

		if *dumpFlag || *stackFlag {
			printFuseEventHeader(fuseEvt)
		}
		if *dumpFlag {
			printFuseEvent(fuseEvt)
		}
		if *stackFlag {
			printStackTrace(stackReader, fuseEvt.StackId)
		}

		opStat, ok := fuseOpsStats[fuseEvt.InH.Opcode]
		if !ok {
			opStat = fuseOpStats{}
		}

		opStat.Count++

		if fuseEvt.StartKtime > 0 {
			opStat.TotalTime += fuseEvt.EndKtime - fuseEvt.StartKtime
			fuseOpsStats[fuseEvt.InH.Opcode] = opStat
			fuseOpsHistData = append(fuseOpsHistData, float64(opStat.TotalTime))
		} else {
			opStat.NoStartTime++
		}
	}
}

func printFuseEventHeader(fuseEvt bpf.Fuse_tracerFuseReqEvt) {
	fmt.Printf("[%d] %s (Len: %d - Request ID: %d - UID: %d - GID: %d - PID: %d): ",
		fuseEvt.StartKtime,
		fuseOperation(fuseEvt.InH.Opcode),
		fuseEvt.InH.Len,
		fuseEvt.InH.Unique,
		fuseEvt.InH.Uid,
		fuseEvt.InH.Gid,
		fuseEvt.InH.Pid)

	if fuseEvt.StartKtime > 0 {
		fmt.Printf("took %.3fµs", float64(fuseEvt.EndKtime-fuseEvt.StartKtime)/1e3)
	}

	fmt.Println()
}

func printFuseEvent(fuseEvt bpf.Fuse_tracerFuseReqEvt) {
	b := &strings.Builder{}

	if fuseEvt.InNumargs == 0 {
		fmt.Fprint(b, "    - (no in args)\n")
	}

	for i := 0; i < int(fuseEvt.InNumargs); i++ {
		arg := fuseEvt.InArgs[i]
		if *hexFlag {
			fmt.Fprintf(b, "    - In Arg %d:\n%s", i, hex.Dump(arg.Value[:arg.Size]))
		} else {
			fmt.Fprintf(b, "    - In Arg %d: %s\n", i, bytes.Trim(arg.Value[:arg.Size], "\x00"))
		}
	}

	if fuseEvt.OutNumargs == 0 {
		fmt.Fprint(b, "    - (no out args)\n")
	}

	for i := 0; i < int(fuseEvt.OutNumargs); i++ {
		arg := fuseEvt.OutArgs[i]
		if *hexFlag {
			fmt.Fprintf(b, "    - Out Arg %d:\n%s", i, hex.Dump(arg.Value[:arg.Size]))
		} else {
			fmt.Fprintf(b, "    - Out Arg %d: %s\n", i, bytes.Trim(arg.Value[:arg.Size], "\x00"))
		}
	}

	fmt.Printf("%s\n", b.String())
}

func printConnStateFlag(m *ebpf.Map) {
	var mapID uint32
	var connState bpf.Fuse_tracerFuseConnState

	if err := m.Lookup(&mapID, &connState); err != nil {
		panic(err)
	}

	fmt.Print("\nFUSE conn state:\n")
	for _, field := range structs.New(connState).Fields() {
		fmt.Printf("    - %s: %d\n", field.Name(), field.Value())
	}
}

func printStackTrace(stackReader *ebpf.Map, stackId uint32) {
	stack := make([]uint64, 127)
	if err := stackReader.Lookup(stackId, &stack); err != nil {
		fmt.Printf("Stack trace: (unavailable)\n\n")
		return
	}

	b := &strings.Builder{}
	for _, fnAddr := range stack {
		if fnAddr == 0 {
			break
		}

		fnName, _ := kallsyms.SearchKsym(fnAddr)
		fmt.Fprintf(b, "    %s [%x]\n", fnName, fnAddr)
	}

	fmt.Printf("Stack trace:\n%s\n", b.String())
}
