// Code generated by bpf2go; DO NOT EDIT.
//go:build 386 || amd64

package main

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

type fuse_tracerFuseConnState struct {
	ConnError          uint64
	ConnInit           uint64
	AsyncRead          uint64
	AbortErr           uint64
	AtomicO_trunc      uint64
	ExportSupport      uint64
	WritebackCache     uint64
	ParallelDirops     uint64
	HandleKillpriv     uint64
	CacheSymlinks      uint64
	LegacyOptsShow     uint64
	HandleKillprivV2   uint64
	NoOpen             uint64
	NoOpendir          uint64
	NoFsync            uint64
	NoFsyncdir         uint64
	NoFlush            uint64
	NoSetxattr         uint64
	SetxattrExt        uint64
	NoGetxattr         uint64
	NoListxattr        uint64
	NoRemovexattr      uint64
	NoLock             uint64
	NoAccess           uint64
	NoCreate           uint64
	NoInterrupt        uint64
	NoBmap             uint64
	NoPoll             uint64
	BigWrites          uint64
	DontMask           uint64
	NoFlock            uint64
	NoFallocate        uint64
	NoRename2          uint64
	AutoInvalData      uint64
	ExplicitInvalData  uint64
	DoReaddirplus      uint64
	ReaddirplusAuto    uint64
	AsyncDio           uint64
	NoLseek            uint64
	PosixAcl           uint64
	DefaultPermissions uint64
	AllowOther         uint64
	NoCopyFileRange    uint64
	Destroy            uint64
	DeleteStale        uint64
	NoControl          uint64
	NoForceUmount      uint64
	AutoSubmounts      uint64
	SyncFs             uint64
	InitSecurity       uint64
	CreateSuppGroup    uint64
	InodeDax           uint64
	NoTmpfile          uint64
	DirectIoAllowMmap  uint64
	NoStatx            uint64
}

type fuse_tracerFuseReqEvt struct {
	StartKtime uint64
	EndKtime   uint64
	InH        struct {
		Len         uint32
		Opcode      uint32
		Unique      uint64
		Nodeid      uint64
		Uid         uint32
		Gid         uint32
		Pid         uint32
		TotalExtlen uint16
		Padding     uint16
	}
	Flags     uint64
	EndFlags  uint64
	InNumargs uint8
	_         [1]byte
	InArgs    [3]struct {
		Size  uint16
		Value [128]uint8
	}
	OutNumargs uint8
	_          [1]byte
	OutArgs    [3]struct {
		Size  uint16
		Value [128]uint8
	}
}

// loadFuse_tracer returns the embedded CollectionSpec for fuse_tracer.
func loadFuse_tracer() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_Fuse_tracerBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load fuse_tracer: %w", err)
	}

	return spec, err
}

// loadFuse_tracerObjects loads fuse_tracer and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*fuse_tracerObjects
//	*fuse_tracerPrograms
//	*fuse_tracerMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadFuse_tracerObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadFuse_tracer()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// fuse_tracerSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type fuse_tracerSpecs struct {
	fuse_tracerProgramSpecs
	fuse_tracerMapSpecs
}

// fuse_tracerSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type fuse_tracerProgramSpecs struct {
	TraceFuseRequest       *ebpf.ProgramSpec `ebpf:"trace_fuse_request"`
	TraceRequestWaitAnswer *ebpf.ProgramSpec `ebpf:"trace_request_wait_answer"`
}

// fuse_tracerMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type fuse_tracerMapSpecs struct {
	FcStateMap    *ebpf.MapSpec `ebpf:"fc_state_map"`
	FuseReqEvents *ebpf.MapSpec `ebpf:"fuse_req_events"`
	InflightReqs  *ebpf.MapSpec `ebpf:"inflight_reqs"`
	ReqHeap       *ebpf.MapSpec `ebpf:"req_heap"`
}

// fuse_tracerObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadFuse_tracerObjects or ebpf.CollectionSpec.LoadAndAssign.
type fuse_tracerObjects struct {
	fuse_tracerPrograms
	fuse_tracerMaps
}

func (o *fuse_tracerObjects) Close() error {
	return _Fuse_tracerClose(
		&o.fuse_tracerPrograms,
		&o.fuse_tracerMaps,
	)
}

// fuse_tracerMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadFuse_tracerObjects or ebpf.CollectionSpec.LoadAndAssign.
type fuse_tracerMaps struct {
	FcStateMap    *ebpf.Map `ebpf:"fc_state_map"`
	FuseReqEvents *ebpf.Map `ebpf:"fuse_req_events"`
	InflightReqs  *ebpf.Map `ebpf:"inflight_reqs"`
	ReqHeap       *ebpf.Map `ebpf:"req_heap"`
}

func (m *fuse_tracerMaps) Close() error {
	return _Fuse_tracerClose(
		m.FcStateMap,
		m.FuseReqEvents,
		m.InflightReqs,
		m.ReqHeap,
	)
}

// fuse_tracerPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadFuse_tracerObjects or ebpf.CollectionSpec.LoadAndAssign.
type fuse_tracerPrograms struct {
	TraceFuseRequest       *ebpf.Program `ebpf:"trace_fuse_request"`
	TraceRequestWaitAnswer *ebpf.Program `ebpf:"trace_request_wait_answer"`
}

func (p *fuse_tracerPrograms) Close() error {
	return _Fuse_tracerClose(
		p.TraceFuseRequest,
		p.TraceRequestWaitAnswer,
	)
}

func _Fuse_tracerClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed fuse_tracer_bpfel_x86.o
var _Fuse_tracerBytes []byte
