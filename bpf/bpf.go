package bpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target $GOARCH -type fuse_req_evt -type fuse_conn_state Fuse_tracer bpf.c
