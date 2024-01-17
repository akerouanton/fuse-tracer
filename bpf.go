package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target $GOARCH -type fuse_req_evt -type fuse_conn_state fuse_tracer bpf.c
