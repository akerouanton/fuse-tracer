.PHONY: generate
generate:
	go generate ./

.PHONY: build
build:
	docker build -t albinkerouanton006/fuse-tracer:latest .

.PHONY: push
push: build
	docker push albinkerouanton006/fuse-tracer:latest

.PHONY: run
run:
	docker run --rm -it --privileged albinkerouanton006/fuse-tracer:latest

vmlinux.h:
	# This is going to dump both vmlinux and fuse BTFs
	sudo bpftool btf dump id 51 format c > vmlinux.h
