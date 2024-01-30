BIN ?= fuse-tracer

.PHONY: dev
dev:
	docker build -t albinkerouanton006/fuse-tracer:dev --target dev .

.PHONY: generate
generate: dev
	docker run --rm -v .:/src -e GOARCH=amd64 albinkerouanton006/fuse-tracer:dev go generate ./bpf
	docker run --rm -v .:/src -e GOARCH=arm64 albinkerouanton006/fuse-tracer:dev go generate ./bpf

.PHONY: build
build: generate
	docker build -t albinkerouanton006/fuse-tracer:latest --target bin .

.PHONY: push
push: build
	docker push albinkerouanton006/fuse-tracer:latest

.PHONY: run
run:
ifeq ($(ARGS),)
	@echo "WARNING: no ARGS specified."
endif
	docker run --rm -it --privileged albinkerouanton006/fuse-tracer:latest $(BIN) $(ARGS)

vmlinux.h:
	# This is going to dump both vmlinux and fuse BTFs
	sudo bpftool btf dump id 51 format c > vmlinux.h
