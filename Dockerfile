FROM golang:alpine as dev

RUN apk add --no-cache bpftool clang libbpf libbpf-dev linux-headers llvm

WORKDIR /src

COPY go.mod go.sum /src
RUN go mod download

####################

FROM dev as bin

COPY bpf/ /src/bpf

COPY . .
RUN CGO_ENABLED=0 go build -o /usr/bin/fuse-tracer -ldflags="-extldflags=-static" ./fuse
RUN CGO_ENABLED=0 go build -o /usr/bin/vfs-tracer -ldflags="-extldflags=-static" ./vfs
RUN CGO_ENABLED=0 go build -o /usr/bin/virtio-tracer -ldflags="-extldflags=-static" ./virtio

CMD ["fuse-tracer"]
