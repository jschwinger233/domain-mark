package bpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang-19 -no-strip -target native Bpf ./bpf.c -- -I./headers -I. -Wall
