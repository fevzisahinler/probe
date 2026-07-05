// Package loader loads probe's eBPF programs and streams their events.
package loader

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -type event probe ../../bpf/probe.bpf.c -- -I../../bpf
