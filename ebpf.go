package main

// eBPF-based execve tracing.
//
// This uses the cilium/ebpf library (pure Go, no cgo) to hook into the
// tracepoint/syscalls/sys_enter_execve and capture every process spawn.
//
// Requirements:
//   - Linux kernel ≥ 5.8 with CONFIG_BPF_SYSCALL=y
//   - CAP_BPF + CAP_PERFMON (or CAP_SYS_ADMIN on older kernels)
//   - Pre-compiled BPF object (generated via bpf2go at build time)
//
// If the kernel doesn't support BPF or capabilities are insufficient,
// startEBPFTracer logs a warning and returns without blocking.

import (
	"log"
	"os"
)

// startEBPFTracer starts the eBPF-based process tracer.
// Currently a stub that gracefully disables when the environment doesn't support BPF.
// Full implementation requires:
//  1. go generate //go:generate go run github.com/cilium/ebpf/cmd/bpf2go ...
//  2. A BPF C program in ebpf/execve.c
//  3. Ring buffer reading loop
//
// TODO(v2): implement full eBPF tracing with cilium/ebpf
func startEBPFTracer(events chan<- SecurityEvent) {
	if !bpfAvailable() {
		log.Printf("[ebpf] BPF not available on this system — skipping execve tracer")
		return
	}

	log.Printf("[ebpf] eBPF support detected but tracing is not yet implemented — will be enabled in a future release")
	// Placeholder: when implemented, this will:
	// 1. Load the compiled BPF program
	// 2. Attach to tracepoint/syscalls/sys_enter_execve
	// 3. Read events from a BPF ring buffer
	// 4. Emit SecurityEvent{Type: EventProcessSpawn, ...} for each execve

	_ = events // suppress unused warning
}

// bpfAvailable checks whether the kernel supports BPF.
func bpfAvailable() bool {
	// /sys/kernel/btf/vmlinux exists on kernels ≥ 5.4 with CONFIG_DEBUG_INFO_BTF=y
	_, err := os.Stat("/sys/kernel/btf/vmlinux")
	return err == nil
}
