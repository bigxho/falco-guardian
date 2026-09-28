# eBPF/C Component — High-Performance Packet Capture

This module moves packet telemetry into the Linux kernel through eBPF/XDP, avoiding full-packet copying to Python and reducing userspace overhead for high-volume monitoring scenarios.

## How it works

1. **`capture.bpf.c`** — eBPF program attached to a network interface through XDP. For each inbound IPv4 packet it extracts source/destination IP addresses and ports, protocol, packet length, and TCP flags, then writes a compact event to a BPF ring buffer. It always returns `XDP_PASS` and therefore does not block traffic itself.
2. **`loader.c`** — userspace process that loads the eBPF program, consumes the ring buffer, serializes events as JSON Lines, and broadcasts them through `/run/falco-guardian/capture.sock`.
3. **`python/core/capture_client.py`** — connects to the Unix socket and forwards events into the Python detector pipeline.

Optional IP enforcement remains in Python through `iptables` (`core/blocker.py`). This keeps observation in the eBPF layer while allowing detection and response logic to evolve without recompiling the kernel program.

## Build

```bash
make vmlinux
make
sudo ./build/loader eth0
```

`make vmlinux` generates `src/vmlinux.h` from the currently running kernel and normally needs to be run once for the target environment.

## Notes

- Requires a kernel with BTF support (`/sys/kernel/btf/vmlinux`).
- XDP behavior and performance depend on the network adapter, driver, kernel, and whether native or generic XDP mode is available.
- Virtual machines commonly use generic XDP, which is suitable for functional validation but should not be treated as representative of native-XDP production performance.
- A future passive IDS deployment connected to a mirror/TAP interface may evaluate TC ingress/egress programs where bidirectional direction metadata is required.
