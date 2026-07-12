"""ebpf_sensor.py — native Linux kernel telemetry via eBPF/BCC (CODE: EBPF).

For a headless Linux sensor node. Hooks process creation (execve) and outbound
TCP (tcp_sendmsg) in-kernel with BCC, streams events to user space over a perf
buffer, translates them into Angerona ``Event`` objects, and drops them on the
EventBus — where the Remote Bridge (RBRG) forwards them to the main Windows GUI.

OFF by default and Linux-only. On Windows, or a Linux host without BCC / kernel
headers / root, it degrades to health 10% and idles — it never crashes the thread.
"""
from __future__ import annotations

import os
import sys
from typing import Optional

from angerona.core.module_base import BaseModule, Severity


# ── Inline eBPF C (compiled by BCC in-kernel) ─────────────────────────────────
_BPF_C = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <net/sock.h>
#include <bcc/proto.h>

// ---- process creation (execve) ----
struct exec_evt {
    u32 pid;
    u32 uid;
    char comm[TASK_COMM_LEN];
    char argv0[128];
};
BPF_PERF_OUTPUT(exec_events);

int trace_execve(struct pt_regs *ctx, const char __user *filename,
                 const char __user *const __user *__argv,
                 const char __user *const __user *__envp) {
    struct exec_evt e = {};
    e.pid = bpf_get_current_pid_tgid() >> 32;
    e.uid = bpf_get_current_uid_gid() & 0xffffffff;
    bpf_get_current_comm(&e.comm, sizeof(e.comm));
    bpf_probe_read_user_str(&e.argv0, sizeof(e.argv0), (void *)filename);

    // Drop the noisiest trusted daemons at the kernel level.
    if (e.comm[0] == 's' && e.comm[1] == 'y' && e.comm[2] == 's') return 0; // systemd*
    exec_events.perf_submit(ctx, &e, sizeof(e));
    return 0;
}

// ---- outbound TCP (tcp_sendmsg) ----
struct net_evt {
    u32 pid;
    u32 daddr;         // IPv4 (network byte order); 0 for IPv6
    u16 dport;
    u8  v6;
    char comm[TASK_COMM_LEN];
};
BPF_PERF_OUTPUT(net_events);

int trace_tcp_sendmsg(struct pt_regs *ctx, struct sock *sk) {
    struct net_evt e = {};
    e.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&e.comm, sizeof(e.comm));
    u16 family = 0;
    bpf_probe_read_kernel(&family, sizeof(family), &sk->__sk_common.skc_family);
    bpf_probe_read_kernel(&e.dport, sizeof(e.dport), &sk->__sk_common.skc_dport);
    e.dport = ntohs(e.dport);
    if (family == AF_INET) {
        bpf_probe_read_kernel(&e.daddr, sizeof(e.daddr), &sk->__sk_common.skc_daddr);
        e.v6 = 0;
    } else {
        e.v6 = 1;  // IPv6 address omitted for brevity; PID/port still forwarded
    }
    net_events.perf_submit(ctx, &e, sizeof(e));
    return 0;
}
"""


class EbpfSensorNode(BaseModule):
    name = "Linux eBPF Sensor"
    CODE = "EBPF"
    description = ("Native Linux kernel telemetry (execve + tcp_sendmsg) via BCC/eBPF; "
                   "forwards to the main instance over the Remote Bridge. Linux-only, opt-in.")
    category = "Sensor"
    version = "1.0.0"
    # Thread runs but self-gates on config.ebpf_enabled so the Settings toggle
    # takes effect without a restart. Inert (healthy) on non-Linux hosts.
    enabled_by_default = True

    def __init__(self) -> None:
        super().__init__()
        self._config = None
        self._bpf = None

    def bind_manager(self, manager) -> None:
        self._config = getattr(manager, "config", None)

    def _enabled(self) -> bool:
        return bool(getattr(self._config, "ebpf_enabled", False))

    # ── perf-buffer callbacks (translate BPF structs → Angerona Events) ────────
    def _on_exec(self, cpu, data, size) -> None:
        try:
            e = self._bpf["exec_events"].event(data)
            comm = e.comm.decode("utf-8", "replace")
            argv0 = e.argv0.decode("utf-8", "replace")
            self.emit(f"exec: {comm} ({argv0}) pid={e.pid} uid={e.uid}",
                      Severity.INFO, kind="execve", pid=int(e.pid), uid=int(e.uid),
                      comm=comm, path=argv0)
        except Exception:
            pass

    def _on_net(self, cpu, data, size) -> None:
        try:
            import socket
            import struct
            e = self._bpf["net_events"].event(data)
            comm = e.comm.decode("utf-8", "replace")
            if e.v6:
                dst = "(IPv6)"
            else:
                dst = socket.inet_ntoa(struct.pack("I", e.daddr))
            self.emit(f"connect: {comm} → {dst}:{e.dport} pid={e.pid}",
                      Severity.INFO, kind="tcp_sendmsg", pid=int(e.pid),
                      comm=comm, raddr=dst, rport=int(e.dport))
        except Exception:
            pass

    # ── Loop ────────────────────────────────────────────────────────────────────
    def run(self) -> None:
        if not sys.platform.startswith("linux"):
            # Healthy-inert on Windows so it doesn't count as a degraded module.
            self.set_health(100, "inert — eBPF is Linux-only")
            while not self.stopping:
                self.sleep(30)
            return

        # Wait until enabled; poll cheaply so toggling it on works without restart.
        while not self.stopping and not self._enabled():
            self.set_health(100, "disabled (enable in Settings ▸ System ▸ eBPF)")
            self.sleep(5)
        if self.stopping:
            return

        if os.geteuid() != 0:
            self.set_health(10, "eBPF requires root — sensor inactive")
            while not self.stopping:
                self.sleep(30)
            return

        try:
            from bcc import BPF
            self._bpf = BPF(text=_BPF_C)
            self._bpf.attach_kprobe(event=self._bpf.get_syscall_fnname("execve"),
                                    fn_name="trace_execve")
            self._bpf.attach_kprobe(event="tcp_sendmsg", fn_name="trace_tcp_sendmsg")
            self._bpf["exec_events"].open_perf_buffer(self._on_exec)
            self._bpf["net_events"].open_perf_buffer(self._on_net)
        except Exception as exc:
            self.set_health(10, f"BCC/eBPF unavailable ({exc}) — sensor inactive")
            self._bpf = None
            while not self.stopping:
                self.sleep(30)
            return

        self.emit("eBPF sensor online — kernel execve + tcp_sendmsg hooks attached.",
                  Severity.INFO)
        try:
            while not self.stopping:
                if not self._enabled():
                    break
                try:
                    self._bpf.perf_buffer_poll(timeout=1000)
                    self.set_health(100, "streaming kernel telemetry")
                except Exception as exc:
                    self.set_health(50, f"perf poll error: {exc}")
                    self.sleep(1)
        finally:
            # Detach probes + free BPF maps so nothing leaks across a restart.
            try:
                if self._bpf is not None:
                    self._bpf.cleanup()
            except Exception:
                pass
            self._bpf = None

    def self_test(self) -> tuple[bool, str]:
        if not sys.platform.startswith("linux"):
            return True, "inert (Linux-only)"
        if not self._enabled():
            return True, "disabled (opt-in)"
        try:
            import bcc  # noqa: F401
            return True, "BCC available"
        except Exception:
            return False, "BCC not installed"


def register() -> BaseModule:
    return EbpfSensorNode()
