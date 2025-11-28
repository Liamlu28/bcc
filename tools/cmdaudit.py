#!/usr/bin/env python
# @lint-avoid-python-3-compatibility-imports
#
# cmdaudit  Trace execve/execveat along with optional bash readline input.
#           Build/Run: sudo ./cmdaudit.py [--pid PID] [--comm COMM]
#                      [--no-bashreadline] [--json]
#           Example:   sudo ./cmdaudit.py --comm sshd
#
# This ships as a single Python tool that embeds its eBPF program. An optional
# reference C source lives in tools/cmdaudit.c for standalone builds.
#
# Copyright (c) 2024 Netflix, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

from __future__ import print_function

import argparse
import json
import os
import sys
import time

from bcc import BPF
from elftools.elf.elffile import ELFFile


EXAMPLES = """examples:
    ./cmdaudit.py                          # trace execve/execveat + bash readline
    ./cmdaudit.py --pid 1234               # filter to a single PID
    ./cmdaudit.py --comm sshd              # filter to a single comm
    ./cmdaudit.py --no-bashreadline        # disable readline tracing
"""

parser = argparse.ArgumentParser(
    description="Audit execve/execveat and bash readline input, output JSON",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=EXAMPLES,
)
parser.add_argument(
    "--pid", type=int, help="filter by PID (tgid) in user space", default=None
)
parser.add_argument(
    "--comm", help="filter by task comm in user space (exact match)", default=None
)
parser.add_argument(
    "--json",
    dest="json",
    action="store_true",
    default=True,
    help="emit JSON output (default on)",
)
parser.add_argument(
    "--plain",
    dest="json",
    action="store_false",
    help="print a compact text line instead of JSON",
)
parser.add_argument(
    "--no-bashreadline",
    action="store_true",
    help="skip uretprobe on bash readline; only exec events",
)
parser.add_argument(
    "--readline-lib",
    default="/lib/libreadline.so",
    help="path to libreadline.so when readline symbol is missing from /bin/bash",
)
args = parser.parse_args()


def _readline_symbol(pathname):
    """Return the best readline symbol for the target binary."""
    try:
        with open(pathname, "rb") as elf_fd:
            elf = ELFFile(elf_fd)
            symbol_table = elf.get_section_by_name(".dynsym")
            if not symbol_table:
                return "readline"
            for symbol in symbol_table.iter_symbols():
                if symbol.name == "readline_internal_teardown":
                    return "readline_internal_teardown"
    except IOError as err:
        print(
            "cmdaudit: unable to read {} ({}), falling back to readline".format(
                pathname, err
            ),
            file=sys.stderr,
        )
    return "readline"


bpf_program = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/tty.h>

#define MAX_ARGS 10
#define ARG_LEN 128
#define FILENAME_LEN 256

struct event_t {
    u32 pid;
    u32 ppid;
    u32 uid;
    char comm[TASK_COMM_LEN];
    char filename[FILENAME_LEN];
    char argv[MAX_ARGS][ARG_LEN];
    int argc;
    char tty[32];
    u64 ts;
};

BPF_PERCPU_ARRAY(event_heap, struct event_t, 1);
BPF_PERF_OUTPUT(events);

static __always_inline struct event_t *reserve_event(void)
{
    int zero = 0;
    struct event_t *event = event_heap.lookup(&zero);
    if (!event)
        return NULL;
    __builtin_memset(event, 0, sizeof(*event));
    return event;
}

static __always_inline void fill_metadata(struct event_t *event)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct task_struct *parent = NULL;
    struct signal_struct *signal = NULL;
    struct tty_struct *tty = NULL;

    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->uid = (u32)bpf_get_current_uid_gid();
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    event->ts = bpf_ktime_get_ns();

    bpf_probe_read_kernel(&parent, sizeof(parent), &task->real_parent);
    if (parent)
        bpf_probe_read_kernel(&event->ppid, sizeof(event->ppid), &parent->tgid);

    bpf_probe_read_kernel(&signal, sizeof(signal), &task->signal);
    if (signal) {
        bpf_probe_read_kernel(&tty, sizeof(tty), &signal->tty);
        if (tty)
            bpf_probe_read_kernel_str(event->tty, sizeof(event->tty), tty->name);
    }
}

static __always_inline void copy_argv(struct event_t *event, const char __user *const __user *argv)
{
    #pragma unroll
    for (int i = 0; i < MAX_ARGS; i++) {
        const char *argp = NULL;
        bpf_probe_read_user(&argp, sizeof(argp), &argv[i]);
        if (!argp)
            break;
        if (bpf_probe_read_user_str(event->argv[event->argc],
                                    sizeof(event->argv[event->argc]),
                                    argp) > 0) {
            event->argc++;
        }
    }
}

static __always_inline int emit_exec(struct pt_regs *ctx, const char __user *filename,
                                     const char __user *const __user *argv)
{
    struct event_t *event = reserve_event();
    if (!event)
        return 0;

    fill_metadata(event);
    bpf_probe_read_user_str(event->filename, sizeof(event->filename), filename);
    copy_argv(event, argv);

    events.perf_submit(ctx, event, sizeof(*event));
    return 0;
}

int handle_execve(struct pt_regs *ctx, const char __user *filename,
                  const char __user *const __user *argv,
                  const char __user *const __user *envp)
{
    return emit_exec(ctx, filename, argv);
}

int handle_execveat(struct pt_regs *ctx, int dfd, const char __user *filename,
                    const char __user *const __user *argv,
                    const char __user *const __user *envp)
{
    return emit_exec(ctx, filename, argv);
}

int handle_readline(struct pt_regs *ctx)
{
    const char *line = (const char *)PT_REGS_RC(ctx);
    if (!line)
        return 0;

    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(&comm, sizeof(comm));
    if (!(comm[0] == 'b' && comm[1] == 'a' && comm[2] == 's' &&
          comm[3] == 'h' && comm[4] == 0))
        return 0;

    struct event_t *event = reserve_event();
    if (!event)
        return 0;

    fill_metadata(event);
    __builtin_memcpy(event->filename, "bash", 4);
    if (bpf_probe_read_user_str(event->argv[0], sizeof(event->argv[0]), line) > 0)
        event->argc = 1;

    events.perf_submit(ctx, event, sizeof(*event));
    return 0;
}
"""


def decode_bytes(raw):
    return raw.decode("utf-8", "replace").rstrip("\x00")


def build_record(event):
    argv = []
    for arg in event.argv:
        value = decode_bytes(bytes(arg))
        if value:
            argv.append(value)
    record = {
        "pid": event.pid,
        "ppid": event.ppid,
        "uid": event.uid,
        "comm": decode_bytes(bytes(event.comm)),
        "tty": decode_bytes(bytes(event.tty)),
        "filename": decode_bytes(bytes(event.filename)),
        "argv": argv,
        "ts": event.ts // 1000000000,
    }
    if args.pid and record["pid"] != args.pid:
        return None
    if args.comm and record["comm"] != args.comm:
        return None
    return record


def print_event(cpu, data, size):
    event = b["events"].event(data)
    record = build_record(event)
    if not record:
        return
    if args.json:
        print(json.dumps(record, sort_keys=False, indent=2))
    else:
        print(
            "{ts} pid={pid} ppid={ppid} uid={uid} comm={comm} filename={filename} argv={argv} tty={tty}".format(
                ts=record["ts"],
                pid=record["pid"],
                ppid=record["ppid"],
                uid=record["uid"],
                comm=record["comm"],
                filename=record["filename"],
                argv=" ".join(record["argv"]),
                tty=record["tty"],
            )
        )


def attach_readline_probe(bpf):
    bash_path = "/bin/bash"
    target = bash_path if os.path.exists(bash_path) else args.readline_lib
    symbol = _readline_symbol(target)
    try:
        bpf.attach_uretprobe(name=target, sym=symbol, fn_name="handle_readline")
    except Exception as err:
        print(
            "cmdaudit: failed to attach readline uretprobe ({}); continuing without readline".format(
                err
            ),
            file=sys.stderr,
        )


b = BPF(text=bpf_program)
try:
    b.attach_kprobe(event=b.get_syscall_fnname("execve"), fn_name="handle_execve")
except Exception as err:
    print("cmdaudit: failed to attach execve kprobe: {}".format(err), file=sys.stderr)
    sys.exit(1)
try:
    b.attach_kprobe(event=b.get_syscall_fnname("execveat"), fn_name="handle_execveat")
except Exception as err:
    print(
        "cmdaudit: failed to attach execveat kprobe ({}); continuing without execveat".format(
            err
        ),
        file=sys.stderr,
    )

if not args.no_bashreadline:
    attach_readline_probe(b)

b["events"].open_perf_buffer(print_event)

while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        sys.exit(0)
