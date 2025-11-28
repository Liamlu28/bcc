/*
 * cmdaudit.c
 * Standalone eBPF program used by tools/cmdaudit.py.
 * Build via BCC: clang -O2 -target bpf -c tools/cmdaudit.c -o /tmp/cmdaudit.o
 */
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
