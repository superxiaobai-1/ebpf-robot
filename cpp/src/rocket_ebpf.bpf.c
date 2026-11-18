#include "rocket_ebpf.h"

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#ifdef ROCKET_ORIN_R36_RT
/* Jetson AGX Orin, L4T R36.4.4, Linux 5.15.148-rt-tegra. */
#define EXEC_DATA_LOC_OFF 12
#define EXEC_PID_OFF 16
#define SCHED_WAKE_PID_OFF 28
#define SCHED_SWITCH_PREV_COMM_OFF 12
#define SCHED_SWITCH_PREV_PID_OFF 28
#define SCHED_SWITCH_NEXT_PID_OFF 64
#else
/* Original project's x86_64 layout. */
#define EXEC_DATA_LOC_OFF 8
#define EXEC_PID_OFF 12
#define SCHED_WAKE_PID_OFF 24
#define SCHED_SWITCH_PREV_COMM_OFF 8
#define SCHED_SWITCH_PREV_PID_OFF 24
#define SCHED_SWITCH_NEXT_PID_OFF 56
#endif

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 4096);
} trace_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct rocket_func_hz_cpu);
} func_hz_stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct rocket_func_hz_gap);
} func_hz_gap SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, __u64);
    __type(value, __u64);
} func_lat_start SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct rocket_func_latency_agg);
} func_lat_agg SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct rocket_sched_config);
} sched_lat_config SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, __u32);
    __type(value, __u8);
} sched_lat_filter SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, __u32);
    __type(value, __u64);
} sched_lat_wake_ns SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 4096);
} sched_lat_events SEC(".maps");

SEC("tracepoint/sched/sched_process_exec")
int sched_process_exec(void *ctx)
{
    const char *base = ctx;
    struct rocket_trace_event *event;
    __u32 data_loc = 0;
    __u32 str_off;
    __u64 id;
    int pid = -1;

    bpf_probe_read_kernel(&data_loc, sizeof(data_loc), base + EXEC_DATA_LOC_OFF);
    str_off = data_loc & 0xffff;
    if (str_off > 2047)
        return 0;

    event = bpf_ringbuf_reserve(&trace_events, sizeof(*event), 0);
    if (!event)
        return 0;
    __builtin_memset(event, 0, sizeof(*event));
    bpf_probe_read_kernel(&pid, sizeof(pid), base + EXEC_PID_OFF);
    id = bpf_get_current_pid_tgid();
    event->kind = ROCKET_EVENT_EXEC;
    event->pid = pid > 0 ? (__u32)pid : 0;
    event->tgid = id >> 32;
    bpf_get_current_comm(event->comm, sizeof(event->comm));
    bpf_probe_read_kernel_str(event->path, sizeof(event->path), base + str_off);
    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int sys_enter_openat(void *ctx)
{
    struct rocket_trace_event *event;
    __u64 id = bpf_get_current_pid_tgid();

    (void)ctx;
    event = bpf_ringbuf_reserve(&trace_events, sizeof(*event), 0);
    if (!event)
        return 0;
    __builtin_memset(event, 0, sizeof(*event));
    event->kind = ROCKET_EVENT_OPENAT;
    event->pid = (__u32)id;
    event->tgid = id >> 32;
    bpf_get_current_comm(event->comm, sizeof(event->comm));
    bpf_ringbuf_submit(event, 0);
    return 0;
}

SEC("uprobe/func_hz_hit")
int func_hz_hit(void *ctx)
{
    __u32 zero = 0;
    __u64 now = bpf_ktime_get_ns();
    struct rocket_func_hz_cpu *cpu;
    struct rocket_func_hz_gap *gap;

    (void)ctx;
    cpu = bpf_map_lookup_elem(&func_hz_stats, &zero);
    if (cpu)
        cpu->hits++;
    gap = bpf_map_lookup_elem(&func_hz_gap, &zero);
    if (gap) {
        if (gap->last_ts_ns) {
            __u64 delta = now - gap->last_ts_ns;
            if (delta > gap->max_gap_ns)
                gap->max_gap_ns = delta;
        }
        gap->last_ts_ns = now;
    }
    return 0;
}

SEC("uprobe/func_lat_entry")
int func_lat_entry(void *ctx)
{
    __u64 id = bpf_get_current_pid_tgid();
    __u64 now = bpf_ktime_get_ns();
    (void)ctx;
    bpf_map_update_elem(&func_lat_start, &id, &now, BPF_ANY);
    return 0;
}

SEC("uretprobe/func_lat_ret")
int func_lat_ret(void *ctx)
{
    __u32 zero = 0;
    __u64 id = bpf_get_current_pid_tgid();
    __u64 *start;
    __u64 latency;
    struct rocket_func_latency_agg *agg;

    (void)ctx;
    start = bpf_map_lookup_elem(&func_lat_start, &id);
    if (!start)
        return 0;
    latency = bpf_ktime_get_ns() - *start;
    bpf_map_delete_elem(&func_lat_start, &id);
    agg = bpf_map_lookup_elem(&func_lat_agg, &zero);
    if (!agg)
        return 0;
    if (!agg->count) {
        agg->min_ns = latency;
        agg->max_ns = latency;
    } else {
        if (latency < agg->min_ns)
            agg->min_ns = latency;
        if (latency > agg->max_ns)
            agg->max_ns = latency;
    }
    agg->count++;
    agg->sum_ns += latency;
    return 0;
}

SEC("tracepoint/sched/sched_waking")
int sched_lat_waking(void *ctx)
{
    const char *base = ctx;
    __u32 tid;
    __u64 now;
    int pid = -1;

    bpf_probe_read_kernel(&pid, sizeof(pid), base + SCHED_WAKE_PID_OFF);
    if (pid <= 0)
        return 0;
    tid = pid;
    if (!bpf_map_lookup_elem(&sched_lat_filter, &tid))
        return 0;
    now = bpf_ktime_get_ns();
    bpf_map_update_elem(&sched_lat_wake_ns, &tid, &now, BPF_ANY);
    return 0;
}

SEC("tracepoint/sched/sched_switch")
int sched_lat_switch(void *ctx)
{
    const char *base = ctx;
    struct rocket_sched_config *config;
    struct rocket_sched_event *event;
    __u32 zero = 0;
    __u32 tid;
    __u64 *wake;
    __u64 now;
    __u64 latency;
    int next_pid = -1;

    bpf_probe_read_kernel(&next_pid, sizeof(next_pid), base + SCHED_SWITCH_NEXT_PID_OFF);
    if (next_pid <= 0)
        return 0;
    tid = next_pid;
    if (!bpf_map_lookup_elem(&sched_lat_filter, &tid))
        return 0;
    wake = bpf_map_lookup_elem(&sched_lat_wake_ns, &tid);
    if (!wake)
        return 0;
    now = bpf_ktime_get_ns();
    latency = now - *wake;
    bpf_map_delete_elem(&sched_lat_wake_ns, &tid);
    config = bpf_map_lookup_elem(&sched_lat_config, &zero);
    if (!config || latency <= config->threshold_ns)
        return 0;

    event = bpf_ringbuf_reserve(&sched_lat_events, sizeof(*event), 0);
    if (!event)
        return 0;
    __builtin_memset(event, 0, sizeof(*event));
    event->ktime_ns = now;
    event->latency_ns = latency;
    event->tid = tid;
    event->cpu = bpf_get_smp_processor_id();
    if (config->include_prev) {
        int prev_pid = -1;
        bpf_probe_read_kernel(event->prev_comm, sizeof(event->prev_comm),
                              base + SCHED_SWITCH_PREV_COMM_OFF);
        bpf_probe_read_kernel(&prev_pid, sizeof(prev_pid),
                              base + SCHED_SWITCH_PREV_PID_OFF);
        if (prev_pid > 0)
            event->prev_tid = prev_pid;
    }
    bpf_ringbuf_submit(event, 0);
    return 0;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
