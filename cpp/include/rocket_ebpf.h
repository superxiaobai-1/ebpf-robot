#ifndef ROCKET_EBPF_H
#define ROCKET_EBPF_H

#include <linux/types.h>

#define ROCKET_COMM_LEN 16
#define ROCKET_PATH_LEN 256

enum rocket_event_kind {
    ROCKET_EVENT_EXEC = 1,
    ROCKET_EVENT_OPENAT = 2,
};

struct rocket_trace_event {
    __u32 kind;
    __u32 pid;
    __u32 tgid;
    char comm[ROCKET_COMM_LEN];
    char path[ROCKET_PATH_LEN];
};

struct rocket_func_hz_cpu {
    __u64 hits;
};

struct rocket_func_hz_gap {
    __u64 last_ts_ns;
    __u64 max_gap_ns;
};

struct rocket_func_latency_agg {
    __u64 count;
    __u64 sum_ns;
    __u64 min_ns;
    __u64 max_ns;
};

struct rocket_sched_config {
    __u64 threshold_ns;
    __u32 include_prev;
    __u32 pad;
};

struct rocket_sched_event {
    __u64 ktime_ns;
    __u64 latency_ns;
    __u32 tid;
    __u32 cpu;
    __u32 prev_tid;
    char prev_comm[ROCKET_COMM_LEN];
};

#endif
