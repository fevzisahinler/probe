#pragma once

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define TASK_COMM_LEN 16
#define MAX_FILENAME_LEN 256
#define CGROUP_NAME_LEN 128

#define CGROUP_MODE_V1 1
#define CGROUP_MODE_V2 2

#define EVENT_EXEC    1
#define EVENT_OPEN    2
#define EVENT_CHMOD   3
#define EVENT_CONNECT 4
#define EVENT_EXIT    5

// Set by userspace at load time: 1 = cgroup v1, 2 = cgroup v2.
const volatile __u32 cgroup_mode = 0;

struct event {
	__u64 timestamp_ns;
	__u32 pid;
	__u32 ppid;
	__u32 uid;
	__u32 mode;
	__u32 exit_code;
	__u32 flags;
	__u16 dport;
	__u16 family;
	__u8  type;
	__u8  daddr[16];
	__u8  comm[TASK_COMM_LEN];
	__u8  filename[MAX_FILENAME_LEN];
	__u8  cgroup[CGROUP_NAME_LEN];
};

// Kept in BTF so bpf2go can generate the matching Go type.
const struct event *unused __attribute__((unused));

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} events SEC(".maps");

// read_cgroup_name resolves the leaf cgroup name for both hierarchies: v2 uses
// the unified cgroup; v1 reads the memory controller's cgroup, whose subsystem
// index is resolved portably via BTF.
static __always_inline const char *read_cgroup_name(struct task_struct *task)
{
	struct css_set *cgroups = BPF_CORE_READ(task, cgroups);

	if (cgroup_mode == CGROUP_MODE_V1) {
		__u32 idx = bpf_core_enum_value(enum cgroup_subsys_id, memory_cgrp_id);
		struct cgroup_subsys_state *css = BPF_CORE_READ(cgroups, subsys[idx]);
		return BPF_CORE_READ(css, cgroup, kn, name);
	}

	return BPF_CORE_READ(cgroups, dfl_cgrp, kn, name);
}

// fill_common populates the fields shared by every event type and zeroes the
// type-specific ones.
static __always_inline void fill_common(struct event *e, __u8 type)
{
	e->type = type;
	e->mode = 0;
	e->exit_code = 0;
	e->flags = 0;
	e->dport = 0;
	e->family = 0;
	e->filename[0] = 0;
	__builtin_memset(e->daddr, 0, sizeof(e->daddr));

	e->timestamp_ns = bpf_ktime_get_ns();
	e->pid = bpf_get_current_pid_tgid() >> 32;
	e->uid = bpf_get_current_uid_gid();

	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	e->ppid = BPF_CORE_READ(task, real_parent, tgid);

	bpf_probe_read_kernel_str(&e->cgroup, sizeof(e->cgroup), read_cgroup_name(task));
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
}
