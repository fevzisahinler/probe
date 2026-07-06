#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define TASK_COMM_LEN 16
#define MAX_FILENAME_LEN 256
#define CGROUP_NAME_LEN 128

#define CGROUP_MODE_V1 1
#define CGROUP_MODE_V2 2

#define EVENT_EXEC  1
#define EVENT_OPEN  2
#define EVENT_CHMOD 3

// Set by userspace at load time: 1 = cgroup v1, 2 = cgroup v2.
const volatile __u32 cgroup_mode = 0;

struct event {
	__u64 timestamp_ns;
	__u32 pid;
	__u32 ppid;
	__u32 uid;
	__u32 mode;
	__u8  type;
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

// fill_common populates the fields shared by every event type.
static __always_inline void fill_common(struct event *e, __u8 type)
{
	e->type = type;
	e->mode = 0;
	e->timestamp_ns = bpf_ktime_get_ns();
	e->pid = bpf_get_current_pid_tgid() >> 32;
	e->uid = bpf_get_current_uid_gid();

	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	e->ppid = BPF_CORE_READ(task, real_parent, tgid);

	bpf_probe_read_kernel_str(&e->cgroup, sizeof(e->cgroup), read_cgroup_name(task));
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
}

static __always_inline int emit_open(const char *filename)
{
	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	fill_common(e, EVENT_OPEN);
	bpf_probe_read_user_str(&e->filename, sizeof(e->filename), filename);

	bpf_ringbuf_submit(e, 0);
	return 0;
}

static __always_inline int emit_chmod(const char *filename, __u32 mode)
{
	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	fill_common(e, EVENT_CHMOD);
	e->mode = mode;
	bpf_probe_read_user_str(&e->filename, sizeof(e->filename), filename);

	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tracepoint/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx)
{
	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	fill_common(e, EVENT_EXEC);

	// Low 16 bits of __data_loc_filename hold the path's offset into the record.
	unsigned int off = ctx->__data_loc_filename & 0xFFFF;
	bpf_probe_read_kernel_str(&e->filename, sizeof(e->filename), (char *)ctx + off);

	bpf_ringbuf_submit(e, 0);
	return 0;
}

// open family — different libcs use different variants; hook all.
SEC("tracepoint/syscalls/sys_enter_open")
int handle_open(struct trace_event_raw_sys_enter *ctx)
{
	return emit_open((const char *)ctx->args[0]);
}

SEC("tracepoint/syscalls/sys_enter_openat")
int handle_openat(struct trace_event_raw_sys_enter *ctx)
{
	return emit_open((const char *)ctx->args[1]);
}

SEC("tracepoint/syscalls/sys_enter_openat2")
int handle_openat2(struct trace_event_raw_sys_enter *ctx)
{
	return emit_open((const char *)ctx->args[1]);
}

// chmod family — chmod(path, mode); fchmodat(dfd, path, mode, flags);
// fchmodat2(dfd, path, mode, flags). Hook all so musl and glibc are covered.
SEC("tracepoint/syscalls/sys_enter_chmod")
int handle_chmod(struct trace_event_raw_sys_enter *ctx)
{
	return emit_chmod((const char *)ctx->args[0], (__u32)ctx->args[1]);
}

SEC("tracepoint/syscalls/sys_enter_fchmodat")
int handle_fchmodat(struct trace_event_raw_sys_enter *ctx)
{
	return emit_chmod((const char *)ctx->args[1], (__u32)ctx->args[2]);
}

SEC("tracepoint/syscalls/sys_enter_fchmodat2")
int handle_fchmodat2(struct trace_event_raw_sys_enter *ctx)
{
	return emit_chmod((const char *)ctx->args[1], (__u32)ctx->args[2]);
}
