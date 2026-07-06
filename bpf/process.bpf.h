#pragma once

#include "common.bpf.h"

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

// exit — only report the thread-group leader (the real process exit), not each
// thread. The exit code lives in task_struct, not the tracepoint context.
SEC("tracepoint/sched/sched_process_exit")
int handle_exit(struct trace_event_raw_sched_process_template *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	if ((__u32)(id >> 32) != (__u32)id)
		return 0;

	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	fill_common(e, EVENT_EXIT);

	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	e->exit_code = BPF_CORE_READ(task, exit_code);

	bpf_ringbuf_submit(e, 0);
	return 0;
}
