#pragma once

#include "common.bpf.h"

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
