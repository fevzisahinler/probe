#pragma once

#include "common.bpf.h"
#include <bpf/bpf_endian.h>

#define AF_UNIX  1
#define AF_INET  2
#define AF_INET6 10

// connect(sockfd, addr, addrlen): args[1] is the userspace sockaddr. IPv4/IPv6
// record the peer address:port; AF_UNIX records the socket path in filename.
SEC("tracepoint/syscalls/sys_enter_connect")
int handle_connect(struct trace_event_raw_sys_enter *ctx)
{
	struct sockaddr *addr = (struct sockaddr *)ctx->args[1];
	__u16 family = 0;
	bpf_probe_read_user(&family, sizeof(family), &addr->sa_family);

	if (family != AF_INET && family != AF_INET6 && family != AF_UNIX)
		return 0;

	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	fill_common(e, EVENT_CONNECT);
	e->family = family;

	if (family == AF_INET) {
		struct sockaddr_in sin = {};
		bpf_probe_read_user(&sin, sizeof(sin), addr);
		e->dport = bpf_ntohs(sin.sin_port);
		__builtin_memcpy(e->daddr, &sin.sin_addr, 4);
	} else if (family == AF_INET6) {
		struct sockaddr_in6 sin6 = {};
		bpf_probe_read_user(&sin6, sizeof(sin6), addr);
		e->dport = bpf_ntohs(sin6.sin6_port);
		__builtin_memcpy(e->daddr, &sin6.sin6_addr, 16);
	} else {
		// sockaddr_un: sun_path starts at offset 2 (after sun_family).
		bpf_probe_read_user_str(&e->filename, sizeof(e->filename), (const char *)((char *)addr + 2));
	}

	bpf_ringbuf_submit(e, 0);
	return 0;
}
