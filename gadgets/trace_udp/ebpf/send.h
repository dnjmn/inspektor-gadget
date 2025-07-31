// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2024 Microsoft Corporation

#ifndef __IG_UDP_SEND_H
#define __IG_UDP_SEND_H

#include "common.h"

static __always_inline int handle_sys_sendto_x(struct syscall_trace_exit *ctx)
{
	__u32 tid = bpf_get_current_pid_tgid();
	struct event *event;
	int ret = ctx->ret;
	int *fd_ptr;
	int fd = -1;

	if (filter_event(send))
		goto cleanup;

	fd_ptr = bpf_map_lookup_elem(&udp_tid_fd, &tid);
	if (fd_ptr)
		fd = *fd_ptr;

	// User does not want to see successful events
	if (failure_only && ret >= 0)
		goto cleanup;

	event = gadget_reserve_buf(&events, sizeof(*event));
	if (!event)
		goto cleanup;

	fill_event(event, send, fd, ret > 0 ? ret : 0, ret < 0 ? -ret : 0);

	gadget_submit_buf(ctx, &events, event, sizeof(*event));

cleanup:
	bpf_map_delete_elem(&udp_tid_fd, &tid);
	return 0;
}

#endif // __IG_UDP_SEND_H