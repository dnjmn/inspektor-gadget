// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2024 Microsoft Corporation

#ifndef __IG_UDP_BIND_H
#define __IG_UDP_BIND_H

#include "common.h"

static __always_inline void handle_udp_bind(struct pt_regs *ctx,
					    struct sock *sk, struct sockaddr *addr)
{
	struct udp_sock_key_t tuple = {};
	struct event *event;
	u16 family;
	struct sockaddr_in *addr_in;
	struct sockaddr_in6 *addr_in6;


	if (filter_event(sk, bind))
		return;

	// User does not want to see successful events
	if (failure_only)
		return;

	family = BPF_CORE_READ(sk, __sk_common.skc_family);
	
	BPF_CORE_READ_INTO(&tuple.netns, sk, __sk_common.skc_net.net, ns.inum);

	switch (family) {
	case AF_INET:
		addr_in = (struct sockaddr_in *)addr;
		BPF_CORE_READ_INTO(&tuple.src.addr_raw.v4, addr_in, sin_addr.s_addr);
		BPF_CORE_READ_INTO(&tuple.src.port, addr_in, sin_port);
		tuple.src.port = bpf_ntohs(tuple.src.port);
		tuple.src.version = 4;
		
		// For bind, dst is typically not set or is zero
		tuple.dst.addr_raw.v4 = 0;
		tuple.dst.port = 0;
		tuple.dst.version = 4;
		break;
	case AF_INET6:
		addr_in6 = (struct sockaddr_in6 *)addr;
		BPF_CORE_READ_INTO(&tuple.src.addr_raw.v6, addr_in6, sin6_addr.in6_u.u6_addr32);
		BPF_CORE_READ_INTO(&tuple.src.port, addr_in6, sin6_port);
		tuple.src.port = bpf_ntohs(tuple.src.port);
		tuple.src.version = 6;
		
		// For bind, dst is typically not set or is zero
		__builtin_memset(&tuple.dst.addr_raw.v6, 0, sizeof(tuple.dst.addr_raw.v6));
		tuple.dst.port = 0;
		tuple.dst.version = 6;
		break;
	default:
		return;
	}

	tuple.src.proto_raw = tuple.dst.proto_raw = IPPROTO_UDP;

	event = gadget_reserve_buf(&events, sizeof(*event));
	if (!event)
		return;

	fill_event(event, &tuple, NULL, 0, bind, 0);

	gadget_submit_buf(ctx, &events, event, sizeof(*event));
}

static __always_inline int handle_sys_bind_x(struct syscall_trace_exit *ctx)
{
	__u32 tid = bpf_get_current_pid_tgid();
	bpf_map_delete_elem(&udp_tid_fd, &tid);
	return 0;
}

#endif // __IG_UDP_BIND_H