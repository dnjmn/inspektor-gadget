// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2024 Microsoft Corporation
//
// Based on trace_tcp implementation and UDP tracing techniques

#include "ebpf/bind.h"
#include "ebpf/recv.h"
#include "ebpf/send.h"
#include "ebpf/common.h"

struct socket_args {
	int domain;
	int type;
	int protocol;
};

/*
 * Hash tid->socket_args to track socket creation arguments
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, __u32); // tid
	__type(value, struct socket_args);
} socket_create_args SEC(".maps");

// Track socket creation to identify UDP sockets

SEC("tracepoint/syscalls/sys_enter_socket")
int sys_socket_e(struct syscall_trace_enter *ctx)
{
	__u32 tid = bpf_get_current_pid_tgid();
	struct socket_args args = {};
	
	args.domain = ctx->args[0];    // AF_INET or AF_INET6
	args.type = ctx->args[1];      // SOCK_DGRAM for UDP
	args.protocol = ctx->args[2];  // IPPROTO_UDP or 0
	
	bpf_map_update_elem(&socket_create_args, &tid, &args, 0);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_socket")
int sys_socket_x(struct syscall_trace_exit *ctx)
{
	__u32 tid = bpf_get_current_pid_tgid();
	struct socket_args *args;
	int ret = ctx->ret;
	
	if (ret < 0)
		goto cleanup;  // Socket creation failed
	
	args = bpf_map_lookup_elem(&socket_create_args, &tid);
	if (!args)
		goto cleanup;
	
	// Check if it's a UDP socket: domain is AF_INET/AF_INET6, type is SOCK_DGRAM
	if ((args->domain == AF_INET || args->domain == AF_INET6) && 
	    args->type == SOCK_DGRAM) {
		track_udp_socket(ret);
	}
	
cleanup:
	bpf_map_delete_elem(&socket_create_args, &tid);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_close")
int sys_close_e(struct syscall_trace_enter *ctx)
{
	int fd = (__u32)ctx->args[0];
	
	// Remove socket from tracking when it's closed
	untrack_udp_socket(fd);
	
	return 0;
}

// Syscall tracepoints for UDP send events

SEC("tracepoint/syscalls/sys_enter_sendto")
int sys_sendto_e(struct syscall_trace_enter *ctx)
{
	return update_udp_tid_fd_map((__u32)ctx->args[0]);
}

SEC("tracepoint/syscalls/sys_exit_sendto")
int sys_sendto_x(struct syscall_trace_exit *ctx)
{
	return handle_sys_sendto_x(ctx);
}

SEC("tracepoint/syscalls/sys_enter_sendmsg")
int sys_sendmsg_e(struct syscall_trace_enter *ctx)
{
	return update_udp_tid_fd_map((__u32)ctx->args[0]);
}

SEC("tracepoint/syscalls/sys_exit_sendmsg")
int sys_sendmsg_x(struct syscall_trace_exit *ctx)
{
	return handle_sys_sendto_x(ctx);
}

// Syscall tracepoints for UDP receive events

SEC("tracepoint/syscalls/sys_enter_recvfrom")
int sys_recvfrom_e(struct syscall_trace_enter *ctx)
{
	return update_udp_tid_fd_map((__u32)ctx->args[0]);
}

SEC("tracepoint/syscalls/sys_exit_recvfrom")
int sys_recvfrom_x(struct syscall_trace_exit *ctx)
{
	return handle_sys_recvfrom_x(ctx);
}

SEC("tracepoint/syscalls/sys_enter_recvmsg")
int sys_recvmsg_e(struct syscall_trace_enter *ctx)
{
	return update_udp_tid_fd_map((__u32)ctx->args[0]);
}

SEC("tracepoint/syscalls/sys_exit_recvmsg")
int sys_recvmsg_x(struct syscall_trace_exit *ctx)
{
	return handle_sys_recvfrom_x(ctx);
}

// Syscall tracepoints for UDP bind events

SEC("tracepoint/syscalls/sys_enter_bind")
int sys_bind_e(struct syscall_trace_enter *ctx)
{
	return update_udp_tid_fd_map((__u32)ctx->args[0]);
}

SEC("tracepoint/syscalls/sys_exit_bind")
int sys_bind_x(struct syscall_trace_exit *ctx)
{
	return handle_sys_bind_x(ctx);
}

char LICENSE[] SEC("license") = "GPL";