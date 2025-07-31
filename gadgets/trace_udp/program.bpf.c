// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2024 Microsoft Corporation
//
// Based on trace_tcp implementation and UDP tracing techniques

#include "ebpf/bind.h"
#include "ebpf/recv.h"
#include "ebpf/send.h"
#include "ebpf/common.h"

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