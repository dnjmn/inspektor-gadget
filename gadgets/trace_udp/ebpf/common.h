// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2024 Microsoft Corporation

#ifndef __IG_UDP_COMMON_H
#define __IG_UDP_COMMON_H

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

#include <gadget/buffer.h>
#include <gadget/common.h>
#include <gadget/filter.h>
#include <gadget/macros.h>
#include <gadget/mntns_filter.h>
#include <gadget/types.h>

/* The maximum number of items in maps */
#define MAX_ENTRIES 8192

enum event_type : u8 {
	send,
	recv,
	bind,
};

struct event {
	gadget_timestamp timestamp_raw;
	struct gadget_process proc;
	gadget_netns_id netns_id;

	struct gadget_l4endpoint_t src;
	struct gadget_l4endpoint_t dst;

	enum event_type type_raw;
	gadget_errno error_raw;
	int fd;
	u32 bytes;
};

/*
 * Hash tid->fd between enter/exit UDP syscalls
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, __u32); // tid
	__type(value, int); // fd
} udp_tid_fd SEC(".maps");

/*
 * Hash fd->1 to track UDP sockets
 * We store 1 for UDP sockets, delete entry when socket is closed
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, int); // fd
	__type(value, __u8); // 1 for UDP socket
} udp_sockets SEC(".maps");

const volatile bool send_only = false;
const volatile bool recv_only = false;
const volatile bool bind_only = false;
const volatile bool failure_only = false;

GADGET_PARAM(send_only);
GADGET_PARAM(recv_only);
GADGET_PARAM(bind_only);
GADGET_PARAM(failure_only);

/* Define here, because there are conflicts with include files */
#define AF_INET 2
#define AF_INET6 10
#define SOCK_DGRAM 2

// we need this to make sure the compiler doesn't remove our struct
const enum event_type unused_eventtype __attribute__((unused));

GADGET_TRACER_MAP(events, 1024 * 256);
GADGET_TRACER(traceudp, events, event);

/* returns true if the event should be skipped */
static __always_inline bool filter_event(enum event_type type)
{
	if (send_only && type != send)
		return true;
	if (recv_only && type != recv)
		return true;
	if (bind_only && type != bind)
		return true;

	return gadget_should_discard_data_current();
}

static __always_inline bool is_udp_socket(int fd)
{
	__u8 *val = bpf_map_lookup_elem(&udp_sockets, &fd);
	return val != NULL;
}

static __always_inline void fill_event(struct event *event,
				       enum event_type type, int fd, 
				       u32 bytes, int err)
{
	event->timestamp_raw = bpf_ktime_get_boot_ns();
	event->type_raw = type;
	event->error_raw = err;
	event->fd = fd;
	event->bytes = bytes;
	gadget_process_populate(&event->proc);
	
	// Initialize endpoints - will be filled by caller if available
	event->src.version = 0;
	event->dst.version = 0;
	event->src.port = 0;
	event->dst.port = 0;
	event->src.proto_raw = IPPROTO_UDP;
	event->dst.proto_raw = IPPROTO_UDP;
}

static __always_inline int update_udp_tid_fd_map(__u32 fd)
{
	__u32 tid = bpf_get_current_pid_tgid();
	bpf_map_update_elem(&udp_tid_fd, &tid, &fd, 0);
	return 0;
}

static __always_inline void track_udp_socket(int fd)
{
	__u8 val = 1;
	bpf_map_update_elem(&udp_sockets, &fd, &val, 0);
}

static __always_inline void untrack_udp_socket(int fd)
{
	bpf_map_delete_elem(&udp_sockets, &fd);
}

#endif // __IG_UDP_COMMON_H