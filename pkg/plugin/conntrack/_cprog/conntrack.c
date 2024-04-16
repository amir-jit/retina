// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

#include "vmlinux.h"
#include "bpf_helpers.h"

struct conn_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8 protocol;
} __attribute__((packed));

struct conn_value {
    __u64 timestamp;
    __u32 flags;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct conn_key);
    __type(value, struct conn_value);
    __uint(max_entries, 4096);
    __uint(pinning, LIBBPF_PIN_BY_NAME); // Pinned to /sys/fs/bpf.
} conntrack_map SEC(".maps");


void process_packet(struct conn_key *key, __u8 tcp_flags)
{
    struct conn_value *value;

    value = bpf_map_lookup_elem(&conntrack_map, key);
    if (!value) {
        // If the connection is not in the map, add it.
        struct conn_value new_value = {
            .timestamp = bpf_ktime_get_ns(),
            .flags = tcp_flags,
        };
        bpf_map_update_elem(&conntrack_map, key, &new_value, BPF_NOEXIST);
    } else {
        // If the connection is in the map, update the flags.
        value->flags |= tcp_flags;
        // Update the timestamp.
        value->timestamp = bpf_ktime_get_ns();
    }
}

bool check_flags(struct conn_key *key, __u32 packet_flags)
{
    struct conn_value *value;

    value = bpf_map_lookup_elem(&conntrack_map, key);
    if (!value)
        return false; // If the connection is not in the map, return false.

    if ((value->flags & packet_flags) == packet_flags)
        return true; // If all flags in packet_flags have been seen before, return true.

    return false; // If not all flags in packet_flags have been seen before, return false.
}