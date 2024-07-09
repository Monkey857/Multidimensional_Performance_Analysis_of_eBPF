// Copyright 2024 The EBPF performance testing Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// author: yys2020haha@163.com
//
// Kernel space BPF program used for eBPF performance testing.
#ifndef __ANALYZE_MAP_H
#define __ANALYZE_MAP_H

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "common.h"
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024*1024);
    __type(key, U32);
    __type(value,u64);
} hash_map SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1024*1024);
    __type(key, u32);
    __type(value,u64);
} array_map SEC(".maps");
//在内核态中进行数据的增删改查，并将数据信息存入到相应的map中
static int hash_vs_array(struct trace_event_raw_sys_enter *args){
    u64 syscall_id = (u64)args->id;
    u32 time = bpf_ktime_get_ns();
    //向hash、array类型的map中存入数据
    bpf_map_update_elem(&hash_map,&time,&syscall_id,BPF_ANY);
    bpf_map_update_elem(&array_map,&time,&syscall_id,BPF_ANY);
}
#endif /* __ANALYZE_MAP_H */
