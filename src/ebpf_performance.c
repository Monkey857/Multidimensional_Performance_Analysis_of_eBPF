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

#include <argp.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include "common.h"
#include "ebpf_performance.skel.h"

// 定义env结构体，用来存储程序中的事件信息
static struct env {
    bool execute_hash_vs_array;
    bool verbose;
    enum EventType event_type;
} env = {
    .execute_hash_vs_array = false,
    .verbose = false,
    .event_type = NONE_TYPE,
};

const char *argp_program_version = "ebpf_performance 1.0";
const char *argp_program_bug_address = "<yys2020haha@163.com>";
const char argp_program_doc[] = "BPF program used for eBPF performance testing\n";
int option_selected = 0;  // 功能标志变量,确保激活子功能
// 具体解释命令行参数
static const struct argp_option opts[] = {
    {"Map:hash_vs_array", 'a', NULL, 0, "Comparing the differences between array and hash"},
    {"verbose", 'v', NULL, 0, "Verbose debug output"},
    {NULL, 'H', NULL, OPTION_HIDDEN, "Show the full help"},
    {},
};
// 解析命令行参数
static error_t parse_arg(int key, char *arg, struct argp_state *state) {
    switch (key) {
        case 'a':
            SET_OPTION_AND_CHECK_USAGE(option_selected, env.execute_hash_vs_array);
            break;
        case 'H':
            argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
            break;
        case 'v':
            env.verbose = true;
            break;
        default:
            return ARGP_ERR_UNKNOWN;
    }
    return 0;
}
// 定义解析参数的处理函数
static const struct argp argp = {
    .options = opts,
    .parser = parse_arg,
    .doc = argp_program_doc,
};

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
                           va_list args) {
    if (level == LIBBPF_DEBUG && !env.verbose)
        return 0;
    return vfprintf(stderr, format, args);
}

static volatile bool exiting = false;
// 设置信号来控制是否打印信息
static void sig_handler(int sig) {
    exiting = true;
}

// 根据 env 设置 EventType
static int determineEventType(struct env *env) {
    if (!env) {
        return 1;
    }
    if (env->execute_hash_vs_array) {
        env->event_type = HASH_VS_ARRAY;
    } else {
        env->event_type = NONE_TYPE;  // 或者根据需要设置一个默认的事件类型
    }
    return 0;
}

/*通过env->event_type属性来选择需要打印的信息表头*/
static int print_event_head(struct env *env) {
    if (!env->event_type) {
        // 处理无效参数，可以选择抛出错误或返回
        return 1;
    }
    switch (env->event_type) {
        case HASH_VS_ARRAY:
            printf("%-18s %-20s %-15s %-15s %-10s %-10s %-10s\n", "TIME(ms)",
                   "DUR_HALT(ms)", "COMM", "PID/TID", "VCPU_ID", "WAIT/POLL",
                   "VAILD?");
            break;
        default:
            // Handle default case or display an error message
            break;
    }
    return 0;
}

static void set_disable_load(struct ebpf_performance_bpf *skel) {
    bpf_program__set_autoload(skel->progs.tp_sys_entry,
                              env.execute_hash_vs_array ? true : false);
}

// 函数不接受参数，返回一个静态分配的字符串
const char *getCurrentTimeFormatted() {
    static char ts[32];  // 静态分配，每次调用都会覆盖
    time_t t;
    struct tm *tm;

    time(&t);
    tm = localtime(&t);

    // 格式化时间到静态分配的字符串中
    strftime(ts, sizeof(ts), "%Y/%m/%d %H:%M:%S", tm);

    return ts;  // 返回指向静态字符串的指针
}


// clear the specific map
int clear_map(void *lookup_key, void *next_key, enum EventType type, int fd) {
    int err;
    switch (type) {
        case HASH_VS_ARRAY:
            memset(lookup_key, 0, sizeof(__u64));
            break;
        default:
            return -1;
    }
    while (!bpf_map_get_next_key(fd, lookup_key, next_key)) {
        err = bpf_map_delete_elem(fd, next_key);
        if (err < 0) {
            fprintf(stderr, "failed to cleanup map: %d\n", err);
            return -1;
        }
        lookup_key = next_key;
    }
    return 1;
}


void print_map_and_check_error(int (*print_func)(struct ebpf_performance_bpf *),
                               struct ebpf_performance_bpf *skel,
                               const char *map_name, int err) {
    OUTPUT_INTERVAL(2);
    print_func(skel);
    if (err < 0 && err != -4) {
        printf("Error printing %s map: %d\n", map_name, err);
    }
}

int attach_probe(struct ebpf_performance_bpf *skel) {
    return ebpf_performance_bpf__attach(skel);
}
#define NUM_ENTRIES 1024
struct timespec diff(struct timespec start, struct timespec end) {
    struct timespec temp;
    if ((end.tv_nsec - start.tv_nsec) < 0) {
        temp.tv_sec = end.tv_sec - start.tv_sec - 1;
        temp.tv_nsec = 1000000000 + end.tv_nsec - start.tv_nsec;
    } else {
        temp.tv_sec = end.tv_sec - start.tv_sec;
        temp.tv_nsec = end.tv_nsec - start.tv_nsec;
    }
    return temp;
}

int compare_hash_array(struct ebpf_performance_bpf *skel){
    printf("I am come in!!\n");
    int hash_fd = bpf_map__fd(skel->maps.hash_map);
    int array_fd = bpf_map__fd(skel->maps.array_map);
    if (hash_fd < 0 || array_fd < 0) {
        fprintf(stderr, "Failed to get map file descriptors: %d, %d\n", hash_fd, array_fd);
        return 1;
    }
    struct timespec start, end, elapsed;
    int key, value;
    __u32 lookup_key;
    __u64 next_key;
    int times = 4;
    // Test lookup for HashMap
    clock_gettime(CLOCK_MONOTONIC, &start);
    while (!bpf_map_get_next_key(hash_fd, &lookup_key, &next_key)){
        times++;
        if (bpf_map_lookup_elem(hash_fd, &next_key, &value) != 0) {
            fprintf(stderr, "Failed to lookup hash_map: %d\n", errno);
            return 1;
        }
        lookup_key = next_key;
    }
    
    clock_gettime(CLOCK_MONOTONIC, &end);
    elapsed = diff(start, end);
    printf("HashMap lookup time: %ld.%09ld seconds\n", elapsed.tv_sec, elapsed.tv_nsec);
    printf("查找了%d次\n",times);
    // Test lookup for ArrayMap
    times = 0;
    clock_gettime(CLOCK_MONOTONIC, &start);
    while (!bpf_map_get_next_key(array_fd, &lookup_key, &next_key)){
        times++;
        if (bpf_map_lookup_elem(array_fd, &next_key, &value) != 0) {
            fprintf(stderr, "Failed to lookup hash_map: %d\n", errno);
            return 1;
        }
        lookup_key = next_key;
    }
    clock_gettime(CLOCK_MONOTONIC, &end);
    elapsed = diff(start, end);
    printf("ArrayMap lookup time: %ld.%09ld seconds\n", elapsed.tv_sec, elapsed.tv_nsec);
    printf("查找了%d次\n",times);
    times = 0;
    // // Test insertion for HashMap
    // clock_gettime(CLOCK_MONOTONIC, &start);
    // for (int i = 0; i < NUM_ENTRIES; i++) {
    //     key = i;
    //     value = i;
    //     if (bpf_map_update_elem(hash_fd, &key, &value, BPF_ANY) != 0) {
    //         fprintf(stderr, "Failed to update hash_map: %d\n", errno);
    //         return 1;
    //     }
    // }
    // clock_gettime(CLOCK_MONOTONIC, &end);
    // elapsed = diff(start, end);
    // printf("HashMap insert time: %ld.%09ld seconds\n", elapsed.tv_sec, elapsed.tv_nsec);

    // // Test insertion for ArrayMap
    // clock_gettime(CLOCK_MONOTONIC, &start);
    // for (int i = 0; i < NUM_ENTRIES; i++) {
    //     key = i;
    //     value = i;
    //     if (bpf_map_update_elem(array_fd, &key, &value, BPF_ANY) != 0) {
    //         fprintf(stderr, "Failed to update array_map: %d\n", errno);
    //         return 1;
    //     }
    // }
    // clock_gettime(CLOCK_MONOTONIC, &end);
    // elapsed = diff(start, end);
    // printf("ArrayMap insert time: %ld.%09ld seconds\n", elapsed.tv_sec, elapsed.tv_nsec);

    // // Test deletion for HashMap
    // clock_gettime(CLOCK_MONOTONIC, &start);
    // for (int i = 0; i < NUM_ENTRIES; i++) {
    //     key = i;
    //     if (bpf_map_delete_elem(hash_fd, &key) != 0) {
    //         fprintf(stderr, "Failed to delete from hash_map: %d\n", errno);
    //         return 1;
    //     }
    // }
    // clock_gettime(CLOCK_MONOTONIC, &end);
    // elapsed = diff(start, end);
    // printf("HashMap delete time: %ld.%09ld seconds\n", elapsed.tv_sec, elapsed.tv_nsec);

    // Note: ArrayMap does not support delete operation

    return 0;
}
int main(int argc, char **argv) {
    struct ebpf_performance_bpf *skel;
    int err;
    /*解析命令行参数*/
    err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
    if (err)
        return err;
    /*设置libbpf的错误和调试信息回调*/
    libbpf_set_print(libbpf_print_fn);
    /* Cleaner handling of Ctrl-C */
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    signal(SIGALRM, sig_handler);
    /* Open BPF application */
    skel = ebpf_performance_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    /* 禁用或加载内核挂钩函数 */
    set_disable_load(skel);

    /* 加载并验证BPF程序 */
    err = ebpf_performance_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load and verify BPF skeleton\n");
        goto cleanup;
    }

    /* 附加跟踪点处理程序 */
    err = attach_probe(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }
    // 根据 env 设置 EventType
    err = determineEventType(&env);
    if (err) {
        fprintf(stderr, "Invalid env parm\n");
        goto cleanup;
    }
    /*打印信息头*/
    err = print_event_head(&env);
    if (err) {
        fprintf(stderr, "Please specify an option using %s.\n", OPTIONS_LIST);
        goto cleanup;
    }
    while (!exiting) {
        if (env.execute_hash_vs_array) {
            print_map_and_check_error(compare_hash_array, skel, "hash_array", err);
        }
        /* Ctrl-C will cause -EINTR */
        if (err == -EINTR) {
            err = 0;
            break;
        }
        if (err < 0) {
            printf("Error polling perf buffer: %d\n", err);
            break;
        }
    }
cleanup:
    ebpf_performance_bpf__destroy(skel);
    return -err;
}