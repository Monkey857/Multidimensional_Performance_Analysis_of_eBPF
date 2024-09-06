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
#ifndef __EBPF_PERFORMANCE_H
#define __EBPF_PERFORMANCE_H


#define OPTIONS_LIST "-a"

#define OUTPUT_INTERVAL(SECONDS) sleep(SECONDS)

#define PRINT_USAGE_ERR()                                               \
    do {                                                                \
        fprintf(stderr, "Please specify exactly one option from %s.\n", \
                OPTIONS_LIST);                                          \
        argp_state_help(state, stdout, ARGP_HELP_STD_HELP);             \
    } while (0)

#define SET_OPTION_AND_CHECK_USAGE(option, value) \
    do {                                          \
        if (option == 0) {                        \
            value = true;                         \
            option = 1;                           \
        } else {                                  \
            PRINT_USAGE_ERR();                    \
        }                                         \
    } while (0)

enum EventType {
    NONE_TYPE,
    EXECUTE_TEST_MAPS,
} event_type;

#endif 