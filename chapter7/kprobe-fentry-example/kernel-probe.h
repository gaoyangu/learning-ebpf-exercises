#ifndef KERNEL_PROBE_H
#define KERNEL_PROBE_H

// 事件数据结构
struct event_data_t {
    unsigned int pid;
    unsigned int uid;
    char comm[16];
    char func_name[32];
    unsigned long long timestamp;
};

#endif