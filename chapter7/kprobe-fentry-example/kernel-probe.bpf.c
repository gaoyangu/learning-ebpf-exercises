#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "kernel-probe.h"

// 性能事件数组映射
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} events SEC(".maps");

// ==================== kprobe 示例 ====================

// kprobe 探测 do_fork 函数
SEC("kprobe/do_fork")
int trace_do_fork(struct pt_regs *ctx)
{
    struct event_data_t event = {};
    
    // 获取进程信息
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    __builtin_memcpy(&event.func_name, "do_fork", 8);
    event.timestamp = bpf_ktime_get_ns();
    
    // 发送事件到用户空间
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    return 0;
}

// kprobe 探测 do_exit 函数
SEC("kprobe/do_exit")
int trace_do_exit(struct pt_regs *ctx)
{
    struct event_data_t event = {};
    
    // 获取退出码
    long exit_code = PT_REGS_PARM1(ctx);
    
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    __builtin_memcpy(&event.func_name, "do_exit", 8);
    event.timestamp = bpf_ktime_get_ns();
    
    // 发送事件到用户空间
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    
    bpf_printk("Process %d exited with code %ld", event.pid, exit_code);
    return 0;
}

// ==================== fentry 示例 ====================

// fentry 探探 vfs_read 函数 (需要较新的内核)
SEC("fentry/vfs_read")
int trace_vfs_read_enter(struct pt_regs *ctx)
{
    struct event_data_t event = {};
    
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    __builtin_memcpy(&event.func_name, "vfs_read", 9);
    event.timestamp = bpf_ktime_get_ns();
    
    // 发送事件到用户空间
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    
    return 0;
}

// fentry 探测 vfs_write 函数
SEC("fentry/vfs_write")
int trace_vfs_write_enter(struct pt_regs *ctx)
{
    struct event_data_t event = {};
    
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    __builtin_memcpy(&event.func_name, "vfs_write", 10);
    event.timestamp = bpf_ktime_get_ns();
    
    // 发送事件到用户空间
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    
    return 0;
}

// ==================== 其他有用的 kprobe ====================

// 探测 TCP 连接建立
SEC("kprobe/tcp_connect")
int trace_tcp_connect(struct pt_regs *ctx)
{
    struct event_data_t event = {};
    
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    __builtin_memcpy(&event.func_name, "tcp_connect", 12);
    event.timestamp = bpf_ktime_get_ns();
    
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    
    bpf_printk("TCP connection attempt from PID %d", event.pid);
    return 0;
}

// 探测内存分配
SEC("kprobe/__kmalloc")
int trace_kmalloc(struct pt_regs *ctx)
{
    struct event_data_t event = {};
    size_t size = PT_REGS_PARM1(ctx);
    
    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    __builtin_memcpy(&event.func_name, "__kmalloc", 10);
    event.timestamp = bpf_ktime_get_ns();
    
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    
    bpf_printk("kmalloc: %zu bytes from PID %d", size, event.pid);
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";