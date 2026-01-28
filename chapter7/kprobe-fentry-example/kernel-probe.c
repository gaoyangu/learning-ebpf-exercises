#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <bpf/libbpf.h>
#include "kernel-probe.h"
#include "kernel-probe.skel.h"

static volatile bool exiting = false;

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    if (level >= LIBBPF_DEBUG)
        return 0;
    return vfprintf(stderr, format, args);
}

void handle_event(void *ctx, int cpu, void *data, unsigned int data_sz)
{
    struct event_data_t *event = data;
    
    printf("%-8llu %-6u %-6u %-16s %-20s\n",
           event->timestamp,
           event->pid,
           event->uid,
           event->comm,
           event->func_name);
}

void lost_event(void *ctx, int cpu, long long unsigned int data_sz)
{
    printf("Lost %llu events on CPU %d\n", data_sz, cpu);
}

void sig_handler(int sig)
{
    exiting = true;
}

int main(int argc, char **argv)
{
    struct kernel_probe_bpf *skel;
    int err;
    struct perf_buffer *pb = NULL;
    struct bpf_link *link_kprobe_fork = NULL;
    struct bpf_link *link_kprobe_exit = NULL;
    struct bpf_link *link_fentry_read = NULL;
    struct bpf_link *link_fentry_write = NULL;
    struct bpf_link *link_kprobe_connect = NULL;
    struct bpf_link *link_kprobe_kmalloc = NULL;

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    libbpf_set_print(libbpf_print_fn);

    printf("加载 eBPF 程序...\n");
    
    skel = kernel_probe_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF object\n");
        return 1;
    }

    printf("附加 kprobe 探针...\n");
    
    // 附加各个探针
    link_kprobe_fork = bpf_program__attach(skel->progs.trace_do_fork);
    if (!link_kprobe_fork) {
        fprintf(stderr, "Failed to attach kprobe/do_fork\n");
    } else {
        printf("✓ kprobe/do_fork 附加成功\n");
    }

    link_kprobe_exit = bpf_program__attach(skel->progs.trace_do_exit);
    if (!link_kprobe_exit) {
        fprintf(stderr, "Failed to attach kprobe/do_exit\n");
    } else {
        printf("✓ kprobe/do_exit 附加成功\n");
    }

    printf("附加 fentry 探针...\n");

    link_fentry_read = bpf_program__attach(skel->progs.trace_vfs_read_enter);
    if (!link_fentry_read) {
        fprintf(stderr, "Failed to attach fentry/vfs_read (可能需要更新的内核)\n");
    } else {
        printf("✓ fentry/vfs_read 附加成功\n");
    }

    link_fentry_write = bpf_program__attach(skel->progs.trace_vfs_write_enter);
    if (!link_fentry_write) {
        fprintf(stderr, "Failed to attach fentry/vfs_write (可能需要更新的内核)\n");
    } else {
        printf("✓ fentry/vfs_write 附加成功\n");
    }

    printf("附加其他 kprobe 探针...\n");

    link_kprobe_connect = bpf_program__attach(skel->progs.trace_tcp_connect);
    if (!link_kprobe_connect) {
        fprintf(stderr, "Failed to attach kprobe/tcp_connect\n");
    } else {
        printf("✓ kprobe/tcp_connect 附加成功\n");
    }

    link_kprobe_kmalloc = bpf_program__attach(skel->progs.trace_kmalloc);
    if (!link_kprobe_kmalloc) {
        fprintf(stderr, "Failed to attach kprobe/__kmalloc\n");
    } else {
        printf("✓ kprobe/__kmalloc 附加成功\n");
    }

    pb = perf_buffer__new(bpf_map__fd(skel->maps.events), 8, 
                          handle_event, lost_event, NULL, NULL);
    if (!pb) {
        err = -1;
        fprintf(stderr, "Failed to create perf buffer\n");
        goto cleanup;
    }

    printf("\n开始监听内核事件...\n");
    printf("时间戳          PID    UID    进程名           函数名\n");
    printf("--------------------------------------------------------\n");

    while (!exiting) {
        err = perf_buffer__poll(pb, 100);
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
    printf("\n清理资源...\n");
    perf_buffer__free(pb);
    
    if (link_kprobe_fork) bpf_link__destroy(link_kprobe_fork);
    if (link_kprobe_exit) bpf_link__destroy(link_kprobe_exit);
    if (link_fentry_read) bpf_link__destroy(link_fentry_read);
    if (link_fentry_write) bpf_link__destroy(link_fentry_write);
    if (link_kprobe_connect) bpf_link__destroy(link_kprobe_connect);
    if (link_kprobe_kmalloc) bpf_link__destroy(link_kprobe_kmalloc);
    
    kernel_probe_bpf__destroy(skel);
    return -err;
}