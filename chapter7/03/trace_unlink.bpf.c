// trace_unlink.bpf.c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

/* === kprobe 版本 === */
SEC("kprobe/do_unlinkat")
int BPF_KPROBE(kprobe_do_unlinkat, int dfd, struct filename *name)
{
    const char *fname;
    fname = BPF_CORE_READ(name, name);
    bpf_printk("kprobe: unlink called on file: %s\n", fname);
    return 0;
}

/* === fentry 版本（需要 BTF）=== */
SEC("fentry/do_unlinkat")
int BPF_PROG(fentry_do_unlinkat, int dfd, struct filename *name)
{
    const char *fname;
    fname = BPF_CORE_READ(name, name);
    bpf_printk("fentry: unlink called on file: %s\n", fname);
    return 0;
}