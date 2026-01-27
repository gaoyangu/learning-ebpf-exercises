// trace_unlink.c
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include "trace_unlink.skel.h"

static volatile bool exiting = false;

void sig_handler(int sig) {
    exiting = true;
}

int main(int argc, char **argv)
{
    struct trace_unlink_bpf *skel;
    int err;

    skel = trace_unlink_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    err = trace_unlink_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF skeleton: %d\n", err);
        goto cleanup;
    }

    err = trace_unlink_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF programs: %d\n", err);
        goto cleanup;
    }

    printf("Tracing unlink calls via kprobe/fentry. Hit Ctrl+C to exit.\n");
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    while (!exiting) {
        sleep(1);
    }

cleanup:
    trace_unlink_bpf__destroy(skel);
    return -err;
}