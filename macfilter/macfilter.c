#include <stdio.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <string.h>
#include "include/macfilter.skel.h"

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    return vfprintf(stderr, format, args);
}

int main(int argc, char **argv)
{
    struct macfilter_bpf *skel;
    int err;

    /* Set up libbpf errors and debug info callback */
    libbpf_set_print(libbpf_print_fn);

    /* Open BPF application */
    skel = macfilter_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    /* Load & verify BPF programs */
    err = macfilter_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load and verify BPF skeleton\n");
        goto cleanup;
    }

    /* Attach tracepoint handler */
    err = macfilter_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }

    printf("Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
           "to see output of the BPF programs.\n");



    FILE *f = fopen("../whitelist.txt", "r");

    for(int i = 0; i < 16; i++) {
        unsigned char mac_addr[6];
        int result;

        result = fscanf(f, "%02x:%02x:%02x:%02x:%02x:%02x[\n]", &mac_addr[0], &mac_addr[1], &mac_addr[2], &mac_addr[3], &mac_addr[4], &mac_addr[5]);

        if (result == EOF || result == 0) {
            break;
        }

        fprintf(stderr, "Loaded mac address: %02x:%02x:%02x:%02x:%02x:%02x\n", mac_addr[0], mac_addr[1], mac_addr[2], mac_addr[3], mac_addr[4], mac_addr[5]);

        bpf_map__update_elem(skel->maps.whitelist_map, &i, sizeof(i), mac_addr, sizeof(mac_addr), BPF_ANY);

    }

    fclose(f);

    for (;;) {
        /* trigger our BPF program */
        fprintf(stderr, ".");
        sleep(1);
    }

    cleanup:
    macfilter_bpf__destroy(skel);
    return -err;
}