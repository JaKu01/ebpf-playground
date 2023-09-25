//
// Created by jannes on 17.09.23.
//
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/libbpf.h>
#include <stdlib.h>
#include <memory.h>
#include <unistd.h>
#include <asm/unistd.h>
#include <errno.h>
#include <stdio.h>

int bpf(enum bpf_cmd cmd, union bpf_attr *attr, unsigned int size)
{
    return syscall(__NR_bpf, cmd, attr, size);
}

int create_map() {
    union bpf_attr attr_map_create;
    strcpy(attr_map_create.map_name, "addresses");
    attr_map_create.key_size =

    return bpf(BPF_MAP_CREATE, &attr_map_create, sizeof(attr_map_create));

}

int main() {

    union bpf_attr attr;
    attr.map_id = 2;

    int fd_map = bpf(BPF_MAP_GET_FD_BY_ID, &attr, sizeof(union bpf_attr));

    union bpf_attr attr_lookup;
    attr_lookup.map_fd = fd_map;
    attr_lookup.key = 0;
    int result = bpf(BPF_MAP_LOOKUP_ELEM, &attr_lookup, sizeof(attr_lookup));
    printf("result: %d", result);

}
