cmake_minimum_required(VERSION 3.16)
project(eBPF C)

set(CMAKE_C_STANDARD 11)

add_library(libbpf SHARED IMPORTED)

add_executable(eBPF
        macfilter.c)

target_link_libraries(eBPF PUBLIC  /home/jannes/Downloads/libbpf/src/libbpf.so)

target_include_directories(eBPF PUBLIC include)
