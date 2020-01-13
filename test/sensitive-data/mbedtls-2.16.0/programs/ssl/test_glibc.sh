#!/usr/bin/env bash
glibc_install=/mnt/Projects/tpalit/glibc/glibc-install
set -eux
rm -rf tmp
mkdir tmp
gcc \
    -O0 \
    -L "${glibc_install}/lib" \
    -I "${glibc_install}/include" \
    -Wl,--rpath="${glibc_install}/lib" \
    -Wl,--dynamic-linker="${glibc_install}/lib/ld-linux-x86-64.so.2" \
    -static \
    -std=c11 \
    -o tmp/test_glibc.out \
    -v \
    ssl_server.2.0.5.o \
    -pthread \
    -lhelper \
    ;
sudo chroot tmp /test_glibc.out

