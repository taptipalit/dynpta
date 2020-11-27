#!/usr/bin/env bash
LLVMROOT=$LLVM_CUSTOM_PARTITION_BIN
objfile="$1"
exefile="$2"
opts="$3"

glibc_install=/mnt/Projects/tpalit/glibc/glibc-install

set -eux
#rm -rf tmp
#mkdir tmp

$LLVMROOT/clang -O0 \
    -L "${glibc_install}/lib" \
    -I "${glibc_install}/include" \
    -Wl,--rpath="${glibc_install}/lib" \
    -Wl,--dynamic-linker="${glibc_install}/lib/ld-linux-x86-64.so.2" \
    -std=c11 \
    -fsanitize=dataflow \
    -o $exefile \
    -v \
    aes.o aes_h.o $objfile \
    -pthread -lcrypt $opts \
    ;
#sudo chroot tmp /test_glibc.out

