#!/bin/bash

make distclean

CC=/mnt/Projects/LLVM-custom/install/bin/clang CFLAG="-O0 -flto" LD=/usr/bin/ld.gold LDFLAGS="-O0 -flto -lhelper" AR=/mnt/Projects/LLVM-custom/install/bin/llvm-ar RANLIB=/mnt/Projects/LLVM-custom/install/bin/llvm-ranlib ./Configure no-threads no-zlib no-asm no-bf no-cast no-des no-dh no-dsa no-md2 no-mdc2 no-rc2 -no-rcmake-rc5 no-shared --prefix=/mnt/Projects/LLVM-custom/test/Datarand/openssl-1.0.2r/install --openssldir=/mnt/Projects/LLVM-custom/test/Datarand/openssl-1.0.2r/install/openssl  linux-x86_64-clang-lto

make dep_build

make build_libs
