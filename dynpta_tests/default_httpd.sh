#!/bin/bash

rm *.png *.dot
file="$1"
fileinst=$file"_inst"
filedfsan=$fileinst"_dfs"

set -x

LLVMROOT=$LLVM_CUSTOM_PARTITION_BIN

rm null_helper.c aes_inreg.s aes_inmemkey.s default_helper.c internal_libc.c
#LLVMROOT=/mnt/donotuse_comparisonONLY/DataRandomization/install/bin

ln -s $LLVM_CUSTOM_SRC/lib/Transforms/Encryption/null_helper.c_ null_helper.c
ln -s $LLVM_CUSTOM_SRC/lib/Transforms/Encryption/aes_inmemkey.s aes_inmemkey.s
ln -s $LLVM_CUSTOM_SRC/lib/Transforms/Encryption/aes_inreg.s aes_inreg.s
ln -s $LLVM_CUSTOM_SRC/lib/Transforms/Encryption/default_helper.c_ default_helper.c
ln -s $LLVM_CUSTOM_SRC/lib/Transforms/LibcTransform/internal_libc.c_ internal_libc.c

GGDB=-ggdb 
if [ -f $file.c ]; then
    $LLVMROOT/clang -O0 -c $GGDB -emit-llvm $file.c -o $file.bc
    if [ $? -ne 0 ]
    then
        exit 1
    fi
fi

$LLVMROOT/clang -c $GGDB -emit-llvm internal_libc.c -o internal_libc.bc
if [ $? -ne 0 ]
then
    exit 1
fi


$LLVMROOT/llvm-dis $file.bc -o $file.ll
#$LLVMROOT/opt -encryption -steens-fast -confidentiality=true -skip-vfa=false -skip-csa=false -optimized-check=true -partitioning=true  $file.bc -o $fileinst.bc
#$LLVMROOT/opt --dfsan -dfsan-abilist=./abilist.txt $fileinst.bc -o $filedfsan.bc

cp $file.bc $fileinst.bc
cp $file.bc $filedfsan.bc

$LLVMROOT/llvm-dis $fileinst.bc -o $fileinst.ll
$LLVMROOT/llvm-dis $filedfsan.bc -o $filedfsan.ll

$LLVMROOT/clang -O0 -c -fPIC -fPIE $filedfsan.bc -o $filedfsan.o
if [ $? -ne 0 ]
then
    exit 1
fi

$LLVMROOT/clang -c -fPIC -fPIE aes_inmemkey.s -o aes.o
$LLVMROOT/clang -c -fPIC -fPIE -march=native default_helper.c -o aes_h.o
#$LLVMROOT/clang $GGDB -O0 -fsanitize=dataflow aes.o aes_h.o $filedfsan.o -o httpd.uninstrumented -luuid -lrt -lcrypt -lpthread -ldl -lpcre -lexpat
./run_glibc.sh $filedfsan.o httpd.uninstrumented "-luuid -lrt -lcrypt -lpthread -ldl -lpcre -lexpat"
if [ $? -ne 0 ]
then
    exit 1
fi


if [ $? -ne 0 ]
then
    exit 1
fi
