#!/bin/bash

rm *.png *.dot
file="$1"
fileinst=$file"_inst"
filedfsan=$fileinst"_dfs"

set -x

LLVMROOT=$LLVM_CUSTOM_PARTITION_BIN

GGDB=-ggdb 

if [ -f $file.c ]; then
    $LLVMROOT/clang -O0 -c $GGDB -emit-llvm $file.c -o $file.bc
    if [ $? -ne 0 ]
    then
        exit 1
    fi
fi

$LLVMROOT/llvm-dis $file.bc -o $file.ll

$LLVMROOT/opt -encryption -steens-fast -integrity=true -skip-csa=true -skip-vfa -optimized-check=false -partitioning=false  $file.bc -o $fileinst.bc

$LLVMROOT/llvm-dis $fileinst.bc -o $fileinst.ll

$LLVMROOT/clang -O0 -c -fPIC -fPIE $fileinst.bc -o $fileinst.o
if [ $? -ne 0 ]
then
    exit 1
fi

$LLVMROOT/clang $GGDB -O0 $fileinst.o -o $file -lhmac

if [ $? -ne 0 ]
then
    exit 1
fi

