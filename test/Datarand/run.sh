#!/bin/bash

rm *.png *.dot
file="$1"
fileinst=$file"_inst"

set -x

LLVMROOT=/mnt/Projects/LLVM-custom/install/bin

rm null_helper.c aes_inreg.s aes_inmemkey.s aes_helper.c internal_libc.c
#LLVMROOT=/mnt/donotuse_comparisonONLY/DataRandomization/install/bin

ln -s /mnt/Projects/LLVM-custom/lib/Transforms/Encryption/null_helper.c_ null_helper.c
ln -s /mnt/Projects/LLVM-custom/lib/Transforms/Encryption/aes_inmemkey.s aes_inmemkey.s
ln -s /mnt/Projects/LLVM-custom/lib/Transforms/Encryption/aes_inreg.s aes_inreg.s
ln -s /mnt/Projects/LLVM-custom/lib/Transforms/Encryption/aes_helper.c_ aes_helper.c
ln -s /mnt/Projects/LLVM-custom/lib/Transforms/LibcTransform/internal_libc.c_ internal_libc.c

GGDB=-ggdb 
musl-clang -O0 -c $GGDB  -emit-llvm $file.c -o $file.bc
if [ $? -ne 0 ]
then
    exit 1
fi

musl-clang -c $GGDB -emit-llvm internal_libc.c -o internal_libc.bc
if [ $? -ne 0 ]
then
    exit 1
fi


$LLVMROOT/llvm-link $file.bc internal_libc.bc  -o $file.bc #internal_libc.bc
if [ $? -ne 0 ]
then
    exit 1
fi

#wpa -nander -keep-self-cycle=all -dump-consG -dump-pag -print-all-pts $file.bc
#wpa -ander -keep-self-cycle=all -dump-consG -dump-pag -print-all-pts $file.bc

#$LLVMROOT/opt -wpa -print-all-pts -dump-pag -dump-consG $file.ll  -o $fileinst.bc 
$LLVMROOT/opt -encryption -print-all-pts -dump-pag -debug-only=encryption -dump-consG $file.bc -o $fileinst.bc 
# -fullanders -dump-pag -print-all-pts -dump-callgraph -dump-consG 
#$LLVMROOT/opt -test-transform $file.bc  -o $fileinst.bc
$LLVMROOT/llvm-dis $file.bc -o $file.ll
$LLVMROOT/llvm-dis $fileinst.bc -o $fileinst.ll
#exit 0
#dot -Tpng pag_final.dot -o $file"_pag_final.png"
#dot -Tpng pag_initial.dot -o $file"_pag_initial.png"
#dot -Tpng consCG_final.dot -o $file"_consg_full_final.png"
#dot -Tpng consCG_selective_final.dot -o $file"_consg_selective_final.png"

$LLVMROOT/llc -O0 -filetype=obj $fileinst.bc -o $fileinst.o
if [ $? -ne 0 ]
then
    exit 1
fi

musl-clang -static $GGDB aes_inreg.s aes_helper.c $fileinst.o -o $file
if [ $? -ne 0 ]
then
    exit 1
fi


if [ $? -ne 0 ]
then
    exit 1
fi
