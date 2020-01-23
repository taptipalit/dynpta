#!/bin/bash

rm *.png *.dot
file="$1"
fileinst=$file"_inst"
filedfsan=$fileinst"_dfs"

set -x

LLVMROOT=$LLVM_CUSTOM_PARTITION_BIN

rm null_helper.c aes_inreg.s aes_inmemkey.s aes_helper.c internal_libc.c
#LLVMROOT=/mnt/donotuse_comparisonONLY/DataRandomization/install/bin

ln -s $LLVM_CUSTOM_SRC/lib/Transforms/Encryption/null_helper.c_ null_helper.c
ln -s $LLVM_CUSTOM_SRC/lib/Transforms/Encryption/aes_inmemkey.s aes_inmemkey.s
ln -s $LLVM_CUSTOM_SRC/lib/Transforms/Encryption/aes_inreg.s aes_inreg.s
ln -s $LLVM_CUSTOM_SRC/lib/Transforms/Encryption/aes_helper.c_ aes_helper.c
ln -s $LLVM_CUSTOM_SRC/lib/Transforms/LibcTransform/internal_libc.c_ internal_libc.c

GGDB=-ggdb 
#$LLVMROOT/clang -O0 -c $GGDB -emit-llvm $file.c -o $file.bc
if [ $? -ne 0 ]
then
    exit 1
fi

$LLVMROOT/clang -c $GGDB -emit-llvm internal_libc.c -o internal_libc.bc
if [ $? -ne 0 ]
then
    exit 1
fi


#$LLVMROOT/llvm-link $file.bc internal_libc.bc  -o $file.bc #internal_libc.bc
#if [ $? -ne 0 ]
#then
#    exit 1
#fi

#wpa -nander -keep-self-cycle=all -dump-consG -dump-pag -print-all-pts $file.bc
#wpa -ander -keep-self-cycle=all -dump-consG -dump-pag -print-all-pts $file.bc

#$LLVMROOT/opt -wpa -print-all-pts -dump-pag -dump-consG $file.ll  -o $fileinst.bc 
$LLVMROOT/opt -encryption -ander -partitioning=false  $file.bc -o $fileinst.bc 
$LLVMROOT/opt --dfsan $fileinst.bc -o $filedfsan.bc

# -fullanders -dump-pag -print-all-pts -dump-callgraph -dump-consG 
#$LLVMROOT/opt -test-transform $file.bc  -o $fileinst.bc
$LLVMROOT/llvm-dis $file.bc -o $file.ll
$LLVMROOT/llvm-dis $fileinst.bc -o $fileinst.ll
$LLVMROOT/llvm-dis $filedfsan.bc -o $filedfsan.ll
#exit 0
#dot -Tpng pag_final.dot -o $file"_pag_final.png"
#dot -Tpng pag_initial.dot -o $file"_pag_initial.png"
#dot -Tpng consCG_final.dot -o $file"_consg_full_final.png"
#dot -Tpng consCG_selective_final.dot -o $file"_consg_selective_final.png"

$LLVMROOT/llc -O0 -filetype=obj $filedfsan.bc -o $filedfsan.o
if [ $? -ne 0 ]
then
    exit 1
fi

$LLVMROOT/clang -c -fPIC -pie aes_inmemkey.s -o aes.o
$LLVMROOT/clang -c -fPIC -pie aes_helper.c -o aes_h.o
#$LLVMROOT/clang -fPIC -pie -fsanitize=dataflow $GGDB aes.o aes_h.o $filedfsan.o -o $file
$LLVMROOT/clang $GGDB -fsanitize=dataflow aes.o aes_h.o $filedfsan.o -o $file
if [ $? -ne 0 ]
then
    exit 1
fi


if [ $? -ne 0 ]
then
    exit 1
fi
