#!/bin/bash

rm *.png *.dot
file="$1"
fileinst=$file"_inst"

set -x

LLVMROOT=/mnt/Projects/LLVM-custom/install/bin

GGDB=-ggdb 
$LLVMROOT/clang -O0 -c $GGDB  -emit-llvm $file.c  -S -o $file.ll
if [ $? -ne 0 ]
then
    exit 1
fi

#wpa -nander -keep-self-cycle=all -dump-consG -dump-pag -print-all-pts $file.bc
#wpa -ander -keep-self-cycle=all -dump-consG -dump-pag -print-all-pts $file.bc

$LLVMROOT/opt -wpa -print-all-pts -dump-pag -dump-consG $file.ll  -o $fileinst.bc 
# -fullanders -dump-pag -print-all-pts -dump-callgraph -dump-consG 
#$LLVMROOT/opt -test-transform $file.bc  -o $fileinst.bc
$LLVMROOT/llvm-dis $fileinst.bc -o $fileinst.ll
#exit 0
dot -Tpng pag_final.dot -o $file"_pag_final.png"
dot -Tpng pag_initial.dot -o $file"_pag_initial.png"
#dot -Tpng callgraph_final.dot -o $file"_callgraph_final.png"
#dot -Tpng callgraph_initial.dot -o $file"_callgraph_initial.png"
dot -Tpng consCG_final.dot -o $file"_consg_full_final.png"
dot -Tpng consCG_selective_final.dot -o $file"_consg_selective_final.png"

if [ $? -ne 0 ]
then
    exit 1
fi
