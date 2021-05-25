### DynPTA
================================

#### Compiling LLVM toolchain with LTO

We provide our own LLVM toolchain. If you're interested in only running the Steensgaard's Analysis, you can skip steps 1 and 2 and jump right to the Steensgaard's analysis section. I'll move the Steensgaard's analysis to its own project soon. 

1. We need [binutils](https://www.gnu.org/software/binutils/) in order to do LTO for Whole Program Analysis. The instructions to set it up correctly is [here](https://llvm.org/docs/GoldPlugin.html). 


2. Then compile LLVM

   1. `cmake -G "Unix Makefiles" -DCMAKE_BUILD_TYPE=<Debug/Release> -DLLVM_TARGETS_TO_BUILD="X86" -DCMAKE_INSTALL_PREFIX=<YOUR_CUSTOM_INSTALL_DIR> -DLLVM_BINUTILS_INCDIR=<BINUTILS_DIR>/include ../`
       
       Choose Debug/Release build and set up the directories correctly. 

   2. `make -jN` (N = number of cores) 

#### Steensgaard's Analysis Implementation

We provide a Steensgaard's pointer analysis as part of our prototype. In order to just run this analysis, use the following command. 

`$LLVMROOT/opt -steens-fast -skip-csa=true -print-all-pts $file.bc -o $fileout.bc`

where `$file.bc` is the LLVM bitcode. 

#### Encrypting sensitive data with DynPTA

/* TODO */

   
#### Citation
```
@article{dynpta, 
title={DynPTA: Combining Static and Dynamic Analysis for Practical Selective Data Protection}, 
booktitle={Proceedings of 42nd IEEE Symposium on Security and Privacy}, 
author={Palit, Tapti and Moon, Jarin Firose and Monrose, Fabian and Polychronakis, Michalis}, 
year={2021}}
```

