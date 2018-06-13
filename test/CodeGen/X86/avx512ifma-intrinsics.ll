; NOTE: Assertions have been autogenerated by utils/update_llc_test_checks.py
; RUN: llc < %s -mtriple=x86_64-apple-darwin -mcpu=knl -mattr=+avx512ifma | FileCheck %s

declare <8 x i64> @llvm.x86.avx512.vpmadd52h.uq.512(<8 x i64>, <8 x i64>, <8 x i64>)

define <8 x i64>@test_int_x86_avx512_mask_vpmadd52h_uq_512(<8 x i64> %x0, <8 x i64> %x1, <8 x i64> %x2, i8 %x3) {
; CHECK-LABEL: test_int_x86_avx512_mask_vpmadd52h_uq_512:
; CHECK:       ## %bb.0:
; CHECK-NEXT:    vmovdqa64 %zmm0, %zmm3
; CHECK-NEXT:    vpmadd52huq %zmm2, %zmm1, %zmm3
; CHECK-NEXT:    kmovw %edi, %k1
; CHECK-NEXT:    vmovdqa64 %zmm0, %zmm4
; CHECK-NEXT:    vpmadd52huq %zmm2, %zmm1, %zmm4 {%k1}
; CHECK-NEXT:    vpxor %xmm2, %xmm2, %xmm2
; CHECK-NEXT:    vpmadd52huq %zmm2, %zmm1, %zmm0 {%k1}
; CHECK-NEXT:    vpaddq %zmm0, %zmm4, %zmm0
; CHECK-NEXT:    vpmadd52huq %zmm2, %zmm1, %zmm2 {%k1} {z}
; CHECK-NEXT:    vpaddq %zmm2, %zmm3, %zmm1
; CHECK-NEXT:    vpaddq %zmm0, %zmm1, %zmm0
; CHECK-NEXT:    retq

  %1 = call <8 x i64> @llvm.x86.avx512.vpmadd52h.uq.512(<8 x i64> %x0, <8 x i64> %x1, <8 x i64> %x2)
  %2 = bitcast i8 %x3 to <8 x i1>
  %3 = select <8 x i1> %2, <8 x i64> %1, <8 x i64> %x0
  %4 = call <8 x i64> @llvm.x86.avx512.vpmadd52h.uq.512(<8 x i64> %x0, <8 x i64> %x1, <8 x i64> zeroinitializer)
  %5 = bitcast i8 %x3 to <8 x i1>
  %6 = select <8 x i1> %5, <8 x i64> %4, <8 x i64> %x0
  %7 = call <8 x i64> @llvm.x86.avx512.vpmadd52h.uq.512(<8 x i64> zeroinitializer, <8 x i64> %x1, <8 x i64> zeroinitializer)
  %8 = bitcast i8 %x3 to <8 x i1>
  %9 = select <8 x i1> %8, <8 x i64> %7, <8 x i64> zeroinitializer
  %10 = call <8 x i64> @llvm.x86.avx512.vpmadd52h.uq.512(<8 x i64> %x0, <8 x i64> %x1, <8 x i64> %x2)
  %res4 = add <8 x i64> %3, %6
  %res5 = add <8 x i64> %10, %9
  %res6 = add <8 x i64> %res5, %res4
  ret <8 x i64> %res6
}

define <8 x i64>@test_int_x86_avx512_maskz_vpmadd52h_uq_512(<8 x i64> %x0, <8 x i64> %x1, <8 x i64> %x2, i8 %x3) {
; CHECK-LABEL: test_int_x86_avx512_maskz_vpmadd52h_uq_512:
; CHECK:       ## %bb.0:
; CHECK-NEXT:    vmovdqa64 %zmm0, %zmm3
; CHECK-NEXT:    vpmadd52huq %zmm2, %zmm1, %zmm3
; CHECK-NEXT:    kmovw %edi, %k1
; CHECK-NEXT:    vmovdqa64 %zmm0, %zmm4
; CHECK-NEXT:    vpmadd52huq %zmm2, %zmm1, %zmm4 {%k1} {z}
; CHECK-NEXT:    vpxor %xmm2, %xmm2, %xmm2
; CHECK-NEXT:    vpmadd52huq %zmm2, %zmm1, %zmm0 {%k1} {z}
; CHECK-NEXT:    vpaddq %zmm0, %zmm4, %zmm0
; CHECK-NEXT:    vpmadd52huq %zmm2, %zmm1, %zmm2 {%k1} {z}
; CHECK-NEXT:    vpaddq %zmm2, %zmm3, %zmm1
; CHECK-NEXT:    vpaddq %zmm0, %zmm1, %zmm0
; CHECK-NEXT:    retq

  %1 = call <8 x i64> @llvm.x86.avx512.vpmadd52h.uq.512(<8 x i64> %x0, <8 x i64> %x1, <8 x i64> %x2)
  %2 = bitcast i8 %x3 to <8 x i1>
  %3 = select <8 x i1> %2, <8 x i64> %1, <8 x i64> zeroinitializer
  %4 = call <8 x i64> @llvm.x86.avx512.vpmadd52h.uq.512(<8 x i64> %x0, <8 x i64> %x1, <8 x i64> zeroinitializer)
  %5 = bitcast i8 %x3 to <8 x i1>
  %6 = select <8 x i1> %5, <8 x i64> %4, <8 x i64> zeroinitializer
  %7 = call <8 x i64> @llvm.x86.avx512.vpmadd52h.uq.512(<8 x i64> zeroinitializer, <8 x i64> %x1, <8 x i64> zeroinitializer)
  %8 = bitcast i8 %x3 to <8 x i1>
  %9 = select <8 x i1> %8, <8 x i64> %7, <8 x i64> zeroinitializer
  %10 = call <8 x i64> @llvm.x86.avx512.vpmadd52h.uq.512(<8 x i64> %x0, <8 x i64> %x1, <8 x i64> %x2)
  %res4 = add <8 x i64> %3, %6
  %res5 = add <8 x i64> %10, %9
  %res6 = add <8 x i64> %res5, %res4
  ret <8 x i64> %res6
}

declare <8 x i64> @llvm.x86.avx512.vpmadd52l.uq.512(<8 x i64>, <8 x i64>, <8 x i64>)

define <8 x i64>@test_int_x86_avx512_mask_vpmadd52l_uq_512(<8 x i64> %x0, <8 x i64> %x1, <8 x i64> %x2, i8 %x3) {
; CHECK-LABEL: test_int_x86_avx512_mask_vpmadd52l_uq_512:
; CHECK:       ## %bb.0:
; CHECK-NEXT:    vmovdqa64 %zmm0, %zmm3
; CHECK-NEXT:    vpmadd52luq %zmm2, %zmm1, %zmm3
; CHECK-NEXT:    kmovw %edi, %k1
; CHECK-NEXT:    vmovdqa64 %zmm0, %zmm4
; CHECK-NEXT:    vpmadd52luq %zmm2, %zmm1, %zmm4 {%k1}
; CHECK-NEXT:    vpxor %xmm2, %xmm2, %xmm2
; CHECK-NEXT:    vpmadd52luq %zmm2, %zmm1, %zmm0 {%k1}
; CHECK-NEXT:    vpaddq %zmm0, %zmm4, %zmm0
; CHECK-NEXT:    vpmadd52luq %zmm2, %zmm1, %zmm2 {%k1} {z}
; CHECK-NEXT:    vpaddq %zmm2, %zmm3, %zmm1
; CHECK-NEXT:    vpaddq %zmm0, %zmm1, %zmm0
; CHECK-NEXT:    retq

  %1 = call <8 x i64> @llvm.x86.avx512.vpmadd52l.uq.512(<8 x i64> %x0, <8 x i64> %x1, <8 x i64> %x2)
  %2 = bitcast i8 %x3 to <8 x i1>
  %3 = select <8 x i1> %2, <8 x i64> %1, <8 x i64> %x0
  %4 = call <8 x i64> @llvm.x86.avx512.vpmadd52l.uq.512(<8 x i64> %x0, <8 x i64> %x1, <8 x i64> zeroinitializer)
  %5 = bitcast i8 %x3 to <8 x i1>
  %6 = select <8 x i1> %5, <8 x i64> %4, <8 x i64> %x0
  %7 = call <8 x i64> @llvm.x86.avx512.vpmadd52l.uq.512(<8 x i64> zeroinitializer, <8 x i64> %x1, <8 x i64> zeroinitializer)
  %8 = bitcast i8 %x3 to <8 x i1>
  %9 = select <8 x i1> %8, <8 x i64> %7, <8 x i64> zeroinitializer
  %10 = call <8 x i64> @llvm.x86.avx512.vpmadd52l.uq.512(<8 x i64> %x0, <8 x i64> %x1, <8 x i64> %x2)
  %res4 = add <8 x i64> %3, %6
  %res5 = add <8 x i64> %10, %9
  %res6 = add <8 x i64> %res5, %res4
  ret <8 x i64> %res6
}

define <8 x i64>@test_int_x86_avx512_maskz_vpmadd52l_uq_512(<8 x i64> %x0, <8 x i64> %x1, <8 x i64> %x2, i8 %x3) {
; CHECK-LABEL: test_int_x86_avx512_maskz_vpmadd52l_uq_512:
; CHECK:       ## %bb.0:
; CHECK-NEXT:    vmovdqa64 %zmm0, %zmm3
; CHECK-NEXT:    vpmadd52luq %zmm2, %zmm1, %zmm3
; CHECK-NEXT:    kmovw %edi, %k1
; CHECK-NEXT:    vmovdqa64 %zmm0, %zmm4
; CHECK-NEXT:    vpmadd52luq %zmm2, %zmm1, %zmm4 {%k1} {z}
; CHECK-NEXT:    vpxor %xmm2, %xmm2, %xmm2
; CHECK-NEXT:    vpmadd52luq %zmm2, %zmm1, %zmm0 {%k1} {z}
; CHECK-NEXT:    vpaddq %zmm0, %zmm4, %zmm0
; CHECK-NEXT:    vpmadd52luq %zmm2, %zmm1, %zmm2 {%k1} {z}
; CHECK-NEXT:    vpaddq %zmm2, %zmm3, %zmm1
; CHECK-NEXT:    vpaddq %zmm0, %zmm1, %zmm0
; CHECK-NEXT:    retq

  %1 = call <8 x i64> @llvm.x86.avx512.vpmadd52l.uq.512(<8 x i64> %x0, <8 x i64> %x1, <8 x i64> %x2)
  %2 = bitcast i8 %x3 to <8 x i1>
  %3 = select <8 x i1> %2, <8 x i64> %1, <8 x i64> zeroinitializer
  %4 = call <8 x i64> @llvm.x86.avx512.vpmadd52l.uq.512(<8 x i64> %x0, <8 x i64> %x1, <8 x i64> zeroinitializer)
  %5 = bitcast i8 %x3 to <8 x i1>
  %6 = select <8 x i1> %5, <8 x i64> %4, <8 x i64> zeroinitializer
  %7 = call <8 x i64> @llvm.x86.avx512.vpmadd52l.uq.512(<8 x i64> zeroinitializer, <8 x i64> %x1, <8 x i64> zeroinitializer)
  %8 = bitcast i8 %x3 to <8 x i1>
  %9 = select <8 x i1> %8, <8 x i64> %7, <8 x i64> zeroinitializer
  %10 = call <8 x i64> @llvm.x86.avx512.vpmadd52l.uq.512(<8 x i64> %x0, <8 x i64> %x1, <8 x i64> %x2)
  %res4 = add <8 x i64> %3, %6
  %res5 = add <8 x i64> %10, %9
  %res6 = add <8 x i64> %res5, %res4
  ret <8 x i64> %res6
}

define <8 x i64>@test_int_x86_avx512_vpmadd52h_uq_512_load(<8 x i64> %x0, <8 x i64> %x1, <8 x i64>* %x2ptr) {
; CHECK-LABEL: test_int_x86_avx512_vpmadd52h_uq_512_load:
; CHECK:       ## %bb.0:
; CHECK-NEXT:    vpmadd52huq (%rdi), %zmm1, %zmm0
; CHECK-NEXT:    retq

  %x2 = load <8 x i64>, <8 x i64>* %x2ptr
  %1 = call <8 x i64> @llvm.x86.avx512.vpmadd52h.uq.512(<8 x i64> %x0, <8 x i64> %x1, <8 x i64> %x2)
  ret <8 x i64> %1
}

define <8 x i64>@test_int_x86_avx512_vpmadd52h_uq_512_load_bcast(<8 x i64> %x0, <8 x i64> %x1, i64* %x2ptr) {
; CHECK-LABEL: test_int_x86_avx512_vpmadd52h_uq_512_load_bcast:
; CHECK:       ## %bb.0:
; CHECK-NEXT:    vpmadd52huq (%rdi){1to8}, %zmm1, %zmm0
; CHECK-NEXT:    retq

  %x2load = load i64, i64* %x2ptr
  %x2insert = insertelement <8 x i64> undef, i64 %x2load, i64 0
  %x2 = shufflevector <8 x i64> %x2insert, <8 x i64> undef, <8 x i32> zeroinitializer
  %1 = call <8 x i64> @llvm.x86.avx512.vpmadd52h.uq.512(<8 x i64> %x0, <8 x i64> %x1, <8 x i64> %x2)
  ret <8 x i64> %1
}

define <8 x i64>@test_int_x86_avx512_vpmadd52h_uq_512_load_commute(<8 x i64> %x0, <8 x i64>* %x1ptr, <8 x i64> %x2) {
; CHECK-LABEL: test_int_x86_avx512_vpmadd52h_uq_512_load_commute:
; CHECK:       ## %bb.0:
; CHECK-NEXT:    vpmadd52huq (%rdi), %zmm1, %zmm0
; CHECK-NEXT:    retq

  %x1 = load <8 x i64>, <8 x i64>* %x1ptr
  %1 = call <8 x i64> @llvm.x86.avx512.vpmadd52h.uq.512(<8 x i64> %x0, <8 x i64> %x1, <8 x i64> %x2)
  ret <8 x i64> %1
}

define <8 x i64>@test_int_x86_avx512_vpmadd52h_uq_512_load_commute_bcast(<8 x i64> %x0, i64* %x1ptr, <8 x i64> %x2) {
; CHECK-LABEL: test_int_x86_avx512_vpmadd52h_uq_512_load_commute_bcast:
; CHECK:       ## %bb.0:
; CHECK-NEXT:    vpmadd52huq (%rdi){1to8}, %zmm1, %zmm0
; CHECK-NEXT:    retq

  %x1load = load i64, i64* %x1ptr
  %x1insert = insertelement <8 x i64> undef, i64 %x1load, i64 0
  %x1 = shufflevector <8 x i64> %x1insert, <8 x i64> undef, <8 x i32> zeroinitializer
  %1 = call <8 x i64> @llvm.x86.avx512.vpmadd52h.uq.512(<8 x i64> %x0, <8 x i64> %x1, <8 x i64> %x2)
  ret <8 x i64> %1
}

define <8 x i64>@test_int_x86_avx512_mask_vpmadd52h_uq_512_load(<8 x i64> %x0, <8 x i64> %x1, <8 x i64>* %x2ptr, i8 %x3) {
; CHECK-LABEL: test_int_x86_avx512_mask_vpmadd52h_uq_512_load:
; CHECK:       ## %bb.0:
; CHECK-NEXT:    kmovw %esi, %k1
; CHECK-NEXT:    vpmadd52huq (%rdi), %zmm1, %zmm0 {%k1}
; CHECK-NEXT:    retq

  %x2 = load <8 x i64>, <8 x i64>* %x2ptr
  %1 = call <8 x i64> @llvm.x86.avx512.vpmadd52h.uq.512(<8 x i64> %x0, <8 x i64> %x1, <8 x i64> %x2)
  %2 = bitcast i8 %x3 to <8 x i1>
  %3 = select <8 x i1> %2, <8 x i64> %1, <8 x i64> %x0
  ret <8 x i64> %3
}

define <8 x i64>@test_int_x86_avx512_mask_vpmadd52h_uq_512_load_bcast(<8 x i64> %x0, <8 x i64> %x1, i64* %x2ptr, i8 %x3) {
; CHECK-LABEL: test_int_x86_avx512_mask_vpmadd52h_uq_512_load_bcast:
; CHECK:       ## %bb.0:
; CHECK-NEXT:    kmovw %esi, %k1
; CHECK-NEXT:    vpmadd52huq (%rdi){1to8}, %zmm1, %zmm0 {%k1}
; CHECK-NEXT:    retq

  %x2load = load i64, i64* %x2ptr
  %x2insert = insertelement <8 x i64> undef, i64 %x2load, i64 0
  %x2 = shufflevector <8 x i64> %x2insert, <8 x i64> undef, <8 x i32> zeroinitializer
  %1 = call <8 x i64> @llvm.x86.avx512.vpmadd52h.uq.512(<8 x i64> %x0, <8 x i64> %x1, <8 x i64> %x2)
  %2 = bitcast i8 %x3 to <8 x i1>
  %3 = select <8 x i1> %2, <8 x i64> %1, <8 x i64> %x0
  ret <8 x i64> %3
}

define <8 x i64>@test_int_x86_avx512_mask_vpmadd52h_uq_512_load_commute(<8 x i64> %x0, <8 x i64>* %x1ptr, <8 x i64> %x2, i8 %x3) {
; CHECK-LABEL: test_int_x86_avx512_mask_vpmadd52h_uq_512_load_commute:
; CHECK:       ## %bb.0:
; CHECK-NEXT:    kmovw %esi, %k1
; CHECK-NEXT:    vpmadd52huq (%rdi), %zmm1, %zmm0 {%k1}
; CHECK-NEXT:    retq

  %x1 = load <8 x i64>, <8 x i64>* %x1ptr
  %1 = call <8 x i64> @llvm.x86.avx512.vpmadd52h.uq.512(<8 x i64> %x0, <8 x i64> %x1, <8 x i64> %x2)
  %2 = bitcast i8 %x3 to <8 x i1>
  %3 = select <8 x i1> %2, <8 x i64> %1, <8 x i64> %x0
  ret <8 x i64> %3
}

define <8 x i64>@test_int_x86_avx512_mask_vpmadd52h_uq_512_load_commute_bcast(<8 x i64> %x0, i64* %x1ptr, <8 x i64> %x2, i8 %x3) {
; CHECK-LABEL: test_int_x86_avx512_mask_vpmadd52h_uq_512_load_commute_bcast:
; CHECK:       ## %bb.0:
; CHECK-NEXT:    kmovw %esi, %k1
; CHECK-NEXT:    vpmadd52huq (%rdi){1to8}, %zmm1, %zmm0 {%k1}
; CHECK-NEXT:    retq

  %x1load = load i64, i64* %x1ptr
  %x1insert = insertelement <8 x i64> undef, i64 %x1load, i64 0
  %x1 = shufflevector <8 x i64> %x1insert, <8 x i64> undef, <8 x i32> zeroinitializer
  %1 = call <8 x i64> @llvm.x86.avx512.vpmadd52h.uq.512(<8 x i64> %x0, <8 x i64> %x1, <8 x i64> %x2)
  %2 = bitcast i8 %x3 to <8 x i1>
  %3 = select <8 x i1> %2, <8 x i64> %1, <8 x i64> %x0
  ret <8 x i64> %3
}

define <8 x i64>@test_int_x86_avx512_maskz_vpmadd52h_uq_512_load(<8 x i64> %x0, <8 x i64> %x1, <8 x i64>* %x2ptr, i8 %x3) {
; CHECK-LABEL: test_int_x86_avx512_maskz_vpmadd52h_uq_512_load:
; CHECK:       ## %bb.0:
; CHECK-NEXT:    kmovw %esi, %k1
; CHECK-NEXT:    vpmadd52huq (%rdi), %zmm1, %zmm0 {%k1} {z}
; CHECK-NEXT:    retq

  %x2 = load <8 x i64>, <8 x i64>* %x2ptr
  %1 = call <8 x i64> @llvm.x86.avx512.vpmadd52h.uq.512(<8 x i64> %x0, <8 x i64> %x1, <8 x i64> %x2)
  %2 = bitcast i8 %x3 to <8 x i1>
  %3 = select <8 x i1> %2, <8 x i64> %1, <8 x i64> zeroinitializer
  ret <8 x i64> %3
}

define <8 x i64>@test_int_x86_avx512_maskz_vpmadd52h_uq_512_load_bcast(<8 x i64> %x0, <8 x i64> %x1, i64* %x2ptr, i8 %x3) {
; CHECK-LABEL: test_int_x86_avx512_maskz_vpmadd52h_uq_512_load_bcast:
; CHECK:       ## %bb.0:
; CHECK-NEXT:    kmovw %esi, %k1
; CHECK-NEXT:    vpmadd52huq (%rdi){1to8}, %zmm1, %zmm0 {%k1} {z}
; CHECK-NEXT:    retq

  %x2load = load i64, i64* %x2ptr
  %x2insert = insertelement <8 x i64> undef, i64 %x2load, i64 0
  %x2 = shufflevector <8 x i64> %x2insert, <8 x i64> undef, <8 x i32> zeroinitializer
  %1 = call <8 x i64> @llvm.x86.avx512.vpmadd52h.uq.512(<8 x i64> %x0, <8 x i64> %x1, <8 x i64> %x2)
  %2 = bitcast i8 %x3 to <8 x i1>
  %3 = select <8 x i1> %2, <8 x i64> %1, <8 x i64> zeroinitializer
  ret <8 x i64> %3
}

define <8 x i64>@test_int_x86_avx512_maskz_vpmadd52h_uq_512_load_commute(<8 x i64> %x0, <8 x i64>* %x1ptr, <8 x i64> %x2, i8 %x3) {
; CHECK-LABEL: test_int_x86_avx512_maskz_vpmadd52h_uq_512_load_commute:
; CHECK:       ## %bb.0:
; CHECK-NEXT:    kmovw %esi, %k1
; CHECK-NEXT:    vpmadd52huq (%rdi), %zmm1, %zmm0 {%k1} {z}
; CHECK-NEXT:    retq

  %x1 = load <8 x i64>, <8 x i64>* %x1ptr
  %1 = call <8 x i64> @llvm.x86.avx512.vpmadd52h.uq.512(<8 x i64> %x0, <8 x i64> %x1, <8 x i64> %x2)
  %2 = bitcast i8 %x3 to <8 x i1>
  %3 = select <8 x i1> %2, <8 x i64> %1, <8 x i64> zeroinitializer
  ret <8 x i64> %3
}

define <8 x i64>@test_int_x86_avx512_maskz_vpmadd52h_uq_512_load_commute_bcast(<8 x i64> %x0, i64* %x1ptr, <8 x i64> %x2, i8 %x3) {
; CHECK-LABEL: test_int_x86_avx512_maskz_vpmadd52h_uq_512_load_commute_bcast:
; CHECK:       ## %bb.0:
; CHECK-NEXT:    kmovw %esi, %k1
; CHECK-NEXT:    vpmadd52huq (%rdi){1to8}, %zmm1, %zmm0 {%k1} {z}
; CHECK-NEXT:    retq

  %x1load = load i64, i64* %x1ptr
  %x1insert = insertelement <8 x i64> undef, i64 %x1load, i64 0
  %x1 = shufflevector <8 x i64> %x1insert, <8 x i64> undef, <8 x i32> zeroinitializer
  %1 = call <8 x i64> @llvm.x86.avx512.vpmadd52h.uq.512(<8 x i64> %x0, <8 x i64> %x1, <8 x i64> %x2)
  %2 = bitcast i8 %x3 to <8 x i1>
  %3 = select <8 x i1> %2, <8 x i64> %1, <8 x i64> zeroinitializer
  ret <8 x i64> %3
}
