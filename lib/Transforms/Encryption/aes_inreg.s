.align 16
enckey0:
	.quad 0x62626262
	.quad 0x0
.align 16
enckey1:
	.quad 0x101010001010100
	.quad 0x101010001010100
.align 16
enckey2:
	.quad 0x637c7c7e627d7d7e
	.quad 0x637c7c7e627d7d7e
.align 16
enckey3:
	.quad 0xf2fa111491866d6a
	.quad 0xf3fb101490876c6a
.align 16
enckey4:
	.quad 0x997173bc6b8b62a8
	.quad 0xfa0d0fc209f61fd6
.align 16
enckey5:
	.quad 0xd7d7c6724ea6b5ce
	.quad 0x242cd666de21d9a4
.align 16
enckey6:
	.quad 0xaa47026a7d90c418
	.quad 0x504a0da87466dbce
.align 16
enckey7:
	.quad 0x158410e5bfc3128f
	.quad 0x31a8c68361e2cb2b
.align 16
enckey8:
	.quad 0x4680c05e5304d0bb
	.quad 0x16cacdf627620b75
.align 16
enckey9:
	.quad 0x57c364431143a41d
	.quad 0x666ba2c070a16f36
.align 16
enckey10:
	.quad 0xfcb3bf52ab70db11
	.quad 0xea7972a48c12d064


.align 16
deckey0:
	.quad 0xfcb3bf52ab70db11
	.quad 0xea7972a48c12d064
.align 16
deckey1:
	.quad 0xef9aa167197661e5
	.quad 0x36d12ca424d6304a
.align 16
deckey2:
	.quad 0xf6ecc08265a79e60
	.quad 0x12071ceecb4c912d
.align 16
deckey3:
	.quad 0x934b5ee2f5b8812d 
	.quad 0xd94b8dc33da051af
.align 16
deckey4:
	.quad 0x66f3dfcfc7e51c0f
	.quad 0xe4ebdc6caeeb0f4d
.align 16
deckey5:
	.quad 0xa116c3c0f3b135e4
	.quad 0x4a00d321c818d082
.align 16
deckey6:
	.quad 0x52a7f624b3bdeeca
	.quad 0x821803a3690e1342
.align 16
deckey7:
	.quad 0xe11a18ee31a5ed69
	.quad 0xeb1610e13ba9e566
.align 16
deckey8:
	.quad 0xd0bff587dab3fd88
	.quad 0xd0bff587dab3fd88
.align 16
deckey9:
	.quad 0xa0c080f0a0c080f
	.quad 0xa0c080f0a0c080f
.align 16
deckey10:
	.quad 0x62626262
	.quad 0x0

.globl populate_keys
populate_keys:
    # YMM8
	# Round 0
	mov $0xfcb3bf52ab70db11, %r10
	pinsrq $0x0, %r10, %xmm15
	mov $0xea7972a48c12d064, %r10
	pinsrq $0x1, %r10, %xmm15
    movdqa %xmm15, %xmm8
   
	# Round 1
	mov $0xef9aa167197661e5, %r10
	pinsrq $0x0, %r10, %xmm15
	mov $0x36d12ca424d6304a, %r10
	pinsrq $0x1, %r10, %xmm15

    vinserti128 $0x1,%xmm15,%ymm8,%ymm8

    #YMM9
	# Round 2
	mov $0xf6ecc08265a79e60, %r10
	pinsrq $0x0, %r10, %xmm9
	mov $0x12071ceecb4c912d, %r10
	pinsrq $0x1, %r10, %xmm9

    # Round 3
	mov $0x934b5ee2f5b8812d, %r10
	pinsrq $0x0, %r10, %xmm15
	mov $0xd94b8dc33da051af, %r10
	pinsrq $0x1, %r10, %xmm15

    vinserti128 $0x1,%xmm15,%ymm9,%ymm9

    #YMM10
	# Round 4
	mov $0x66f3dfcfc7e51c0f, %r10
	pinsrq $0x0, %r10, %xmm10
	mov $0xe4ebdc6caeeb0f4d, %r10
	pinsrq $0x1, %r10, %xmm10

	# Round 5
	mov $0xa116c3c0f3b135e4, %r10
	pinsrq $0x0, %r10, %xmm15
	mov $0x4a00d321c818d082, %r10
	pinsrq $0x1, %r10, %xmm15

    vinserti128 $0x1,%xmm15,%ymm10,%ymm10

    #YMM11
	# Round 6
	mov $0x52a7f624b3bdeeca, %r10
	pinsrq $0x0, %r10, %xmm11
	mov $0x821803a3690e1342, %r10
	pinsrq $0x1, %r10, %xmm11

	# Round 7
	mov $0xe11a18ee31a5ed69, %r10
	pinsrq $0x0, %r10, %xmm15
	mov $0xeb1610e13ba9e566, %r10
	pinsrq $0x1, %r10, %xmm15

    vinserti128 $0x1,%xmm15,%ymm11,%ymm11

    #YMM12
	# Round 8
	mov $0xd0bff587dab3fd88, %r10
	pinsrq $0x0, %r10, %xmm12
	mov $0xd0bff587dab3fd88, %r10
	pinsrq $0x1, %r10, %xmm12


	# Round 9
	mov $0xa0c080f0a0c080f, %r10
	pinsrq $0x0, %r10, %xmm15
	mov $0xa0c080f0a0c080f, %r10
	pinsrq $0x1, %r10, %xmm15

    vinserti128 $0x1,%xmm15,%ymm12,%ymm12

    #YMM13
	# Round 10
	mov $0x62626262, %r10
	pinsrq $0x0, %r10, %xmm13
	mov $0x0, %r10
	pinsrq $0x1, %r10, %xmm13

	retq



# decrypt(ptr) ==> Decrypt the 128 bit contents at ptr and store to XMM13
.globl decrypt_cache
decrypt_cache:
    movdqu (%rdi), %xmm14

    vextracti128 $0x0, %ymm8, %xmm0
	pxor %xmm0,  %xmm13
    vextracti128 $0x1, %ymm8, %xmm0
	aesdec %xmm0,  %xmm14

    vextracti128 $0x0, %ymm9, %xmm0
	aesdec %xmm0,  %xmm14
    vextracti128 $0x1, %ymm9, %xmm0
	aesdec %xmm0,  %xmm14

    vextracti128 $0x0, %ymm10, %xmm0
	aesdec %xmm0,  %xmm14
    vextracti128 $0x1, %ymm10, %xmm0
	aesdec %xmm0,  %xmm14

    vextracti128 $0x0, %ymm11, %xmm0
	aesdec %xmm0,  %xmm14
    vextracti128 $0x1, %ymm11, %xmm0
	aesdec %xmm0,  %xmm14

    vextracti128 $0x0, %ymm12, %xmm0
	aesdec %xmm0,  %xmm14
    vextracti128 $0x1, %ymm12, %xmm0
	aesdec %xmm0,  %xmm14

    vextracti128 $0x0, %ymm13, %xmm0
	aesdeclast %xmm0,  %xmm14

	retq


# encrypt_cache(ptr) ==> Encrypt the contents of XMM13 and store to ptr
# XMM13 contains the data
.globl encrypt_cache
encrypt_cache:
	# Round 0
	mov $0x62626262, %r10
	pinsrq $0x0, %r10, %xmm15
	mov $0x0, %r10
	pinsrq $0x1, %r10, %xmm15
	pxor %xmm15,  %xmm13
#	aesenc %xmm15,  %xmm13

	# Round 1
	mov $0x101010001010100, %r10
	pinsrq $0x0, %r10, %xmm15
	mov $0x101010001010100, %r10
	pinsrq $0x1, %r10, %xmm15
	aesenc %xmm15,  %xmm13

	# Round 2
	mov $0x637c7c7e627d7d7e, %r10
	pinsrq $0x0, %r10, %xmm15
	mov $0x637c7c7e627d7d7e, %r10
	pinsrq $0x1, %r10, %xmm15
	aesenc %xmm15,  %xmm13

	# Round 3
	mov $0xf2fa111491866d6a, %r10
	pinsrq $0x0, %r10, %xmm15
	mov $0xf3fb101490876c6a, %r10
	pinsrq $0x1, %r10, %xmm15
	aesenc %xmm15,  %xmm13

     	# Round 4
	mov $0x997173bc6b8b62a8, %r10
	pinsrq $0x0, %r10, %xmm15
	mov $0xfa0d0fc209f61fd6, %r10
	pinsrq $0x1, %r10, %xmm15
	aesenc %xmm15,  %xmm13

	# Round 5
	mov $0xd7d7c6724ea6b5ce, %r10
	pinsrq $0x0, %r10, %xmm15
	mov $0x242cd666de21d9a4, %r10
	pinsrq $0x1, %r10, %xmm15
	aesenc %xmm15,  %xmm13

	# Round 6
	mov $0xaa47026a7d90c418, %r10
	pinsrq $0x0, %r10, %xmm15
	mov $0x504a0da87466dbce, %r10
	pinsrq $0x1, %r10, %xmm15
	aesenc %xmm15,  %xmm13

	# Round 7
	mov $0x158410e5bfc3128f, %r10
	pinsrq $0x0, %r10, %xmm15
	mov $0x31a8c68361e2cb2b, %r10
	pinsrq $0x1, %r10, %xmm15
	aesenc %xmm15,  %xmm13

	# Round 8
	mov $0x4680c05e5304d0bb, %r10
	pinsrq $0x0, %r10, %xmm15
	mov $0x16cacdf627620b75, %r10
	pinsrq $0x1, %r10, %xmm15
	aesenc %xmm15,  %xmm13

	# Round 9
	mov $0x57c364431143a41d, %r10
	pinsrq $0x0, %r10, %xmm15
	mov $0x666ba2c070a16f36, %r10
	pinsrq $0x1, %r10, %xmm15
	aesenc %xmm15,  %xmm13

	# Round 10
	mov $0xfcb3bf52ab70db11, %r10
	pinsrq $0x0, %r10, %xmm15
	mov $0xea7972a48c12d064, %r10
	pinsrq $0x1, %r10, %xmm15
	aesenclast %xmm15,  %xmm13

	movdqu %xmm13, (%rdi)
	retq

.globl decrypt_cache_pipelined
decrypt_cache_pipelined:
	movdqu (%rdi), %xmm10
	movdqu 16(%rdi), %xmm11
	movdqu 32(%rdi), %xmm12
	movdqu 48(%rdi), %xmm13

	# Round 0
	mov $0xfcb3bf52ab70db11, %r10
	mov $0xfcb3bf52ab70db11, %r11
	mov $0xfcb3bf52ab70db11, %r12
	mov $0xfcb3bf52ab70db11, %r13

	pinsrq $0x0, %r10, %xmm0
	pinsrq $0x0, %r11, %xmm1
	pinsrq $0x0, %r12, %xmm2
	pinsrq $0x0, %r13, %xmm3

	mov $0xea7972a48c12d064, %r10
	mov $0xea7972a48c12d064, %r11
	mov $0xea7972a48c12d064, %r12
	mov $0xea7972a48c12d064, %r13

	pinsrq $0x1, %r10, %xmm0
	pinsrq $0x1, %r11, %xmm1
	pinsrq $0x1, %r12, %xmm2
	pinsrq $0x1, %r13, %xmm3

	pxor %xmm0,  %xmm10
	pxor %xmm1,  %xmm11
	pxor %xmm2,  %xmm12
	pxor %xmm3,  %xmm13

	# Round 1
	mov $0xef9aa167197661e5, %r10
	mov $0xef9aa167197661e5, %r11
	mov $0xef9aa167197661e5, %r12
	mov $0xef9aa167197661e5, %r13

	pinsrq $0x0, %r10, %xmm0
	pinsrq $0x0, %r11, %xmm1
	pinsrq $0x0, %r12, %xmm2
	pinsrq $0x0, %r13, %xmm3

	mov $0x36d12ca424d6304a, %r10
	mov $0x36d12ca424d6304a, %r11
	mov $0x36d12ca424d6304a, %r12
	mov $0x36d12ca424d6304a, %r13

	pinsrq $0x1, %r10, %xmm0
	pinsrq $0x1, %r11, %xmm1
	pinsrq $0x1, %r12, %xmm2
	pinsrq $0x1, %r13, %xmm3

	aesdec %xmm0,  %xmm10
	aesdec %xmm1,  %xmm11
	aesdec %xmm2,  %xmm12
	aesdec %xmm3,  %xmm13

	# Round 2
	mov $0xf6ecc08265a79e60, %r10
	mov $0xf6ecc08265a79e60, %r11
	mov $0xf6ecc08265a79e60, %r12
	mov $0xf6ecc08265a79e60, %r13

	pinsrq $0x0, %r10, %xmm0
	pinsrq $0x0, %r11, %xmm1
	pinsrq $0x0, %r12, %xmm2
	pinsrq $0x0, %r13, %xmm3

	mov $0x12071ceecb4c912d, %r10
	mov $0x12071ceecb4c912d, %r11
	mov $0x12071ceecb4c912d, %r12
	mov $0x12071ceecb4c912d, %r13

	pinsrq $0x1, %r10, %xmm0
	pinsrq $0x1, %r11, %xmm1
	pinsrq $0x1, %r12, %xmm2
	pinsrq $0x1, %r13, %xmm3

	aesdec %xmm0,  %xmm10
	aesdec %xmm1,  %xmm11
	aesdec %xmm2,  %xmm12
	aesdec %xmm3,  %xmm13

	# Round 3
	mov $0x934b5ee2f5b8812d, %r10
	mov $0x934b5ee2f5b8812d, %r11
	mov $0x934b5ee2f5b8812d, %r12
	mov $0x934b5ee2f5b8812d, %r13

	pinsrq $0x0, %r10, %xmm0
	pinsrq $0x0, %r11, %xmm1
	pinsrq $0x0, %r12, %xmm2
	pinsrq $0x0, %r13, %xmm3

	mov $0xd94b8dc33da051af, %r10
	mov $0xd94b8dc33da051af, %r11
	mov $0xd94b8dc33da051af, %r12
	mov $0xd94b8dc33da051af, %r13

	pinsrq $0x1, %r10, %xmm0
	pinsrq $0x1, %r11, %xmm1
	pinsrq $0x1, %r12, %xmm2
	pinsrq $0x1, %r13, %xmm3

	aesdec %xmm0,  %xmm10
	aesdec %xmm1,  %xmm11
	aesdec %xmm2,  %xmm12
	aesdec %xmm3,  %xmm13

	# Round 4
	mov $0x66f3dfcfc7e51c0f, %r10
	mov $0x66f3dfcfc7e51c0f, %r11
	mov $0x66f3dfcfc7e51c0f, %r12
	mov $0x66f3dfcfc7e51c0f, %r13

	pinsrq $0x0, %r10, %xmm0
	pinsrq $0x0, %r11, %xmm1
	pinsrq $0x0, %r12, %xmm2
	pinsrq $0x0, %r13, %xmm3

	mov $0xe4ebdc6caeeb0f4d, %r10
	mov $0xe4ebdc6caeeb0f4d, %r11
	mov $0xe4ebdc6caeeb0f4d, %r12
	mov $0xe4ebdc6caeeb0f4d, %r13

	pinsrq $0x1, %r10, %xmm0
	pinsrq $0x1, %r11, %xmm1
	pinsrq $0x1, %r12, %xmm2
	pinsrq $0x1, %r13, %xmm3

	aesdec %xmm0,  %xmm10
	aesdec %xmm1,  %xmm11
	aesdec %xmm2,  %xmm12
	aesdec %xmm3,  %xmm13

	# Round 5
	mov $0xa116c3c0f3b135e4, %r10
	mov $0xa116c3c0f3b135e4, %r11
	mov $0xa116c3c0f3b135e4, %r12
	mov $0xa116c3c0f3b135e4, %r13

	pinsrq $0x0, %r10, %xmm0
	pinsrq $0x0, %r11, %xmm1
	pinsrq $0x0, %r12, %xmm2
	pinsrq $0x0, %r13, %xmm3

	mov $0x4a00d321c818d082, %r10
	mov $0x4a00d321c818d082, %r11
	mov $0x4a00d321c818d082, %r12
	mov $0x4a00d321c818d082, %r13

	pinsrq $0x1, %r10, %xmm0
	pinsrq $0x1, %r11, %xmm1
	pinsrq $0x1, %r12, %xmm2
	pinsrq $0x1, %r13, %xmm3

	aesdec %xmm0,  %xmm10
	aesdec %xmm1,  %xmm11
	aesdec %xmm2,  %xmm12
	aesdec %xmm3,  %xmm13

	# Round 6
	mov $0x52a7f624b3bdeeca, %r10
	mov $0x52a7f624b3bdeeca, %r11
	mov $0x52a7f624b3bdeeca, %r12
	mov $0x52a7f624b3bdeeca, %r13

	pinsrq $0x0, %r10, %xmm0
	pinsrq $0x0, %r11, %xmm1
	pinsrq $0x0, %r12, %xmm2
	pinsrq $0x0, %r13, %xmm3

	mov $0x821803a3690e1342, %r10
	mov $0x821803a3690e1342, %r11
	mov $0x821803a3690e1342, %r12
	mov $0x821803a3690e1342, %r13

	pinsrq $0x1, %r10, %xmm0
	pinsrq $0x1, %r11, %xmm1
	pinsrq $0x1, %r12, %xmm2
	pinsrq $0x1, %r13, %xmm3

	aesdec %xmm0,  %xmm10
	aesdec %xmm1,  %xmm11
	aesdec %xmm2,  %xmm12
	aesdec %xmm3,  %xmm13

	# Round 7
	mov $0xe11a18ee31a5ed69, %r10
	mov $0xe11a18ee31a5ed69, %r11
	mov $0xe11a18ee31a5ed69, %r12
	mov $0xe11a18ee31a5ed69, %r13

	pinsrq $0x0, %r10, %xmm0
	pinsrq $0x0, %r11, %xmm1
	pinsrq $0x0, %r12, %xmm2
	pinsrq $0x0, %r13, %xmm3

	mov $0xeb1610e13ba9e566, %r10
	mov $0xeb1610e13ba9e566, %r11
	mov $0xeb1610e13ba9e566, %r12
	mov $0xeb1610e13ba9e566, %r13

	pinsrq $0x1, %r10, %xmm0
	pinsrq $0x1, %r11, %xmm1
	pinsrq $0x1, %r12, %xmm2
	pinsrq $0x1, %r13, %xmm3

	aesdec %xmm0,  %xmm10
	aesdec %xmm1,  %xmm11
	aesdec %xmm2,  %xmm12
	aesdec %xmm3,  %xmm13

	# Round 8
	mov $0xd0bff587dab3fd88, %r10
	mov $0xd0bff587dab3fd88, %r11
	mov $0xd0bff587dab3fd88, %r12
	mov $0xd0bff587dab3fd88, %r13

	pinsrq $0x0, %r10, %xmm0
	pinsrq $0x0, %r11, %xmm1
	pinsrq $0x0, %r12, %xmm2
	pinsrq $0x0, %r13, %xmm3

	mov $0xd0bff587dab3fd88, %r10
	mov $0xd0bff587dab3fd88, %r11
	mov $0xd0bff587dab3fd88, %r12
	mov $0xd0bff587dab3fd88, %r13

	pinsrq $0x1, %r10, %xmm0
	pinsrq $0x1, %r11, %xmm1
	pinsrq $0x1, %r12, %xmm2
	pinsrq $0x1, %r13, %xmm3

	aesdec %xmm0,  %xmm10
	aesdec %xmm1,  %xmm11
	aesdec %xmm2,  %xmm12
	aesdec %xmm3,  %xmm13

	# Round 9
	mov $0xa0c080f0a0c080f, %r10
	mov $0xa0c080f0a0c080f, %r11
	mov $0xa0c080f0a0c080f, %r12
	mov $0xa0c080f0a0c080f, %r13

	pinsrq $0x0, %r10, %xmm0
	pinsrq $0x0, %r11, %xmm1
	pinsrq $0x0, %r12, %xmm2
	pinsrq $0x0, %r13, %xmm3

	mov $0xa0c080f0a0c080f, %r10
	mov $0xa0c080f0a0c080f, %r11
	mov $0xa0c080f0a0c080f, %r12
	mov $0xa0c080f0a0c080f, %r13

	pinsrq $0x1, %r10, %xmm0
	pinsrq $0x1, %r11, %xmm1
	pinsrq $0x1, %r12, %xmm2
	pinsrq $0x1, %r13, %xmm3

	aesdec %xmm0,  %xmm10
	aesdec %xmm1,  %xmm11
	aesdec %xmm2,  %xmm12
	aesdec %xmm3,  %xmm13

	# Round 10
	mov $0x62626262, %r10
	mov $0x62626262, %r11
	mov $0x62626262, %r12
	mov $0x62626262, %r13

	pinsrq $0x0, %r10, %xmm0
	pinsrq $0x0, %r11, %xmm1
	pinsrq $0x0, %r12, %xmm2
	pinsrq $0x0, %r13, %xmm3

	mov $0x0, %r10
	mov $0x0, %r11
	mov $0x0, %r12
	mov $0x0, %r13

	pinsrq $0x1, %r10, %xmm0
	pinsrq $0x1, %r11, %xmm1
	pinsrq $0x1, %r12, %xmm2
	pinsrq $0x1, %r13, %xmm3

	aesdeclast %xmm0,  %xmm10
	aesdeclast %xmm1,  %xmm11
	aesdeclast %xmm2,  %xmm12
	aesdeclast %xmm3,  %xmm13

	retq


.globl encrypt_cache_pipelined
encrypt_cache_pipelined:
	#TODO REMOVE begin
	#movdqu (%rdi), %xmm10
	#movdqu 16(%rdi), %xmm11
	#movdqu 32(%rdi), %xmm12
	#movdqu 48(%rdi), %xmm13
	#TODO REMOVE end

	# Round 0
	mov $0x62626262, %r10
	mov $0x62626262, %r11
	mov $0x62626262, %r12
	mov $0x62626262, %r13

	pinsrq $0x0, %r10, %xmm0
	pinsrq $0x0, %r11, %xmm1
	pinsrq $0x0, %r12, %xmm2
	pinsrq $0x0, %r13, %xmm3

	mov $0x0, %r10
	mov $0x0, %r11
	mov $0x0, %r12
	mov $0x0, %r13

	pinsrq $0x1, %r10, %xmm0
	pinsrq $0x1, %r11, %xmm1
	pinsrq $0x1, %r12, %xmm2
	pinsrq $0x1, %r13, %xmm3

	pxor %xmm0,  %xmm10
	pxor %xmm1,  %xmm11
	pxor %xmm2,  %xmm12
	pxor %xmm3,  %xmm13

#	aesenc %xmm15,  %xmm13

	# Round 1
	mov $0x101010001010100, %r10
	mov $0x101010001010100, %r11
	mov $0x101010001010100, %r12
	mov $0x101010001010100, %r13

	pinsrq $0x0, %r10, %xmm0
	pinsrq $0x0, %r11, %xmm1
	pinsrq $0x0, %r12, %xmm2
	pinsrq $0x0, %r13, %xmm3

	mov $0x101010001010100, %r10
	mov $0x101010001010100, %r11
	mov $0x101010001010100, %r12
	mov $0x101010001010100, %r13

	pinsrq $0x1, %r10, %xmm0
	pinsrq $0x1, %r11, %xmm1
	pinsrq $0x1, %r12, %xmm2
	pinsrq $0x1, %r13, %xmm3

	aesenc %xmm0,  %xmm10
	aesenc %xmm1,  %xmm11
	aesenc %xmm2,  %xmm12
	aesenc %xmm3,  %xmm13

	# Round 2
	mov $0x637c7c7e627d7d7e, %r10
	mov $0x637c7c7e627d7d7e, %r11
	mov $0x637c7c7e627d7d7e, %r12
	mov $0x637c7c7e627d7d7e, %r13

	pinsrq $0x0, %r10, %xmm0
	pinsrq $0x0, %r11, %xmm1
	pinsrq $0x0, %r12, %xmm2
	pinsrq $0x0, %r13, %xmm3

	mov $0x637c7c7e627d7d7e, %r10
	mov $0x637c7c7e627d7d7e, %r11
	mov $0x637c7c7e627d7d7e, %r12
	mov $0x637c7c7e627d7d7e, %r13

	pinsrq $0x1, %r10, %xmm0
	pinsrq $0x1, %r11, %xmm1
	pinsrq $0x1, %r12, %xmm2
	pinsrq $0x1, %r13, %xmm3

	aesenc %xmm0,  %xmm10
	aesenc %xmm1,  %xmm11
	aesenc %xmm2,  %xmm12
	aesenc %xmm3,  %xmm13

	# Round 3
	mov $0xf2fa111491866d6a, %r10
	mov $0xf2fa111491866d6a, %r11
	mov $0xf2fa111491866d6a, %r12
	mov $0xf2fa111491866d6a, %r13

	pinsrq $0x0, %r10, %xmm0
	pinsrq $0x0, %r11, %xmm1
	pinsrq $0x0, %r12, %xmm2
	pinsrq $0x0, %r13, %xmm3

	mov $0xf3fb101490876c6a, %r10
	mov $0xf3fb101490876c6a, %r11
	mov $0xf3fb101490876c6a, %r12
	mov $0xf3fb101490876c6a, %r13

	pinsrq $0x1, %r10, %xmm0
	pinsrq $0x1, %r11, %xmm1
	pinsrq $0x1, %r12, %xmm2
	pinsrq $0x1, %r13, %xmm3

	aesenc %xmm0,  %xmm10
	aesenc %xmm1,  %xmm11
	aesenc %xmm2,  %xmm12
	aesenc %xmm3,  %xmm13

	# Round 4
	mov $0x997173bc6b8b62a8, %r10
	mov $0x997173bc6b8b62a8, %r11
	mov $0x997173bc6b8b62a8, %r12
	mov $0x997173bc6b8b62a8, %r13

	pinsrq $0x0, %r10, %xmm0
	pinsrq $0x0, %r11, %xmm1
	pinsrq $0x0, %r12, %xmm2
	pinsrq $0x0, %r13, %xmm3

	mov $0xfa0d0fc209f61fd6, %r10
	mov $0xfa0d0fc209f61fd6, %r11
	mov $0xfa0d0fc209f61fd6, %r12
	mov $0xfa0d0fc209f61fd6, %r13

	pinsrq $0x1, %r10, %xmm0
	pinsrq $0x1, %r11, %xmm1
	pinsrq $0x1, %r12, %xmm2
	pinsrq $0x1, %r13, %xmm3

	aesenc %xmm0,  %xmm10
	aesenc %xmm1,  %xmm11
	aesenc %xmm2,  %xmm12
	aesenc %xmm3,  %xmm13

	# Round 5
	mov $0xd7d7c6724ea6b5ce, %r10
	mov $0xd7d7c6724ea6b5ce, %r11
	mov $0xd7d7c6724ea6b5ce, %r12
	mov $0xd7d7c6724ea6b5ce, %r13

	pinsrq $0x0, %r10, %xmm0
	pinsrq $0x0, %r11, %xmm1
	pinsrq $0x0, %r12, %xmm2
	pinsrq $0x0, %r13, %xmm3

	mov $0x242cd666de21d9a4, %r10
	mov $0x242cd666de21d9a4, %r11
	mov $0x242cd666de21d9a4, %r12
	mov $0x242cd666de21d9a4, %r13

	pinsrq $0x1, %r10, %xmm0
	pinsrq $0x1, %r11, %xmm1
	pinsrq $0x1, %r12, %xmm2
	pinsrq $0x1, %r13, %xmm3

	aesenc %xmm0,  %xmm10
	aesenc %xmm1,  %xmm11
	aesenc %xmm2,  %xmm12
	aesenc %xmm3,  %xmm13

	# Round 6
	mov $0xaa47026a7d90c418, %r10
	mov $0xaa47026a7d90c418, %r11
	mov $0xaa47026a7d90c418, %r12
	mov $0xaa47026a7d90c418, %r13

	pinsrq $0x0, %r10, %xmm0
	pinsrq $0x0, %r11, %xmm1
	pinsrq $0x0, %r12, %xmm2
	pinsrq $0x0, %r13, %xmm3

	mov $0x504a0da87466dbce, %r10
	mov $0x504a0da87466dbce, %r11
	mov $0x504a0da87466dbce, %r12
	mov $0x504a0da87466dbce, %r13

	pinsrq $0x1, %r10, %xmm0
	pinsrq $0x1, %r11, %xmm1
	pinsrq $0x1, %r12, %xmm2
	pinsrq $0x1, %r13, %xmm3

	aesenc %xmm0,  %xmm10
	aesenc %xmm1,  %xmm11
	aesenc %xmm2,  %xmm12
	aesenc %xmm3,  %xmm13

	# Round 7
	mov $0x158410e5bfc3128f, %r10
	mov $0x158410e5bfc3128f, %r11
	mov $0x158410e5bfc3128f, %r12
	mov $0x158410e5bfc3128f, %r13

	pinsrq $0x0, %r10, %xmm0
	pinsrq $0x0, %r11, %xmm1
	pinsrq $0x0, %r12, %xmm2
	pinsrq $0x0, %r13, %xmm3

	mov $0x31a8c68361e2cb2b, %r10
	mov $0x31a8c68361e2cb2b, %r11
	mov $0x31a8c68361e2cb2b, %r12
	mov $0x31a8c68361e2cb2b, %r13

	pinsrq $0x1, %r10, %xmm0
	pinsrq $0x1, %r11, %xmm1
	pinsrq $0x1, %r12, %xmm2
	pinsrq $0x1, %r13, %xmm3

	aesenc %xmm0,  %xmm10
	aesenc %xmm1,  %xmm11
	aesenc %xmm2,  %xmm12
	aesenc %xmm3,  %xmm13

	# Round 8
	mov $0x4680c05e5304d0bb, %r10
	mov $0x4680c05e5304d0bb, %r11
	mov $0x4680c05e5304d0bb, %r12
	mov $0x4680c05e5304d0bb, %r13

	pinsrq $0x0, %r10, %xmm0
	pinsrq $0x0, %r11, %xmm1
	pinsrq $0x0, %r12, %xmm2
	pinsrq $0x0, %r13, %xmm3

	mov $0x16cacdf627620b75, %r10
	mov $0x16cacdf627620b75, %r11
	mov $0x16cacdf627620b75, %r12
	mov $0x16cacdf627620b75, %r13

	pinsrq $0x1, %r10, %xmm0
	pinsrq $0x1, %r11, %xmm1
	pinsrq $0x1, %r12, %xmm2
	pinsrq $0x1, %r13, %xmm3

	aesenc %xmm0,  %xmm10
	aesenc %xmm1,  %xmm11
	aesenc %xmm2,  %xmm12
	aesenc %xmm3,  %xmm13

	# Round 9
	mov $0x57c364431143a41d, %r10
	mov $0x57c364431143a41d, %r11
	mov $0x57c364431143a41d, %r12
	mov $0x57c364431143a41d, %r13

	pinsrq $0x0, %r10, %xmm0
	pinsrq $0x0, %r11, %xmm1
	pinsrq $0x0, %r12, %xmm2
	pinsrq $0x0, %r13, %xmm3

	mov $0x666ba2c070a16f36, %r10
	mov $0x666ba2c070a16f36, %r11
	mov $0x666ba2c070a16f36, %r12
	mov $0x666ba2c070a16f36, %r13

	pinsrq $0x1, %r10, %xmm0
	pinsrq $0x1, %r11, %xmm1
	pinsrq $0x1, %r12, %xmm2
	pinsrq $0x1, %r13, %xmm3

	aesenc %xmm0,  %xmm10
	aesenc %xmm1,  %xmm11
	aesenc %xmm2,  %xmm12
	aesenc %xmm3,  %xmm13

	# Round 10
	mov $0xfcb3bf52ab70db11, %r10
	mov $0xfcb3bf52ab70db11, %r11
	mov $0xfcb3bf52ab70db11, %r12
	mov $0xfcb3bf52ab70db11, %r13

	pinsrq $0x0, %r10, %xmm0
	pinsrq $0x0, %r11, %xmm1
	pinsrq $0x0, %r12, %xmm2
	pinsrq $0x0, %r13, %xmm3

	mov $0xea7972a48c12d064, %r10
	mov $0xea7972a48c12d064, %r11
	mov $0xea7972a48c12d064, %r12
	mov $0xea7972a48c12d064, %r13

	pinsrq $0x1, %r10, %xmm0
	pinsrq $0x1, %r11, %xmm1
	pinsrq $0x1, %r12, %xmm2
	pinsrq $0x1, %r13, %xmm3

	aesenclast %xmm0,  %xmm10
	aesenclast %xmm1,  %xmm11
	aesenclast %xmm2,  %xmm12
	aesenclast %xmm3,  %xmm13

	movdqu %xmm10, (%rdi)
	movdqu %xmm11, 16(%rdi)
	movdqu %xmm12, 32(%rdi)
	movdqu %xmm13, 48(%rdi)

	retq

.globl encrypt_memory
encrypt_memory:
	movdqu (%rdi), %xmm14
	# Round 0
	movdqa enckey0(%rip), %xmm15
	pxor %xmm15,  %xmm14
#	aesenc %xmm15,  %xmm13

	# Round 1
	movdqa enckey1(%rip), %xmm15
	aesenc %xmm15,  %xmm14


	# Round 2
	movdqa enckey2(%rip), %xmm15
	aesenc %xmm15,  %xmm14

     	# Round 3
	movdqa enckey3(%rip), %xmm15
	aesenc %xmm15,  %xmm14

     	# Round 4
	movdqa enckey4(%rip), %xmm15
	aesenc %xmm15,  %xmm14

	# Round 5
	movdqa enckey5(%rip), %xmm15
	aesenc %xmm15,  %xmm14

	# Round 6
	movdqa enckey6(%rip), %xmm15
	aesenc %xmm15,  %xmm14

	# Round 7
	movdqa enckey7(%rip), %xmm15
	aesenc %xmm15,  %xmm14

	# Round 8
	movdqa enckey8(%rip), %xmm15
	aesenc %xmm15,  %xmm14

	# Round 9
	movdqa enckey9(%rip), %xmm15
	aesenc %xmm15,  %xmm14

	# Round 10
	movdqa enckey10(%rip), %xmm15
	aesenclast %xmm15,  %xmm14

	movdqu %xmm14, (%rdi)
	retq

.globl decrypt_memory
decrypt_memory:
    movdqu (%rdi), %xmm14

    vextracti128 $0x0, %ymm8, %xmm0
	pxor %xmm0,  %xmm14
    vextracti128 $0x1, %ymm8, %xmm0
	aesdec %xmm0,  %xmm14

    vextracti128 $0x0, %ymm9, %xmm0
	aesdec %xmm0,  %xmm14
    vextracti128 $0x1, %ymm9, %xmm0
	aesdec %xmm0,  %xmm14

    vextracti128 $0x0, %ymm10, %xmm0
	aesdec %xmm0,  %xmm14
    vextracti128 $0x1, %ymm10, %xmm0
	aesdec %xmm0,  %xmm14

    vextracti128 $0x0, %ymm11, %xmm0
	aesdec %xmm0,  %xmm14
    vextracti128 $0x1, %ymm11, %xmm0
	aesdec %xmm0,  %xmm14

    vextracti128 $0x0, %ymm12, %xmm0
	aesdec %xmm0,  %xmm14
    vextracti128 $0x1, %ymm12, %xmm0
	aesdec %xmm0,  %xmm14

    vextracti128 $0x0, %ymm13, %xmm0
	aesdeclast %xmm0,  %xmm14

    movdqu %xmm14, (%rdi)
	retq

