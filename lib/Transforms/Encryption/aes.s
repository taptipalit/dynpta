/**
 * Encrypt using the basic AES Scheme:
 * 	encrypt_basic(value, pointer) -> Store aes_enc(value) to pointer
 */
.globl encrypt_basic
encrypt_basic:
       	movq %rdi, %xmm14
	movdqu %xmm14, %xmm13

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

	movdqu %xmm13, (%rsi)
	retq


# encrypt_cache(ptr) ==> Encrypt the contents of XMM13 and store to ptr
# XMM13 contains the data
.globl encrypt_cache
encrypt_cache:
	#TODO remove this
	#movdqu (%rdi), %xmm13
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

	pinsrq $0x0, %r10, %xmm0

	mov $0xea7972a48c12d064, %r10

	pinsrq $0x1, %r10, %xmm0

	movdqa %xmm0, %xmm1
	movdqa %xmm0, %xmm2
	movdqa %xmm0, %xmm3

	pxor %xmm0,  %xmm10
	pxor %xmm1,  %xmm11
	pxor %xmm2,  %xmm12
	pxor %xmm3,  %xmm13

	# Round 1
	mov $0xef9aa167197661e5, %r10
	pinsrq $0x0, %r10, %xmm0
	mov $0x36d12ca424d6304a, %r10
	pinsrq $0x1, %r10, %xmm0

	movdqa %xmm0, %xmm1
	movdqa %xmm0, %xmm2
	movdqa %xmm0, %xmm3

	aesdec %xmm0,  %xmm10
	aesdec %xmm1,  %xmm11
	aesdec %xmm2,  %xmm12
	aesdec %xmm3,  %xmm13

	# Round 2
	mov $0xf6ecc08265a79e60, %r10
	pinsrq $0x0, %r10, %xmm0
	mov $0x12071ceecb4c912d, %r10
	pinsrq $0x1, %r10, %xmm0

	movdqa %xmm0, %xmm1
	movdqa %xmm0, %xmm2
	movdqa %xmm0, %xmm3

	aesdec %xmm0,  %xmm10
	aesdec %xmm1,  %xmm11
	aesdec %xmm2,  %xmm12
	aesdec %xmm3,  %xmm13

	# Round 3
	mov $0x934b5ee2f5b8812d, %r10
	pinsrq $0x0, %r10, %xmm0
	mov $0xd94b8dc33da051af, %r10
	pinsrq $0x1, %r10, %xmm0
	
	movdqa %xmm0, %xmm1
	movdqa %xmm0, %xmm2
	movdqa %xmm0, %xmm3

	aesdec %xmm0,  %xmm10
	aesdec %xmm1,  %xmm11
	aesdec %xmm2,  %xmm12
	aesdec %xmm3,  %xmm13

	# Round 4
	mov $0x66f3dfcfc7e51c0f, %r10
	pinsrq $0x0, %r10, %xmm0
	mov $0xe4ebdc6caeeb0f4d, %r10
	pinsrq $0x1, %r10, %xmm0

	movdqa %xmm0, %xmm1
	movdqa %xmm0, %xmm2
	movdqa %xmm0, %xmm3

	aesdec %xmm0,  %xmm10
	aesdec %xmm1,  %xmm11
	aesdec %xmm2,  %xmm12
	aesdec %xmm3,  %xmm13

	# Round 5
	mov $0xa116c3c0f3b135e4, %r10
	pinsrq $0x0, %r10, %xmm0
	mov $0x4a00d321c818d082, %r10
	pinsrq $0x1, %r10, %xmm0
	
	movdqa %xmm0, %xmm1
	movdqa %xmm0, %xmm2
	movdqa %xmm0, %xmm3

	aesdec %xmm0,  %xmm10
	aesdec %xmm1,  %xmm11
	aesdec %xmm2,  %xmm12
	aesdec %xmm3,  %xmm13

	# Round 6
	mov $0x52a7f624b3bdeeca, %r10
	pinsrq $0x0, %r10, %xmm0
	mov $0x821803a3690e1342, %r10
	pinsrq $0x1, %r10, %xmm0

	movdqa %xmm0, %xmm1
	movdqa %xmm0, %xmm2
	movdqa %xmm0, %xmm3

	aesdec %xmm0,  %xmm10
	aesdec %xmm1,  %xmm11
	aesdec %xmm2,  %xmm12
	aesdec %xmm3,  %xmm13

	# Round 7
	mov $0xe11a18ee31a5ed69, %r10
	pinsrq $0x0, %r10, %xmm0
	mov $0xeb1610e13ba9e566, %r10
	pinsrq $0x1, %r10, %xmm0

	movdqa %xmm0, %xmm1
	movdqa %xmm0, %xmm2
	movdqa %xmm0, %xmm3

	aesdec %xmm0,  %xmm10
	aesdec %xmm1,  %xmm11
	aesdec %xmm2,  %xmm12
	aesdec %xmm3,  %xmm13

	# Round 8
	mov $0xd0bff587dab3fd88, %r10
	pinsrq $0x0, %r10, %xmm0
	mov $0xd0bff587dab3fd88, %r10
	pinsrq $0x1, %r10, %xmm0

	movdqa %xmm0, %xmm1
	movdqa %xmm0, %xmm2
	movdqa %xmm0, %xmm3

	aesdec %xmm0,  %xmm10
	aesdec %xmm1,  %xmm11
	aesdec %xmm2,  %xmm12
	aesdec %xmm3,  %xmm13

	# Round 9
	mov $0xa0c080f0a0c080f, %r10
	pinsrq $0x0, %r10, %xmm0
	mov $0xa0c080f0a0c080f, %r10
	pinsrq $0x1, %r10, %xmm0

	movdqa %xmm0, %xmm1
	movdqa %xmm0, %xmm2
	movdqa %xmm0, %xmm3

	aesdec %xmm0,  %xmm10
	aesdec %xmm1,  %xmm11
	aesdec %xmm2,  %xmm12
	aesdec %xmm3,  %xmm13

	# Round 10
	mov $0x62626262, %r10
	pinsrq $0x0, %r10, %xmm0
	mov $0x0, %r10
	pinsrq $0x1, %r10, %xmm0

	movdqa %xmm0, %xmm1
	movdqa %xmm0, %xmm2
	movdqa %xmm0, %xmm3

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
	pinsrq $0x0, %r10, %xmm0
	mov $0x0, %r10
	pinsrq $0x1, %r10, %xmm0

	movdqa %xmm0, %xmm1
	movdqa %xmm0, %xmm2
	movdqa %xmm0, %xmm3

	pxor %xmm0,  %xmm10
	pxor %xmm1,  %xmm11
	pxor %xmm2,  %xmm12
	pxor %xmm3,  %xmm13

#	aesenc %xmm15,  %xmm13

	# Round 1
	mov $0x101010001010100, %r10
	pinsrq $0x0, %r10, %xmm0
	mov $0x101010001010100, %r10
	pinsrq $0x1, %r10, %xmm0

	movdqa %xmm0, %xmm1
	movdqa %xmm0, %xmm2
	movdqa %xmm0, %xmm3

	aesenc %xmm0,  %xmm10
	aesenc %xmm1,  %xmm11
	aesenc %xmm2,  %xmm12
	aesenc %xmm3,  %xmm13

	# Round 2
	mov $0x637c7c7e627d7d7e, %r10
	pinsrq $0x0, %r10, %xmm0
	mov $0x637c7c7e627d7d7e, %r10
	pinsrq $0x1, %r10, %xmm0

	movdqa %xmm0, %xmm1
	movdqa %xmm0, %xmm2
	movdqa %xmm0, %xmm3

	aesenc %xmm0,  %xmm10
	aesenc %xmm1,  %xmm11
	aesenc %xmm2,  %xmm12
	aesenc %xmm3,  %xmm13

	# Round 3
	mov $0xf2fa111491866d6a, %r10
	pinsrq $0x0, %r10, %xmm0
	mov $0xf3fb101490876c6a, %r10
	pinsrq $0x1, %r10, %xmm0
	
	movdqa %xmm0, %xmm1
	movdqa %xmm0, %xmm2
	movdqa %xmm0, %xmm3

	aesenc %xmm0,  %xmm10
	aesenc %xmm1,  %xmm11
	aesenc %xmm2,  %xmm12
	aesenc %xmm3,  %xmm13

	# Round 4
	mov $0x997173bc6b8b62a8, %r10
	pinsrq $0x0, %r10, %xmm0
	mov $0xfa0d0fc209f61fd6, %r10
	pinsrq $0x1, %r10, %xmm0

	movdqa %xmm0, %xmm1
	movdqa %xmm0, %xmm2
	movdqa %xmm0, %xmm3


	aesenc %xmm0,  %xmm10
	aesenc %xmm1,  %xmm11
	aesenc %xmm2,  %xmm12
	aesenc %xmm3,  %xmm13

	# Round 5
	mov $0xd7d7c6724ea6b5ce, %r10
	pinsrq $0x0, %r10, %xmm0
	mov $0x242cd666de21d9a4, %r10
	pinsrq $0x1, %r10, %xmm0

	movdqa %xmm0, %xmm1
	movdqa %xmm0, %xmm2
	movdqa %xmm0, %xmm3

	aesenc %xmm0,  %xmm10
	aesenc %xmm1,  %xmm11
	aesenc %xmm2,  %xmm12
	aesenc %xmm3,  %xmm13

	# Round 6
	mov $0xaa47026a7d90c418, %r10
	pinsrq $0x0, %r10, %xmm0
	mov $0x504a0da87466dbce, %r10
	pinsrq $0x1, %r10, %xmm0

	movdqa %xmm0, %xmm1
	movdqa %xmm0, %xmm2
	movdqa %xmm0, %xmm3

	aesenc %xmm0,  %xmm10
	aesenc %xmm1,  %xmm11
	aesenc %xmm2,  %xmm12
	aesenc %xmm3,  %xmm13

	# Round 7
	mov $0x158410e5bfc3128f, %r10
	pinsrq $0x0, %r10, %xmm0
	mov $0x31a8c68361e2cb2b, %r10
	pinsrq $0x1, %r10, %xmm0

	movdqa %xmm0, %xmm1
	movdqa %xmm0, %xmm2
	movdqa %xmm0, %xmm3

	aesenc %xmm0,  %xmm10
	aesenc %xmm1,  %xmm11
	aesenc %xmm2,  %xmm12
	aesenc %xmm3,  %xmm13

	# Round 8
	mov $0x4680c05e5304d0bb, %r10
	pinsrq $0x0, %r10, %xmm0
	mov $0x16cacdf627620b75, %r10
	pinsrq $0x1, %r10, %xmm0

	movdqa %xmm0, %xmm1
	movdqa %xmm0, %xmm2
	movdqa %xmm0, %xmm3

	aesenc %xmm0,  %xmm10
	aesenc %xmm1,  %xmm11
	aesenc %xmm2,  %xmm12
	aesenc %xmm3,  %xmm13

	# Round 9
	mov $0x57c364431143a41d, %r10
	pinsrq $0x0, %r10, %xmm0
	mov $0x666ba2c070a16f36, %r10
	pinsrq $0x1, %r10, %xmm0

	movdqa %xmm0, %xmm1
	movdqa %xmm0, %xmm2
	movdqa %xmm0, %xmm3

	aesenc %xmm0,  %xmm10
	aesenc %xmm1,  %xmm11
	aesenc %xmm2,  %xmm12
	aesenc %xmm3,  %xmm13

	# Round 10
	mov $0xfcb3bf52ab70db11, %r10
	pinsrq $0x0, %r10, %xmm0
	mov $0xea7972a48c12d064, %r10
	pinsrq $0x1, %r10, %xmm0

	movdqa %xmm0, %xmm1
	movdqa %xmm0, %xmm2
	movdqa %xmm0, %xmm3

	aesenclast %xmm0,  %xmm10
	aesenclast %xmm1,  %xmm11
	aesenclast %xmm2,  %xmm12
	aesenclast %xmm3,  %xmm13

	movdqu %xmm10, (%rdi)
	movdqu %xmm11, 16(%rdi)
	movdqu %xmm12, 32(%rdi)
	movdqu %xmm13, 48(%rdi)

	retq


.globl decrypt_basic
decrypt_basic:
       	movdqu (%rdi), %xmm14
	movdqu %xmm14, %xmm13

	# Round 0
	mov $0xfcb3bf52ab70db11, %r10
	pinsrq $0x0, %r10, %xmm15
	mov $0xea7972a48c12d064, %r10
	pinsrq $0x1, %r10, %xmm15
	pxor %xmm15,  %xmm13

	# Round 1
	mov $0xef9aa167197661e5, %r10
	pinsrq $0x0, %r10, %xmm15
	mov $0x36d12ca424d6304a, %r10
	pinsrq $0x1, %r10, %xmm15
	aesdec %xmm15,  %xmm13


	# Round 2
	mov $0xf6ecc08265a79e60, %r10
	pinsrq $0x0, %r10, %xmm15
	mov $0x12071ceecb4c912d, %r10
	pinsrq $0x1, %r10, %xmm15
	aesdec %xmm15,  %xmm13

     	# Round 3
	mov $0x934b5ee2f5b8812d, %r10
	pinsrq $0x0, %r10, %xmm15
	mov $0xd94b8dc33da051af, %r10
	pinsrq $0x1, %r10, %xmm15
	aesdec %xmm15,  %xmm13

	# Round 4
	mov $0x66f3dfcfc7e51c0f, %r10
	pinsrq $0x0, %r10, %xmm15
	mov $0xe4ebdc6caeeb0f4d, %r10
	pinsrq $0x1, %r10, %xmm15
	aesdec %xmm15,  %xmm13

	# Round 5
	mov $0xa116c3c0f3b135e4, %r10
	pinsrq $0x0, %r10, %xmm15
	mov $0x4a00d321c818d082, %r10
	pinsrq $0x1, %r10, %xmm15
	aesdec %xmm15,  %xmm13

	# Round 6
	mov $0x52a7f624b3bdeeca, %r10
	pinsrq $0x0, %r10, %xmm15
	mov $0x821803a3690e1342, %r10
	pinsrq $0x1, %r10, %xmm15
	aesdec %xmm15,  %xmm13

	# Round 7
	mov $0xe11a18ee31a5ed69, %r10
	pinsrq $0x0, %r10, %xmm15
	mov $0xeb1610e13ba9e566, %r10
	pinsrq $0x1, %r10, %xmm15
	aesdec %xmm15,  %xmm13

	# Round 8
	mov $0xd0bff587dab3fd88, %r10
	pinsrq $0x0, %r10, %xmm15
	mov $0xd0bff587dab3fd88, %r10
	pinsrq $0x1, %r10, %xmm15
	aesdec %xmm15,  %xmm13

	# Round 9
	mov $0xa0c080f0a0c080f, %r10
	pinsrq $0x0, %r10, %xmm15
	mov $0xa0c080f0a0c080f, %r10
	pinsrq $0x1, %r10, %xmm15
	aesdec %xmm15,  %xmm13

	mov $0x62626262, %r10
	pinsrq $0x0, %r10, %xmm15
	mov $0x0, %r10
	pinsrq $0x1, %r10, %xmm15
	aesdeclast %xmm15,  %xmm13

	#movdqu %xmm13, %xmm0
	movq %xmm13, %rax
	# movdqu %xmm0, (%rdi)

	retq


# decrypt(ptr) ==> Decrypt the 128 bit contents at ptr and store to XMM13
.globl decrypt_cache
decrypt_cache:
       	movdqu (%rdi), %xmm14
	movdqu %xmm14, %xmm13

	# Round 0
	mov $0xfcb3bf52ab70db11, %r10
	pinsrq $0x0, %r10, %xmm15
	mov $0xea7972a48c12d064, %r10
	pinsrq $0x1, %r10, %xmm15
	pxor %xmm15,  %xmm13

	# Round 1
	mov $0xef9aa167197661e5, %r10
	pinsrq $0x0, %r10, %xmm15
	mov $0x36d12ca424d6304a, %r10
	pinsrq $0x1, %r10, %xmm15
	aesdec %xmm15,  %xmm13


	# Round 2
	mov $0xf6ecc08265a79e60, %r10
	pinsrq $0x0, %r10, %xmm15
	mov $0x12071ceecb4c912d, %r10
	pinsrq $0x1, %r10, %xmm15
	aesdec %xmm15,  %xmm13

     	# Round 3
	mov $0x934b5ee2f5b8812d, %r10
	pinsrq $0x0, %r10, %xmm15
	mov $0xd94b8dc33da051af, %r10
	pinsrq $0x1, %r10, %xmm15
	aesdec %xmm15,  %xmm13

	# Round 4
	mov $0x66f3dfcfc7e51c0f, %r10
	pinsrq $0x0, %r10, %xmm15
	mov $0xe4ebdc6caeeb0f4d, %r10
	pinsrq $0x1, %r10, %xmm15
	aesdec %xmm15,  %xmm13

	# Round 5
	mov $0xa116c3c0f3b135e4, %r10
	pinsrq $0x0, %r10, %xmm15
	mov $0x4a00d321c818d082, %r10
	pinsrq $0x1, %r10, %xmm15
	aesdec %xmm15,  %xmm13

	# Round 6
	mov $0x52a7f624b3bdeeca, %r10
	pinsrq $0x0, %r10, %xmm15
	mov $0x821803a3690e1342, %r10
	pinsrq $0x1, %r10, %xmm15
	aesdec %xmm15,  %xmm13

	# Round 7
	mov $0xe11a18ee31a5ed69, %r10
	pinsrq $0x0, %r10, %xmm15
	mov $0xeb1610e13ba9e566, %r10
	pinsrq $0x1, %r10, %xmm15
	aesdec %xmm15,  %xmm13

	# Round 8
	mov $0xd0bff587dab3fd88, %r10
	pinsrq $0x0, %r10, %xmm15
	mov $0xd0bff587dab3fd88, %r10
	pinsrq $0x1, %r10, %xmm15
	aesdec %xmm15,  %xmm13

	# Round 9
	mov $0xa0c080f0a0c080f, %r10
	pinsrq $0x0, %r10, %xmm15
	mov $0xa0c080f0a0c080f, %r10
	pinsrq $0x1, %r10, %xmm15
	aesdec %xmm15,  %xmm13

	mov $0x62626262, %r10
	pinsrq $0x0, %r10, %xmm15
	mov $0x0, %r10
	pinsrq $0x1, %r10, %xmm15
	aesdeclast %xmm15,  %xmm13

	#movdqu %xmm13, %xmm0
	movq %xmm13, %rax
	# movdqu %xmm0, (%rdi)

	retq





