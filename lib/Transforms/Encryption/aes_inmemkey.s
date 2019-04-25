/**
 * Encrypt using the basic AES Scheme:
 * 	encrypt_basic(value, pointer) -> Store aes_enc(value) to pointer
 */
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
.globl encrypt_basic
encrypt_basic:
       	movq %rdi, %xmm14
	movdqu %xmm14, %xmm13

	# Round 0
	movdqa enckey0(%rip), %xmm15
	pxor %xmm15,  %xmm13
#	aesenc %xmm15,  %xmm13

	# Round 1
	movdqa enckey1(%rip), %xmm15
	aesenc %xmm15,  %xmm13


	# Round 2
	movdqa enckey2(%rip), %xmm15
	aesenc %xmm15,  %xmm13

     	# Round 3
	movdqa enckey3(%rip), %xmm15
	aesenc %xmm15,  %xmm13

     	# Round 4
	movdqa enckey4(%rip), %xmm15
	aesenc %xmm15,  %xmm13

	# Round 5
	movdqa enckey5(%rip), %xmm15
	aesenc %xmm15,  %xmm13

	# Round 6
	movdqa enckey6(%rip), %xmm15
	aesenc %xmm15,  %xmm13

	# Round 7
	movdqa enckey7(%rip), %xmm15
	aesenc %xmm15,  %xmm13

	# Round 8
	movdqa enckey8(%rip), %xmm15
	aesenc %xmm15,  %xmm13

	# Round 9
	movdqa enckey9(%rip), %xmm15
	aesenc %xmm15,  %xmm13

	# Round 10
	movdqa enckey10(%rip), %xmm15
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
	movdqa enckey0(%rip), %xmm15
	pxor %xmm15,  %xmm13
#	aesenc %xmm15,  %xmm13

	# Round 1
	movdqa enckey1(%rip), %xmm15
	aesenc %xmm15,  %xmm13


	# Round 2
	movdqa enckey2(%rip), %xmm15
	aesenc %xmm15,  %xmm13

     	# Round 3
	movdqa enckey3(%rip), %xmm15
	aesenc %xmm15,  %xmm13

     	# Round 4
	movdqa enckey4(%rip), %xmm15
	aesenc %xmm15,  %xmm13

	# Round 5
	movdqa enckey5(%rip), %xmm15
	aesenc %xmm15,  %xmm13

	# Round 6
	movdqa enckey6(%rip), %xmm15
	aesenc %xmm15,  %xmm13

	# Round 7
	movdqa enckey7(%rip), %xmm15
	aesenc %xmm15,  %xmm13

	# Round 8
	movdqa enckey8(%rip), %xmm15
	aesenc %xmm15,  %xmm13

	# Round 9
	movdqa enckey9(%rip), %xmm15
	aesenc %xmm15,  %xmm13

	# Round 10
	movdqa enckey10(%rip), %xmm15
	aesenclast %xmm15,  %xmm13

	movdqu %xmm13, (%rdi)
	retq

.globl encrypt_memory
encrypt_memory:
	movdqu (%rdi), %xmm13
	# Round 0
	movdqa enckey0(%rip), %xmm15
	pxor %xmm15,  %xmm13
#	aesenc %xmm15,  %xmm13

	# Round 1
	movdqa enckey1(%rip), %xmm15
	aesenc %xmm15,  %xmm13


	# Round 2
	movdqa enckey2(%rip), %xmm15
	aesenc %xmm15,  %xmm13

     	# Round 3
	movdqa enckey3(%rip), %xmm15
	aesenc %xmm15,  %xmm13

     	# Round 4
	movdqa enckey4(%rip), %xmm15
	aesenc %xmm15,  %xmm13

	# Round 5
	movdqa enckey5(%rip), %xmm15
	aesenc %xmm15,  %xmm13

	# Round 6
	movdqa enckey6(%rip), %xmm15
	aesenc %xmm15,  %xmm13

	# Round 7
	movdqa enckey7(%rip), %xmm15
	aesenc %xmm15,  %xmm13

	# Round 8
	movdqa enckey8(%rip), %xmm15
	aesenc %xmm15,  %xmm13

	# Round 9
	movdqa enckey9(%rip), %xmm15
	aesenc %xmm15,  %xmm13

	# Round 10
	movdqa enckey10(%rip), %xmm15
	aesenclast %xmm15,  %xmm13

	movdqu %xmm13, (%rdi)
	retq

.globl ext_decrypt_cache_pipelined
ext_decrypt_cache_pipelined:
	callq decrypt_cache_pipelined
	movdqa %xmm10, (%rdi)
	movdqa %xmm11, 16(%rdi)
	movdqa %xmm12, 32(%rdi)
	movdqa %xmm13, 48(%rdi)
	retq

.globl decrypt_cache_pipelined
decrypt_cache_pipelined:
	movdqu (%rdi), %xmm10
	movdqu 16(%rdi), %xmm11
	movdqu 32(%rdi), %xmm12
	movdqu 48(%rdi), %xmm13

	# Round 0
	movdqa deckey0(%rip), %xmm0
	movdqa %xmm0, %xmm1
	movdqa %xmm0, %xmm2
	movdqa %xmm0, %xmm3

	pxor %xmm0,  %xmm10
	pxor %xmm1,  %xmm11
	pxor %xmm2,  %xmm12
	pxor %xmm3,  %xmm13

	# Round 1
	movdqa deckey1(%rip), %xmm0
	movdqa %xmm0, %xmm1
	movdqa %xmm0, %xmm2
	movdqa %xmm0, %xmm3

	aesdec %xmm0,  %xmm10
	aesdec %xmm1,  %xmm11
	aesdec %xmm2,  %xmm12
	aesdec %xmm3,  %xmm13

	# Round 2
	movdqa deckey2(%rip), %xmm0
	movdqa %xmm0, %xmm1
	movdqa %xmm0, %xmm2
	movdqa %xmm0, %xmm3

	aesdec %xmm0,  %xmm10
	aesdec %xmm1,  %xmm11
	aesdec %xmm2,  %xmm12
	aesdec %xmm3,  %xmm13

	# Round 3
	movdqa deckey3(%rip), %xmm0
	movdqa %xmm0, %xmm1
	movdqa %xmm0, %xmm2
	movdqa %xmm0, %xmm3

	aesdec %xmm0,  %xmm10
	aesdec %xmm1,  %xmm11
	aesdec %xmm2,  %xmm12
	aesdec %xmm3,  %xmm13

	# Round 4
	movdqa deckey4(%rip), %xmm0
	movdqa %xmm0, %xmm1
	movdqa %xmm0, %xmm2
	movdqa %xmm0, %xmm3

	aesdec %xmm0,  %xmm10
	aesdec %xmm1,  %xmm11
	aesdec %xmm2,  %xmm12
	aesdec %xmm3,  %xmm13

	# Round 5
	movdqa deckey5(%rip), %xmm0
	movdqa %xmm0, %xmm1
	movdqa %xmm0, %xmm2
	movdqa %xmm0, %xmm3

	aesdec %xmm0,  %xmm10
	aesdec %xmm1,  %xmm11
	aesdec %xmm2,  %xmm12
	aesdec %xmm3,  %xmm13

	# Round 6
	movdqa deckey6(%rip), %xmm0
	movdqa %xmm0, %xmm1
	movdqa %xmm0, %xmm2
	movdqa %xmm0, %xmm3

	aesdec %xmm0,  %xmm10
	aesdec %xmm1,  %xmm11
	aesdec %xmm2,  %xmm12
	aesdec %xmm3,  %xmm13

	# Round 7
	movdqa deckey7(%rip), %xmm0
	movdqa %xmm0, %xmm1
	movdqa %xmm0, %xmm2
	movdqa %xmm0, %xmm3

	aesdec %xmm0,  %xmm10
	aesdec %xmm1,  %xmm11
	aesdec %xmm2,  %xmm12
	aesdec %xmm3,  %xmm13

	# Round 8
	movdqa deckey8(%rip), %xmm0
	movdqa %xmm0, %xmm1
	movdqa %xmm0, %xmm2
	movdqa %xmm0, %xmm3

	aesdec %xmm0,  %xmm10
	aesdec %xmm1,  %xmm11
	aesdec %xmm2,  %xmm12
	aesdec %xmm3,  %xmm13

	# Round 9
	movdqa deckey9(%rip), %xmm0
	movdqa %xmm0, %xmm1
	movdqa %xmm0, %xmm2
	movdqa %xmm0, %xmm3

	aesdec %xmm0,  %xmm10
	aesdec %xmm1,  %xmm11
	aesdec %xmm2,  %xmm12
	aesdec %xmm3,  %xmm13

	# Round 10
	movdqa deckey10(%rip), %xmm0
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
	movdqa enckey0(%rip), %xmm0
	movdqa %xmm0, %xmm1
	movdqa %xmm0, %xmm2
	movdqa %xmm0, %xmm3

	pxor %xmm0,  %xmm10
	pxor %xmm1,  %xmm11
	pxor %xmm2,  %xmm12
	pxor %xmm3,  %xmm13

#	aesenc %xmm15,  %xmm13

	# Round 1
	movdqa enckey1(%rip), %xmm0
	movdqa %xmm0, %xmm1
	movdqa %xmm0, %xmm2
	movdqa %xmm0, %xmm3

	aesenc %xmm0,  %xmm10
	aesenc %xmm1,  %xmm11
	aesenc %xmm2,  %xmm12
	aesenc %xmm3,  %xmm13

	# Round 2
	movdqa enckey2(%rip), %xmm0
	movdqa %xmm0, %xmm1
	movdqa %xmm0, %xmm2
	movdqa %xmm0, %xmm3

	aesenc %xmm0,  %xmm10
	aesenc %xmm1,  %xmm11
	aesenc %xmm2,  %xmm12
	aesenc %xmm3,  %xmm13

	# Round 3
	movdqa enckey3(%rip), %xmm0
	movdqa %xmm0, %xmm1
	movdqa %xmm0, %xmm2
	movdqa %xmm0, %xmm3

	aesenc %xmm0,  %xmm10
	aesenc %xmm1,  %xmm11
	aesenc %xmm2,  %xmm12
	aesenc %xmm3,  %xmm13

	# Round 4
	movdqa enckey4(%rip), %xmm0
	movdqa %xmm0, %xmm1
	movdqa %xmm0, %xmm2
	movdqa %xmm0, %xmm3


	aesenc %xmm0,  %xmm10
	aesenc %xmm1,  %xmm11
	aesenc %xmm2,  %xmm12
	aesenc %xmm3,  %xmm13

	# Round 5
	movdqa enckey5(%rip), %xmm0
	movdqa %xmm0, %xmm1
	movdqa %xmm0, %xmm2
	movdqa %xmm0, %xmm3

	aesenc %xmm0,  %xmm10
	aesenc %xmm1,  %xmm11
	aesenc %xmm2,  %xmm12
	aesenc %xmm3,  %xmm13

	# Round 6
	movdqa enckey6(%rip), %xmm0
	movdqa %xmm0, %xmm1
	movdqa %xmm0, %xmm2
	movdqa %xmm0, %xmm3

	aesenc %xmm0,  %xmm10
	aesenc %xmm1,  %xmm11
	aesenc %xmm2,  %xmm12
	aesenc %xmm3,  %xmm13

	# Round 7
	movdqa enckey7(%rip), %xmm0
	movdqa %xmm0, %xmm1
	movdqa %xmm0, %xmm2
	movdqa %xmm0, %xmm3

	aesenc %xmm0,  %xmm10
	aesenc %xmm1,  %xmm11
	aesenc %xmm2,  %xmm12
	aesenc %xmm3,  %xmm13

	# Round 8
	movdqa enckey8(%rip), %xmm0
	movdqa %xmm0, %xmm1
	movdqa %xmm0, %xmm2
	movdqa %xmm0, %xmm3

	aesenc %xmm0,  %xmm10
	aesenc %xmm1,  %xmm11
	aesenc %xmm2,  %xmm12
	aesenc %xmm3,  %xmm13

	# Round 9
	movdqa enckey9(%rip), %xmm0
	movdqa %xmm0, %xmm1
	movdqa %xmm0, %xmm2
	movdqa %xmm0, %xmm3

	aesenc %xmm0,  %xmm10
	aesenc %xmm1,  %xmm11
	aesenc %xmm2,  %xmm12
	aesenc %xmm3,  %xmm13

	# Round 10
	movdqa enckey10(%rip), %xmm0
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
	movdqa deckey0(%rip), %xmm15
	pxor %xmm15,  %xmm13

	# Round 1
	movdqa deckey1(%rip), %xmm15
	aesdec %xmm15,  %xmm13


	# Round 2
	movdqa deckey2(%rip), %xmm15
	aesdec %xmm15,  %xmm13

     	# Round 3
	movdqa deckey3(%rip), %xmm15
	aesdec %xmm15,  %xmm13

	# Round 4
	movdqa deckey4(%rip), %xmm15
	aesdec %xmm15,  %xmm13

	# Round 5
	movdqa deckey5(%rip), %xmm15
	aesdec %xmm15,  %xmm13

	# Round 6
	movdqa deckey6(%rip), %xmm15
	aesdec %xmm15,  %xmm13

	# Round 7
	movdqa deckey7(%rip), %xmm15
	aesdec %xmm15,  %xmm13

	# Round 8
	movdqa deckey8(%rip), %xmm15
	aesdec %xmm15,  %xmm13

	# Round 9
	movdqa deckey9(%rip), %xmm15
	aesdec %xmm15,  %xmm13

	movdqa deckey10(%rip), %xmm15
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

	movdqa deckey0(%rip), %xmm15
	pxor %xmm15,  %xmm13

	# Round 1
	movdqa deckey1(%rip), %xmm15
	aesdec %xmm15,  %xmm13


	# Round 2
	movdqa deckey2(%rip), %xmm15
	aesdec %xmm15,  %xmm13

     	# Round 3
	movdqa deckey3(%rip), %xmm15
	aesdec %xmm15,  %xmm13

	# Round 4
	movdqa deckey4(%rip), %xmm15
	aesdec %xmm15,  %xmm13

	# Round 5
	movdqa deckey5(%rip), %xmm15
	aesdec %xmm15,  %xmm13

	# Round 6
	movdqa deckey6(%rip), %xmm15
	aesdec %xmm15,  %xmm13

	# Round 7
	movdqa deckey7(%rip), %xmm15
	aesdec %xmm15,  %xmm13

	# Round 8
	movdqa deckey8(%rip), %xmm15
	aesdec %xmm15,  %xmm13

	# Round 9
	movdqa deckey9(%rip), %xmm15
	aesdec %xmm15,  %xmm13

	movdqa deckey10(%rip), %xmm15
	aesdeclast %xmm15,  %xmm13

	#movdqu %xmm13, %xmm0
	movq %xmm13, %rax
	# movdqu %xmm0, (%rdi)

	retq

.globl decrypt_memory
decrypt_memory:
    movdqu (%rdi), %xmm14
	movdqu %xmm14, %xmm13

	# Round 0

	movdqa deckey0(%rip), %xmm15
	pxor %xmm15,  %xmm13

	# Round 1
	movdqa deckey1(%rip), %xmm15
	aesdec %xmm15,  %xmm13


	# Round 2
	movdqa deckey2(%rip), %xmm15
	aesdec %xmm15,  %xmm13

     	# Round 3
	movdqa deckey3(%rip), %xmm15
	aesdec %xmm15,  %xmm13

	# Round 4
	movdqa deckey4(%rip), %xmm15
	aesdec %xmm15,  %xmm13

	# Round 5
	movdqa deckey5(%rip), %xmm15
	aesdec %xmm15,  %xmm13

	# Round 6
	movdqa deckey6(%rip), %xmm15
	aesdec %xmm15,  %xmm13

	# Round 7
	movdqa deckey7(%rip), %xmm15
	aesdec %xmm15,  %xmm13

	# Round 8
	movdqa deckey8(%rip), %xmm15
	aesdec %xmm15,  %xmm13

	# Round 9
	movdqa deckey9(%rip), %xmm15
	aesdec %xmm15,  %xmm13

	movdqa deckey10(%rip), %xmm15
	aesdeclast %xmm15,  %xmm13

	#movdqu %xmm13, %xmm0
	movdqu %xmm13, (%rdi)
	# movdqu %xmm0, (%rdi)

	retq



# Routine to help debugging by decrypting
# decrypt_debug(hival, loval, *res) ==> Decrypt the 128 bit contents in {hival, loval} and return in *res
.globl decrypt_debug
decrypt_debug:
    movdqu (%rdi), %xmm10
	# Round 0

	movdqa deckey0(%rip), %xmm11
	pxor %xmm11,  %xmm10

	# Round 1
	movdqa deckey1(%rip), %xmm11
	aesdec %xmm11,  %xmm10


	# Round 2
	movdqa deckey2(%rip), %xmm11
	aesdec %xmm11,  %xmm10

     	# Round 3
	movdqa deckey3(%rip), %xmm11
	aesdec %xmm11,  %xmm10

	# Round 4
	movdqa deckey4(%rip), %xmm11
	aesdec %xmm11,  %xmm10

	# Round 5
	movdqa deckey5(%rip), %xmm11
	aesdec %xmm11,  %xmm10

	# Round 6
	movdqa deckey6(%rip), %xmm11
	aesdec %xmm11,  %xmm10

	# Round 7
	movdqa deckey7(%rip), %xmm11
	aesdec %xmm11,  %xmm10

	# Round 8
	movdqa deckey8(%rip), %xmm11
	aesdec %xmm11,  %xmm10

	# Round 9
	movdqa deckey9(%rip), %xmm11
	aesdec %xmm11,  %xmm10

	movdqa deckey10(%rip), %xmm11
	aesdeclast %xmm11,  %xmm10

    movdqu %xmm10, (%rdi)
	retq

# Routine to help debugging by encrypting
# encrypt_debug(hival, loval, *res) ==> Encrypt the 128 bit contents in {hival, loval} and return in *res
.globl encrypt_debug
encrypt_debug:
    movdqu (%rdi), %xmm10
 
	movdqa enckey0(%rip), %xmm11
	pxor %xmm11,  %xmm10
#	aesenc %xmm11,  %xmm10

	# Round 1
	movdqa enckey1(%rip), %xmm11
	aesenc %xmm11,  %xmm10


	# Round 2
	movdqa enckey2(%rip), %xmm11
	aesenc %xmm11,  %xmm10

     	# Round 3
	movdqa enckey3(%rip), %xmm11
	aesenc %xmm11,  %xmm10

     	# Round 4
	movdqa enckey4(%rip), %xmm11
	aesenc %xmm11,  %xmm10

	# Round 5
	movdqa enckey5(%rip), %xmm11
	aesenc %xmm11,  %xmm10

	# Round 6
	movdqa enckey6(%rip), %xmm11
	aesenc %xmm11,  %xmm10

	# Round 7
	movdqa enckey7(%rip), %xmm11
	aesenc %xmm11,  %xmm10

	# Round 8
	movdqa enckey8(%rip), %xmm11
	aesenc %xmm11,  %xmm10

	# Round 9
	movdqa enckey9(%rip), %xmm11
	aesenc %xmm11,  %xmm10

	# Round 10
	movdqa enckey10(%rip), %xmm11
	aesenclast %xmm11,  %xmm10

	movdqu %xmm10, (%rdi)
	retq

.globl populate_keys
populate_keys:
    retq

