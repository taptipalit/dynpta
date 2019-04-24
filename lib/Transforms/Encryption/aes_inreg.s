.globl populate_keys
populate_keys:
    # YMM8
	# Round 0
	mov $0x62626262, %r10
	pinsrq $0x0, %r10, %xmm15
	mov $0x0, %r10
	pinsrq $0x1, %r10, %xmm15
    vinserti128 $0x1,%xmm15,%ymm5,%ymm5

   
	# Round 1
	mov $0x101010001010100, %r10
	pinsrq $0x0, %r10, %xmm15
	mov $0x101010001010100, %r10
	pinsrq $0x1, %r10, %xmm15

    vinserti128 $0x1,%xmm15,%ymm6,%ymm6

    #YMM9
	# Round 2
	mov $0x637c7c7e627d7d7e, %r10
	pinsrq $0x0, %r10, %xmm15
	mov $0x637c7c7e627d7d7e, %r10
	pinsrq $0x1, %r10, %xmm15
    vinserti128 $0x1,%xmm15,%ymm7,%ymm7

    # Round 3
	mov $0xf2fa111491866d6a, %r10
	pinsrq $0x0, %r10, %xmm15
	mov $0xf3fb101490876c6a, %r10
	pinsrq $0x1, %r10, %xmm15

    vinserti128 $0x1,%xmm15,%ymm8,%ymm8

    #YMM10
	# Round 4
	mov $0x997173bc6b8b62a8, %r10
	pinsrq $0x0, %r10, %xmm15
	mov $0xfa0d0fc209f61fd6, %r10
	pinsrq $0x1, %r10, %xmm15
    vinserti128 $0x1,%xmm15,%ymm9,%ymm9

	# Round 5
	mov $0xd7d7c6724ea6b5ce, %r10
	pinsrq $0x0, %r10, %xmm15
	mov $0x242cd666de21d9a4, %r10
	pinsrq $0x1, %r10, %xmm15
    vinserti128 $0x1,%xmm15,%ymm10,%ymm10

    #YMM11
	# Round 6
	mov $0xaa47026a7d90c418, %r10
	pinsrq $0x0, %r10, %xmm15
	mov $0x504a0da87466dbce, %r10
	pinsrq $0x1, %r10, %xmm15
    vinserti128 $0x1,%xmm15,%ymm11,%ymm11

	# Round 7
	mov $0x158410e5bfc3128f, %r10
	pinsrq $0x0, %r10, %xmm15
	mov $0x31a8c68361e2cb2b, %r10
	pinsrq $0x1, %r10, %xmm15
    vinserti128 $0x1,%xmm15,%ymm12,%ymm12

    #YMM12
	# Round 8
	mov $0x4680c05e5304d0bb, %r10
	pinsrq $0x0, %r10, %xmm15
	mov $0x16cacdf627620b75, %r10
	pinsrq $0x1, %r10, %xmm15
    vinserti128 $0x1,%xmm15,%ymm13,%ymm13

	# Round 9
	mov $0x57c364431143a41d, %r10
	pinsrq $0x0, %r10, %xmm15
	mov $0x666ba2c070a16f36, %r10
	pinsrq $0x1, %r10, %xmm15
    vinserti128 $0x1,%xmm15,%ymm14,%ymm14

    #YMM13
	# Round 10
	mov $0xfcb3bf52ab70db11, %r10
	pinsrq $0x0, %r10, %xmm15
	mov $0xea7972a48c12d064, %r10
	pinsrq $0x1, %r10, %xmm15
    vinserti128 $0x1,%xmm15,%ymm15,%ymm15

	retq



# decrypt(ptr) ==> Decrypt the 128 bit contents at ptr and store to XMM15
.globl decrypt_cache
decrypt_cache:
    movdqu (%rdi), %xmm14

    # Round 0
    vextracti128 $0x1, %ymm15, %xmm0
#   aesimc %xmm0, %xmm0
	pxor %xmm0,  %xmm14

    # Round 1
    vextracti128 $0x1, %ymm14, %xmm0
    vaesimc %xmm0, %xmm0
	aesdec %xmm0,  %xmm14

    # Round 2
    vextracti128 $0x1, %ymm13, %xmm0
    vaesimc %xmm0, %xmm0
	aesdec %xmm0,  %xmm14

    # Round 3
    vextracti128 $0x1, %ymm12, %xmm0
    vaesimc %xmm0, %xmm0
	aesdec %xmm0,  %xmm14

    # Round 4
    vextracti128 $0x1, %ymm11, %xmm0
    vaesimc %xmm0, %xmm0
	aesdec %xmm0,  %xmm14

    # Round 5
    vextracti128 $0x1, %ymm10, %xmm0
    vaesimc %xmm0, %xmm0
	aesdec %xmm0,  %xmm14

    # Round 6
    vextracti128 $0x1, %ymm9, %xmm0
    vaesimc %xmm0, %xmm0
	aesdec %xmm0,  %xmm14

    # Round 7
    vextracti128 $0x1, %ymm8, %xmm0
    vaesimc %xmm0, %xmm0
	aesdec %xmm0,  %xmm14

    # Round 8
    vextracti128 $0x1, %ymm7, %xmm0
    vaesimc %xmm0, %xmm0
	aesdec %xmm0,  %xmm14

    # Round 9
    vextracti128 $0x1, %ymm6, %xmm0
    vaesimc %xmm0, %xmm0
	aesdec %xmm0,  %xmm14

    # Round 10
    vextracti128 $0x1, %ymm5, %xmm0
	aesdeclast %xmm0,  %xmm14

    movdqa %xmm14, %xmm15

    retq


# encrypt_cache(ptr) ==> Encrypt the contents of XMM15 and store to ptr
# XMM13 contains the data
.globl encrypt_cache
encrypt_cache:
    movdqa %xmm15, %xmm14
	# Round 0
    vextracti128 $0x1, %ymm5, %xmm0
	pxor %xmm0,  %xmm14

	# Round 1
    vextracti128 $0x1, %ymm6, %xmm0
	aesenc %xmm0,  %xmm14

	# Round 2
    vextracti128 $0x1, %ymm7, %xmm0
	aesenc %xmm0,  %xmm14


	# Round 3
    vextracti128 $0x1, %ymm8, %xmm0
	aesenc %xmm0,  %xmm14

	# Round 4
    vextracti128 $0x1, %ymm9, %xmm0
	aesenc %xmm0,  %xmm14

	# Round 5
    vextracti128 $0x1, %ymm10, %xmm0
	aesenc %xmm0,  %xmm14

	# Round 6
    vextracti128 $0x1, %ymm11, %xmm0
	aesenc %xmm0,  %xmm14

	# Round 7
    vextracti128 $0x1, %ymm12, %xmm0
	aesenc %xmm0,  %xmm14

	# Round 8
    vextracti128 $0x1, %ymm13, %xmm0
	aesenc %xmm0,  %xmm14

	# Round 9
    vextracti128 $0x1, %ymm14, %xmm0
	aesenc %xmm0,  %xmm14

	# Round 10
    vextracti128 $0x1, %ymm15, %xmm0
	aesenclast %xmm0,  %xmm14

	movdqu %xmm14, (%rdi)
	retq

.globl encrypt_memory
encrypt_memory:
	movdqu (%rdi), %xmm14
	# Round 0
    vextracti128 $0x1, %ymm5, %xmm0
	pxor %xmm0,  %xmm14

	# Round 1
    vextracti128 $0x1, %ymm6, %xmm0
	aesenc %xmm0,  %xmm14

	# Round 2
    vextracti128 $0x1, %ymm7, %xmm0
	aesenc %xmm0,  %xmm14


	# Round 3
    vextracti128 $0x1, %ymm8, %xmm0
	aesenc %xmm0,  %xmm14

	# Round 4
    vextracti128 $0x1, %ymm9, %xmm0
	aesenc %xmm0,  %xmm14

	# Round 5
    vextracti128 $0x1, %ymm10, %xmm0
	aesenc %xmm0,  %xmm14

	# Round 6
    vextracti128 $0x1, %ymm11, %xmm0
	aesenc %xmm0,  %xmm14

	# Round 7
    vextracti128 $0x1, %ymm12, %xmm0
	aesenc %xmm0,  %xmm14

	# Round 8
    vextracti128 $0x1, %ymm13, %xmm0
	aesenc %xmm0,  %xmm14

	# Round 9
    vextracti128 $0x1, %ymm14, %xmm0
	aesenc %xmm0,  %xmm14

	# Round 10
    vextracti128 $0x1, %ymm15, %xmm0
	aesenclast %xmm0,  %xmm14

	movdqu %xmm14, (%rdi)
	retq

.globl decrypt_memory
decrypt_memory:
    movdqu (%rdi), %xmm14

    # Round 0
    vextracti128 $0x1, %ymm15, %xmm0
#   aesimc %xmm0, %xmm0
	pxor %xmm0,  %xmm14

    # Round 1
    vextracti128 $0x1, %ymm14, %xmm0
    aesimc %xmm0, %xmm0
	aesdec %xmm0,  %xmm14

    # Round 2
    vextracti128 $0x1, %ymm13, %xmm0
    aesimc %xmm0, %xmm0
	aesdec %xmm0,  %xmm14

    # Round 3
    vextracti128 $0x1, %ymm12, %xmm0
    aesimc %xmm0, %xmm0
	aesdec %xmm0,  %xmm14

    # Round 4
    vextracti128 $0x1, %ymm11, %xmm0
    aesimc %xmm0, %xmm0
	aesdec %xmm0,  %xmm14

    # Round 5
    vextracti128 $0x1, %ymm10, %xmm0
    aesimc %xmm0, %xmm0
	aesdec %xmm0,  %xmm14

    # Round 6
    vextracti128 $0x1, %ymm9, %xmm0
    aesimc %xmm0, %xmm0
	aesdec %xmm0,  %xmm14

    # Round 7
    vextracti128 $0x1, %ymm8, %xmm0
    aesimc %xmm0, %xmm0
	aesdec %xmm0,  %xmm14

    # Round 8
    vextracti128 $0x1, %ymm7, %xmm0
    aesimc %xmm0, %xmm0
	aesdec %xmm0,  %xmm14

    # Round 9
    vextracti128 $0x1, %ymm6, %xmm0
    aesimc %xmm0, %xmm0
	aesdec %xmm0,  %xmm14

    # Round 10
    vextracti128 $0x1, %ymm5, %xmm0
	aesdeclast %xmm0,  %xmm14

    movdqu %xmm14, (%rdi)
	retq

