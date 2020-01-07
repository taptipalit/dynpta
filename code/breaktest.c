#include <stdio.h>
#include <stdint.h>
#define SENSITIVE __attribute__((annotate("sensitive")))


typedef struct mbedtls_aes_context
{
    int nr;                     /*!< The number of rounds. */
    uint32_t *rk;               /*!< AES round keys. */
    uint32_t buf[68];           /*!< Unaligned data buffer. This buffer can
                                     hold 32 extra Bytes, which can be used for
                                     one of the following purposes:
                                     <ul><li>Alignment if VIA padlock is
                                             used.</li>
                                     <li>Simplifying key expansion in the 256-bit
                                         case by generating an extra round key.
                                         </li></ul> */
}
mbedtls_aes_context;

/*void mbedtls_aes_init( mbedtls_aes_context *ctx ) {

	memset( ctx, 0, sizeof( mbedtls_aes_context ) );
}*/

void mbedtls_aes_setkey_enc( mbedtls_aes_context *ctx) {
	unsigned int i;
	uint32_t *RK;
	ctx->nr =10;

	ctx->rk = RK = ctx->buf;
	
	for( i = 0; i < 16; i++ )
    	{
		RK[i] = 'a';
    	}
	printf(" ctx->rk  %p\n", ctx->rk);
}

void mbedtls_internal_aes_encrypt( mbedtls_aes_context *ctx) {
	uint32_t *RK;
	RK = ctx->rk;
	printf("Value of RK is %d\n", *(RK)); 
}

struct S {
    int *ptr;
};

int main() {
	SENSITIVE struct S sobj;
	mbedtls_aes_context ctx;
	sobj.ptr = &ctx.nr;
	//unsigned char keybuf[16] = "blah blah";
	//unsigned int keybits = 256;
	//mbedtls_aes_init( &ctx);
	ctx.nr = 10;
	ctx.rk = ctx.buf;
	ctx.buf[0] = 'a';
	mbedtls_aes_setkey_enc(&ctx);
	mbedtls_internal_aes_encrypt(&ctx);
	return 0;	
}
