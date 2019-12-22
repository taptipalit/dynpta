/**
 * Attempt at replicating why just handling the points-to and points-from
 * cases don't work. 
 * We need to recursively process all the edges too. Why?
 *
 * Status: This example seems to do exactly what mbedtls does, but somehow it
 * works, but mbedtls doesn't.
 */
#include <stdio.h>

#define SENSITIVE __attribute__((annotate("sensitive")))

#define size_t int

typedef enum {
    MBEDTLS_PK_NONE=0,
    MBEDTLS_PK_RSA,
    MBEDTLS_PK_ECKEY,
    MBEDTLS_PK_ECKEY_DH,
    MBEDTLS_PK_ECDSA,
    MBEDTLS_PK_RSA_ALT,
    MBEDTLS_PK_RSASSA_PSS,
} mbedtls_pk_type_t;

typedef unsigned long mbedtls_mpi_uint;

typedef struct mbedtls_mpi
{
    int s;              /*!<  integer sign      */
    size_t n;           /*!<  total # of limbs  */
    mbedtls_mpi_uint *p;          /*!<  pointer to limbs  */
}
mbedtls_mpi;


typedef struct mbedtls_rsa_context
{
    int ver;                    /*!<  Always 0.*/
    size_t len;                 /*!<  The size of \p N in Bytes. */

    mbedtls_mpi N;              /*!<  The public modulus. */
    mbedtls_mpi E;              /*!<  The public exponent. */

    mbedtls_mpi D;              /*!<  The private exponent. */
    mbedtls_mpi P;              /*!<  The first prime factor. */
    mbedtls_mpi Q;              /*!<  The second prime factor. */

    mbedtls_mpi DP;             /*!<  <code>D % (P - 1)</code>. */
    mbedtls_mpi DQ;             /*!<  <code>D % (Q - 1)</code>. */
    mbedtls_mpi QP;             /*!<  <code>1 / (Q % P)</code>. */

    mbedtls_mpi RN;             /*!<  cached <code>R^2 mod N</code>. */

    mbedtls_mpi RP;             /*!<  cached <code>R^2 mod P</code>. */
    mbedtls_mpi RQ;             /*!<  cached <code>R^2 mod Q</code>. */

    mbedtls_mpi Vi;             /*!<  The cached blinding value. */
    mbedtls_mpi Vf;             /*!<  The cached un-blinding value. */

    int padding;                /*!< Selects padding mode:
                                     #MBEDTLS_RSA_PKCS_V15 for 1.5 padding and
                                     #MBEDTLS_RSA_PKCS_V21 for OAEP or PSS. */
    int hash_id;                /*!< Hash identifier of mbedtls_md_type_t type,
                                     as specified in md.h for use in the MGF
                                     mask generating function used in the
                                     EME-OAEP and EMSA-PSS encodings. */

}
mbedtls_rsa_context;


struct mbedtls_pk_info_t
{
    /** Public key type */
    mbedtls_pk_type_t type;

    /** Type name */
    const char *name;

    /** Get key size in bits */
    size_t (*get_bitlen)( const void * );

    /** Tell if the context implements this type (e.g. ECKEY can do ECDSA) */
    int (*can_do)( mbedtls_pk_type_t type );

    /** Allocate a new context */
    void * (*ctx_alloc_func)( void );


};

#define mbedtls_calloc    calloc

typedef struct mbedtls_pk_info_t mbedtls_pk_info_t;

static void *rsa_alloc_wrap( void )
{
    void *ctx = mbedtls_calloc( 1, sizeof( mbedtls_rsa_context ) );

    return( ctx );
}


static size_t rsa_get_bitlen( const void *ctx )
{
    return 100;
}

static int rsa_can_do( mbedtls_pk_type_t type )
{
    return 1;
}

const mbedtls_pk_info_t mbedtls_rsa_info = {
    MBEDTLS_PK_RSA,
    "RSA",
    rsa_get_bitlen,
    rsa_can_do,
    rsa_alloc_wrap,
};

typedef struct mbedtls_pk_context
{
    const mbedtls_pk_info_t *   pk_info; /**< Public key information         */
    void *                      pk_ctx;  /**< Underlying public key context  */
} mbedtls_pk_context;

void mbedtls_pk_init( mbedtls_pk_context *ctx )
{
    ctx->pk_info = NULL;
    ctx->pk_ctx = NULL;
}

/*
 * Get pk_info structure from type
 */
const mbedtls_pk_info_t * mbedtls_pk_info_from_type( mbedtls_pk_type_t pk_type )
{
    return( &mbedtls_rsa_info );
}

int mbedtls_pk_setup( mbedtls_pk_context *ctx, const mbedtls_pk_info_t *info )
{
    if( ( ctx->pk_ctx = info->ctx_alloc_func() ) == NULL )
        return( -1 );

    ctx->pk_info = info;

    return( 0 );
}


void mbedtls_pk_parse_key( mbedtls_pk_context *pk) {
    const mbedtls_pk_info_t *pk_info;

    pk_info = mbedtls_pk_info_from_type(MBEDTLS_PK_RSA);
    mbedtls_pk_setup(pk, pk_info);
}

int main(void) {
    SENSITIVE mbedtls_pk_context pkey;
    mbedtls_pk_init( &pkey );
    mbedtls_pk_parse_key(&pkey);

    return 0;
}
