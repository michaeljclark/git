#ifndef SHA3_GCRYPT_H
#define SHA3_GCRYPT_H

#include <gcrypt.h>

#define SHA3_224_DIGEST_SIZE 28
#define SHA3_256_DIGEST_SIZE 32
#define SHA3_384_DIGEST_SIZE 48
#define SHA3_512_DIGEST_SIZE 64

typedef gcry_md_hd_t gcrypt_SHA3_CTX;

inline void gcrypt_SHA3_224_Init(gcrypt_SHA3_CTX *ctx)
{
	gcry_md_open(ctx, GCRY_MD_SHA3_224, 0);
}

inline void gcrypt_SHA3_256_Init(gcrypt_SHA3_CTX *ctx)
{
	gcry_md_open(ctx, GCRY_MD_SHA3_256, 0);
}

inline void gcrypt_SHA3_384_Init(gcrypt_SHA3_CTX *ctx)
{
	gcry_md_open(ctx, GCRY_MD_SHA3_384, 0);
}

inline void gcrypt_SHA3_512_Init(gcrypt_SHA3_CTX *ctx)
{
	gcry_md_open(ctx, GCRY_MD_SHA3_512, 0);
}

inline void gcrypt_SHA3_Update(gcrypt_SHA3_CTX *ctx, const void *data, size_t len)
{
	gcry_md_write(*ctx, data, len);
}

inline void gcrypt_SHA3_Final(unsigned char *digest, gcrypt_SHA3_CTX *ctx)
{
	int algo = gcry_md_get_algo(ctx);
	unsigned int dlen = gcry_md_get_algo_dlen(algo);
	memcpy(digest, gcry_md_read(*ctx, algo), dlen);
}

#define platform_SHA3_CTX gcrypt_SHA3_CTX
#define platform_SHA3_224_Init gcrypt_SHA3_224_Init
#define platform_SHA3_256_Init gcrypt_SHA3_256_Init
#define platform_SHA3_384_Init gcrypt_SHA3_384_Init
#define platform_SHA3_512_Init gcrypt_SHA3_512_Init
#define platform_SHA3_Update gcrypt_SHA3_Update
#define platform_SHA3_Final gcrypt_SHA3_Final

#endif
