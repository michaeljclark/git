#ifndef SHA512_GCRYPT_H
#define SHA512_GCRYPT_H

#include <gcrypt.h>

#define SHA512_DIGEST_SIZE 64

typedef gcry_md_hd_t gcrypt_SHA512_CTX;

inline void gcrypt_SHA512_Init(gcrypt_SHA512_CTX *ctx)
{
	gcry_md_open(ctx, GCRY_MD_SHA512, 0);
}

inline void gcrypt_SHA512_224_Init(gcrypt_SHA512_CTX *ctx)
{
	gcry_md_open(ctx, GCRY_MD_SHA512_224, 0);
}

inline void gcrypt_SHA512_256_Init(gcrypt_SHA512_CTX *ctx)
{
	gcry_md_open(ctx, GCRY_MD_SHA512_256, 0);
}

inline void gcrypt_SHA512_Update(gcrypt_SHA512_CTX *ctx, const void *data, size_t len)
{
	gcry_md_write(*ctx, data, len);
}

inline void gcrypt_SHA512_Final(unsigned char *digest, gcrypt_SHA512_CTX *ctx)
{
	int algo = gcry_md_get_algo(ctx);
	unsigned int dlen = gcry_md_get_algo_dlen(algo);
	memcpy(digest, gcry_md_read(*ctx, algo), dlen);
}

#define platform_SHA512_CTX gcrypt_SHA512_CTX
#define platform_SHA512_Init gcrypt_SHA512_Init
#define platform_SHA512_256_Init gcrypt_SHA512_256_Init
#define platform_SHA512_Update gcrypt_SHA512_Update
#define platform_SHA512_Final gcrypt_SHA512_Final

#endif
