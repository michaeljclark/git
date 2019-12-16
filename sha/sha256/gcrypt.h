#ifndef SHA256_GCRYPT_H
#define SHA256_GCRYPT_H

#include <gcrypt.h>

#define SHA224_DIGEST_SIZE 28
#define SHA256_DIGEST_SIZE 32

typedef gcry_md_hd_t gcrypt_SHA256_CTX;

inline void gcrypt_SHA224_Init(gcrypt_SHA256_CTX *ctx)
{
	gcry_md_open(ctx, GCRY_MD_SHA224, 0);
}

inline void gcrypt_SHA256_Init(gcrypt_SHA256_CTX *ctx)
{
	gcry_md_open(ctx, GCRY_MD_SHA256, 0);
}

inline void gcrypt_SHA256_Update(gcrypt_SHA256_CTX *ctx, const void *data, size_t len)
{
	gcry_md_write(*ctx, data, len);
}

inline void gcrypt_SHA256_Final(unsigned char *digest, gcrypt_SHA256_CTX *ctx)
{
	int algo = gcry_md_get_algo(ctx);
	unsigned int dlen = gcry_md_get_algo_dlen(algo);
	memcpy(digest, gcry_md_read(*ctx, algo), dlen);
}

#define platform_SHA256_CTX gcrypt_SHA256_CTX
#define platform_SHA256_Init gcrypt_SHA256_Init
#define platform_SHA256_Update gcrypt_SHA256_Update
#define platform_SHA256_Final gcrypt_SHA256_Final

#define platform_SHA224_CTX gcrypt_SHA256_CTX
#define platform_SHA224_Init gcrypt_SHA224_Init
#define platform_SHA224_Update gcrypt_SHA256_Update
#define platform_SHA224_Final gcrypt_SHA256_Final

#endif
