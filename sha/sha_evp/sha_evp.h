#ifndef SHAEVP_BLOCK_H
#define SHAEVP_BLOCK_H

#include <openssl/evp.h>

#define evp_SHA2_256_hash_size      32
#define evp_SHA2_512_224_hash_size  28
#define evp_SHA2_512_256_hash_size  32
#define evp_SHA2_512_hash_size      64
#define evp_SHA3_224_hash_size      28
#define evp_SHA3_256_hash_size      32
#define evp_SHA3_384_hash_size      48
#define evp_SHA3_512_hash_size      64

struct SHA_EVP_CTX {
	EVP_MD_CTX *digest_ctx;
	const EVP_MD* digest_md;
};

typedef struct SHA_EVP_CTX SHA_EVP_CTX;

void evp_SHA2_224_Init(SHA_EVP_CTX *ctx);
void evp_SHA2_256_Init(SHA_EVP_CTX *ctx);
void evp_SHA2_512_Init(SHA_EVP_CTX *ctx);
void evp_SHA2_512_224_Init(SHA_EVP_CTX *ctx);
void evp_SHA2_512_256_Init(SHA_EVP_CTX *ctx);
void evp_SHA3_224_Init(SHA_EVP_CTX *ctx);
void evp_SHA3_256_Init(SHA_EVP_CTX *ctx);
void evp_SHA3_384_Init(SHA_EVP_CTX *ctx);
void evp_SHA3_512_Init(SHA_EVP_CTX *ctx);

void evp_SHA_Update(SHA_EVP_CTX *ctx, const void *data, size_t len);
void evp_SHA_Final(unsigned char *result, SHA_EVP_CTX *ctx);

#define platform_SHA512_CTX SHA_EVP_CTX
#define platform_SHA512_Init evp_SHA2_512_Init
#define platform_SHA512_224_Init evp_SHA2_512_224_Init
#define platform_SHA512_256_Init evp_SHA2_512_256_Init
#define platform_SHA512_Update evp_SHA_Update
#define platform_SHA512_Final evp_SHA_Final

#define platform_SHA3_CTX SHA_EVP_CTX
#define platform_SHA3_Init evp_SHA3_256_Init
#define platform_SHA3_224_Init evp_SHA3_224_Init
#define platform_SHA3_256_Init evp_SHA3_256_Init
#define platform_SHA3_384_Init evp_SHA3_384_Init
#define platform_SHA3_512_Init evp_SHA3_512_Init
#define platform_SHA3_Update evp_SHA_Update
#define platform_SHA3_Final evp_SHA_Final

#endif