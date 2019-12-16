#include "git-compat-util.h"
#include "sha_evp.h"

void evp_SHA2_224_Init(SHA_EVP_CTX *ctx)
{
	ctx->digest_ctx = NULL;
	ctx->digest_md = EVP_sha224();
}

void evp_SHA2_256_Init(SHA_EVP_CTX *ctx)
{
	ctx->digest_ctx = NULL;
	ctx->digest_md = EVP_sha256();
}

void evp_SHA2_512_Init(SHA_EVP_CTX *ctx)
{
	ctx->digest_ctx = NULL;
	ctx->digest_md = EVP_sha512();
}

void evp_SHA2_512_224_Init(SHA_EVP_CTX *ctx)
{
	ctx->digest_ctx = NULL;
	ctx->digest_md = EVP_sha512_224();
}

void evp_SHA2_512_256_Init(SHA_EVP_CTX *ctx)
{
	ctx->digest_ctx = NULL;
	ctx->digest_md = EVP_sha512_256();
}

void evp_SHA3_224_Init(SHA_EVP_CTX *ctx)
{
	ctx->digest_ctx = NULL;
	ctx->digest_md = EVP_sha3_224();
}

void evp_SHA3_256_Init(SHA_EVP_CTX *ctx)
{
	ctx->digest_ctx = NULL;
	ctx->digest_md = EVP_sha3_256();
}

void evp_SHA3_384_Init(SHA_EVP_CTX *ctx)
{
	ctx->digest_ctx = NULL;
	ctx->digest_md = EVP_sha3_384();
}

void evp_SHA3_512_Init(SHA_EVP_CTX *ctx)
{
	ctx->digest_ctx = NULL;
	ctx->digest_md = EVP_sha3_512();
}

static void evp_SHA_Lazy_Init(SHA_EVP_CTX *ctx)
{
	/*
	 * The OpenSSL EVP digest API requires a dynamically sized context to be
	 * allocated and destroyed, however, the digest API we are emulating uses
	 * static structures and thus has no allocation or deallocation API.
	 *
	 * Due to this, we must call EVP_MD_CTX_destroy in Final to free up
	 * dynamically allocated memory. Context creation is thus done lazily in
	 * either Update or Final to handle cases where the context is reused
	 * after Final has been called.
 	 */
	if (ctx->digest_ctx) return;
	if ((ctx->digest_ctx = EVP_MD_CTX_create()) == NULL)
		abort();
	if (EVP_DigestInit_ex(ctx->digest_ctx, ctx->digest_md, NULL) != 1)
		abort();
}

void evp_SHA_Update(SHA_EVP_CTX *ctx, const void *data, size_t len)
{
	/* handle late Init as well as being called again after Final */
	evp_SHA_Lazy_Init(ctx);

	if (EVP_DigestUpdate(ctx->digest_ctx, data, len) != 1)
		abort();
}

void evp_SHA_Final(unsigned char *result, SHA_EVP_CTX *ctx)
{
	unsigned int len;

	/* handle case where Final is called without Update (empty hash) */
	evp_SHA_Lazy_Init(ctx);

	if (EVP_DigestFinal_ex(ctx->digest_ctx, result, &len) != 1)
		abort();
	assert(EVP_MD_size(ctx->digest_md) == len);

	EVP_MD_CTX_destroy(ctx->digest_ctx);
	ctx->digest_ctx = NULL;
}
