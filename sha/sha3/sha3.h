#ifndef SHA3_BLOCK_H
#define SHA3_BLOCK_H

#define blk_SHA3_224_hash_size 28
#define blk_SHA3_256_hash_size 32
#define blk_SHA3_384_hash_size 48
#define blk_SHA3_512_hash_size 64
#define blk_SHA3_max_permutation_size 200

typedef struct blk_SHA3_CTX
{
	uint64_t state[blk_SHA3_max_permutation_size];
	uint64_t size;
	uint64_t block_size;
	uint8_t buf[blk_SHA3_max_permutation_size];
} blk_SHA3_CTX;

void blk_SHA3_224_Init(blk_SHA3_CTX* ctx);
void blk_SHA3_256_Init(blk_SHA3_CTX* ctx);
void blk_SHA3_384_Init(blk_SHA3_CTX* ctx);
void blk_SHA3_512_Init(blk_SHA3_CTX* ctx);
void blk_SHA3_Update(blk_SHA3_CTX* ctx, const void *data, size_t len);
void blk_SHA3_Final(unsigned char* digest, blk_SHA3_CTX* ctx);

#define platform_SHA3_CTX blk_SHA3_CTX
#define platform_SHA3_Init blk_SHA3_Init
#define platform_SHA3_224_Init blk_SHA3_224_Init
#define platform_SHA3_256_Init blk_SHA3_256_Init
#define platform_SHA3_384_Init blk_SHA3_384_Init
#define platform_SHA3_512_Init blk_SHA3_512_Init
#define platform_SHA3_Update blk_SHA3_Update
#define platform_SHA3_Final blk_SHA3_Final

#endif