#ifndef SHA256_BLOCK_SHA256_H
#define SHA256_BLOCK_SHA256_H

#define blk_SHA256_BLKSIZE 64
#define blk_SHA224_HASHSIZE 28
#define blk_SHA256_HASHSIZE 32

struct blk_SHA256_CTX {
	uint32_t state[8];
	uint64_t size;
	uint32_t offset;
	uint32_t digestlen;
	uint8_t buf[blk_SHA256_BLKSIZE];
};

typedef struct blk_SHA256_CTX blk_SHA256_CTX;

void blk_SHA224_Init(blk_SHA256_CTX *ctx);
void blk_SHA256_Init(blk_SHA256_CTX *ctx);
void blk_SHA256_Update(blk_SHA256_CTX *ctx, const void *data, size_t len);
void blk_SHA256_Final(unsigned char *digest, blk_SHA256_CTX *ctx);

#define platform_SHA256_CTX blk_SHA256_CTX
#define platform_SHA256_Init blk_SHA256_Init
#define platform_SHA256_Update blk_SHA256_Update
#define platform_SHA256_Final blk_SHA256_Final

#define platform_SHA224_CTX blk_SHA256_CTX
#define platform_SHA224_Init blk_SHA224_Init
#define platform_SHA224_Update blk_SHA256_Update
#define platform_SHA224_Final blk_SHA256_Final

#endif
