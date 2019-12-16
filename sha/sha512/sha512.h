#ifndef SHA512_BLOCK_SHA512_H
#define SHA512_BLOCK_SHA512_H

#define blk_SHA512_BLKSIZE 128
#define blk_SHA512_224_HASHSIZE 28
#define blk_SHA512_256_HASHSIZE 32
#define blk_SHA512_HASHSIZE 64

struct blk_SHA512_CTX {
	uint64_t state[8];
	uint64_t size;
	uint64_t digestlen;
	uint8_t buf[blk_SHA512_BLKSIZE];
};

typedef struct blk_SHA512_CTX blk_SHA512_CTX;

void blk_SHA512_Init(blk_SHA512_CTX *ctx);
void blk_SHA512_224_Init(blk_SHA512_CTX *ctx);
void blk_SHA512_256_Init(blk_SHA512_CTX *ctx);
void blk_SHA512_Update(blk_SHA512_CTX *ctx, const void *data, size_t len);
void blk_SHA512_Final(unsigned char *digest, blk_SHA512_CTX *ctx);

#define platform_SHA512_CTX blk_SHA512_CTX
#define platform_SHA512_Init blk_SHA512_Init
#define platform_SHA512_224_Init blk_SHA512_224_Init
#define platform_SHA512_256_Init blk_SHA512_256_Init
#define platform_SHA512_Update blk_SHA512_Update
#define platform_SHA512_Final blk_SHA512_Final

#endif
