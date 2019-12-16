#include "git-compat-util.h"
#include "./sha512.h"

static const uint64_t SHA_512_K[80] = {
	0x428a2f98d728ae22ull, 0x7137449123ef65cdull,
	0xb5c0fbcfec4d3b2full, 0xe9b5dba58189dbbcull,
	0x3956c25bf348b538ull, 0x59f111f1b605d019ull,
	0x923f82a4af194f9bull, 0xab1c5ed5da6d8118ull,
	0xd807aa98a3030242ull, 0x12835b0145706fbeull,
	0x243185be4ee4b28cull, 0x550c7dc3d5ffb4e2ull,
	0x72be5d74f27b896full, 0x80deb1fe3b1696b1ull,
	0x9bdc06a725c71235ull, 0xc19bf174cf692694ull,
	0xe49b69c19ef14ad2ull, 0xefbe4786384f25e3ull,
	0x0fc19dc68b8cd5b5ull, 0x240ca1cc77ac9c65ull,
	0x2de92c6f592b0275ull, 0x4a7484aa6ea6e483ull,
	0x5cb0a9dcbd41fbd4ull, 0x76f988da831153b5ull,
	0x983e5152ee66dfabull, 0xa831c66d2db43210ull,
	0xb00327c898fb213full, 0xbf597fc7beef0ee4ull,
	0xc6e00bf33da88fc2ull, 0xd5a79147930aa725ull,
	0x06ca6351e003826full, 0x142929670a0e6e70ull,
	0x27b70a8546d22ffcull, 0x2e1b21385c26c926ull,
	0x4d2c6dfc5ac42aedull, 0x53380d139d95b3dfull,
	0x650a73548baf63deull, 0x766a0abb3c77b2a8ull,
	0x81c2c92e47edaee6ull, 0x92722c851482353bull,
	0xa2bfe8a14cf10364ull, 0xa81a664bbc423001ull,
	0xc24b8b70d0f89791ull, 0xc76c51a30654be30ull,
	0xd192e819d6ef5218ull, 0xd69906245565a910ull,
	0xf40e35855771202aull, 0x106aa07032bbd1b8ull,
	0x19a4c116b8d2d0c8ull, 0x1e376c085141ab53ull,
	0x2748774cdf8eeb99ull, 0x34b0bcb5e19b48a8ull,
	0x391c0cb3c5c95a63ull, 0x4ed8aa4ae3418acbull,
	0x5b9cca4f7763e373ull, 0x682e6ff3d6b2b8a3ull,
	0x748f82ee5defb2fcull, 0x78a5636f43172f60ull,
	0x84c87814a1f0ab72ull, 0x8cc702081a6439ecull,
	0x90befffa23631e28ull, 0xa4506cebde82bde9ull,
	0xbef9a3f7b2c67915ull, 0xc67178f2e372532bull,
	0xca273eceea26619cull, 0xd186b8c721c0c207ull,
	0xeada7dd6cde0eb1eull, 0xf57d4f7fee6ed178ull,
	0x06f067aa72176fbaull, 0x0a637dc5a2c898a6ull,
	0x113f9804bef90daeull, 0x1b710b35131c471bull,
	0x28db77f523047d84ull, 0x32caab7b40c72493ull,
	0x3c9ebe0a15c9bebcull, 0x431d67c49c100d4cull,
	0x4cc5d4becb3e42b6ull, 0x597f299cfc657e2aull,
	0x5fcb6fab3ad6faecull, 0x6c44198c4a475817ull
};

void blk_SHA512_224_Init(blk_SHA512_CTX *ctx)
{
	ctx->size = 0;
	ctx->digestlen = blk_SHA512_224_HASHSIZE;
	ctx->state[0] = 0x8c3d37c819544da2ull;
	ctx->state[1] = 0x73e1996689dcd4d6ull;
	ctx->state[2] = 0x1dfab7ae32ff9c82ull;
	ctx->state[3] = 0x679dd514582f9fcfull;
	ctx->state[4] = 0x0f6d2b697bd44da8ull;
	ctx->state[5] = 0x77e36f7304c48942ull;
	ctx->state[6] = 0x3f9d85a86a1d36c8ull;
	ctx->state[7] = 0x1112e6ad91d692a1ull;
}

void blk_SHA512_256_Init(blk_SHA512_CTX *ctx)
{
	ctx->size = 0;
	ctx->digestlen = blk_SHA512_256_HASHSIZE;
	ctx->state[0] = 0x22312194fc2bf72cull;
	ctx->state[1] = 0x9f555fa3c84c64c2ull;
	ctx->state[2] = 0x2393b86b6f53b151ull;
	ctx->state[3] = 0x963877195940eabdull;
	ctx->state[4] = 0x96283ee2a88effe3ull;
	ctx->state[5] = 0xbe5e1e2553863992ull;
	ctx->state[6] = 0x2b0199fc2c85b8aaull;
	ctx->state[7] = 0x0eb72ddc81c52ca2ull;
}

void blk_SHA512_Init(blk_SHA512_CTX *ctx)
{
	ctx->size = 0;
	ctx->digestlen = blk_SHA512_HASHSIZE;
	ctx->state[0] = 0x6a09e667f3bcc908ull;
	ctx->state[1] = 0xbb67ae8584caa73bull;
	ctx->state[2] = 0x3c6ef372fe94f82bull;
	ctx->state[3] = 0xa54ff53a5f1d36f1ull;
	ctx->state[4] = 0x510e527fade682d1ull;
	ctx->state[5] = 0x9b05688c2b3e6c1full;
	ctx->state[6] = 0x1f83d9abfb41bd6bull;
	ctx->state[7] = 0x5be0cd19137e2179ull;
}

static inline uint64_t ror(uint64_t x, unsigned n)
{
	return (x >> n) | (x << (64 - n));
}

static inline uint64_t ch(uint64_t x, uint64_t y, uint64_t z)
{
	return z ^ (x & (y ^ z));
}

static inline uint64_t maj(uint64_t x, uint64_t y, uint64_t z)
{
	return ((x | y) & z) | (x & y);
}

static inline uint64_t sigma0(uint64_t x)
{
	return ror(x, 28) ^ ror(x, 34) ^ ror(x, 39);
}

static inline uint64_t sigma1(uint64_t x)
{
	return ror(x, 14) ^ ror(x, 18) ^ ror(x, 41);
}

static inline uint64_t gamma0(uint64_t x)
{
	return ror(x, 1) ^ ror(x, 8) ^ (x >> 7);
}

static inline uint64_t gamma1(uint64_t x)
{
	return ror(x, 19) ^ ror(x, 61) ^ (x >> 6);
}

static void blk_SHA512_Transform(blk_SHA512_CTX *ctx, const unsigned char *buf)
{
	uint64_t S[8], W[80], t0, t1;
	int i;

	/* copy state into S */
	for (i = 0; i < 8; i++)
		S[i] = ctx->state[i];

	/* copy the state into 1024-bits into W[0..15] */
	for (i=0; i<16; i++, buf += sizeof(uint64_t)) {
		W[i] = get_be64(buf);
	}

	/* fill W[16..80] */
	for (; i<80; i++) {
		W[i] = gamma1(W[i - 2]) + W[i - 7] + gamma0(W[i - 15]) + W[i - 16];
	}

	/* compute SHA rounds */
	for (i=0; i<80; i++) {
		t0 = W[i] + S[7] + sigma1(S[4]) + ch(S[4], S[5], S[6]) + SHA_512_K[i];
		t1 = maj(S[0], S[1], S[2]) + sigma0(S[0]);
		S[7] = S[6];
		S[6] = S[5];
		S[5] = S[4];
		S[4] = S[3] + t0;
		S[3] = S[2];
		S[2] = S[1];
		S[1] = S[0];
		S[0] = t0 + t1;
	}

	for (i = 0; i < 8; i++)
		ctx->state[i] += S[i];
}

void blk_SHA512_Update(blk_SHA512_CTX *ctx, const void *data, size_t len)
{
	unsigned int len_buf = ctx->size & 127;

	ctx->size += len;

	/* Read the data into buf and process blocks as they get full */
	if (len_buf) {
		unsigned int left = 128 - len_buf;
		if (len < left)
			left = len;
		memcpy(len_buf + ctx->buf, data, left);
		len_buf = (len_buf + left) & 127;
		len -= left;
		data = ((const char *)data + left);
		if (len_buf)
			return;
		blk_SHA512_Transform(ctx, ctx->buf);
	}
	while (len >= 128) {
		blk_SHA512_Transform(ctx, data);
		data = ((const char *)data + 128);
		len -= 128;
	}
	if (len)
		memcpy(ctx->buf, data, len);
}

void blk_SHA512_Final(uint8_t *digest, blk_SHA512_CTX *ctx)
{
	static const unsigned char pad[128] = { 0x80 };
	unsigned int padlen[2];
	int i;

	/* Pad with a binary 1 (ie 0x80), then zeroes, then length */
	padlen[0] = htonl((uint32_t)(ctx->size >> 29));
	padlen[1] = htonl((uint32_t)(ctx->size << 3));

	i = ctx->size & 127;
	blk_SHA512_Update(ctx, pad, 1 + (127 & (119 - i)));
	blk_SHA512_Update(ctx, padlen, 8);

	/* copy output */
	for (i = 0; i < 8; i++, digest += sizeof(uint64_t))
		put_be64(digest, ctx->state[i]);
}
