/*
 * sha3.c
 *
 * an implementation of Secure Hash Algorithm 3 (Keccak) based on:
 * The Keccak SHA-3 submission. Submission to NIST (Round 3), 2011
 * by Guido Bertoni, Joan Daemen, Michaël Peeters and Gilles Van Assche
 *
 * portions derived from RHash/sha3.c
 *
 * Copyright (c) 2013, Aleksey Kravchenko <rhash.admin@gmail.com>
 * Copyright (c) 2019, Michael Clark <michaeljclark@mac.com>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "git-compat-util.h"
#include "sha3.h"

/*
 * macro to expand Keccak 7-term GF(2) round constant:
 *
 * (ax^63 + bx^31 + cx^15 + dx^7 + ex^3 + fx + g)
 *
 * K(c) -> forall (b in 0...6) |= c[b] << (1 << b) ;
 */
#define T(c,b) 0b##c##ull>>b<<63>>(64-(1 << b))
#define K(c) T(c,0)|T(c,1)|T(c,2)|T(c,3)|T(c,4)|T(c,5)|T(c,6)

/*
 * expand SHA3 (Keccak) constants for 24 rounds
 */
static uint64_t keccak_round_constants[24] = {
	K(0000001), K(0011010), K(1011110), K(1110000),
	K(0011111), K(0100001), K(1111001), K(1010101),
	K(0001110), K(0001100), K(0110101), K(0100110),
	K(0111111), K(1001111), K(1011101), K(1010011),
	K(1010010), K(1001000), K(0010110), K(1100110),
	K(1111001), K(1011000), K(0100001), K(1110100),
};

static inline uint64_t rol(uint64_t x, int d)
{
	return (x << d) | (x >> (64-d));
}

/* Keccak theta() transformation */
static void keccak_theta(uint64_t A[25])
{
	uint64_t C[5] = {
		A[0] ^ A[5] ^ A[10] ^ A[15] ^ A[20],
		A[1] ^ A[6] ^ A[11] ^ A[16] ^ A[21],
		A[2] ^ A[7] ^ A[12] ^ A[17] ^ A[22],
		A[3] ^ A[8] ^ A[13] ^ A[18] ^ A[23],
		A[4] ^ A[9] ^ A[14] ^ A[19] ^ A[24]
	};

	uint64_t D[5] = {
		rol(C[1], 1) ^ C[4],
		rol(C[2], 1) ^ C[0],
		rol(C[3], 1) ^ C[1],
		rol(C[4], 1) ^ C[2],
		rol(C[0], 1) ^ C[3]
	};

	for (size_t i = 0; i < 25; i += 5) {
		A[i + 0] ^= D[0];
		A[i + 1] ^= D[1];
		A[i + 2] ^= D[2];
		A[i + 3] ^= D[3];
		A[i + 4] ^= D[4];
	}
}

/* Keccak pi() transformation */
static void keccak_pi(uint64_t A[25])
{
	uint64_t A1;
	A1 = A[1];
	A[ 1] = A[ 6];
	A[ 6] = A[ 9];
	A[ 9] = A[22];
	A[22] = A[14];
	A[14] = A[20];
	A[20] = A[ 2];
	A[ 2] = A[12];
	A[12] = A[13];
	A[13] = A[19];
	A[19] = A[23];
	A[23] = A[15];
	A[15] = A[ 4];
	A[ 4] = A[24];
	A[24] = A[21];
	A[21] = A[ 8];
	A[ 8] = A[16];
	A[16] = A[ 5];
	A[ 5] = A[ 3];
	A[ 3] = A[18];
	A[18] = A[17];
	A[17] = A[11];
	A[11] = A[ 7];
	A[ 7] = A[10];
	A[10] = A1;
	/* note: A[ 0] is left as is */
}

static inline void ChiStep(uint64_t A[25], size_t i)
{
	uint64_t C[5];
	C[0] = A[0 + i] ^ ~A[1 + i] & A[2 + i];
	C[1] = A[1 + i] ^ ~A[2 + i] & A[3 + i];
	C[2] = A[2 + i] ^ ~A[3 + i] & A[4 + i];
	C[3] = A[3 + i] ^ ~A[4 + i] & A[0 + i];
	C[4] = A[4 + i] ^ ~A[0 + i] & A[1 + i];
	A[0 + i] = C[0];
	A[1 + i] = C[1];
	A[2 + i] = C[2];
	A[3 + i] = C[3];
	A[4 + i] = C[4];
}

/* Keccak chi() transformation */
static void keccak_chi(uint64_t A[25])
{
	ChiStep(A,0);
	ChiStep(A,5);
	ChiStep(A,10);
	ChiStep(A,15);
	ChiStep(A,20);
}

static void keccak_rho(uint64_t A[25])
{
	/* apply Keccak rho() transformation */
	A[ 1] = rol(A[ 1],  1);
	A[ 2] = rol(A[ 2], 62);
	A[ 3] = rol(A[ 3], 28);
	A[ 4] = rol(A[ 4], 27);
	A[ 5] = rol(A[ 5], 36);
	A[ 6] = rol(A[ 6], 44);
	A[ 7] = rol(A[ 7],  6);
	A[ 8] = rol(A[ 8], 55);
	A[ 9] = rol(A[ 9], 20);
	A[10] = rol(A[10],  3);
	A[11] = rol(A[11], 10);
	A[12] = rol(A[12], 43);
	A[13] = rol(A[13], 25);
	A[14] = rol(A[14], 39);
	A[15] = rol(A[15], 41);
	A[16] = rol(A[16], 45);
	A[17] = rol(A[17], 15);
	A[18] = rol(A[18], 21);
	A[19] = rol(A[19],  8);
	A[20] = rol(A[20], 18);
	A[21] = rol(A[21],  2);
	A[22] = rol(A[22], 61);
	A[23] = rol(A[23], 56);
	A[24] = rol(A[24], 14);
}

static void keccak_iota(uint64_t A[25], size_t round)
{
	/* apply iota(state, round) */
	A[0] ^= keccak_round_constants[round];
}

static void keccak_permutation(uint64_t A[25])
{
	for (size_t round = 0; round < 24; round++)
	{
		keccak_theta(A);
		keccak_rho(A);
		keccak_pi(A);
		keccak_chi(A);
		keccak_iota(A, round);
	}
}

static void blk_SHA3_Transform(blk_SHA3_CTX* ctx, const unsigned char *buf)
{
	size_t block_size = ctx->block_size;
	for (size_t i = 0; i < block_size/8; i++)
	{
		ctx->state[i] ^= le64toh(((uint64_t*)buf)[i]);
	}
	keccak_permutation(ctx->state);
}

static void blk_SHA3_Init(blk_SHA3_CTX* ctx, unsigned bits)
{
	/* NB: The Keccak capacity parameter = bits * 2 */
	unsigned rate = 1600 - bits * 2;

	memset(ctx, 0, sizeof(blk_SHA3_CTX));
	ctx->block_size = rate / 8;
	assert(rate <= 1600 && (rate % 64) == 0);
}

void blk_SHA3_224_Init(blk_SHA3_CTX* ctx) { blk_SHA3_Init(ctx, 224); }
void blk_SHA3_256_Init(blk_SHA3_CTX* ctx) { blk_SHA3_Init(ctx, 256); }
void blk_SHA3_384_Init(blk_SHA3_CTX* ctx) { blk_SHA3_Init(ctx, 384); }
void blk_SHA3_512_Init(blk_SHA3_CTX* ctx) { blk_SHA3_Init(ctx, 512); }

void blk_SHA3_Update(blk_SHA3_CTX* ctx, const void *data, size_t len)
{
	unsigned int block_size = ctx->block_size;
	unsigned int len_buf = ctx->size % block_size;

	ctx->size += len;

	/* Read the data into buf and process blocks as they get full */
	if (len_buf) {
		unsigned int left = block_size - len_buf;
		if (len < left)
			left = len;
		memcpy(len_buf + ctx->buf, data, left);
		len_buf = (len_buf + left) % block_size;
		len -= left;
		data = ((const char *)data + left);
		if (len_buf)
			return;
		blk_SHA3_Transform(ctx, ctx->buf);
	}
	while (len >= block_size) {
		blk_SHA3_Transform(ctx, data);
		data = ((const char *)data + block_size);
		len -= block_size;
	}
	if (len)
		memcpy(ctx->buf, data, len);
}

static inline void put_le64(void *ptr, uint64_t value)
{
	unsigned char *p = ptr;
	p[0] = value >>  0;
	p[1] = value >>  8;
	p[2] = value >> 16;
	p[3] = value >> 24;
	p[4] = value >> 32;
	p[5] = value >> 40;
	p[6] = value >> 48;
	p[7] = value >> 56;
}

void blk_SHA3_Final(unsigned char* digest, blk_SHA3_CTX* ctx)
{
	unsigned int digest_length = 100 - ctx->block_size / 2;
	unsigned int block_size = ctx->block_size;
	unsigned int len = ctx->size % block_size, i;

	/* Pad with 0x06, then zeroes, then 0x80 */
	memset((char*)ctx->buf + len, 0, block_size - len);
	((char*)ctx->buf)[len] |= 0x06;
	((char*)ctx->buf)[block_size - 1] |= 0x80;

	/* process final block */
	blk_SHA3_Transform(ctx, ctx->buf);

	/* copy output */
	for (i = 0; i < (digest_length+7)/8; i++, digest += sizeof(uint64_t))
		put_le64(digest, ctx->state[i]);
}
