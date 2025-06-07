/* vi: set sw=4 ts=4: */
/*
 * Utility routines.
 *
 * Copyright (C) 2010 Denys Vlasenko
 *
 * Licensed under GPLv2 or later, see file LICENSE in this source tree.
 */
#include "libbb.h"
#include <windows.h>
#include <bcrypt.h>

#define BCRYPT_MD5_ALG_HANDLE                   ((BCRYPT_ALG_HANDLE) 0x00000021)
#define BCRYPT_SHA1_ALG_HANDLE                  ((BCRYPT_ALG_HANDLE) 0x00000031)
#define BCRYPT_SHA256_ALG_HANDLE                ((BCRYPT_ALG_HANDLE) 0x00000041)
#define BCRYPT_SHA512_ALG_HANDLE                ((BCRYPT_ALG_HANDLE) 0x00000061)

#define STR1(s) #s
#define STR(s) STR1(s)

#define NEED_SHA512 (ENABLE_SHA512SUM || ENABLE_USE_BB_CRYPT_SHA)

/* gcc 4.2.1 optimizes rotr64 better with inline than with macro
 * (for rotX32, there is no difference). Why? My guess is that
 * macro requires clever common subexpression elimination heuristics
 * in gcc, while inline basically forces it to happen.
 */
//#define rotl32(x,n) (((x) << (n)) | ((x) >> (32 - (n))))
static ALWAYS_INLINE uint32_t rotl32(uint32_t x, unsigned n)
{
	return (x << n) | (x >> (32 - n));
}
//#define rotr32(x,n) (((x) >> (n)) | ((x) << (32 - (n))))
static ALWAYS_INLINE uint32_t rotr32(uint32_t x, unsigned n)
{
	return (x >> n) | (x << (32 - n));
}
/* rotr64 in needed for sha512 only: */
//#define rotr64(x,n) (((x) >> (n)) | ((x) << (64 - (n))))
static ALWAYS_INLINE uint64_t rotr64(uint64_t x, unsigned n)
{
	return (x >> n) | (x << (64 - n));
}

/* rotl64 only used for sha3 currently */
static ALWAYS_INLINE uint64_t rotl64(uint64_t x, unsigned n)
{
	return (x << n) | (x >> (64 - n));
}

/* Initialize structure containing state of computation.
 * (RFC 1321, 3.3: Step 3)
 */
void FAST_FUNC md5_begin(md5_ctx_t *ctx)
{
	DWORD hash_object_length = 0;
    ULONG _unused;

	BCryptGetProperty(BCRYPT_MD5_ALG_HANDLE, BCRYPT_OBJECT_LENGTH, (PUCHAR)&hash_object_length, sizeof(DWORD), &_unused, 0);
	BCryptGetProperty(BCRYPT_MD5_ALG_HANDLE, BCRYPT_HASH_LENGTH, (PUCHAR)&ctx->output_size, sizeof(DWORD), &_unused, 0);

	ctx->hash_obj = malloc(hash_object_length);
	if (!ctx->hash_obj) {
		// this function doesn't support error handling
		exit(1);
	}

	BCryptCreateHash(BCRYPT_MD5_ALG_HANDLE, &ctx->handle, ctx->hash_obj, hash_object_length, NULL, 0, BCRYPT_HASH_REUSABLE_FLAG);
}

/* Used also for sha1 and sha256 */
void FAST_FUNC md5_hash(md5_ctx_t *ctx, const void *buffer, size_t len)
{
	BCryptHashData(ctx->handle, (const PUCHAR *)buffer, len, 0);
}

unsigned FAST_FUNC md5_end(md5_ctx_t *ctx, void *resbuf)
{
	BCryptFinishHash(ctx->handle, resbuf, ctx->output_size, 0);
	return ctx->output_size;
}

void FAST_FUNC sha1_begin(sha1_ctx_t *ctx)
{
	DWORD hash_object_length = 0;
    ULONG _unused;

	BCryptGetProperty(BCRYPT_SHA1_ALG_HANDLE, BCRYPT_OBJECT_LENGTH, (PUCHAR)&hash_object_length, sizeof(DWORD), &_unused, 0);
	BCryptGetProperty(BCRYPT_SHA1_ALG_HANDLE, BCRYPT_HASH_LENGTH, (PUCHAR)&ctx->output_size, sizeof(DWORD), &_unused, 0);

	ctx->hash_obj = malloc(hash_object_length);
	if (!ctx->hash_obj) {
		// this function doesn't support error handling
		exit(1);
	}

	BCryptCreateHash(BCRYPT_SHA1_ALG_HANDLE, &ctx->handle, ctx->hash_obj, hash_object_length, NULL, 0, BCRYPT_HASH_REUSABLE_FLAG);
}

/* Initialize structure containing state of computation.
   (FIPS 180-2:5.3.2)  */
void FAST_FUNC sha256_begin(sha256_ctx_t *ctx)
{
	DWORD hash_object_length = 0;
    ULONG _unused;

	BCryptGetProperty(BCRYPT_SHA256_ALG_HANDLE, BCRYPT_OBJECT_LENGTH, (PUCHAR)&hash_object_length, sizeof(DWORD), &_unused, 0);
	BCryptGetProperty(BCRYPT_SHA256_ALG_HANDLE, BCRYPT_HASH_LENGTH, (PUCHAR)&ctx->output_size, sizeof(DWORD), &_unused, 0);
	
	ctx->hash_obj = malloc(hash_object_length);
	if (!ctx->hash_obj) {
		// this function doesn't support error handling
		exit(1);
	}

	BCryptCreateHash(BCRYPT_SHA256_ALG_HANDLE, &ctx->handle, ctx->hash_obj, hash_object_length, NULL, 0, BCRYPT_HASH_REUSABLE_FLAG);
}

#if NEED_SHA512
/* Initialize structure containing state of computation.
   (FIPS 180-2:5.3.3)  */
void FAST_FUNC sha512_begin(sha512_ctx_t *ctx)
{
	DWORD hash_object_length = 0;
    ULONG _unused;

	BCryptGetProperty(BCRYPT_SHA512_ALG_HANDLE, BCRYPT_OBJECT_LENGTH, (PUCHAR)&hash_object_length, sizeof(DWORD), &_unused, 0);
	BCryptGetProperty(BCRYPT_SHA512_ALG_HANDLE, BCRYPT_HASH_LENGTH, (PUCHAR)&ctx->output_size, sizeof(DWORD), &_unused, 0);

	ctx->hash_obj = malloc(hash_object_length);
	if (!ctx->hash_obj) {
		// this function doesn't support error handling
		exit(1);
	}

	BCryptCreateHash(BCRYPT_SHA512_ALG_HANDLE, &ctx->handle, ctx->hash_obj, hash_object_length, NULL, 0, BCRYPT_HASH_REUSABLE_FLAG);
}
#endif /* NEED_SHA512 */



/*
 * The Keccak sponge function, designed by Guido Bertoni, Joan Daemen,
 * Michael Peeters and Gilles Van Assche. For more information, feedback or
 * questions, please refer to our website: http://keccak.noekeon.org/
 *
 * Implementation by Ronny Van Keer,
 * hereby denoted as "the implementer".
 *
 * To the extent possible under law, the implementer has waived all copyright
 * and related or neighboring rights to the source code in this file.
 * http://creativecommons.org/publicdomain/zero/1.0/
 *
 * Busybox modifications (C) Lauri Kasanen, under the GPLv2.
 */

#if CONFIG_SHA3_SMALL < 0
# define SHA3_SMALL 0
#elif CONFIG_SHA3_SMALL > 1
# define SHA3_SMALL 1
#else
# define SHA3_SMALL CONFIG_SHA3_SMALL
#endif

#define OPTIMIZE_SHA3_FOR_32 0
/*
 * SHA3 can be optimized for 32-bit CPUs with bit-slicing:
 * every 64-bit word of state[] can be split into two 32-bit words
 * by even/odd bits. In this form, all rotations of sha3 round
 * are 32-bit - and there are lots of them.
 * However, it requires either splitting/combining state words
 * before/after sha3 round (code does this now)
 * or shuffling bits before xor'ing them into state and in sha3_end.
 * Without shuffling, bit-slicing results in -130 bytes of code
 * and marginal speedup (but of course it gives wrong result).
 * With shuffling it works, but +260 code bytes, and slower.
 * Disabled for now:
 */
#if 0 /* LONG_MAX == 0x7fffffff */
# undef OPTIMIZE_SHA3_FOR_32
# define OPTIMIZE_SHA3_FOR_32 1
#endif

#if OPTIMIZE_SHA3_FOR_32
/* This splits every 64-bit word into a pair of 32-bit words,
 * even bits go into first word, odd bits go to second one.
 * The conversion is done in-place.
 */
static void split_halves(uint64_t *state)
{
	/* Credit: Henry S. Warren, Hacker's Delight, Addison-Wesley, 2002 */
	uint32_t *s32 = (uint32_t*)state;
	uint32_t t, x0, x1;
	int i;
	for (i = 24; i >= 0; --i) {
		x0 = s32[0];
		t = (x0 ^ (x0 >> 1)) & 0x22222222; x0 = x0 ^ t ^ (t << 1);
		t = (x0 ^ (x0 >> 2)) & 0x0C0C0C0C; x0 = x0 ^ t ^ (t << 2);
		t = (x0 ^ (x0 >> 4)) & 0x00F000F0; x0 = x0 ^ t ^ (t << 4);
		t = (x0 ^ (x0 >> 8)) & 0x0000FF00; x0 = x0 ^ t ^ (t << 8);
		x1 = s32[1];
		t = (x1 ^ (x1 >> 1)) & 0x22222222; x1 = x1 ^ t ^ (t << 1);
		t = (x1 ^ (x1 >> 2)) & 0x0C0C0C0C; x1 = x1 ^ t ^ (t << 2);
		t = (x1 ^ (x1 >> 4)) & 0x00F000F0; x1 = x1 ^ t ^ (t << 4);
		t = (x1 ^ (x1 >> 8)) & 0x0000FF00; x1 = x1 ^ t ^ (t << 8);
		*s32++ = (x0 & 0x0000FFFF) | (x1 << 16);
		*s32++ = (x0 >> 16) | (x1 & 0xFFFF0000);
	}
}
/* The reverse operation */
static void combine_halves(uint64_t *state)
{
	uint32_t *s32 = (uint32_t*)state;
	uint32_t t, x0, x1;
	int i;
	for (i = 24; i >= 0; --i) {
		x0 = s32[0];
		x1 = s32[1];
		t = (x0 & 0x0000FFFF) | (x1 << 16);
		x1 = (x0 >> 16) | (x1 & 0xFFFF0000);
		x0 = t;
		t = (x0 ^ (x0 >> 8)) & 0x0000FF00; x0 = x0 ^ t ^ (t << 8);
		t = (x0 ^ (x0 >> 4)) & 0x00F000F0; x0 = x0 ^ t ^ (t << 4);
		t = (x0 ^ (x0 >> 2)) & 0x0C0C0C0C; x0 = x0 ^ t ^ (t << 2);
		t = (x0 ^ (x0 >> 1)) & 0x22222222; x0 = x0 ^ t ^ (t << 1);
		*s32++ = x0;
		t = (x1 ^ (x1 >> 8)) & 0x0000FF00; x1 = x1 ^ t ^ (t << 8);
		t = (x1 ^ (x1 >> 4)) & 0x00F000F0; x1 = x1 ^ t ^ (t << 4);
		t = (x1 ^ (x1 >> 2)) & 0x0C0C0C0C; x1 = x1 ^ t ^ (t << 2);
		t = (x1 ^ (x1 >> 1)) & 0x22222222; x1 = x1 ^ t ^ (t << 1);
		*s32++ = x1;
	}
}
#endif

/*
 * In the crypto literature this function is usually called Keccak-f().
 */
static void sha3_process_block72(uint64_t *state)
{
	enum { NROUNDS = 24 };

#if OPTIMIZE_SHA3_FOR_32
	/*
	static const uint32_t IOTA_CONST_0[NROUNDS] ALIGN4 = {
		0x00000001UL,
		0x00000000UL,
		0x00000000UL,
		0x00000000UL,
		0x00000001UL,
		0x00000001UL,
		0x00000001UL,
		0x00000001UL,
		0x00000000UL,
		0x00000000UL,
		0x00000001UL,
		0x00000000UL,
		0x00000001UL,
		0x00000001UL,
		0x00000001UL,
		0x00000001UL,
		0x00000000UL,
		0x00000000UL,
		0x00000000UL,
		0x00000000UL,
		0x00000001UL,
		0x00000000UL,
		0x00000001UL,
		0x00000000UL,
	};
	** bits are in lsb: 0101 0000 1111 0100 1111 0001
	*/
	uint32_t IOTA_CONST_0bits = (uint32_t)(0x0050f4f1);
	static const uint32_t IOTA_CONST_1[NROUNDS] ALIGN4 = {
		0x00000000UL,
		0x00000089UL,
		0x8000008bUL,
		0x80008080UL,
		0x0000008bUL,
		0x00008000UL,
		0x80008088UL,
		0x80000082UL,
		0x0000000bUL,
		0x0000000aUL,
		0x00008082UL,
		0x00008003UL,
		0x0000808bUL,
		0x8000000bUL,
		0x8000008aUL,
		0x80000081UL,
		0x80000081UL,
		0x80000008UL,
		0x00000083UL,
		0x80008003UL,
		0x80008088UL,
		0x80000088UL,
		0x00008000UL,
		0x80008082UL,
	};

	uint32_t *const s32 = (uint32_t*)state;
	unsigned round;

	split_halves(state);

	for (round = 0; round < NROUNDS; round++) {
		unsigned x;

		/* Theta */
		{
			uint32_t BC[20];
			for (x = 0; x < 10; ++x) {
				BC[x+10] = BC[x] = s32[x]^s32[x+10]^s32[x+20]^s32[x+30]^s32[x+40];
			}
			for (x = 0; x < 10; x += 2) {
				uint32_t ta, tb;
				ta = BC[x+8] ^ rotl32(BC[x+3], 1);
				tb = BC[x+9] ^ BC[x+2];
				s32[x+0] ^= ta;
				s32[x+1] ^= tb;
				s32[x+10] ^= ta;
				s32[x+11] ^= tb;
				s32[x+20] ^= ta;
				s32[x+21] ^= tb;
				s32[x+30] ^= ta;
				s32[x+31] ^= tb;
				s32[x+40] ^= ta;
				s32[x+41] ^= tb;
			}
		}
		/* RhoPi */
		{
			uint32_t t0a,t0b, t1a,t1b;
			t1a = s32[1*2+0];
			t1b = s32[1*2+1];

#define RhoPi(PI_LANE, ROT_CONST) \
	t0a = s32[PI_LANE*2+0];\
	t0b = s32[PI_LANE*2+1];\
	if (ROT_CONST & 1) {\
		s32[PI_LANE*2+0] = rotl32(t1b, ROT_CONST/2+1);\
		s32[PI_LANE*2+1] = ROT_CONST == 1 ? t1a : rotl32(t1a, ROT_CONST/2+0);\
	} else {\
		s32[PI_LANE*2+0] = rotl32(t1a, ROT_CONST/2);\
		s32[PI_LANE*2+1] = rotl32(t1b, ROT_CONST/2);\
	}\
	t1a = t0a; t1b = t0b;

			RhoPi(10, 1)
			RhoPi( 7, 3)
			RhoPi(11, 6)
			RhoPi(17,10)
			RhoPi(18,15)
			RhoPi( 3,21)
			RhoPi( 5,28)
			RhoPi(16,36)
			RhoPi( 8,45)
			RhoPi(21,55)
			RhoPi(24, 2)
			RhoPi( 4,14)
			RhoPi(15,27)
			RhoPi(23,41)
			RhoPi(19,56)
			RhoPi(13, 8)
			RhoPi(12,25)
			RhoPi( 2,43)
			RhoPi(20,62)
			RhoPi(14,18)
			RhoPi(22,39)
			RhoPi( 9,61)
			RhoPi( 6,20)
			RhoPi( 1,44)
#undef RhoPi
		}
		/* Chi */
		for (x = 0; x <= 40;) {
			uint32_t BC0, BC1, BC2, BC3, BC4;
			BC0 = s32[x + 0*2];
			BC1 = s32[x + 1*2];
			BC2 = s32[x + 2*2];
			s32[x + 0*2] = BC0 ^ ((~BC1) & BC2);
			BC3 = s32[x + 3*2];
			s32[x + 1*2] = BC1 ^ ((~BC2) & BC3);
			BC4 = s32[x + 4*2];
			s32[x + 2*2] = BC2 ^ ((~BC3) & BC4);
			s32[x + 3*2] = BC3 ^ ((~BC4) & BC0);
			s32[x + 4*2] = BC4 ^ ((~BC0) & BC1);
			x++;
			BC0 = s32[x + 0*2];
			BC1 = s32[x + 1*2];
			BC2 = s32[x + 2*2];
			s32[x + 0*2] = BC0 ^ ((~BC1) & BC2);
			BC3 = s32[x + 3*2];
			s32[x + 1*2] = BC1 ^ ((~BC2) & BC3);
			BC4 = s32[x + 4*2];
			s32[x + 2*2] = BC2 ^ ((~BC3) & BC4);
			s32[x + 3*2] = BC3 ^ ((~BC4) & BC0);
			s32[x + 4*2] = BC4 ^ ((~BC0) & BC1);
			x += 9;
		}
		/* Iota */
		s32[0] ^= IOTA_CONST_0bits & 1;
		IOTA_CONST_0bits >>= 1;
		s32[1] ^= IOTA_CONST_1[round];
	}

	combine_halves(state);
#else
	/* Native 64-bit algorithm */
	static const uint16_t IOTA_CONST[NROUNDS] ALIGN2 = {
		/* Elements should be 64-bit, but top half is always zero
		 * or 0x80000000. We encode 63rd bits in a separate word below.
		 * Same is true for 31th bits, which lets us use 16-bit table
		 * instead of 64-bit. The speed penalty is lost in the noise.
		 */
		0x0001,
		0x8082,
		0x808a,
		0x8000,
		0x808b,
		0x0001,
		0x8081,
		0x8009,
		0x008a,
		0x0088,
		0x8009,
		0x000a,
		0x808b,
		0x008b,
		0x8089,
		0x8003,
		0x8002,
		0x0080,
		0x800a,
		0x000a,
		0x8081,
		0x8080,
		0x0001,
		0x8008,
	};
	/* bit for CONST[0] is in msb: 0011 0011 0000 0111 1101 1101 */
	const uint32_t IOTA_CONST_bit63 = (uint32_t)(0x3307dd00);
	/* bit for CONST[0] is in msb: 0001 0110 0011 1000 0001 1011 */
	const uint32_t IOTA_CONST_bit31 = (uint32_t)(0x16381b00);

	static const uint8_t ROT_CONST[24] ALIGN1 = {
		1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14,
		27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
	};
	static const uint8_t PI_LANE[24] ALIGN1 = {
		10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4,
		15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
	};
	/*static const uint8_t MOD5[10] ALIGN1 = { 0, 1, 2, 3, 4, 0, 1, 2, 3, 4, };*/

	unsigned x;
	unsigned round;

	if (BB_BIG_ENDIAN) {
		for (x = 0; x < 25; x++) {
			state[x] = SWAP_LE64(state[x]);
		}
	}

	for (round = 0; round < NROUNDS; ++round) {
		/* Theta */
		{
			uint64_t BC[10];
			for (x = 0; x < 5; ++x) {
				BC[x + 5] = BC[x] = state[x]
					^ state[x + 5] ^ state[x + 10]
					^ state[x + 15]	^ state[x + 20];
			}
			/* Using 2x5 vector above eliminates the need to use
			 * BC[MOD5[x+N]] trick below to fetch BC[(x+N) % 5],
			 * and the code is a bit _smaller_.
			 */
			for (x = 0; x < 5; ++x) {
				uint64_t temp = BC[x + 4] ^ rotl64(BC[x + 1], 1);
				state[x] ^= temp;
				state[x + 5] ^= temp;
				state[x + 10] ^= temp;
				state[x + 15] ^= temp;
				state[x + 20] ^= temp;
			}
		}

		/* Rho Pi */
		if (SHA3_SMALL) {
			uint64_t t1 = state[1];
			for (x = 0; x < 24; ++x) {
				uint64_t t0 = state[PI_LANE[x]];
				state[PI_LANE[x]] = rotl64(t1, ROT_CONST[x]);
				t1 = t0;
			}
		} else {
			/* Especially large benefit for 32-bit arch (75% faster):
			 * 64-bit rotations by non-constant usually are SLOW on those.
			 * We resort to unrolling here.
			 * This optimizes out PI_LANE[] and ROT_CONST[],
			 * but generates 300-500 more bytes of code.
			 */
			uint64_t t0;
			uint64_t t1 = state[1];
#define RhoPi_twice(x) \
	t0 = state[PI_LANE[x  ]]; \
	state[PI_LANE[x  ]] = rotl64(t1, ROT_CONST[x  ]); \
	t1 = state[PI_LANE[x+1]]; \
	state[PI_LANE[x+1]] = rotl64(t0, ROT_CONST[x+1]);
			RhoPi_twice(0); RhoPi_twice(2);
			RhoPi_twice(4); RhoPi_twice(6);
			RhoPi_twice(8); RhoPi_twice(10);
			RhoPi_twice(12); RhoPi_twice(14);
			RhoPi_twice(16); RhoPi_twice(18);
			RhoPi_twice(20); RhoPi_twice(22);
#undef RhoPi_twice
		}
		/* Chi */
# if LONG_MAX > 0x7fffffff
		for (x = 0; x <= 20; x += 5) {
			uint64_t BC0, BC1, BC2, BC3, BC4;
			BC0 = state[x + 0];
			BC1 = state[x + 1];
			BC2 = state[x + 2];
			state[x + 0] = BC0 ^ ((~BC1) & BC2);
			BC3 = state[x + 3];
			state[x + 1] = BC1 ^ ((~BC2) & BC3);
			BC4 = state[x + 4];
			state[x + 2] = BC2 ^ ((~BC3) & BC4);
			state[x + 3] = BC3 ^ ((~BC4) & BC0);
			state[x + 4] = BC4 ^ ((~BC0) & BC1);
		}
# else
		/* Reduced register pressure version
		 * for register-starved 32-bit arches
		 * (i386: -95 bytes, and it is _faster_)
		 */
		for (x = 0; x <= 40;) {
			uint32_t BC0, BC1, BC2, BC3, BC4;
			uint32_t *const s32 = (uint32_t*)state;
#  if SHA3_SMALL
 do_half:
#  endif
			BC0 = s32[x + 0*2];
			BC1 = s32[x + 1*2];
			BC2 = s32[x + 2*2];
			s32[x + 0*2] = BC0 ^ ((~BC1) & BC2);
			BC3 = s32[x + 3*2];
			s32[x + 1*2] = BC1 ^ ((~BC2) & BC3);
			BC4 = s32[x + 4*2];
			s32[x + 2*2] = BC2 ^ ((~BC3) & BC4);
			s32[x + 3*2] = BC3 ^ ((~BC4) & BC0);
			s32[x + 4*2] = BC4 ^ ((~BC0) & BC1);
			x++;
#  if SHA3_SMALL
			if (x & 1)
				goto do_half;
			x += 8;
#  else
			BC0 = s32[x + 0*2];
			BC1 = s32[x + 1*2];
			BC2 = s32[x + 2*2];
			s32[x + 0*2] = BC0 ^ ((~BC1) & BC2);
			BC3 = s32[x + 3*2];
			s32[x + 1*2] = BC1 ^ ((~BC2) & BC3);
			BC4 = s32[x + 4*2];
			s32[x + 2*2] = BC2 ^ ((~BC3) & BC4);
			s32[x + 3*2] = BC3 ^ ((~BC4) & BC0);
			s32[x + 4*2] = BC4 ^ ((~BC0) & BC1);
			x += 9;
#  endif
		}
# endif /* long is 32-bit */
		/* Iota */
		state[0] ^= IOTA_CONST[round]
			| (uint32_t)((IOTA_CONST_bit31 << round) & 0x80000000)
			| (uint64_t)((IOTA_CONST_bit63 << round) & 0x80000000) << 32;
	}

	if (BB_BIG_ENDIAN) {
		for (x = 0; x < 25; x++) {
			state[x] = SWAP_LE64(state[x]);
		}
	}
#endif
}

void FAST_FUNC sha3_begin(sha3_ctx_t *ctx)
{
	memset(ctx, 0, sizeof(*ctx));
	/* SHA3-512, user can override */
	ctx->input_block_bytes = (1600 - 512*2) / 8; /* 72 bytes */
}

void FAST_FUNC sha3_hash(sha3_ctx_t *ctx, const void *buffer, size_t len)
{
#if SHA3_SMALL
	const uint8_t *data = buffer;
	unsigned bufpos = ctx->bytes_queued;

	while (1) {
		unsigned remaining = ctx->input_block_bytes - bufpos;
		if (remaining > len)
			remaining = len;
		len -= remaining;
		/* XOR data into buffer */
		while (remaining != 0) {
			uint8_t *buf = (uint8_t*)ctx->state;
			buf[bufpos] ^= *data++;
			bufpos++;
			remaining--;
		}

		/* Clever way to do "if (bufpos != N) break; ... ; bufpos = 0;" */
		bufpos -= ctx->input_block_bytes;
		if (bufpos != 0)
			break;

		/* Buffer is filled up, process it */
		sha3_process_block72(ctx->state);
		/*bufpos = 0; - already is */
	}
	ctx->bytes_queued = bufpos + ctx->input_block_bytes;
#else
	/* +50 bytes code size, but a bit faster because of long-sized XORs */
	const uint8_t *data = buffer;
	unsigned bufpos = ctx->bytes_queued;
	unsigned iblk_bytes = ctx->input_block_bytes;

	/* If already data in queue, continue queuing first */
	if (bufpos != 0) {
		while (len != 0) {
			uint8_t *buf = (uint8_t*)ctx->state;
			buf[bufpos] ^= *data++;
			len--;
			bufpos++;
			if (bufpos == iblk_bytes) {
				bufpos = 0;
				goto do_block;
			}
		}
	}

	/* Absorb complete blocks */
	while (len >= iblk_bytes) {
		/* XOR data onto beginning of state[].
		 * We try to be efficient - operate one word at a time, not byte.
		 * Careful wrt unaligned access: can't just use "*(long*)data"!
		 */
		unsigned count = iblk_bytes / sizeof(long);
		long *buf = (long*)ctx->state;
		do {
			long v;
			move_from_unaligned_long(v, (long*)data);
			*buf++ ^= v;
			data += sizeof(long);
		} while (--count);
		len -= iblk_bytes;
 do_block:
		sha3_process_block72(ctx->state);
	}

	/* Queue remaining data bytes */
	while (len != 0) {
		uint8_t *buf = (uint8_t*)ctx->state;
		buf[bufpos] ^= *data++;
		bufpos++;
		len--;
	}

	ctx->bytes_queued = bufpos;
#endif
}

unsigned FAST_FUNC sha3_end(sha3_ctx_t *ctx, void *resbuf)
{
	/* Padding */
	uint8_t *buf = (uint8_t*)ctx->state;
	/*
	 * Keccak block padding is: add 1 bit after last bit of input,
	 * then add zero bits until the end of block, and add the last 1 bit
	 * (the last bit in the block) - the "10*1" pattern.
	 * SHA3 standard appends additional two bits, 01,  before that padding:
	 *
	 * SHA3-224(M) = KECCAK[448](M||01, 224)
	 * SHA3-256(M) = KECCAK[512](M||01, 256)
	 * SHA3-384(M) = KECCAK[768](M||01, 384)
	 * SHA3-512(M) = KECCAK[1024](M||01, 512)
	 * (M is the input, || is bit concatenation)
	 *
	 * The 6 below contains 01 "SHA3" bits and the first 1 "Keccak" bit:
	 */
	buf[ctx->bytes_queued]          ^= 6; /* bit pattern 00000110 */
	buf[ctx->input_block_bytes - 1] ^= 0x80;

	sha3_process_block72(ctx->state);

	/* Output */
	memcpy(resbuf, ctx->state, 64);
	return 64;
}
