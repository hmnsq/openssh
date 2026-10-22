/*	$OpenBSD: md5.c,v 1.9 2014/01/08 06:14:57 tedu Exp $	*/

/*
 * This code implements the MD5 message-digest algorithm.
 * The algorithm is due to Ron Rivest.	This code was
 * written by Colin Plumb in 1993, no copyright is claimed.
 * This code is in the public domain; do with it what you wish.
 *
 * Equivalent code is available from RSA Data Security, Inc.
 * This code has been tested against that, and is equivalent,
 * except that you don't need to include two pages of legalese
 * with every copy.
 *
 * To compute the message digest of a chunk of bytes, declare an
 * MD5Context structure, pass it to MD5Init, call MD5Update as
 * needed on buffers full of bytes, and then call MD5Final, which
 * will fill a supplied 16-byte array with the digest.
 */

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ "md5.h"

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ PUT_64_ਦੋਆਧਾਰੀ_ਅੰਕ_LE(cp, ਮੁੱਲ) ਕਰੋ {					\
	(cp)[7] = (ਮੁੱਲ) >> 56;					\
	(cp)[6] = (ਮੁੱਲ) >> 48;					\
	(cp)[5] = (ਮੁੱਲ) >> 40;					\
	(cp)[4] = (ਮੁੱਲ) >> 32;					\
	(cp)[3] = (ਮੁੱਲ) >> 24;					\
	(cp)[2] = (ਮੁੱਲ) >> 16;					\
	(cp)[1] = (ਮੁੱਲ) >> 8;						\
	(cp)[0] = (ਮੁੱਲ); } ਜਦੋਂ (0)

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ PUT_32_ਦੋਆਧਾਰੀ_ਅੰਕ_LE(cp, ਮੁੱਲ) ਕਰੋ {					\
	(cp)[3] = (ਮੁੱਲ) >> 24;					\
	(cp)[2] = (ਮੁੱਲ) >> 16;					\
	(cp)[1] = (ਮੁੱਲ) >> 8;						\
	(cp)[0] = (ਮੁੱਲ); } ਜਦੋਂ (0)

ਸਥਿਰ u_int8_t PADDING[MD5_ਖੰਡ_ਲੰਮਾਈ] = {
	0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

/*
 * Start MD5 accumulation.  Set bit count to 0 and buffer to mysterious
 * initialization constants.
 */
ਖਾਲੀ
MD5Init(MD5_CTX *ctx)
{
	ctx->ਗਿਣਤੀ_2 = 0;
	ctx->state[0] = 0x67452301;
	ctx->state[1] = 0xefcdab89;
	ctx->state[2] = 0x98badcfe;
	ctx->state[3] = 0x10325476;
}

/*
 * Update context to reflect the concatenation of another buffer full
 * of bytes.
 */
ਖਾਲੀ
MD5Update(MD5_CTX *ctx, ਅਚਲ ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ *ਨਿਵੇਸ਼, ਮਾਪ_t len)
{
	ਮਾਪ_t have, need;

	/* Check how many bytes we already have and how many more we need. */
	have = (ਮਾਪ_t)((ctx->ਗਿਣਤੀ_2 >> 3) & (MD5_ਖੰਡ_ਲੰਮਾਈ - 1));
	need = MD5_ਖੰਡ_ਲੰਮਾਈ - have;

	/* Update bitcount */
	ctx->ਗਿਣਤੀ_2 += (u_int64_t)len << 3;

	ਜੇ (len >= need) {
		ਜੇ (have != 0) {
			ਸਮ੍ਰਿਤੀ_ਨਕਲ(ctx->ਬਫਰ + have, ਨਿਵੇਸ਼, need);
			MD5Transform(ctx->state, ctx->ਬਫਰ);
			ਨਿਵੇਸ਼ += need;
			len -= need;
			have = 0;
		}

		/* Process data in MD5_BLOCK_LENGTH-byte chunks. */
		ਜਦੋਂ (len >= MD5_ਖੰਡ_ਲੰਮਾਈ) {
			MD5Transform(ctx->state, ਨਿਵੇਸ਼);
			ਨਿਵੇਸ਼ += MD5_ਖੰਡ_ਲੰਮਾਈ;
			len -= MD5_ਖੰਡ_ਲੰਮਾਈ;
		}
	}

	/* Handle any remaining bytes of data. */
	ਜੇ (len != 0)
		ਸਮ੍ਰਿਤੀ_ਨਕਲ(ctx->ਬਫਰ + have, ਨਿਵੇਸ਼, len);
}

/*
 * Pad pad to 64-byte boundary with the bit pattern
 * 1 0* (64-bit count of bits processed, MSB-first)
 */
ਖਾਲੀ
MD5Pad(MD5_CTX *ctx)
{
	u_int8_t ਗਿਣਤੀ_2[8];
	ਮਾਪ_t padlen;

	/* Convert count to 8 bytes in little endian order. */
	PUT_64_ਦੋਆਧਾਰੀ_ਅੰਕ_LE(ਗਿਣਤੀ_2, ctx->ਗਿਣਤੀ_2);

	/* Pad out to 56 mod 64. */
	padlen = MD5_ਖੰਡ_ਲੰਮਾਈ -
	    ((ctx->ਗਿਣਤੀ_2 >> 3) & (MD5_ਖੰਡ_ਲੰਮਾਈ - 1));
	ਜੇ (padlen < 1 + 8)
		padlen += MD5_ਖੰਡ_ਲੰਮਾਈ;
	MD5Update(ctx, PADDING, padlen - 8);		/* padlen - 8 <= 64 */
	MD5Update(ctx, ਗਿਣਤੀ_2, 8);
}

/*
 * Final wrapup--call MD5Pad, fill in digest and zero out ctx.
 */
ਖਾਲੀ
MD5Final(ਬਿਨਾਨਿਸ਼ਾਨੀ ਅੱਖਰ digest[MD5_DIGEST_ਲੰਮਾਈ], MD5_CTX *ctx)
{
	ਪੂਰਨ i;

	MD5Pad(ctx);
	ਲਈ (i = 0; i < 4; i++)
		PUT_32_ਦੋਆਧਾਰੀ_ਅੰਕ_LE(digest + i * 4, ctx->state[i]);
	memset(ctx, 0, ਆਕਾਰ(*ctx));
}


/* The four core functions - F1 is optimized somewhat */

/* #define F1(x, y, z) (x & y | ~x & z) */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ F1(x, y, z) (z ^ (x & (y ^ z)))
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ F2(x, y, z) F1(z, x, y)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ F3(x, y, z) (x ^ y ^ z)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ F4(x, y, z) (y ^ (x | ~z))

/* This is the central step in the MD5 algorithm. */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ MD5_ਕਦਮ(f, w, x, y, z, ਅੰਕੜੇ, s) \
	( w += f(x, y, z) + ਅੰਕੜੇ,  w = w<<s | w>>(32-s),  w += x )

/*
 * The core of the MD5 algorithm, this alters an existing MD5 hash to
 * reflect the addition of 16 longwords of new data.  MD5Update blocks
 * the data and converts bytes into longwords for this routine.
 */
ਖਾਲੀ
MD5Transform(u_int32_t state[4], ਅਚਲ u_int8_t ਖੰਡ[MD5_ਖੰਡ_ਲੰਮਾਈ])
{
	u_int32_t a, b, c, d, ਵਿੱਚ[MD5_ਖੰਡ_ਲੰਮਾਈ / 4];

#ਜੇ BYTE_ORDER == LITTLE_ENDIAN
	ਸਮ੍ਰਿਤੀ_ਨਕਲ(ਵਿੱਚ, ਖੰਡ, ਆਕਾਰ(ਵਿੱਚ));
#ਨਹੀਂਤਾਂ
	ਲਈ (a = 0; a < MD5_ਖੰਡ_ਲੰਮਾਈ / 4; a++) {
		ਵਿੱਚ[a] = (u_int32_t)(
		    (u_int32_t)(ਖੰਡ[a * 4 + 0]) |
		    (u_int32_t)(ਖੰਡ[a * 4 + 1]) <<  8 |
		    (u_int32_t)(ਖੰਡ[a * 4 + 2]) << 16 |
		    (u_int32_t)(ਖੰਡ[a * 4 + 3]) << 24);
	}
#ਜੇ_ਅੰਤ

	a = state[0];
	b = state[1];
	c = state[2];
	d = state[3];

	MD5_ਕਦਮ(F1, a, b, c, d, ਵਿੱਚ[ 0] + 0xd76aa478,  7);
	MD5_ਕਦਮ(F1, d, a, b, c, ਵਿੱਚ[ 1] + 0xe8c7b756, 12);
	MD5_ਕਦਮ(F1, c, d, a, b, ਵਿੱਚ[ 2] + 0x242070db, 17);
	MD5_ਕਦਮ(F1, b, c, d, a, ਵਿੱਚ[ 3] + 0xc1bdceee, 22);
	MD5_ਕਦਮ(F1, a, b, c, d, ਵਿੱਚ[ 4] + 0xf57c0faf,  7);
	MD5_ਕਦਮ(F1, d, a, b, c, ਵਿੱਚ[ 5] + 0x4787c62a, 12);
	MD5_ਕਦਮ(F1, c, d, a, b, ਵਿੱਚ[ 6] + 0xa8304613, 17);
	MD5_ਕਦਮ(F1, b, c, d, a, ਵਿੱਚ[ 7] + 0xfd469501, 22);
	MD5_ਕਦਮ(F1, a, b, c, d, ਵਿੱਚ[ 8] + 0x698098d8,  7);
	MD5_ਕਦਮ(F1, d, a, b, c, ਵਿੱਚ[ 9] + 0x8b44f7af, 12);
	MD5_ਕਦਮ(F1, c, d, a, b, ਵਿੱਚ[10] + 0xffff5bb1, 17);
	MD5_ਕਦਮ(F1, b, c, d, a, ਵਿੱਚ[11] + 0x895cd7be, 22);
	MD5_ਕਦਮ(F1, a, b, c, d, ਵਿੱਚ[12] + 0x6b901122,  7);
	MD5_ਕਦਮ(F1, d, a, b, c, ਵਿੱਚ[13] + 0xfd987193, 12);
	MD5_ਕਦਮ(F1, c, d, a, b, ਵਿੱਚ[14] + 0xa679438e, 17);
	MD5_ਕਦਮ(F1, b, c, d, a, ਵਿੱਚ[15] + 0x49b40821, 22);

	MD5_ਕਦਮ(F2, a, b, c, d, ਵਿੱਚ[ 1] + 0xf61e2562,  5);
	MD5_ਕਦਮ(F2, d, a, b, c, ਵਿੱਚ[ 6] + 0xc040b340,  9);
	MD5_ਕਦਮ(F2, c, d, a, b, ਵਿੱਚ[11] + 0x265e5a51, 14);
	MD5_ਕਦਮ(F2, b, c, d, a, ਵਿੱਚ[ 0] + 0xe9b6c7aa, 20);
	MD5_ਕਦਮ(F2, a, b, c, d, ਵਿੱਚ[ 5] + 0xd62f105d,  5);
	MD5_ਕਦਮ(F2, d, a, b, c, ਵਿੱਚ[10] + 0x02441453,  9);
	MD5_ਕਦਮ(F2, c, d, a, b, ਵਿੱਚ[15] + 0xd8a1e681, 14);
	MD5_ਕਦਮ(F2, b, c, d, a, ਵਿੱਚ[ 4] + 0xe7d3fbc8, 20);
	MD5_ਕਦਮ(F2, a, b, c, d, ਵਿੱਚ[ 9] + 0x21e1cde6,  5);
	MD5_ਕਦਮ(F2, d, a, b, c, ਵਿੱਚ[14] + 0xc33707d6,  9);
	MD5_ਕਦਮ(F2, c, d, a, b, ਵਿੱਚ[ 3] + 0xf4d50d87, 14);
	MD5_ਕਦਮ(F2, b, c, d, a, ਵਿੱਚ[ 8] + 0x455a14ed, 20);
	MD5_ਕਦਮ(F2, a, b, c, d, ਵਿੱਚ[13] + 0xa9e3e905,  5);
	MD5_ਕਦਮ(F2, d, a, b, c, ਵਿੱਚ[ 2] + 0xfcefa3f8,  9);
	MD5_ਕਦਮ(F2, c, d, a, b, ਵਿੱਚ[ 7] + 0x676f02d9, 14);
	MD5_ਕਦਮ(F2, b, c, d, a, ਵਿੱਚ[12] + 0x8d2a4c8a, 20);

	MD5_ਕਦਮ(F3, a, b, c, d, ਵਿੱਚ[ 5] + 0xfffa3942,  4);
	MD5_ਕਦਮ(F3, d, a, b, c, ਵਿੱਚ[ 8] + 0x8771f681, 11);
	MD5_ਕਦਮ(F3, c, d, a, b, ਵਿੱਚ[11] + 0x6d9d6122, 16);
	MD5_ਕਦਮ(F3, b, c, d, a, ਵਿੱਚ[14] + 0xfde5380c, 23);
	MD5_ਕਦਮ(F3, a, b, c, d, ਵਿੱਚ[ 1] + 0xa4beea44,  4);
	MD5_ਕਦਮ(F3, d, a, b, c, ਵਿੱਚ[ 4] + 0x4bdecfa9, 11);
	MD5_ਕਦਮ(F3, c, d, a, b, ਵਿੱਚ[ 7] + 0xf6bb4b60, 16);
	MD5_ਕਦਮ(F3, b, c, d, a, ਵਿੱਚ[10] + 0xbebfbc70, 23);
	MD5_ਕਦਮ(F3, a, b, c, d, ਵਿੱਚ[13] + 0x289b7ec6,  4);
	MD5_ਕਦਮ(F3, d, a, b, c, ਵਿੱਚ[ 0] + 0xeaa127fa, 11);
	MD5_ਕਦਮ(F3, c, d, a, b, ਵਿੱਚ[ 3] + 0xd4ef3085, 16);
	MD5_ਕਦਮ(F3, b, c, d, a, ਵਿੱਚ[ 6] + 0x04881d05, 23);
	MD5_ਕਦਮ(F3, a, b, c, d, ਵਿੱਚ[ 9] + 0xd9d4d039,  4);
	MD5_ਕਦਮ(F3, d, a, b, c, ਵਿੱਚ[12] + 0xe6db99e5, 11);
	MD5_ਕਦਮ(F3, c, d, a, b, ਵਿੱਚ[15] + 0x1fa27cf8, 16);
	MD5_ਕਦਮ(F3, b, c, d, a, ਵਿੱਚ[2 ] + 0xc4ac5665, 23);

	MD5_ਕਦਮ(F4, a, b, c, d, ਵਿੱਚ[ 0] + 0xf4292244,  6);
	MD5_ਕਦਮ(F4, d, a, b, c, ਵਿੱਚ[7 ] + 0x432aff97, 10);
	MD5_ਕਦਮ(F4, c, d, a, b, ਵਿੱਚ[14] + 0xab9423a7, 15);
	MD5_ਕਦਮ(F4, b, c, d, a, ਵਿੱਚ[5 ] + 0xfc93a039, 21);
	MD5_ਕਦਮ(F4, a, b, c, d, ਵਿੱਚ[12] + 0x655b59c3,  6);
	MD5_ਕਦਮ(F4, d, a, b, c, ਵਿੱਚ[3 ] + 0x8f0ccc92, 10);
	MD5_ਕਦਮ(F4, c, d, a, b, ਵਿੱਚ[10] + 0xffeff47d, 15);
	MD5_ਕਦਮ(F4, b, c, d, a, ਵਿੱਚ[1 ] + 0x85845dd1, 21);
	MD5_ਕਦਮ(F4, a, b, c, d, ਵਿੱਚ[8 ] + 0x6fa87e4f,  6);
	MD5_ਕਦਮ(F4, d, a, b, c, ਵਿੱਚ[15] + 0xfe2ce6e0, 10);
	MD5_ਕਦਮ(F4, c, d, a, b, ਵਿੱਚ[6 ] + 0xa3014314, 15);
	MD5_ਕਦਮ(F4, b, c, d, a, ਵਿੱਚ[13] + 0x4e0811a1, 21);
	MD5_ਕਦਮ(F4, a, b, c, d, ਵਿੱਚ[4 ] + 0xf7537e82,  6);
	MD5_ਕਦਮ(F4, d, a, b, c, ਵਿੱਚ[11] + 0xbd3af235, 10);
	MD5_ਕਦਮ(F4, c, d, a, b, ਵਿੱਚ[2 ] + 0x2ad7d2bb, 15);
	MD5_ਕਦਮ(F4, b, c, d, a, ਵਿੱਚ[9 ] + 0xeb86d391, 21);

	state[0] += a;
	state[1] += b;
	state[2] += c;
	state[3] += d;
}
#ਜੇ_ਅੰਤ /* !WITH_OPENSSL */
