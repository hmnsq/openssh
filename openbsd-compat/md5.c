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

#समावेश "includes.h"

#अगर_अघोषित WITH_OPENSSL

#समावेश <sys/types.h>
#समावेश <string.h>
#समावेश "md5.h"

#घोषणा PUT_64BIT_LE(cp, मूल्य) करो {					\
	(cp)[7] = (मूल्य) >> 56;					\
	(cp)[6] = (मूल्य) >> 48;					\
	(cp)[5] = (मूल्य) >> 40;					\
	(cp)[4] = (मूल्य) >> 32;					\
	(cp)[3] = (मूल्य) >> 24;					\
	(cp)[2] = (मूल्य) >> 16;					\
	(cp)[1] = (मूल्य) >> 8;						\
	(cp)[0] = (मूल्य); } जबतक (0)

#घोषणा PUT_32BIT_LE(cp, मूल्य) करो {					\
	(cp)[3] = (मूल्य) >> 24;					\
	(cp)[2] = (मूल्य) >> 16;					\
	(cp)[1] = (मूल्य) >> 8;						\
	(cp)[0] = (मूल्य); } जबतक (0)

अटल u_int8_t PADDING[MD5_BLOCK_लंबाई] = {
	0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

/*
 * Start MD5 accumulation.  Set bit count to 0 and buffer to mysterious
 * initialization constants.
 */
व्योम
MD5Init(MD5_CTX *ctx)
{
	ctx->गिनती = 0;
	ctx->state[0] = 0x67452301;
	ctx->state[1] = 0xefcdab89;
	ctx->state[2] = 0x98badcfe;
	ctx->state[3] = 0x10325476;
}

/*
 * Update context to reflect the concatenation of another buffer full
 * of bytes.
 */
व्योम
MD5Update(MD5_CTX *ctx, स्थिर अचिन्हित अक्षर *निवेश, माप_प्रकार len)
{
	माप_प्रकार have, need;

	/* Check how many bytes we already have and how many more we need. */
	have = (माप_प्रकार)((ctx->गिनती >> 3) & (MD5_BLOCK_लंबाई - 1));
	need = MD5_BLOCK_लंबाई - have;

	/* Update bitcount */
	ctx->गिनती += (u_int64_t)len << 3;

	अगर (len >= need) {
		अगर (have != 0) {
			स_नकल(ctx->बफर + have, निवेश, need);
			MD5Transform(ctx->state, ctx->बफर);
			निवेश += need;
			len -= need;
			have = 0;
		}

		/* Process data in MD5_BLOCK_LENGTH-byte chunks. */
		जबतक (len >= MD5_BLOCK_लंबाई) {
			MD5Transform(ctx->state, निवेश);
			निवेश += MD5_BLOCK_लंबाई;
			len -= MD5_BLOCK_लंबाई;
		}
	}

	/* Handle any remaining bytes of data. */
	अगर (len != 0)
		स_नकल(ctx->बफर + have, निवेश, len);
}

/*
 * Pad pad to 64-byte boundary with the bit pattern
 * 1 0* (64-bit count of bits processed, MSB-first)
 */
व्योम
MD5Pad(MD5_CTX *ctx)
{
	u_int8_t गिनती[8];
	माप_प्रकार padlen;

	/* Convert count to 8 bytes in little endian order. */
	PUT_64BIT_LE(गिनती, ctx->गिनती);

	/* Pad out to 56 mod 64. */
	padlen = MD5_BLOCK_लंबाई -
	    ((ctx->गिनती >> 3) & (MD5_BLOCK_लंबाई - 1));
	अगर (padlen < 1 + 8)
		padlen += MD5_BLOCK_लंबाई;
	MD5Update(ctx, PADDING, padlen - 8);		/* padlen - 8 <= 64 */
	MD5Update(ctx, गिनती, 8);
}

/*
 * Final wrapup--call MD5Pad, fill in digest and zero out ctx.
 */
व्योम
MD5Final(अचिन्हित अक्षर digest[MD5_DIGEST_लंबाई], MD5_CTX *ctx)
{
	पूर्णांक i;

	MD5Pad(ctx);
	क्रम (i = 0; i < 4; i++)
		PUT_32BIT_LE(digest + i * 4, ctx->state[i]);
	स_रखो(ctx, 0, माप(*ctx));
}


/* The four core functions - F1 is optimized somewhat */

/* #define F1(x, y, z) (x & y | ~x & z) */
#घोषणा F1(x, y, z) (z ^ (x & (y ^ z)))
#घोषणा F2(x, y, z) F1(z, x, y)
#घोषणा F3(x, y, z) (x ^ y ^ z)
#घोषणा F4(x, y, z) (y ^ (x | ~z))

/* This is the central step in the MD5 algorithm. */
#घोषणा MD5STEP(f, w, x, y, z, तथ्य, s) \
	( w += f(x, y, z) + तथ्य,  w = w<<s | w>>(32-s),  w += x )

/*
 * The core of the MD5 algorithm, this alters an existing MD5 hash to
 * reflect the addition of 16 longwords of new data.  MD5Update blocks
 * the data and converts bytes into longwords for this routine.
 */
व्योम
MD5Transform(u_int32_t state[4], स्थिर u_int8_t block[MD5_BLOCK_लंबाई])
{
	u_int32_t a, b, c, d, in[MD5_BLOCK_लंबाई / 4];

#अगर BYTE_ORDER == LITTLE_ENDIAN
	स_नकल(in, block, माप(in));
#अन्यथा
	क्रम (a = 0; a < MD5_BLOCK_लंबाई / 4; a++) {
		in[a] = (u_int32_t)(
		    (u_int32_t)(block[a * 4 + 0]) |
		    (u_int32_t)(block[a * 4 + 1]) <<  8 |
		    (u_int32_t)(block[a * 4 + 2]) << 16 |
		    (u_int32_t)(block[a * 4 + 3]) << 24);
	}
#पूर्ण_अगर

	a = state[0];
	b = state[1];
	c = state[2];
	d = state[3];

	MD5STEP(F1, a, b, c, d, in[ 0] + 0xd76aa478,  7);
	MD5STEP(F1, d, a, b, c, in[ 1] + 0xe8c7b756, 12);
	MD5STEP(F1, c, d, a, b, in[ 2] + 0x242070db, 17);
	MD5STEP(F1, b, c, d, a, in[ 3] + 0xc1bdceee, 22);
	MD5STEP(F1, a, b, c, d, in[ 4] + 0xf57c0faf,  7);
	MD5STEP(F1, d, a, b, c, in[ 5] + 0x4787c62a, 12);
	MD5STEP(F1, c, d, a, b, in[ 6] + 0xa8304613, 17);
	MD5STEP(F1, b, c, d, a, in[ 7] + 0xfd469501, 22);
	MD5STEP(F1, a, b, c, d, in[ 8] + 0x698098d8,  7);
	MD5STEP(F1, d, a, b, c, in[ 9] + 0x8b44f7af, 12);
	MD5STEP(F1, c, d, a, b, in[10] + 0xffff5bb1, 17);
	MD5STEP(F1, b, c, d, a, in[11] + 0x895cd7be, 22);
	MD5STEP(F1, a, b, c, d, in[12] + 0x6b901122,  7);
	MD5STEP(F1, d, a, b, c, in[13] + 0xfd987193, 12);
	MD5STEP(F1, c, d, a, b, in[14] + 0xa679438e, 17);
	MD5STEP(F1, b, c, d, a, in[15] + 0x49b40821, 22);

	MD5STEP(F2, a, b, c, d, in[ 1] + 0xf61e2562,  5);
	MD5STEP(F2, d, a, b, c, in[ 6] + 0xc040b340,  9);
	MD5STEP(F2, c, d, a, b, in[11] + 0x265e5a51, 14);
	MD5STEP(F2, b, c, d, a, in[ 0] + 0xe9b6c7aa, 20);
	MD5STEP(F2, a, b, c, d, in[ 5] + 0xd62f105d,  5);
	MD5STEP(F2, d, a, b, c, in[10] + 0x02441453,  9);
	MD5STEP(F2, c, d, a, b, in[15] + 0xd8a1e681, 14);
	MD5STEP(F2, b, c, d, a, in[ 4] + 0xe7d3fbc8, 20);
	MD5STEP(F2, a, b, c, d, in[ 9] + 0x21e1cde6,  5);
	MD5STEP(F2, d, a, b, c, in[14] + 0xc33707d6,  9);
	MD5STEP(F2, c, d, a, b, in[ 3] + 0xf4d50d87, 14);
	MD5STEP(F2, b, c, d, a, in[ 8] + 0x455a14ed, 20);
	MD5STEP(F2, a, b, c, d, in[13] + 0xa9e3e905,  5);
	MD5STEP(F2, d, a, b, c, in[ 2] + 0xfcefa3f8,  9);
	MD5STEP(F2, c, d, a, b, in[ 7] + 0x676f02d9, 14);
	MD5STEP(F2, b, c, d, a, in[12] + 0x8d2a4c8a, 20);

	MD5STEP(F3, a, b, c, d, in[ 5] + 0xfffa3942,  4);
	MD5STEP(F3, d, a, b, c, in[ 8] + 0x8771f681, 11);
	MD5STEP(F3, c, d, a, b, in[11] + 0x6d9d6122, 16);
	MD5STEP(F3, b, c, d, a, in[14] + 0xfde5380c, 23);
	MD5STEP(F3, a, b, c, d, in[ 1] + 0xa4beea44,  4);
	MD5STEP(F3, d, a, b, c, in[ 4] + 0x4bdecfa9, 11);
	MD5STEP(F3, c, d, a, b, in[ 7] + 0xf6bb4b60, 16);
	MD5STEP(F3, b, c, d, a, in[10] + 0xbebfbc70, 23);
	MD5STEP(F3, a, b, c, d, in[13] + 0x289b7ec6,  4);
	MD5STEP(F3, d, a, b, c, in[ 0] + 0xeaa127fa, 11);
	MD5STEP(F3, c, d, a, b, in[ 3] + 0xd4ef3085, 16);
	MD5STEP(F3, b, c, d, a, in[ 6] + 0x04881d05, 23);
	MD5STEP(F3, a, b, c, d, in[ 9] + 0xd9d4d039,  4);
	MD5STEP(F3, d, a, b, c, in[12] + 0xe6db99e5, 11);
	MD5STEP(F3, c, d, a, b, in[15] + 0x1fa27cf8, 16);
	MD5STEP(F3, b, c, d, a, in[2 ] + 0xc4ac5665, 23);

	MD5STEP(F4, a, b, c, d, in[ 0] + 0xf4292244,  6);
	MD5STEP(F4, d, a, b, c, in[7 ] + 0x432aff97, 10);
	MD5STEP(F4, c, d, a, b, in[14] + 0xab9423a7, 15);
	MD5STEP(F4, b, c, d, a, in[5 ] + 0xfc93a039, 21);
	MD5STEP(F4, a, b, c, d, in[12] + 0x655b59c3,  6);
	MD5STEP(F4, d, a, b, c, in[3 ] + 0x8f0ccc92, 10);
	MD5STEP(F4, c, d, a, b, in[10] + 0xffeff47d, 15);
	MD5STEP(F4, b, c, d, a, in[1 ] + 0x85845dd1, 21);
	MD5STEP(F4, a, b, c, d, in[8 ] + 0x6fa87e4f,  6);
	MD5STEP(F4, d, a, b, c, in[15] + 0xfe2ce6e0, 10);
	MD5STEP(F4, c, d, a, b, in[6 ] + 0xa3014314, 15);
	MD5STEP(F4, b, c, d, a, in[13] + 0x4e0811a1, 21);
	MD5STEP(F4, a, b, c, d, in[4 ] + 0xf7537e82,  6);
	MD5STEP(F4, d, a, b, c, in[11] + 0xbd3af235, 10);
	MD5STEP(F4, c, d, a, b, in[2 ] + 0x2ad7d2bb, 15);
	MD5STEP(F4, b, c, d, a, in[9 ] + 0xeb86d391, 21);

	state[0] += a;
	state[1] += b;
	state[2] += c;
	state[3] += d;
}
#पूर्ण_अगर /* !WITH_OPENSSL */
