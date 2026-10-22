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

#ضمن "includes.h"

#اگر_تعریف_نشده WITH_OPENSSL

#ضمن <sys/types.h>
#ضمن <string.h>
#ضمن "md5.h"

#تعریف_کن PUT_64_بیت_LE(cp, مقدار) افعل {					\
	(cp)[7] = (مقدار) >> 56;					\
	(cp)[6] = (مقدار) >> 48;					\
	(cp)[5] = (مقدار) >> 40;					\
	(cp)[4] = (مقدار) >> 32;					\
	(cp)[3] = (مقدار) >> 24;					\
	(cp)[2] = (مقدار) >> 16;					\
	(cp)[1] = (مقدار) >> 8;						\
	(cp)[0] = (مقدار); } طالما (0)

#تعریف_کن PUT_32_بیت_LE(cp, مقدار) افعل {					\
	(cp)[3] = (مقدار) >> 24;					\
	(cp)[2] = (مقدار) >> 16;					\
	(cp)[1] = (مقدار) >> 8;						\
	(cp)[0] = (مقدار); } طالما (0)

ساكن u_int8_t PADDING[MD5_بلوک_درازی] = {
	0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

/*
 * Start MD5 accumulation.  Set bit count to 0 and buffer to mysterious
 * initialization constants.
 */
فراغ
MD5Init(MD5_CTX *ctx)
{
	ctx->شمار = 0;
	ctx->state[0] = 0x67452301;
	ctx->state[1] = 0xefcdab89;
	ctx->state[2] = 0x98badcfe;
	ctx->state[3] = 0x10325476;
}

/*
 * Update context to reflect the concatenation of another buffer full
 * of bytes.
 */
فراغ
MD5Update(MD5_CTX *ctx, ثابت بیعلامت حرف *درون_داد, اندازه_t len)
{
	اندازه_t have, need;

	/* Check how many bytes we already have and how many more we need. */
	have = (اندازه_t)((ctx->شمار >> 3) & (MD5_بلوک_درازی - 1));
	need = MD5_بلوک_درازی - have;

	/* Update bitcount */
	ctx->شمار += (u_int64_t)len << 3;

	إذا (len >= need) {
		إذا (have != 0) {
			کپی_حافظه(ctx->میانگیر + have, درون_داد, need);
			MD5Transform(ctx->state, ctx->میانگیر);
			درون_داد += need;
			len -= need;
			have = 0;
		}

		/* Process data in MD5_BLOCK_LENGTH-byte chunks. */
		طالما (len >= MD5_بلوک_درازی) {
			MD5Transform(ctx->state, درون_داد);
			درون_داد += MD5_بلوک_درازی;
			len -= MD5_بلوک_درازی;
		}
	}

	/* Handle any remaining bytes of data. */
	إذا (len != 0)
		کپی_حافظه(ctx->میانگیر + have, درون_داد, len);
}

/*
 * Pad pad to 64-byte boundary with the bit pattern
 * 1 0* (64-bit count of bits processed, MSB-first)
 */
فراغ
MD5Pad(MD5_CTX *ctx)
{
	u_int8_t شمار[8];
	اندازه_t padlen;

	/* Convert count to 8 bytes in little endian order. */
	PUT_64_بیت_LE(شمار, ctx->شمار);

	/* Pad out to 56 mod 64. */
	padlen = MD5_بلوک_درازی -
	    ((ctx->شمار >> 3) & (MD5_بلوک_درازی - 1));
	إذا (padlen < 1 + 8)
		padlen += MD5_بلوک_درازی;
	MD5Update(ctx, PADDING, padlen - 8);		/* padlen - 8 <= 64 */
	MD5Update(ctx, شمار, 8);
}

/*
 * Final wrapup--call MD5Pad, fill in digest and zero out ctx.
 */
فراغ
MD5Final(بیعلامت حرف digest[MD5_DIGEST_درازی], MD5_CTX *ctx)
{
	صحيح i;

	MD5Pad(ctx);
	لكل (i = 0; i < 4; i++)
		PUT_32_بیت_LE(digest + i * 4, ctx->state[i]);
	memset(ctx, 0, حجم(*ctx));
}


/* The four core functions - F1 is optimized somewhat */

/* #define F1(x, y, z) (x & y | ~x & z) */
#تعریف_کن F1(x, y, z) (z ^ (x & (y ^ z)))
#تعریف_کن F2(x, y, z) F1(z, x, y)
#تعریف_کن F3(x, y, z) (x ^ y ^ z)
#تعریف_کن F4(x, y, z) (y ^ (x | ~z))

/* This is the central step in the MD5 algorithm. */
#تعریف_کن MD5_گام(f, w, x, y, z, داده, s) \
	( w += f(x, y, z) + داده,  w = w<<s | w>>(32-s),  w += x )

/*
 * The core of the MD5 algorithm, this alters an existing MD5 hash to
 * reflect the addition of 16 longwords of new data.  MD5Update blocks
 * the data and converts bytes into longwords for this routine.
 */
فراغ
MD5Transform(u_int32_t state[4], ثابت u_int8_t بلوک[MD5_بلوک_درازی])
{
	u_int32_t a, b, c, d, درون[MD5_بلوک_درازی / 4];

#إذا BYTE_ORDER == LITTLE_ENDIAN
	کپی_حافظه(درون, بلوک, حجم(درون));
#وإلا
	لكل (a = 0; a < MD5_بلوک_درازی / 4; a++) {
		درون[a] = (u_int32_t)(
		    (u_int32_t)(بلوک[a * 4 + 0]) |
		    (u_int32_t)(بلوک[a * 4 + 1]) <<  8 |
		    (u_int32_t)(بلوک[a * 4 + 2]) << 16 |
		    (u_int32_t)(بلوک[a * 4 + 3]) << 24);
	}
#پایان_اگر

	a = state[0];
	b = state[1];
	c = state[2];
	d = state[3];

	MD5_گام(F1, a, b, c, d, درون[ 0] + 0xd76aa478,  7);
	MD5_گام(F1, d, a, b, c, درون[ 1] + 0xe8c7b756, 12);
	MD5_گام(F1, c, d, a, b, درون[ 2] + 0x242070db, 17);
	MD5_گام(F1, b, c, d, a, درون[ 3] + 0xc1bdceee, 22);
	MD5_گام(F1, a, b, c, d, درون[ 4] + 0xf57c0faf,  7);
	MD5_گام(F1, d, a, b, c, درون[ 5] + 0x4787c62a, 12);
	MD5_گام(F1, c, d, a, b, درون[ 6] + 0xa8304613, 17);
	MD5_گام(F1, b, c, d, a, درون[ 7] + 0xfd469501, 22);
	MD5_گام(F1, a, b, c, d, درون[ 8] + 0x698098d8,  7);
	MD5_گام(F1, d, a, b, c, درون[ 9] + 0x8b44f7af, 12);
	MD5_گام(F1, c, d, a, b, درون[10] + 0xffff5bb1, 17);
	MD5_گام(F1, b, c, d, a, درون[11] + 0x895cd7be, 22);
	MD5_گام(F1, a, b, c, d, درون[12] + 0x6b901122,  7);
	MD5_گام(F1, d, a, b, c, درون[13] + 0xfd987193, 12);
	MD5_گام(F1, c, d, a, b, درون[14] + 0xa679438e, 17);
	MD5_گام(F1, b, c, d, a, درون[15] + 0x49b40821, 22);

	MD5_گام(F2, a, b, c, d, درون[ 1] + 0xf61e2562,  5);
	MD5_گام(F2, d, a, b, c, درون[ 6] + 0xc040b340,  9);
	MD5_گام(F2, c, d, a, b, درون[11] + 0x265e5a51, 14);
	MD5_گام(F2, b, c, d, a, درون[ 0] + 0xe9b6c7aa, 20);
	MD5_گام(F2, a, b, c, d, درون[ 5] + 0xd62f105d,  5);
	MD5_گام(F2, d, a, b, c, درون[10] + 0x02441453,  9);
	MD5_گام(F2, c, d, a, b, درون[15] + 0xd8a1e681, 14);
	MD5_گام(F2, b, c, d, a, درون[ 4] + 0xe7d3fbc8, 20);
	MD5_گام(F2, a, b, c, d, درون[ 9] + 0x21e1cde6,  5);
	MD5_گام(F2, d, a, b, c, درون[14] + 0xc33707d6,  9);
	MD5_گام(F2, c, d, a, b, درون[ 3] + 0xf4d50d87, 14);
	MD5_گام(F2, b, c, d, a, درون[ 8] + 0x455a14ed, 20);
	MD5_گام(F2, a, b, c, d, درون[13] + 0xa9e3e905,  5);
	MD5_گام(F2, d, a, b, c, درون[ 2] + 0xfcefa3f8,  9);
	MD5_گام(F2, c, d, a, b, درون[ 7] + 0x676f02d9, 14);
	MD5_گام(F2, b, c, d, a, درون[12] + 0x8d2a4c8a, 20);

	MD5_گام(F3, a, b, c, d, درون[ 5] + 0xfffa3942,  4);
	MD5_گام(F3, d, a, b, c, درون[ 8] + 0x8771f681, 11);
	MD5_گام(F3, c, d, a, b, درون[11] + 0x6d9d6122, 16);
	MD5_گام(F3, b, c, d, a, درون[14] + 0xfde5380c, 23);
	MD5_گام(F3, a, b, c, d, درون[ 1] + 0xa4beea44,  4);
	MD5_گام(F3, d, a, b, c, درون[ 4] + 0x4bdecfa9, 11);
	MD5_گام(F3, c, d, a, b, درون[ 7] + 0xf6bb4b60, 16);
	MD5_گام(F3, b, c, d, a, درون[10] + 0xbebfbc70, 23);
	MD5_گام(F3, a, b, c, d, درون[13] + 0x289b7ec6,  4);
	MD5_گام(F3, d, a, b, c, درون[ 0] + 0xeaa127fa, 11);
	MD5_گام(F3, c, d, a, b, درون[ 3] + 0xd4ef3085, 16);
	MD5_گام(F3, b, c, d, a, درون[ 6] + 0x04881d05, 23);
	MD5_گام(F3, a, b, c, d, درون[ 9] + 0xd9d4d039,  4);
	MD5_گام(F3, d, a, b, c, درون[12] + 0xe6db99e5, 11);
	MD5_گام(F3, c, d, a, b, درون[15] + 0x1fa27cf8, 16);
	MD5_گام(F3, b, c, d, a, درون[2 ] + 0xc4ac5665, 23);

	MD5_گام(F4, a, b, c, d, درون[ 0] + 0xf4292244,  6);
	MD5_گام(F4, d, a, b, c, درون[7 ] + 0x432aff97, 10);
	MD5_گام(F4, c, d, a, b, درون[14] + 0xab9423a7, 15);
	MD5_گام(F4, b, c, d, a, درون[5 ] + 0xfc93a039, 21);
	MD5_گام(F4, a, b, c, d, درون[12] + 0x655b59c3,  6);
	MD5_گام(F4, d, a, b, c, درون[3 ] + 0x8f0ccc92, 10);
	MD5_گام(F4, c, d, a, b, درون[10] + 0xffeff47d, 15);
	MD5_گام(F4, b, c, d, a, درون[1 ] + 0x85845dd1, 21);
	MD5_گام(F4, a, b, c, d, درون[8 ] + 0x6fa87e4f,  6);
	MD5_گام(F4, d, a, b, c, درون[15] + 0xfe2ce6e0, 10);
	MD5_گام(F4, c, d, a, b, درون[6 ] + 0xa3014314, 15);
	MD5_گام(F4, b, c, d, a, درون[13] + 0x4e0811a1, 21);
	MD5_گام(F4, a, b, c, d, درون[4 ] + 0xf7537e82,  6);
	MD5_گام(F4, d, a, b, c, درون[11] + 0xbd3af235, 10);
	MD5_گام(F4, c, d, a, b, درون[2 ] + 0x2ad7d2bb, 15);
	MD5_گام(F4, b, c, d, a, درون[9 ] + 0xeb86d391, 21);

	state[0] += a;
	state[1] += b;
	state[2] += c;
	state[3] += d;
}
#پایان_اگر /* !WITH_OPENSSL */
