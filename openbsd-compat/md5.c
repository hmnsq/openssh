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

#अन्तर्भाव "includes.h"

#यदि_अपरिभाषितम् WITH_OPENSSL

#अन्तर्भाव <sys/types.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव "md5.h"

#परिभाषय PUT_64BIT_LE(cp, मानम्) कुरु {					\
	(cp)[7] = (मानम्) >> 56;					\
	(cp)[6] = (मानम्) >> 48;					\
	(cp)[5] = (मानम्) >> 40;					\
	(cp)[4] = (मानम्) >> 32;					\
	(cp)[3] = (मानम्) >> 24;					\
	(cp)[2] = (मानम्) >> 16;					\
	(cp)[1] = (मानम्) >> 8;						\
	(cp)[0] = (मानम्); } यावत् (0)

#परिभाषय PUT_32BIT_LE(cp, मानम्) कुरु {					\
	(cp)[3] = (मानम्) >> 24;					\
	(cp)[2] = (मानम्) >> 16;					\
	(cp)[1] = (मानम्) >> 8;						\
	(cp)[0] = (मानम्); } यावत् (0)

स्थिर u_int8_t PADDING[MD5_खण्डम्_दीर्घता] = {
	0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

/*
 * Start MD5 accumulation.  Set bit count to 0 and buffer to mysterious
 * initialization constants.
 */
शून्य
MD5Init(MD5_CTX *ctx)
{
	ctx->गणनम् = 0;
	ctx->state[0] = 0x67452301;
	ctx->state[1] = 0xefcdab89;
	ctx->state[2] = 0x98badcfe;
	ctx->state[3] = 0x10325476;
}

/*
 * Update context to reflect the concatenation of another buffer full
 * of bytes.
 */
शून्य
MD5Update(MD5_CTX *ctx, ध्रुव अचिह्नित वर्ण *निवेशः, आकार_t len)
{
	आकार_t have, need;

	/* Check how many bytes we already have and how many more we need. */
	have = (आकार_t)((ctx->गणनम् >> 3) & (MD5_खण्डम्_दीर्घता - 1));
	need = MD5_खण्डम्_दीर्घता - have;

	/* Update bitcount */
	ctx->गणनम् += (u_int64_t)len << 3;

	यदि (len >= need) {
		यदि (have != 0) {
			स्मृतिं_प्रतिलिख(ctx->बफर + have, निवेशः, need);
			MD5Transform(ctx->state, ctx->बफर);
			निवेशः += need;
			len -= need;
			have = 0;
		}

		/* Process data in MD5_BLOCK_LENGTH-byte chunks. */
		यावत् (len >= MD5_खण्डम्_दीर्घता) {
			MD5Transform(ctx->state, निवेशः);
			निवेशः += MD5_खण्डम्_दीर्घता;
			len -= MD5_खण्डम्_दीर्घता;
		}
	}

	/* Handle any remaining bytes of data. */
	यदि (len != 0)
		स्मृतिं_प्रतिलिख(ctx->बफर + have, निवेशः, len);
}

/*
 * Pad pad to 64-byte boundary with the bit pattern
 * 1 0* (64-bit count of bits processed, MSB-first)
 */
शून्य
MD5Pad(MD5_CTX *ctx)
{
	u_int8_t गणनम्[8];
	आकार_t padlen;

	/* Convert count to 8 bytes in little endian order. */
	PUT_64BIT_LE(गणनम्, ctx->गणनम्);

	/* Pad out to 56 mod 64. */
	padlen = MD5_खण्डम्_दीर्घता -
	    ((ctx->गणनम् >> 3) & (MD5_खण्डम्_दीर्घता - 1));
	यदि (padlen < 1 + 8)
		padlen += MD5_खण्डम्_दीर्घता;
	MD5Update(ctx, PADDING, padlen - 8);		/* padlen - 8 <= 64 */
	MD5Update(ctx, गणनम्, 8);
}

/*
 * Final wrapup--call MD5Pad, fill in digest and zero out ctx.
 */
शून्य
MD5Final(अचिह्नित वर्ण digest[MD5_DIGEST_दीर्घता], MD5_CTX *ctx)
{
	पूर्णाङ्क i;

	MD5Pad(ctx);
	प्रति (i = 0; i < 4; i++)
		PUT_32BIT_LE(digest + i * 4, ctx->state[i]);
	स्मृतिं_पूरय(ctx, 0, परिमाण(*ctx));
}


/* The four core functions - F1 is optimized somewhat */

/* #define F1(x, y, z) (x & y | ~x & z) */
#परिभाषय F1(x, y, z) (z ^ (x & (y ^ z)))
#परिभाषय F2(x, y, z) F1(z, x, y)
#परिभाषय F3(x, y, z) (x ^ y ^ z)
#परिभाषय F4(x, y, z) (y ^ (x | ~z))

/* This is the central step in the MD5 algorithm. */
#परिभाषय MD5_चरणः(f, w, x, y, z, दत्त, s) \
	( w += f(x, y, z) + दत्त,  w = w<<s | w>>(32-s),  w += x )

/*
 * The core of the MD5 algorithm, this alters an existing MD5 hash to
 * reflect the addition of 16 longwords of new data.  MD5Update blocks
 * the data and converts bytes into longwords for this routine.
 */
शून्य
MD5Transform(u_int32_t state[4], ध्रुव u_int8_t खण्डम्[MD5_खण्डम्_दीर्घता])
{
	u_int32_t a, b, c, d, अन्तर्[MD5_खण्डम्_दीर्घता / 4];

#यदि BYTE_ORDER == LITTLE_ENDIAN
	स्मृतिं_प्रतिलिख(अन्तर्, खण्डम्, परिमाण(अन्तर्));
#अन्यथा
	प्रति (a = 0; a < MD5_खण्डम्_दीर्घता / 4; a++) {
		अन्तर्[a] = (u_int32_t)(
		    (u_int32_t)(खण्डम्[a * 4 + 0]) |
		    (u_int32_t)(खण्डम्[a * 4 + 1]) <<  8 |
		    (u_int32_t)(खण्डम्[a * 4 + 2]) << 16 |
		    (u_int32_t)(खण्डम्[a * 4 + 3]) << 24);
	}
#यदि_अन्तः

	a = state[0];
	b = state[1];
	c = state[2];
	d = state[3];

	MD5_चरणः(F1, a, b, c, d, अन्तर्[ 0] + 0xd76aa478,  7);
	MD5_चरणः(F1, d, a, b, c, अन्तर्[ 1] + 0xe8c7b756, 12);
	MD5_चरणः(F1, c, d, a, b, अन्तर्[ 2] + 0x242070db, 17);
	MD5_चरणः(F1, b, c, d, a, अन्तर्[ 3] + 0xc1bdceee, 22);
	MD5_चरणः(F1, a, b, c, d, अन्तर्[ 4] + 0xf57c0faf,  7);
	MD5_चरणः(F1, d, a, b, c, अन्तर्[ 5] + 0x4787c62a, 12);
	MD5_चरणः(F1, c, d, a, b, अन्तर्[ 6] + 0xa8304613, 17);
	MD5_चरणः(F1, b, c, d, a, अन्तर्[ 7] + 0xfd469501, 22);
	MD5_चरणः(F1, a, b, c, d, अन्तर्[ 8] + 0x698098d8,  7);
	MD5_चरणः(F1, d, a, b, c, अन्तर्[ 9] + 0x8b44f7af, 12);
	MD5_चरणः(F1, c, d, a, b, अन्तर्[10] + 0xffff5bb1, 17);
	MD5_चरणः(F1, b, c, d, a, अन्तर्[11] + 0x895cd7be, 22);
	MD5_चरणः(F1, a, b, c, d, अन्तर्[12] + 0x6b901122,  7);
	MD5_चरणः(F1, d, a, b, c, अन्तर्[13] + 0xfd987193, 12);
	MD5_चरणः(F1, c, d, a, b, अन्तर्[14] + 0xa679438e, 17);
	MD5_चरणः(F1, b, c, d, a, अन्तर्[15] + 0x49b40821, 22);

	MD5_चरणः(F2, a, b, c, d, अन्तर्[ 1] + 0xf61e2562,  5);
	MD5_चरणः(F2, d, a, b, c, अन्तर्[ 6] + 0xc040b340,  9);
	MD5_चरणः(F2, c, d, a, b, अन्तर्[11] + 0x265e5a51, 14);
	MD5_चरणः(F2, b, c, d, a, अन्तर्[ 0] + 0xe9b6c7aa, 20);
	MD5_चरणः(F2, a, b, c, d, अन्तर्[ 5] + 0xd62f105d,  5);
	MD5_चरणः(F2, d, a, b, c, अन्तर्[10] + 0x02441453,  9);
	MD5_चरणः(F2, c, d, a, b, अन्तर्[15] + 0xd8a1e681, 14);
	MD5_चरणः(F2, b, c, d, a, अन्तर्[ 4] + 0xe7d3fbc8, 20);
	MD5_चरणः(F2, a, b, c, d, अन्तर्[ 9] + 0x21e1cde6,  5);
	MD5_चरणः(F2, d, a, b, c, अन्तर्[14] + 0xc33707d6,  9);
	MD5_चरणः(F2, c, d, a, b, अन्तर्[ 3] + 0xf4d50d87, 14);
	MD5_चरणः(F2, b, c, d, a, अन्तर्[ 8] + 0x455a14ed, 20);
	MD5_चरणः(F2, a, b, c, d, अन्तर्[13] + 0xa9e3e905,  5);
	MD5_चरणः(F2, d, a, b, c, अन्तर्[ 2] + 0xfcefa3f8,  9);
	MD5_चरणः(F2, c, d, a, b, अन्तर्[ 7] + 0x676f02d9, 14);
	MD5_चरणः(F2, b, c, d, a, अन्तर्[12] + 0x8d2a4c8a, 20);

	MD5_चरणः(F3, a, b, c, d, अन्तर्[ 5] + 0xfffa3942,  4);
	MD5_चरणः(F3, d, a, b, c, अन्तर्[ 8] + 0x8771f681, 11);
	MD5_चरणः(F3, c, d, a, b, अन्तर्[11] + 0x6d9d6122, 16);
	MD5_चरणः(F3, b, c, d, a, अन्तर्[14] + 0xfde5380c, 23);
	MD5_चरणः(F3, a, b, c, d, अन्तर्[ 1] + 0xa4beea44,  4);
	MD5_चरणः(F3, d, a, b, c, अन्तर्[ 4] + 0x4bdecfa9, 11);
	MD5_चरणः(F3, c, d, a, b, अन्तर्[ 7] + 0xf6bb4b60, 16);
	MD5_चरणः(F3, b, c, d, a, अन्तर्[10] + 0xbebfbc70, 23);
	MD5_चरणः(F3, a, b, c, d, अन्तर्[13] + 0x289b7ec6,  4);
	MD5_चरणः(F3, d, a, b, c, अन्तर्[ 0] + 0xeaa127fa, 11);
	MD5_चरणः(F3, c, d, a, b, अन्तर्[ 3] + 0xd4ef3085, 16);
	MD5_चरणः(F3, b, c, d, a, अन्तर्[ 6] + 0x04881d05, 23);
	MD5_चरणः(F3, a, b, c, d, अन्तर्[ 9] + 0xd9d4d039,  4);
	MD5_चरणः(F3, d, a, b, c, अन्तर्[12] + 0xe6db99e5, 11);
	MD5_चरणः(F3, c, d, a, b, अन्तर्[15] + 0x1fa27cf8, 16);
	MD5_चरणः(F3, b, c, d, a, अन्तर्[2 ] + 0xc4ac5665, 23);

	MD5_चरणः(F4, a, b, c, d, अन्तर्[ 0] + 0xf4292244,  6);
	MD5_चरणः(F4, d, a, b, c, अन्तर्[7 ] + 0x432aff97, 10);
	MD5_चरणः(F4, c, d, a, b, अन्तर्[14] + 0xab9423a7, 15);
	MD5_चरणः(F4, b, c, d, a, अन्तर्[5 ] + 0xfc93a039, 21);
	MD5_चरणः(F4, a, b, c, d, अन्तर्[12] + 0x655b59c3,  6);
	MD5_चरणः(F4, d, a, b, c, अन्तर्[3 ] + 0x8f0ccc92, 10);
	MD5_चरणः(F4, c, d, a, b, अन्तर्[10] + 0xffeff47d, 15);
	MD5_चरणः(F4, b, c, d, a, अन्तर्[1 ] + 0x85845dd1, 21);
	MD5_चरणः(F4, a, b, c, d, अन्तर्[8 ] + 0x6fa87e4f,  6);
	MD5_चरणः(F4, d, a, b, c, अन्तर्[15] + 0xfe2ce6e0, 10);
	MD5_चरणः(F4, c, d, a, b, अन्तर्[6 ] + 0xa3014314, 15);
	MD5_चरणः(F4, b, c, d, a, अन्तर्[13] + 0x4e0811a1, 21);
	MD5_चरणः(F4, a, b, c, d, अन्तर्[4 ] + 0xf7537e82,  6);
	MD5_चरणः(F4, d, a, b, c, अन्तर्[11] + 0xbd3af235, 10);
	MD5_चरणः(F4, c, d, a, b, अन्तर्[2 ] + 0x2ad7d2bb, 15);
	MD5_चरणः(F4, b, c, d, a, अन्तर्[9 ] + 0xeb86d391, 21);

	state[0] += a;
	state[1] += b;
	state[2] += c;
	state[3] += d;
}
#यदि_अन्तः /* !WITH_OPENSSL */
