/*	$OpenBSD: md5.h,v 1.17 2012/12/05 23:19:57 deraadt Exp $	*/

/*
 * This code implements the MD5 message-digest algorithm.
 * The algorithm is due to Ron Rivest.  This code was
 * written by Colin Plumb in 1993, no copyright is claimed.
 * This code is in the public domain; do with it what you wish.
 *
 * Equivalent code is available from RSA Data Security, Inc.
 * This code has been tested against that, and is equivalent,
 * except that you don't need to include two pages of legalese
 * with every copy.
 */

#ifndef _MD5_H_
#define _MD5_H_

#ifndef WITH_OPENSSL

#define	MD5_BLOCK_LENGTH		64
#define	MD5_DIGEST_LENGTH		16
#define	MD5_DIGEST_STRING_LENGTH	(MD5_DIGEST_LENGTH * 2 + 1)

வகைவரை கட்டமைப்பு MD5Context {
	u_int32_t state[4];			/* state */
	u_int64_t மொத்தம்;			/* number of bits, mod 2^64 */
	u_int8_t buffer[MD5_BLOCK_LENGTH];	/* input buffer */
} MD5_CTX;

வெறுமை	 MD5Init(MD5_CTX *);
வெறுமை	 MD5Update(MD5_CTX *, மாறிலி u_int8_t *, size_t)
		__attribute__((__bounded__(__string__,2,3)));
வெறுமை	 MD5Pad(MD5_CTX *);
வெறுமை	 MD5Final(u_int8_t [MD5_DIGEST_LENGTH], MD5_CTX *)
		__attribute__((__bounded__(__minbytes__,1,MD5_DIGEST_LENGTH)));
வெறுமை	 MD5Transform(u_int32_t [4], மாறிலி u_int8_t [MD5_BLOCK_LENGTH])
		__attribute__((__bounded__(__minbytes__,1,4)))
		__attribute__((__bounded__(__minbytes__,2,MD5_BLOCK_LENGTH)));
எழுத்து	*MD5End(MD5_CTX *, எழுத்து *)
		__attribute__((__bounded__(__minbytes__,2,MD5_DIGEST_STRING_LENGTH)));
எழுத்து	*MD5File(மாறிலி எழுத்து *, எழுத்து *)
		__attribute__((__bounded__(__minbytes__,2,MD5_DIGEST_STRING_LENGTH)));
எழுத்து	*MD5FileChunk(மாறிலி எழுத்து *, எழுத்து *, off_t, off_t)
		__attribute__((__bounded__(__minbytes__,2,MD5_DIGEST_STRING_LENGTH)));
எழுத்து	*MD5Data(மாறிலி u_int8_t *, size_t, எழுத்து *)
		__attribute__((__bounded__(__string__,1,2)))
		__attribute__((__bounded__(__minbytes__,3,MD5_DIGEST_STRING_LENGTH)));

#endif /* !WITH_OPENSSL */

#endif /* _MD5_H_ */
