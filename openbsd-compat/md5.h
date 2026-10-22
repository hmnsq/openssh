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

#اگر_تعریف_نشده _MD5_H_
#تعریف_کن _MD5_H_

#اگر_تعریف_نشده WITH_OPENSSL

#تعریف_کن	MD5_بلوک_درازی		64
#تعریف_کن	MD5_DIGEST_درازی		16
#تعریف_کن	MD5_DIGEST_STRING_درازی	(MD5_DIGEST_درازی * 2 + 1)

تعريفنوع بنية MD5Context {
	u_int32_t state[4];			/* state */
	u_int64_t شمار;			/* number of bits, mod 2^64 */
	u_int8_t میانگیر[MD5_بلوک_درازی];	/* input buffer */
} MD5_CTX;

فراغ	 MD5Init(MD5_CTX *);
فراغ	 MD5Update(MD5_CTX *, ثابت u_int8_t *, اندازه_t)
		__attribute__((__bounded__(__string__,2,3)));
فراغ	 MD5Pad(MD5_CTX *);
فراغ	 MD5Final(u_int8_t [MD5_DIGEST_درازی], MD5_CTX *)
		__attribute__((__bounded__(__minbytes__,1,MD5_DIGEST_درازی)));
فراغ	 MD5Transform(u_int32_t [4], ثابت u_int8_t [MD5_بلوک_درازی])
		__attribute__((__bounded__(__minbytes__,1,4)))
		__attribute__((__bounded__(__minbytes__,2,MD5_بلوک_درازی)));
حرف	*MD5_انتها(MD5_CTX *, حرف *)
		__attribute__((__bounded__(__minbytes__,2,MD5_DIGEST_STRING_درازی)));
حرف	*MD5File(ثابت حرف *, حرف *)
		__attribute__((__bounded__(__minbytes__,2,MD5_DIGEST_STRING_درازی)));
حرف	*MD5FileChunk(ثابت حرف *, حرف *, off_t, off_t)
		__attribute__((__bounded__(__minbytes__,2,MD5_DIGEST_STRING_درازی)));
حرف	*MD5_داده(ثابت u_int8_t *, اندازه_t, حرف *)
		__attribute__((__bounded__(__string__,1,2)))
		__attribute__((__bounded__(__minbytes__,3,MD5_DIGEST_STRING_درازی)));

#پایان_اگر /* !WITH_OPENSSL */

#پایان_اگر /* _MD5_H_ */
