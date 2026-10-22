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

#اگر_غیر_تعریف_شدہ _MD5_H_
#تعریف_کرو _MD5_H_

#اگر_غیر_تعریف_شدہ WITH_OPENSSL

#تعریف_کرو	MD5_بلاک_لمبائی		64
#تعریف_کرو	MD5_DIGEST_لمبائی		16
#تعریف_کرو	MD5_DIGEST_STRING_لمبائی	(MD5_DIGEST_لمبائی * 2 + 1)

قسمتعریف ساخت MD5Context {
	u_int32_t state[4];			/* state */
	u_int64_t گنتی;			/* number of bits, mod 2^64 */
	u_int8_t بفر[MD5_بلاک_لمبائی];	/* input buffer */
} MD5_CTX;

خالی	 MD5Init(MD5_CTX *);
خالی	 MD5Update(MD5_CTX *, ثابت u_int8_t *, سائز_t)
		__attribute__((__bounded__(__string__,2,3)));
خالی	 MD5Pad(MD5_CTX *);
خالی	 MD5Final(u_int8_t [MD5_DIGEST_لمبائی], MD5_CTX *)
		__attribute__((__bounded__(__minbytes__,1,MD5_DIGEST_لمبائی)));
خالی	 MD5Transform(u_int32_t [4], ثابت u_int8_t [MD5_بلاک_لمبائی])
		__attribute__((__bounded__(__minbytes__,1,4)))
		__attribute__((__bounded__(__minbytes__,2,MD5_بلاک_لمبائی)));
حرف	*MD5_انتہا(MD5_CTX *, حرف *)
		__attribute__((__bounded__(__minbytes__,2,MD5_DIGEST_STRING_لمبائی)));
حرف	*MD5File(ثابت حرف *, حرف *)
		__attribute__((__bounded__(__minbytes__,2,MD5_DIGEST_STRING_لمبائی)));
حرف	*MD5FileChunk(ثابت حرف *, حرف *, off_t, off_t)
		__attribute__((__bounded__(__minbytes__,2,MD5_DIGEST_STRING_لمبائی)));
حرف	*MD5_ڈیٹا(ثابت u_int8_t *, سائز_t, حرف *)
		__attribute__((__bounded__(__string__,1,2)))
		__attribute__((__bounded__(__minbytes__,3,MD5_DIGEST_STRING_لمبائی)));

#اگر_ختم /* !WITH_OPENSSL */

#اگر_ختم /* _MD5_H_ */
