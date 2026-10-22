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

#جيڪڏهن_وصف_نه_ٿيل _MD5_H_
#وصف_ڪريو _MD5_H_

#جيڪڏهن_وصف_نه_ٿيل WITH_OPENSSL

#وصف_ڪريو	MD5_بلاڪ_ڊيگهائي		64
#وصف_ڪريو	MD5_DIGEST_ڊيگهائي		16
#وصف_ڪريو	MD5_DIGEST_STRING_ڊيگهائي	(MD5_DIGEST_ڊيگهائي * 2 + 1)

تعريفنوع بنية MD5Context {
	u_int32_t state[4];			/* state */
	u_int64_t ڳڻپ;			/* number of bits, mod 2^64 */
	u_int8_t بفر[MD5_بلاڪ_ڊيگهائي];	/* input buffer */
} MD5_CTX;

فراغ	 MD5Init(MD5_CTX *);
فراغ	 MD5Update(MD5_CTX *, ثابت u_int8_t *, سائيز_t)
		__attribute__((__bounded__(__string__,2,3)));
فراغ	 MD5Pad(MD5_CTX *);
فراغ	 MD5Final(u_int8_t [MD5_DIGEST_ڊيگهائي], MD5_CTX *)
		__attribute__((__bounded__(__minbytes__,1,MD5_DIGEST_ڊيگهائي)));
فراغ	 MD5Transform(u_int32_t [4], ثابت u_int8_t [MD5_بلاڪ_ڊيگهائي])
		__attribute__((__bounded__(__minbytes__,1,4)))
		__attribute__((__bounded__(__minbytes__,2,MD5_بلاڪ_ڊيگهائي)));
حرف	*MD5_پڇاڙي(MD5_CTX *, حرف *)
		__attribute__((__bounded__(__minbytes__,2,MD5_DIGEST_STRING_ڊيگهائي)));
حرف	*MD5File(ثابت حرف *, حرف *)
		__attribute__((__bounded__(__minbytes__,2,MD5_DIGEST_STRING_ڊيگهائي)));
حرف	*MD5FileChunk(ثابت حرف *, حرف *, off_t, off_t)
		__attribute__((__bounded__(__minbytes__,2,MD5_DIGEST_STRING_ڊيگهائي)));
حرف	*MD5_معلومات(ثابت u_int8_t *, سائيز_t, حرف *)
		__attribute__((__bounded__(__string__,1,2)))
		__attribute__((__bounded__(__minbytes__,3,MD5_DIGEST_STRING_ڊيگهائي)));

#جيڪڏهن_پورو /* !WITH_OPENSSL */

#جيڪڏهن_پورو /* _MD5_H_ */
