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

#यदि_अपरिभाषितम् _MD5_H_
#परिभाषय _MD5_H_

#यदि_अपरिभाषितम् WITH_OPENSSL

#परिभाषय	MD5_खण्डम्_दीर्घता		64
#परिभाषय	MD5_DIGEST_दीर्घता		16
#परिभाषय	MD5_DIGEST_STRING_दीर्घता	(MD5_DIGEST_दीर्घता * 2 + 1)

प्रकारनिर्देश संरचना MD5Context {
	u_int32_t state[4];			/* state */
	u_int64_t गणनम्;			/* number of bits, mod 2^64 */
	u_int8_t बफर[MD5_खण्डम्_दीर्घता];	/* input buffer */
} MD5_CTX;

शून्य	 MD5Init(MD5_CTX *);
शून्य	 MD5Update(MD5_CTX *, ध्रुव u_int8_t *, आकार_t)
		__attribute__((__bounded__(__string__,2,3)));
शून्य	 MD5Pad(MD5_CTX *);
शून्य	 MD5Final(u_int8_t [MD5_DIGEST_दीर्घता], MD5_CTX *)
		__attribute__((__bounded__(__minbytes__,1,MD5_DIGEST_दीर्घता)));
शून्य	 MD5Transform(u_int32_t [4], ध्रुव u_int8_t [MD5_खण्डम्_दीर्घता])
		__attribute__((__bounded__(__minbytes__,1,4)))
		__attribute__((__bounded__(__minbytes__,2,MD5_खण्डम्_दीर्घता)));
वर्ण	*MD5_अन्तः(MD5_CTX *, वर्ण *)
		__attribute__((__bounded__(__minbytes__,2,MD5_DIGEST_STRING_दीर्घता)));
वर्ण	*MD5File(ध्रुव वर्ण *, वर्ण *)
		__attribute__((__bounded__(__minbytes__,2,MD5_DIGEST_STRING_दीर्घता)));
वर्ण	*MD5FileChunk(ध्रुव वर्ण *, वर्ण *, off_t, off_t)
		__attribute__((__bounded__(__minbytes__,2,MD5_DIGEST_STRING_दीर्घता)));
वर्ण	*MD5_दत्त(ध्रुव u_int8_t *, आकार_t, वर्ण *)
		__attribute__((__bounded__(__string__,1,2)))
		__attribute__((__bounded__(__minbytes__,3,MD5_DIGEST_STRING_दीर्घता)));

#यदि_अन्तः /* !WITH_OPENSSL */

#यदि_अन्तः /* _MD5_H_ */
