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

#define	MD5_BLOCK_দৈর্ঘ্য		64
#define	MD5_DIGEST_দৈর্ঘ্য		16
#define	MD5_DIGEST_STRING_দৈর্ঘ্য	(MD5_DIGEST_দৈর্ঘ্য * 2 + 1)

প্রকারলেখ কাঠামো MD5Context {
	u_int32_t state[4];			/* state */
	u_int64_t গুনতি;			/* number of bits, mod 2^64 */
	u_int8_t বাফার[MD5_BLOCK_দৈর্ঘ্য];	/* input buffer */
} MD5_CTX;

শূন্য	 MD5Init(MD5_CTX *);
শূন্য	 MD5Update(MD5_CTX *, ধ্রুবক u_int8_t *, আকার_t)
		__attribute__((__bounded__(__string__,2,3)));
শূন্য	 MD5Pad(MD5_CTX *);
শূন্য	 MD5Final(u_int8_t [MD5_DIGEST_দৈর্ঘ্য], MD5_CTX *)
		__attribute__((__bounded__(__minbytes__,1,MD5_DIGEST_দৈর্ঘ্য)));
শূন্য	 MD5Transform(u_int32_t [4], ধ্রুবক u_int8_t [MD5_BLOCK_দৈর্ঘ্য])
		__attribute__((__bounded__(__minbytes__,1,4)))
		__attribute__((__bounded__(__minbytes__,2,MD5_BLOCK_দৈর্ঘ্য)));
অক্ষর	*MD5End(MD5_CTX *, অক্ষর *)
		__attribute__((__bounded__(__minbytes__,2,MD5_DIGEST_STRING_দৈর্ঘ্য)));
অক্ষর	*MD5File(ধ্রুবক অক্ষর *, অক্ষর *)
		__attribute__((__bounded__(__minbytes__,2,MD5_DIGEST_STRING_দৈর্ঘ্য)));
অক্ষর	*MD5FileChunk(ধ্রুবক অক্ষর *, অক্ষর *, off_t, off_t)
		__attribute__((__bounded__(__minbytes__,2,MD5_DIGEST_STRING_দৈর্ঘ্য)));
অক্ষর	*MD5_তথ্য(ধ্রুবক u_int8_t *, আকার_t, অক্ষর *)
		__attribute__((__bounded__(__string__,1,2)))
		__attribute__((__bounded__(__minbytes__,3,MD5_DIGEST_STRING_দৈর্ঘ্য)));

#endif /* !WITH_OPENSSL */

#endif /* _MD5_H_ */
