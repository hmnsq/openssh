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

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ _MD5_H_
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ _MD5_H_

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	MD5_ਖੰਡ_ਲੰਮਾਈ		64
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	MD5_DIGEST_ਲੰਮਾਈ		16
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	MD5_DIGEST_STRING_ਲੰਮਾਈ	(MD5_DIGEST_ਲੰਮਾਈ * 2 + 1)

ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਬਣਤਰ MD5Context {
	u_int32_t state[4];			/* state */
	u_int64_t ਗਿਣਤੀ_2;			/* number of bits, mod 2^64 */
	u_int8_t ਬਫਰ[MD5_ਖੰਡ_ਲੰਮਾਈ];	/* input buffer */
} MD5_CTX;

ਖਾਲੀ	 MD5Init(MD5_CTX *);
ਖਾਲੀ	 MD5Update(MD5_CTX *, ਅਚਲ u_int8_t *, ਮਾਪ_t)
		__attribute__((__bounded__(__string__,2,3)));
ਖਾਲੀ	 MD5Pad(MD5_CTX *);
ਖਾਲੀ	 MD5Final(u_int8_t [MD5_DIGEST_ਲੰਮਾਈ], MD5_CTX *)
		__attribute__((__bounded__(__minbytes__,1,MD5_DIGEST_ਲੰਮਾਈ)));
ਖਾਲੀ	 MD5Transform(u_int32_t [4], ਅਚਲ u_int8_t [MD5_ਖੰਡ_ਲੰਮਾਈ])
		__attribute__((__bounded__(__minbytes__,1,4)))
		__attribute__((__bounded__(__minbytes__,2,MD5_ਖੰਡ_ਲੰਮਾਈ)));
ਅੱਖਰ	*MD5_ਸਿਰਾ(MD5_CTX *, ਅੱਖਰ *)
		__attribute__((__bounded__(__minbytes__,2,MD5_DIGEST_STRING_ਲੰਮਾਈ)));
ਅੱਖਰ	*MD5File(ਅਚਲ ਅੱਖਰ *, ਅੱਖਰ *)
		__attribute__((__bounded__(__minbytes__,2,MD5_DIGEST_STRING_ਲੰਮਾਈ)));
ਅੱਖਰ	*MD5FileChunk(ਅਚਲ ਅੱਖਰ *, ਅੱਖਰ *, off_t, off_t)
		__attribute__((__bounded__(__minbytes__,2,MD5_DIGEST_STRING_ਲੰਮਾਈ)));
ਅੱਖਰ	*MD5_ਅੰਕੜੇ(ਅਚਲ u_int8_t *, ਮਾਪ_t, ਅੱਖਰ *)
		__attribute__((__bounded__(__string__,1,2)))
		__attribute__((__bounded__(__minbytes__,3,MD5_DIGEST_STRING_ਲੰਮਾਈ)));

#ਜੇ_ਅੰਤ /* !WITH_OPENSSL */

#ਜੇ_ਅੰਤ /* _MD5_H_ */
