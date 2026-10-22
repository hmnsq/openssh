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

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ _MD5_H_
#ವ್ಯಾಖ್ಯಾನಿಸು _MD5_H_

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ WITH_OPENSSL

#ವ್ಯಾಖ್ಯಾನಿಸು	MD5_ಖಂಡ_ಉದ್ದಳತೆ		64
#ವ್ಯಾಖ್ಯಾನಿಸು	MD5_DIGEST_ಉದ್ದಳತೆ		16
#ವ್ಯಾಖ್ಯಾನಿಸು	MD5_DIGEST_STRING_ಉದ್ದಳತೆ	(MD5_DIGEST_ಉದ್ದಳತೆ * 2 + 1)

ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ MD5Context {
	u_int32_t state[4];			/* state */
	u_int64_t ಎಣಿಕೆ_2;			/* number of bits, mod 2^64 */
	u_int8_t ಬಫರ್[MD5_ಖಂಡ_ಉದ್ದಳತೆ];	/* input buffer */
} MD5_CTX;

ಶೂನ್ಯ	 MD5Init(MD5_CTX *);
ಶೂನ್ಯ	 MD5Update(MD5_CTX *, ಸ್ಥಿರಾಂಕ u_int8_t *, ಗಾತ್ರ_t)
		__attribute__((__bounded__(__string__,2,3)));
ಶೂನ್ಯ	 MD5Pad(MD5_CTX *);
ಶೂನ್ಯ	 MD5Final(u_int8_t [MD5_DIGEST_ಉದ್ದಳತೆ], MD5_CTX *)
		__attribute__((__bounded__(__minbytes__,1,MD5_DIGEST_ಉದ್ದಳತೆ)));
ಶೂನ್ಯ	 MD5Transform(u_int32_t [4], ಸ್ಥಿರಾಂಕ u_int8_t [MD5_ಖಂಡ_ಉದ್ದಳತೆ])
		__attribute__((__bounded__(__minbytes__,1,4)))
		__attribute__((__bounded__(__minbytes__,2,MD5_ಖಂಡ_ಉದ್ದಳತೆ)));
ಅಕ್ಷರ	*MD5_ಕೊನೆ(MD5_CTX *, ಅಕ್ಷರ *)
		__attribute__((__bounded__(__minbytes__,2,MD5_DIGEST_STRING_ಉದ್ದಳತೆ)));
ಅಕ್ಷರ	*MD5File(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಅಕ್ಷರ *)
		__attribute__((__bounded__(__minbytes__,2,MD5_DIGEST_STRING_ಉದ್ದಳತೆ)));
ಅಕ್ಷರ	*MD5FileChunk(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಅಕ್ಷರ *, off_t, off_t)
		__attribute__((__bounded__(__minbytes__,2,MD5_DIGEST_STRING_ಉದ್ದಳತೆ)));
ಅಕ್ಷರ	*MD5_ದತ್ತಾಂಶ(ಸ್ಥಿರಾಂಕ u_int8_t *, ಗಾತ್ರ_t, ಅಕ್ಷರ *)
		__attribute__((__bounded__(__string__,1,2)))
		__attribute__((__bounded__(__minbytes__,3,MD5_DIGEST_STRING_ಉದ್ದಳತೆ)));

#ಆದರೆ_ಅಂತ್ಯ /* !WITH_OPENSSL */

#ಆದರೆ_ಅಂತ್ಯ /* _MD5_H_ */
