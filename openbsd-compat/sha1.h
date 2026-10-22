/*	$OpenBSD: sha1.h,v 1.24 2012/12/05 23:19:57 deraadt Exp $	*/

/*
 * SHA-1 in C
 * By Steve Reid <steve@edmweb.com>
 * 100% Public Domain
 */

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ _SHA1_H
#ವ್ಯಾಖ್ಯಾನಿಸು _SHA1_H

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ WITH_OPENSSL

#ವ್ಯಾಖ್ಯಾನಿಸು	SHA1_ಖಂಡ_ಉದ್ದಳತೆ		64
#ವ್ಯಾಖ್ಯಾನಿಸು	SHA1_DIGEST_ಉದ್ದಳತೆ		20
#ವ್ಯಾಖ್ಯಾನಿಸು	SHA1_DIGEST_STRING_ಉದ್ದಳತೆ	(SHA1_DIGEST_ಉದ್ದಳತೆ * 2 + 1)

ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ {
    u_int32_t state[5];
    u_int64_t ಎಣಿಕೆ_2;
    u_int8_t ಬಫರ್[SHA1_ಖಂಡ_ಉದ್ದಳತೆ];
} SHA1_CTX;

ಶೂನ್ಯ SHA1Init(SHA1_CTX *);
ಶೂನ್ಯ SHA1Pad(SHA1_CTX *);
ಶೂನ್ಯ SHA1Transform(u_int32_t [5], ಸ್ಥಿರಾಂಕ u_int8_t [SHA1_ಖಂಡ_ಉದ್ದಳತೆ])
	__attribute__((__bounded__(__minbytes__,1,5)))
	__attribute__((__bounded__(__minbytes__,2,SHA1_ಖಂಡ_ಉದ್ದಳತೆ)));
ಶೂನ್ಯ SHA1Update(SHA1_CTX *, ಸ್ಥಿರಾಂಕ u_int8_t *, ಗಾತ್ರ_t)
	__attribute__((__bounded__(__string__,2,3)));
ಶೂನ್ಯ SHA1Final(u_int8_t [SHA1_DIGEST_ಉದ್ದಳತೆ], SHA1_CTX *)
	__attribute__((__bounded__(__minbytes__,1,SHA1_DIGEST_ಉದ್ದಳತೆ)));
ಅಕ್ಷರ *SHA1_ಕೊನೆ(SHA1_CTX *, ಅಕ್ಷರ *)
	__attribute__((__bounded__(__minbytes__,2,SHA1_DIGEST_STRING_ಉದ್ದಳತೆ)));
ಅಕ್ಷರ *SHA1File(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಅಕ್ಷರ *)
	__attribute__((__bounded__(__minbytes__,2,SHA1_DIGEST_STRING_ಉದ್ದಳತೆ)));
ಅಕ್ಷರ *SHA1FileChunk(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಅಕ್ಷರ *, off_t, off_t)
	__attribute__((__bounded__(__minbytes__,2,SHA1_DIGEST_STRING_ಉದ್ದಳತೆ)));
ಅಕ್ಷರ *SHA1_ದತ್ತಾಂಶ(ಸ್ಥಿರಾಂಕ u_int8_t *, ಗಾತ್ರ_t, ಅಕ್ಷರ *)
	__attribute__((__bounded__(__string__,1,2)))
	__attribute__((__bounded__(__minbytes__,3,SHA1_DIGEST_STRING_ಉದ್ದಳತೆ)));

#ವ್ಯಾಖ್ಯಾನಿಸು HTONDIGEST(x) ಮಾಡು {                                              \
        x[0] = htonl(x[0]);                                             \
        x[1] = htonl(x[1]);                                             \
        x[2] = htonl(x[2]);                                             \
        x[3] = htonl(x[3]);                                             \
        x[4] = htonl(x[4]); } ಆಗ (0)

#ವ್ಯಾಖ್ಯಾನಿಸು NTOHDIGEST(x) ಮಾಡು {                                              \
        x[0] = ntohl(x[0]);                                             \
        x[1] = ntohl(x[1]);                                             \
        x[2] = ntohl(x[2]);                                             \
        x[3] = ntohl(x[3]);                                             \
        x[4] = ntohl(x[4]); } ಆಗ (0)

#ಆದರೆ_ಅಂತ್ಯ /* !WITH_OPENSSL */
#ಆದರೆ_ಅಂತ್ಯ /* _SHA1_H */
