/*	$OpenBSD: sha1.h,v 1.24 2012/12/05 23:19:57 deraadt Exp $	*/

/*
 * SHA-1 in C
 * By Steve Reid <steve@edmweb.com>
 * 100% Public Domain
 */

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ _SHA1_H
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ _SHA1_H

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	SHA1_ਖੰਡ_ਲੰਮਾਈ		64
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	SHA1_DIGEST_ਲੰਮਾਈ		20
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ	SHA1_DIGEST_STRING_ਲੰਮਾਈ	(SHA1_DIGEST_ਲੰਮਾਈ * 2 + 1)

ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਬਣਤਰ {
    u_int32_t state[5];
    u_int64_t ਗਿਣਤੀ_2;
    u_int8_t ਬਫਰ[SHA1_ਖੰਡ_ਲੰਮਾਈ];
} SHA1_CTX;

ਖਾਲੀ SHA1Init(SHA1_CTX *);
ਖਾਲੀ SHA1Pad(SHA1_CTX *);
ਖਾਲੀ SHA1Transform(u_int32_t [5], ਅਚਲ u_int8_t [SHA1_ਖੰਡ_ਲੰਮਾਈ])
	__attribute__((__bounded__(__minbytes__,1,5)))
	__attribute__((__bounded__(__minbytes__,2,SHA1_ਖੰਡ_ਲੰਮਾਈ)));
ਖਾਲੀ SHA1Update(SHA1_CTX *, ਅਚਲ u_int8_t *, ਮਾਪ_t)
	__attribute__((__bounded__(__string__,2,3)));
ਖਾਲੀ SHA1Final(u_int8_t [SHA1_DIGEST_ਲੰਮਾਈ], SHA1_CTX *)
	__attribute__((__bounded__(__minbytes__,1,SHA1_DIGEST_ਲੰਮਾਈ)));
ਅੱਖਰ *SHA1_ਸਿਰਾ(SHA1_CTX *, ਅੱਖਰ *)
	__attribute__((__bounded__(__minbytes__,2,SHA1_DIGEST_STRING_ਲੰਮਾਈ)));
ਅੱਖਰ *SHA1File(ਅਚਲ ਅੱਖਰ *, ਅੱਖਰ *)
	__attribute__((__bounded__(__minbytes__,2,SHA1_DIGEST_STRING_ਲੰਮਾਈ)));
ਅੱਖਰ *SHA1FileChunk(ਅਚਲ ਅੱਖਰ *, ਅੱਖਰ *, off_t, off_t)
	__attribute__((__bounded__(__minbytes__,2,SHA1_DIGEST_STRING_ਲੰਮਾਈ)));
ਅੱਖਰ *SHA1_ਅੰਕੜੇ(ਅਚਲ u_int8_t *, ਮਾਪ_t, ਅੱਖਰ *)
	__attribute__((__bounded__(__string__,1,2)))
	__attribute__((__bounded__(__minbytes__,3,SHA1_DIGEST_STRING_ਲੰਮਾਈ)));

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ HTONDIGEST(x) ਕਰੋ {                                              \
        x[0] = htonl(x[0]);                                             \
        x[1] = htonl(x[1]);                                             \
        x[2] = htonl(x[2]);                                             \
        x[3] = htonl(x[3]);                                             \
        x[4] = htonl(x[4]); } ਜਦੋਂ (0)

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ NTOHDIGEST(x) ਕਰੋ {                                              \
        x[0] = ntohl(x[0]);                                             \
        x[1] = ntohl(x[1]);                                             \
        x[2] = ntohl(x[2]);                                             \
        x[3] = ntohl(x[3]);                                             \
        x[4] = ntohl(x[4]); } ਜਦੋਂ (0)

#ਜੇ_ਅੰਤ /* !WITH_OPENSSL */
#ਜੇ_ਅੰਤ /* _SHA1_H */
