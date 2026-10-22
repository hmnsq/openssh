/*	$OpenBSD: sha1.h,v 1.24 2012/12/05 23:19:57 deraadt Exp $	*/

/*
 * SHA-1 in C
 * By Steve Reid <steve@edmweb.com>
 * 100% Public Domain
 */

#ifndef _SHA1_H
#define _SHA1_H

#ifndef WITH_OPENSSL

#define	SHA1_BLOCK_LENGTH		64
#define	SHA1_DIGEST_LENGTH		20
#define	SHA1_DIGEST_STRING_LENGTH	(SHA1_DIGEST_LENGTH * 2 + 1)

प्रकारव्याख्या संरचना {
    u_int32_t state[5];
    u_int64_t मोजणी;
    u_int8_t buffer[SHA1_BLOCK_LENGTH];
} SHA1_CTX;

शून्य SHA1Init(SHA1_CTX *);
शून्य SHA1Pad(SHA1_CTX *);
शून्य SHA1Transform(u_int32_t [5], स्थिरांक u_int8_t [SHA1_BLOCK_LENGTH])
	__attribute__((__bounded__(__minbytes__,1,5)))
	__attribute__((__bounded__(__minbytes__,2,SHA1_BLOCK_LENGTH)));
शून्य SHA1Update(SHA1_CTX *, स्थिरांक u_int8_t *, माप_प्रकार)
	__attribute__((__bounded__(__string__,2,3)));
शून्य SHA1Final(u_int8_t [SHA1_DIGEST_LENGTH], SHA1_CTX *)
	__attribute__((__bounded__(__minbytes__,1,SHA1_DIGEST_LENGTH)));
अक्षर *SHA1End(SHA1_CTX *, अक्षर *)
	__attribute__((__bounded__(__minbytes__,2,SHA1_DIGEST_STRING_LENGTH)));
अक्षर *SHA1File(स्थिरांक अक्षर *, अक्षर *)
	__attribute__((__bounded__(__minbytes__,2,SHA1_DIGEST_STRING_LENGTH)));
अक्षर *SHA1FileChunk(स्थिरांक अक्षर *, अक्षर *, off_t, off_t)
	__attribute__((__bounded__(__minbytes__,2,SHA1_DIGEST_STRING_LENGTH)));
अक्षर *SHA1Data(स्थिरांक u_int8_t *, माप_प्रकार, अक्षर *)
	__attribute__((__bounded__(__string__,1,2)))
	__attribute__((__bounded__(__minbytes__,3,SHA1_DIGEST_STRING_LENGTH)));

#define HTONDIGEST(x) करा {                                              \
        x[0] = htonl(x[0]);                                             \
        x[1] = htonl(x[1]);                                             \
        x[2] = htonl(x[2]);                                             \
        x[3] = htonl(x[3]);                                             \
        x[4] = htonl(x[4]); } पर्यंत (0)

#define NTOHDIGEST(x) करा {                                              \
        x[0] = ntohl(x[0]);                                             \
        x[1] = ntohl(x[1]);                                             \
        x[2] = ntohl(x[2]);                                             \
        x[3] = ntohl(x[3]);                                             \
        x[4] = ntohl(x[4]); } पर्यंत (0)

#endif /* !WITH_OPENSSL */
#endif /* _SHA1_H */
