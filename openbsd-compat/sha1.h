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

typedef sa_nracanaa {
    u_int32_t state[5];
    u_int64_t count;
    u_int8_t buffer[SHA1_BLOCK_LENGTH];
} SHA1_CTX;

void SHA1Init(SHA1_CTX *);
void SHA1Pad(SHA1_CTX *);
void SHA1Transform(u_int32_t [5], const u_int8_t [SHA1_BLOCK_LENGTH])
	__attribute__((__bounded__(__minbytes__,1,5)))
	__attribute__((__bounded__(__minbytes__,2,SHA1_BLOCK_LENGTH)));
void SHA1Update(SHA1_CTX *, const u_int8_t *, size_t)
	__attribute__((__bounded__(__string__,2,3)));
void SHA1Final(u_int8_t [SHA1_DIGEST_LENGTH], SHA1_CTX *)
	__attribute__((__bounded__(__minbytes__,1,SHA1_DIGEST_LENGTH)));
var_na *SHA1End(SHA1_CTX *, var_na *)
	__attribute__((__bounded__(__minbytes__,2,SHA1_DIGEST_STRING_LENGTH)));
var_na *SHA1File(const var_na *, var_na *)
	__attribute__((__bounded__(__minbytes__,2,SHA1_DIGEST_STRING_LENGTH)));
var_na *SHA1FileChunk(const var_na *, var_na *, off_t, off_t)
	__attribute__((__bounded__(__minbytes__,2,SHA1_DIGEST_STRING_LENGTH)));
var_na *SHA1Data(const u_int8_t *, size_t, var_na *)
	__attribute__((__bounded__(__string__,1,2)))
	__attribute__((__bounded__(__minbytes__,3,SHA1_DIGEST_STRING_LENGTH)));

#define HTONDIGEST(x) do {                                              \
        x[0] = htonl(x[0]);                                             \
        x[1] = htonl(x[1]);                                             \
        x[2] = htonl(x[2]);                                             \
        x[3] = htonl(x[3]);                                             \
        x[4] = htonl(x[4]); } ꦱꦼꦢꦼꦭ (0)

#define NTOHDIGEST(x) do {                                              \
        x[0] = ntohl(x[0]);                                             \
        x[1] = ntohl(x[1]);                                             \
        x[2] = ntohl(x[2]);                                             \
        x[3] = ntohl(x[3]);                                             \
        x[4] = ntohl(x[4]); } ꦱꦼꦢꦼꦭ (0)

#endif /* !WITH_OPENSSL */
#endif /* _SHA1_H */
