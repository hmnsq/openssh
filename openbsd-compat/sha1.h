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

প্রকারনির্দেশ সংরচনা {
    u_int32_t state[5];
    u_int64_t গুনতি;
    u_int8_t buffer[SHA1_BLOCK_LENGTH];
} SHA1_CTX;

শূন্য SHA1Init(SHA1_CTX *);
শূন্য SHA1Pad(SHA1_CTX *);
শূন্য SHA1Transform(u_int32_t [5], ধ্রুব u_int8_t [SHA1_BLOCK_LENGTH])
	__attribute__((__bounded__(__minbytes__,1,5)))
	__attribute__((__bounded__(__minbytes__,2,SHA1_BLOCK_LENGTH)));
শূন্য SHA1Update(SHA1_CTX *, ধ্রুব u_int8_t *, size_t)
	__attribute__((__bounded__(__string__,2,3)));
শূন্য SHA1Final(u_int8_t [SHA1_DIGEST_LENGTH], SHA1_CTX *)
	__attribute__((__bounded__(__minbytes__,1,SHA1_DIGEST_LENGTH)));
বর্ণ *SHA1End(SHA1_CTX *, বর্ণ *)
	__attribute__((__bounded__(__minbytes__,2,SHA1_DIGEST_STRING_LENGTH)));
বর্ণ *SHA1File(ধ্রুব বর্ণ *, বর্ণ *)
	__attribute__((__bounded__(__minbytes__,2,SHA1_DIGEST_STRING_LENGTH)));
বর্ণ *SHA1FileChunk(ধ্রুব বর্ণ *, বর্ণ *, off_t, off_t)
	__attribute__((__bounded__(__minbytes__,2,SHA1_DIGEST_STRING_LENGTH)));
বর্ণ *SHA1Data(ধ্রুব u_int8_t *, size_t, বর্ণ *)
	__attribute__((__bounded__(__string__,1,2)))
	__attribute__((__bounded__(__minbytes__,3,SHA1_DIGEST_STRING_LENGTH)));

#define HTONDIGEST(x) কুরু {                                              \
        x[0] = htonl(x[0]);                                             \
        x[1] = htonl(x[1]);                                             \
        x[2] = htonl(x[2]);                                             \
        x[3] = htonl(x[3]);                                             \
        x[4] = htonl(x[4]); } যাবত্ (0)

#define NTOHDIGEST(x) কুরু {                                              \
        x[0] = ntohl(x[0]);                                             \
        x[1] = ntohl(x[1]);                                             \
        x[2] = ntohl(x[2]);                                             \
        x[3] = ntohl(x[3]);                                             \
        x[4] = ntohl(x[4]); } যাবত্ (0)

#endif /* !WITH_OPENSSL */
#endif /* _SHA1_H */
