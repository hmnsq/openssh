/*	$OpenBSD: sha1.h,v 1.24 2012/12/05 23:19:57 deraadt Exp $	*/

/*
 * SHA-1 in C
 * By Steve Reid <steve@edmweb.com>
 * 100% Public Domain
 */

#अगर_अघोषित _SHA1_H
#घोषणा _SHA1_H

#अगर_अघोषित WITH_OPENSSL

#घोषणा	SHA1_BLOCK_लंबाई		64
#घोषणा	SHA1_DIGEST_लंबाई		20
#घोषणा	SHA1_DIGEST_STRING_लंबाई	(SHA1_DIGEST_लंबाई * 2 + 1)

प्रकार काष्ठा {
    u_int32_t state[5];
    u_int64_t गिनती;
    u_int8_t बफर[SHA1_BLOCK_लंबाई];
} SHA1_CTX;

व्योम SHA1Init(SHA1_CTX *);
व्योम SHA1Pad(SHA1_CTX *);
व्योम SHA1Transform(u_int32_t [5], स्थिर u_int8_t [SHA1_BLOCK_लंबाई])
	__attribute__((__bounded__(__minbytes__,1,5)))
	__attribute__((__bounded__(__minbytes__,2,SHA1_BLOCK_लंबाई)));
व्योम SHA1Update(SHA1_CTX *, स्थिर u_int8_t *, माप_प्रकार)
	__attribute__((__bounded__(__string__,2,3)));
व्योम SHA1Final(u_int8_t [SHA1_DIGEST_लंबाई], SHA1_CTX *)
	__attribute__((__bounded__(__minbytes__,1,SHA1_DIGEST_लंबाई)));
अक्षर *SHA1End(SHA1_CTX *, अक्षर *)
	__attribute__((__bounded__(__minbytes__,2,SHA1_DIGEST_STRING_लंबाई)));
अक्षर *SHA1File(स्थिर अक्षर *, अक्षर *)
	__attribute__((__bounded__(__minbytes__,2,SHA1_DIGEST_STRING_लंबाई)));
अक्षर *SHA1FileChunk(स्थिर अक्षर *, अक्षर *, off_t, off_t)
	__attribute__((__bounded__(__minbytes__,2,SHA1_DIGEST_STRING_लंबाई)));
अक्षर *SHA1_तथ्य(स्थिर u_int8_t *, माप_प्रकार, अक्षर *)
	__attribute__((__bounded__(__string__,1,2)))
	__attribute__((__bounded__(__minbytes__,3,SHA1_DIGEST_STRING_लंबाई)));

#घोषणा HTONDIGEST(x) करो {                                              \
        x[0] = htonl(x[0]);                                             \
        x[1] = htonl(x[1]);                                             \
        x[2] = htonl(x[2]);                                             \
        x[3] = htonl(x[3]);                                             \
        x[4] = htonl(x[4]); } जबतक (0)

#घोषणा NTOHDIGEST(x) करो {                                              \
        x[0] = ntohl(x[0]);                                             \
        x[1] = ntohl(x[1]);                                             \
        x[2] = ntohl(x[2]);                                             \
        x[3] = ntohl(x[3]);                                             \
        x[4] = ntohl(x[4]); } जबतक (0)

#पूर्ण_अगर /* !WITH_OPENSSL */
#पूर्ण_अगर /* _SHA1_H */
