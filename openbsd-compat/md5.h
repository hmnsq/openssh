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

#अगर_अघोषित _MD5_H_
#घोषणा _MD5_H_

#अगर_अघोषित WITH_OPENSSL

#घोषणा	MD5_BLOCK_लंबाई		64
#घोषणा	MD5_DIGEST_लंबाई		16
#घोषणा	MD5_DIGEST_STRING_लंबाई	(MD5_DIGEST_लंबाई * 2 + 1)

प्रकार काष्ठा MD5Context {
	u_int32_t state[4];			/* state */
	u_int64_t गिनती;			/* number of bits, mod 2^64 */
	u_int8_t बफर[MD5_BLOCK_लंबाई];	/* input buffer */
} MD5_CTX;

व्योम	 MD5Init(MD5_CTX *);
व्योम	 MD5Update(MD5_CTX *, स्थिर u_int8_t *, माप_प्रकार)
		__attribute__((__bounded__(__string__,2,3)));
व्योम	 MD5Pad(MD5_CTX *);
व्योम	 MD5Final(u_int8_t [MD5_DIGEST_लंबाई], MD5_CTX *)
		__attribute__((__bounded__(__minbytes__,1,MD5_DIGEST_लंबाई)));
व्योम	 MD5Transform(u_int32_t [4], स्थिर u_int8_t [MD5_BLOCK_लंबाई])
		__attribute__((__bounded__(__minbytes__,1,4)))
		__attribute__((__bounded__(__minbytes__,2,MD5_BLOCK_लंबाई)));
अक्षर	*MD5End(MD5_CTX *, अक्षर *)
		__attribute__((__bounded__(__minbytes__,2,MD5_DIGEST_STRING_लंबाई)));
अक्षर	*MD5File(स्थिर अक्षर *, अक्षर *)
		__attribute__((__bounded__(__minbytes__,2,MD5_DIGEST_STRING_लंबाई)));
अक्षर	*MD5FileChunk(स्थिर अक्षर *, अक्षर *, off_t, off_t)
		__attribute__((__bounded__(__minbytes__,2,MD5_DIGEST_STRING_लंबाई)));
अक्षर	*MD5_तथ्य(स्थिर u_int8_t *, माप_प्रकार, अक्षर *)
		__attribute__((__bounded__(__string__,1,2)))
		__attribute__((__bounded__(__minbytes__,3,MD5_DIGEST_STRING_लंबाई)));

#पूर्ण_अगर /* !WITH_OPENSSL */

#पूर्ण_अगर /* _MD5_H_ */
