/*	$OpenBSD: sha1.h,v 1.24 2012/12/05 23:19:57 deraadt Exp $	*/

/*
 * SHA-1 in C
 * By Steve Reid <steve@edmweb.com>
 * 100% Public Domain
 */

#اگر_تعریف_نشده _SHA1_H
#تعریف_کن _SHA1_H

#اگر_تعریف_نشده WITH_OPENSSL

#تعریف_کن	SHA1_بلوک_درازی		64
#تعریف_کن	SHA1_DIGEST_درازی		20
#تعریف_کن	SHA1_DIGEST_STRING_درازی	(SHA1_DIGEST_درازی * 2 + 1)

تعريفنوع بنية {
    u_int32_t state[5];
    u_int64_t شمار;
    u_int8_t میانگیر[SHA1_بلوک_درازی];
} SHA1_CTX;

فراغ SHA1Init(SHA1_CTX *);
فراغ SHA1Pad(SHA1_CTX *);
فراغ SHA1Transform(u_int32_t [5], ثابت u_int8_t [SHA1_بلوک_درازی])
	__attribute__((__bounded__(__minbytes__,1,5)))
	__attribute__((__bounded__(__minbytes__,2,SHA1_بلوک_درازی)));
فراغ SHA1Update(SHA1_CTX *, ثابت u_int8_t *, اندازه_t)
	__attribute__((__bounded__(__string__,2,3)));
فراغ SHA1Final(u_int8_t [SHA1_DIGEST_درازی], SHA1_CTX *)
	__attribute__((__bounded__(__minbytes__,1,SHA1_DIGEST_درازی)));
حرف *SHA1_انتها(SHA1_CTX *, حرف *)
	__attribute__((__bounded__(__minbytes__,2,SHA1_DIGEST_STRING_درازی)));
حرف *SHA1File(ثابت حرف *, حرف *)
	__attribute__((__bounded__(__minbytes__,2,SHA1_DIGEST_STRING_درازی)));
حرف *SHA1FileChunk(ثابت حرف *, حرف *, off_t, off_t)
	__attribute__((__bounded__(__minbytes__,2,SHA1_DIGEST_STRING_درازی)));
حرف *SHA1_داده(ثابت u_int8_t *, اندازه_t, حرف *)
	__attribute__((__bounded__(__string__,1,2)))
	__attribute__((__bounded__(__minbytes__,3,SHA1_DIGEST_STRING_درازی)));

#تعریف_کن HTONDIGEST(x) افعل {                                              \
        x[0] = htonl(x[0]);                                             \
        x[1] = htonl(x[1]);                                             \
        x[2] = htonl(x[2]);                                             \
        x[3] = htonl(x[3]);                                             \
        x[4] = htonl(x[4]); } طالما (0)

#تعریف_کن NTOHDIGEST(x) افعل {                                              \
        x[0] = ntohl(x[0]);                                             \
        x[1] = ntohl(x[1]);                                             \
        x[2] = ntohl(x[2]);                                             \
        x[3] = ntohl(x[3]);                                             \
        x[4] = ntohl(x[4]); } طالما (0)

#پایان_اگر /* !WITH_OPENSSL */
#پایان_اگر /* _SHA1_H */
