/*	$OpenBSD: sha1.h,v 1.24 2012/12/05 23:19:57 deraadt Exp $	*/

/*
 * SHA-1 in C
 * By Steve Reid <steve@edmweb.com>
 * 100% Public Domain
 */

#اگر_غیر_تعریف_شدہ _SHA1_H
#تعریف_کرو _SHA1_H

#اگر_غیر_تعریف_شدہ WITH_OPENSSL

#تعریف_کرو	SHA1_بلاک_لمبائی		64
#تعریف_کرو	SHA1_DIGEST_لمبائی		20
#تعریف_کرو	SHA1_DIGEST_STRING_لمبائی	(SHA1_DIGEST_لمبائی * 2 + 1)

قسمتعریف ساخت {
    u_int32_t state[5];
    u_int64_t گنتی;
    u_int8_t بفر[SHA1_بلاک_لمبائی];
} SHA1_CTX;

خالی SHA1Init(SHA1_CTX *);
خالی SHA1Pad(SHA1_CTX *);
خالی SHA1Transform(u_int32_t [5], ثابت u_int8_t [SHA1_بلاک_لمبائی])
	__attribute__((__bounded__(__minbytes__,1,5)))
	__attribute__((__bounded__(__minbytes__,2,SHA1_بلاک_لمبائی)));
خالی SHA1Update(SHA1_CTX *, ثابت u_int8_t *, سائز_t)
	__attribute__((__bounded__(__string__,2,3)));
خالی SHA1Final(u_int8_t [SHA1_DIGEST_لمبائی], SHA1_CTX *)
	__attribute__((__bounded__(__minbytes__,1,SHA1_DIGEST_لمبائی)));
حرف *SHA1_انتہا(SHA1_CTX *, حرف *)
	__attribute__((__bounded__(__minbytes__,2,SHA1_DIGEST_STRING_لمبائی)));
حرف *SHA1File(ثابت حرف *, حرف *)
	__attribute__((__bounded__(__minbytes__,2,SHA1_DIGEST_STRING_لمبائی)));
حرف *SHA1FileChunk(ثابت حرف *, حرف *, off_t, off_t)
	__attribute__((__bounded__(__minbytes__,2,SHA1_DIGEST_STRING_لمبائی)));
حرف *SHA1_ڈیٹا(ثابت u_int8_t *, سائز_t, حرف *)
	__attribute__((__bounded__(__string__,1,2)))
	__attribute__((__bounded__(__minbytes__,3,SHA1_DIGEST_STRING_لمبائی)));

#تعریف_کرو HTONDIGEST(x) کرو {                                              \
        x[0] = htonl(x[0]);                                             \
        x[1] = htonl(x[1]);                                             \
        x[2] = htonl(x[2]);                                             \
        x[3] = htonl(x[3]);                                             \
        x[4] = htonl(x[4]); } جب (0)

#تعریف_کرو NTOHDIGEST(x) کرو {                                              \
        x[0] = ntohl(x[0]);                                             \
        x[1] = ntohl(x[1]);                                             \
        x[2] = ntohl(x[2]);                                             \
        x[3] = ntohl(x[3]);                                             \
        x[4] = ntohl(x[4]); } جب (0)

#اگر_ختم /* !WITH_OPENSSL */
#اگر_ختم /* _SHA1_H */
