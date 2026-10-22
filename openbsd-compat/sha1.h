/*	$OpenBSD: sha1.h,v 1.24 2012/12/05 23:19:57 deraadt Exp $	*/

/*
 * SHA-1 in C
 * By Steve Reid <steve@edmweb.com>
 * 100% Public Domain
 */

#جيڪڏهن_وصف_نه_ٿيل _SHA1_H
#وصف_ڪريو _SHA1_H

#جيڪڏهن_وصف_نه_ٿيل WITH_OPENSSL

#وصف_ڪريو	SHA1_بلاڪ_ڊيگهائي		64
#وصف_ڪريو	SHA1_DIGEST_ڊيگهائي		20
#وصف_ڪريو	SHA1_DIGEST_STRING_ڊيگهائي	(SHA1_DIGEST_ڊيگهائي * 2 + 1)

تعريفنوع بنية {
    u_int32_t state[5];
    u_int64_t ڳڻپ;
    u_int8_t بفر[SHA1_بلاڪ_ڊيگهائي];
} SHA1_CTX;

فراغ SHA1Init(SHA1_CTX *);
فراغ SHA1Pad(SHA1_CTX *);
فراغ SHA1Transform(u_int32_t [5], ثابت u_int8_t [SHA1_بلاڪ_ڊيگهائي])
	__attribute__((__bounded__(__minbytes__,1,5)))
	__attribute__((__bounded__(__minbytes__,2,SHA1_بلاڪ_ڊيگهائي)));
فراغ SHA1Update(SHA1_CTX *, ثابت u_int8_t *, سائيز_t)
	__attribute__((__bounded__(__string__,2,3)));
فراغ SHA1Final(u_int8_t [SHA1_DIGEST_ڊيگهائي], SHA1_CTX *)
	__attribute__((__bounded__(__minbytes__,1,SHA1_DIGEST_ڊيگهائي)));
حرف *SHA1_پڇاڙي(SHA1_CTX *, حرف *)
	__attribute__((__bounded__(__minbytes__,2,SHA1_DIGEST_STRING_ڊيگهائي)));
حرف *SHA1File(ثابت حرف *, حرف *)
	__attribute__((__bounded__(__minbytes__,2,SHA1_DIGEST_STRING_ڊيگهائي)));
حرف *SHA1FileChunk(ثابت حرف *, حرف *, off_t, off_t)
	__attribute__((__bounded__(__minbytes__,2,SHA1_DIGEST_STRING_ڊيگهائي)));
حرف *SHA1_معلومات(ثابت u_int8_t *, سائيز_t, حرف *)
	__attribute__((__bounded__(__string__,1,2)))
	__attribute__((__bounded__(__minbytes__,3,SHA1_DIGEST_STRING_ڊيگهائي)));

#وصف_ڪريو HTONDIGEST(x) افعل {                                              \
        x[0] = htonl(x[0]);                                             \
        x[1] = htonl(x[1]);                                             \
        x[2] = htonl(x[2]);                                             \
        x[3] = htonl(x[3]);                                             \
        x[4] = htonl(x[4]); } طالما (0)

#وصف_ڪريو NTOHDIGEST(x) افعل {                                              \
        x[0] = ntohl(x[0]);                                             \
        x[1] = ntohl(x[1]);                                             \
        x[2] = ntohl(x[2]);                                             \
        x[3] = ntohl(x[3]);                                             \
        x[4] = ntohl(x[4]); } طالما (0)

#جيڪڏهن_پورو /* !WITH_OPENSSL */
#جيڪڏهن_پورو /* _SHA1_H */
