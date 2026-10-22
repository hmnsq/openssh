/*	$OpenBSD: sha1.h,v 1.24 2012/12/05 23:19:57 deraadt Exp $	*/

/*
 * SHA-1 in C
 * By Steve Reid <steve@edmweb.com>
 * 100% Public Domain
 */

#यदि_अपरिभाषितम् _SHA1_H
#परिभाषय _SHA1_H

#यदि_अपरिभाषितम् WITH_OPENSSL

#परिभाषय	SHA1_खण्डम्_दीर्घता		64
#परिभाषय	SHA1_DIGEST_दीर्घता		20
#परिभाषय	SHA1_DIGEST_STRING_दीर्घता	(SHA1_DIGEST_दीर्घता * 2 + 1)

प्रकारनिर्देश संरचना {
    u_int32_t state[5];
    u_int64_t गणनम्;
    u_int8_t बफर[SHA1_खण्डम्_दीर्घता];
} SHA1_CTX;

शून्य SHA1Init(SHA1_CTX *);
शून्य SHA1Pad(SHA1_CTX *);
शून्य SHA1Transform(u_int32_t [5], ध्रुव u_int8_t [SHA1_खण्डम्_दीर्घता])
	__attribute__((__bounded__(__minbytes__,1,5)))
	__attribute__((__bounded__(__minbytes__,2,SHA1_खण्डम्_दीर्घता)));
शून्य SHA1Update(SHA1_CTX *, ध्रुव u_int8_t *, आकार_t)
	__attribute__((__bounded__(__string__,2,3)));
शून्य SHA1Final(u_int8_t [SHA1_DIGEST_दीर्घता], SHA1_CTX *)
	__attribute__((__bounded__(__minbytes__,1,SHA1_DIGEST_दीर्घता)));
वर्ण *SHA1_अन्तः(SHA1_CTX *, वर्ण *)
	__attribute__((__bounded__(__minbytes__,2,SHA1_DIGEST_STRING_दीर्घता)));
वर्ण *SHA1File(ध्रुव वर्ण *, वर्ण *)
	__attribute__((__bounded__(__minbytes__,2,SHA1_DIGEST_STRING_दीर्घता)));
वर्ण *SHA1FileChunk(ध्रुव वर्ण *, वर्ण *, off_t, off_t)
	__attribute__((__bounded__(__minbytes__,2,SHA1_DIGEST_STRING_दीर्घता)));
वर्ण *SHA1_दत्त(ध्रुव u_int8_t *, आकार_t, वर्ण *)
	__attribute__((__bounded__(__string__,1,2)))
	__attribute__((__bounded__(__minbytes__,3,SHA1_DIGEST_STRING_दीर्घता)));

#परिभाषय HTONDIGEST(x) कुरु {                                              \
        x[0] = htonl(x[0]);                                             \
        x[1] = htonl(x[1]);                                             \
        x[2] = htonl(x[2]);                                             \
        x[3] = htonl(x[3]);                                             \
        x[4] = htonl(x[4]); } यावत् (0)

#परिभाषय NTOHDIGEST(x) कुरु {                                              \
        x[0] = ntohl(x[0]);                                             \
        x[1] = ntohl(x[1]);                                             \
        x[2] = ntohl(x[2]);                                             \
        x[3] = ntohl(x[3]);                                             \
        x[4] = ntohl(x[4]); } यावत् (0)

#यदि_अन्तः /* !WITH_OPENSSL */
#यदि_अन्तः /* _SHA1_H */
