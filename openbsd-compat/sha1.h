/*	$OpenBSD: sha1.h,v 1.24 2012/12/05 23:19:57 deraadt Exp $	*/

/*
 * SHA-1 in C
 * By Steve Reid <steve@edmweb.com>
 * 100% Public Domain
 */

#నిర్వచితం_కాకపోతే _SHA1_H
#నిర్వచించు _SHA1_H

#నిర్వచితం_కాకపోతే WITH_OPENSSL

#నిర్వచించు	SHA1_ఖండం_నిడివి		64
#నిర్వచించు	SHA1_DIGEST_నిడివి		20
#నిర్వచించు	SHA1_DIGEST_STRING_నిడివి	(SHA1_DIGEST_నిడివి * 2 + 1)

రకనిర్వచనం నిర్మాణం {
    u_int32_t state[5];
    u_int64_t లెక్క;
    u_int8_t బఫరు[SHA1_ఖండం_నిడివి];
} SHA1_CTX;

శూన్య SHA1Init(SHA1_CTX *);
శూన్య SHA1Pad(SHA1_CTX *);
శూన్య SHA1Transform(u_int32_t [5], స్థిరరాశి u_int8_t [SHA1_ఖండం_నిడివి])
	__attribute__((__bounded__(__minbytes__,1,5)))
	__attribute__((__bounded__(__minbytes__,2,SHA1_ఖండం_నిడివి)));
శూన్య SHA1Update(SHA1_CTX *, స్థిరరాశి u_int8_t *, కొలత_t)
	__attribute__((__bounded__(__string__,2,3)));
శూన్య SHA1Final(u_int8_t [SHA1_DIGEST_నిడివి], SHA1_CTX *)
	__attribute__((__bounded__(__minbytes__,1,SHA1_DIGEST_నిడివి)));
అక్షరం *SHA1_చివర(SHA1_CTX *, అక్షరం *)
	__attribute__((__bounded__(__minbytes__,2,SHA1_DIGEST_STRING_నిడివి)));
అక్షరం *SHA1File(స్థిరరాశి అక్షరం *, అక్షరం *)
	__attribute__((__bounded__(__minbytes__,2,SHA1_DIGEST_STRING_నిడివి)));
అక్షరం *SHA1FileChunk(స్థిరరాశి అక్షరం *, అక్షరం *, off_t, off_t)
	__attribute__((__bounded__(__minbytes__,2,SHA1_DIGEST_STRING_నిడివి)));
అక్షరం *SHA1_దత్తాంశం(స్థిరరాశి u_int8_t *, కొలత_t, అక్షరం *)
	__attribute__((__bounded__(__string__,1,2)))
	__attribute__((__bounded__(__minbytes__,3,SHA1_DIGEST_STRING_నిడివి)));

#నిర్వచించు HTONDIGEST(x) చేయి {                                              \
        x[0] = htonl(x[0]);                                             \
        x[1] = htonl(x[1]);                                             \
        x[2] = htonl(x[2]);                                             \
        x[3] = htonl(x[3]);                                             \
        x[4] = htonl(x[4]); } అయితే (0)

#నిర్వచించు NTOHDIGEST(x) చేయి {                                              \
        x[0] = ntohl(x[0]);                                             \
        x[1] = ntohl(x[1]);                                             \
        x[2] = ntohl(x[2]);                                             \
        x[3] = ntohl(x[3]);                                             \
        x[4] = ntohl(x[4]); } అయితే (0)

#అయితే_ముగింపు /* !WITH_OPENSSL */
#అయితే_ముగింపు /* _SHA1_H */
