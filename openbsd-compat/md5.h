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

#నిర్వచితం_కాకపోతే _MD5_H_
#నిర్వచించు _MD5_H_

#నిర్వచితం_కాకపోతే WITH_OPENSSL

#నిర్వచించు	MD5_ఖండం_నిడివి		64
#నిర్వచించు	MD5_DIGEST_నిడివి		16
#నిర్వచించు	MD5_DIGEST_STRING_నిడివి	(MD5_DIGEST_నిడివి * 2 + 1)

రకనిర్వచనం నిర్మాణం MD5Context {
	u_int32_t state[4];			/* state */
	u_int64_t లెక్క;			/* number of bits, mod 2^64 */
	u_int8_t బఫరు[MD5_ఖండం_నిడివి];	/* input buffer */
} MD5_CTX;

శూన్య	 MD5Init(MD5_CTX *);
శూన్య	 MD5Update(MD5_CTX *, స్థిరరాశి u_int8_t *, కొలత_t)
		__attribute__((__bounded__(__string__,2,3)));
శూన్య	 MD5Pad(MD5_CTX *);
శూన్య	 MD5Final(u_int8_t [MD5_DIGEST_నిడివి], MD5_CTX *)
		__attribute__((__bounded__(__minbytes__,1,MD5_DIGEST_నిడివి)));
శూన్య	 MD5Transform(u_int32_t [4], స్థిరరాశి u_int8_t [MD5_ఖండం_నిడివి])
		__attribute__((__bounded__(__minbytes__,1,4)))
		__attribute__((__bounded__(__minbytes__,2,MD5_ఖండం_నిడివి)));
అక్షరం	*MD5_చివర(MD5_CTX *, అక్షరం *)
		__attribute__((__bounded__(__minbytes__,2,MD5_DIGEST_STRING_నిడివి)));
అక్షరం	*MD5File(స్థిరరాశి అక్షరం *, అక్షరం *)
		__attribute__((__bounded__(__minbytes__,2,MD5_DIGEST_STRING_నిడివి)));
అక్షరం	*MD5FileChunk(స్థిరరాశి అక్షరం *, అక్షరం *, off_t, off_t)
		__attribute__((__bounded__(__minbytes__,2,MD5_DIGEST_STRING_నిడివి)));
అక్షరం	*MD5_దత్తాంశం(స్థిరరాశి u_int8_t *, కొలత_t, అక్షరం *)
		__attribute__((__bounded__(__string__,1,2)))
		__attribute__((__bounded__(__minbytes__,3,MD5_DIGEST_STRING_నిడివి)));

#అయితే_ముగింపు /* !WITH_OPENSSL */

#అయితే_ముగింపు /* _MD5_H_ */
