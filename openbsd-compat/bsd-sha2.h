/*	$OpenBSD: sha2.h,v 1.10 2016/09/03 17:00:29 tedu Exp $	*/

/*
 * FILE:	sha2.h
 * AUTHOR:	Aaron D. Gifford <me@aarongifford.com>
 * 
 * Copyright (c) 2000-2001, Aaron D. Gifford
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTOR(S) ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTOR(S) BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $From: sha2.h,v 1.1 2001/11/08 00:02:01 adg Exp adg $
 */

/* OPENBSD ORIGINAL: include/sha2.h */

#నిర్వచితం_కాకపోతే _SSHSHA2_H
#నిర్వచించు _SSHSHA2_H

#అన్తర్భావ "includes.h"

#ఒకవేళ !defined(HAVE_SHA256UPDATE) || !defined(HAVE_SHA384UPDATE) || \
    !defined(HAVE_SHA512UPDATE)

/*** SHA-256/384/512 Various Length Definitions ***********************/
#నిర్వచించు SHA224_ఖండం_నిడివి		64
#నిర్వచించు SHA224_DIGEST_నిడివి		28
#నిర్వచించు SHA224_DIGEST_STRING_నిడివి	(SHA224_DIGEST_నిడివి * 2 + 1)
#నిర్వచించు SHA256_ఖండం_నిడివి		64
#నిర్వచించు SHA256_DIGEST_నిడివి		32
#నిర్వచించు SHA256_DIGEST_STRING_నిడివి	(SHA256_DIGEST_నిడివి * 2 + 1)
#నిర్వచించు SHA384_ఖండం_నిడివి		128
#నిర్వచించు SHA384_DIGEST_నిడివి		48
#నిర్వచించు SHA384_DIGEST_STRING_నిడివి	(SHA384_DIGEST_నిడివి * 2 + 1)
#నిర్వచించు SHA512_ఖండం_నిడివి		128
#నిర్వచించు SHA512_DIGEST_నిడివి		64
#నిర్వచించు SHA512_DIGEST_STRING_నిడివి	(SHA512_DIGEST_నిడివి * 2 + 1)
#నిర్వచించు SHA512_256_ఖండం_నిడివి		128
#నిర్వచించు SHA512_256_DIGEST_నిడివి	32
#నిర్వచించు SHA512_256_DIGEST_STRING_నిడివి	(SHA512_256_DIGEST_నిడివి * 2 + 1)


/*** SHA-224/256/384/512 Context Structure *******************************/
రకనిర్వచనం నిర్మాణం _SHA2_CTX {
	సంఘం {
		u_int32_t	st32[8];
		u_int64_t	st64[8];
	} state;
	u_int64_t	bitcount[2];
	u_int8_t	బఫరు[SHA512_ఖండం_నిడివి];
} SHA2_CTX;

#ఒకవేళ 0
__BEGIN_DECLS
శూన్య SHA224Init(SHA2_CTX *);
శూన్య SHA224Transform(u_int32_t state[8], స్థిరరాశి u_int8_t [SHA224_ఖండం_నిడివి]);
శూన్య SHA224Update(SHA2_CTX *, స్థిరరాశి u_int8_t *, కొలత_t)
	__attribute__((__bounded__(__string__,2,3)));
శూన్య SHA224Pad(SHA2_CTX *);
శూన్య SHA224Final(u_int8_t [SHA224_DIGEST_నిడివి], SHA2_CTX *)
	__attribute__((__bounded__(__minbytes__,1,SHA224_DIGEST_నిడివి)));
అక్షరం *SHA224_చివర(SHA2_CTX *, అక్షరం *)
	__attribute__((__bounded__(__minbytes__,2,SHA224_DIGEST_STRING_నిడివి)));
అక్షరం *SHA224File(స్థిరరాశి అక్షరం *, అక్షరం *)
	__attribute__((__bounded__(__minbytes__,2,SHA224_DIGEST_STRING_నిడివి)));
అక్షరం *SHA224FileChunk(స్థిరరాశి అక్షరం *, అక్షరం *, off_t, off_t)
	__attribute__((__bounded__(__minbytes__,2,SHA224_DIGEST_STRING_నిడివి)));
అక్షరం *SHA224_దత్తాంశం(స్థిరరాశి u_int8_t *, కొలత_t, అక్షరం *)
	__attribute__((__bounded__(__string__,1,2)))
	__attribute__((__bounded__(__minbytes__,3,SHA224_DIGEST_STRING_నిడివి)));
#అయితే_ముగింపు /* 0 */

#నిర్వచితం_కాకపోతే HAVE_SHA256UPDATE
శూన్య SHA256Init(SHA2_CTX *);
శూన్య SHA256Transform(u_int32_t state[8], స్థిరరాశి u_int8_t [SHA256_ఖండం_నిడివి]);
శూన్య SHA256Update(SHA2_CTX *, స్థిరరాశి u_int8_t *, కొలత_t)
	__attribute__((__bounded__(__string__,2,3)));
శూన్య SHA256Pad(SHA2_CTX *);
శూన్య SHA256Final(u_int8_t [SHA256_DIGEST_నిడివి], SHA2_CTX *)
	__attribute__((__bounded__(__minbytes__,1,SHA256_DIGEST_నిడివి)));
అక్షరం *SHA256_చివర(SHA2_CTX *, అక్షరం *)
	__attribute__((__bounded__(__minbytes__,2,SHA256_DIGEST_STRING_నిడివి)));
అక్షరం *SHA256File(స్థిరరాశి అక్షరం *, అక్షరం *)
	__attribute__((__bounded__(__minbytes__,2,SHA256_DIGEST_STRING_నిడివి)));
అక్షరం *SHA256FileChunk(స్థిరరాశి అక్షరం *, అక్షరం *, off_t, off_t)
	__attribute__((__bounded__(__minbytes__,2,SHA256_DIGEST_STRING_నిడివి)));
అక్షరం *SHA256_దత్తాంశం(స్థిరరాశి u_int8_t *, కొలత_t, అక్షరం *)
	__attribute__((__bounded__(__string__,1,2)))
	__attribute__((__bounded__(__minbytes__,3,SHA256_DIGEST_STRING_నిడివి)));
#అయితే_ముగింపు /* HAVE_SHA256UPDATE */

#నిర్వచితం_కాకపోతే HAVE_SHA384UPDATE
శూన్య SHA384Init(SHA2_CTX *);
శూన్య SHA384Transform(u_int64_t state[8], స్థిరరాశి u_int8_t [SHA384_ఖండం_నిడివి]);
శూన్య SHA384Update(SHA2_CTX *, స్థిరరాశి u_int8_t *, కొలత_t)
	__attribute__((__bounded__(__string__,2,3)));
శూన్య SHA384Pad(SHA2_CTX *);
శూన్య SHA384Final(u_int8_t [SHA384_DIGEST_నిడివి], SHA2_CTX *)
	__attribute__((__bounded__(__minbytes__,1,SHA384_DIGEST_నిడివి)));
అక్షరం *SHA384_చివర(SHA2_CTX *, అక్షరం *)
	__attribute__((__bounded__(__minbytes__,2,SHA384_DIGEST_STRING_నిడివి)));
అక్షరం *SHA384File(స్థిరరాశి అక్షరం *, అక్షరం *)
	__attribute__((__bounded__(__minbytes__,2,SHA384_DIGEST_STRING_నిడివి)));
అక్షరం *SHA384FileChunk(స్థిరరాశి అక్షరం *, అక్షరం *, off_t, off_t)
	__attribute__((__bounded__(__minbytes__,2,SHA384_DIGEST_STRING_నిడివి)));
అక్షరం *SHA384_దత్తాంశం(స్థిరరాశి u_int8_t *, కొలత_t, అక్షరం *)
	__attribute__((__bounded__(__string__,1,2)))
	__attribute__((__bounded__(__minbytes__,3,SHA384_DIGEST_STRING_నిడివి)));
#అయితే_ముగింపు /* HAVE_SHA384UPDATE */

#నిర్వచితం_కాకపోతే HAVE_SHA512UPDATE
శూన్య SHA512Init(SHA2_CTX *);
శూన్య SHA512Transform(u_int64_t state[8], స్థిరరాశి u_int8_t [SHA512_ఖండం_నిడివి]);
శూన్య SHA512Update(SHA2_CTX *, స్థిరరాశి u_int8_t *, కొలత_t)
	__attribute__((__bounded__(__string__,2,3)));
శూన్య SHA512Pad(SHA2_CTX *);
శూన్య SHA512Final(u_int8_t [SHA512_DIGEST_నిడివి], SHA2_CTX *)
	__attribute__((__bounded__(__minbytes__,1,SHA512_DIGEST_నిడివి)));
అక్షరం *SHA512_చివర(SHA2_CTX *, అక్షరం *)
	__attribute__((__bounded__(__minbytes__,2,SHA512_DIGEST_STRING_నిడివి)));
అక్షరం *SHA512File(స్థిరరాశి అక్షరం *, అక్షరం *)
	__attribute__((__bounded__(__minbytes__,2,SHA512_DIGEST_STRING_నిడివి)));
అక్షరం *SHA512FileChunk(స్థిరరాశి అక్షరం *, అక్షరం *, off_t, off_t)
	__attribute__((__bounded__(__minbytes__,2,SHA512_DIGEST_STRING_నిడివి)));
అక్షరం *SHA512_దత్తాంశం(స్థిరరాశి u_int8_t *, కొలత_t, అక్షరం *)
	__attribute__((__bounded__(__string__,1,2)))
	__attribute__((__bounded__(__minbytes__,3,SHA512_DIGEST_STRING_నిడివి)));
#అయితే_ముగింపు /* HAVE_SHA512UPDATE */

#ఒకవేళ 0
శూన్య SHA512_256Init(SHA2_CTX *);
శూన్య SHA512_256Transform(u_int64_t state[8], స్థిరరాశి u_int8_t [SHA512_256_ఖండం_నిడివి]);
శూన్య SHA512_256Update(SHA2_CTX *, స్థిరరాశి u_int8_t *, కొలత_t)
	__attribute__((__bounded__(__string__,2,3)));
శూన్య SHA512_256Pad(SHA2_CTX *);
శూన్య SHA512_256Final(u_int8_t [SHA512_256_DIGEST_నిడివి], SHA2_CTX *)
	__attribute__((__bounded__(__minbytes__,1,SHA512_256_DIGEST_నిడివి)));
అక్షరం *SHA512_256_చివర(SHA2_CTX *, అక్షరం *)
	__attribute__((__bounded__(__minbytes__,2,SHA512_256_DIGEST_STRING_నిడివి)));
అక్షరం *SHA512_256File(స్థిరరాశి అక్షరం *, అక్షరం *)
	__attribute__((__bounded__(__minbytes__,2,SHA512_256_DIGEST_STRING_నిడివి)));
అక్షరం *SHA512_256FileChunk(స్థిరరాశి అక్షరం *, అక్షరం *, off_t, off_t)
	__attribute__((__bounded__(__minbytes__,2,SHA512_256_DIGEST_STRING_నిడివి)));
అక్షరం *SHA512_256_దత్తాంశం(స్థిరరాశి u_int8_t *, కొలత_t, అక్షరం *)
	__attribute__((__bounded__(__string__,1,2)))
	__attribute__((__bounded__(__minbytes__,3,SHA512_256_DIGEST_STRING_నిడివి)));
__END_DECLS
#అయితే_ముగింపు /* 0 */

#అయితే_ముగింపు /* HAVE_SHA{256,384,512}UPDATE */

#అయితే_ముగింపు /* _SSHSHA2_H */
