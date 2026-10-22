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

#यदि_अपरिभाषितम् _SSHSHA2_H
#परिभाषय _SSHSHA2_H

#अन्तर्भाव "includes.h"

#यदि !defined(HAVE_SHA256UPDATE) || !defined(HAVE_SHA384UPDATE) || \
    !defined(HAVE_SHA512UPDATE)

/*** SHA-256/384/512 Various Length Definitions ***********************/
#परिभाषय SHA224_खण्डम्_दीर्घता		64
#परिभाषय SHA224_DIGEST_दीर्घता		28
#परिभाषय SHA224_DIGEST_STRING_दीर्घता	(SHA224_DIGEST_दीर्घता * 2 + 1)
#परिभाषय SHA256_खण्डम्_दीर्घता		64
#परिभाषय SHA256_DIGEST_दीर्घता		32
#परिभाषय SHA256_DIGEST_STRING_दीर्घता	(SHA256_DIGEST_दीर्घता * 2 + 1)
#परिभाषय SHA384_खण्डम्_दीर्घता		128
#परिभाषय SHA384_DIGEST_दीर्घता		48
#परिभाषय SHA384_DIGEST_STRING_दीर्घता	(SHA384_DIGEST_दीर्घता * 2 + 1)
#परिभाषय SHA512_खण्डम्_दीर्घता		128
#परिभाषय SHA512_DIGEST_दीर्घता		64
#परिभाषय SHA512_DIGEST_STRING_दीर्घता	(SHA512_DIGEST_दीर्घता * 2 + 1)
#परिभाषय SHA512_256_खण्डम्_दीर्घता		128
#परिभाषय SHA512_256_DIGEST_दीर्घता	32
#परिभाषय SHA512_256_DIGEST_STRING_दीर्घता	(SHA512_256_DIGEST_दीर्घता * 2 + 1)


/*** SHA-224/256/384/512 Context Structure *******************************/
प्रकारनिर्देश संरचना _SHA2_CTX {
	सङ्घ {
		u_int32_t	st32[8];
		u_int64_t	st64[8];
	} state;
	u_int64_t	bitcount[2];
	u_int8_t	बफर[SHA512_खण्डम्_दीर्घता];
} SHA2_CTX;

#यदि 0
__BEGIN_DECLS
शून्य SHA224Init(SHA2_CTX *);
शून्य SHA224Transform(u_int32_t state[8], ध्रुव u_int8_t [SHA224_खण्डम्_दीर्घता]);
शून्य SHA224Update(SHA2_CTX *, ध्रुव u_int8_t *, आकार_t)
	__attribute__((__bounded__(__string__,2,3)));
शून्य SHA224Pad(SHA2_CTX *);
शून्य SHA224Final(u_int8_t [SHA224_DIGEST_दीर्घता], SHA2_CTX *)
	__attribute__((__bounded__(__minbytes__,1,SHA224_DIGEST_दीर्घता)));
वर्ण *SHA224_अन्तः(SHA2_CTX *, वर्ण *)
	__attribute__((__bounded__(__minbytes__,2,SHA224_DIGEST_STRING_दीर्घता)));
वर्ण *SHA224File(ध्रुव वर्ण *, वर्ण *)
	__attribute__((__bounded__(__minbytes__,2,SHA224_DIGEST_STRING_दीर्घता)));
वर्ण *SHA224FileChunk(ध्रुव वर्ण *, वर्ण *, off_t, off_t)
	__attribute__((__bounded__(__minbytes__,2,SHA224_DIGEST_STRING_दीर्घता)));
वर्ण *SHA224_दत्त(ध्रुव u_int8_t *, आकार_t, वर्ण *)
	__attribute__((__bounded__(__string__,1,2)))
	__attribute__((__bounded__(__minbytes__,3,SHA224_DIGEST_STRING_दीर्घता)));
#यदि_अन्तः /* 0 */

#यदि_अपरिभाषितम् HAVE_SHA256UPDATE
शून्य SHA256Init(SHA2_CTX *);
शून्य SHA256Transform(u_int32_t state[8], ध्रुव u_int8_t [SHA256_खण्डम्_दीर्घता]);
शून्य SHA256Update(SHA2_CTX *, ध्रुव u_int8_t *, आकार_t)
	__attribute__((__bounded__(__string__,2,3)));
शून्य SHA256Pad(SHA2_CTX *);
शून्य SHA256Final(u_int8_t [SHA256_DIGEST_दीर्घता], SHA2_CTX *)
	__attribute__((__bounded__(__minbytes__,1,SHA256_DIGEST_दीर्घता)));
वर्ण *SHA256_अन्तः(SHA2_CTX *, वर्ण *)
	__attribute__((__bounded__(__minbytes__,2,SHA256_DIGEST_STRING_दीर्घता)));
वर्ण *SHA256File(ध्रुव वर्ण *, वर्ण *)
	__attribute__((__bounded__(__minbytes__,2,SHA256_DIGEST_STRING_दीर्घता)));
वर्ण *SHA256FileChunk(ध्रुव वर्ण *, वर्ण *, off_t, off_t)
	__attribute__((__bounded__(__minbytes__,2,SHA256_DIGEST_STRING_दीर्घता)));
वर्ण *SHA256_दत्त(ध्रुव u_int8_t *, आकार_t, वर्ण *)
	__attribute__((__bounded__(__string__,1,2)))
	__attribute__((__bounded__(__minbytes__,3,SHA256_DIGEST_STRING_दीर्घता)));
#यदि_अन्तः /* HAVE_SHA256UPDATE */

#यदि_अपरिभाषितम् HAVE_SHA384UPDATE
शून्य SHA384Init(SHA2_CTX *);
शून्य SHA384Transform(u_int64_t state[8], ध्रुव u_int8_t [SHA384_खण्डम्_दीर्घता]);
शून्य SHA384Update(SHA2_CTX *, ध्रुव u_int8_t *, आकार_t)
	__attribute__((__bounded__(__string__,2,3)));
शून्य SHA384Pad(SHA2_CTX *);
शून्य SHA384Final(u_int8_t [SHA384_DIGEST_दीर्घता], SHA2_CTX *)
	__attribute__((__bounded__(__minbytes__,1,SHA384_DIGEST_दीर्घता)));
वर्ण *SHA384_अन्तः(SHA2_CTX *, वर्ण *)
	__attribute__((__bounded__(__minbytes__,2,SHA384_DIGEST_STRING_दीर्घता)));
वर्ण *SHA384File(ध्रुव वर्ण *, वर्ण *)
	__attribute__((__bounded__(__minbytes__,2,SHA384_DIGEST_STRING_दीर्घता)));
वर्ण *SHA384FileChunk(ध्रुव वर्ण *, वर्ण *, off_t, off_t)
	__attribute__((__bounded__(__minbytes__,2,SHA384_DIGEST_STRING_दीर्घता)));
वर्ण *SHA384_दत्त(ध्रुव u_int8_t *, आकार_t, वर्ण *)
	__attribute__((__bounded__(__string__,1,2)))
	__attribute__((__bounded__(__minbytes__,3,SHA384_DIGEST_STRING_दीर्घता)));
#यदि_अन्तः /* HAVE_SHA384UPDATE */

#यदि_अपरिभाषितम् HAVE_SHA512UPDATE
शून्य SHA512Init(SHA2_CTX *);
शून्य SHA512Transform(u_int64_t state[8], ध्रुव u_int8_t [SHA512_खण्डम्_दीर्घता]);
शून्य SHA512Update(SHA2_CTX *, ध्रुव u_int8_t *, आकार_t)
	__attribute__((__bounded__(__string__,2,3)));
शून्य SHA512Pad(SHA2_CTX *);
शून्य SHA512Final(u_int8_t [SHA512_DIGEST_दीर्घता], SHA2_CTX *)
	__attribute__((__bounded__(__minbytes__,1,SHA512_DIGEST_दीर्घता)));
वर्ण *SHA512_अन्तः(SHA2_CTX *, वर्ण *)
	__attribute__((__bounded__(__minbytes__,2,SHA512_DIGEST_STRING_दीर्घता)));
वर्ण *SHA512File(ध्रुव वर्ण *, वर्ण *)
	__attribute__((__bounded__(__minbytes__,2,SHA512_DIGEST_STRING_दीर्घता)));
वर्ण *SHA512FileChunk(ध्रुव वर्ण *, वर्ण *, off_t, off_t)
	__attribute__((__bounded__(__minbytes__,2,SHA512_DIGEST_STRING_दीर्घता)));
वर्ण *SHA512_दत्त(ध्रुव u_int8_t *, आकार_t, वर्ण *)
	__attribute__((__bounded__(__string__,1,2)))
	__attribute__((__bounded__(__minbytes__,3,SHA512_DIGEST_STRING_दीर्घता)));
#यदि_अन्तः /* HAVE_SHA512UPDATE */

#यदि 0
शून्य SHA512_256Init(SHA2_CTX *);
शून्य SHA512_256Transform(u_int64_t state[8], ध्रुव u_int8_t [SHA512_256_खण्डम्_दीर्घता]);
शून्य SHA512_256Update(SHA2_CTX *, ध्रुव u_int8_t *, आकार_t)
	__attribute__((__bounded__(__string__,2,3)));
शून्य SHA512_256Pad(SHA2_CTX *);
शून्य SHA512_256Final(u_int8_t [SHA512_256_DIGEST_दीर्घता], SHA2_CTX *)
	__attribute__((__bounded__(__minbytes__,1,SHA512_256_DIGEST_दीर्घता)));
वर्ण *SHA512_256_अन्तः(SHA2_CTX *, वर्ण *)
	__attribute__((__bounded__(__minbytes__,2,SHA512_256_DIGEST_STRING_दीर्घता)));
वर्ण *SHA512_256File(ध्रुव वर्ण *, वर्ण *)
	__attribute__((__bounded__(__minbytes__,2,SHA512_256_DIGEST_STRING_दीर्घता)));
वर्ण *SHA512_256FileChunk(ध्रुव वर्ण *, वर्ण *, off_t, off_t)
	__attribute__((__bounded__(__minbytes__,2,SHA512_256_DIGEST_STRING_दीर्घता)));
वर्ण *SHA512_256_दत्त(ध्रुव u_int8_t *, आकार_t, वर्ण *)
	__attribute__((__bounded__(__string__,1,2)))
	__attribute__((__bounded__(__minbytes__,3,SHA512_256_DIGEST_STRING_दीर्घता)));
__END_DECLS
#यदि_अन्तः /* 0 */

#यदि_अन्तः /* HAVE_SHA{256,384,512}UPDATE */

#यदि_अन्तः /* _SSHSHA2_H */
