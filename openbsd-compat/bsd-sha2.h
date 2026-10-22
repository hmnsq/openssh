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

#ifndef _SSHSHA2_H
#define _SSHSHA2_H

#अन्तर्भाव "includes.h"

#जर !defined(HAVE_SHA256UPDATE) || !defined(HAVE_SHA384UPDATE) || \
    !defined(HAVE_SHA512UPDATE)

/*** SHA-256/384/512 Various Length Definitions ***********************/
#define SHA224_BLOCK_LENGTH		64
#define SHA224_DIGEST_LENGTH		28
#define SHA224_DIGEST_STRING_LENGTH	(SHA224_DIGEST_LENGTH * 2 + 1)
#define SHA256_BLOCK_LENGTH		64
#define SHA256_DIGEST_LENGTH		32
#define SHA256_DIGEST_STRING_LENGTH	(SHA256_DIGEST_LENGTH * 2 + 1)
#define SHA384_BLOCK_LENGTH		128
#define SHA384_DIGEST_LENGTH		48
#define SHA384_DIGEST_STRING_LENGTH	(SHA384_DIGEST_LENGTH * 2 + 1)
#define SHA512_BLOCK_LENGTH		128
#define SHA512_DIGEST_LENGTH		64
#define SHA512_DIGEST_STRING_LENGTH	(SHA512_DIGEST_LENGTH * 2 + 1)
#define SHA512_256_BLOCK_LENGTH		128
#define SHA512_256_DIGEST_LENGTH	32
#define SHA512_256_DIGEST_STRING_LENGTH	(SHA512_256_DIGEST_LENGTH * 2 + 1)


/*** SHA-224/256/384/512 Context Structure *******************************/
प्रकारव्याख्या संरचना _SHA2_CTX {
	संघ {
		u_int32_t	st32[8];
		u_int64_t	st64[8];
	} state;
	u_int64_t	bitcount[2];
	u_int8_t	buffer[SHA512_BLOCK_LENGTH];
} SHA2_CTX;

#जर 0
__BEGIN_DECLS
शून्य SHA224Init(SHA2_CTX *);
शून्य SHA224Transform(u_int32_t state[8], स्थिरांक u_int8_t [SHA224_BLOCK_LENGTH]);
शून्य SHA224Update(SHA2_CTX *, स्थिरांक u_int8_t *, माप_प्रकार)
	__attribute__((__bounded__(__string__,2,3)));
शून्य SHA224Pad(SHA2_CTX *);
शून्य SHA224Final(u_int8_t [SHA224_DIGEST_LENGTH], SHA2_CTX *)
	__attribute__((__bounded__(__minbytes__,1,SHA224_DIGEST_LENGTH)));
अक्षर *SHA224End(SHA2_CTX *, अक्षर *)
	__attribute__((__bounded__(__minbytes__,2,SHA224_DIGEST_STRING_LENGTH)));
अक्षर *SHA224File(स्थिरांक अक्षर *, अक्षर *)
	__attribute__((__bounded__(__minbytes__,2,SHA224_DIGEST_STRING_LENGTH)));
अक्षर *SHA224FileChunk(स्थिरांक अक्षर *, अक्षर *, off_t, off_t)
	__attribute__((__bounded__(__minbytes__,2,SHA224_DIGEST_STRING_LENGTH)));
अक्षर *SHA224Data(स्थिरांक u_int8_t *, माप_प्रकार, अक्षर *)
	__attribute__((__bounded__(__string__,1,2)))
	__attribute__((__bounded__(__minbytes__,3,SHA224_DIGEST_STRING_LENGTH)));
#endif /* 0 */

#ifndef HAVE_SHA256UPDATE
शून्य SHA256Init(SHA2_CTX *);
शून्य SHA256Transform(u_int32_t state[8], स्थिरांक u_int8_t [SHA256_BLOCK_LENGTH]);
शून्य SHA256Update(SHA2_CTX *, स्थिरांक u_int8_t *, माप_प्रकार)
	__attribute__((__bounded__(__string__,2,3)));
शून्य SHA256Pad(SHA2_CTX *);
शून्य SHA256Final(u_int8_t [SHA256_DIGEST_LENGTH], SHA2_CTX *)
	__attribute__((__bounded__(__minbytes__,1,SHA256_DIGEST_LENGTH)));
अक्षर *SHA256End(SHA2_CTX *, अक्षर *)
	__attribute__((__bounded__(__minbytes__,2,SHA256_DIGEST_STRING_LENGTH)));
अक्षर *SHA256File(स्थिरांक अक्षर *, अक्षर *)
	__attribute__((__bounded__(__minbytes__,2,SHA256_DIGEST_STRING_LENGTH)));
अक्षर *SHA256FileChunk(स्थिरांक अक्षर *, अक्षर *, off_t, off_t)
	__attribute__((__bounded__(__minbytes__,2,SHA256_DIGEST_STRING_LENGTH)));
अक्षर *SHA256Data(स्थिरांक u_int8_t *, माप_प्रकार, अक्षर *)
	__attribute__((__bounded__(__string__,1,2)))
	__attribute__((__bounded__(__minbytes__,3,SHA256_DIGEST_STRING_LENGTH)));
#endif /* HAVE_SHA256UPDATE */

#ifndef HAVE_SHA384UPDATE
शून्य SHA384Init(SHA2_CTX *);
शून्य SHA384Transform(u_int64_t state[8], स्थिरांक u_int8_t [SHA384_BLOCK_LENGTH]);
शून्य SHA384Update(SHA2_CTX *, स्थिरांक u_int8_t *, माप_प्रकार)
	__attribute__((__bounded__(__string__,2,3)));
शून्य SHA384Pad(SHA2_CTX *);
शून्य SHA384Final(u_int8_t [SHA384_DIGEST_LENGTH], SHA2_CTX *)
	__attribute__((__bounded__(__minbytes__,1,SHA384_DIGEST_LENGTH)));
अक्षर *SHA384End(SHA2_CTX *, अक्षर *)
	__attribute__((__bounded__(__minbytes__,2,SHA384_DIGEST_STRING_LENGTH)));
अक्षर *SHA384File(स्थिरांक अक्षर *, अक्षर *)
	__attribute__((__bounded__(__minbytes__,2,SHA384_DIGEST_STRING_LENGTH)));
अक्षर *SHA384FileChunk(स्थिरांक अक्षर *, अक्षर *, off_t, off_t)
	__attribute__((__bounded__(__minbytes__,2,SHA384_DIGEST_STRING_LENGTH)));
अक्षर *SHA384Data(स्थिरांक u_int8_t *, माप_प्रकार, अक्षर *)
	__attribute__((__bounded__(__string__,1,2)))
	__attribute__((__bounded__(__minbytes__,3,SHA384_DIGEST_STRING_LENGTH)));
#endif /* HAVE_SHA384UPDATE */

#ifndef HAVE_SHA512UPDATE
शून्य SHA512Init(SHA2_CTX *);
शून्य SHA512Transform(u_int64_t state[8], स्थिरांक u_int8_t [SHA512_BLOCK_LENGTH]);
शून्य SHA512Update(SHA2_CTX *, स्थिरांक u_int8_t *, माप_प्रकार)
	__attribute__((__bounded__(__string__,2,3)));
शून्य SHA512Pad(SHA2_CTX *);
शून्य SHA512Final(u_int8_t [SHA512_DIGEST_LENGTH], SHA2_CTX *)
	__attribute__((__bounded__(__minbytes__,1,SHA512_DIGEST_LENGTH)));
अक्षर *SHA512End(SHA2_CTX *, अक्षर *)
	__attribute__((__bounded__(__minbytes__,2,SHA512_DIGEST_STRING_LENGTH)));
अक्षर *SHA512File(स्थिरांक अक्षर *, अक्षर *)
	__attribute__((__bounded__(__minbytes__,2,SHA512_DIGEST_STRING_LENGTH)));
अक्षर *SHA512FileChunk(स्थिरांक अक्षर *, अक्षर *, off_t, off_t)
	__attribute__((__bounded__(__minbytes__,2,SHA512_DIGEST_STRING_LENGTH)));
अक्षर *SHA512Data(स्थिरांक u_int8_t *, माप_प्रकार, अक्षर *)
	__attribute__((__bounded__(__string__,1,2)))
	__attribute__((__bounded__(__minbytes__,3,SHA512_DIGEST_STRING_LENGTH)));
#endif /* HAVE_SHA512UPDATE */

#जर 0
शून्य SHA512_256Init(SHA2_CTX *);
शून्य SHA512_256Transform(u_int64_t state[8], स्थिरांक u_int8_t [SHA512_256_BLOCK_LENGTH]);
शून्य SHA512_256Update(SHA2_CTX *, स्थिरांक u_int8_t *, माप_प्रकार)
	__attribute__((__bounded__(__string__,2,3)));
शून्य SHA512_256Pad(SHA2_CTX *);
शून्य SHA512_256Final(u_int8_t [SHA512_256_DIGEST_LENGTH], SHA2_CTX *)
	__attribute__((__bounded__(__minbytes__,1,SHA512_256_DIGEST_LENGTH)));
अक्षर *SHA512_256End(SHA2_CTX *, अक्षर *)
	__attribute__((__bounded__(__minbytes__,2,SHA512_256_DIGEST_STRING_LENGTH)));
अक्षर *SHA512_256File(स्थिरांक अक्षर *, अक्षर *)
	__attribute__((__bounded__(__minbytes__,2,SHA512_256_DIGEST_STRING_LENGTH)));
अक्षर *SHA512_256FileChunk(स्थिरांक अक्षर *, अक्षर *, off_t, off_t)
	__attribute__((__bounded__(__minbytes__,2,SHA512_256_DIGEST_STRING_LENGTH)));
अक्षर *SHA512_256Data(स्थिरांक u_int8_t *, माप_प्रकार, अक्षर *)
	__attribute__((__bounded__(__string__,1,2)))
	__attribute__((__bounded__(__minbytes__,3,SHA512_256_DIGEST_STRING_LENGTH)));
__END_DECLS
#endif /* 0 */

#endif /* HAVE_SHA{256,384,512}UPDATE */

#endif /* _SSHSHA2_H */
