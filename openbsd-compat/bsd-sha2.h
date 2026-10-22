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

#شامل "includes.h"

#اگر !defined(HAVE_SHA256UPDATE) || !defined(HAVE_SHA384UPDATE) || \
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
تعریفنوع ساختار _SHA2_CTX {
	اجتماع {
		u_int32_t	st32[8];
		u_int64_t	st64[8];
	} state;
	u_int64_t	bitcount[2];
	u_int8_t	buffer[SHA512_BLOCK_LENGTH];
} SHA2_CTX;

#اگر 0
__BEGIN_DECLS
تهی SHA224Init(SHA2_CTX *);
تهی SHA224Transform(u_int32_t state[8], ثابت u_int8_t [SHA224_BLOCK_LENGTH]);
تهی SHA224Update(SHA2_CTX *, ثابت u_int8_t *, size_t)
	__attribute__((__bounded__(__string__,2,3)));
تهی SHA224Pad(SHA2_CTX *);
تهی SHA224Final(u_int8_t [SHA224_DIGEST_LENGTH], SHA2_CTX *)
	__attribute__((__bounded__(__minbytes__,1,SHA224_DIGEST_LENGTH)));
نویسه *SHA224End(SHA2_CTX *, نویسه *)
	__attribute__((__bounded__(__minbytes__,2,SHA224_DIGEST_STRING_LENGTH)));
نویسه *SHA224File(ثابت نویسه *, نویسه *)
	__attribute__((__bounded__(__minbytes__,2,SHA224_DIGEST_STRING_LENGTH)));
نویسه *SHA224FileChunk(ثابت نویسه *, نویسه *, off_t, off_t)
	__attribute__((__bounded__(__minbytes__,2,SHA224_DIGEST_STRING_LENGTH)));
نویسه *SHA224Data(ثابت u_int8_t *, size_t, نویسه *)
	__attribute__((__bounded__(__string__,1,2)))
	__attribute__((__bounded__(__minbytes__,3,SHA224_DIGEST_STRING_LENGTH)));
#endif /* 0 */

#ifndef HAVE_SHA256UPDATE
تهی SHA256Init(SHA2_CTX *);
تهی SHA256Transform(u_int32_t state[8], ثابت u_int8_t [SHA256_BLOCK_LENGTH]);
تهی SHA256Update(SHA2_CTX *, ثابت u_int8_t *, size_t)
	__attribute__((__bounded__(__string__,2,3)));
تهی SHA256Pad(SHA2_CTX *);
تهی SHA256Final(u_int8_t [SHA256_DIGEST_LENGTH], SHA2_CTX *)
	__attribute__((__bounded__(__minbytes__,1,SHA256_DIGEST_LENGTH)));
نویسه *SHA256End(SHA2_CTX *, نویسه *)
	__attribute__((__bounded__(__minbytes__,2,SHA256_DIGEST_STRING_LENGTH)));
نویسه *SHA256File(ثابت نویسه *, نویسه *)
	__attribute__((__bounded__(__minbytes__,2,SHA256_DIGEST_STRING_LENGTH)));
نویسه *SHA256FileChunk(ثابت نویسه *, نویسه *, off_t, off_t)
	__attribute__((__bounded__(__minbytes__,2,SHA256_DIGEST_STRING_LENGTH)));
نویسه *SHA256Data(ثابت u_int8_t *, size_t, نویسه *)
	__attribute__((__bounded__(__string__,1,2)))
	__attribute__((__bounded__(__minbytes__,3,SHA256_DIGEST_STRING_LENGTH)));
#endif /* HAVE_SHA256UPDATE */

#ifndef HAVE_SHA384UPDATE
تهی SHA384Init(SHA2_CTX *);
تهی SHA384Transform(u_int64_t state[8], ثابت u_int8_t [SHA384_BLOCK_LENGTH]);
تهی SHA384Update(SHA2_CTX *, ثابت u_int8_t *, size_t)
	__attribute__((__bounded__(__string__,2,3)));
تهی SHA384Pad(SHA2_CTX *);
تهی SHA384Final(u_int8_t [SHA384_DIGEST_LENGTH], SHA2_CTX *)
	__attribute__((__bounded__(__minbytes__,1,SHA384_DIGEST_LENGTH)));
نویسه *SHA384End(SHA2_CTX *, نویسه *)
	__attribute__((__bounded__(__minbytes__,2,SHA384_DIGEST_STRING_LENGTH)));
نویسه *SHA384File(ثابت نویسه *, نویسه *)
	__attribute__((__bounded__(__minbytes__,2,SHA384_DIGEST_STRING_LENGTH)));
نویسه *SHA384FileChunk(ثابت نویسه *, نویسه *, off_t, off_t)
	__attribute__((__bounded__(__minbytes__,2,SHA384_DIGEST_STRING_LENGTH)));
نویسه *SHA384Data(ثابت u_int8_t *, size_t, نویسه *)
	__attribute__((__bounded__(__string__,1,2)))
	__attribute__((__bounded__(__minbytes__,3,SHA384_DIGEST_STRING_LENGTH)));
#endif /* HAVE_SHA384UPDATE */

#ifndef HAVE_SHA512UPDATE
تهی SHA512Init(SHA2_CTX *);
تهی SHA512Transform(u_int64_t state[8], ثابت u_int8_t [SHA512_BLOCK_LENGTH]);
تهی SHA512Update(SHA2_CTX *, ثابت u_int8_t *, size_t)
	__attribute__((__bounded__(__string__,2,3)));
تهی SHA512Pad(SHA2_CTX *);
تهی SHA512Final(u_int8_t [SHA512_DIGEST_LENGTH], SHA2_CTX *)
	__attribute__((__bounded__(__minbytes__,1,SHA512_DIGEST_LENGTH)));
نویسه *SHA512End(SHA2_CTX *, نویسه *)
	__attribute__((__bounded__(__minbytes__,2,SHA512_DIGEST_STRING_LENGTH)));
نویسه *SHA512File(ثابت نویسه *, نویسه *)
	__attribute__((__bounded__(__minbytes__,2,SHA512_DIGEST_STRING_LENGTH)));
نویسه *SHA512FileChunk(ثابت نویسه *, نویسه *, off_t, off_t)
	__attribute__((__bounded__(__minbytes__,2,SHA512_DIGEST_STRING_LENGTH)));
نویسه *SHA512Data(ثابت u_int8_t *, size_t, نویسه *)
	__attribute__((__bounded__(__string__,1,2)))
	__attribute__((__bounded__(__minbytes__,3,SHA512_DIGEST_STRING_LENGTH)));
#endif /* HAVE_SHA512UPDATE */

#اگر 0
تهی SHA512_256Init(SHA2_CTX *);
تهی SHA512_256Transform(u_int64_t state[8], ثابت u_int8_t [SHA512_256_BLOCK_LENGTH]);
تهی SHA512_256Update(SHA2_CTX *, ثابت u_int8_t *, size_t)
	__attribute__((__bounded__(__string__,2,3)));
تهی SHA512_256Pad(SHA2_CTX *);
تهی SHA512_256Final(u_int8_t [SHA512_256_DIGEST_LENGTH], SHA2_CTX *)
	__attribute__((__bounded__(__minbytes__,1,SHA512_256_DIGEST_LENGTH)));
نویسه *SHA512_256End(SHA2_CTX *, نویسه *)
	__attribute__((__bounded__(__minbytes__,2,SHA512_256_DIGEST_STRING_LENGTH)));
نویسه *SHA512_256File(ثابت نویسه *, نویسه *)
	__attribute__((__bounded__(__minbytes__,2,SHA512_256_DIGEST_STRING_LENGTH)));
نویسه *SHA512_256FileChunk(ثابت نویسه *, نویسه *, off_t, off_t)
	__attribute__((__bounded__(__minbytes__,2,SHA512_256_DIGEST_STRING_LENGTH)));
نویسه *SHA512_256Data(ثابت u_int8_t *, size_t, نویسه *)
	__attribute__((__bounded__(__string__,1,2)))
	__attribute__((__bounded__(__minbytes__,3,SHA512_256_DIGEST_STRING_LENGTH)));
__END_DECLS
#endif /* 0 */

#endif /* HAVE_SHA{256,384,512}UPDATE */

#endif /* _SSHSHA2_H */
