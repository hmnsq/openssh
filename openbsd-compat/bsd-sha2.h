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

#جے_بنا_تعریف _SSHSHA2_H
#تعریف_کرو _SSHSHA2_H

#ضمن "includes.h"

#إذا !defined(HAVE_SHA256UPDATE) || !defined(HAVE_SHA384UPDATE) || \
    !defined(HAVE_SHA512UPDATE)

/*** SHA-256/384/512 Various Length Definitions ***********************/
#تعریف_کرو SHA224_بلاک_لمائی		64
#تعریف_کرو SHA224_DIGEST_لمائی		28
#تعریف_کرو SHA224_DIGEST_STRING_لمائی	(SHA224_DIGEST_لمائی * 2 + 1)
#تعریف_کرو SHA256_بلاک_لمائی		64
#تعریف_کرو SHA256_DIGEST_لمائی		32
#تعریف_کرو SHA256_DIGEST_STRING_لمائی	(SHA256_DIGEST_لمائی * 2 + 1)
#تعریف_کرو SHA384_بلاک_لمائی		128
#تعریف_کرو SHA384_DIGEST_لمائی		48
#تعریف_کرو SHA384_DIGEST_STRING_لمائی	(SHA384_DIGEST_لمائی * 2 + 1)
#تعریف_کرو SHA512_بلاک_لمائی		128
#تعریف_کرو SHA512_DIGEST_لمائی		64
#تعریف_کرو SHA512_DIGEST_STRING_لمائی	(SHA512_DIGEST_لمائی * 2 + 1)
#تعریف_کرو SHA512_256_بلاک_لمائی		128
#تعریف_کرو SHA512_256_DIGEST_لمائی	32
#تعریف_کرو SHA512_256_DIGEST_STRING_لمائی	(SHA512_256_DIGEST_لمائی * 2 + 1)


/*** SHA-224/256/384/512 Context Structure *******************************/
تعريفنوع بنية _SHA2_CTX {
	اتحاد {
		u_int32_t	st32[8];
		u_int64_t	st64[8];
	} state;
	u_int64_t	bitcount[2];
	u_int8_t	بفر[SHA512_بلاک_لمائی];
} SHA2_CTX;

#إذا 0
__BEGIN_DECLS
فراغ SHA224Init(SHA2_CTX *);
فراغ SHA224Transform(u_int32_t state[8], ثابت u_int8_t [SHA224_بلاک_لمائی]);
فراغ SHA224Update(SHA2_CTX *, ثابت u_int8_t *, ناپ_t)
	__attribute__((__bounded__(__string__,2,3)));
فراغ SHA224Pad(SHA2_CTX *);
فراغ SHA224Final(u_int8_t [SHA224_DIGEST_لمائی], SHA2_CTX *)
	__attribute__((__bounded__(__minbytes__,1,SHA224_DIGEST_لمائی)));
حرف *SHA224_سرا(SHA2_CTX *, حرف *)
	__attribute__((__bounded__(__minbytes__,2,SHA224_DIGEST_STRING_لمائی)));
حرف *SHA224File(ثابت حرف *, حرف *)
	__attribute__((__bounded__(__minbytes__,2,SHA224_DIGEST_STRING_لمائی)));
حرف *SHA224FileChunk(ثابت حرف *, حرف *, off_t, off_t)
	__attribute__((__bounded__(__minbytes__,2,SHA224_DIGEST_STRING_لمائی)));
حرف *SHA224_انکڑے(ثابت u_int8_t *, ناپ_t, حرف *)
	__attribute__((__bounded__(__string__,1,2)))
	__attribute__((__bounded__(__minbytes__,3,SHA224_DIGEST_STRING_لمائی)));
#جے_انت /* 0 */

#جے_بنا_تعریف HAVE_SHA256UPDATE
فراغ SHA256Init(SHA2_CTX *);
فراغ SHA256Transform(u_int32_t state[8], ثابت u_int8_t [SHA256_بلاک_لمائی]);
فراغ SHA256Update(SHA2_CTX *, ثابت u_int8_t *, ناپ_t)
	__attribute__((__bounded__(__string__,2,3)));
فراغ SHA256Pad(SHA2_CTX *);
فراغ SHA256Final(u_int8_t [SHA256_DIGEST_لمائی], SHA2_CTX *)
	__attribute__((__bounded__(__minbytes__,1,SHA256_DIGEST_لمائی)));
حرف *SHA256_سرا(SHA2_CTX *, حرف *)
	__attribute__((__bounded__(__minbytes__,2,SHA256_DIGEST_STRING_لمائی)));
حرف *SHA256File(ثابت حرف *, حرف *)
	__attribute__((__bounded__(__minbytes__,2,SHA256_DIGEST_STRING_لمائی)));
حرف *SHA256FileChunk(ثابت حرف *, حرف *, off_t, off_t)
	__attribute__((__bounded__(__minbytes__,2,SHA256_DIGEST_STRING_لمائی)));
حرف *SHA256_انکڑے(ثابت u_int8_t *, ناپ_t, حرف *)
	__attribute__((__bounded__(__string__,1,2)))
	__attribute__((__bounded__(__minbytes__,3,SHA256_DIGEST_STRING_لمائی)));
#جے_انت /* HAVE_SHA256UPDATE */

#جے_بنا_تعریف HAVE_SHA384UPDATE
فراغ SHA384Init(SHA2_CTX *);
فراغ SHA384Transform(u_int64_t state[8], ثابت u_int8_t [SHA384_بلاک_لمائی]);
فراغ SHA384Update(SHA2_CTX *, ثابت u_int8_t *, ناپ_t)
	__attribute__((__bounded__(__string__,2,3)));
فراغ SHA384Pad(SHA2_CTX *);
فراغ SHA384Final(u_int8_t [SHA384_DIGEST_لمائی], SHA2_CTX *)
	__attribute__((__bounded__(__minbytes__,1,SHA384_DIGEST_لمائی)));
حرف *SHA384_سرا(SHA2_CTX *, حرف *)
	__attribute__((__bounded__(__minbytes__,2,SHA384_DIGEST_STRING_لمائی)));
حرف *SHA384File(ثابت حرف *, حرف *)
	__attribute__((__bounded__(__minbytes__,2,SHA384_DIGEST_STRING_لمائی)));
حرف *SHA384FileChunk(ثابت حرف *, حرف *, off_t, off_t)
	__attribute__((__bounded__(__minbytes__,2,SHA384_DIGEST_STRING_لمائی)));
حرف *SHA384_انکڑے(ثابت u_int8_t *, ناپ_t, حرف *)
	__attribute__((__bounded__(__string__,1,2)))
	__attribute__((__bounded__(__minbytes__,3,SHA384_DIGEST_STRING_لمائی)));
#جے_انت /* HAVE_SHA384UPDATE */

#جے_بنا_تعریف HAVE_SHA512UPDATE
فراغ SHA512Init(SHA2_CTX *);
فراغ SHA512Transform(u_int64_t state[8], ثابت u_int8_t [SHA512_بلاک_لمائی]);
فراغ SHA512Update(SHA2_CTX *, ثابت u_int8_t *, ناپ_t)
	__attribute__((__bounded__(__string__,2,3)));
فراغ SHA512Pad(SHA2_CTX *);
فراغ SHA512Final(u_int8_t [SHA512_DIGEST_لمائی], SHA2_CTX *)
	__attribute__((__bounded__(__minbytes__,1,SHA512_DIGEST_لمائی)));
حرف *SHA512_سرا(SHA2_CTX *, حرف *)
	__attribute__((__bounded__(__minbytes__,2,SHA512_DIGEST_STRING_لمائی)));
حرف *SHA512File(ثابت حرف *, حرف *)
	__attribute__((__bounded__(__minbytes__,2,SHA512_DIGEST_STRING_لمائی)));
حرف *SHA512FileChunk(ثابت حرف *, حرف *, off_t, off_t)
	__attribute__((__bounded__(__minbytes__,2,SHA512_DIGEST_STRING_لمائی)));
حرف *SHA512_انکڑے(ثابت u_int8_t *, ناپ_t, حرف *)
	__attribute__((__bounded__(__string__,1,2)))
	__attribute__((__bounded__(__minbytes__,3,SHA512_DIGEST_STRING_لمائی)));
#جے_انت /* HAVE_SHA512UPDATE */

#إذا 0
فراغ SHA512_256Init(SHA2_CTX *);
فراغ SHA512_256Transform(u_int64_t state[8], ثابت u_int8_t [SHA512_256_بلاک_لمائی]);
فراغ SHA512_256Update(SHA2_CTX *, ثابت u_int8_t *, ناپ_t)
	__attribute__((__bounded__(__string__,2,3)));
فراغ SHA512_256Pad(SHA2_CTX *);
فراغ SHA512_256Final(u_int8_t [SHA512_256_DIGEST_لمائی], SHA2_CTX *)
	__attribute__((__bounded__(__minbytes__,1,SHA512_256_DIGEST_لمائی)));
حرف *SHA512_256_سرا(SHA2_CTX *, حرف *)
	__attribute__((__bounded__(__minbytes__,2,SHA512_256_DIGEST_STRING_لمائی)));
حرف *SHA512_256File(ثابت حرف *, حرف *)
	__attribute__((__bounded__(__minbytes__,2,SHA512_256_DIGEST_STRING_لمائی)));
حرف *SHA512_256FileChunk(ثابت حرف *, حرف *, off_t, off_t)
	__attribute__((__bounded__(__minbytes__,2,SHA512_256_DIGEST_STRING_لمائی)));
حرف *SHA512_256_انکڑے(ثابت u_int8_t *, ناپ_t, حرف *)
	__attribute__((__bounded__(__string__,1,2)))
	__attribute__((__bounded__(__minbytes__,3,SHA512_256_DIGEST_STRING_لمائی)));
__END_DECLS
#جے_انت /* 0 */

#جے_انت /* HAVE_SHA{256,384,512}UPDATE */

#جے_انت /* _SSHSHA2_H */
