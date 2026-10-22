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

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ _SSHSHA2_H
#ವ್ಯಾಖ್ಯಾನಿಸು _SSHSHA2_H

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಆದರೆ !defined(HAVE_SHA256UPDATE) || !defined(HAVE_SHA384UPDATE) || \
    !defined(HAVE_SHA512UPDATE)

/*** SHA-256/384/512 Various Length Definitions ***********************/
#ವ್ಯಾಖ್ಯಾನಿಸು SHA224_ಖಂಡ_ಉದ್ದಳತೆ		64
#ವ್ಯಾಖ್ಯಾನಿಸು SHA224_DIGEST_ಉದ್ದಳತೆ		28
#ವ್ಯಾಖ್ಯಾನಿಸು SHA224_DIGEST_STRING_ಉದ್ದಳತೆ	(SHA224_DIGEST_ಉದ್ದಳತೆ * 2 + 1)
#ವ್ಯಾಖ್ಯಾನಿಸು SHA256_ಖಂಡ_ಉದ್ದಳತೆ		64
#ವ್ಯಾಖ್ಯಾನಿಸು SHA256_DIGEST_ಉದ್ದಳತೆ		32
#ವ್ಯಾಖ್ಯಾನಿಸು SHA256_DIGEST_STRING_ಉದ್ದಳತೆ	(SHA256_DIGEST_ಉದ್ದಳತೆ * 2 + 1)
#ವ್ಯಾಖ್ಯಾನಿಸು SHA384_ಖಂಡ_ಉದ್ದಳತೆ		128
#ವ್ಯಾಖ್ಯಾನಿಸು SHA384_DIGEST_ಉದ್ದಳತೆ		48
#ವ್ಯಾಖ್ಯಾನಿಸು SHA384_DIGEST_STRING_ಉದ್ದಳತೆ	(SHA384_DIGEST_ಉದ್ದಳತೆ * 2 + 1)
#ವ್ಯಾಖ್ಯಾನಿಸು SHA512_ಖಂಡ_ಉದ್ದಳತೆ		128
#ವ್ಯಾಖ್ಯಾನಿಸು SHA512_DIGEST_ಉದ್ದಳತೆ		64
#ವ್ಯಾಖ್ಯಾನಿಸು SHA512_DIGEST_STRING_ಉದ್ದಳತೆ	(SHA512_DIGEST_ಉದ್ದಳತೆ * 2 + 1)
#ವ್ಯಾಖ್ಯಾನಿಸು SHA512_256_ಖಂಡ_ಉದ್ದಳತೆ		128
#ವ್ಯಾಖ್ಯಾನಿಸು SHA512_256_DIGEST_ಉದ್ದಳತೆ	32
#ವ್ಯಾಖ್ಯಾನಿಸು SHA512_256_DIGEST_STRING_ಉದ್ದಳತೆ	(SHA512_256_DIGEST_ಉದ್ದಳತೆ * 2 + 1)


/*** SHA-224/256/384/512 Context Structure *******************************/
ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ರಚನೆ _SHA2_CTX {
	ಒಕ್ಕೂಟ {
		u_int32_t	st32[8];
		u_int64_t	st64[8];
	} state;
	u_int64_t	bitcount[2];
	u_int8_t	ಬಫರ್[SHA512_ಖಂಡ_ಉದ್ದಳತೆ];
} SHA2_CTX;

#ಆದರೆ 0
__BEGIN_DECLS
ಶೂನ್ಯ SHA224Init(SHA2_CTX *);
ಶೂನ್ಯ SHA224Transform(u_int32_t state[8], ಸ್ಥಿರಾಂಕ u_int8_t [SHA224_ಖಂಡ_ಉದ್ದಳತೆ]);
ಶೂನ್ಯ SHA224Update(SHA2_CTX *, ಸ್ಥಿರಾಂಕ u_int8_t *, ಗಾತ್ರ_t)
	__attribute__((__bounded__(__string__,2,3)));
ಶೂನ್ಯ SHA224Pad(SHA2_CTX *);
ಶೂನ್ಯ SHA224Final(u_int8_t [SHA224_DIGEST_ಉದ್ದಳತೆ], SHA2_CTX *)
	__attribute__((__bounded__(__minbytes__,1,SHA224_DIGEST_ಉದ್ದಳತೆ)));
ಅಕ್ಷರ *SHA224_ಕೊನೆ(SHA2_CTX *, ಅಕ್ಷರ *)
	__attribute__((__bounded__(__minbytes__,2,SHA224_DIGEST_STRING_ಉದ್ದಳತೆ)));
ಅಕ್ಷರ *SHA224File(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಅಕ್ಷರ *)
	__attribute__((__bounded__(__minbytes__,2,SHA224_DIGEST_STRING_ಉದ್ದಳತೆ)));
ಅಕ್ಷರ *SHA224FileChunk(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಅಕ್ಷರ *, off_t, off_t)
	__attribute__((__bounded__(__minbytes__,2,SHA224_DIGEST_STRING_ಉದ್ದಳತೆ)));
ಅಕ್ಷರ *SHA224_ದತ್ತಾಂಶ(ಸ್ಥಿರಾಂಕ u_int8_t *, ಗಾತ್ರ_t, ಅಕ್ಷರ *)
	__attribute__((__bounded__(__string__,1,2)))
	__attribute__((__bounded__(__minbytes__,3,SHA224_DIGEST_STRING_ಉದ್ದಳತೆ)));
#ಆದರೆ_ಅಂತ್ಯ /* 0 */

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_SHA256UPDATE
ಶೂನ್ಯ SHA256Init(SHA2_CTX *);
ಶೂನ್ಯ SHA256Transform(u_int32_t state[8], ಸ್ಥಿರಾಂಕ u_int8_t [SHA256_ಖಂಡ_ಉದ್ದಳತೆ]);
ಶೂನ್ಯ SHA256Update(SHA2_CTX *, ಸ್ಥಿರಾಂಕ u_int8_t *, ಗಾತ್ರ_t)
	__attribute__((__bounded__(__string__,2,3)));
ಶೂನ್ಯ SHA256Pad(SHA2_CTX *);
ಶೂನ್ಯ SHA256Final(u_int8_t [SHA256_DIGEST_ಉದ್ದಳತೆ], SHA2_CTX *)
	__attribute__((__bounded__(__minbytes__,1,SHA256_DIGEST_ಉದ್ದಳತೆ)));
ಅಕ್ಷರ *SHA256_ಕೊನೆ(SHA2_CTX *, ಅಕ್ಷರ *)
	__attribute__((__bounded__(__minbytes__,2,SHA256_DIGEST_STRING_ಉದ್ದಳತೆ)));
ಅಕ್ಷರ *SHA256File(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಅಕ್ಷರ *)
	__attribute__((__bounded__(__minbytes__,2,SHA256_DIGEST_STRING_ಉದ್ದಳತೆ)));
ಅಕ್ಷರ *SHA256FileChunk(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಅಕ್ಷರ *, off_t, off_t)
	__attribute__((__bounded__(__minbytes__,2,SHA256_DIGEST_STRING_ಉದ್ದಳತೆ)));
ಅಕ್ಷರ *SHA256_ದತ್ತಾಂಶ(ಸ್ಥಿರಾಂಕ u_int8_t *, ಗಾತ್ರ_t, ಅಕ್ಷರ *)
	__attribute__((__bounded__(__string__,1,2)))
	__attribute__((__bounded__(__minbytes__,3,SHA256_DIGEST_STRING_ಉದ್ದಳತೆ)));
#ಆದರೆ_ಅಂತ್ಯ /* HAVE_SHA256UPDATE */

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_SHA384UPDATE
ಶೂನ್ಯ SHA384Init(SHA2_CTX *);
ಶೂನ್ಯ SHA384Transform(u_int64_t state[8], ಸ್ಥಿರಾಂಕ u_int8_t [SHA384_ಖಂಡ_ಉದ್ದಳತೆ]);
ಶೂನ್ಯ SHA384Update(SHA2_CTX *, ಸ್ಥಿರಾಂಕ u_int8_t *, ಗಾತ್ರ_t)
	__attribute__((__bounded__(__string__,2,3)));
ಶೂನ್ಯ SHA384Pad(SHA2_CTX *);
ಶೂನ್ಯ SHA384Final(u_int8_t [SHA384_DIGEST_ಉದ್ದಳತೆ], SHA2_CTX *)
	__attribute__((__bounded__(__minbytes__,1,SHA384_DIGEST_ಉದ್ದಳತೆ)));
ಅಕ್ಷರ *SHA384_ಕೊನೆ(SHA2_CTX *, ಅಕ್ಷರ *)
	__attribute__((__bounded__(__minbytes__,2,SHA384_DIGEST_STRING_ಉದ್ದಳತೆ)));
ಅಕ್ಷರ *SHA384File(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಅಕ್ಷರ *)
	__attribute__((__bounded__(__minbytes__,2,SHA384_DIGEST_STRING_ಉದ್ದಳತೆ)));
ಅಕ್ಷರ *SHA384FileChunk(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಅಕ್ಷರ *, off_t, off_t)
	__attribute__((__bounded__(__minbytes__,2,SHA384_DIGEST_STRING_ಉದ್ದಳತೆ)));
ಅಕ್ಷರ *SHA384_ದತ್ತಾಂಶ(ಸ್ಥಿರಾಂಕ u_int8_t *, ಗಾತ್ರ_t, ಅಕ್ಷರ *)
	__attribute__((__bounded__(__string__,1,2)))
	__attribute__((__bounded__(__minbytes__,3,SHA384_DIGEST_STRING_ಉದ್ದಳತೆ)));
#ಆದರೆ_ಅಂತ್ಯ /* HAVE_SHA384UPDATE */

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_SHA512UPDATE
ಶೂನ್ಯ SHA512Init(SHA2_CTX *);
ಶೂನ್ಯ SHA512Transform(u_int64_t state[8], ಸ್ಥಿರಾಂಕ u_int8_t [SHA512_ಖಂಡ_ಉದ್ದಳತೆ]);
ಶೂನ್ಯ SHA512Update(SHA2_CTX *, ಸ್ಥಿರಾಂಕ u_int8_t *, ಗಾತ್ರ_t)
	__attribute__((__bounded__(__string__,2,3)));
ಶೂನ್ಯ SHA512Pad(SHA2_CTX *);
ಶೂನ್ಯ SHA512Final(u_int8_t [SHA512_DIGEST_ಉದ್ದಳತೆ], SHA2_CTX *)
	__attribute__((__bounded__(__minbytes__,1,SHA512_DIGEST_ಉದ್ದಳತೆ)));
ಅಕ್ಷರ *SHA512_ಕೊನೆ(SHA2_CTX *, ಅಕ್ಷರ *)
	__attribute__((__bounded__(__minbytes__,2,SHA512_DIGEST_STRING_ಉದ್ದಳತೆ)));
ಅಕ್ಷರ *SHA512File(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಅಕ್ಷರ *)
	__attribute__((__bounded__(__minbytes__,2,SHA512_DIGEST_STRING_ಉದ್ದಳತೆ)));
ಅಕ್ಷರ *SHA512FileChunk(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಅಕ್ಷರ *, off_t, off_t)
	__attribute__((__bounded__(__minbytes__,2,SHA512_DIGEST_STRING_ಉದ್ದಳತೆ)));
ಅಕ್ಷರ *SHA512_ದತ್ತಾಂಶ(ಸ್ಥಿರಾಂಕ u_int8_t *, ಗಾತ್ರ_t, ಅಕ್ಷರ *)
	__attribute__((__bounded__(__string__,1,2)))
	__attribute__((__bounded__(__minbytes__,3,SHA512_DIGEST_STRING_ಉದ್ದಳತೆ)));
#ಆದರೆ_ಅಂತ್ಯ /* HAVE_SHA512UPDATE */

#ಆದರೆ 0
ಶೂನ್ಯ SHA512_256Init(SHA2_CTX *);
ಶೂನ್ಯ SHA512_256Transform(u_int64_t state[8], ಸ್ಥಿರಾಂಕ u_int8_t [SHA512_256_ಖಂಡ_ಉದ್ದಳತೆ]);
ಶೂನ್ಯ SHA512_256Update(SHA2_CTX *, ಸ್ಥಿರಾಂಕ u_int8_t *, ಗಾತ್ರ_t)
	__attribute__((__bounded__(__string__,2,3)));
ಶೂನ್ಯ SHA512_256Pad(SHA2_CTX *);
ಶೂನ್ಯ SHA512_256Final(u_int8_t [SHA512_256_DIGEST_ಉದ್ದಳತೆ], SHA2_CTX *)
	__attribute__((__bounded__(__minbytes__,1,SHA512_256_DIGEST_ಉದ್ದಳತೆ)));
ಅಕ್ಷರ *SHA512_256_ಕೊನೆ(SHA2_CTX *, ಅಕ್ಷರ *)
	__attribute__((__bounded__(__minbytes__,2,SHA512_256_DIGEST_STRING_ಉದ್ದಳತೆ)));
ಅಕ್ಷರ *SHA512_256File(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಅಕ್ಷರ *)
	__attribute__((__bounded__(__minbytes__,2,SHA512_256_DIGEST_STRING_ಉದ್ದಳತೆ)));
ಅಕ್ಷರ *SHA512_256FileChunk(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಅಕ್ಷರ *, off_t, off_t)
	__attribute__((__bounded__(__minbytes__,2,SHA512_256_DIGEST_STRING_ಉದ್ದಳತೆ)));
ಅಕ್ಷರ *SHA512_256_ದತ್ತಾಂಶ(ಸ್ಥಿರಾಂಕ u_int8_t *, ಗಾತ್ರ_t, ಅಕ್ಷರ *)
	__attribute__((__bounded__(__string__,1,2)))
	__attribute__((__bounded__(__minbytes__,3,SHA512_256_DIGEST_STRING_ಉದ್ದಳತೆ)));
__END_DECLS
#ಆದರೆ_ಅಂತ್ಯ /* 0 */

#ಆದರೆ_ಅಂತ್ಯ /* HAVE_SHA{256,384,512}UPDATE */

#ಆದರೆ_ಅಂತ್ಯ /* _SSHSHA2_H */
