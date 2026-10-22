/* $OpenBSD: cipher.h,v 1.58 2026/06/19 05:26:04 djm Exp $ */

/*
 * Author: Tatu Ylonen <ylo@cs.hut.fi>
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 *
 * Copyright (c) 2000 Markus Friedl.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef CIPHER_H
#define CIPHER_H

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ifdef WITH_OPENSSL
#ಅನ್ತರ್ಭಾವ <openssl/evp.h>
#endif
#ಅನ್ತರ್ಭಾವ "cipher-chachapoly.h"
#ಅನ್ತರ್ಭಾವ "cipher-aesctr.h"

#define CIPHER_ENCRYPT		1
#define CIPHER_DECRYPT		0

ಸಂರಚನಾ sshcipher;
ಸಂರಚನಾ sshcipher_ctx;

ಧ್ರುವ ಸಂರಚನಾ sshcipher *cipher_by_name(ಧ್ರುವ ವರ್ಣ *);
ಧ್ರುವ ವರ್ಣ *cipher_warning_message(ಧ್ರುವ ಸಂರಚನಾ sshcipher_ctx *);
ಪೂರ್ಣಾಙ್ಕ	 ciphers_valid(ಧ್ರುವ ವರ್ಣ *);
ವರ್ಣ	*cipher_alg_list(ವರ್ಣ, ಪೂರ್ಣಾಙ್ಕ);
ಧ್ರುವ ವರ್ಣ *compression_alg_list(ಪೂರ್ಣಾಙ್ಕ);
ಪೂರ್ಣಾಙ್ಕ	 cipher_init(ಸಂರಚನಾ sshcipher_ctx **, ಧ್ರುವ ಸಂರಚನಾ sshcipher *,
    ಧ್ರುವ u_char *, u_int, ಧ್ರುವ u_char *, u_int, ಪೂರ್ಣಾಙ್ಕ);
ಪೂರ್ಣಾಙ್ಕ	 cipher_crypt(ಸಂರಚನಾ sshcipher_ctx *, u_int, u_char *, ಧ್ರುವ u_char *,
    u_int, u_int, u_int);
ಪೂರ್ಣಾಙ್ಕ	 cipher_get_length(ಸಂರಚನಾ sshcipher_ctx *, u_int *, u_int,
    ಧ್ರುವ u_char *, u_int);
ಶೂನ್ಯ	 cipher_free(ಸಂರಚನಾ sshcipher_ctx *);
u_int	 cipher_blocksize(ಧ್ರುವ ಸಂರಚನಾ sshcipher *);
u_int	 cipher_keylen(ಧ್ರುವ ಸಂರಚನಾ sshcipher *);
u_int	 cipher_seclen(ಧ್ರುವ ಸಂರಚನಾ sshcipher *);
u_int	 cipher_authlen(ಧ್ರುವ ಸಂರಚನಾ sshcipher *);
u_int	 cipher_ivlen(ಧ್ರುವ ಸಂರಚನಾ sshcipher *);
u_int	 cipher_is_cbc(ಧ್ರುವ ಸಂರಚನಾ sshcipher *);
u_int	 cipher_is_internal(ಧ್ರುವ ಸಂರಚನಾ sshcipher *);

u_int	 cipher_ctx_is_plaintext(ಸಂರಚನಾ sshcipher_ctx *);

ಪೂರ್ಣಾಙ್ಕ	 cipher_get_keyiv(ಸಂರಚನಾ sshcipher_ctx *, u_char *, size_t);

#endif				/* CIPHER_H */
