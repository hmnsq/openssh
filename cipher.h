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

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ CIPHER_H
#ವ್ಯಾಖ್ಯಾನಿಸು CIPHER_H

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL
#ಅನ್ತರ್ಭಾವ <openssl/evp.h>
#ಆದರೆ_ಅಂತ್ಯ
#ಅನ್ತರ್ಭಾವ "cipher-chachapoly.h"
#ಅನ್ತರ್ಭಾವ "cipher-aesctr.h"

#ವ್ಯಾಖ್ಯಾನಿಸು CIPHER_ENCRYPT		1
#ವ್ಯಾಖ್ಯಾನಿಸು CIPHER_DECRYPT		0

ರಚನೆ sshcipher;
ರಚನೆ sshcipher_ctx;

ಸ್ಥಿರಾಂಕ ರಚನೆ sshcipher *cipher_by_name(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *);
ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *cipher_warning_ಸಂದೇಶ(ಸ್ಥಿರಾಂಕ ರಚನೆ sshcipher_ctx *);
ಪೂರ್ಣಾಂಕ	 ciphers_valid(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *);
ಅಕ್ಷರ	*cipher_alg_list(ಅಕ್ಷರ, ಪೂರ್ಣಾಂಕ);
ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *compression_alg_list(ಪೂರ್ಣಾಂಕ);
ಪೂರ್ಣಾಂಕ	 cipher_init(ರಚನೆ sshcipher_ctx **, ಸ್ಥಿರಾಂಕ ರಚನೆ sshcipher *,
    ಸ್ಥಿರಾಂಕ u_char *, u_int, ಸ್ಥಿರಾಂಕ u_char *, u_int, ಪೂರ್ಣಾಂಕ);
ಪೂರ್ಣಾಂಕ	 cipher_crypt(ರಚನೆ sshcipher_ctx *, u_int, u_char *, ಸ್ಥಿರಾಂಕ u_char *,
    u_int, u_int, u_int);
ಪೂರ್ಣಾಂಕ	 cipher_get_ಉದ್ದಳತೆ(ರಚನೆ sshcipher_ctx *, u_int *, u_int,
    ಸ್ಥಿರಾಂಕ u_char *, u_int);
ಶೂನ್ಯ	 cipher_free(ರಚನೆ sshcipher_ctx *);
u_int	 cipher_blocksize(ಸ್ಥಿರಾಂಕ ರಚನೆ sshcipher *);
u_int	 cipher_keylen(ಸ್ಥಿರಾಂಕ ರಚನೆ sshcipher *);
u_int	 cipher_seclen(ಸ್ಥಿರಾಂಕ ರಚನೆ sshcipher *);
u_int	 cipher_authlen(ಸ್ಥಿರಾಂಕ ರಚನೆ sshcipher *);
u_int	 cipher_ivlen(ಸ್ಥಿರಾಂಕ ರಚನೆ sshcipher *);
u_int	 cipher_is_cbc(ಸ್ಥಿರಾಂಕ ರಚನೆ sshcipher *);
u_int	 cipher_is_ಆಂತರಿಕ(ಸ್ಥಿರಾಂಕ ರಚನೆ sshcipher *);

u_int	 cipher_ctx_is_plaintext(ರಚನೆ sshcipher_ctx *);

ಪೂರ್ಣಾಂಕ	 cipher_get_keyiv(ರಚನೆ sshcipher_ctx *, u_char *, ಗಾತ್ರ_t);

#ಆದರೆ_ಅಂತ್ಯ				/* CIPHER_H */
