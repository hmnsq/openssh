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

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ CIPHER_H
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CIPHER_H

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
#ਅਨ੍ਤਰ੍ਭਾਵ <openssl/evp.h>
#ਜੇ_ਅੰਤ
#ਅਨ੍ਤਰ੍ਭਾਵ "cipher-chachapoly.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "cipher-aesctr.h"

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CIPHER_ENCRYPT		1
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CIPHER_DECRYPT		0

ਬਣਤਰ sshcipher;
ਬਣਤਰ sshcipher_ctx;

ਅਚਲ ਬਣਤਰ sshcipher *cipher_by_name(ਅਚਲ ਅੱਖਰ *);
ਅਚਲ ਅੱਖਰ *cipher_warning_ਸੁਨੇਹਾ(ਅਚਲ ਬਣਤਰ sshcipher_ctx *);
ਪੂਰਨ	 ciphers_valid(ਅਚਲ ਅੱਖਰ *);
ਅੱਖਰ	*cipher_alg_list(ਅੱਖਰ, ਪੂਰਨ);
ਅਚਲ ਅੱਖਰ *compression_alg_list(ਪੂਰਨ);
ਪੂਰਨ	 cipher_init(ਬਣਤਰ sshcipher_ctx **, ਅਚਲ ਬਣਤਰ sshcipher *,
    ਅਚਲ u_char *, u_int, ਅਚਲ u_char *, u_int, ਪੂਰਨ);
ਪੂਰਨ	 cipher_crypt(ਬਣਤਰ sshcipher_ctx *, u_int, u_char *, ਅਚਲ u_char *,
    u_int, u_int, u_int);
ਪੂਰਨ	 cipher_get_ਲੰਮਾਈ(ਬਣਤਰ sshcipher_ctx *, u_int *, u_int,
    ਅਚਲ u_char *, u_int);
ਖਾਲੀ	 cipher_free(ਬਣਤਰ sshcipher_ctx *);
u_int	 cipher_blocksize(ਅਚਲ ਬਣਤਰ sshcipher *);
u_int	 cipher_keylen(ਅਚਲ ਬਣਤਰ sshcipher *);
u_int	 cipher_seclen(ਅਚਲ ਬਣਤਰ sshcipher *);
u_int	 cipher_authlen(ਅਚਲ ਬਣਤਰ sshcipher *);
u_int	 cipher_ivlen(ਅਚਲ ਬਣਤਰ sshcipher *);
u_int	 cipher_is_cbc(ਅਚਲ ਬਣਤਰ sshcipher *);
u_int	 cipher_is_ਅੰਦਰੂਨੀ(ਅਚਲ ਬਣਤਰ sshcipher *);

u_int	 cipher_ctx_is_plaintext(ਬਣਤਰ sshcipher_ctx *);

ਪੂਰਨ	 cipher_get_keyiv(ਬਣਤਰ sshcipher_ctx *, u_char *, ਮਾਪ_t);

#ਜੇ_ਅੰਤ				/* CIPHER_H */
