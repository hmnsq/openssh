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

#شامل <sys/types.h>
#ifdef WITH_OPENSSL
#شامل <openssl/evp.h>
#endif
#شامل "cipher-chachapoly.h"
#شامل "cipher-aesctr.h"

#define CIPHER_ENCRYPT		1
#define CIPHER_DECRYPT		0

ساختار sshcipher;
ساختار sshcipher_ctx;

ثابت ساختار sshcipher *cipher_by_name(ثابت نویسه *);
ثابت نویسه *cipher_warning_message(ثابت ساختار sshcipher_ctx *);
صحیح	 ciphers_valid(ثابت نویسه *);
نویسه	*cipher_alg_list(نویسه, صحیح);
ثابت نویسه *compression_alg_list(صحیح);
صحیح	 cipher_init(ساختار sshcipher_ctx **, ثابت ساختار sshcipher *,
    ثابت u_char *, u_int, ثابت u_char *, u_int, صحیح);
صحیح	 cipher_crypt(ساختار sshcipher_ctx *, u_int, u_char *, ثابت u_char *,
    u_int, u_int, u_int);
صحیح	 cipher_get_length(ساختار sshcipher_ctx *, u_int *, u_int,
    ثابت u_char *, u_int);
تهی	 cipher_free(ساختار sshcipher_ctx *);
u_int	 cipher_blocksize(ثابت ساختار sshcipher *);
u_int	 cipher_keylen(ثابت ساختار sshcipher *);
u_int	 cipher_seclen(ثابت ساختار sshcipher *);
u_int	 cipher_authlen(ثابت ساختار sshcipher *);
u_int	 cipher_ivlen(ثابت ساختار sshcipher *);
u_int	 cipher_is_cbc(ثابت ساختار sshcipher *);
u_int	 cipher_is_internal(ثابت ساختار sshcipher *);

u_int	 cipher_ctx_is_plaintext(ساختار sshcipher_ctx *);

صحیح	 cipher_get_keyiv(ساختار sshcipher_ctx *, u_char *, size_t);

#endif				/* CIPHER_H */
