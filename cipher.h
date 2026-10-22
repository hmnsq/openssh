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

#اگر_تعریف_نشده CIPHER_H
#تعریف_کن CIPHER_H

#ضمن <sys/types.h>
#اگر_تعریف_شده WITH_OPENSSL
#ضمن <openssl/evp.h>
#پایان_اگر
#ضمن "cipher-chachapoly.h"
#ضمن "cipher-aesctr.h"

#تعریف_کن CIPHER_ENCRYPT		1
#تعریف_کن CIPHER_DECRYPT		0

بنية sshcipher;
بنية sshcipher_ctx;

ثابت بنية sshcipher *cipher_by_name(ثابت حرف *);
ثابت حرف *cipher_warning_پیام(ثابت بنية sshcipher_ctx *);
صحيح	 ciphers_valid(ثابت حرف *);
حرف	*cipher_alg_list(حرف, صحيح);
ثابت حرف *compression_alg_list(صحيح);
صحيح	 cipher_init(بنية sshcipher_ctx **, ثابت بنية sshcipher *,
    ثابت u_char *, u_int, ثابت u_char *, u_int, صحيح);
صحيح	 cipher_crypt(بنية sshcipher_ctx *, u_int, u_char *, ثابت u_char *,
    u_int, u_int, u_int);
صحيح	 cipher_get_درازی(بنية sshcipher_ctx *, u_int *, u_int,
    ثابت u_char *, u_int);
فراغ	 cipher_free(بنية sshcipher_ctx *);
u_int	 cipher_blocksize(ثابت بنية sshcipher *);
u_int	 cipher_keylen(ثابت بنية sshcipher *);
u_int	 cipher_seclen(ثابت بنية sshcipher *);
u_int	 cipher_authlen(ثابت بنية sshcipher *);
u_int	 cipher_ivlen(ثابت بنية sshcipher *);
u_int	 cipher_is_cbc(ثابت بنية sshcipher *);
u_int	 cipher_is_داخلی(ثابت بنية sshcipher *);

u_int	 cipher_ctx_is_plaintext(بنية sshcipher_ctx *);

صحيح	 cipher_get_keyiv(بنية sshcipher_ctx *, u_char *, اندازه_t);

#پایان_اگر				/* CIPHER_H */
