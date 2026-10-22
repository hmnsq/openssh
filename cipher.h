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

#અન્તર્ભાવ <sys/types.h>
#ifdef WITH_OPENSSL
#અન્તર્ભાવ <openssl/evp.h>
#endif
#અન્તર્ભાવ "cipher-chachapoly.h"
#અન્તર્ભાવ "cipher-aesctr.h"

#define CIPHER_ENCRYPT		1
#define CIPHER_DECRYPT		0

સંરચના sshcipher;
સંરચના sshcipher_ctx;

અચલ સંરચના sshcipher *cipher_by_name(અચલ અક્ષર *);
અચલ અક્ષર *cipher_warning_message(અચલ સંરચના sshcipher_ctx *);
પૂર્ણાંક	 ciphers_valid(અચલ અક્ષર *);
અક્ષર	*cipher_alg_list(અક્ષર, પૂર્ણાંક);
અચલ અક્ષર *compression_alg_list(પૂર્ણાંક);
પૂર્ણાંક	 cipher_init(સંરચના sshcipher_ctx **, અચલ સંરચના sshcipher *,
    અચલ u_char *, u_int, અચલ u_char *, u_int, પૂર્ણાંક);
પૂર્ણાંક	 cipher_crypt(સંરચના sshcipher_ctx *, u_int, u_char *, અચલ u_char *,
    u_int, u_int, u_int);
પૂર્ણાંક	 cipher_get_length(સંરચના sshcipher_ctx *, u_int *, u_int,
    અચલ u_char *, u_int);
શૂન્ય	 cipher_free(સંરચના sshcipher_ctx *);
u_int	 cipher_blocksize(અચલ સંરચના sshcipher *);
u_int	 cipher_keylen(અચલ સંરચના sshcipher *);
u_int	 cipher_seclen(અચલ સંરચના sshcipher *);
u_int	 cipher_authlen(અચલ સંરચના sshcipher *);
u_int	 cipher_ivlen(અચલ સંરચના sshcipher *);
u_int	 cipher_is_cbc(અચલ સંરચના sshcipher *);
u_int	 cipher_is_internal(અચલ સંરચના sshcipher *);

u_int	 cipher_ctx_is_plaintext(સંરચના sshcipher_ctx *);

પૂર્ણાંક	 cipher_get_keyiv(સંરચના sshcipher_ctx *, u_char *, size_t);

#endif				/* CIPHER_H */
