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

#अन्तर्भाव <sys/types.h>
#ifdef WITH_OPENSSL
#अन्तर्भाव <openssl/evp.h>
#endif
#अन्तर्भाव "cipher-chachapoly.h"
#अन्तर्भाव "cipher-aesctr.h"

#define CIPHER_ENCRYPT		1
#define CIPHER_DECRYPT		0

संरचना sshcipher;
संरचना sshcipher_ctx;

ध्रुव संरचना sshcipher *cipher_by_name(ध्रुव वर्ण *);
ध्रुव वर्ण *cipher_warning_message(ध्रुव संरचना sshcipher_ctx *);
पूर्णाङ्क	 ciphers_valid(ध्रुव वर्ण *);
वर्ण	*cipher_alg_list(वर्ण, पूर्णाङ्क);
ध्रुव वर्ण *compression_alg_list(पूर्णाङ्क);
पूर्णाङ्क	 cipher_init(संरचना sshcipher_ctx **, ध्रुव संरचना sshcipher *,
    ध्रुव u_char *, u_int, ध्रुव u_char *, u_int, पूर्णाङ्क);
पूर्णाङ्क	 cipher_crypt(संरचना sshcipher_ctx *, u_int, u_char *, ध्रुव u_char *,
    u_int, u_int, u_int);
पूर्णाङ्क	 cipher_get_length(संरचना sshcipher_ctx *, u_int *, u_int,
    ध्रुव u_char *, u_int);
शून्य	 cipher_free(संरचना sshcipher_ctx *);
u_int	 cipher_blocksize(ध्रुव संरचना sshcipher *);
u_int	 cipher_keylen(ध्रुव संरचना sshcipher *);
u_int	 cipher_seclen(ध्रुव संरचना sshcipher *);
u_int	 cipher_authlen(ध्रुव संरचना sshcipher *);
u_int	 cipher_ivlen(ध्रुव संरचना sshcipher *);
u_int	 cipher_is_cbc(ध्रुव संरचना sshcipher *);
u_int	 cipher_is_internal(ध्रुव संरचना sshcipher *);

u_int	 cipher_ctx_is_plaintext(संरचना sshcipher_ctx *);

पूर्णाङ्क	 cipher_get_keyiv(संरचना sshcipher_ctx *, u_char *, माप_प्रकार);

#endif				/* CIPHER_H */
