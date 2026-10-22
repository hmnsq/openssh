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

#অন্তর্ভাব <sys/types.h>
#ifdef WITH_OPENSSL
#অন্তর্ভাব <openssl/evp.h>
#endif
#অন্তর্ভাব "cipher-chachapoly.h"
#অন্তর্ভাব "cipher-aesctr.h"

#define CIPHER_ENCRYPT		1
#define CIPHER_DECRYPT		0

কাঠামো sshcipher;
কাঠামো sshcipher_ctx;

ধ্রুবক কাঠামো sshcipher *cipher_by_name(ধ্রুবক অক্ষর *);
ধ্রুবক অক্ষর *cipher_warning_message(ধ্রুবক কাঠামো sshcipher_ctx *);
পূর্ণসংখ্যা	 ciphers_valid(ধ্রুবক অক্ষর *);
অক্ষর	*cipher_alg_list(অক্ষর, পূর্ণসংখ্যা);
ধ্রুবক অক্ষর *compression_alg_list(পূর্ণসংখ্যা);
পূর্ণসংখ্যা	 cipher_init(কাঠামো sshcipher_ctx **, ধ্রুবক কাঠামো sshcipher *,
    ধ্রুবক u_char *, u_int, ধ্রুবক u_char *, u_int, পূর্ণসংখ্যা);
পূর্ণসংখ্যা	 cipher_crypt(কাঠামো sshcipher_ctx *, u_int, u_char *, ধ্রুবক u_char *,
    u_int, u_int, u_int);
পূর্ণসংখ্যা	 cipher_get_দৈর্ঘ্য(কাঠামো sshcipher_ctx *, u_int *, u_int,
    ধ্রুবক u_char *, u_int);
শূন্য	 cipher_free(কাঠামো sshcipher_ctx *);
u_int	 cipher_blocksize(ধ্রুবক কাঠামো sshcipher *);
u_int	 cipher_keylen(ধ্রুবক কাঠামো sshcipher *);
u_int	 cipher_seclen(ধ্রুবক কাঠামো sshcipher *);
u_int	 cipher_authlen(ধ্রুবক কাঠামো sshcipher *);
u_int	 cipher_ivlen(ধ্রুবক কাঠামো sshcipher *);
u_int	 cipher_is_cbc(ধ্রুবক কাঠামো sshcipher *);
u_int	 cipher_is_internal(ধ্রুবক কাঠামো sshcipher *);

u_int	 cipher_ctx_is_plaintext(কাঠামো sshcipher_ctx *);

পূর্ণসংখ্যা	 cipher_get_keyiv(কাঠামো sshcipher_ctx *, u_char *, আকার_t);

#endif				/* CIPHER_H */
