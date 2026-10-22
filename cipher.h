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

#నిర్వచితం_కాకపోతే CIPHER_H
#నిర్వచించు CIPHER_H

#అన్తర్భావ <sys/types.h>
#నిర్వచితమైతే WITH_OPENSSL
#అన్తర్భావ <openssl/evp.h>
#అయితే_ముగింపు
#అన్తర్భావ "cipher-chachapoly.h"
#అన్తర్భావ "cipher-aesctr.h"

#నిర్వచించు CIPHER_ENCRYPT		1
#నిర్వచించు CIPHER_DECRYPT		0

నిర్మాణం sshcipher;
నిర్మాణం sshcipher_ctx;

స్థిరరాశి నిర్మాణం sshcipher *cipher_by_name(స్థిరరాశి అక్షరం *);
స్థిరరాశి అక్షరం *cipher_warning_సందేశం(స్థిరరాశి నిర్మాణం sshcipher_ctx *);
పూర్ణాంకం	 ciphers_valid(స్థిరరాశి అక్షరం *);
అక్షరం	*cipher_alg_list(అక్షరం, పూర్ణాంకం);
స్థిరరాశి అక్షరం *compression_alg_list(పూర్ణాంకం);
పూర్ణాంకం	 cipher_init(నిర్మాణం sshcipher_ctx **, స్థిరరాశి నిర్మాణం sshcipher *,
    స్థిరరాశి u_char *, u_int, స్థిరరాశి u_char *, u_int, పూర్ణాంకం);
పూర్ణాంకం	 cipher_crypt(నిర్మాణం sshcipher_ctx *, u_int, u_char *, స్థిరరాశి u_char *,
    u_int, u_int, u_int);
పూర్ణాంకం	 cipher_get_నిడివి(నిర్మాణం sshcipher_ctx *, u_int *, u_int,
    స్థిరరాశి u_char *, u_int);
శూన్య	 cipher_free(నిర్మాణం sshcipher_ctx *);
u_int	 cipher_blocksize(స్థిరరాశి నిర్మాణం sshcipher *);
u_int	 cipher_keylen(స్థిరరాశి నిర్మాణం sshcipher *);
u_int	 cipher_seclen(స్థిరరాశి నిర్మాణం sshcipher *);
u_int	 cipher_authlen(స్థిరరాశి నిర్మాణం sshcipher *);
u_int	 cipher_ivlen(స్థిరరాశి నిర్మాణం sshcipher *);
u_int	 cipher_is_cbc(స్థిరరాశి నిర్మాణం sshcipher *);
u_int	 cipher_is_అంతర్గత(స్థిరరాశి నిర్మాణం sshcipher *);

u_int	 cipher_ctx_is_plaintext(నిర్మాణం sshcipher_ctx *);

పూర్ణాంకం	 cipher_get_keyiv(నిర్మాణం sshcipher_ctx *, u_char *, కొలత_t);

#అయితే_ముగింపు				/* CIPHER_H */
