/* $OpenBSD: kexgex.c,v 1.33 2026/02/14 00:18:34 jsg Exp $ */
/*
 * Copyright (c) 2000 Niels Provos.  All rights reserved.
 * Copyright (c) 2001 Markus Friedl.  All rights reserved.
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

#అన్తర్భావ "includes.h"

#నిర్వచితమైతే WITH_OPENSSL

#అన్తర్భావ <sys/types.h>

#అన్తర్భావ <openssl/evp.h>
#అన్తర్భావ <signal.h>

#అన్తర్భావ "openbsd-compat/openssl-compat.h"

#అన్తర్భావ "sshkey.h"
#అన్తర్భావ "cipher.h"
#అన్తర్భావ "kex.h"
#అన్తర్భావ "ssh2.h"
#అన్తర్భావ "ssherr.h"
#అన్తర్భావ "sshbuf.h"
#అన్తర్భావ "digest.h"

పూర్ణాంకం
kexgex_hash(
    పూర్ణాంకం hash_alg,
    స్థిరరాశి నిర్మాణం sshbuf *client_సంస్కరణ,
    స్థిరరాశి నిర్మాణం sshbuf *server_సంస్కరణ,
    స్థిరరాశి నిర్మాణం sshbuf *client_kexinit,
    స్థిరరాశి నిర్మాణం sshbuf *server_kexinit,
    స్థిరరాశి నిర్మాణం sshbuf *server_host_కీలకం_blob,
    పూర్ణాంకం min, పూర్ణాంకం wantbits, పూర్ణాంకం max,
    స్థిరరాశి BIGNUM *ప్రధానసంఖ్య,
    స్థిరరాశి BIGNUM *gen,
    స్థిరరాశి BIGNUM *client_dh_pub,
    స్థిరరాశి BIGNUM *server_dh_pub,
    స్థిరరాశి u_char *shared_secret, కొలత_t secretlen,
    u_char *hash, కొలత_t *hashlen)
{
	నిర్మాణం sshbuf *b;
	పూర్ణాంకం r;

	ఒకవేళ (*hashlen < ssh_digest_బైట్లు(SSH_DIGEST_SHA1))
		తిరిగి SSH_ERR_INVALID_వాదం;
	ఒకవేళ ((b = sshbuf_new()) == ఖాళీ)
		తిరిగి SSH_ERR_ALLOC_FAIL;
	ఒకవేళ ((r = sshbuf_put_stringb(b, client_సంస్కరణ)) < 0 ||
	    (r = sshbuf_put_stringb(b, server_సంస్కరణ)) < 0 ||
	    /* kexinit messages: fake header: len+SSH2_MSG_KEXINIT */
	    (r = sshbuf_put_u32(b, sshbuf_len(client_kexinit) + 1)) != 0 ||
	    (r = sshbuf_put_u8(b, SSH2_సందేశం_KEXINIT)) != 0 ||
	    (r = sshbuf_putb(b, client_kexinit)) != 0 ||
	    (r = sshbuf_put_u32(b, sshbuf_len(server_kexinit) + 1)) != 0 ||
	    (r = sshbuf_put_u8(b, SSH2_సందేశం_KEXINIT)) != 0 ||
	    (r = sshbuf_putb(b, server_kexinit)) != 0 ||
	    (r = sshbuf_put_stringb(b, server_host_కీలకం_blob)) != 0 ||
	    (min != -1 && (r = sshbuf_put_u32(b, min)) != 0) ||
	    (r = sshbuf_put_u32(b, wantbits)) != 0 ||
	    (max != -1 && (r = sshbuf_put_u32(b, max)) != 0) ||
	    (r = sshbuf_put_bignum2(b, ప్రధానసంఖ్య)) != 0 ||
	    (r = sshbuf_put_bignum2(b, gen)) != 0 ||
	    (r = sshbuf_put_bignum2(b, client_dh_pub)) != 0 ||
	    (r = sshbuf_put_bignum2(b, server_dh_pub)) != 0 ||
	    (r = sshbuf_put(b, shared_secret, secretlen)) != 0) {
		sshbuf_free(b);
		తిరిగి r;
	}
#నిర్వచితమైతే DEBUG_KEXDH
	sshbuf_dump(b, stderr);
#అయితే_ముగింపు
	ఒకవేళ (ssh_digest_బఫరు(hash_alg, b, hash, *hashlen) != 0) {
		sshbuf_free(b);
		తిరిగి SSH_ERR_LIBCRYPTO_ERROR;
	}
	sshbuf_free(b);
	*hashlen = ssh_digest_బైట్లు(hash_alg);
#నిర్వచితమైతే DEBUG_KEXDH
	dump_digest("hash", hash, *hashlen);
#అయితే_ముగింపు
	తిరిగి 0;
}
#అయితే_ముగింపు /* WITH_OPENSSL */
