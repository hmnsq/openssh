/* $OpenBSD: kexc25519.c,v 1.18 2024/09/02 12:13:56 djm Exp $ */
/*
 * Copyright (c) 2019 Markus Friedl.  All rights reserved.
 * Copyright (c) 2010 Damien Miller.  All rights reserved.
 * Copyright (c) 2013 Aris Adamantiadis.  All rights reserved.
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

#అన్తర్భావ <sys/types.h>

#అన్తర్భావ <stdio.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <signal.h>

#అన్తర్భావ "sshkey.h"
#అన్తర్భావ "kex.h"
#అన్తర్భావ "sshbuf.h"
#అన్తర్భావ "digest.h"
#అన్తర్భావ "ssherr.h"
#అన్తర్భావ "ssh2.h"

బాహ్య పూర్ణాంకం crypto_scalarmult_curve25519(u_char a[CURVE25519_కొలత],
    స్థిరరాశి u_char b[CURVE25519_కొలత], స్థిరరాశి u_char c[CURVE25519_కొలత])
	__attribute__((__bounded__(__minbytes__, 1, CURVE25519_కొలత)))
	__attribute__((__bounded__(__minbytes__, 2, CURVE25519_కొలత)))
	__attribute__((__bounded__(__minbytes__, 3, CURVE25519_కొలత)));

శూన్య
kexc25519_keygen(u_char కీలకం[CURVE25519_కొలత], u_char pub[CURVE25519_కొలత])
{
	స్థిర స్థిరరాశి u_char basepoint[CURVE25519_కొలత] = {9};

	arc4random_buf(కీలకం, CURVE25519_కొలత);
	crypto_scalarmult_curve25519(pub, కీలకం, basepoint);
}

పూర్ణాంకం
kexc25519_shared_కీలకం_ext(స్థిరరాశి u_char కీలకం[CURVE25519_కొలత],
    స్థిరరాశి u_char pub[CURVE25519_కొలత], నిర్మాణం sshbuf *బహిర్గతం, పూర్ణాంకం raw)
{
	u_char shared_కీలకం[CURVE25519_కొలత];
	u_char zero[CURVE25519_కొలత];
	పూర్ణాంకం r;

	crypto_scalarmult_curve25519(shared_కీలకం, కీలకం, pub);

	/* Check for all-zero shared secret */
	explicit_bzero(zero, CURVE25519_కొలత);
	ఒకవేళ (timingsafe_bcmp(zero, shared_కీలకం, CURVE25519_కొలత) == 0)
		తిరిగి SSH_ERR_కీలకం_INVALID_EC_విలువ;

#నిర్వచితమైతే DEBUG_KEXECDH
	dump_digest("shared secret 25519", shared_కీలకం, CURVE25519_కొలత);
#అయితే_ముగింపు
	ఒకవేళ (raw)
		r = sshbuf_put(బహిర్గతం, shared_కీలకం, CURVE25519_కొలత);
	లేకపోతే
		r = sshbuf_put_bignum2_బైట్లు(బహిర్గతం, shared_కీలకం, CURVE25519_కొలత);
	explicit_bzero(shared_కీలకం, CURVE25519_కొలత);
	తిరిగి r;
}

పూర్ణాంకం
kexc25519_shared_కీలకం(స్థిరరాశి u_char కీలకం[CURVE25519_కొలత],
    స్థిరరాశి u_char pub[CURVE25519_కొలత], నిర్మాణం sshbuf *బహిర్గతం)
{
	తిరిగి kexc25519_shared_కీలకం_ext(కీలకం, pub, బహిర్గతం, 0);
}

పూర్ణాంకం
kex_c25519_keypair(నిర్మాణం kex *kex)
{
	నిర్మాణం sshbuf *buf = ఖాళీ;
	u_char *cp = ఖాళీ;
	పూర్ణాంకం r;

	ఒకవేళ ((buf = sshbuf_new()) == ఖాళీ)
		తిరిగి SSH_ERR_ALLOC_FAIL;
	ఒకవేళ ((r = sshbuf_reserve(buf, CURVE25519_కొలత, &cp)) != 0)
		వెళ్ళు బహిర్గతం;
	kexc25519_keygen(kex->c25519_client_కీలకం, cp);
#నిర్వచితమైతే DEBUG_KEXECDH
	dump_digest("client public key c25519:", cp, CURVE25519_కొలత);
#అయితే_ముగింపు
	kex->client_pub = buf;
	buf = ఖాళీ;
 బహిర్గతం:
	sshbuf_free(buf);
	తిరిగి r;
}

పూర్ణాంకం
kex_c25519_enc(నిర్మాణం kex *kex, స్థిరరాశి నిర్మాణం sshbuf *client_blob,
   నిర్మాణం sshbuf **server_blobp, నిర్మాణం sshbuf **shared_secretp)
{
	నిర్మాణం sshbuf *server_blob = ఖాళీ;
	నిర్మాణం sshbuf *buf = ఖాళీ;
	స్థిరరాశి u_char *client_pub;
	u_char *server_pub;
	u_char server_కీలకం[CURVE25519_కొలత];
	పూర్ణాంకం r;

	*server_blobp = ఖాళీ;
	*shared_secretp = ఖాళీ;

	ఒకవేళ (sshbuf_len(client_blob) != CURVE25519_కొలత) {
		r = SSH_ERR_SIGNATURE_INVALID;
		వెళ్ళు బహిర్గతం;
	}
	client_pub = sshbuf_ptr(client_blob);
#నిర్వచితమైతే DEBUG_KEXECDH
	dump_digest("client public key 25519:", client_pub, CURVE25519_కొలత);
#అయితే_ముగింపు
	/* allocate space for encrypted KEM key and ECDH pub key */
	ఒకవేళ ((server_blob = sshbuf_new()) == ఖాళీ) {
		r = SSH_ERR_ALLOC_FAIL;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((r = sshbuf_reserve(server_blob, CURVE25519_కొలత, &server_pub)) != 0)
		వెళ్ళు బహిర్గతం;
	kexc25519_keygen(server_కీలకం, server_pub);
	/* allocate shared secret */
	ఒకవేళ ((buf = sshbuf_new()) == ఖాళీ) {
		r = SSH_ERR_ALLOC_FAIL;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((r = kexc25519_shared_కీలకం_ext(server_కీలకం, client_pub, buf, 0)) < 0)
		వెళ్ళు బహిర్గతం;
#నిర్వచితమైతే DEBUG_KEXECDH
	dump_digest("server public key 25519:", server_pub, CURVE25519_కొలత);
	dump_digest("encoded shared secret:", sshbuf_ptr(buf), sshbuf_len(buf));
#అయితే_ముగింపు
	*server_blobp = server_blob;
	*shared_secretp = buf;
	server_blob = ఖాళీ;
	buf = ఖాళీ;
 బహిర్గతం:
	explicit_bzero(server_కీలకం, పరిమాణం(server_కీలకం));
	sshbuf_free(server_blob);
	sshbuf_free(buf);
	తిరిగి r;
}

పూర్ణాంకం
kex_c25519_dec(నిర్మాణం kex *kex, స్థిరరాశి నిర్మాణం sshbuf *server_blob,
    నిర్మాణం sshbuf **shared_secretp)
{
	నిర్మాణం sshbuf *buf = ఖాళీ;
	స్థిరరాశి u_char *server_pub;
	పూర్ణాంకం r;

	*shared_secretp = ఖాళీ;

	ఒకవేళ (sshbuf_len(server_blob) != CURVE25519_కొలత) {
		r = SSH_ERR_SIGNATURE_INVALID;
		వెళ్ళు బహిర్గతం;
	}
	server_pub = sshbuf_ptr(server_blob);
#నిర్వచితమైతే DEBUG_KEXECDH
	dump_digest("server public key c25519:", server_pub, CURVE25519_కొలత);
#అయితే_ముగింపు
	/* shared secret */
	ఒకవేళ ((buf = sshbuf_new()) == ఖాళీ) {
		r = SSH_ERR_ALLOC_FAIL;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((r = kexc25519_shared_కీలకం_ext(kex->c25519_client_కీలకం, server_pub,
	    buf, 0)) < 0)
		వెళ్ళు బహిర్గతం;
#నిర్వచితమైతే DEBUG_KEXECDH
	dump_digest("encoded shared secret:", sshbuf_ptr(buf), sshbuf_len(buf));
#అయితే_ముగింపు
	*shared_secretp = buf;
	buf = ఖాళీ;
 బహిర్గతం:
	sshbuf_free(buf);
	తిరిగి r;
}
