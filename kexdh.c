/* $OpenBSD: kexdh.c,v 1.36 2026/02/14 00:18:34 jsg Exp $ */
/*
 * Copyright (c) 2019 Markus Friedl.  All rights reserved.
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
#అన్తర్భావ "openbsd-compat/openssl-compat.h"

#అన్తర్భావ <sys/types.h>

#అన్తర్భావ <stdio.h>
#అన్తర్భావ <signal.h>

#అన్తర్భావ <openssl/bn.h>
#అన్తర్భావ <openssl/dh.h>

#అన్తర్భావ "kex.h"
#అన్తర్భావ "sshbuf.h"
#అన్తర్భావ "ssherr.h"
#అన్తర్భావ "dh.h"
#అన్తర్భావ "log.h"

పూర్ణాంకం
kex_dh_keygen(నిర్మాణం kex *kex)
{
	ఎంపిక (kex->kex_type) {
	స్థితి KEX_DH_GRP1_SHA1:
		kex->dh = dh_new_group1();
		ఆపు;
	స్థితి KEX_DH_GRP14_SHA1:
	స్థితి KEX_DH_GRP14_SHA256:
		kex->dh = dh_new_group14();
		ఆపు;
	స్థితి KEX_DH_GRP16_SHA512:
		kex->dh = dh_new_group16();
		ఆపు;
	స్థితి KEX_DH_GRP18_SHA512:
		kex->dh = dh_new_group18();
		ఆపు;
	అప్రమేయ:
		తిరిగి SSH_ERR_INVALID_వాదం;
	}
	ఒకవేళ (kex->dh == ఖాళీ)
		తిరిగి SSH_ERR_ALLOC_FAIL;
	తిరిగి (dh_gen_కీలకం(kex->dh, kex->we_need * 8));
}

పూర్ణాంకం
kex_dh_compute_కీలకం(నిర్మాణం kex *kex, BIGNUM *dh_pub, నిర్మాణం sshbuf *బహిర్గతం)
{
	BIGNUM *shared_secret = ఖాళీ;
	u_char *kbuf = ఖాళీ;
	కొలత_t klen = 0;
	పూర్ణాంకం kout, r;

#నిర్వచితమైతే DEBUG_KEXDH
	fprintf(stderr, "dh_pub= ");
	BN_print_fp(stderr, dh_pub);
	fprintf(stderr, "\n");
	debug("bits %d", BN_అంకె_బిట్లు(dh_pub));
	DHparams_print_fp(stderr, kex->dh);
	fprintf(stderr, "\n");
#అయితే_ముగింపు

	ఒకవేళ (!dh_pub_is_valid(kex->dh, dh_pub)) {
		r = SSH_ERR_సందేశం_INCOMPLETE;
		వెళ్ళు బహిర్గతం;
	}
	klen = DH_కొలత(kex->dh);
	ఒకవేళ ((kbuf = జ్ఞాపకం_ఇవ్వు(klen)) == ఖాళీ ||
	    (shared_secret = BN_new()) == ఖాళీ) {
		r = SSH_ERR_ALLOC_FAIL;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((kout = DH_compute_కీలకం(kbuf, dh_pub, kex->dh)) < 0 ||
	    BN_bin2bn(kbuf, kout, shared_secret) == ఖాళీ) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		వెళ్ళు బహిర్గతం;
	}
#నిర్వచితమైతే DEBUG_KEXDH
	dump_digest("shared secret", kbuf, kout);
#అయితే_ముగింపు
	r = sshbuf_put_bignum2(బహిర్గతం, shared_secret);
 బహిర్గతం:
	freezero(kbuf, klen);
	BN_clear_free(shared_secret);
	తిరిగి r;
}

పూర్ణాంకం
kex_dh_keypair(నిర్మాణం kex *kex)
{
	స్థిరరాశి BIGNUM *pub_కీలకం;
	నిర్మాణం sshbuf *buf = ఖాళీ;
	పూర్ణాంకం r;

	ఒకవేళ ((r = kex_dh_keygen(kex)) != 0)
		తిరిగి r;
	DH_get0_కీలకం(kex->dh, &pub_కీలకం, ఖాళీ);
	ఒకవేళ ((buf = sshbuf_new()) == ఖాళీ)
		తిరిగి SSH_ERR_ALLOC_FAIL;
	ఒకవేళ ((r = sshbuf_put_bignum2(buf, pub_కీలకం)) != 0 ||
	    (r = sshbuf_get_u32(buf, ఖాళీ)) != 0)
		వెళ్ళు బహిర్గతం;
#నిర్వచితమైతే DEBUG_KEXDH
	DHparams_print_fp(stderr, kex->dh);
	fprintf(stderr, "pub= ");
	BN_print_fp(stderr, pub_కీలకం);
	fprintf(stderr, "\n");
#అయితే_ముగింపు
	kex->client_pub = buf;
	buf = ఖాళీ;
 బహిర్గతం:
	sshbuf_free(buf);
	తిరిగి r;
}

పూర్ణాంకం
kex_dh_enc(నిర్మాణం kex *kex, స్థిరరాశి నిర్మాణం sshbuf *client_blob,
    నిర్మాణం sshbuf **server_blobp, నిర్మాణం sshbuf **shared_secretp)
{
	స్థిరరాశి BIGNUM *pub_కీలకం;
	నిర్మాణం sshbuf *server_blob = ఖాళీ;
	పూర్ణాంకం r;

	*server_blobp = ఖాళీ;
	*shared_secretp = ఖాళీ;

	ఒకవేళ ((r = kex_dh_keygen(kex)) != 0)
		వెళ్ళు బహిర్గతం;
	DH_get0_కీలకం(kex->dh, &pub_కీలకం, ఖాళీ);
	ఒకవేళ ((server_blob = sshbuf_new()) == ఖాళీ) {
		r = SSH_ERR_ALLOC_FAIL;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((r = sshbuf_put_bignum2(server_blob, pub_కీలకం)) != 0 ||
	    (r = sshbuf_get_u32(server_blob, ఖాళీ)) != 0)
		వెళ్ళు బహిర్గతం;
	ఒకవేళ ((r = kex_dh_dec(kex, client_blob, shared_secretp)) != 0)
		వెళ్ళు బహిర్గతం;
	*server_blobp = server_blob;
	server_blob = ఖాళీ;
 బహిర్గతం:
	DH_free(kex->dh);
	kex->dh = ఖాళీ;
	sshbuf_free(server_blob);
	తిరిగి r;
}

పూర్ణాంకం
kex_dh_dec(నిర్మాణం kex *kex, స్థిరరాశి నిర్మాణం sshbuf *dh_blob,
    నిర్మాణం sshbuf **shared_secretp)
{
	నిర్మాణం sshbuf *buf = ఖాళీ;
	BIGNUM *dh_pub = ఖాళీ;
	పూర్ణాంకం r;

	*shared_secretp = ఖాళీ;

	ఒకవేళ ((buf = sshbuf_new()) == ఖాళీ) {
		r = SSH_ERR_ALLOC_FAIL;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((r = sshbuf_put_stringb(buf, dh_blob)) != 0 ||
	    (r = sshbuf_get_bignum2(buf, &dh_pub)) != 0)
		వెళ్ళు బహిర్గతం;
	sshbuf_reset(buf);
	ఒకవేళ ((r = kex_dh_compute_కీలకం(kex, dh_pub, buf)) != 0)
		వెళ్ళు బహిర్గతం;
	*shared_secretp = buf;
	buf = ఖాళీ;
 బహిర్గతం:
	BN_free(dh_pub);
	DH_free(kex->dh);
	kex->dh = ఖాళీ;
	sshbuf_free(buf);
	తిరిగి r;
}
#అయితే_ముగింపు /* WITH_OPENSSL */
