/* $OpenBSD: kexecdh.c,v 1.14 2026/08/03 06:43:16 djm Exp $ */
/*
 * Copyright (c) 2010 Damien Miller.  All rights reserved.
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

#ఒకవేళ defined(WITH_OPENSSL)

#అన్తర్భావ <sys/types.h>

#అన్తర్భావ <stdio.h>
#అన్తర్భావ <signal.h>

#అన్తర్భావ <openssl/bn.h>
#అన్తర్భావ <openssl/ecdh.h>

#అన్తర్భావ "sshkey.h"
#అన్తర్భావ "kex.h"
#అన్తర్భావ "sshbuf.h"
#అన్తర్భావ "ssherr.h"

పూర్ణాంకం
kex_ecdh_keypair(నిర్మాణం kex *kex)
{
	EC_కీలకం *client_కీలకం = ఖాళీ;
	స్థిరరాశి EC_సమూహం *సమూహం;
	స్థిరరాశి EC_బిందువు *ప్రజా_కీలకం;
	నిర్మాణం sshbuf *buf = ఖాళీ;
	పూర్ణాంకం r;

	ఒకవేళ ((client_కీలకం = EC_కీలకం_new_by_వక్రం_name(kex->ec_nid)) == ఖాళీ) {
		r = SSH_ERR_ALLOC_FAIL;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ (EC_కీలకం_generate_కీలకం(client_కీలకం) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		వెళ్ళు బహిర్గతం;
	}
	సమూహం = EC_కీలకం_get0_సమూహం(client_కీలకం);
	ప్రజా_కీలకం = EC_కీలకం_get0_ప్రజా_కీలకం(client_కీలకం);

	ఒకవేళ ((buf = sshbuf_new()) == ఖాళీ) {
		r = SSH_ERR_ALLOC_FAIL;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((r = sshbuf_put_ec(buf, ప్రజా_కీలకం, సమూహం)) != 0 ||
	    (r = sshbuf_get_u32(buf, ఖాళీ)) != 0)
		వెళ్ళు బహిర్గతం;
#నిర్వచితమైతే DEBUG_KEXECDH
	fputs("client private key:\n", stderr);
	sshkey_dump_ec_కీలకం(client_కీలకం);
#అయితే_ముగింపు
	kex->ec_client_కీలకం = client_కీలకం;
	kex->ec_సమూహం = సమూహం;
	client_కీలకం = ఖాళీ;	/* owned by the kex */
	kex->client_pub = buf;
	buf = ఖాళీ;
 బహిర్గతం:
	EC_కీలకం_free(client_కీలకం);
	sshbuf_free(buf);
	తిరిగి r;
}

పూర్ణాంకం
kex_ecdh_enc(నిర్మాణం kex *kex, స్థిరరాశి నిర్మాణం sshbuf *client_blob,
    నిర్మాణం sshbuf **server_blobp, నిర్మాణం sshbuf **shared_secretp)
{
	స్థిరరాశి EC_సమూహం *సమూహం;
	స్థిరరాశి EC_బిందువు *pub_కీలకం;
	EC_కీలకం *server_కీలకం = ఖాళీ;
	నిర్మాణం sshbuf *server_blob = ఖాళీ;
	పూర్ణాంకం r;

	*server_blobp = ఖాళీ;
	*shared_secretp = ఖాళీ;

	ఒకవేళ ((server_కీలకం = EC_కీలకం_new_by_వక్రం_name(kex->ec_nid)) == ఖాళీ) {
		r = SSH_ERR_ALLOC_FAIL;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ (EC_కీలకం_generate_కీలకం(server_కీలకం) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		వెళ్ళు బహిర్గతం;
	}
	సమూహం = EC_కీలకం_get0_సమూహం(server_కీలకం);

#నిర్వచితమైతే DEBUG_KEXECDH
	fputs("server private key:\n", stderr);
	sshkey_dump_ec_కీలకం(server_కీలకం);
#అయితే_ముగింపు
	pub_కీలకం = EC_కీలకం_get0_ప్రజా_కీలకం(server_కీలకం);
	ఒకవేళ ((server_blob = sshbuf_new()) == ఖాళీ) {
		r = SSH_ERR_ALLOC_FAIL;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((r = sshbuf_put_ec(server_blob, pub_కీలకం, సమూహం)) != 0 ||
	    (r = sshbuf_get_u32(server_blob, ఖాళీ)) != 0)
		వెళ్ళు బహిర్గతం;
	ఒకవేళ ((r = kex_ecdh_dec_కీలకం_సమూహం(kex, client_blob, server_కీలకం, సమూహం,
	    0, shared_secretp)) != 0)
		వెళ్ళు బహిర్గతం;
	*server_blobp = server_blob;
	server_blob = ఖాళీ;
 బహిర్గతం:
	EC_కీలకం_free(server_కీలకం);
	sshbuf_free(server_blob);
	తిరిగి r;
}

పూర్ణాంకం
kex_ecdh_dec_కీలకం_సమూహం(నిర్మాణం kex *kex, స్థిరరాశి నిర్మాణం sshbuf *ec_blob,
    EC_కీలకం *కీలకం, స్థిరరాశి EC_సమూహం *సమూహం, పూర్ణాంకం raw, నిర్మాణం sshbuf **shared_secretp)
{
	నిర్మాణం sshbuf *buf = ఖాళీ;
	BIGNUM *shared_secret = ఖాళీ;
	EC_బిందువు *dh_pub = ఖాళీ;
	u_char *kbuf = ఖాళీ;
	కొలత_t klen = 0;
	పూర్ణాంకం r;

	*shared_secretp = ఖాళీ;

	ఒకవేళ ((buf = sshbuf_new()) == ఖాళీ) {
		r = SSH_ERR_ALLOC_FAIL;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((r = sshbuf_put_stringb(buf, ec_blob)) != 0)
		వెళ్ళు బహిర్గతం;
	ఒకవేళ ((dh_pub = EC_బిందువు_new(సమూహం)) == ఖాళీ) {
		r = SSH_ERR_ALLOC_FAIL;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((r = sshbuf_get_ec(buf, dh_pub, సమూహం)) != 0) {
		వెళ్ళు బహిర్గతం;
	}
	sshbuf_reset(buf);

#నిర్వచితమైతే DEBUG_KEXECDH
	fputs("public key:\n", stderr);
	sshkey_dump_ec_బిందువు(సమూహం, dh_pub);
#అయితే_ముగింపు
	ఒకవేళ (sshkey_ec_validate_ప్రజా(సమూహం, dh_pub) != 0) {
		r = SSH_ERR_సందేశం_INCOMPLETE;
		వెళ్ళు బహిర్గతం;
	}
	klen = (EC_సమూహం_get_degree(సమూహం) + 7) / 8;
	ఒకవేళ ((kbuf = జ్ఞాపకం_ఇవ్వు(klen)) == ఖాళీ) {
		r = SSH_ERR_ALLOC_FAIL;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ (ECDH_compute_కీలకం(kbuf, klen, dh_pub, కీలకం, ఖాళీ) != (పూర్ణాంకం)klen) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		వెళ్ళు బహిర్గతం;
	}
#నిర్వచితమైతే DEBUG_KEXECDH
	dump_digest("shared secret", kbuf, klen);
#అయితే_ముగింపు
	ఒకవేళ (raw) {
		ఒకవేళ ((r = sshbuf_put(buf, kbuf, klen)) != 0)
			వెళ్ళు బహిర్గతం;
	} లేకపోతే {
		ఒకవేళ ((shared_secret = BN_new()) == ఖాళీ) {
			r = SSH_ERR_ALLOC_FAIL;
			వెళ్ళు బహిర్గతం;
		}
		ఒకవేళ (BN_bin2bn(kbuf, klen, shared_secret) == ఖాళీ) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			వెళ్ళు బహిర్గతం;
		}
		ఒకవేళ ((r = sshbuf_put_bignum2(buf, shared_secret)) != 0)
			వెళ్ళు బహిర్గతం;
	}
	*shared_secretp = buf;
	buf = ఖాళీ;
 బహిర్గతం:
	EC_బిందువు_clear_free(dh_pub);
	BN_clear_free(shared_secret);
	freezero(kbuf, klen);
	sshbuf_free(buf);
	తిరిగి r;
}

పూర్ణాంకం
kex_ecdh_dec(నిర్మాణం kex *kex, స్థిరరాశి నిర్మాణం sshbuf *server_blob,
    నిర్మాణం sshbuf **shared_secretp)
{
	పూర్ణాంకం r;

	r = kex_ecdh_dec_కీలకం_సమూహం(kex, server_blob, kex->ec_client_కీలకం,
	    kex->ec_సమూహం, 0, shared_secretp);
	EC_కీలకం_free(kex->ec_client_కీలకం);
	kex->ec_client_కీలకం = ఖాళీ;
	తిరిగి r;
}

#అయితే_ముగింపు /* WITH_OPENSSL */
