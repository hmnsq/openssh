/* $OpenBSD: kexmlkem768ecdh.c,v 1.4 2026/08/03 06:43:16 djm Exp $ */
/*
 * Copyright (c) 2025 Markus Friedl.  All rights reserved.
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
#అన్తర్భావ <stdint.h>
#అన్తర్భావ <stdbool.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <signal.h>
#అన్తర్భావ <endian.h>

#అన్తర్భావ "sshkey.h"
#అన్తర్భావ "kex.h"
#అన్తర్భావ "sshbuf.h"
#అన్తర్భావ "digest.h"
#అన్తర్భావ "ssherr.h"

#నిర్వచితమైతే WITH_OPENSSL
పూర్ణాంకం
kex_kem_mlkem768ecdh_keypair(నిర్మాణం kex *kex)
{
	నిర్మాణం sshbuf *buf = ఖాళీ;
	నిర్మాణం sshbuf *ec_blob = ఖాళీ;
	EC_కీలకం *client_కీలకం = ఖాళీ;
	స్థిరరాశి EC_సమూహం *సమూహం;
	స్థిరరాశి EC_బిందువు *ప్రజా_కీలకం;
	u_char *cp = ఖాళీ;
	కొలత_t need;
	పూర్ణాంకం r = SSH_ERR_అంతర్గత_ERROR;

	ఒకవేళ ((buf = sshbuf_new()) == ఖాళీ)
		తిరిగి SSH_ERR_ALLOC_FAIL;
	need = MLKEM768_PUBLICKEYBYTES;
	ఒకవేళ ((r = sshbuf_reserve(buf, need, &cp)) != 0)
		వెళ్ళు బహిర్గతం;
	ఒకవేళ (crypto_kem_mlkem768_keypair(cp, kex->mlkem768_client_కీలకం) != 0) {
		r = SSH_ERR_అంతర్గత_ERROR;
		వెళ్ళు బహిర్గతం;
	}
#నిర్వచితమైతే DEBUG_KEXECDH
	dump_digest("client public key mlkem768:", cp,
	    MLKEM768_PUBLICKEYBYTES);
#అయితే_ముగింపు
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

	ఒకవేళ ((ec_blob = sshbuf_new()) == ఖాళీ) {
		r = SSH_ERR_ALLOC_FAIL;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((r = sshbuf_put_ec(ec_blob, ప్రజా_కీలకం, సమూహం)) != 0 ||
	    (r = sshbuf_get_u32(ec_blob, ఖాళీ)) != 0 ||
	    (r = sshbuf_putb(buf, ec_blob)) != 0)
		వెళ్ళు బహిర్గతం;
#నిర్వచితమైతే DEBUG_KEXECDH
	fputs("client private key EC:\n", stderr);
	sshkey_dump_ec_కీలకం(client_కీలకం);
#అయితే_ముగింపు
	/* success */
	r = 0;
	kex->ec_client_కీలకం = client_కీలకం;
	kex->ec_సమూహం = సమూహం;
	client_కీలకం = ఖాళీ;	/* owned by the kex */
	kex->client_pub = buf;
	buf = ఖాళీ;
 బహిర్గతం:
	sshbuf_free(buf);
	sshbuf_free(ec_blob);
	EC_కీలకం_free(client_కీలకం);
	తిరిగి r;
}

పూర్ణాంకం
kex_kem_mlkem768ecdh_enc(నిర్మాణం kex *kex,
   స్థిరరాశి నిర్మాణం sshbuf *client_blob, నిర్మాణం sshbuf **server_blobp,
   నిర్మాణం sshbuf **shared_secretp)
{
	స్థిరరాశి EC_సమూహం *సమూహం;
	స్థిరరాశి EC_బిందువు *pub_కీలకం;
	EC_కీలకం *server_కీలకం = ఖాళీ;
	నిర్మాణం sshbuf *ec_pub = ఖాళీ;
	నిర్మాణం sshbuf *ec_blob = ఖాళీ;
	నిర్మాణం sshbuf *ec_shared = ఖాళీ;
	నిర్మాణం sshbuf *server_blob = ఖాళీ;
	నిర్మాణం sshbuf *buf = ఖాళీ;
	స్థిరరాశి u_char *client_pub;
	u_char hash[SSH_DIGEST_MAX_నిడివి];
	u_char ct[MLKEM768_CIPHERTEXTBYTES];
	u_char shared_secret[MLKEM768_బైట్లు];
	కొలత_t need;
	పూర్ణాంకం r = SSH_ERR_అంతర్గత_ERROR;

	*server_blobp = ఖాళీ;
	*shared_secretp = ఖాళీ;

	/* client_blob contains both KEM and ECDH client pubkeys */
	need = MLKEM768_PUBLICKEYBYTES;
	ఒకవేళ (sshbuf_len(client_blob) <= need) {
		r = SSH_ERR_SIGNATURE_INVALID;
		వెళ్ళు బహిర్గతం;
	}
	client_pub = sshbuf_ptr(client_blob);
#నిర్వచితమైతే DEBUG_KEXECDH
	dump_digest("client public key mlkem768:", client_pub,
	    MLKEM768_PUBLICKEYBYTES);
#అయితే_ముగింపు

	/* allocate buffer for concatenation of KEM key and ECDH shared key */
	/* the buffer will be hashed and the result is the shared secret */
	ఒకవేళ ((buf = sshbuf_new()) == ఖాళీ) {
		r = SSH_ERR_ALLOC_FAIL;
		వెళ్ళు బహిర్గతం;
	}
	/* allocate space for encrypted KEM key and ECDH pub key */
	ఒకవేళ ((server_blob = sshbuf_new()) == ఖాళీ) {
		r = SSH_ERR_ALLOC_FAIL;
		వెళ్ళు బహిర్గతం;
	}
	/* generate and encrypt KEM key with client key */
	ఒకవేళ (crypto_kem_mlkem768_enc(ct, shared_secret, client_pub) != 0) {
		r = SSH_ERR_అంతర్గత_ERROR;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((r = sshbuf_put(buf, shared_secret, పరిమాణం(shared_secret))) != 0 ||
	    (r = sshbuf_put(server_blob, ct, పరిమాణం(ct))) != 0)
		వెళ్ళు బహిర్గతం;

	client_pub += MLKEM768_PUBLICKEYBYTES;
	ఒకవేళ ((ec_pub = sshbuf_from(client_pub, sshbuf_len(client_blob) -
	    MLKEM768_PUBLICKEYBYTES)) == ఖాళీ) {
		r = SSH_ERR_ALLOC_FAIL;
		వెళ్ళు బహిర్గతం;
	}
	/* generate ECDH key pair */
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
	fputs("server private key EC:\n", stderr);
	sshkey_dump_ec_కీలకం(server_కీలకం);
#అయితే_ముగింపు
	/* store server pubkey after ciphertext */
	pub_కీలకం = EC_కీలకం_get0_ప్రజా_కీలకం(server_కీలకం);
	ఒకవేళ ((ec_blob = sshbuf_new()) == ఖాళీ) {
		r = SSH_ERR_ALLOC_FAIL;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((r = sshbuf_put_ec(ec_blob, pub_కీలకం, సమూహం)) != 0 ||
	    (r = sshbuf_get_u32(ec_blob, ఖాళీ)) != 0 ||
	    (r = sshbuf_putb(server_blob, ec_blob)) != 0)
		వెళ్ళు బహిర్గతం;

	/* append ECDH shared key */
	ఒకవేళ ((r = kex_ecdh_dec_కీలకం_సమూహం(kex, ec_pub, server_కీలకం, సమూహం,
	    1, &ec_shared)) != 0 ||
	    (r = sshbuf_putb(buf, ec_shared)) != 0)
		వెళ్ళు బహిర్గతం;

	ఒకవేళ ((r = ssh_digest_బఫరు(kex->hash_alg, buf, hash, పరిమాణం(hash))) != 0)
		వెళ్ళు బహిర్గతం;
#నిర్వచితమైతే DEBUG_KEXECDH
	dump_digest("server cipher text:", ct, పరిమాణం(ct));
	dump_digest("server kem key:", shared_secret, పరిమాణం(shared_secret));
	dump_digest("concatenation of KEM key and ECDH shared key:",
	    sshbuf_ptr(buf), sshbuf_len(buf));
#అయితే_ముగింపు
	/* string-encoded hash is resulting shared secret */
	sshbuf_reset(buf);
	ఒకవేళ ((r = sshbuf_put_string(buf, hash,
	    ssh_digest_బైట్లు(kex->hash_alg))) != 0)
		వెళ్ళు బహిర్గతం;
#నిర్వచితమైతే DEBUG_KEXECDH
	dump_digest("encoded shared secret:", sshbuf_ptr(buf), sshbuf_len(buf));
#అయితే_ముగింపు
	/* success */
	r = 0;
	*server_blobp = server_blob;
	*shared_secretp = buf;
	server_blob = ఖాళీ;
	buf = ఖాళీ;
 బహిర్గతం:
	explicit_bzero(hash, పరిమాణం(hash));
	explicit_bzero(shared_secret, పరిమాణం(shared_secret));
	EC_కీలకం_free(server_కీలకం);
	sshbuf_free(ec_pub);
	sshbuf_free(ec_blob);
	sshbuf_free(ec_shared);
	sshbuf_free(server_blob);
	sshbuf_free(buf);
	తిరిగి r;
}

పూర్ణాంకం
kex_kem_mlkem768ecdh_dec(నిర్మాణం kex *kex,
    స్థిరరాశి నిర్మాణం sshbuf *server_blob, నిర్మాణం sshbuf **shared_secretp)
{
	నిర్మాణం sshbuf *buf = ఖాళీ;
	నిర్మాణం sshbuf *ec_pub = ఖాళీ;
	నిర్మాణం sshbuf *ec_shared = ఖాళీ;
	u_char shared_secret[MLKEM768_బైట్లు];
	స్థిరరాశి u_char *ciphertext, *server_pub;
	u_char hash[SSH_DIGEST_MAX_నిడివి];
	కొలత_t need;
	పూర్ణాంకం r;

	*shared_secretp = ఖాళీ;

	need = MLKEM768_CIPHERTEXTBYTES;
	ఒకవేళ (sshbuf_len(server_blob) <= need) {
		r = SSH_ERR_SIGNATURE_INVALID;
		వెళ్ళు బహిర్గతం;
	}
	ciphertext = sshbuf_ptr(server_blob);
	server_pub = ciphertext + MLKEM768_CIPHERTEXTBYTES;
#నిర్వచితమైతే DEBUG_KEXECDH
	dump_digest("server cipher text (dec):", ciphertext,
	    MLKEM768_CIPHERTEXTBYTES);
#అయితే_ముగింపు
	/* hash concatenation of KEM key and ECDH shared key */
	ఒకవేళ ((buf = sshbuf_new()) == ఖాళీ) {
		r = SSH_ERR_ALLOC_FAIL;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ (crypto_kem_mlkem768_dec(shared_secret, ciphertext,
	    kex->mlkem768_client_కీలకం) != 0) {
		r = SSH_ERR_అంతర్గత_ERROR;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((r = sshbuf_put(buf, shared_secret, పరిమాణం(shared_secret))) != 0)
		వెళ్ళు బహిర్గతం;
	ఒకవేళ ((ec_pub = sshbuf_from(server_pub, sshbuf_len(server_blob) - need))
	    == ఖాళీ) {
		r = SSH_ERR_ALLOC_FAIL;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((r = kex_ecdh_dec_కీలకం_సమూహం(kex, ec_pub, kex->ec_client_కీలకం,
	    kex->ec_సమూహం, 1, &ec_shared)) != 0 ||
	    (r = sshbuf_putb(buf, ec_shared)) != 0)
		వెళ్ళు బహిర్గతం;
	ఒకవేళ ((r = ssh_digest_బఫరు(kex->hash_alg, buf,
	    hash, పరిమాణం(hash))) != 0)
		వెళ్ళు బహిర్గతం;
#నిర్వచితమైతే DEBUG_KEXECDH
	dump_digest("client kem key:", shared_secret, పరిమాణం(shared_secret));
	dump_digest("concatenation of KEM key and ECDH shared key:",
	    sshbuf_ptr(buf), sshbuf_len(buf));
#అయితే_ముగింపు
	sshbuf_reset(buf);
	ఒకవేళ ((r = sshbuf_put_string(buf, hash,
	    ssh_digest_బైట్లు(kex->hash_alg))) != 0)
		వెళ్ళు బహిర్గతం;
#నిర్వచితమైతే DEBUG_KEXECDH
	dump_digest("encoded shared secret:", sshbuf_ptr(buf), sshbuf_len(buf));
#అయితే_ముగింపు
	/* success */
	r = 0;
	*shared_secretp = buf;
	buf = ఖాళీ;
 బహిర్గతం:
	explicit_bzero(hash, పరిమాణం(hash));
	explicit_bzero(shared_secret, పరిమాణం(shared_secret));
	EC_కీలకం_free(kex->ec_client_కీలకం);
	kex->ec_client_కీలకం = ఖాళీ;
	sshbuf_free(ec_pub);
	sshbuf_free(ec_shared);
	sshbuf_free(buf);
	తిరిగి r;
}
#అయితే_ముగింపు	/* WITH_OPENSSL */
