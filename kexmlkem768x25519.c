/* $OpenBSD: kexmlkem768x25519.c,v 1.3 2026/06/14 03:59:34 djm Exp $ */
/*
 * Copyright (c) 2023 Markus Friedl.  All rights reserved.
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
#అన్తర్భావ "log.h"

#అన్తర్భావ "crypto_api.h"

#నిర్వచితమైతే USE_MLKEM768X25519

పూర్ణాంకం
kex_kem_mlkem768x25519_keypair(నిర్మాణం kex *kex)
{
	నిర్మాణం sshbuf *buf = ఖాళీ;
	u_char *cp = ఖాళీ;
	కొలత_t need;
	పూర్ణాంకం r = SSH_ERR_అంతర్గత_ERROR;

	ఒకవేళ ((buf = sshbuf_new()) == ఖాళీ)
		తిరిగి SSH_ERR_ALLOC_FAIL;
	need = MLKEM768_PUBLICKEYBYTES + CURVE25519_కొలత;
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
	cp += MLKEM768_PUBLICKEYBYTES;
	kexc25519_keygen(kex->c25519_client_కీలకం, cp);
#నిర్వచితమైతే DEBUG_KEXECDH
	dump_digest("client public key c25519:", cp, CURVE25519_కొలత);
#అయితే_ముగింపు
	/* success */
	r = 0;
	kex->client_pub = buf;
	buf = ఖాళీ;
 బహిర్గతం:
	sshbuf_free(buf);
	తిరిగి r;
}

పూర్ణాంకం
kex_kem_mlkem768x25519_enc(నిర్మాణం kex *kex,
   స్థిరరాశి నిర్మాణం sshbuf *client_blob, నిర్మాణం sshbuf **server_blobp,
   నిర్మాణం sshbuf **shared_secretp)
{
	నిర్మాణం sshbuf *server_blob = ఖాళీ;
	నిర్మాణం sshbuf *buf = ఖాళీ;
	స్థిరరాశి u_char *client_pub;
	u_char server_pub[CURVE25519_కొలత], server_కీలకం[CURVE25519_కొలత];
	u_char hash[SSH_DIGEST_MAX_నిడివి];
	u_char ct[MLKEM768_CIPHERTEXTBYTES];
	u_char shared_secret[MLKEM768_బైట్లు];
	కొలత_t need;
	పూర్ణాంకం r = SSH_ERR_అంతర్గత_ERROR;

	*server_blobp = ఖాళీ;
	*shared_secretp = ఖాళీ;

	/* client_blob contains both KEM and ECDH client pubkeys */
	need = MLKEM768_PUBLICKEYBYTES + CURVE25519_కొలత;
	ఒకవేళ (sshbuf_len(client_blob) != need) {
		r = SSH_ERR_SIGNATURE_INVALID;
		వెళ్ళు బహిర్గతం;
	}
	client_pub = sshbuf_ptr(client_blob);
#నిర్వచితమైతే DEBUG_KEXECDH
	dump_digest("client public key mlkem768:", client_pub,
	    MLKEM768_PUBLICKEYBYTES);
	dump_digest("client public key 25519:",
	    client_pub + MLKEM768_PUBLICKEYBYTES,
	    CURVE25519_కొలత);
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
	/* generate ECDH key pair, store server pubkey after ciphertext */
	kexc25519_keygen(server_కీలకం, server_pub);
	ఒకవేళ ((r = sshbuf_put(buf, shared_secret, పరిమాణం(shared_secret))) != 0 ||
	    (r = sshbuf_put(server_blob, ct, పరిమాణం(ct))) != 0 ||
	    (r = sshbuf_put(server_blob, server_pub, పరిమాణం(server_pub))) != 0)
		వెళ్ళు బహిర్గతం;
	/* append ECDH shared key */
	client_pub += MLKEM768_PUBLICKEYBYTES;
	ఒకవేళ ((r = kexc25519_shared_కీలకం_ext(server_కీలకం, client_pub, buf, 1)) < 0)
		వెళ్ళు బహిర్గతం;
	ఒకవేళ ((r = ssh_digest_బఫరు(kex->hash_alg, buf,
	    hash, పరిమాణం(hash))) != 0)
		వెళ్ళు బహిర్గతం;
#నిర్వచితమైతే DEBUG_KEXECDH
	dump_digest("server public key 25519:", server_pub, CURVE25519_కొలత);
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
	explicit_bzero(server_కీలకం, పరిమాణం(server_కీలకం));
	explicit_bzero(shared_secret, పరిమాణం(shared_secret));
	sshbuf_free(server_blob);
	sshbuf_free(buf);
	తిరిగి r;
}

పూర్ణాంకం
kex_kem_mlkem768x25519_dec(నిర్మాణం kex *kex,
    స్థిరరాశి నిర్మాణం sshbuf *server_blob, నిర్మాణం sshbuf **shared_secretp)
{
	నిర్మాణం sshbuf *buf = ఖాళీ;
	u_char shared_secret[MLKEM768_బైట్లు];
	స్థిరరాశి u_char *ciphertext, *server_pub;
	u_char hash[SSH_DIGEST_MAX_నిడివి];
	కొలత_t need;
	పూర్ణాంకం r;

	*shared_secretp = ఖాళీ;

	need = MLKEM768_CIPHERTEXTBYTES + CURVE25519_కొలత;
	ఒకవేళ (sshbuf_len(server_blob) != need) {
		r = SSH_ERR_SIGNATURE_INVALID;
		వెళ్ళు బహిర్గతం;
	}
	ciphertext = sshbuf_ptr(server_blob);
	server_pub = ciphertext + MLKEM768_CIPHERTEXTBYTES;
	/* hash concatenation of KEM key and ECDH shared key */
	ఒకవేళ ((buf = sshbuf_new()) == ఖాళీ) {
		r = SSH_ERR_ALLOC_FAIL;
		వెళ్ళు బహిర్గతం;
	}
#నిర్వచితమైతే DEBUG_KEXECDH
	dump_digest("server cipher text:", ciphertext,
	    MLKEM768_CIPHERTEXTBYTES);
	dump_digest("server public key c25519:", server_pub, CURVE25519_కొలత);
#అయితే_ముగింపు
	ఒకవేళ (crypto_kem_mlkem768_dec(shared_secret, ciphertext,
	    kex->mlkem768_client_కీలకం) != 0) {
		r = SSH_ERR_అంతర్గత_ERROR;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((r = sshbuf_put(buf, shared_secret, పరిమాణం(shared_secret))) != 0)
		వెళ్ళు బహిర్గతం;
	ఒకవేళ ((r = kexc25519_shared_కీలకం_ext(kex->c25519_client_కీలకం, server_pub,
	    buf, 1)) < 0)
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
	sshbuf_free(buf);
	తిరిగి r;
}
#లేకపోతే /* USE_MLKEM768X25519 */
పూర్ణాంకం
kex_kem_mlkem768x25519_keypair(నిర్మాణం kex *kex)
{
	తిరిగి SSH_ERR_SIGN_ALG_UNSUPPORTED;
}

పూర్ణాంకం
kex_kem_mlkem768x25519_enc(నిర్మాణం kex *kex,
   స్థిరరాశి నిర్మాణం sshbuf *client_blob, నిర్మాణం sshbuf **server_blobp,
   నిర్మాణం sshbuf **shared_secretp)
{
	తిరిగి SSH_ERR_SIGN_ALG_UNSUPPORTED;
}

పూర్ణాంకం
kex_kem_mlkem768x25519_dec(నిర్మాణం kex *kex,
    స్థిరరాశి నిర్మాణం sshbuf *server_blob, నిర్మాణం sshbuf **shared_secretp)
{
	తిరిగి SSH_ERR_SIGN_ALG_UNSUPPORTED;
}
#అయితే_ముగింపు /* USE_MLKEM768X25519 */
