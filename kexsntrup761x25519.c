/* $OpenBSD: kexsntrup761x25519.c,v 1.3 2024/09/15 02:20:51 djm Exp $ */
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

#నిర్వచితమైతే USE_SNTRUP761X25519

#అన్తర్భావ <sys/types.h>

#అన్తర్భావ <stdio.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <signal.h>

#అన్తర్భావ "sshkey.h"
#అన్తర్భావ "kex.h"
#అన్తర్భావ "sshbuf.h"
#అన్తర్భావ "digest.h"
#అన్తర్భావ "ssherr.h"

అస్థిర crypto_int16 crypto_int16_optblocker = 0;
అస్థిర crypto_int32 crypto_int32_optblocker = 0;
అస్థిర crypto_int64 crypto_int64_optblocker = 0;

పూర్ణాంకం
kex_kem_sntrup761x25519_keypair(నిర్మాణం kex *kex)
{
	నిర్మాణం sshbuf *buf = ఖాళీ;
	u_char *cp = ఖాళీ;
	కొలత_t need;
	పూర్ణాంకం r;

	ఒకవేళ ((buf = sshbuf_new()) == ఖాళీ)
		తిరిగి SSH_ERR_ALLOC_FAIL;
	need = crypto_kem_sntrup761_PUBLICKEYBYTES + CURVE25519_కొలత;
	ఒకవేళ ((r = sshbuf_reserve(buf, need, &cp)) != 0)
		వెళ్ళు బహిర్గతం;
	crypto_kem_sntrup761_keypair(cp, kex->sntrup761_client_కీలకం);
#నిర్వచితమైతే DEBUG_KEXECDH
	dump_digest("client public key sntrup761:", cp,
	    crypto_kem_sntrup761_PUBLICKEYBYTES);
#అయితే_ముగింపు
	cp += crypto_kem_sntrup761_PUBLICKEYBYTES;
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
kex_kem_sntrup761x25519_enc(నిర్మాణం kex *kex,
   స్థిరరాశి నిర్మాణం sshbuf *client_blob, నిర్మాణం sshbuf **server_blobp,
   నిర్మాణం sshbuf **shared_secretp)
{
	నిర్మాణం sshbuf *server_blob = ఖాళీ;
	నిర్మాణం sshbuf *buf = ఖాళీ;
	స్థిరరాశి u_char *client_pub;
	u_char *kem_కీలకం, *ciphertext, *server_pub;
	u_char server_కీలకం[CURVE25519_కొలత];
	u_char hash[SSH_DIGEST_MAX_నిడివి];
	కొలత_t need;
	పూర్ణాంకం r;

	*server_blobp = ఖాళీ;
	*shared_secretp = ఖాళీ;

	/* client_blob contains both KEM and ECDH client pubkeys */
	need = crypto_kem_sntrup761_PUBLICKEYBYTES + CURVE25519_కొలత;
	ఒకవేళ (sshbuf_len(client_blob) != need) {
		r = SSH_ERR_SIGNATURE_INVALID;
		వెళ్ళు బహిర్గతం;
	}
	client_pub = sshbuf_ptr(client_blob);
#నిర్వచితమైతే DEBUG_KEXECDH
	dump_digest("client public key sntrup761:", client_pub,
	    crypto_kem_sntrup761_PUBLICKEYBYTES);
	dump_digest("client public key 25519:",
	    client_pub + crypto_kem_sntrup761_PUBLICKEYBYTES,
	    CURVE25519_కొలత);
#అయితే_ముగింపు
	/* allocate buffer for concatenation of KEM key and ECDH shared key */
	/* the buffer will be hashed and the result is the shared secret */
	ఒకవేళ ((buf = sshbuf_new()) == ఖాళీ) {
		r = SSH_ERR_ALLOC_FAIL;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((r = sshbuf_reserve(buf, crypto_kem_sntrup761_బైట్లు,
	    &kem_కీలకం)) != 0)
		వెళ్ళు బహిర్గతం;
	/* allocate space for encrypted KEM key and ECDH pub key */
	ఒకవేళ ((server_blob = sshbuf_new()) == ఖాళీ) {
		r = SSH_ERR_ALLOC_FAIL;
		వెళ్ళు బహిర్గతం;
	}
	need = crypto_kem_sntrup761_CIPHERTEXTBYTES + CURVE25519_కొలత;
	ఒకవేళ ((r = sshbuf_reserve(server_blob, need, &ciphertext)) != 0)
		వెళ్ళు బహిర్గతం;
	/* generate and encrypt KEM key with client key */
	crypto_kem_sntrup761_enc(ciphertext, kem_కీలకం, client_pub);
	/* generate ECDH key pair, store server pubkey after ciphertext */
	server_pub = ciphertext + crypto_kem_sntrup761_CIPHERTEXTBYTES;
	kexc25519_keygen(server_కీలకం, server_pub);
	/* append ECDH shared key */
	client_pub += crypto_kem_sntrup761_PUBLICKEYBYTES;
	ఒకవేళ ((r = kexc25519_shared_కీలకం_ext(server_కీలకం, client_pub, buf, 1)) < 0)
		వెళ్ళు బహిర్గతం;
	ఒకవేళ ((r = ssh_digest_బఫరు(kex->hash_alg, buf, hash, పరిమాణం(hash))) != 0)
		వెళ్ళు బహిర్గతం;
#నిర్వచితమైతే DEBUG_KEXECDH
	dump_digest("server public key 25519:", server_pub, CURVE25519_కొలత);
	dump_digest("server cipher text:", ciphertext,
	    crypto_kem_sntrup761_CIPHERTEXTBYTES);
	dump_digest("server kem key:", kem_కీలకం, crypto_kem_sntrup761_బైట్లు);
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
	*server_blobp = server_blob;
	*shared_secretp = buf;
	server_blob = ఖాళీ;
	buf = ఖాళీ;
 బహిర్గతం:
	explicit_bzero(hash, పరిమాణం(hash));
	explicit_bzero(server_కీలకం, పరిమాణం(server_కీలకం));
	sshbuf_free(server_blob);
	sshbuf_free(buf);
	తిరిగి r;
}

పూర్ణాంకం
kex_kem_sntrup761x25519_dec(నిర్మాణం kex *kex,
    స్థిరరాశి నిర్మాణం sshbuf *server_blob, నిర్మాణం sshbuf **shared_secretp)
{
	నిర్మాణం sshbuf *buf = ఖాళీ;
	u_char *kem_కీలకం = ఖాళీ;
	స్థిరరాశి u_char *ciphertext, *server_pub;
	u_char hash[SSH_DIGEST_MAX_నిడివి];
	కొలత_t need;
	పూర్ణాంకం r, decoded;

	*shared_secretp = ఖాళీ;

	need = crypto_kem_sntrup761_CIPHERTEXTBYTES + CURVE25519_కొలత;
	ఒకవేళ (sshbuf_len(server_blob) != need) {
		r = SSH_ERR_SIGNATURE_INVALID;
		వెళ్ళు బహిర్గతం;
	}
	ciphertext = sshbuf_ptr(server_blob);
	server_pub = ciphertext + crypto_kem_sntrup761_CIPHERTEXTBYTES;
#నిర్వచితమైతే DEBUG_KEXECDH
	dump_digest("server cipher text:", ciphertext,
	    crypto_kem_sntrup761_CIPHERTEXTBYTES);
	dump_digest("server public key c25519:", server_pub, CURVE25519_కొలత);
#అయితే_ముగింపు
	/* hash concatenation of KEM key and ECDH shared key */
	ఒకవేళ ((buf = sshbuf_new()) == ఖాళీ) {
		r = SSH_ERR_ALLOC_FAIL;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((r = sshbuf_reserve(buf, crypto_kem_sntrup761_బైట్లు,
	    &kem_కీలకం)) != 0)
		వెళ్ళు బహిర్గతం;
	decoded = crypto_kem_sntrup761_dec(kem_కీలకం, ciphertext,
	    kex->sntrup761_client_కీలకం);
	ఒకవేళ ((r = kexc25519_shared_కీలకం_ext(kex->c25519_client_కీలకం, server_pub,
	    buf, 1)) < 0)
		వెళ్ళు బహిర్గతం;
	ఒకవేళ ((r = ssh_digest_బఫరు(kex->hash_alg, buf, hash, పరిమాణం(hash))) != 0)
		వెళ్ళు బహిర్గతం;
#నిర్వచితమైతే DEBUG_KEXECDH
	dump_digest("client kem key:", kem_కీలకం, crypto_kem_sntrup761_బైట్లు);
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
	ఒకవేళ (decoded != 0) {
		r = SSH_ERR_SIGNATURE_INVALID;
		వెళ్ళు బహిర్గతం;
	}
	*shared_secretp = buf;
	buf = ఖాళీ;
 బహిర్గతం:
	explicit_bzero(hash, పరిమాణం(hash));
	sshbuf_free(buf);
	తిరిగి r;
}

#లేకపోతే

#అన్తర్భావ "ssherr.h"

నిర్మాణం kex;
నిర్మాణం sshbuf;
నిర్మాణం sshkey;

పూర్ణాంకం
kex_kem_sntrup761x25519_keypair(నిర్మాణం kex *kex)
{
	తిరిగి SSH_ERR_SIGN_ALG_UNSUPPORTED;
}

పూర్ణాంకం
kex_kem_sntrup761x25519_enc(నిర్మాణం kex *kex,
   స్థిరరాశి నిర్మాణం sshbuf *client_blob, నిర్మాణం sshbuf **server_blobp,
   నిర్మాణం sshbuf **shared_secretp)
{
	తిరిగి SSH_ERR_SIGN_ALG_UNSUPPORTED;
}

పూర్ణాంకం
kex_kem_sntrup761x25519_dec(నిర్మాణం kex *kex,
    స్థిరరాశి నిర్మాణం sshbuf *server_blob, నిర్మాణం sshbuf **shared_secretp)
{
	తిరిగి SSH_ERR_SIGN_ALG_UNSUPPORTED;
}
#అయితే_ముగింపు /* USE_SNTRUP761X25519 */
