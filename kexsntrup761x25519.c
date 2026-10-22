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

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ifdef USE_SNTRUP761X25519

#ଅନ୍ତର୍ଭାଵ <sys/types.h>

#ଅନ୍ତର୍ଭାଵ <stdio.h>
#ଅନ୍ତର୍ଭାଵ <string.h>
#ଅନ୍ତର୍ଭାଵ <signal.h>

#ଅନ୍ତର୍ଭାଵ "sshkey.h"
#ଅନ୍ତର୍ଭାଵ "kex.h"
#ଅନ୍ତର୍ଭାଵ "sshbuf.h"
#ଅନ୍ତର୍ଭାଵ "digest.h"
#ଅନ୍ତର୍ଭାଵ "ssherr.h"

ଅସ୍ଥିର crypto_int16 crypto_int16_optblocker = 0;
ଅସ୍ଥିର crypto_int32 crypto_int32_optblocker = 0;
ଅସ୍ଥିର crypto_int64 crypto_int64_optblocker = 0;

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
kex_kem_sntrup761x25519_keypair(ସଂରଚନା kex *kex)
{
	ସଂରଚନା sshbuf *buf = ଖାଲି;
	u_char *cp = ଖାଲି;
	size_t need;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି ((buf = sshbuf_new()) == ଖାଲି)
		ଫେରନ୍ତୁ SSH_ERR_ALLOC_FAIL;
	need = crypto_kem_sntrup761_PUBLICKEYBYTES + CURVE25519_SIZE;
	ଯଦି ((r = sshbuf_reserve(buf, need, &cp)) != 0)
		ଯାଅ out;
	crypto_kem_sntrup761_keypair(cp, kex->sntrup761_client_ଚାବି);
#ifdef DEBUG_KEXECDH
	dump_digest("client public key sntrup761:", cp,
	    crypto_kem_sntrup761_PUBLICKEYBYTES);
#endif
	cp += crypto_kem_sntrup761_PUBLICKEYBYTES;
	kexc25519_keygen(kex->c25519_client_ଚାବି, cp);
#ifdef DEBUG_KEXECDH
	dump_digest("client public key c25519:", cp, CURVE25519_SIZE);
#endif
	kex->client_pub = buf;
	buf = ଖାଲି;
 out:
	sshbuf_free(buf);
	ଫେରନ୍ତୁ r;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
kex_kem_sntrup761x25519_enc(ସଂରଚନା kex *kex,
   ଅଚଳ ସଂରଚନା sshbuf *client_blob, ସଂରଚନା sshbuf **server_blobp,
   ସଂରଚନା sshbuf **shared_secretp)
{
	ସଂରଚନା sshbuf *server_blob = ଖାଲି;
	ସଂରଚନା sshbuf *buf = ଖାଲି;
	ଅଚଳ u_char *client_pub;
	u_char *kem_ଚାବି, *ciphertext, *server_pub;
	u_char server_ଚାବି[CURVE25519_SIZE];
	u_char hash[SSH_DIGEST_MAX_LENGTH];
	size_t need;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	*server_blobp = ଖାଲି;
	*shared_secretp = ଖାଲି;

	/* client_blob contains both KEM and ECDH client pubkeys */
	need = crypto_kem_sntrup761_PUBLICKEYBYTES + CURVE25519_SIZE;
	ଯଦି (sshbuf_len(client_blob) != need) {
		r = SSH_ERR_SIGNATURE_INVALID;
		ଯାଅ out;
	}
	client_pub = sshbuf_ptr(client_blob);
#ifdef DEBUG_KEXECDH
	dump_digest("client public key sntrup761:", client_pub,
	    crypto_kem_sntrup761_PUBLICKEYBYTES);
	dump_digest("client public key 25519:",
	    client_pub + crypto_kem_sntrup761_PUBLICKEYBYTES,
	    CURVE25519_SIZE);
#endif
	/* allocate buffer for concatenation of KEM key and ECDH shared key */
	/* the buffer will be hashed and the result is the shared secret */
	ଯଦି ((buf = sshbuf_new()) == ଖାଲି) {
		r = SSH_ERR_ALLOC_FAIL;
		ଯାଅ out;
	}
	ଯଦି ((r = sshbuf_reserve(buf, crypto_kem_sntrup761_BYTES,
	    &kem_ଚାବି)) != 0)
		ଯାଅ out;
	/* allocate space for encrypted KEM key and ECDH pub key */
	ଯଦି ((server_blob = sshbuf_new()) == ଖାଲି) {
		r = SSH_ERR_ALLOC_FAIL;
		ଯାଅ out;
	}
	need = crypto_kem_sntrup761_CIPHERTEXTBYTES + CURVE25519_SIZE;
	ଯଦି ((r = sshbuf_reserve(server_blob, need, &ciphertext)) != 0)
		ଯାଅ out;
	/* generate and encrypt KEM key with client key */
	crypto_kem_sntrup761_enc(ciphertext, kem_ଚାବି, client_pub);
	/* generate ECDH key pair, store server pubkey after ciphertext */
	server_pub = ciphertext + crypto_kem_sntrup761_CIPHERTEXTBYTES;
	kexc25519_keygen(server_ଚାବି, server_pub);
	/* append ECDH shared key */
	client_pub += crypto_kem_sntrup761_PUBLICKEYBYTES;
	ଯଦି ((r = kexc25519_shared_ଚାବି_ext(server_ଚାବି, client_pub, buf, 1)) < 0)
		ଯାଅ out;
	ଯଦି ((r = ssh_digest_buffer(kex->hash_alg, buf, hash, ଆକାର(hash))) != 0)
		ଯାଅ out;
#ifdef DEBUG_KEXECDH
	dump_digest("server public key 25519:", server_pub, CURVE25519_SIZE);
	dump_digest("server cipher text:", ciphertext,
	    crypto_kem_sntrup761_CIPHERTEXTBYTES);
	dump_digest("server kem key:", kem_ଚାବି, crypto_kem_sntrup761_BYTES);
	dump_digest("concatenation of KEM key and ECDH shared key:",
	    sshbuf_ptr(buf), sshbuf_len(buf));
#endif
	/* string-encoded hash is resulting shared secret */
	sshbuf_reset(buf);
	ଯଦି ((r = sshbuf_put_string(buf, hash,
	    ssh_digest_bytes(kex->hash_alg))) != 0)
		ଯାଅ out;
#ifdef DEBUG_KEXECDH
	dump_digest("encoded shared secret:", sshbuf_ptr(buf), sshbuf_len(buf));
#endif
	*server_blobp = server_blob;
	*shared_secretp = buf;
	server_blob = ଖାଲି;
	buf = ଖାଲି;
 out:
	explicit_bzero(hash, ଆକାର(hash));
	explicit_bzero(server_ଚାବି, ଆକାର(server_ଚାବି));
	sshbuf_free(server_blob);
	sshbuf_free(buf);
	ଫେରନ୍ତୁ r;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
kex_kem_sntrup761x25519_dec(ସଂରଚନା kex *kex,
    ଅଚଳ ସଂରଚନା sshbuf *server_blob, ସଂରଚନା sshbuf **shared_secretp)
{
	ସଂରଚନା sshbuf *buf = ଖାଲି;
	u_char *kem_ଚାବି = ଖାଲି;
	ଅଚଳ u_char *ciphertext, *server_pub;
	u_char hash[SSH_DIGEST_MAX_LENGTH];
	size_t need;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, decoded;

	*shared_secretp = ଖାଲି;

	need = crypto_kem_sntrup761_CIPHERTEXTBYTES + CURVE25519_SIZE;
	ଯଦି (sshbuf_len(server_blob) != need) {
		r = SSH_ERR_SIGNATURE_INVALID;
		ଯାଅ out;
	}
	ciphertext = sshbuf_ptr(server_blob);
	server_pub = ciphertext + crypto_kem_sntrup761_CIPHERTEXTBYTES;
#ifdef DEBUG_KEXECDH
	dump_digest("server cipher text:", ciphertext,
	    crypto_kem_sntrup761_CIPHERTEXTBYTES);
	dump_digest("server public key c25519:", server_pub, CURVE25519_SIZE);
#endif
	/* hash concatenation of KEM key and ECDH shared key */
	ଯଦି ((buf = sshbuf_new()) == ଖାଲି) {
		r = SSH_ERR_ALLOC_FAIL;
		ଯାଅ out;
	}
	ଯଦି ((r = sshbuf_reserve(buf, crypto_kem_sntrup761_BYTES,
	    &kem_ଚାବି)) != 0)
		ଯାଅ out;
	decoded = crypto_kem_sntrup761_dec(kem_ଚାବି, ciphertext,
	    kex->sntrup761_client_ଚାବି);
	ଯଦି ((r = kexc25519_shared_ଚାବି_ext(kex->c25519_client_ଚାବି, server_pub,
	    buf, 1)) < 0)
		ଯାଅ out;
	ଯଦି ((r = ssh_digest_buffer(kex->hash_alg, buf, hash, ଆକାର(hash))) != 0)
		ଯାଅ out;
#ifdef DEBUG_KEXECDH
	dump_digest("client kem key:", kem_ଚାବି, crypto_kem_sntrup761_BYTES);
	dump_digest("concatenation of KEM key and ECDH shared key:",
	    sshbuf_ptr(buf), sshbuf_len(buf));
#endif
	sshbuf_reset(buf);
	ଯଦି ((r = sshbuf_put_string(buf, hash,
	    ssh_digest_bytes(kex->hash_alg))) != 0)
		ଯାଅ out;
#ifdef DEBUG_KEXECDH
	dump_digest("encoded shared secret:", sshbuf_ptr(buf), sshbuf_len(buf));
#endif
	ଯଦି (decoded != 0) {
		r = SSH_ERR_SIGNATURE_INVALID;
		ଯାଅ out;
	}
	*shared_secretp = buf;
	buf = ଖାଲି;
 out:
	explicit_bzero(hash, ଆକାର(hash));
	sshbuf_free(buf);
	ଫେରନ୍ତୁ r;
}

#ଅନ୍ୟଥା

#ଅନ୍ତର୍ଭାଵ "ssherr.h"

ସଂରଚନା kex;
ସଂରଚନା sshbuf;
ସଂରଚନା sshkey;

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
kex_kem_sntrup761x25519_keypair(ସଂରଚନା kex *kex)
{
	ଫେରନ୍ତୁ SSH_ERR_SIGN_ALG_UNSUPPORTED;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
kex_kem_sntrup761x25519_enc(ସଂରଚନା kex *kex,
   ଅଚଳ ସଂରଚନା sshbuf *client_blob, ସଂରଚନା sshbuf **server_blobp,
   ସଂରଚନା sshbuf **shared_secretp)
{
	ଫେରନ୍ତୁ SSH_ERR_SIGN_ALG_UNSUPPORTED;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
kex_kem_sntrup761x25519_dec(ସଂରଚନା kex *kex,
    ଅଚଳ ସଂରଚନା sshbuf *server_blob, ସଂରଚନା sshbuf **shared_secretp)
{
	ଫେରନ୍ତୁ SSH_ERR_SIGN_ALG_UNSUPPORTED;
}
#endif /* USE_SNTRUP761X25519 */
