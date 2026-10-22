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

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ଅନ୍ତର୍ଭାଵ <sys/types.h>

#ଅନ୍ତର୍ଭାଵ <stdio.h>
#ଅନ୍ତର୍ଭାଵ <stdint.h>
#ଅନ୍ତର୍ଭାଵ <stdbool.h>
#ଅନ୍ତର୍ଭାଵ <string.h>
#ଅନ୍ତର୍ଭାଵ <signal.h>
#ଅନ୍ତର୍ଭାଵ <endian.h>

#ଅନ୍ତର୍ଭାଵ "sshkey.h"
#ଅନ୍ତର୍ଭାଵ "kex.h"
#ଅନ୍ତର୍ଭାଵ "sshbuf.h"
#ଅନ୍ତର୍ଭାଵ "digest.h"
#ଅନ୍ତର୍ଭାଵ "ssherr.h"
#ଅନ୍ତର୍ଭାଵ "log.h"

#ଅନ୍ତର୍ଭାଵ "crypto_api.h"

#ifdef USE_MLKEM768X25519

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
kex_kem_mlkem768x25519_keypair(ସଂରଚନା kex *kex)
{
	ସଂରଚନା sshbuf *buf = ଖାଲି;
	u_char *cp = ଖାଲି;
	size_t need;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r = SSH_ERR_INTERNAL_ERROR;

	ଯଦି ((buf = sshbuf_new()) == ଖାଲି)
		ଫେରନ୍ତୁ SSH_ERR_ALLOC_FAIL;
	need = MLKEM768_PUBLICKEYBYTES + CURVE25519_SIZE;
	ଯଦି ((r = sshbuf_reserve(buf, need, &cp)) != 0)
		ଯାଅ out;
	ଯଦି (crypto_kem_mlkem768_keypair(cp, kex->mlkem768_client_ଚାବି) != 0) {
		r = SSH_ERR_INTERNAL_ERROR;
		ଯାଅ out;
	}
#ifdef DEBUG_KEXECDH
	dump_digest("client public key mlkem768:", cp,
	    MLKEM768_PUBLICKEYBYTES);
#endif
	cp += MLKEM768_PUBLICKEYBYTES;
	kexc25519_keygen(kex->c25519_client_ଚାବି, cp);
#ifdef DEBUG_KEXECDH
	dump_digest("client public key c25519:", cp, CURVE25519_SIZE);
#endif
	/* success */
	r = 0;
	kex->client_pub = buf;
	buf = ଖାଲି;
 out:
	sshbuf_free(buf);
	ଫେରନ୍ତୁ r;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
kex_kem_mlkem768x25519_enc(ସଂରଚନା kex *kex,
   ଅଚଳ ସଂରଚନା sshbuf *client_blob, ସଂରଚନା sshbuf **server_blobp,
   ସଂରଚନା sshbuf **shared_secretp)
{
	ସଂରଚନା sshbuf *server_blob = ଖାଲି;
	ସଂରଚନା sshbuf *buf = ଖାଲି;
	ଅଚଳ u_char *client_pub;
	u_char server_pub[CURVE25519_SIZE], server_ଚାବି[CURVE25519_SIZE];
	u_char hash[SSH_DIGEST_MAX_LENGTH];
	u_char ct[MLKEM768_CIPHERTEXTBYTES];
	u_char shared_secret[MLKEM768_BYTES];
	size_t need;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r = SSH_ERR_INTERNAL_ERROR;

	*server_blobp = ଖାଲି;
	*shared_secretp = ଖାଲି;

	/* client_blob contains both KEM and ECDH client pubkeys */
	need = MLKEM768_PUBLICKEYBYTES + CURVE25519_SIZE;
	ଯଦି (sshbuf_len(client_blob) != need) {
		r = SSH_ERR_SIGNATURE_INVALID;
		ଯାଅ out;
	}
	client_pub = sshbuf_ptr(client_blob);
#ifdef DEBUG_KEXECDH
	dump_digest("client public key mlkem768:", client_pub,
	    MLKEM768_PUBLICKEYBYTES);
	dump_digest("client public key 25519:",
	    client_pub + MLKEM768_PUBLICKEYBYTES,
	    CURVE25519_SIZE);
#endif

	/* allocate buffer for concatenation of KEM key and ECDH shared key */
	/* the buffer will be hashed and the result is the shared secret */
	ଯଦି ((buf = sshbuf_new()) == ଖାଲି) {
		r = SSH_ERR_ALLOC_FAIL;
		ଯାଅ out;
	}
	/* allocate space for encrypted KEM key and ECDH pub key */
	ଯଦି ((server_blob = sshbuf_new()) == ଖାଲି) {
		r = SSH_ERR_ALLOC_FAIL;
		ଯାଅ out;
	}
	/* generate and encrypt KEM key with client key */
	ଯଦି (crypto_kem_mlkem768_enc(ct, shared_secret, client_pub) != 0) {
		r = SSH_ERR_INTERNAL_ERROR;
		ଯାଅ out;
	}
	/* generate ECDH key pair, store server pubkey after ciphertext */
	kexc25519_keygen(server_ଚାବି, server_pub);
	ଯଦି ((r = sshbuf_put(buf, shared_secret, ଆକାର(shared_secret))) != 0 ||
	    (r = sshbuf_put(server_blob, ct, ଆକାର(ct))) != 0 ||
	    (r = sshbuf_put(server_blob, server_pub, ଆକାର(server_pub))) != 0)
		ଯାଅ out;
	/* append ECDH shared key */
	client_pub += MLKEM768_PUBLICKEYBYTES;
	ଯଦି ((r = kexc25519_shared_ଚାବି_ext(server_ଚାବି, client_pub, buf, 1)) < 0)
		ଯାଅ out;
	ଯଦି ((r = ssh_digest_buffer(kex->hash_alg, buf,
	    hash, ଆକାର(hash))) != 0)
		ଯାଅ out;
#ifdef DEBUG_KEXECDH
	dump_digest("server public key 25519:", server_pub, CURVE25519_SIZE);
	dump_digest("server cipher text:", ct, ଆକାର(ct));
	dump_digest("server kem key:", shared_secret, ଆକାର(shared_secret));
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
	/* success */
	r = 0;
	*server_blobp = server_blob;
	*shared_secretp = buf;
	server_blob = ଖାଲି;
	buf = ଖାଲି;
 out:
	explicit_bzero(hash, ଆକାର(hash));
	explicit_bzero(server_ଚାବି, ଆକାର(server_ଚାବି));
	explicit_bzero(shared_secret, ଆକାର(shared_secret));
	sshbuf_free(server_blob);
	sshbuf_free(buf);
	ଫେରନ୍ତୁ r;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
kex_kem_mlkem768x25519_dec(ସଂରଚନା kex *kex,
    ଅଚଳ ସଂରଚନା sshbuf *server_blob, ସଂରଚନା sshbuf **shared_secretp)
{
	ସଂରଚନା sshbuf *buf = ଖାଲି;
	u_char shared_secret[MLKEM768_BYTES];
	ଅଚଳ u_char *ciphertext, *server_pub;
	u_char hash[SSH_DIGEST_MAX_LENGTH];
	size_t need;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	*shared_secretp = ଖାଲି;

	need = MLKEM768_CIPHERTEXTBYTES + CURVE25519_SIZE;
	ଯଦି (sshbuf_len(server_blob) != need) {
		r = SSH_ERR_SIGNATURE_INVALID;
		ଯାଅ out;
	}
	ciphertext = sshbuf_ptr(server_blob);
	server_pub = ciphertext + MLKEM768_CIPHERTEXTBYTES;
	/* hash concatenation of KEM key and ECDH shared key */
	ଯଦି ((buf = sshbuf_new()) == ଖାଲି) {
		r = SSH_ERR_ALLOC_FAIL;
		ଯାଅ out;
	}
#ifdef DEBUG_KEXECDH
	dump_digest("server cipher text:", ciphertext,
	    MLKEM768_CIPHERTEXTBYTES);
	dump_digest("server public key c25519:", server_pub, CURVE25519_SIZE);
#endif
	ଯଦି (crypto_kem_mlkem768_dec(shared_secret, ciphertext,
	    kex->mlkem768_client_ଚାବି) != 0) {
		r = SSH_ERR_INTERNAL_ERROR;
		ଯାଅ out;
	}
	ଯଦି ((r = sshbuf_put(buf, shared_secret, ଆକାର(shared_secret))) != 0)
		ଯାଅ out;
	ଯଦି ((r = kexc25519_shared_ଚାବି_ext(kex->c25519_client_ଚାବି, server_pub,
	    buf, 1)) < 0)
		ଯାଅ out;
	ଯଦି ((r = ssh_digest_buffer(kex->hash_alg, buf,
	    hash, ଆକାର(hash))) != 0)
		ଯାଅ out;
#ifdef DEBUG_KEXECDH
	dump_digest("client kem key:", shared_secret, ଆକାର(shared_secret));
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
	/* success */
	r = 0;
	*shared_secretp = buf;
	buf = ଖାଲି;
 out:
	explicit_bzero(hash, ଆକାର(hash));
	explicit_bzero(shared_secret, ଆକାର(shared_secret));
	sshbuf_free(buf);
	ଫେରନ୍ତୁ r;
}
#ଅନ୍ୟଥା /* USE_MLKEM768X25519 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
kex_kem_mlkem768x25519_keypair(ସଂରଚନା kex *kex)
{
	ଫେରନ୍ତୁ SSH_ERR_SIGN_ALG_UNSUPPORTED;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
kex_kem_mlkem768x25519_enc(ସଂରଚନା kex *kex,
   ଅଚଳ ସଂରଚନା sshbuf *client_blob, ସଂରଚନା sshbuf **server_blobp,
   ସଂରଚନା sshbuf **shared_secretp)
{
	ଫେରନ୍ତୁ SSH_ERR_SIGN_ALG_UNSUPPORTED;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
kex_kem_mlkem768x25519_dec(ସଂରଚନା kex *kex,
    ଅଚଳ ସଂରଚନା sshbuf *server_blob, ସଂରଚନା sshbuf **shared_secretp)
{
	ଫେରନ୍ତୁ SSH_ERR_SIGN_ALG_UNSUPPORTED;
}
#endif /* USE_MLKEM768X25519 */
