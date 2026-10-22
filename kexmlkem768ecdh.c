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

#ifdef WITH_OPENSSL
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
kex_kem_mlkem768ecdh_keypair(ସଂରଚନା kex *kex)
{
	ସଂରଚନା sshbuf *buf = ଖାଲି;
	ସଂରଚନା sshbuf *ec_blob = ଖାଲି;
	EC_ଚାବି *client_ଚାବି = ଖାଲି;
	ଅଚଳ EC_GROUP *group;
	ଅଚଳ EC_POINT *public_ଚାବି;
	u_char *cp = ଖାଲି;
	size_t need;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r = SSH_ERR_INTERNAL_ERROR;

	ଯଦି ((buf = sshbuf_new()) == ଖାଲି)
		ଫେରନ୍ତୁ SSH_ERR_ALLOC_FAIL;
	need = MLKEM768_PUBLICKEYBYTES;
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
	ଯଦି ((client_ଚାବି = EC_ଚାବି_new_by_curve_name(kex->ec_nid)) == ଖାଲି) {
		r = SSH_ERR_ALLOC_FAIL;
		ଯାଅ out;
	}
	ଯଦି (EC_ଚାବି_generate_ଚାବି(client_ଚାବି) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		ଯାଅ out;
	}
	group = EC_ଚାବି_get0_group(client_ଚାବି);
	public_ଚାବି = EC_ଚାବି_get0_public_ଚାବି(client_ଚାବି);

	ଯଦି ((ec_blob = sshbuf_new()) == ଖାଲି) {
		r = SSH_ERR_ALLOC_FAIL;
		ଯାଅ out;
	}
	ଯଦି ((r = sshbuf_put_ec(ec_blob, public_ଚାବି, group)) != 0 ||
	    (r = sshbuf_get_u32(ec_blob, ଖାଲି)) != 0 ||
	    (r = sshbuf_putb(buf, ec_blob)) != 0)
		ଯାଅ out;
#ifdef DEBUG_KEXECDH
	fputs("client private key EC:\n", stderr);
	sshkey_dump_ec_ଚାବି(client_ଚାବି);
#endif
	/* success */
	r = 0;
	kex->ec_client_ଚାବି = client_ଚାବି;
	kex->ec_group = group;
	client_ଚାବି = ଖାଲି;	/* owned by the kex */
	kex->client_pub = buf;
	buf = ଖାଲି;
 out:
	sshbuf_free(buf);
	sshbuf_free(ec_blob);
	EC_ଚାବି_free(client_ଚାବି);
	ଫେରନ୍ତୁ r;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
kex_kem_mlkem768ecdh_enc(ସଂରଚନା kex *kex,
   ଅଚଳ ସଂରଚନା sshbuf *client_blob, ସଂରଚନା sshbuf **server_blobp,
   ସଂରଚନା sshbuf **shared_secretp)
{
	ଅଚଳ EC_GROUP *group;
	ଅଚଳ EC_POINT *pub_ଚାବି;
	EC_ଚାବି *server_ଚାବି = ଖାଲି;
	ସଂରଚନା sshbuf *ec_pub = ଖାଲି;
	ସଂରଚନା sshbuf *ec_blob = ଖାଲି;
	ସଂରଚନା sshbuf *ec_shared = ଖାଲି;
	ସଂରଚନା sshbuf *server_blob = ଖାଲି;
	ସଂରଚନା sshbuf *buf = ଖାଲି;
	ଅଚଳ u_char *client_pub;
	u_char hash[SSH_DIGEST_MAX_LENGTH];
	u_char ct[MLKEM768_CIPHERTEXTBYTES];
	u_char shared_secret[MLKEM768_BYTES];
	size_t need;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r = SSH_ERR_INTERNAL_ERROR;

	*server_blobp = ଖାଲି;
	*shared_secretp = ଖାଲି;

	/* client_blob contains both KEM and ECDH client pubkeys */
	need = MLKEM768_PUBLICKEYBYTES;
	ଯଦି (sshbuf_len(client_blob) <= need) {
		r = SSH_ERR_SIGNATURE_INVALID;
		ଯାଅ out;
	}
	client_pub = sshbuf_ptr(client_blob);
#ifdef DEBUG_KEXECDH
	dump_digest("client public key mlkem768:", client_pub,
	    MLKEM768_PUBLICKEYBYTES);
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
	ଯଦି ((r = sshbuf_put(buf, shared_secret, ଆକାର(shared_secret))) != 0 ||
	    (r = sshbuf_put(server_blob, ct, ଆକାର(ct))) != 0)
		ଯାଅ out;

	client_pub += MLKEM768_PUBLICKEYBYTES;
	ଯଦି ((ec_pub = sshbuf_from(client_pub, sshbuf_len(client_blob) -
	    MLKEM768_PUBLICKEYBYTES)) == ଖାଲି) {
		r = SSH_ERR_ALLOC_FAIL;
		ଯାଅ out;
	}
	/* generate ECDH key pair */
	ଯଦି ((server_ଚାବି = EC_ଚାବି_new_by_curve_name(kex->ec_nid)) == ଖାଲି) {
		r = SSH_ERR_ALLOC_FAIL;
		ଯାଅ out;
	}
	ଯଦି (EC_ଚାବି_generate_ଚାବି(server_ଚାବି) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		ଯାଅ out;
	}
	group = EC_ଚାବି_get0_group(server_ଚାବି);
#ifdef DEBUG_KEXECDH
	fputs("server private key EC:\n", stderr);
	sshkey_dump_ec_ଚାବି(server_ଚାବି);
#endif
	/* store server pubkey after ciphertext */
	pub_ଚାବି = EC_ଚାବି_get0_public_ଚାବି(server_ଚାବି);
	ଯଦି ((ec_blob = sshbuf_new()) == ଖାଲି) {
		r = SSH_ERR_ALLOC_FAIL;
		ଯାଅ out;
	}
	ଯଦି ((r = sshbuf_put_ec(ec_blob, pub_ଚାବି, group)) != 0 ||
	    (r = sshbuf_get_u32(ec_blob, ଖାଲି)) != 0 ||
	    (r = sshbuf_putb(server_blob, ec_blob)) != 0)
		ଯାଅ out;

	/* append ECDH shared key */
	ଯଦି ((r = kex_ecdh_dec_ଚାବି_group(kex, ec_pub, server_ଚାବି, group,
	    1, &ec_shared)) != 0 ||
	    (r = sshbuf_putb(buf, ec_shared)) != 0)
		ଯାଅ out;

	ଯଦି ((r = ssh_digest_buffer(kex->hash_alg, buf, hash, ଆକାର(hash))) != 0)
		ଯାଅ out;
#ifdef DEBUG_KEXECDH
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
	explicit_bzero(shared_secret, ଆକାର(shared_secret));
	EC_ଚାବି_free(server_ଚାବି);
	sshbuf_free(ec_pub);
	sshbuf_free(ec_blob);
	sshbuf_free(ec_shared);
	sshbuf_free(server_blob);
	sshbuf_free(buf);
	ଫେରନ୍ତୁ r;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
kex_kem_mlkem768ecdh_dec(ସଂରଚନା kex *kex,
    ଅଚଳ ସଂରଚନା sshbuf *server_blob, ସଂରଚନା sshbuf **shared_secretp)
{
	ସଂରଚନା sshbuf *buf = ଖାଲି;
	ସଂରଚନା sshbuf *ec_pub = ଖାଲି;
	ସଂରଚନା sshbuf *ec_shared = ଖାଲି;
	u_char shared_secret[MLKEM768_BYTES];
	ଅଚଳ u_char *ciphertext, *server_pub;
	u_char hash[SSH_DIGEST_MAX_LENGTH];
	size_t need;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	*shared_secretp = ଖାଲି;

	need = MLKEM768_CIPHERTEXTBYTES;
	ଯଦି (sshbuf_len(server_blob) <= need) {
		r = SSH_ERR_SIGNATURE_INVALID;
		ଯାଅ out;
	}
	ciphertext = sshbuf_ptr(server_blob);
	server_pub = ciphertext + MLKEM768_CIPHERTEXTBYTES;
#ifdef DEBUG_KEXECDH
	dump_digest("server cipher text (dec):", ciphertext,
	    MLKEM768_CIPHERTEXTBYTES);
#endif
	/* hash concatenation of KEM key and ECDH shared key */
	ଯଦି ((buf = sshbuf_new()) == ଖାଲି) {
		r = SSH_ERR_ALLOC_FAIL;
		ଯାଅ out;
	}
	ଯଦି (crypto_kem_mlkem768_dec(shared_secret, ciphertext,
	    kex->mlkem768_client_ଚାବି) != 0) {
		r = SSH_ERR_INTERNAL_ERROR;
		ଯାଅ out;
	}
	ଯଦି ((r = sshbuf_put(buf, shared_secret, ଆକାର(shared_secret))) != 0)
		ଯାଅ out;
	ଯଦି ((ec_pub = sshbuf_from(server_pub, sshbuf_len(server_blob) - need))
	    == ଖାଲି) {
		r = SSH_ERR_ALLOC_FAIL;
		ଯାଅ out;
	}
	ଯଦି ((r = kex_ecdh_dec_ଚାବି_group(kex, ec_pub, kex->ec_client_ଚାବି,
	    kex->ec_group, 1, &ec_shared)) != 0 ||
	    (r = sshbuf_putb(buf, ec_shared)) != 0)
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
	EC_ଚାବି_free(kex->ec_client_ଚାବି);
	kex->ec_client_ଚାବି = ଖାଲି;
	sshbuf_free(ec_pub);
	sshbuf_free(ec_shared);
	sshbuf_free(buf);
	ଫେରନ୍ତୁ r;
}
#endif	/* WITH_OPENSSL */
