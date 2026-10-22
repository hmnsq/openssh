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

#include "includes.h"

#include <sys/types.h>

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <signal.h>
#include <endian.h>

#include "sshkey.h"
#include "kex.h"
#include "sshbuf.h"
#include "digest.h"
#include "ssherr.h"

#ifdef WITH_OPENSSL
정수
kex_kem_mlkem768ecdh_keypair(struct kex *kex)
{
	struct sshbuf *buf = NULL;
	struct sshbuf *ec_blob = NULL;
	EC_KEY *client_key = NULL;
	const EC_GROUP *group;
	const EC_POINT *public_key;
	u_char *cp = NULL;
	size_t need;
	정수 r = SSH_ERR_INTERNAL_ERROR;

	만약 ((buf = sshbuf_new()) == NULL)
		반환 SSH_ERR_ALLOC_FAIL;
	need = MLKEM768_PUBLICKEYBYTES;
	만약 ((r = sshbuf_reserve(buf, need, &cp)) != 0)
		goto out;
	만약 (crypto_kem_mlkem768_keypair(cp, kex->mlkem768_client_key) != 0) {
		r = SSH_ERR_INTERNAL_ERROR;
		goto out;
	}
#ifdef DEBUG_KEXECDH
	dump_digest("client public key mlkem768:", cp,
	    MLKEM768_PUBLICKEYBYTES);
#endif
	만약 ((client_key = EC_KEY_new_by_curve_name(kex->ec_nid)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	만약 (EC_KEY_generate_key(client_key) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	group = EC_KEY_get0_group(client_key);
	public_key = EC_KEY_get0_public_key(client_key);

	만약 ((ec_blob = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	만약 ((r = sshbuf_put_ec(ec_blob, public_key, group)) != 0 ||
	    (r = sshbuf_get_u32(ec_blob, NULL)) != 0 ||
	    (r = sshbuf_putb(buf, ec_blob)) != 0)
		goto out;
#ifdef DEBUG_KEXECDH
	fputs("client private key EC:\n", stderr);
	sshkey_dump_ec_key(client_key);
#endif
	/* success */
	r = 0;
	kex->ec_client_key = client_key;
	kex->ec_group = group;
	client_key = NULL;	/* owned by the kex */
	kex->client_pub = buf;
	buf = NULL;
 out:
	sshbuf_free(buf);
	sshbuf_free(ec_blob);
	EC_KEY_free(client_key);
	반환 r;
}

정수
kex_kem_mlkem768ecdh_enc(struct kex *kex,
   const struct sshbuf *client_blob, struct sshbuf **server_blobp,
   struct sshbuf **shared_secretp)
{
	const EC_GROUP *group;
	const EC_POINT *pub_key;
	EC_KEY *server_key = NULL;
	struct sshbuf *ec_pub = NULL;
	struct sshbuf *ec_blob = NULL;
	struct sshbuf *ec_shared = NULL;
	struct sshbuf *server_blob = NULL;
	struct sshbuf *buf = NULL;
	const u_char *client_pub;
	u_char hash[SSH_DIGEST_MAX_LENGTH];
	u_char ct[MLKEM768_CIPHERTEXTBYTES];
	u_char shared_secret[MLKEM768_BYTES];
	size_t need;
	정수 r = SSH_ERR_INTERNAL_ERROR;

	*server_blobp = NULL;
	*shared_secretp = NULL;

	/* client_blob contains both KEM and ECDH client pubkeys */
	need = MLKEM768_PUBLICKEYBYTES;
	만약 (sshbuf_len(client_blob) <= need) {
		r = SSH_ERR_SIGNATURE_INVALID;
		goto out;
	}
	client_pub = sshbuf_ptr(client_blob);
#ifdef DEBUG_KEXECDH
	dump_digest("client public key mlkem768:", client_pub,
	    MLKEM768_PUBLICKEYBYTES);
#endif

	/* allocate buffer for concatenation of KEM key and ECDH shared key */
	/* the buffer will be hashed and the result is the shared secret */
	만약 ((buf = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	/* allocate space for encrypted KEM key and ECDH pub key */
	만약 ((server_blob = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	/* generate and encrypt KEM key with client key */
	만약 (crypto_kem_mlkem768_enc(ct, shared_secret, client_pub) != 0) {
		r = SSH_ERR_INTERNAL_ERROR;
		goto out;
	}
	만약 ((r = sshbuf_put(buf, shared_secret, sizeof(shared_secret))) != 0 ||
	    (r = sshbuf_put(server_blob, ct, sizeof(ct))) != 0)
		goto out;

	client_pub += MLKEM768_PUBLICKEYBYTES;
	만약 ((ec_pub = sshbuf_from(client_pub, sshbuf_len(client_blob) -
	    MLKEM768_PUBLICKEYBYTES)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	/* generate ECDH key pair */
	만약 ((server_key = EC_KEY_new_by_curve_name(kex->ec_nid)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	만약 (EC_KEY_generate_key(server_key) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	group = EC_KEY_get0_group(server_key);
#ifdef DEBUG_KEXECDH
	fputs("server private key EC:\n", stderr);
	sshkey_dump_ec_key(server_key);
#endif
	/* store server pubkey after ciphertext */
	pub_key = EC_KEY_get0_public_key(server_key);
	만약 ((ec_blob = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	만약 ((r = sshbuf_put_ec(ec_blob, pub_key, group)) != 0 ||
	    (r = sshbuf_get_u32(ec_blob, NULL)) != 0 ||
	    (r = sshbuf_putb(server_blob, ec_blob)) != 0)
		goto out;

	/* append ECDH shared key */
	만약 ((r = kex_ecdh_dec_key_group(kex, ec_pub, server_key, group,
	    1, &ec_shared)) != 0 ||
	    (r = sshbuf_putb(buf, ec_shared)) != 0)
		goto out;

	만약 ((r = ssh_digest_buffer(kex->hash_alg, buf, hash, sizeof(hash))) != 0)
		goto out;
#ifdef DEBUG_KEXECDH
	dump_digest("server cipher text:", ct, sizeof(ct));
	dump_digest("server kem key:", shared_secret, sizeof(shared_secret));
	dump_digest("concatenation of KEM key and ECDH shared key:",
	    sshbuf_ptr(buf), sshbuf_len(buf));
#endif
	/* string-encoded hash is resulting shared secret */
	sshbuf_reset(buf);
	만약 ((r = sshbuf_put_string(buf, hash,
	    ssh_digest_bytes(kex->hash_alg))) != 0)
		goto out;
#ifdef DEBUG_KEXECDH
	dump_digest("encoded shared secret:", sshbuf_ptr(buf), sshbuf_len(buf));
#endif
	/* success */
	r = 0;
	*server_blobp = server_blob;
	*shared_secretp = buf;
	server_blob = NULL;
	buf = NULL;
 out:
	explicit_bzero(hash, sizeof(hash));
	explicit_bzero(shared_secret, sizeof(shared_secret));
	EC_KEY_free(server_key);
	sshbuf_free(ec_pub);
	sshbuf_free(ec_blob);
	sshbuf_free(ec_shared);
	sshbuf_free(server_blob);
	sshbuf_free(buf);
	반환 r;
}

정수
kex_kem_mlkem768ecdh_dec(struct kex *kex,
    const struct sshbuf *server_blob, struct sshbuf **shared_secretp)
{
	struct sshbuf *buf = NULL;
	struct sshbuf *ec_pub = NULL;
	struct sshbuf *ec_shared = NULL;
	u_char shared_secret[MLKEM768_BYTES];
	const u_char *ciphertext, *server_pub;
	u_char hash[SSH_DIGEST_MAX_LENGTH];
	size_t need;
	정수 r;

	*shared_secretp = NULL;

	need = MLKEM768_CIPHERTEXTBYTES;
	만약 (sshbuf_len(server_blob) <= need) {
		r = SSH_ERR_SIGNATURE_INVALID;
		goto out;
	}
	ciphertext = sshbuf_ptr(server_blob);
	server_pub = ciphertext + MLKEM768_CIPHERTEXTBYTES;
#ifdef DEBUG_KEXECDH
	dump_digest("server cipher text (dec):", ciphertext,
	    MLKEM768_CIPHERTEXTBYTES);
#endif
	/* hash concatenation of KEM key and ECDH shared key */
	만약 ((buf = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	만약 (crypto_kem_mlkem768_dec(shared_secret, ciphertext,
	    kex->mlkem768_client_key) != 0) {
		r = SSH_ERR_INTERNAL_ERROR;
		goto out;
	}
	만약 ((r = sshbuf_put(buf, shared_secret, sizeof(shared_secret))) != 0)
		goto out;
	만약 ((ec_pub = sshbuf_from(server_pub, sshbuf_len(server_blob) - need))
	    == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	만약 ((r = kex_ecdh_dec_key_group(kex, ec_pub, kex->ec_client_key,
	    kex->ec_group, 1, &ec_shared)) != 0 ||
	    (r = sshbuf_putb(buf, ec_shared)) != 0)
		goto out;
	만약 ((r = ssh_digest_buffer(kex->hash_alg, buf,
	    hash, sizeof(hash))) != 0)
		goto out;
#ifdef DEBUG_KEXECDH
	dump_digest("client kem key:", shared_secret, sizeof(shared_secret));
	dump_digest("concatenation of KEM key and ECDH shared key:",
	    sshbuf_ptr(buf), sshbuf_len(buf));
#endif
	sshbuf_reset(buf);
	만약 ((r = sshbuf_put_string(buf, hash,
	    ssh_digest_bytes(kex->hash_alg))) != 0)
		goto out;
#ifdef DEBUG_KEXECDH
	dump_digest("encoded shared secret:", sshbuf_ptr(buf), sshbuf_len(buf));
#endif
	/* success */
	r = 0;
	*shared_secretp = buf;
	buf = NULL;
 out:
	explicit_bzero(hash, sizeof(hash));
	explicit_bzero(shared_secret, sizeof(shared_secret));
	EC_KEY_free(kex->ec_client_key);
	kex->ec_client_key = NULL;
	sshbuf_free(ec_pub);
	sshbuf_free(ec_shared);
	sshbuf_free(buf);
	반환 r;
}
#endif	/* WITH_OPENSSL */
