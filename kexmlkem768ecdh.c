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

#ضمن "includes.h"

#ضمن <sys/types.h>

#ضمن <stdio.h>
#ضمن <stdint.h>
#ضمن <stdbool.h>
#ضمن <string.h>
#ضمن <signal.h>
#ضمن <endian.h>

#ضمن "sshkey.h"
#ضمن "kex.h"
#ضمن "sshbuf.h"
#ضمن "digest.h"
#ضمن "ssherr.h"

#ifdef WITH_OPENSSL
صحيح
kex_kem_mlkem768ecdh_keypair(بنية kex *kex)
{
	بنية sshbuf *buf = عدم;
	بنية sshbuf *ec_blob = عدم;
	EC_KEY *client_key = عدم;
	ثابت EC_GROUP *group;
	ثابت EC_POINT *public_key;
	u_char *cp = عدم;
	size_t need;
	صحيح r = SSH_ERR_INTERNAL_ERROR;

	𐤀𐤌 ((buf = sshbuf_new()) == عدم)
		أرجع SSH_ERR_ALLOC_FAIL;
	need = MLKEM768_PUBLICKEYBYTES;
	𐤀𐤌 ((r = sshbuf_reserve(buf, need, &cp)) != 0)
		اذهب out;
	𐤀𐤌 (crypto_kem_mlkem768_keypair(cp, kex->mlkem768_client_key) != 0) {
		r = SSH_ERR_INTERNAL_ERROR;
		اذهب out;
	}
#ifdef DEBUG_KEXECDH
	dump_digest("client public key mlkem768:", cp,
	    MLKEM768_PUBLICKEYBYTES);
#endif
	𐤀𐤌 ((client_key = EC_KEY_new_by_curve_name(kex->ec_nid)) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب out;
	}
	𐤀𐤌 (EC_KEY_generate_key(client_key) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		اذهب out;
	}
	group = EC_KEY_get0_group(client_key);
	public_key = EC_KEY_get0_public_key(client_key);

	𐤀𐤌 ((ec_blob = sshbuf_new()) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب out;
	}
	𐤀𐤌 ((r = sshbuf_put_ec(ec_blob, public_key, group)) != 0 ||
	    (r = sshbuf_get_u32(ec_blob, عدم)) != 0 ||
	    (r = sshbuf_putb(buf, ec_blob)) != 0)
		اذهب out;
#ifdef DEBUG_KEXECDH
	fputs("client private key EC:\n", stderr);
	sshkey_dump_ec_key(client_key);
#endif
	/* success */
	r = 0;
	kex->ec_client_key = client_key;
	kex->ec_group = group;
	client_key = عدم;	/* owned by the kex */
	kex->client_pub = buf;
	buf = عدم;
 out:
	sshbuf_free(buf);
	sshbuf_free(ec_blob);
	EC_KEY_free(client_key);
	أرجع r;
}

صحيح
kex_kem_mlkem768ecdh_enc(بنية kex *kex,
   ثابت بنية sshbuf *client_blob, بنية sshbuf **server_blobp,
   بنية sshbuf **shared_secretp)
{
	ثابت EC_GROUP *group;
	ثابت EC_POINT *pub_key;
	EC_KEY *server_key = عدم;
	بنية sshbuf *ec_pub = عدم;
	بنية sshbuf *ec_blob = عدم;
	بنية sshbuf *ec_shared = عدم;
	بنية sshbuf *server_blob = عدم;
	بنية sshbuf *buf = عدم;
	ثابت u_char *client_pub;
	u_char hash[SSH_DIGEST_MAX_LENGTH];
	u_char ct[MLKEM768_CIPHERTEXTBYTES];
	u_char shared_secret[MLKEM768_BYTES];
	size_t need;
	صحيح r = SSH_ERR_INTERNAL_ERROR;

	*server_blobp = عدم;
	*shared_secretp = عدم;

	/* client_blob contains both KEM and ECDH client pubkeys */
	need = MLKEM768_PUBLICKEYBYTES;
	𐤀𐤌 (sshbuf_len(client_blob) <= need) {
		r = SSH_ERR_SIGNATURE_INVALID;
		اذهب out;
	}
	client_pub = sshbuf_ptr(client_blob);
#ifdef DEBUG_KEXECDH
	dump_digest("client public key mlkem768:", client_pub,
	    MLKEM768_PUBLICKEYBYTES);
#endif

	/* allocate buffer for concatenation of KEM key and ECDH shared key */
	/* the buffer will be hashed and the result is the shared secret */
	𐤀𐤌 ((buf = sshbuf_new()) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب out;
	}
	/* allocate space for encrypted KEM key and ECDH pub key */
	𐤀𐤌 ((server_blob = sshbuf_new()) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب out;
	}
	/* generate and encrypt KEM key with client key */
	𐤀𐤌 (crypto_kem_mlkem768_enc(ct, shared_secret, client_pub) != 0) {
		r = SSH_ERR_INTERNAL_ERROR;
		اذهب out;
	}
	𐤀𐤌 ((r = sshbuf_put(buf, shared_secret, حجم(shared_secret))) != 0 ||
	    (r = sshbuf_put(server_blob, ct, حجم(ct))) != 0)
		اذهب out;

	client_pub += MLKEM768_PUBLICKEYBYTES;
	𐤀𐤌 ((ec_pub = sshbuf_from(client_pub, sshbuf_len(client_blob) -
	    MLKEM768_PUBLICKEYBYTES)) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب out;
	}
	/* generate ECDH key pair */
	𐤀𐤌 ((server_key = EC_KEY_new_by_curve_name(kex->ec_nid)) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب out;
	}
	𐤀𐤌 (EC_KEY_generate_key(server_key) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		اذهب out;
	}
	group = EC_KEY_get0_group(server_key);
#ifdef DEBUG_KEXECDH
	fputs("server private key EC:\n", stderr);
	sshkey_dump_ec_key(server_key);
#endif
	/* store server pubkey after ciphertext */
	pub_key = EC_KEY_get0_public_key(server_key);
	𐤀𐤌 ((ec_blob = sshbuf_new()) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب out;
	}
	𐤀𐤌 ((r = sshbuf_put_ec(ec_blob, pub_key, group)) != 0 ||
	    (r = sshbuf_get_u32(ec_blob, عدم)) != 0 ||
	    (r = sshbuf_putb(server_blob, ec_blob)) != 0)
		اذهب out;

	/* append ECDH shared key */
	𐤀𐤌 ((r = kex_ecdh_dec_key_group(kex, ec_pub, server_key, group,
	    1, &ec_shared)) != 0 ||
	    (r = sshbuf_putb(buf, ec_shared)) != 0)
		اذهب out;

	𐤀𐤌 ((r = ssh_digest_buffer(kex->hash_alg, buf, hash, حجم(hash))) != 0)
		اذهب out;
#ifdef DEBUG_KEXECDH
	dump_digest("server cipher text:", ct, حجم(ct));
	dump_digest("server kem key:", shared_secret, حجم(shared_secret));
	dump_digest("concatenation of KEM key and ECDH shared key:",
	    sshbuf_ptr(buf), sshbuf_len(buf));
#endif
	/* string-encoded hash is resulting shared secret */
	sshbuf_reset(buf);
	𐤀𐤌 ((r = sshbuf_put_string(buf, hash,
	    ssh_digest_bytes(kex->hash_alg))) != 0)
		اذهب out;
#ifdef DEBUG_KEXECDH
	dump_digest("encoded shared secret:", sshbuf_ptr(buf), sshbuf_len(buf));
#endif
	/* success */
	r = 0;
	*server_blobp = server_blob;
	*shared_secretp = buf;
	server_blob = عدم;
	buf = عدم;
 out:
	explicit_bzero(hash, حجم(hash));
	explicit_bzero(shared_secret, حجم(shared_secret));
	EC_KEY_free(server_key);
	sshbuf_free(ec_pub);
	sshbuf_free(ec_blob);
	sshbuf_free(ec_shared);
	sshbuf_free(server_blob);
	sshbuf_free(buf);
	أرجع r;
}

صحيح
kex_kem_mlkem768ecdh_dec(بنية kex *kex,
    ثابت بنية sshbuf *server_blob, بنية sshbuf **shared_secretp)
{
	بنية sshbuf *buf = عدم;
	بنية sshbuf *ec_pub = عدم;
	بنية sshbuf *ec_shared = عدم;
	u_char shared_secret[MLKEM768_BYTES];
	ثابت u_char *ciphertext, *server_pub;
	u_char hash[SSH_DIGEST_MAX_LENGTH];
	size_t need;
	صحيح r;

	*shared_secretp = عدم;

	need = MLKEM768_CIPHERTEXTBYTES;
	𐤀𐤌 (sshbuf_len(server_blob) <= need) {
		r = SSH_ERR_SIGNATURE_INVALID;
		اذهب out;
	}
	ciphertext = sshbuf_ptr(server_blob);
	server_pub = ciphertext + MLKEM768_CIPHERTEXTBYTES;
#ifdef DEBUG_KEXECDH
	dump_digest("server cipher text (dec):", ciphertext,
	    MLKEM768_CIPHERTEXTBYTES);
#endif
	/* hash concatenation of KEM key and ECDH shared key */
	𐤀𐤌 ((buf = sshbuf_new()) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب out;
	}
	𐤀𐤌 (crypto_kem_mlkem768_dec(shared_secret, ciphertext,
	    kex->mlkem768_client_key) != 0) {
		r = SSH_ERR_INTERNAL_ERROR;
		اذهب out;
	}
	𐤀𐤌 ((r = sshbuf_put(buf, shared_secret, حجم(shared_secret))) != 0)
		اذهب out;
	𐤀𐤌 ((ec_pub = sshbuf_from(server_pub, sshbuf_len(server_blob) - need))
	    == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب out;
	}
	𐤀𐤌 ((r = kex_ecdh_dec_key_group(kex, ec_pub, kex->ec_client_key,
	    kex->ec_group, 1, &ec_shared)) != 0 ||
	    (r = sshbuf_putb(buf, ec_shared)) != 0)
		اذهب out;
	𐤀𐤌 ((r = ssh_digest_buffer(kex->hash_alg, buf,
	    hash, حجم(hash))) != 0)
		اذهب out;
#ifdef DEBUG_KEXECDH
	dump_digest("client kem key:", shared_secret, حجم(shared_secret));
	dump_digest("concatenation of KEM key and ECDH shared key:",
	    sshbuf_ptr(buf), sshbuf_len(buf));
#endif
	sshbuf_reset(buf);
	𐤀𐤌 ((r = sshbuf_put_string(buf, hash,
	    ssh_digest_bytes(kex->hash_alg))) != 0)
		اذهب out;
#ifdef DEBUG_KEXECDH
	dump_digest("encoded shared secret:", sshbuf_ptr(buf), sshbuf_len(buf));
#endif
	/* success */
	r = 0;
	*shared_secretp = buf;
	buf = عدم;
 out:
	explicit_bzero(hash, حجم(hash));
	explicit_bzero(shared_secret, حجم(shared_secret));
	EC_KEY_free(kex->ec_client_key);
	kex->ec_client_key = عدم;
	sshbuf_free(ec_pub);
	sshbuf_free(ec_shared);
	sshbuf_free(buf);
	أرجع r;
}
#endif	/* WITH_OPENSSL */
