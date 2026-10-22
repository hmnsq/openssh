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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdint.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdbool.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <signal.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <endian.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "sshkey.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "kex.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshbuf.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "digest.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssherr.h"

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
ਪੂਰਨ
kex_kem_mlkem768ecdh_keypair(ਬਣਤਰ kex *kex)
{
	ਬਣਤਰ sshbuf *buf = ਨਿਰਾ;
	ਬਣਤਰ sshbuf *ec_blob = ਨਿਰਾ;
	EC_ਕੁੰਜੀ *client_ਕੁੰਜੀ = ਨਿਰਾ;
	ਅਚਲ EC_ਸਮੂਹ *ਸਮੂਹ;
	ਅਚਲ EC_ਬਿੰਦੂ *ਜਨਤਕ_ਕੁੰਜੀ;
	u_char *cp = ਨਿਰਾ;
	ਮਾਪ_t need;
	ਪੂਰਨ r = SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;

	ਜੇ ((buf = sshbuf_new()) == ਨਿਰਾ)
		ਵਾਪਸ SSH_ERR_ALLOC_FAIL;
	need = MLKEM768_PUBLICKEYBYTES;
	ਜੇ ((r = sshbuf_reserve(buf, need, &cp)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	ਜੇ (crypto_kem_mlkem768_keypair(cp, kex->mlkem768_client_ਕੁੰਜੀ) != 0) {
		r = SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ DEBUG_KEXECDH
	dump_digest("client public key mlkem768:", cp,
	    MLKEM768_PUBLICKEYBYTES);
#ਜੇ_ਅੰਤ
	ਜੇ ((client_ਕੁੰਜੀ = EC_ਕੁੰਜੀ_new_by_ਵਕਰ_name(kex->ec_nid)) == ਨਿਰਾ) {
		r = SSH_ERR_ALLOC_FAIL;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ (EC_ਕੁੰਜੀ_generate_ਕੁੰਜੀ(client_ਕੁੰਜੀ) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਸਮੂਹ = EC_ਕੁੰਜੀ_get0_ਸਮੂਹ(client_ਕੁੰਜੀ);
	ਜਨਤਕ_ਕੁੰਜੀ = EC_ਕੁੰਜੀ_get0_ਜਨਤਕ_ਕੁੰਜੀ(client_ਕੁੰਜੀ);

	ਜੇ ((ec_blob = sshbuf_new()) == ਨਿਰਾ) {
		r = SSH_ERR_ALLOC_FAIL;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((r = sshbuf_put_ec(ec_blob, ਜਨਤਕ_ਕੁੰਜੀ, ਸਮੂਹ)) != 0 ||
	    (r = sshbuf_get_u32(ec_blob, ਨਿਰਾ)) != 0 ||
	    (r = sshbuf_putb(buf, ec_blob)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ DEBUG_KEXECDH
	fputs("client private key EC:\n", stderr);
	sshkey_dump_ec_ਕੁੰਜੀ(client_ਕੁੰਜੀ);
#ਜੇ_ਅੰਤ
	/* success */
	r = 0;
	kex->ec_client_ਕੁੰਜੀ = client_ਕੁੰਜੀ;
	kex->ec_ਸਮੂਹ = ਸਮੂਹ;
	client_ਕੁੰਜੀ = ਨਿਰਾ;	/* owned by the kex */
	kex->client_pub = buf;
	buf = ਨਿਰਾ;
 ਬਾਹਰਲਾ:
	sshbuf_free(buf);
	sshbuf_free(ec_blob);
	EC_ਕੁੰਜੀ_free(client_ਕੁੰਜੀ);
	ਵਾਪਸ r;
}

ਪੂਰਨ
kex_kem_mlkem768ecdh_enc(ਬਣਤਰ kex *kex,
   ਅਚਲ ਬਣਤਰ sshbuf *client_blob, ਬਣਤਰ sshbuf **server_blobp,
   ਬਣਤਰ sshbuf **shared_secretp)
{
	ਅਚਲ EC_ਸਮੂਹ *ਸਮੂਹ;
	ਅਚਲ EC_ਬਿੰਦੂ *pub_ਕੁੰਜੀ;
	EC_ਕੁੰਜੀ *server_ਕੁੰਜੀ = ਨਿਰਾ;
	ਬਣਤਰ sshbuf *ec_pub = ਨਿਰਾ;
	ਬਣਤਰ sshbuf *ec_blob = ਨਿਰਾ;
	ਬਣਤਰ sshbuf *ec_shared = ਨਿਰਾ;
	ਬਣਤਰ sshbuf *server_blob = ਨਿਰਾ;
	ਬਣਤਰ sshbuf *buf = ਨਿਰਾ;
	ਅਚਲ u_char *client_pub;
	u_char hash[SSH_DIGEST_MAX_ਲੰਮਾਈ];
	u_char ct[MLKEM768_CIPHERTEXTBYTES];
	u_char shared_secret[MLKEM768_ਬਾਈਟਾਂ];
	ਮਾਪ_t need;
	ਪੂਰਨ r = SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;

	*server_blobp = ਨਿਰਾ;
	*shared_secretp = ਨਿਰਾ;

	/* client_blob contains both KEM and ECDH client pubkeys */
	need = MLKEM768_PUBLICKEYBYTES;
	ਜੇ (sshbuf_len(client_blob) <= need) {
		r = SSH_ERR_SIGNATURE_INVALID;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	client_pub = sshbuf_ptr(client_blob);
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ DEBUG_KEXECDH
	dump_digest("client public key mlkem768:", client_pub,
	    MLKEM768_PUBLICKEYBYTES);
#ਜੇ_ਅੰਤ

	/* allocate buffer for concatenation of KEM key and ECDH shared key */
	/* the buffer will be hashed and the result is the shared secret */
	ਜੇ ((buf = sshbuf_new()) == ਨਿਰਾ) {
		r = SSH_ERR_ALLOC_FAIL;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	/* allocate space for encrypted KEM key and ECDH pub key */
	ਜੇ ((server_blob = sshbuf_new()) == ਨਿਰਾ) {
		r = SSH_ERR_ALLOC_FAIL;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	/* generate and encrypt KEM key with client key */
	ਜੇ (crypto_kem_mlkem768_enc(ct, shared_secret, client_pub) != 0) {
		r = SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((r = sshbuf_put(buf, shared_secret, ਆਕਾਰ(shared_secret))) != 0 ||
	    (r = sshbuf_put(server_blob, ct, ਆਕਾਰ(ct))) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;

	client_pub += MLKEM768_PUBLICKEYBYTES;
	ਜੇ ((ec_pub = sshbuf_from(client_pub, sshbuf_len(client_blob) -
	    MLKEM768_PUBLICKEYBYTES)) == ਨਿਰਾ) {
		r = SSH_ERR_ALLOC_FAIL;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	/* generate ECDH key pair */
	ਜੇ ((server_ਕੁੰਜੀ = EC_ਕੁੰਜੀ_new_by_ਵਕਰ_name(kex->ec_nid)) == ਨਿਰਾ) {
		r = SSH_ERR_ALLOC_FAIL;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ (EC_ਕੁੰਜੀ_generate_ਕੁੰਜੀ(server_ਕੁੰਜੀ) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਸਮੂਹ = EC_ਕੁੰਜੀ_get0_ਸਮੂਹ(server_ਕੁੰਜੀ);
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ DEBUG_KEXECDH
	fputs("server private key EC:\n", stderr);
	sshkey_dump_ec_ਕੁੰਜੀ(server_ਕੁੰਜੀ);
#ਜੇ_ਅੰਤ
	/* store server pubkey after ciphertext */
	pub_ਕੁੰਜੀ = EC_ਕੁੰਜੀ_get0_ਜਨਤਕ_ਕੁੰਜੀ(server_ਕੁੰਜੀ);
	ਜੇ ((ec_blob = sshbuf_new()) == ਨਿਰਾ) {
		r = SSH_ERR_ALLOC_FAIL;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((r = sshbuf_put_ec(ec_blob, pub_ਕੁੰਜੀ, ਸਮੂਹ)) != 0 ||
	    (r = sshbuf_get_u32(ec_blob, ਨਿਰਾ)) != 0 ||
	    (r = sshbuf_putb(server_blob, ec_blob)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;

	/* append ECDH shared key */
	ਜੇ ((r = kex_ecdh_dec_ਕੁੰਜੀ_ਸਮੂਹ(kex, ec_pub, server_ਕੁੰਜੀ, ਸਮੂਹ,
	    1, &ec_shared)) != 0 ||
	    (r = sshbuf_putb(buf, ec_shared)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;

	ਜੇ ((r = ssh_digest_ਬਫਰ(kex->hash_alg, buf, hash, ਆਕਾਰ(hash))) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ DEBUG_KEXECDH
	dump_digest("server cipher text:", ct, ਆਕਾਰ(ct));
	dump_digest("server kem key:", shared_secret, ਆਕਾਰ(shared_secret));
	dump_digest("concatenation of KEM key and ECDH shared key:",
	    sshbuf_ptr(buf), sshbuf_len(buf));
#ਜੇ_ਅੰਤ
	/* string-encoded hash is resulting shared secret */
	sshbuf_reset(buf);
	ਜੇ ((r = sshbuf_put_string(buf, hash,
	    ssh_digest_ਬਾਈਟਾਂ(kex->hash_alg))) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ DEBUG_KEXECDH
	dump_digest("encoded shared secret:", sshbuf_ptr(buf), sshbuf_len(buf));
#ਜੇ_ਅੰਤ
	/* success */
	r = 0;
	*server_blobp = server_blob;
	*shared_secretp = buf;
	server_blob = ਨਿਰਾ;
	buf = ਨਿਰਾ;
 ਬਾਹਰਲਾ:
	explicit_bzero(hash, ਆਕਾਰ(hash));
	explicit_bzero(shared_secret, ਆਕਾਰ(shared_secret));
	EC_ਕੁੰਜੀ_free(server_ਕੁੰਜੀ);
	sshbuf_free(ec_pub);
	sshbuf_free(ec_blob);
	sshbuf_free(ec_shared);
	sshbuf_free(server_blob);
	sshbuf_free(buf);
	ਵਾਪਸ r;
}

ਪੂਰਨ
kex_kem_mlkem768ecdh_dec(ਬਣਤਰ kex *kex,
    ਅਚਲ ਬਣਤਰ sshbuf *server_blob, ਬਣਤਰ sshbuf **shared_secretp)
{
	ਬਣਤਰ sshbuf *buf = ਨਿਰਾ;
	ਬਣਤਰ sshbuf *ec_pub = ਨਿਰਾ;
	ਬਣਤਰ sshbuf *ec_shared = ਨਿਰਾ;
	u_char shared_secret[MLKEM768_ਬਾਈਟਾਂ];
	ਅਚਲ u_char *ciphertext, *server_pub;
	u_char hash[SSH_DIGEST_MAX_ਲੰਮਾਈ];
	ਮਾਪ_t need;
	ਪੂਰਨ r;

	*shared_secretp = ਨਿਰਾ;

	need = MLKEM768_CIPHERTEXTBYTES;
	ਜੇ (sshbuf_len(server_blob) <= need) {
		r = SSH_ERR_SIGNATURE_INVALID;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ciphertext = sshbuf_ptr(server_blob);
	server_pub = ciphertext + MLKEM768_CIPHERTEXTBYTES;
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ DEBUG_KEXECDH
	dump_digest("server cipher text (dec):", ciphertext,
	    MLKEM768_CIPHERTEXTBYTES);
#ਜੇ_ਅੰਤ
	/* hash concatenation of KEM key and ECDH shared key */
	ਜੇ ((buf = sshbuf_new()) == ਨਿਰਾ) {
		r = SSH_ERR_ALLOC_FAIL;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ (crypto_kem_mlkem768_dec(shared_secret, ciphertext,
	    kex->mlkem768_client_ਕੁੰਜੀ) != 0) {
		r = SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((r = sshbuf_put(buf, shared_secret, ਆਕਾਰ(shared_secret))) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	ਜੇ ((ec_pub = sshbuf_from(server_pub, sshbuf_len(server_blob) - need))
	    == ਨਿਰਾ) {
		r = SSH_ERR_ALLOC_FAIL;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((r = kex_ecdh_dec_ਕੁੰਜੀ_ਸਮੂਹ(kex, ec_pub, kex->ec_client_ਕੁੰਜੀ,
	    kex->ec_ਸਮੂਹ, 1, &ec_shared)) != 0 ||
	    (r = sshbuf_putb(buf, ec_shared)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	ਜੇ ((r = ssh_digest_ਬਫਰ(kex->hash_alg, buf,
	    hash, ਆਕਾਰ(hash))) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ DEBUG_KEXECDH
	dump_digest("client kem key:", shared_secret, ਆਕਾਰ(shared_secret));
	dump_digest("concatenation of KEM key and ECDH shared key:",
	    sshbuf_ptr(buf), sshbuf_len(buf));
#ਜੇ_ਅੰਤ
	sshbuf_reset(buf);
	ਜੇ ((r = sshbuf_put_string(buf, hash,
	    ssh_digest_ਬਾਈਟਾਂ(kex->hash_alg))) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ DEBUG_KEXECDH
	dump_digest("encoded shared secret:", sshbuf_ptr(buf), sshbuf_len(buf));
#ਜੇ_ਅੰਤ
	/* success */
	r = 0;
	*shared_secretp = buf;
	buf = ਨਿਰਾ;
 ਬਾਹਰਲਾ:
	explicit_bzero(hash, ਆਕਾਰ(hash));
	explicit_bzero(shared_secret, ਆਕਾਰ(shared_secret));
	EC_ਕੁੰਜੀ_free(kex->ec_client_ਕੁੰਜੀ);
	kex->ec_client_ਕੁੰਜੀ = ਨਿਰਾ;
	sshbuf_free(ec_pub);
	sshbuf_free(ec_shared);
	sshbuf_free(buf);
	ਵਾਪਸ r;
}
#ਜੇ_ਅੰਤ	/* WITH_OPENSSL */
