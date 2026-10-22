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
#ਅਨ੍ਤਰ੍ਭਾਵ "log.h"

#ਅਨ੍ਤਰ੍ਭਾਵ "crypto_api.h"

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ USE_MLKEM768X25519

ਪੂਰਨ
kex_kem_mlkem768x25519_keypair(ਬਣਤਰ kex *kex)
{
	ਬਣਤਰ sshbuf *buf = ਨਿਰਾ;
	u_char *cp = ਨਿਰਾ;
	ਮਾਪ_t need;
	ਪੂਰਨ r = SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;

	ਜੇ ((buf = sshbuf_new()) == ਨਿਰਾ)
		ਵਾਪਸ SSH_ERR_ALLOC_FAIL;
	need = MLKEM768_PUBLICKEYBYTES + CURVE25519_ਮਾਪ;
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
	cp += MLKEM768_PUBLICKEYBYTES;
	kexc25519_keygen(kex->c25519_client_ਕੁੰਜੀ, cp);
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ DEBUG_KEXECDH
	dump_digest("client public key c25519:", cp, CURVE25519_ਮਾਪ);
#ਜੇ_ਅੰਤ
	/* success */
	r = 0;
	kex->client_pub = buf;
	buf = ਨਿਰਾ;
 ਬਾਹਰਲਾ:
	sshbuf_free(buf);
	ਵਾਪਸ r;
}

ਪੂਰਨ
kex_kem_mlkem768x25519_enc(ਬਣਤਰ kex *kex,
   ਅਚਲ ਬਣਤਰ sshbuf *client_blob, ਬਣਤਰ sshbuf **server_blobp,
   ਬਣਤਰ sshbuf **shared_secretp)
{
	ਬਣਤਰ sshbuf *server_blob = ਨਿਰਾ;
	ਬਣਤਰ sshbuf *buf = ਨਿਰਾ;
	ਅਚਲ u_char *client_pub;
	u_char server_pub[CURVE25519_ਮਾਪ], server_ਕੁੰਜੀ[CURVE25519_ਮਾਪ];
	u_char hash[SSH_DIGEST_MAX_ਲੰਮਾਈ];
	u_char ct[MLKEM768_CIPHERTEXTBYTES];
	u_char shared_secret[MLKEM768_ਬਾਈਟਾਂ];
	ਮਾਪ_t need;
	ਪੂਰਨ r = SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;

	*server_blobp = ਨਿਰਾ;
	*shared_secretp = ਨਿਰਾ;

	/* client_blob contains both KEM and ECDH client pubkeys */
	need = MLKEM768_PUBLICKEYBYTES + CURVE25519_ਮਾਪ;
	ਜੇ (sshbuf_len(client_blob) != need) {
		r = SSH_ERR_SIGNATURE_INVALID;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	client_pub = sshbuf_ptr(client_blob);
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ DEBUG_KEXECDH
	dump_digest("client public key mlkem768:", client_pub,
	    MLKEM768_PUBLICKEYBYTES);
	dump_digest("client public key 25519:",
	    client_pub + MLKEM768_PUBLICKEYBYTES,
	    CURVE25519_ਮਾਪ);
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
	/* generate ECDH key pair, store server pubkey after ciphertext */
	kexc25519_keygen(server_ਕੁੰਜੀ, server_pub);
	ਜੇ ((r = sshbuf_put(buf, shared_secret, ਆਕਾਰ(shared_secret))) != 0 ||
	    (r = sshbuf_put(server_blob, ct, ਆਕਾਰ(ct))) != 0 ||
	    (r = sshbuf_put(server_blob, server_pub, ਆਕਾਰ(server_pub))) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	/* append ECDH shared key */
	client_pub += MLKEM768_PUBLICKEYBYTES;
	ਜੇ ((r = kexc25519_shared_ਕੁੰਜੀ_ext(server_ਕੁੰਜੀ, client_pub, buf, 1)) < 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	ਜੇ ((r = ssh_digest_ਬਫਰ(kex->hash_alg, buf,
	    hash, ਆਕਾਰ(hash))) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ DEBUG_KEXECDH
	dump_digest("server public key 25519:", server_pub, CURVE25519_ਮਾਪ);
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
	explicit_bzero(server_ਕੁੰਜੀ, ਆਕਾਰ(server_ਕੁੰਜੀ));
	explicit_bzero(shared_secret, ਆਕਾਰ(shared_secret));
	sshbuf_free(server_blob);
	sshbuf_free(buf);
	ਵਾਪਸ r;
}

ਪੂਰਨ
kex_kem_mlkem768x25519_dec(ਬਣਤਰ kex *kex,
    ਅਚਲ ਬਣਤਰ sshbuf *server_blob, ਬਣਤਰ sshbuf **shared_secretp)
{
	ਬਣਤਰ sshbuf *buf = ਨਿਰਾ;
	u_char shared_secret[MLKEM768_ਬਾਈਟਾਂ];
	ਅਚਲ u_char *ciphertext, *server_pub;
	u_char hash[SSH_DIGEST_MAX_ਲੰਮਾਈ];
	ਮਾਪ_t need;
	ਪੂਰਨ r;

	*shared_secretp = ਨਿਰਾ;

	need = MLKEM768_CIPHERTEXTBYTES + CURVE25519_ਮਾਪ;
	ਜੇ (sshbuf_len(server_blob) != need) {
		r = SSH_ERR_SIGNATURE_INVALID;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ciphertext = sshbuf_ptr(server_blob);
	server_pub = ciphertext + MLKEM768_CIPHERTEXTBYTES;
	/* hash concatenation of KEM key and ECDH shared key */
	ਜੇ ((buf = sshbuf_new()) == ਨਿਰਾ) {
		r = SSH_ERR_ALLOC_FAIL;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ DEBUG_KEXECDH
	dump_digest("server cipher text:", ciphertext,
	    MLKEM768_CIPHERTEXTBYTES);
	dump_digest("server public key c25519:", server_pub, CURVE25519_ਮਾਪ);
#ਜੇ_ਅੰਤ
	ਜੇ (crypto_kem_mlkem768_dec(shared_secret, ciphertext,
	    kex->mlkem768_client_ਕੁੰਜੀ) != 0) {
		r = SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((r = sshbuf_put(buf, shared_secret, ਆਕਾਰ(shared_secret))) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	ਜੇ ((r = kexc25519_shared_ਕੁੰਜੀ_ext(kex->c25519_client_ਕੁੰਜੀ, server_pub,
	    buf, 1)) < 0)
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
	sshbuf_free(buf);
	ਵਾਪਸ r;
}
#ਨਹੀਂਤਾਂ /* USE_MLKEM768X25519 */
ਪੂਰਨ
kex_kem_mlkem768x25519_keypair(ਬਣਤਰ kex *kex)
{
	ਵਾਪਸ SSH_ERR_SIGN_ALG_UNSUPPORTED;
}

ਪੂਰਨ
kex_kem_mlkem768x25519_enc(ਬਣਤਰ kex *kex,
   ਅਚਲ ਬਣਤਰ sshbuf *client_blob, ਬਣਤਰ sshbuf **server_blobp,
   ਬਣਤਰ sshbuf **shared_secretp)
{
	ਵਾਪਸ SSH_ERR_SIGN_ALG_UNSUPPORTED;
}

ਪੂਰਨ
kex_kem_mlkem768x25519_dec(ਬਣਤਰ kex *kex,
    ਅਚਲ ਬਣਤਰ sshbuf *server_blob, ਬਣਤਰ sshbuf **shared_secretp)
{
	ਵਾਪਸ SSH_ERR_SIGN_ALG_UNSUPPORTED;
}
#ਜੇ_ਅੰਤ /* USE_MLKEM768X25519 */
