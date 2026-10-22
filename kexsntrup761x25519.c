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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ USE_SNTRUP761X25519

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <signal.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "sshkey.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "kex.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshbuf.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "digest.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssherr.h"

ਅਸਥਿਰ crypto_int16 crypto_int16_optblocker = 0;
ਅਸਥਿਰ crypto_int32 crypto_int32_optblocker = 0;
ਅਸਥਿਰ crypto_int64 crypto_int64_optblocker = 0;

ਪੂਰਨ
kex_kem_sntrup761x25519_keypair(ਬਣਤਰ kex *kex)
{
	ਬਣਤਰ sshbuf *buf = ਨਿਰਾ;
	u_char *cp = ਨਿਰਾ;
	ਮਾਪ_t need;
	ਪੂਰਨ r;

	ਜੇ ((buf = sshbuf_new()) == ਨਿਰਾ)
		ਵਾਪਸ SSH_ERR_ALLOC_FAIL;
	need = crypto_kem_sntrup761_PUBLICKEYBYTES + CURVE25519_ਮਾਪ;
	ਜੇ ((r = sshbuf_reserve(buf, need, &cp)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	crypto_kem_sntrup761_keypair(cp, kex->sntrup761_client_ਕੁੰਜੀ);
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ DEBUG_KEXECDH
	dump_digest("client public key sntrup761:", cp,
	    crypto_kem_sntrup761_PUBLICKEYBYTES);
#ਜੇ_ਅੰਤ
	cp += crypto_kem_sntrup761_PUBLICKEYBYTES;
	kexc25519_keygen(kex->c25519_client_ਕੁੰਜੀ, cp);
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ DEBUG_KEXECDH
	dump_digest("client public key c25519:", cp, CURVE25519_ਮਾਪ);
#ਜੇ_ਅੰਤ
	kex->client_pub = buf;
	buf = ਨਿਰਾ;
 ਬਾਹਰਲਾ:
	sshbuf_free(buf);
	ਵਾਪਸ r;
}

ਪੂਰਨ
kex_kem_sntrup761x25519_enc(ਬਣਤਰ kex *kex,
   ਅਚਲ ਬਣਤਰ sshbuf *client_blob, ਬਣਤਰ sshbuf **server_blobp,
   ਬਣਤਰ sshbuf **shared_secretp)
{
	ਬਣਤਰ sshbuf *server_blob = ਨਿਰਾ;
	ਬਣਤਰ sshbuf *buf = ਨਿਰਾ;
	ਅਚਲ u_char *client_pub;
	u_char *kem_ਕੁੰਜੀ, *ciphertext, *server_pub;
	u_char server_ਕੁੰਜੀ[CURVE25519_ਮਾਪ];
	u_char hash[SSH_DIGEST_MAX_ਲੰਮਾਈ];
	ਮਾਪ_t need;
	ਪੂਰਨ r;

	*server_blobp = ਨਿਰਾ;
	*shared_secretp = ਨਿਰਾ;

	/* client_blob contains both KEM and ECDH client pubkeys */
	need = crypto_kem_sntrup761_PUBLICKEYBYTES + CURVE25519_ਮਾਪ;
	ਜੇ (sshbuf_len(client_blob) != need) {
		r = SSH_ERR_SIGNATURE_INVALID;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	client_pub = sshbuf_ptr(client_blob);
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ DEBUG_KEXECDH
	dump_digest("client public key sntrup761:", client_pub,
	    crypto_kem_sntrup761_PUBLICKEYBYTES);
	dump_digest("client public key 25519:",
	    client_pub + crypto_kem_sntrup761_PUBLICKEYBYTES,
	    CURVE25519_ਮਾਪ);
#ਜੇ_ਅੰਤ
	/* allocate buffer for concatenation of KEM key and ECDH shared key */
	/* the buffer will be hashed and the result is the shared secret */
	ਜੇ ((buf = sshbuf_new()) == ਨਿਰਾ) {
		r = SSH_ERR_ALLOC_FAIL;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((r = sshbuf_reserve(buf, crypto_kem_sntrup761_ਬਾਈਟਾਂ,
	    &kem_ਕੁੰਜੀ)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	/* allocate space for encrypted KEM key and ECDH pub key */
	ਜੇ ((server_blob = sshbuf_new()) == ਨਿਰਾ) {
		r = SSH_ERR_ALLOC_FAIL;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	need = crypto_kem_sntrup761_CIPHERTEXTBYTES + CURVE25519_ਮਾਪ;
	ਜੇ ((r = sshbuf_reserve(server_blob, need, &ciphertext)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	/* generate and encrypt KEM key with client key */
	crypto_kem_sntrup761_enc(ciphertext, kem_ਕੁੰਜੀ, client_pub);
	/* generate ECDH key pair, store server pubkey after ciphertext */
	server_pub = ciphertext + crypto_kem_sntrup761_CIPHERTEXTBYTES;
	kexc25519_keygen(server_ਕੁੰਜੀ, server_pub);
	/* append ECDH shared key */
	client_pub += crypto_kem_sntrup761_PUBLICKEYBYTES;
	ਜੇ ((r = kexc25519_shared_ਕੁੰਜੀ_ext(server_ਕੁੰਜੀ, client_pub, buf, 1)) < 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	ਜੇ ((r = ssh_digest_ਬਫਰ(kex->hash_alg, buf, hash, ਆਕਾਰ(hash))) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ DEBUG_KEXECDH
	dump_digest("server public key 25519:", server_pub, CURVE25519_ਮਾਪ);
	dump_digest("server cipher text:", ciphertext,
	    crypto_kem_sntrup761_CIPHERTEXTBYTES);
	dump_digest("server kem key:", kem_ਕੁੰਜੀ, crypto_kem_sntrup761_ਬਾਈਟਾਂ);
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
	*server_blobp = server_blob;
	*shared_secretp = buf;
	server_blob = ਨਿਰਾ;
	buf = ਨਿਰਾ;
 ਬਾਹਰਲਾ:
	explicit_bzero(hash, ਆਕਾਰ(hash));
	explicit_bzero(server_ਕੁੰਜੀ, ਆਕਾਰ(server_ਕੁੰਜੀ));
	sshbuf_free(server_blob);
	sshbuf_free(buf);
	ਵਾਪਸ r;
}

ਪੂਰਨ
kex_kem_sntrup761x25519_dec(ਬਣਤਰ kex *kex,
    ਅਚਲ ਬਣਤਰ sshbuf *server_blob, ਬਣਤਰ sshbuf **shared_secretp)
{
	ਬਣਤਰ sshbuf *buf = ਨਿਰਾ;
	u_char *kem_ਕੁੰਜੀ = ਨਿਰਾ;
	ਅਚਲ u_char *ciphertext, *server_pub;
	u_char hash[SSH_DIGEST_MAX_ਲੰਮਾਈ];
	ਮਾਪ_t need;
	ਪੂਰਨ r, decoded;

	*shared_secretp = ਨਿਰਾ;

	need = crypto_kem_sntrup761_CIPHERTEXTBYTES + CURVE25519_ਮਾਪ;
	ਜੇ (sshbuf_len(server_blob) != need) {
		r = SSH_ERR_SIGNATURE_INVALID;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ciphertext = sshbuf_ptr(server_blob);
	server_pub = ciphertext + crypto_kem_sntrup761_CIPHERTEXTBYTES;
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ DEBUG_KEXECDH
	dump_digest("server cipher text:", ciphertext,
	    crypto_kem_sntrup761_CIPHERTEXTBYTES);
	dump_digest("server public key c25519:", server_pub, CURVE25519_ਮਾਪ);
#ਜੇ_ਅੰਤ
	/* hash concatenation of KEM key and ECDH shared key */
	ਜੇ ((buf = sshbuf_new()) == ਨਿਰਾ) {
		r = SSH_ERR_ALLOC_FAIL;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((r = sshbuf_reserve(buf, crypto_kem_sntrup761_ਬਾਈਟਾਂ,
	    &kem_ਕੁੰਜੀ)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	decoded = crypto_kem_sntrup761_dec(kem_ਕੁੰਜੀ, ciphertext,
	    kex->sntrup761_client_ਕੁੰਜੀ);
	ਜੇ ((r = kexc25519_shared_ਕੁੰਜੀ_ext(kex->c25519_client_ਕੁੰਜੀ, server_pub,
	    buf, 1)) < 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	ਜੇ ((r = ssh_digest_ਬਫਰ(kex->hash_alg, buf, hash, ਆਕਾਰ(hash))) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ DEBUG_KEXECDH
	dump_digest("client kem key:", kem_ਕੁੰਜੀ, crypto_kem_sntrup761_ਬਾਈਟਾਂ);
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
	ਜੇ (decoded != 0) {
		r = SSH_ERR_SIGNATURE_INVALID;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	*shared_secretp = buf;
	buf = ਨਿਰਾ;
 ਬਾਹਰਲਾ:
	explicit_bzero(hash, ਆਕਾਰ(hash));
	sshbuf_free(buf);
	ਵਾਪਸ r;
}

#ਨਹੀਂਤਾਂ

#ਅਨ੍ਤਰ੍ਭਾਵ "ssherr.h"

ਬਣਤਰ kex;
ਬਣਤਰ sshbuf;
ਬਣਤਰ sshkey;

ਪੂਰਨ
kex_kem_sntrup761x25519_keypair(ਬਣਤਰ kex *kex)
{
	ਵਾਪਸ SSH_ERR_SIGN_ALG_UNSUPPORTED;
}

ਪੂਰਨ
kex_kem_sntrup761x25519_enc(ਬਣਤਰ kex *kex,
   ਅਚਲ ਬਣਤਰ sshbuf *client_blob, ਬਣਤਰ sshbuf **server_blobp,
   ਬਣਤਰ sshbuf **shared_secretp)
{
	ਵਾਪਸ SSH_ERR_SIGN_ALG_UNSUPPORTED;
}

ਪੂਰਨ
kex_kem_sntrup761x25519_dec(ਬਣਤਰ kex *kex,
    ਅਚਲ ਬਣਤਰ sshbuf *server_blob, ਬਣਤਰ sshbuf **shared_secretp)
{
	ਵਾਪਸ SSH_ERR_SIGN_ALG_UNSUPPORTED;
}
#ਜੇ_ਅੰਤ /* USE_SNTRUP761X25519 */
