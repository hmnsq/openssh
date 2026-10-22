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

#شامل "includes.h"

#ifdef USE_SNTRUP761X25519

#شامل <sys/types.h>

#شامل <stdio.h>
#شامل <string.h>
#شامل <signal.h>

#شامل "sshkey.h"
#شامل "kex.h"
#شامل "sshbuf.h"
#شامل "digest.h"
#شامل "ssherr.h"

فرار crypto_int16 crypto_int16_optblocker = 0;
فرار crypto_int32 crypto_int32_optblocker = 0;
فرار crypto_int64 crypto_int64_optblocker = 0;

صحیح
kex_kem_sntrup761x25519_keypair(ساختار kex *kex)
{
	ساختار sshbuf *buf = پوچ;
	u_char *cp = پوچ;
	size_t need;
	صحیح r;

	اگر ((buf = sshbuf_new()) == پوچ)
		بازگشت SSH_ERR_ALLOC_FAIL;
	need = crypto_kem_sntrup761_PUBLICKEYBYTES + CURVE25519_SIZE;
	اگر ((r = sshbuf_reserve(buf, need, &cp)) != 0)
		برو out;
	crypto_kem_sntrup761_keypair(cp, kex->sntrup761_client_کلید);
#ifdef DEBUG_KEXECDH
	dump_digest("client public key sntrup761:", cp,
	    crypto_kem_sntrup761_PUBLICKEYBYTES);
#endif
	cp += crypto_kem_sntrup761_PUBLICKEYBYTES;
	kexc25519_keygen(kex->c25519_client_کلید, cp);
#ifdef DEBUG_KEXECDH
	dump_digest("client public key c25519:", cp, CURVE25519_SIZE);
#endif
	kex->client_pub = buf;
	buf = پوچ;
 out:
	sshbuf_free(buf);
	بازگشت r;
}

صحیح
kex_kem_sntrup761x25519_enc(ساختار kex *kex,
   ثابت ساختار sshbuf *client_blob, ساختار sshbuf **server_blobp,
   ساختار sshbuf **shared_secretp)
{
	ساختار sshbuf *server_blob = پوچ;
	ساختار sshbuf *buf = پوچ;
	ثابت u_char *client_pub;
	u_char *kem_کلید, *ciphertext, *server_pub;
	u_char server_کلید[CURVE25519_SIZE];
	u_char hash[SSH_DIGEST_MAX_LENGTH];
	size_t need;
	صحیح r;

	*server_blobp = پوچ;
	*shared_secretp = پوچ;

	/* client_blob contains both KEM and ECDH client pubkeys */
	need = crypto_kem_sntrup761_PUBLICKEYBYTES + CURVE25519_SIZE;
	اگر (sshbuf_len(client_blob) != need) {
		r = SSH_ERR_SIGNATURE_INVALID;
		برو out;
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
	اگر ((buf = sshbuf_new()) == پوچ) {
		r = SSH_ERR_ALLOC_FAIL;
		برو out;
	}
	اگر ((r = sshbuf_reserve(buf, crypto_kem_sntrup761_BYTES,
	    &kem_کلید)) != 0)
		برو out;
	/* allocate space for encrypted KEM key and ECDH pub key */
	اگر ((server_blob = sshbuf_new()) == پوچ) {
		r = SSH_ERR_ALLOC_FAIL;
		برو out;
	}
	need = crypto_kem_sntrup761_CIPHERTEXTBYTES + CURVE25519_SIZE;
	اگر ((r = sshbuf_reserve(server_blob, need, &ciphertext)) != 0)
		برو out;
	/* generate and encrypt KEM key with client key */
	crypto_kem_sntrup761_enc(ciphertext, kem_کلید, client_pub);
	/* generate ECDH key pair, store server pubkey after ciphertext */
	server_pub = ciphertext + crypto_kem_sntrup761_CIPHERTEXTBYTES;
	kexc25519_keygen(server_کلید, server_pub);
	/* append ECDH shared key */
	client_pub += crypto_kem_sntrup761_PUBLICKEYBYTES;
	اگر ((r = kexc25519_shared_کلید_ext(server_کلید, client_pub, buf, 1)) < 0)
		برو out;
	اگر ((r = ssh_digest_buffer(kex->hash_alg, buf, hash, اندازه(hash))) != 0)
		برو out;
#ifdef DEBUG_KEXECDH
	dump_digest("server public key 25519:", server_pub, CURVE25519_SIZE);
	dump_digest("server cipher text:", ciphertext,
	    crypto_kem_sntrup761_CIPHERTEXTBYTES);
	dump_digest("server kem key:", kem_کلید, crypto_kem_sntrup761_BYTES);
	dump_digest("concatenation of KEM key and ECDH shared key:",
	    sshbuf_ptr(buf), sshbuf_len(buf));
#endif
	/* string-encoded hash is resulting shared secret */
	sshbuf_reset(buf);
	اگر ((r = sshbuf_put_string(buf, hash,
	    ssh_digest_bytes(kex->hash_alg))) != 0)
		برو out;
#ifdef DEBUG_KEXECDH
	dump_digest("encoded shared secret:", sshbuf_ptr(buf), sshbuf_len(buf));
#endif
	*server_blobp = server_blob;
	*shared_secretp = buf;
	server_blob = پوچ;
	buf = پوچ;
 out:
	explicit_bzero(hash, اندازه(hash));
	explicit_bzero(server_کلید, اندازه(server_کلید));
	sshbuf_free(server_blob);
	sshbuf_free(buf);
	بازگشت r;
}

صحیح
kex_kem_sntrup761x25519_dec(ساختار kex *kex,
    ثابت ساختار sshbuf *server_blob, ساختار sshbuf **shared_secretp)
{
	ساختار sshbuf *buf = پوچ;
	u_char *kem_کلید = پوچ;
	ثابت u_char *ciphertext, *server_pub;
	u_char hash[SSH_DIGEST_MAX_LENGTH];
	size_t need;
	صحیح r, decoded;

	*shared_secretp = پوچ;

	need = crypto_kem_sntrup761_CIPHERTEXTBYTES + CURVE25519_SIZE;
	اگر (sshbuf_len(server_blob) != need) {
		r = SSH_ERR_SIGNATURE_INVALID;
		برو out;
	}
	ciphertext = sshbuf_ptr(server_blob);
	server_pub = ciphertext + crypto_kem_sntrup761_CIPHERTEXTBYTES;
#ifdef DEBUG_KEXECDH
	dump_digest("server cipher text:", ciphertext,
	    crypto_kem_sntrup761_CIPHERTEXTBYTES);
	dump_digest("server public key c25519:", server_pub, CURVE25519_SIZE);
#endif
	/* hash concatenation of KEM key and ECDH shared key */
	اگر ((buf = sshbuf_new()) == پوچ) {
		r = SSH_ERR_ALLOC_FAIL;
		برو out;
	}
	اگر ((r = sshbuf_reserve(buf, crypto_kem_sntrup761_BYTES,
	    &kem_کلید)) != 0)
		برو out;
	decoded = crypto_kem_sntrup761_dec(kem_کلید, ciphertext,
	    kex->sntrup761_client_کلید);
	اگر ((r = kexc25519_shared_کلید_ext(kex->c25519_client_کلید, server_pub,
	    buf, 1)) < 0)
		برو out;
	اگر ((r = ssh_digest_buffer(kex->hash_alg, buf, hash, اندازه(hash))) != 0)
		برو out;
#ifdef DEBUG_KEXECDH
	dump_digest("client kem key:", kem_کلید, crypto_kem_sntrup761_BYTES);
	dump_digest("concatenation of KEM key and ECDH shared key:",
	    sshbuf_ptr(buf), sshbuf_len(buf));
#endif
	sshbuf_reset(buf);
	اگر ((r = sshbuf_put_string(buf, hash,
	    ssh_digest_bytes(kex->hash_alg))) != 0)
		برو out;
#ifdef DEBUG_KEXECDH
	dump_digest("encoded shared secret:", sshbuf_ptr(buf), sshbuf_len(buf));
#endif
	اگر (decoded != 0) {
		r = SSH_ERR_SIGNATURE_INVALID;
		برو out;
	}
	*shared_secretp = buf;
	buf = پوچ;
 out:
	explicit_bzero(hash, اندازه(hash));
	sshbuf_free(buf);
	بازگشت r;
}

#وگرنه

#شامل "ssherr.h"

ساختار kex;
ساختار sshbuf;
ساختار sshkey;

صحیح
kex_kem_sntrup761x25519_keypair(ساختار kex *kex)
{
	بازگشت SSH_ERR_SIGN_ALG_UNSUPPORTED;
}

صحیح
kex_kem_sntrup761x25519_enc(ساختار kex *kex,
   ثابت ساختار sshbuf *client_blob, ساختار sshbuf **server_blobp,
   ساختار sshbuf **shared_secretp)
{
	بازگشت SSH_ERR_SIGN_ALG_UNSUPPORTED;
}

صحیح
kex_kem_sntrup761x25519_dec(ساختار kex *kex,
    ثابت ساختار sshbuf *server_blob, ساختار sshbuf **shared_secretp)
{
	بازگشت SSH_ERR_SIGN_ALG_UNSUPPORTED;
}
#endif /* USE_SNTRUP761X25519 */
