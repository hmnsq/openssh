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

#شامل "includes.h"

#شامل <sys/types.h>

#شامل <stdio.h>
#شامل <stdint.h>
#شامل <stdbool.h>
#شامل <string.h>
#شامل <signal.h>
#شامل <endian.h>

#شامل "sshkey.h"
#شامل "kex.h"
#شامل "sshbuf.h"
#شامل "digest.h"
#شامل "ssherr.h"
#شامل "log.h"

#شامل "crypto_api.h"

#ifdef USE_MLKEM768X25519

صحیح
kex_kem_mlkem768x25519_keypair(ساختار kex *kex)
{
	ساختار sshbuf *buf = پوچ;
	u_char *cp = پوچ;
	size_t need;
	صحیح r = SSH_ERR_INTERNAL_ERROR;

	اگر ((buf = sshbuf_new()) == پوچ)
		بازگشت SSH_ERR_ALLOC_FAIL;
	need = MLKEM768_PUBLICKEYBYTES + CURVE25519_SIZE;
	اگر ((r = sshbuf_reserve(buf, need, &cp)) != 0)
		برو out;
	اگر (crypto_kem_mlkem768_keypair(cp, kex->mlkem768_client_کلید) != 0) {
		r = SSH_ERR_INTERNAL_ERROR;
		برو out;
	}
#ifdef DEBUG_KEXECDH
	dump_digest("client public key mlkem768:", cp,
	    MLKEM768_PUBLICKEYBYTES);
#endif
	cp += MLKEM768_PUBLICKEYBYTES;
	kexc25519_keygen(kex->c25519_client_کلید, cp);
#ifdef DEBUG_KEXECDH
	dump_digest("client public key c25519:", cp, CURVE25519_SIZE);
#endif
	/* success */
	r = 0;
	kex->client_pub = buf;
	buf = پوچ;
 out:
	sshbuf_free(buf);
	بازگشت r;
}

صحیح
kex_kem_mlkem768x25519_enc(ساختار kex *kex,
   ثابت ساختار sshbuf *client_blob, ساختار sshbuf **server_blobp,
   ساختار sshbuf **shared_secretp)
{
	ساختار sshbuf *server_blob = پوچ;
	ساختار sshbuf *buf = پوچ;
	ثابت u_char *client_pub;
	u_char server_pub[CURVE25519_SIZE], server_کلید[CURVE25519_SIZE];
	u_char hash[SSH_DIGEST_MAX_LENGTH];
	u_char ct[MLKEM768_CIPHERTEXTBYTES];
	u_char shared_secret[MLKEM768_BYTES];
	size_t need;
	صحیح r = SSH_ERR_INTERNAL_ERROR;

	*server_blobp = پوچ;
	*shared_secretp = پوچ;

	/* client_blob contains both KEM and ECDH client pubkeys */
	need = MLKEM768_PUBLICKEYBYTES + CURVE25519_SIZE;
	اگر (sshbuf_len(client_blob) != need) {
		r = SSH_ERR_SIGNATURE_INVALID;
		برو out;
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
	اگر ((buf = sshbuf_new()) == پوچ) {
		r = SSH_ERR_ALLOC_FAIL;
		برو out;
	}
	/* allocate space for encrypted KEM key and ECDH pub key */
	اگر ((server_blob = sshbuf_new()) == پوچ) {
		r = SSH_ERR_ALLOC_FAIL;
		برو out;
	}
	/* generate and encrypt KEM key with client key */
	اگر (crypto_kem_mlkem768_enc(ct, shared_secret, client_pub) != 0) {
		r = SSH_ERR_INTERNAL_ERROR;
		برو out;
	}
	/* generate ECDH key pair, store server pubkey after ciphertext */
	kexc25519_keygen(server_کلید, server_pub);
	اگر ((r = sshbuf_put(buf, shared_secret, اندازه(shared_secret))) != 0 ||
	    (r = sshbuf_put(server_blob, ct, اندازه(ct))) != 0 ||
	    (r = sshbuf_put(server_blob, server_pub, اندازه(server_pub))) != 0)
		برو out;
	/* append ECDH shared key */
	client_pub += MLKEM768_PUBLICKEYBYTES;
	اگر ((r = kexc25519_shared_کلید_ext(server_کلید, client_pub, buf, 1)) < 0)
		برو out;
	اگر ((r = ssh_digest_buffer(kex->hash_alg, buf,
	    hash, اندازه(hash))) != 0)
		برو out;
#ifdef DEBUG_KEXECDH
	dump_digest("server public key 25519:", server_pub, CURVE25519_SIZE);
	dump_digest("server cipher text:", ct, اندازه(ct));
	dump_digest("server kem key:", shared_secret, اندازه(shared_secret));
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
	/* success */
	r = 0;
	*server_blobp = server_blob;
	*shared_secretp = buf;
	server_blob = پوچ;
	buf = پوچ;
 out:
	explicit_bzero(hash, اندازه(hash));
	explicit_bzero(server_کلید, اندازه(server_کلید));
	explicit_bzero(shared_secret, اندازه(shared_secret));
	sshbuf_free(server_blob);
	sshbuf_free(buf);
	بازگشت r;
}

صحیح
kex_kem_mlkem768x25519_dec(ساختار kex *kex,
    ثابت ساختار sshbuf *server_blob, ساختار sshbuf **shared_secretp)
{
	ساختار sshbuf *buf = پوچ;
	u_char shared_secret[MLKEM768_BYTES];
	ثابت u_char *ciphertext, *server_pub;
	u_char hash[SSH_DIGEST_MAX_LENGTH];
	size_t need;
	صحیح r;

	*shared_secretp = پوچ;

	need = MLKEM768_CIPHERTEXTBYTES + CURVE25519_SIZE;
	اگر (sshbuf_len(server_blob) != need) {
		r = SSH_ERR_SIGNATURE_INVALID;
		برو out;
	}
	ciphertext = sshbuf_ptr(server_blob);
	server_pub = ciphertext + MLKEM768_CIPHERTEXTBYTES;
	/* hash concatenation of KEM key and ECDH shared key */
	اگر ((buf = sshbuf_new()) == پوچ) {
		r = SSH_ERR_ALLOC_FAIL;
		برو out;
	}
#ifdef DEBUG_KEXECDH
	dump_digest("server cipher text:", ciphertext,
	    MLKEM768_CIPHERTEXTBYTES);
	dump_digest("server public key c25519:", server_pub, CURVE25519_SIZE);
#endif
	اگر (crypto_kem_mlkem768_dec(shared_secret, ciphertext,
	    kex->mlkem768_client_کلید) != 0) {
		r = SSH_ERR_INTERNAL_ERROR;
		برو out;
	}
	اگر ((r = sshbuf_put(buf, shared_secret, اندازه(shared_secret))) != 0)
		برو out;
	اگر ((r = kexc25519_shared_کلید_ext(kex->c25519_client_کلید, server_pub,
	    buf, 1)) < 0)
		برو out;
	اگر ((r = ssh_digest_buffer(kex->hash_alg, buf,
	    hash, اندازه(hash))) != 0)
		برو out;
#ifdef DEBUG_KEXECDH
	dump_digest("client kem key:", shared_secret, اندازه(shared_secret));
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
	/* success */
	r = 0;
	*shared_secretp = buf;
	buf = پوچ;
 out:
	explicit_bzero(hash, اندازه(hash));
	explicit_bzero(shared_secret, اندازه(shared_secret));
	sshbuf_free(buf);
	بازگشت r;
}
#وگرنه /* USE_MLKEM768X25519 */
صحیح
kex_kem_mlkem768x25519_keypair(ساختار kex *kex)
{
	بازگشت SSH_ERR_SIGN_ALG_UNSUPPORTED;
}

صحیح
kex_kem_mlkem768x25519_enc(ساختار kex *kex,
   ثابت ساختار sshbuf *client_blob, ساختار sshbuf **server_blobp,
   ساختار sshbuf **shared_secretp)
{
	بازگشت SSH_ERR_SIGN_ALG_UNSUPPORTED;
}

صحیح
kex_kem_mlkem768x25519_dec(ساختار kex *kex,
    ثابت ساختار sshbuf *server_blob, ساختار sshbuf **shared_secretp)
{
	بازگشت SSH_ERR_SIGN_ALG_UNSUPPORTED;
}
#endif /* USE_MLKEM768X25519 */
