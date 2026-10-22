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
#ضمن "log.h"

#ضمن "crypto_api.h"

#جے_تعریف_شدہ USE_MLKEM768X25519

صحيح
kex_kem_mlkem768x25519_keypair(بنية kex *kex)
{
	بنية sshbuf *buf = عدم;
	u_char *cp = عدم;
	ناپ_t need;
	صحيح r = SSH_ERR_اندرونی_ERROR;

	إذا ((buf = sshbuf_new()) == عدم)
		أرجع SSH_ERR_ALLOC_FAIL;
	need = MLKEM768_PUBLICKEYBYTES + CURVE25519_ناپ;
	إذا ((r = sshbuf_reserve(buf, need, &cp)) != 0)
		اذهب باہرلا;
	إذا (crypto_kem_mlkem768_keypair(cp, kex->mlkem768_client_کلید) != 0) {
		r = SSH_ERR_اندرونی_ERROR;
		اذهب باہرلا;
	}
#جے_تعریف_شدہ DEBUG_KEXECDH
	dump_digest("client public key mlkem768:", cp,
	    MLKEM768_PUBLICKEYBYTES);
#جے_انت
	cp += MLKEM768_PUBLICKEYBYTES;
	kexc25519_keygen(kex->c25519_client_کلید, cp);
#جے_تعریف_شدہ DEBUG_KEXECDH
	dump_digest("client public key c25519:", cp, CURVE25519_ناپ);
#جے_انت
	/* success */
	r = 0;
	kex->client_pub = buf;
	buf = عدم;
 باہرلا:
	sshbuf_free(buf);
	أرجع r;
}

صحيح
kex_kem_mlkem768x25519_enc(بنية kex *kex,
   ثابت بنية sshbuf *client_blob, بنية sshbuf **server_blobp,
   بنية sshbuf **shared_secretp)
{
	بنية sshbuf *server_blob = عدم;
	بنية sshbuf *buf = عدم;
	ثابت u_char *client_pub;
	u_char server_pub[CURVE25519_ناپ], server_کلید[CURVE25519_ناپ];
	u_char hash[SSH_DIGEST_MAX_لمائی];
	u_char ct[MLKEM768_CIPHERTEXTBYTES];
	u_char shared_secret[MLKEM768_بائٹاں];
	ناپ_t need;
	صحيح r = SSH_ERR_اندرونی_ERROR;

	*server_blobp = عدم;
	*shared_secretp = عدم;

	/* client_blob contains both KEM and ECDH client pubkeys */
	need = MLKEM768_PUBLICKEYBYTES + CURVE25519_ناپ;
	إذا (sshbuf_len(client_blob) != need) {
		r = SSH_ERR_SIGNATURE_INVALID;
		اذهب باہرلا;
	}
	client_pub = sshbuf_ptr(client_blob);
#جے_تعریف_شدہ DEBUG_KEXECDH
	dump_digest("client public key mlkem768:", client_pub,
	    MLKEM768_PUBLICKEYBYTES);
	dump_digest("client public key 25519:",
	    client_pub + MLKEM768_PUBLICKEYBYTES,
	    CURVE25519_ناپ);
#جے_انت

	/* allocate buffer for concatenation of KEM key and ECDH shared key */
	/* the buffer will be hashed and the result is the shared secret */
	إذا ((buf = sshbuf_new()) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب باہرلا;
	}
	/* allocate space for encrypted KEM key and ECDH pub key */
	إذا ((server_blob = sshbuf_new()) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب باہرلا;
	}
	/* generate and encrypt KEM key with client key */
	إذا (crypto_kem_mlkem768_enc(ct, shared_secret, client_pub) != 0) {
		r = SSH_ERR_اندرونی_ERROR;
		اذهب باہرلا;
	}
	/* generate ECDH key pair, store server pubkey after ciphertext */
	kexc25519_keygen(server_کلید, server_pub);
	إذا ((r = sshbuf_put(buf, shared_secret, حجم(shared_secret))) != 0 ||
	    (r = sshbuf_put(server_blob, ct, حجم(ct))) != 0 ||
	    (r = sshbuf_put(server_blob, server_pub, حجم(server_pub))) != 0)
		اذهب باہرلا;
	/* append ECDH shared key */
	client_pub += MLKEM768_PUBLICKEYBYTES;
	إذا ((r = kexc25519_shared_کلید_ext(server_کلید, client_pub, buf, 1)) < 0)
		اذهب باہرلا;
	إذا ((r = ssh_digest_بفر(kex->hash_alg, buf,
	    hash, حجم(hash))) != 0)
		اذهب باہرلا;
#جے_تعریف_شدہ DEBUG_KEXECDH
	dump_digest("server public key 25519:", server_pub, CURVE25519_ناپ);
	dump_digest("server cipher text:", ct, حجم(ct));
	dump_digest("server kem key:", shared_secret, حجم(shared_secret));
	dump_digest("concatenation of KEM key and ECDH shared key:",
	    sshbuf_ptr(buf), sshbuf_len(buf));
#جے_انت
	/* string-encoded hash is resulting shared secret */
	sshbuf_reset(buf);
	إذا ((r = sshbuf_put_string(buf, hash,
	    ssh_digest_بائٹاں(kex->hash_alg))) != 0)
		اذهب باہرلا;
#جے_تعریف_شدہ DEBUG_KEXECDH
	dump_digest("encoded shared secret:", sshbuf_ptr(buf), sshbuf_len(buf));
#جے_انت
	/* success */
	r = 0;
	*server_blobp = server_blob;
	*shared_secretp = buf;
	server_blob = عدم;
	buf = عدم;
 باہرلا:
	explicit_bzero(hash, حجم(hash));
	explicit_bzero(server_کلید, حجم(server_کلید));
	explicit_bzero(shared_secret, حجم(shared_secret));
	sshbuf_free(server_blob);
	sshbuf_free(buf);
	أرجع r;
}

صحيح
kex_kem_mlkem768x25519_dec(بنية kex *kex,
    ثابت بنية sshbuf *server_blob, بنية sshbuf **shared_secretp)
{
	بنية sshbuf *buf = عدم;
	u_char shared_secret[MLKEM768_بائٹاں];
	ثابت u_char *ciphertext, *server_pub;
	u_char hash[SSH_DIGEST_MAX_لمائی];
	ناپ_t need;
	صحيح r;

	*shared_secretp = عدم;

	need = MLKEM768_CIPHERTEXTBYTES + CURVE25519_ناپ;
	إذا (sshbuf_len(server_blob) != need) {
		r = SSH_ERR_SIGNATURE_INVALID;
		اذهب باہرلا;
	}
	ciphertext = sshbuf_ptr(server_blob);
	server_pub = ciphertext + MLKEM768_CIPHERTEXTBYTES;
	/* hash concatenation of KEM key and ECDH shared key */
	إذا ((buf = sshbuf_new()) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب باہرلا;
	}
#جے_تعریف_شدہ DEBUG_KEXECDH
	dump_digest("server cipher text:", ciphertext,
	    MLKEM768_CIPHERTEXTBYTES);
	dump_digest("server public key c25519:", server_pub, CURVE25519_ناپ);
#جے_انت
	إذا (crypto_kem_mlkem768_dec(shared_secret, ciphertext,
	    kex->mlkem768_client_کلید) != 0) {
		r = SSH_ERR_اندرونی_ERROR;
		اذهب باہرلا;
	}
	إذا ((r = sshbuf_put(buf, shared_secret, حجم(shared_secret))) != 0)
		اذهب باہرلا;
	إذا ((r = kexc25519_shared_کلید_ext(kex->c25519_client_کلید, server_pub,
	    buf, 1)) < 0)
		اذهب باہرلا;
	إذا ((r = ssh_digest_بفر(kex->hash_alg, buf,
	    hash, حجم(hash))) != 0)
		اذهب باہرلا;
#جے_تعریف_شدہ DEBUG_KEXECDH
	dump_digest("client kem key:", shared_secret, حجم(shared_secret));
	dump_digest("concatenation of KEM key and ECDH shared key:",
	    sshbuf_ptr(buf), sshbuf_len(buf));
#جے_انت
	sshbuf_reset(buf);
	إذا ((r = sshbuf_put_string(buf, hash,
	    ssh_digest_بائٹاں(kex->hash_alg))) != 0)
		اذهب باہرلا;
#جے_تعریف_شدہ DEBUG_KEXECDH
	dump_digest("encoded shared secret:", sshbuf_ptr(buf), sshbuf_len(buf));
#جے_انت
	/* success */
	r = 0;
	*shared_secretp = buf;
	buf = عدم;
 باہرلا:
	explicit_bzero(hash, حجم(hash));
	explicit_bzero(shared_secret, حجم(shared_secret));
	sshbuf_free(buf);
	أرجع r;
}
#وإلا /* USE_MLKEM768X25519 */
صحيح
kex_kem_mlkem768x25519_keypair(بنية kex *kex)
{
	أرجع SSH_ERR_SIGN_ALG_UNSUPPORTED;
}

صحيح
kex_kem_mlkem768x25519_enc(بنية kex *kex,
   ثابت بنية sshbuf *client_blob, بنية sshbuf **server_blobp,
   بنية sshbuf **shared_secretp)
{
	أرجع SSH_ERR_SIGN_ALG_UNSUPPORTED;
}

صحيح
kex_kem_mlkem768x25519_dec(بنية kex *kex,
    ثابت بنية sshbuf *server_blob, بنية sshbuf **shared_secretp)
{
	أرجع SSH_ERR_SIGN_ALG_UNSUPPORTED;
}
#جے_انت /* USE_MLKEM768X25519 */
