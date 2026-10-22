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

#اگر_تعریف_شدہ WITH_OPENSSL
صحیح
kex_kem_mlkem768ecdh_keypair(ساخت kex *kex)
{
	ساخت sshbuf *buf = تہی;
	ساخت sshbuf *ec_blob = تہی;
	EC_کلید *client_کلید = تہی;
	ثابت EC_گروہ *گروہ;
	ثابت EC_نقطہ *عوامی_کلید;
	u_char *cp = تہی;
	سائز_t need;
	صحیح r = SSH_ERR_اندرونی_ERROR;

	اگر ((buf = sshbuf_new()) == تہی)
		واپس SSH_ERR_ALLOC_FAIL;
	need = MLKEM768_PUBLICKEYBYTES;
	اگر ((r = sshbuf_reserve(buf, need, &cp)) != 0)
		جاؤ برآمد;
	اگر (crypto_kem_mlkem768_keypair(cp, kex->mlkem768_client_کلید) != 0) {
		r = SSH_ERR_اندرونی_ERROR;
		جاؤ برآمد;
	}
#اگر_تعریف_شدہ DEBUG_KEXECDH
	dump_digest("client public key mlkem768:", cp,
	    MLKEM768_PUBLICKEYBYTES);
#اگر_ختم
	اگر ((client_کلید = EC_کلید_new_by_خم_name(kex->ec_nid)) == تہی) {
		r = SSH_ERR_ALLOC_FAIL;
		جاؤ برآمد;
	}
	اگر (EC_کلید_generate_کلید(client_کلید) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		جاؤ برآمد;
	}
	گروہ = EC_کلید_get0_گروہ(client_کلید);
	عوامی_کلید = EC_کلید_get0_عوامی_کلید(client_کلید);

	اگر ((ec_blob = sshbuf_new()) == تہی) {
		r = SSH_ERR_ALLOC_FAIL;
		جاؤ برآمد;
	}
	اگر ((r = sshbuf_put_ec(ec_blob, عوامی_کلید, گروہ)) != 0 ||
	    (r = sshbuf_get_u32(ec_blob, تہی)) != 0 ||
	    (r = sshbuf_putb(buf, ec_blob)) != 0)
		جاؤ برآمد;
#اگر_تعریف_شدہ DEBUG_KEXECDH
	fputs("client private key EC:\n", stderr);
	sshkey_dump_ec_کلید(client_کلید);
#اگر_ختم
	/* success */
	r = 0;
	kex->ec_client_کلید = client_کلید;
	kex->ec_گروہ = گروہ;
	client_کلید = تہی;	/* owned by the kex */
	kex->client_pub = buf;
	buf = تہی;
 برآمد:
	sshbuf_free(buf);
	sshbuf_free(ec_blob);
	EC_کلید_free(client_کلید);
	واپس r;
}

صحیح
kex_kem_mlkem768ecdh_enc(ساخت kex *kex,
   ثابت ساخت sshbuf *client_blob, ساخت sshbuf **server_blobp,
   ساخت sshbuf **shared_secretp)
{
	ثابت EC_گروہ *گروہ;
	ثابت EC_نقطہ *pub_کلید;
	EC_کلید *server_کلید = تہی;
	ساخت sshbuf *ec_pub = تہی;
	ساخت sshbuf *ec_blob = تہی;
	ساخت sshbuf *ec_shared = تہی;
	ساخت sshbuf *server_blob = تہی;
	ساخت sshbuf *buf = تہی;
	ثابت u_char *client_pub;
	u_char hash[SSH_DIGEST_MAX_لمبائی];
	u_char ct[MLKEM768_CIPHERTEXTBYTES];
	u_char shared_secret[MLKEM768_بائٹیں];
	سائز_t need;
	صحیح r = SSH_ERR_اندرونی_ERROR;

	*server_blobp = تہی;
	*shared_secretp = تہی;

	/* client_blob contains both KEM and ECDH client pubkeys */
	need = MLKEM768_PUBLICKEYBYTES;
	اگر (sshbuf_len(client_blob) <= need) {
		r = SSH_ERR_SIGNATURE_INVALID;
		جاؤ برآمد;
	}
	client_pub = sshbuf_ptr(client_blob);
#اگر_تعریف_شدہ DEBUG_KEXECDH
	dump_digest("client public key mlkem768:", client_pub,
	    MLKEM768_PUBLICKEYBYTES);
#اگر_ختم

	/* allocate buffer for concatenation of KEM key and ECDH shared key */
	/* the buffer will be hashed and the result is the shared secret */
	اگر ((buf = sshbuf_new()) == تہی) {
		r = SSH_ERR_ALLOC_FAIL;
		جاؤ برآمد;
	}
	/* allocate space for encrypted KEM key and ECDH pub key */
	اگر ((server_blob = sshbuf_new()) == تہی) {
		r = SSH_ERR_ALLOC_FAIL;
		جاؤ برآمد;
	}
	/* generate and encrypt KEM key with client key */
	اگر (crypto_kem_mlkem768_enc(ct, shared_secret, client_pub) != 0) {
		r = SSH_ERR_اندرونی_ERROR;
		جاؤ برآمد;
	}
	اگر ((r = sshbuf_put(buf, shared_secret, حجم(shared_secret))) != 0 ||
	    (r = sshbuf_put(server_blob, ct, حجم(ct))) != 0)
		جاؤ برآمد;

	client_pub += MLKEM768_PUBLICKEYBYTES;
	اگر ((ec_pub = sshbuf_from(client_pub, sshbuf_len(client_blob) -
	    MLKEM768_PUBLICKEYBYTES)) == تہی) {
		r = SSH_ERR_ALLOC_FAIL;
		جاؤ برآمد;
	}
	/* generate ECDH key pair */
	اگر ((server_کلید = EC_کلید_new_by_خم_name(kex->ec_nid)) == تہی) {
		r = SSH_ERR_ALLOC_FAIL;
		جاؤ برآمد;
	}
	اگر (EC_کلید_generate_کلید(server_کلید) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		جاؤ برآمد;
	}
	گروہ = EC_کلید_get0_گروہ(server_کلید);
#اگر_تعریف_شدہ DEBUG_KEXECDH
	fputs("server private key EC:\n", stderr);
	sshkey_dump_ec_کلید(server_کلید);
#اگر_ختم
	/* store server pubkey after ciphertext */
	pub_کلید = EC_کلید_get0_عوامی_کلید(server_کلید);
	اگر ((ec_blob = sshbuf_new()) == تہی) {
		r = SSH_ERR_ALLOC_FAIL;
		جاؤ برآمد;
	}
	اگر ((r = sshbuf_put_ec(ec_blob, pub_کلید, گروہ)) != 0 ||
	    (r = sshbuf_get_u32(ec_blob, تہی)) != 0 ||
	    (r = sshbuf_putb(server_blob, ec_blob)) != 0)
		جاؤ برآمد;

	/* append ECDH shared key */
	اگر ((r = kex_ecdh_dec_کلید_گروہ(kex, ec_pub, server_کلید, گروہ,
	    1, &ec_shared)) != 0 ||
	    (r = sshbuf_putb(buf, ec_shared)) != 0)
		جاؤ برآمد;

	اگر ((r = ssh_digest_بفر(kex->hash_alg, buf, hash, حجم(hash))) != 0)
		جاؤ برآمد;
#اگر_تعریف_شدہ DEBUG_KEXECDH
	dump_digest("server cipher text:", ct, حجم(ct));
	dump_digest("server kem key:", shared_secret, حجم(shared_secret));
	dump_digest("concatenation of KEM key and ECDH shared key:",
	    sshbuf_ptr(buf), sshbuf_len(buf));
#اگر_ختم
	/* string-encoded hash is resulting shared secret */
	sshbuf_reset(buf);
	اگر ((r = sshbuf_put_string(buf, hash,
	    ssh_digest_بائٹیں(kex->hash_alg))) != 0)
		جاؤ برآمد;
#اگر_تعریف_شدہ DEBUG_KEXECDH
	dump_digest("encoded shared secret:", sshbuf_ptr(buf), sshbuf_len(buf));
#اگر_ختم
	/* success */
	r = 0;
	*server_blobp = server_blob;
	*shared_secretp = buf;
	server_blob = تہی;
	buf = تہی;
 برآمد:
	explicit_bzero(hash, حجم(hash));
	explicit_bzero(shared_secret, حجم(shared_secret));
	EC_کلید_free(server_کلید);
	sshbuf_free(ec_pub);
	sshbuf_free(ec_blob);
	sshbuf_free(ec_shared);
	sshbuf_free(server_blob);
	sshbuf_free(buf);
	واپس r;
}

صحیح
kex_kem_mlkem768ecdh_dec(ساخت kex *kex,
    ثابت ساخت sshbuf *server_blob, ساخت sshbuf **shared_secretp)
{
	ساخت sshbuf *buf = تہی;
	ساخت sshbuf *ec_pub = تہی;
	ساخت sshbuf *ec_shared = تہی;
	u_char shared_secret[MLKEM768_بائٹیں];
	ثابت u_char *ciphertext, *server_pub;
	u_char hash[SSH_DIGEST_MAX_لمبائی];
	سائز_t need;
	صحیح r;

	*shared_secretp = تہی;

	need = MLKEM768_CIPHERTEXTBYTES;
	اگر (sshbuf_len(server_blob) <= need) {
		r = SSH_ERR_SIGNATURE_INVALID;
		جاؤ برآمد;
	}
	ciphertext = sshbuf_ptr(server_blob);
	server_pub = ciphertext + MLKEM768_CIPHERTEXTBYTES;
#اگر_تعریف_شدہ DEBUG_KEXECDH
	dump_digest("server cipher text (dec):", ciphertext,
	    MLKEM768_CIPHERTEXTBYTES);
#اگر_ختم
	/* hash concatenation of KEM key and ECDH shared key */
	اگر ((buf = sshbuf_new()) == تہی) {
		r = SSH_ERR_ALLOC_FAIL;
		جاؤ برآمد;
	}
	اگر (crypto_kem_mlkem768_dec(shared_secret, ciphertext,
	    kex->mlkem768_client_کلید) != 0) {
		r = SSH_ERR_اندرونی_ERROR;
		جاؤ برآمد;
	}
	اگر ((r = sshbuf_put(buf, shared_secret, حجم(shared_secret))) != 0)
		جاؤ برآمد;
	اگر ((ec_pub = sshbuf_from(server_pub, sshbuf_len(server_blob) - need))
	    == تہی) {
		r = SSH_ERR_ALLOC_FAIL;
		جاؤ برآمد;
	}
	اگر ((r = kex_ecdh_dec_کلید_گروہ(kex, ec_pub, kex->ec_client_کلید,
	    kex->ec_گروہ, 1, &ec_shared)) != 0 ||
	    (r = sshbuf_putb(buf, ec_shared)) != 0)
		جاؤ برآمد;
	اگر ((r = ssh_digest_بفر(kex->hash_alg, buf,
	    hash, حجم(hash))) != 0)
		جاؤ برآمد;
#اگر_تعریف_شدہ DEBUG_KEXECDH
	dump_digest("client kem key:", shared_secret, حجم(shared_secret));
	dump_digest("concatenation of KEM key and ECDH shared key:",
	    sshbuf_ptr(buf), sshbuf_len(buf));
#اگر_ختم
	sshbuf_reset(buf);
	اگر ((r = sshbuf_put_string(buf, hash,
	    ssh_digest_بائٹیں(kex->hash_alg))) != 0)
		جاؤ برآمد;
#اگر_تعریف_شدہ DEBUG_KEXECDH
	dump_digest("encoded shared secret:", sshbuf_ptr(buf), sshbuf_len(buf));
#اگر_ختم
	/* success */
	r = 0;
	*shared_secretp = buf;
	buf = تہی;
 برآمد:
	explicit_bzero(hash, حجم(hash));
	explicit_bzero(shared_secret, حجم(shared_secret));
	EC_کلید_free(kex->ec_client_کلید);
	kex->ec_client_کلید = تہی;
	sshbuf_free(ec_pub);
	sshbuf_free(ec_shared);
	sshbuf_free(buf);
	واپس r;
}
#اگر_ختم	/* WITH_OPENSSL */
