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

#اگر_تعریف_شده WITH_OPENSSL
صحيح
kex_kem_mlkem768ecdh_keypair(بنية kex *kex)
{
	بنية sshbuf *buf = عدم;
	بنية sshbuf *ec_blob = عدم;
	EC_کلید *client_کلید = عدم;
	ثابت EC_گروه *گروه;
	ثابت EC_نقطه *عمومی_کلید;
	u_char *cp = عدم;
	اندازه_t need;
	صحيح r = SSH_ERR_داخلی_ERROR;

	إذا ((buf = sshbuf_new()) == عدم)
		أرجع SSH_ERR_ALLOC_FAIL;
	need = MLKEM768_PUBLICKEYBYTES;
	إذا ((r = sshbuf_reserve(buf, need, &cp)) != 0)
		اذهب بیرون;
	إذا (crypto_kem_mlkem768_keypair(cp, kex->mlkem768_client_کلید) != 0) {
		r = SSH_ERR_داخلی_ERROR;
		اذهب بیرون;
	}
#اگر_تعریف_شده DEBUG_KEXECDH
	dump_digest("client public key mlkem768:", cp,
	    MLKEM768_PUBLICKEYBYTES);
#پایان_اگر
	إذا ((client_کلید = EC_کلید_new_by_منحنی_name(kex->ec_nid)) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب بیرون;
	}
	إذا (EC_کلید_generate_کلید(client_کلید) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		اذهب بیرون;
	}
	گروه = EC_کلید_get0_گروه(client_کلید);
	عمومی_کلید = EC_کلید_get0_عمومی_کلید(client_کلید);

	إذا ((ec_blob = sshbuf_new()) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب بیرون;
	}
	إذا ((r = sshbuf_put_ec(ec_blob, عمومی_کلید, گروه)) != 0 ||
	    (r = sshbuf_get_u32(ec_blob, عدم)) != 0 ||
	    (r = sshbuf_putb(buf, ec_blob)) != 0)
		اذهب بیرون;
#اگر_تعریف_شده DEBUG_KEXECDH
	fputs("client private key EC:\n", stderr);
	sshkey_dump_ec_کلید(client_کلید);
#پایان_اگر
	/* success */
	r = 0;
	kex->ec_client_کلید = client_کلید;
	kex->ec_گروه = گروه;
	client_کلید = عدم;	/* owned by the kex */
	kex->client_pub = buf;
	buf = عدم;
 بیرون:
	sshbuf_free(buf);
	sshbuf_free(ec_blob);
	EC_کلید_free(client_کلید);
	أرجع r;
}

صحيح
kex_kem_mlkem768ecdh_enc(بنية kex *kex,
   ثابت بنية sshbuf *client_blob, بنية sshbuf **server_blobp,
   بنية sshbuf **shared_secretp)
{
	ثابت EC_گروه *گروه;
	ثابت EC_نقطه *pub_کلید;
	EC_کلید *server_کلید = عدم;
	بنية sshbuf *ec_pub = عدم;
	بنية sshbuf *ec_blob = عدم;
	بنية sshbuf *ec_shared = عدم;
	بنية sshbuf *server_blob = عدم;
	بنية sshbuf *buf = عدم;
	ثابت u_char *client_pub;
	u_char hash[SSH_DIGEST_MAX_درازی];
	u_char ct[MLKEM768_CIPHERTEXTBYTES];
	u_char shared_secret[MLKEM768_بایتها];
	اندازه_t need;
	صحيح r = SSH_ERR_داخلی_ERROR;

	*server_blobp = عدم;
	*shared_secretp = عدم;

	/* client_blob contains both KEM and ECDH client pubkeys */
	need = MLKEM768_PUBLICKEYBYTES;
	إذا (sshbuf_len(client_blob) <= need) {
		r = SSH_ERR_SIGNATURE_INVALID;
		اذهب بیرون;
	}
	client_pub = sshbuf_ptr(client_blob);
#اگر_تعریف_شده DEBUG_KEXECDH
	dump_digest("client public key mlkem768:", client_pub,
	    MLKEM768_PUBLICKEYBYTES);
#پایان_اگر

	/* allocate buffer for concatenation of KEM key and ECDH shared key */
	/* the buffer will be hashed and the result is the shared secret */
	إذا ((buf = sshbuf_new()) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب بیرون;
	}
	/* allocate space for encrypted KEM key and ECDH pub key */
	إذا ((server_blob = sshbuf_new()) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب بیرون;
	}
	/* generate and encrypt KEM key with client key */
	إذا (crypto_kem_mlkem768_enc(ct, shared_secret, client_pub) != 0) {
		r = SSH_ERR_داخلی_ERROR;
		اذهب بیرون;
	}
	إذا ((r = sshbuf_put(buf, shared_secret, حجم(shared_secret))) != 0 ||
	    (r = sshbuf_put(server_blob, ct, حجم(ct))) != 0)
		اذهب بیرون;

	client_pub += MLKEM768_PUBLICKEYBYTES;
	إذا ((ec_pub = sshbuf_from(client_pub, sshbuf_len(client_blob) -
	    MLKEM768_PUBLICKEYBYTES)) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب بیرون;
	}
	/* generate ECDH key pair */
	إذا ((server_کلید = EC_کلید_new_by_منحنی_name(kex->ec_nid)) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب بیرون;
	}
	إذا (EC_کلید_generate_کلید(server_کلید) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		اذهب بیرون;
	}
	گروه = EC_کلید_get0_گروه(server_کلید);
#اگر_تعریف_شده DEBUG_KEXECDH
	fputs("server private key EC:\n", stderr);
	sshkey_dump_ec_کلید(server_کلید);
#پایان_اگر
	/* store server pubkey after ciphertext */
	pub_کلید = EC_کلید_get0_عمومی_کلید(server_کلید);
	إذا ((ec_blob = sshbuf_new()) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب بیرون;
	}
	إذا ((r = sshbuf_put_ec(ec_blob, pub_کلید, گروه)) != 0 ||
	    (r = sshbuf_get_u32(ec_blob, عدم)) != 0 ||
	    (r = sshbuf_putb(server_blob, ec_blob)) != 0)
		اذهب بیرون;

	/* append ECDH shared key */
	إذا ((r = kex_ecdh_dec_کلید_گروه(kex, ec_pub, server_کلید, گروه,
	    1, &ec_shared)) != 0 ||
	    (r = sshbuf_putb(buf, ec_shared)) != 0)
		اذهب بیرون;

	إذا ((r = ssh_digest_میانگیر(kex->hash_alg, buf, hash, حجم(hash))) != 0)
		اذهب بیرون;
#اگر_تعریف_شده DEBUG_KEXECDH
	dump_digest("server cipher text:", ct, حجم(ct));
	dump_digest("server kem key:", shared_secret, حجم(shared_secret));
	dump_digest("concatenation of KEM key and ECDH shared key:",
	    sshbuf_ptr(buf), sshbuf_len(buf));
#پایان_اگر
	/* string-encoded hash is resulting shared secret */
	sshbuf_reset(buf);
	إذا ((r = sshbuf_put_string(buf, hash,
	    ssh_digest_بایتها(kex->hash_alg))) != 0)
		اذهب بیرون;
#اگر_تعریف_شده DEBUG_KEXECDH
	dump_digest("encoded shared secret:", sshbuf_ptr(buf), sshbuf_len(buf));
#پایان_اگر
	/* success */
	r = 0;
	*server_blobp = server_blob;
	*shared_secretp = buf;
	server_blob = عدم;
	buf = عدم;
 بیرون:
	explicit_bzero(hash, حجم(hash));
	explicit_bzero(shared_secret, حجم(shared_secret));
	EC_کلید_free(server_کلید);
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
	u_char shared_secret[MLKEM768_بایتها];
	ثابت u_char *ciphertext, *server_pub;
	u_char hash[SSH_DIGEST_MAX_درازی];
	اندازه_t need;
	صحيح r;

	*shared_secretp = عدم;

	need = MLKEM768_CIPHERTEXTBYTES;
	إذا (sshbuf_len(server_blob) <= need) {
		r = SSH_ERR_SIGNATURE_INVALID;
		اذهب بیرون;
	}
	ciphertext = sshbuf_ptr(server_blob);
	server_pub = ciphertext + MLKEM768_CIPHERTEXTBYTES;
#اگر_تعریف_شده DEBUG_KEXECDH
	dump_digest("server cipher text (dec):", ciphertext,
	    MLKEM768_CIPHERTEXTBYTES);
#پایان_اگر
	/* hash concatenation of KEM key and ECDH shared key */
	إذا ((buf = sshbuf_new()) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب بیرون;
	}
	إذا (crypto_kem_mlkem768_dec(shared_secret, ciphertext,
	    kex->mlkem768_client_کلید) != 0) {
		r = SSH_ERR_داخلی_ERROR;
		اذهب بیرون;
	}
	إذا ((r = sshbuf_put(buf, shared_secret, حجم(shared_secret))) != 0)
		اذهب بیرون;
	إذا ((ec_pub = sshbuf_from(server_pub, sshbuf_len(server_blob) - need))
	    == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب بیرون;
	}
	إذا ((r = kex_ecdh_dec_کلید_گروه(kex, ec_pub, kex->ec_client_کلید,
	    kex->ec_گروه, 1, &ec_shared)) != 0 ||
	    (r = sshbuf_putb(buf, ec_shared)) != 0)
		اذهب بیرون;
	إذا ((r = ssh_digest_میانگیر(kex->hash_alg, buf,
	    hash, حجم(hash))) != 0)
		اذهب بیرون;
#اگر_تعریف_شده DEBUG_KEXECDH
	dump_digest("client kem key:", shared_secret, حجم(shared_secret));
	dump_digest("concatenation of KEM key and ECDH shared key:",
	    sshbuf_ptr(buf), sshbuf_len(buf));
#پایان_اگر
	sshbuf_reset(buf);
	إذا ((r = sshbuf_put_string(buf, hash,
	    ssh_digest_بایتها(kex->hash_alg))) != 0)
		اذهب بیرون;
#اگر_تعریف_شده DEBUG_KEXECDH
	dump_digest("encoded shared secret:", sshbuf_ptr(buf), sshbuf_len(buf));
#پایان_اگر
	/* success */
	r = 0;
	*shared_secretp = buf;
	buf = عدم;
 بیرون:
	explicit_bzero(hash, حجم(hash));
	explicit_bzero(shared_secret, حجم(shared_secret));
	EC_کلید_free(kex->ec_client_کلید);
	kex->ec_client_کلید = عدم;
	sshbuf_free(ec_pub);
	sshbuf_free(ec_shared);
	sshbuf_free(buf);
	أرجع r;
}
#پایان_اگر	/* WITH_OPENSSL */
