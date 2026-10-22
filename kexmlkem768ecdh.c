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

#که_تعریف_شوی WITH_OPENSSL
صحيح
kex_kem_mlkem768ecdh_keypair(بنية kex *kex)
{
	بنية sshbuf *buf = عدم;
	بنية sshbuf *ec_blob = عدم;
	EC_کلی *client_کلی = عدم;
	ثابت EC_ډله *ډله;
	ثابت EC_ټکی *عامه_کلی;
	u_char *cp = عدم;
	اندازه_t need;
	صحيح r = SSH_ERR_دننی_ERROR;

	إذا ((buf = sshbuf_new()) == عدم)
		أرجع SSH_ERR_ALLOC_FAIL;
	need = MLKEM768_PUBLICKEYBYTES;
	إذا ((r = sshbuf_reserve(buf, need, &cp)) != 0)
		اذهب بهر;
	إذا (crypto_kem_mlkem768_keypair(cp, kex->mlkem768_client_کلی) != 0) {
		r = SSH_ERR_دننی_ERROR;
		اذهب بهر;
	}
#که_تعریف_شوی DEBUG_KEXECDH
	dump_digest("client public key mlkem768:", cp,
	    MLKEM768_PUBLICKEYBYTES);
#د_که_پای
	إذا ((client_کلی = EC_کلی_new_by_منحني_name(kex->ec_nid)) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب بهر;
	}
	إذا (EC_کلی_generate_کلی(client_کلی) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		اذهب بهر;
	}
	ډله = EC_کلی_get0_ډله(client_کلی);
	عامه_کلی = EC_کلی_get0_عامه_کلی(client_کلی);

	إذا ((ec_blob = sshbuf_new()) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب بهر;
	}
	إذا ((r = sshbuf_put_ec(ec_blob, عامه_کلی, ډله)) != 0 ||
	    (r = sshbuf_get_u32(ec_blob, عدم)) != 0 ||
	    (r = sshbuf_putb(buf, ec_blob)) != 0)
		اذهب بهر;
#که_تعریف_شوی DEBUG_KEXECDH
	fputs("client private key EC:\n", stderr);
	sshkey_dump_ec_کلی(client_کلی);
#د_که_پای
	/* success */
	r = 0;
	kex->ec_client_کلی = client_کلی;
	kex->ec_ډله = ډله;
	client_کلی = عدم;	/* owned by the kex */
	kex->client_pub = buf;
	buf = عدم;
 بهر:
	sshbuf_free(buf);
	sshbuf_free(ec_blob);
	EC_کلی_free(client_کلی);
	أرجع r;
}

صحيح
kex_kem_mlkem768ecdh_enc(بنية kex *kex,
   ثابت بنية sshbuf *client_blob, بنية sshbuf **server_blobp,
   بنية sshbuf **shared_secretp)
{
	ثابت EC_ډله *ډله;
	ثابت EC_ټکی *pub_کلی;
	EC_کلی *server_کلی = عدم;
	بنية sshbuf *ec_pub = عدم;
	بنية sshbuf *ec_blob = عدم;
	بنية sshbuf *ec_shared = عدم;
	بنية sshbuf *server_blob = عدم;
	بنية sshbuf *buf = عدم;
	ثابت u_char *client_pub;
	u_char hash[SSH_DIGEST_MAX_اوږدتیا];
	u_char ct[MLKEM768_CIPHERTEXTBYTES];
	u_char shared_secret[MLKEM768_بایټونه];
	اندازه_t need;
	صحيح r = SSH_ERR_دننی_ERROR;

	*server_blobp = عدم;
	*shared_secretp = عدم;

	/* client_blob contains both KEM and ECDH client pubkeys */
	need = MLKEM768_PUBLICKEYBYTES;
	إذا (sshbuf_len(client_blob) <= need) {
		r = SSH_ERR_SIGNATURE_INVALID;
		اذهب بهر;
	}
	client_pub = sshbuf_ptr(client_blob);
#که_تعریف_شوی DEBUG_KEXECDH
	dump_digest("client public key mlkem768:", client_pub,
	    MLKEM768_PUBLICKEYBYTES);
#د_که_پای

	/* allocate buffer for concatenation of KEM key and ECDH shared key */
	/* the buffer will be hashed and the result is the shared secret */
	إذا ((buf = sshbuf_new()) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب بهر;
	}
	/* allocate space for encrypted KEM key and ECDH pub key */
	إذا ((server_blob = sshbuf_new()) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب بهر;
	}
	/* generate and encrypt KEM key with client key */
	إذا (crypto_kem_mlkem768_enc(ct, shared_secret, client_pub) != 0) {
		r = SSH_ERR_دننی_ERROR;
		اذهب بهر;
	}
	إذا ((r = sshbuf_put(buf, shared_secret, حجم(shared_secret))) != 0 ||
	    (r = sshbuf_put(server_blob, ct, حجم(ct))) != 0)
		اذهب بهر;

	client_pub += MLKEM768_PUBLICKEYBYTES;
	إذا ((ec_pub = sshbuf_from(client_pub, sshbuf_len(client_blob) -
	    MLKEM768_PUBLICKEYBYTES)) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب بهر;
	}
	/* generate ECDH key pair */
	إذا ((server_کلی = EC_کلی_new_by_منحني_name(kex->ec_nid)) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب بهر;
	}
	إذا (EC_کلی_generate_کلی(server_کلی) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		اذهب بهر;
	}
	ډله = EC_کلی_get0_ډله(server_کلی);
#که_تعریف_شوی DEBUG_KEXECDH
	fputs("server private key EC:\n", stderr);
	sshkey_dump_ec_کلی(server_کلی);
#د_که_پای
	/* store server pubkey after ciphertext */
	pub_کلی = EC_کلی_get0_عامه_کلی(server_کلی);
	إذا ((ec_blob = sshbuf_new()) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب بهر;
	}
	إذا ((r = sshbuf_put_ec(ec_blob, pub_کلی, ډله)) != 0 ||
	    (r = sshbuf_get_u32(ec_blob, عدم)) != 0 ||
	    (r = sshbuf_putb(server_blob, ec_blob)) != 0)
		اذهب بهر;

	/* append ECDH shared key */
	إذا ((r = kex_ecdh_dec_کلی_ډله(kex, ec_pub, server_کلی, ډله,
	    1, &ec_shared)) != 0 ||
	    (r = sshbuf_putb(buf, ec_shared)) != 0)
		اذهب بهر;

	إذا ((r = ssh_digest_بفر(kex->hash_alg, buf, hash, حجم(hash))) != 0)
		اذهب بهر;
#که_تعریف_شوی DEBUG_KEXECDH
	dump_digest("server cipher text:", ct, حجم(ct));
	dump_digest("server kem key:", shared_secret, حجم(shared_secret));
	dump_digest("concatenation of KEM key and ECDH shared key:",
	    sshbuf_ptr(buf), sshbuf_len(buf));
#د_که_پای
	/* string-encoded hash is resulting shared secret */
	sshbuf_reset(buf);
	إذا ((r = sshbuf_put_string(buf, hash,
	    ssh_digest_بایټونه(kex->hash_alg))) != 0)
		اذهب بهر;
#که_تعریف_شوی DEBUG_KEXECDH
	dump_digest("encoded shared secret:", sshbuf_ptr(buf), sshbuf_len(buf));
#د_که_پای
	/* success */
	r = 0;
	*server_blobp = server_blob;
	*shared_secretp = buf;
	server_blob = عدم;
	buf = عدم;
 بهر:
	explicit_bzero(hash, حجم(hash));
	explicit_bzero(shared_secret, حجم(shared_secret));
	EC_کلی_free(server_کلی);
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
	u_char shared_secret[MLKEM768_بایټونه];
	ثابت u_char *ciphertext, *server_pub;
	u_char hash[SSH_DIGEST_MAX_اوږدتیا];
	اندازه_t need;
	صحيح r;

	*shared_secretp = عدم;

	need = MLKEM768_CIPHERTEXTBYTES;
	إذا (sshbuf_len(server_blob) <= need) {
		r = SSH_ERR_SIGNATURE_INVALID;
		اذهب بهر;
	}
	ciphertext = sshbuf_ptr(server_blob);
	server_pub = ciphertext + MLKEM768_CIPHERTEXTBYTES;
#که_تعریف_شوی DEBUG_KEXECDH
	dump_digest("server cipher text (dec):", ciphertext,
	    MLKEM768_CIPHERTEXTBYTES);
#د_که_پای
	/* hash concatenation of KEM key and ECDH shared key */
	إذا ((buf = sshbuf_new()) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب بهر;
	}
	إذا (crypto_kem_mlkem768_dec(shared_secret, ciphertext,
	    kex->mlkem768_client_کلی) != 0) {
		r = SSH_ERR_دننی_ERROR;
		اذهب بهر;
	}
	إذا ((r = sshbuf_put(buf, shared_secret, حجم(shared_secret))) != 0)
		اذهب بهر;
	إذا ((ec_pub = sshbuf_from(server_pub, sshbuf_len(server_blob) - need))
	    == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب بهر;
	}
	إذا ((r = kex_ecdh_dec_کلی_ډله(kex, ec_pub, kex->ec_client_کلی,
	    kex->ec_ډله, 1, &ec_shared)) != 0 ||
	    (r = sshbuf_putb(buf, ec_shared)) != 0)
		اذهب بهر;
	إذا ((r = ssh_digest_بفر(kex->hash_alg, buf,
	    hash, حجم(hash))) != 0)
		اذهب بهر;
#که_تعریف_شوی DEBUG_KEXECDH
	dump_digest("client kem key:", shared_secret, حجم(shared_secret));
	dump_digest("concatenation of KEM key and ECDH shared key:",
	    sshbuf_ptr(buf), sshbuf_len(buf));
#د_که_پای
	sshbuf_reset(buf);
	إذا ((r = sshbuf_put_string(buf, hash,
	    ssh_digest_بایټونه(kex->hash_alg))) != 0)
		اذهب بهر;
#که_تعریف_شوی DEBUG_KEXECDH
	dump_digest("encoded shared secret:", sshbuf_ptr(buf), sshbuf_len(buf));
#د_که_پای
	/* success */
	r = 0;
	*shared_secretp = buf;
	buf = عدم;
 بهر:
	explicit_bzero(hash, حجم(hash));
	explicit_bzero(shared_secret, حجم(shared_secret));
	EC_کلی_free(kex->ec_client_کلی);
	kex->ec_client_کلی = عدم;
	sshbuf_free(ec_pub);
	sshbuf_free(ec_shared);
	sshbuf_free(buf);
	أرجع r;
}
#د_که_پای	/* WITH_OPENSSL */
