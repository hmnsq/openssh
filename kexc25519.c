/* $OpenBSD: kexc25519.c,v 1.18 2024/09/02 12:13:56 djm Exp $ */
/*
 * Copyright (c) 2019 Markus Friedl.  All rights reserved.
 * Copyright (c) 2010 Damien Miller.  All rights reserved.
 * Copyright (c) 2013 Aris Adamantiadis.  All rights reserved.
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
#شامل <string.h>
#شامل <signal.h>

#شامل "sshkey.h"
#شامل "kex.h"
#شامل "sshbuf.h"
#شامل "digest.h"
#شامل "ssherr.h"
#شامل "ssh2.h"

بیرونی صحیح crypto_scalarmult_curve25519(u_char a[CURVE25519_SIZE],
    ثابت u_char b[CURVE25519_SIZE], ثابت u_char c[CURVE25519_SIZE])
	__attribute__((__bounded__(__minbytes__, 1, CURVE25519_SIZE)))
	__attribute__((__bounded__(__minbytes__, 2, CURVE25519_SIZE)))
	__attribute__((__bounded__(__minbytes__, 3, CURVE25519_SIZE)));

تهی
kexc25519_keygen(u_char کلید[CURVE25519_SIZE], u_char pub[CURVE25519_SIZE])
{
	ایستا ثابت u_char basepoint[CURVE25519_SIZE] = {9};

	arc4random_buf(کلید, CURVE25519_SIZE);
	crypto_scalarmult_curve25519(pub, کلید, basepoint);
}

صحیح
kexc25519_shared_کلید_ext(ثابت u_char کلید[CURVE25519_SIZE],
    ثابت u_char pub[CURVE25519_SIZE], ساختار sshbuf *out, صحیح raw)
{
	u_char shared_کلید[CURVE25519_SIZE];
	u_char zero[CURVE25519_SIZE];
	صحیح r;

	crypto_scalarmult_curve25519(shared_کلید, کلید, pub);

	/* Check for all-zero shared secret */
	explicit_bzero(zero, CURVE25519_SIZE);
	اگر (timingsafe_bcmp(zero, shared_کلید, CURVE25519_SIZE) == 0)
		بازگشت SSH_ERR_کلید_INVALID_EC_مقدار;

#ifdef DEBUG_KEXECDH
	dump_digest("shared secret 25519", shared_کلید, CURVE25519_SIZE);
#endif
	اگر (raw)
		r = sshbuf_put(out, shared_کلید, CURVE25519_SIZE);
	وگرنه
		r = sshbuf_put_bignum2_bytes(out, shared_کلید, CURVE25519_SIZE);
	explicit_bzero(shared_کلید, CURVE25519_SIZE);
	بازگشت r;
}

صحیح
kexc25519_shared_کلید(ثابت u_char کلید[CURVE25519_SIZE],
    ثابت u_char pub[CURVE25519_SIZE], ساختار sshbuf *out)
{
	بازگشت kexc25519_shared_کلید_ext(کلید, pub, out, 0);
}

صحیح
kex_c25519_keypair(ساختار kex *kex)
{
	ساختار sshbuf *buf = پوچ;
	u_char *cp = پوچ;
	صحیح r;

	اگر ((buf = sshbuf_new()) == پوچ)
		بازگشت SSH_ERR_ALLOC_FAIL;
	اگر ((r = sshbuf_reserve(buf, CURVE25519_SIZE, &cp)) != 0)
		برو out;
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
kex_c25519_enc(ساختار kex *kex, ثابت ساختار sshbuf *client_blob,
   ساختار sshbuf **server_blobp, ساختار sshbuf **shared_secretp)
{
	ساختار sshbuf *server_blob = پوچ;
	ساختار sshbuf *buf = پوچ;
	ثابت u_char *client_pub;
	u_char *server_pub;
	u_char server_کلید[CURVE25519_SIZE];
	صحیح r;

	*server_blobp = پوچ;
	*shared_secretp = پوچ;

	اگر (sshbuf_len(client_blob) != CURVE25519_SIZE) {
		r = SSH_ERR_SIGNATURE_INVALID;
		برو out;
	}
	client_pub = sshbuf_ptr(client_blob);
#ifdef DEBUG_KEXECDH
	dump_digest("client public key 25519:", client_pub, CURVE25519_SIZE);
#endif
	/* allocate space for encrypted KEM key and ECDH pub key */
	اگر ((server_blob = sshbuf_new()) == پوچ) {
		r = SSH_ERR_ALLOC_FAIL;
		برو out;
	}
	اگر ((r = sshbuf_reserve(server_blob, CURVE25519_SIZE, &server_pub)) != 0)
		برو out;
	kexc25519_keygen(server_کلید, server_pub);
	/* allocate shared secret */
	اگر ((buf = sshbuf_new()) == پوچ) {
		r = SSH_ERR_ALLOC_FAIL;
		برو out;
	}
	اگر ((r = kexc25519_shared_کلید_ext(server_کلید, client_pub, buf, 0)) < 0)
		برو out;
#ifdef DEBUG_KEXECDH
	dump_digest("server public key 25519:", server_pub, CURVE25519_SIZE);
	dump_digest("encoded shared secret:", sshbuf_ptr(buf), sshbuf_len(buf));
#endif
	*server_blobp = server_blob;
	*shared_secretp = buf;
	server_blob = پوچ;
	buf = پوچ;
 out:
	explicit_bzero(server_کلید, اندازه(server_کلید));
	sshbuf_free(server_blob);
	sshbuf_free(buf);
	بازگشت r;
}

صحیح
kex_c25519_dec(ساختار kex *kex, ثابت ساختار sshbuf *server_blob,
    ساختار sshbuf **shared_secretp)
{
	ساختار sshbuf *buf = پوچ;
	ثابت u_char *server_pub;
	صحیح r;

	*shared_secretp = پوچ;

	اگر (sshbuf_len(server_blob) != CURVE25519_SIZE) {
		r = SSH_ERR_SIGNATURE_INVALID;
		برو out;
	}
	server_pub = sshbuf_ptr(server_blob);
#ifdef DEBUG_KEXECDH
	dump_digest("server public key c25519:", server_pub, CURVE25519_SIZE);
#endif
	/* shared secret */
	اگر ((buf = sshbuf_new()) == پوچ) {
		r = SSH_ERR_ALLOC_FAIL;
		برو out;
	}
	اگر ((r = kexc25519_shared_کلید_ext(kex->c25519_client_کلید, server_pub,
	    buf, 0)) < 0)
		برو out;
#ifdef DEBUG_KEXECDH
	dump_digest("encoded shared secret:", sshbuf_ptr(buf), sshbuf_len(buf));
#endif
	*shared_secretp = buf;
	buf = پوچ;
 out:
	sshbuf_free(buf);
	بازگشت r;
}
