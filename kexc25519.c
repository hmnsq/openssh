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

#ضمن "includes.h"

#ضمن <sys/types.h>

#ضمن <stdio.h>
#ضمن <string.h>
#ضمن <signal.h>

#ضمن "sshkey.h"
#ضمن "kex.h"
#ضمن "sshbuf.h"
#ضمن "digest.h"
#ضمن "ssherr.h"
#ضمن "ssh2.h"

خارجي صحيح crypto_scalarmult_curve25519(u_char a[CURVE25519_اندازه],
    ثابت u_char b[CURVE25519_اندازه], ثابت u_char c[CURVE25519_اندازه])
	__attribute__((__bounded__(__minbytes__, 1, CURVE25519_اندازه)))
	__attribute__((__bounded__(__minbytes__, 2, CURVE25519_اندازه)))
	__attribute__((__bounded__(__minbytes__, 3, CURVE25519_اندازه)));

فراغ
kexc25519_keygen(u_char کلی[CURVE25519_اندازه], u_char pub[CURVE25519_اندازه])
{
	ساكن ثابت u_char basepoint[CURVE25519_اندازه] = {9};

	arc4random_buf(کلی, CURVE25519_اندازه);
	crypto_scalarmult_curve25519(pub, کلی, basepoint);
}

صحيح
kexc25519_shared_کلی_ext(ثابت u_char کلی[CURVE25519_اندازه],
    ثابت u_char pub[CURVE25519_اندازه], بنية sshbuf *بهر, صحيح raw)
{
	u_char shared_کلی[CURVE25519_اندازه];
	u_char zero[CURVE25519_اندازه];
	صحيح r;

	crypto_scalarmult_curve25519(shared_کلی, کلی, pub);

	/* Check for all-zero shared secret */
	explicit_bzero(zero, CURVE25519_اندازه);
	إذا (timingsafe_bcmp(zero, shared_کلی, CURVE25519_اندازه) == 0)
		أرجع SSH_ERR_کلی_INVALID_EC_ارزښت;

#که_تعریف_شوی DEBUG_KEXECDH
	dump_digest("shared secret 25519", shared_کلی, CURVE25519_اندازه);
#د_که_پای
	إذا (raw)
		r = sshbuf_put(بهر, shared_کلی, CURVE25519_اندازه);
	وإلا
		r = sshbuf_put_bignum2_بایټونه(بهر, shared_کلی, CURVE25519_اندازه);
	explicit_bzero(shared_کلی, CURVE25519_اندازه);
	أرجع r;
}

صحيح
kexc25519_shared_کلی(ثابت u_char کلی[CURVE25519_اندازه],
    ثابت u_char pub[CURVE25519_اندازه], بنية sshbuf *بهر)
{
	أرجع kexc25519_shared_کلی_ext(کلی, pub, بهر, 0);
}

صحيح
kex_c25519_keypair(بنية kex *kex)
{
	بنية sshbuf *buf = عدم;
	u_char *cp = عدم;
	صحيح r;

	إذا ((buf = sshbuf_new()) == عدم)
		أرجع SSH_ERR_ALLOC_FAIL;
	إذا ((r = sshbuf_reserve(buf, CURVE25519_اندازه, &cp)) != 0)
		اذهب بهر;
	kexc25519_keygen(kex->c25519_client_کلی, cp);
#که_تعریف_شوی DEBUG_KEXECDH
	dump_digest("client public key c25519:", cp, CURVE25519_اندازه);
#د_که_پای
	kex->client_pub = buf;
	buf = عدم;
 بهر:
	sshbuf_free(buf);
	أرجع r;
}

صحيح
kex_c25519_enc(بنية kex *kex, ثابت بنية sshbuf *client_blob,
   بنية sshbuf **server_blobp, بنية sshbuf **shared_secretp)
{
	بنية sshbuf *server_blob = عدم;
	بنية sshbuf *buf = عدم;
	ثابت u_char *client_pub;
	u_char *server_pub;
	u_char server_کلی[CURVE25519_اندازه];
	صحيح r;

	*server_blobp = عدم;
	*shared_secretp = عدم;

	إذا (sshbuf_len(client_blob) != CURVE25519_اندازه) {
		r = SSH_ERR_SIGNATURE_INVALID;
		اذهب بهر;
	}
	client_pub = sshbuf_ptr(client_blob);
#که_تعریف_شوی DEBUG_KEXECDH
	dump_digest("client public key 25519:", client_pub, CURVE25519_اندازه);
#د_که_پای
	/* allocate space for encrypted KEM key and ECDH pub key */
	إذا ((server_blob = sshbuf_new()) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب بهر;
	}
	إذا ((r = sshbuf_reserve(server_blob, CURVE25519_اندازه, &server_pub)) != 0)
		اذهب بهر;
	kexc25519_keygen(server_کلی, server_pub);
	/* allocate shared secret */
	إذا ((buf = sshbuf_new()) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب بهر;
	}
	إذا ((r = kexc25519_shared_کلی_ext(server_کلی, client_pub, buf, 0)) < 0)
		اذهب بهر;
#که_تعریف_شوی DEBUG_KEXECDH
	dump_digest("server public key 25519:", server_pub, CURVE25519_اندازه);
	dump_digest("encoded shared secret:", sshbuf_ptr(buf), sshbuf_len(buf));
#د_که_پای
	*server_blobp = server_blob;
	*shared_secretp = buf;
	server_blob = عدم;
	buf = عدم;
 بهر:
	explicit_bzero(server_کلی, حجم(server_کلی));
	sshbuf_free(server_blob);
	sshbuf_free(buf);
	أرجع r;
}

صحيح
kex_c25519_dec(بنية kex *kex, ثابت بنية sshbuf *server_blob,
    بنية sshbuf **shared_secretp)
{
	بنية sshbuf *buf = عدم;
	ثابت u_char *server_pub;
	صحيح r;

	*shared_secretp = عدم;

	إذا (sshbuf_len(server_blob) != CURVE25519_اندازه) {
		r = SSH_ERR_SIGNATURE_INVALID;
		اذهب بهر;
	}
	server_pub = sshbuf_ptr(server_blob);
#که_تعریف_شوی DEBUG_KEXECDH
	dump_digest("server public key c25519:", server_pub, CURVE25519_اندازه);
#د_که_پای
	/* shared secret */
	إذا ((buf = sshbuf_new()) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب بهر;
	}
	إذا ((r = kexc25519_shared_کلی_ext(kex->c25519_client_کلی, server_pub,
	    buf, 0)) < 0)
		اذهب بهر;
#که_تعریف_شوی DEBUG_KEXECDH
	dump_digest("encoded shared secret:", sshbuf_ptr(buf), sshbuf_len(buf));
#د_که_پای
	*shared_secretp = buf;
	buf = عدم;
 بهر:
	sshbuf_free(buf);
	أرجع r;
}
