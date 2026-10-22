/* $OpenBSD: kexecdh.c,v 1.14 2026/08/03 06:43:16 djm Exp $ */
/*
 * Copyright (c) 2010 Damien Miller.  All rights reserved.
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

#ضمن "includes.h"

#إذا defined(WITH_OPENSSL)

#ضمن <sys/types.h>

#ضمن <stdio.h>
#ضمن <signal.h>

#ضمن <openssl/bn.h>
#ضمن <openssl/ecdh.h>

#ضمن "sshkey.h"
#ضمن "kex.h"
#ضمن "sshbuf.h"
#ضمن "ssherr.h"

صحيح
kex_ecdh_keypair(بنية kex *kex)
{
	EC_کلی *client_کلی = عدم;
	ثابت EC_ډله *ډله;
	ثابت EC_ټکی *عامه_کلی;
	بنية sshbuf *buf = عدم;
	صحيح r;

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

	إذا ((buf = sshbuf_new()) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب بهر;
	}
	إذا ((r = sshbuf_put_ec(buf, عامه_کلی, ډله)) != 0 ||
	    (r = sshbuf_get_u32(buf, عدم)) != 0)
		اذهب بهر;
#که_تعریف_شوی DEBUG_KEXECDH
	fputs("client private key:\n", stderr);
	sshkey_dump_ec_کلی(client_کلی);
#د_که_پای
	kex->ec_client_کلی = client_کلی;
	kex->ec_ډله = ډله;
	client_کلی = عدم;	/* owned by the kex */
	kex->client_pub = buf;
	buf = عدم;
 بهر:
	EC_کلی_free(client_کلی);
	sshbuf_free(buf);
	أرجع r;
}

صحيح
kex_ecdh_enc(بنية kex *kex, ثابت بنية sshbuf *client_blob,
    بنية sshbuf **server_blobp, بنية sshbuf **shared_secretp)
{
	ثابت EC_ډله *ډله;
	ثابت EC_ټکی *pub_کلی;
	EC_کلی *server_کلی = عدم;
	بنية sshbuf *server_blob = عدم;
	صحيح r;

	*server_blobp = عدم;
	*shared_secretp = عدم;

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
	fputs("server private key:\n", stderr);
	sshkey_dump_ec_کلی(server_کلی);
#د_که_پای
	pub_کلی = EC_کلی_get0_عامه_کلی(server_کلی);
	إذا ((server_blob = sshbuf_new()) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب بهر;
	}
	إذا ((r = sshbuf_put_ec(server_blob, pub_کلی, ډله)) != 0 ||
	    (r = sshbuf_get_u32(server_blob, عدم)) != 0)
		اذهب بهر;
	إذا ((r = kex_ecdh_dec_کلی_ډله(kex, client_blob, server_کلی, ډله,
	    0, shared_secretp)) != 0)
		اذهب بهر;
	*server_blobp = server_blob;
	server_blob = عدم;
 بهر:
	EC_کلی_free(server_کلی);
	sshbuf_free(server_blob);
	أرجع r;
}

صحيح
kex_ecdh_dec_کلی_ډله(بنية kex *kex, ثابت بنية sshbuf *ec_blob,
    EC_کلی *کلی, ثابت EC_ډله *ډله, صحيح raw, بنية sshbuf **shared_secretp)
{
	بنية sshbuf *buf = عدم;
	BIGNUM *shared_secret = عدم;
	EC_ټکی *dh_pub = عدم;
	u_char *kbuf = عدم;
	اندازه_t klen = 0;
	صحيح r;

	*shared_secretp = عدم;

	إذا ((buf = sshbuf_new()) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب بهر;
	}
	إذا ((r = sshbuf_put_stringb(buf, ec_blob)) != 0)
		اذهب بهر;
	إذا ((dh_pub = EC_ټکی_new(ډله)) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب بهر;
	}
	إذا ((r = sshbuf_get_ec(buf, dh_pub, ډله)) != 0) {
		اذهب بهر;
	}
	sshbuf_reset(buf);

#که_تعریف_شوی DEBUG_KEXECDH
	fputs("public key:\n", stderr);
	sshkey_dump_ec_ټکی(ډله, dh_pub);
#د_که_پای
	إذا (sshkey_ec_validate_عامه(ډله, dh_pub) != 0) {
		r = SSH_ERR_پیغام_INCOMPLETE;
		اذهب بهر;
	}
	klen = (EC_ډله_get_degree(ډله) + 7) / 8;
	إذا ((kbuf = حافظه_ورکړه(klen)) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب بهر;
	}
	إذا (ECDH_compute_کلی(kbuf, klen, dh_pub, کلی, عدم) != (صحيح)klen) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		اذهب بهر;
	}
#که_تعریف_شوی DEBUG_KEXECDH
	dump_digest("shared secret", kbuf, klen);
#د_که_پای
	إذا (raw) {
		إذا ((r = sshbuf_put(buf, kbuf, klen)) != 0)
			اذهب بهر;
	} وإلا {
		إذا ((shared_secret = BN_new()) == عدم) {
			r = SSH_ERR_ALLOC_FAIL;
			اذهب بهر;
		}
		إذا (BN_bin2bn(kbuf, klen, shared_secret) == عدم) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			اذهب بهر;
		}
		إذا ((r = sshbuf_put_bignum2(buf, shared_secret)) != 0)
			اذهب بهر;
	}
	*shared_secretp = buf;
	buf = عدم;
 بهر:
	EC_ټکی_clear_free(dh_pub);
	BN_clear_free(shared_secret);
	freezero(kbuf, klen);
	sshbuf_free(buf);
	أرجع r;
}

صحيح
kex_ecdh_dec(بنية kex *kex, ثابت بنية sshbuf *server_blob,
    بنية sshbuf **shared_secretp)
{
	صحيح r;

	r = kex_ecdh_dec_کلی_ډله(kex, server_blob, kex->ec_client_کلی,
	    kex->ec_ډله, 0, shared_secretp);
	EC_کلی_free(kex->ec_client_کلی);
	kex->ec_client_کلی = عدم;
	أرجع r;
}

#د_که_پای /* WITH_OPENSSL */
