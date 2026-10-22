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
	EC_کلید *client_کلید = عدم;
	ثابت EC_گروه *گروه;
	ثابت EC_نقطه *عمومی_کلید;
	بنية sshbuf *buf = عدم;
	صحيح r;

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

	إذا ((buf = sshbuf_new()) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب بیرون;
	}
	إذا ((r = sshbuf_put_ec(buf, عمومی_کلید, گروه)) != 0 ||
	    (r = sshbuf_get_u32(buf, عدم)) != 0)
		اذهب بیرون;
#اگر_تعریف_شده DEBUG_KEXECDH
	fputs("client private key:\n", stderr);
	sshkey_dump_ec_کلید(client_کلید);
#پایان_اگر
	kex->ec_client_کلید = client_کلید;
	kex->ec_گروه = گروه;
	client_کلید = عدم;	/* owned by the kex */
	kex->client_pub = buf;
	buf = عدم;
 بیرون:
	EC_کلید_free(client_کلید);
	sshbuf_free(buf);
	أرجع r;
}

صحيح
kex_ecdh_enc(بنية kex *kex, ثابت بنية sshbuf *client_blob,
    بنية sshbuf **server_blobp, بنية sshbuf **shared_secretp)
{
	ثابت EC_گروه *گروه;
	ثابت EC_نقطه *pub_کلید;
	EC_کلید *server_کلید = عدم;
	بنية sshbuf *server_blob = عدم;
	صحيح r;

	*server_blobp = عدم;
	*shared_secretp = عدم;

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
	fputs("server private key:\n", stderr);
	sshkey_dump_ec_کلید(server_کلید);
#پایان_اگر
	pub_کلید = EC_کلید_get0_عمومی_کلید(server_کلید);
	إذا ((server_blob = sshbuf_new()) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب بیرون;
	}
	إذا ((r = sshbuf_put_ec(server_blob, pub_کلید, گروه)) != 0 ||
	    (r = sshbuf_get_u32(server_blob, عدم)) != 0)
		اذهب بیرون;
	إذا ((r = kex_ecdh_dec_کلید_گروه(kex, client_blob, server_کلید, گروه,
	    0, shared_secretp)) != 0)
		اذهب بیرون;
	*server_blobp = server_blob;
	server_blob = عدم;
 بیرون:
	EC_کلید_free(server_کلید);
	sshbuf_free(server_blob);
	أرجع r;
}

صحيح
kex_ecdh_dec_کلید_گروه(بنية kex *kex, ثابت بنية sshbuf *ec_blob,
    EC_کلید *کلید, ثابت EC_گروه *گروه, صحيح raw, بنية sshbuf **shared_secretp)
{
	بنية sshbuf *buf = عدم;
	BIGNUM *shared_secret = عدم;
	EC_نقطه *dh_pub = عدم;
	u_char *kbuf = عدم;
	اندازه_t klen = 0;
	صحيح r;

	*shared_secretp = عدم;

	إذا ((buf = sshbuf_new()) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب بیرون;
	}
	إذا ((r = sshbuf_put_stringb(buf, ec_blob)) != 0)
		اذهب بیرون;
	إذا ((dh_pub = EC_نقطه_new(گروه)) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب بیرون;
	}
	إذا ((r = sshbuf_get_ec(buf, dh_pub, گروه)) != 0) {
		اذهب بیرون;
	}
	sshbuf_reset(buf);

#اگر_تعریف_شده DEBUG_KEXECDH
	fputs("public key:\n", stderr);
	sshkey_dump_ec_نقطه(گروه, dh_pub);
#پایان_اگر
	إذا (sshkey_ec_validate_عمومی(گروه, dh_pub) != 0) {
		r = SSH_ERR_پیام_INCOMPLETE;
		اذهب بیرون;
	}
	klen = (EC_گروه_get_degree(گروه) + 7) / 8;
	إذا ((kbuf = حافظه_بده(klen)) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب بیرون;
	}
	إذا (ECDH_compute_کلید(kbuf, klen, dh_pub, کلید, عدم) != (صحيح)klen) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		اذهب بیرون;
	}
#اگر_تعریف_شده DEBUG_KEXECDH
	dump_digest("shared secret", kbuf, klen);
#پایان_اگر
	إذا (raw) {
		إذا ((r = sshbuf_put(buf, kbuf, klen)) != 0)
			اذهب بیرون;
	} وإلا {
		إذا ((shared_secret = BN_new()) == عدم) {
			r = SSH_ERR_ALLOC_FAIL;
			اذهب بیرون;
		}
		إذا (BN_bin2bn(kbuf, klen, shared_secret) == عدم) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			اذهب بیرون;
		}
		إذا ((r = sshbuf_put_bignum2(buf, shared_secret)) != 0)
			اذهب بیرون;
	}
	*shared_secretp = buf;
	buf = عدم;
 بیرون:
	EC_نقطه_clear_free(dh_pub);
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

	r = kex_ecdh_dec_کلید_گروه(kex, server_blob, kex->ec_client_کلید,
	    kex->ec_گروه, 0, shared_secretp);
	EC_کلید_free(kex->ec_client_کلید);
	kex->ec_client_کلید = عدم;
	أرجع r;
}

#پایان_اگر /* WITH_OPENSSL */
