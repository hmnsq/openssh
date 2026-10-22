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

#شامل "includes.h"

#اگر defined(WITH_OPENSSL)

#شامل <sys/types.h>

#شامل <stdio.h>
#شامل <signal.h>

#شامل <openssl/bn.h>
#شامل <openssl/ecdh.h>

#شامل "sshkey.h"
#شامل "kex.h"
#شامل "sshbuf.h"
#شامل "ssherr.h"

صحیح
kex_ecdh_keypair(ساخت kex *kex)
{
	EC_کلید *client_کلید = تہی;
	ثابت EC_گروہ *گروہ;
	ثابت EC_نقطہ *عوامی_کلید;
	ساخت sshbuf *buf = تہی;
	صحیح r;

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

	اگر ((buf = sshbuf_new()) == تہی) {
		r = SSH_ERR_ALLOC_FAIL;
		جاؤ برآمد;
	}
	اگر ((r = sshbuf_put_ec(buf, عوامی_کلید, گروہ)) != 0 ||
	    (r = sshbuf_get_u32(buf, تہی)) != 0)
		جاؤ برآمد;
#اگر_تعریف_شدہ DEBUG_KEXECDH
	fputs("client private key:\n", stderr);
	sshkey_dump_ec_کلید(client_کلید);
#اگر_ختم
	kex->ec_client_کلید = client_کلید;
	kex->ec_گروہ = گروہ;
	client_کلید = تہی;	/* owned by the kex */
	kex->client_pub = buf;
	buf = تہی;
 برآمد:
	EC_کلید_free(client_کلید);
	sshbuf_free(buf);
	واپس r;
}

صحیح
kex_ecdh_enc(ساخت kex *kex, ثابت ساخت sshbuf *client_blob,
    ساخت sshbuf **server_blobp, ساخت sshbuf **shared_secretp)
{
	ثابت EC_گروہ *گروہ;
	ثابت EC_نقطہ *pub_کلید;
	EC_کلید *server_کلید = تہی;
	ساخت sshbuf *server_blob = تہی;
	صحیح r;

	*server_blobp = تہی;
	*shared_secretp = تہی;

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
	fputs("server private key:\n", stderr);
	sshkey_dump_ec_کلید(server_کلید);
#اگر_ختم
	pub_کلید = EC_کلید_get0_عوامی_کلید(server_کلید);
	اگر ((server_blob = sshbuf_new()) == تہی) {
		r = SSH_ERR_ALLOC_FAIL;
		جاؤ برآمد;
	}
	اگر ((r = sshbuf_put_ec(server_blob, pub_کلید, گروہ)) != 0 ||
	    (r = sshbuf_get_u32(server_blob, تہی)) != 0)
		جاؤ برآمد;
	اگر ((r = kex_ecdh_dec_کلید_گروہ(kex, client_blob, server_کلید, گروہ,
	    0, shared_secretp)) != 0)
		جاؤ برآمد;
	*server_blobp = server_blob;
	server_blob = تہی;
 برآمد:
	EC_کلید_free(server_کلید);
	sshbuf_free(server_blob);
	واپس r;
}

صحیح
kex_ecdh_dec_کلید_گروہ(ساخت kex *kex, ثابت ساخت sshbuf *ec_blob,
    EC_کلید *کلید, ثابت EC_گروہ *گروہ, صحیح raw, ساخت sshbuf **shared_secretp)
{
	ساخت sshbuf *buf = تہی;
	BIGNUM *shared_secret = تہی;
	EC_نقطہ *dh_pub = تہی;
	u_char *kbuf = تہی;
	سائز_t klen = 0;
	صحیح r;

	*shared_secretp = تہی;

	اگر ((buf = sshbuf_new()) == تہی) {
		r = SSH_ERR_ALLOC_FAIL;
		جاؤ برآمد;
	}
	اگر ((r = sshbuf_put_stringb(buf, ec_blob)) != 0)
		جاؤ برآمد;
	اگر ((dh_pub = EC_نقطہ_new(گروہ)) == تہی) {
		r = SSH_ERR_ALLOC_FAIL;
		جاؤ برآمد;
	}
	اگر ((r = sshbuf_get_ec(buf, dh_pub, گروہ)) != 0) {
		جاؤ برآمد;
	}
	sshbuf_reset(buf);

#اگر_تعریف_شدہ DEBUG_KEXECDH
	fputs("public key:\n", stderr);
	sshkey_dump_ec_نقطہ(گروہ, dh_pub);
#اگر_ختم
	اگر (sshkey_ec_validate_عوامی(گروہ, dh_pub) != 0) {
		r = SSH_ERR_پیغام_INCOMPLETE;
		جاؤ برآمد;
	}
	klen = (EC_گروہ_get_degree(گروہ) + 7) / 8;
	اگر ((kbuf = حافظہ_دو(klen)) == تہی) {
		r = SSH_ERR_ALLOC_FAIL;
		جاؤ برآمد;
	}
	اگر (ECDH_compute_کلید(kbuf, klen, dh_pub, کلید, تہی) != (صحیح)klen) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		جاؤ برآمد;
	}
#اگر_تعریف_شدہ DEBUG_KEXECDH
	dump_digest("shared secret", kbuf, klen);
#اگر_ختم
	اگر (raw) {
		اگر ((r = sshbuf_put(buf, kbuf, klen)) != 0)
			جاؤ برآمد;
	} ورنہ {
		اگر ((shared_secret = BN_new()) == تہی) {
			r = SSH_ERR_ALLOC_FAIL;
			جاؤ برآمد;
		}
		اگر (BN_bin2bn(kbuf, klen, shared_secret) == تہی) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			جاؤ برآمد;
		}
		اگر ((r = sshbuf_put_bignum2(buf, shared_secret)) != 0)
			جاؤ برآمد;
	}
	*shared_secretp = buf;
	buf = تہی;
 برآمد:
	EC_نقطہ_clear_free(dh_pub);
	BN_clear_free(shared_secret);
	freezero(kbuf, klen);
	sshbuf_free(buf);
	واپس r;
}

صحیح
kex_ecdh_dec(ساخت kex *kex, ثابت ساخت sshbuf *server_blob,
    ساخت sshbuf **shared_secretp)
{
	صحیح r;

	r = kex_ecdh_dec_کلید_گروہ(kex, server_blob, kex->ec_client_کلید,
	    kex->ec_گروہ, 0, shared_secretp);
	EC_کلید_free(kex->ec_client_کلید);
	kex->ec_client_کلید = تہی;
	واپس r;
}

#اگر_ختم /* WITH_OPENSSL */
