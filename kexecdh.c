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
kex_ecdh_keypair(ساختار kex *kex)
{
	EC_کلید *client_کلید = پوچ;
	ثابت EC_GROUP *group;
	ثابت EC_POINT *public_کلید;
	ساختار sshbuf *buf = پوچ;
	صحیح r;

	اگر ((client_کلید = EC_کلید_new_by_curve_name(kex->ec_nid)) == پوچ) {
		r = SSH_ERR_ALLOC_FAIL;
		برو out;
	}
	اگر (EC_کلید_generate_کلید(client_کلید) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		برو out;
	}
	group = EC_کلید_get0_group(client_کلید);
	public_کلید = EC_کلید_get0_public_کلید(client_کلید);

	اگر ((buf = sshbuf_new()) == پوچ) {
		r = SSH_ERR_ALLOC_FAIL;
		برو out;
	}
	اگر ((r = sshbuf_put_ec(buf, public_کلید, group)) != 0 ||
	    (r = sshbuf_get_u32(buf, پوچ)) != 0)
		برو out;
#ifdef DEBUG_KEXECDH
	fputs("client private key:\n", stderr);
	sshkey_dump_ec_کلید(client_کلید);
#endif
	kex->ec_client_کلید = client_کلید;
	kex->ec_group = group;
	client_کلید = پوچ;	/* owned by the kex */
	kex->client_pub = buf;
	buf = پوچ;
 out:
	EC_کلید_free(client_کلید);
	sshbuf_free(buf);
	بازگشت r;
}

صحیح
kex_ecdh_enc(ساختار kex *kex, ثابت ساختار sshbuf *client_blob,
    ساختار sshbuf **server_blobp, ساختار sshbuf **shared_secretp)
{
	ثابت EC_GROUP *group;
	ثابت EC_POINT *pub_کلید;
	EC_کلید *server_کلید = پوچ;
	ساختار sshbuf *server_blob = پوچ;
	صحیح r;

	*server_blobp = پوچ;
	*shared_secretp = پوچ;

	اگر ((server_کلید = EC_کلید_new_by_curve_name(kex->ec_nid)) == پوچ) {
		r = SSH_ERR_ALLOC_FAIL;
		برو out;
	}
	اگر (EC_کلید_generate_کلید(server_کلید) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		برو out;
	}
	group = EC_کلید_get0_group(server_کلید);

#ifdef DEBUG_KEXECDH
	fputs("server private key:\n", stderr);
	sshkey_dump_ec_کلید(server_کلید);
#endif
	pub_کلید = EC_کلید_get0_public_کلید(server_کلید);
	اگر ((server_blob = sshbuf_new()) == پوچ) {
		r = SSH_ERR_ALLOC_FAIL;
		برو out;
	}
	اگر ((r = sshbuf_put_ec(server_blob, pub_کلید, group)) != 0 ||
	    (r = sshbuf_get_u32(server_blob, پوچ)) != 0)
		برو out;
	اگر ((r = kex_ecdh_dec_کلید_group(kex, client_blob, server_کلید, group,
	    0, shared_secretp)) != 0)
		برو out;
	*server_blobp = server_blob;
	server_blob = پوچ;
 out:
	EC_کلید_free(server_کلید);
	sshbuf_free(server_blob);
	بازگشت r;
}

صحیح
kex_ecdh_dec_کلید_group(ساختار kex *kex, ثابت ساختار sshbuf *ec_blob,
    EC_کلید *کلید, ثابت EC_GROUP *group, صحیح raw, ساختار sshbuf **shared_secretp)
{
	ساختار sshbuf *buf = پوچ;
	BIGNUM *shared_secret = پوچ;
	EC_POINT *dh_pub = پوچ;
	u_char *kbuf = پوچ;
	size_t klen = 0;
	صحیح r;

	*shared_secretp = پوچ;

	اگر ((buf = sshbuf_new()) == پوچ) {
		r = SSH_ERR_ALLOC_FAIL;
		برو out;
	}
	اگر ((r = sshbuf_put_stringb(buf, ec_blob)) != 0)
		برو out;
	اگر ((dh_pub = EC_POINT_new(group)) == پوچ) {
		r = SSH_ERR_ALLOC_FAIL;
		برو out;
	}
	اگر ((r = sshbuf_get_ec(buf, dh_pub, group)) != 0) {
		برو out;
	}
	sshbuf_reset(buf);

#ifdef DEBUG_KEXECDH
	fputs("public key:\n", stderr);
	sshkey_dump_ec_point(group, dh_pub);
#endif
	اگر (sshkey_ec_validate_public(group, dh_pub) != 0) {
		r = SSH_ERR_MESSAGE_INCOMPLETE;
		برو out;
	}
	klen = (EC_GROUP_get_degree(group) + 7) / 8;
	اگر ((kbuf = malloc(klen)) == پوچ) {
		r = SSH_ERR_ALLOC_FAIL;
		برو out;
	}
	اگر (ECDH_compute_کلید(kbuf, klen, dh_pub, کلید, پوچ) != (صحیح)klen) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		برو out;
	}
#ifdef DEBUG_KEXECDH
	dump_digest("shared secret", kbuf, klen);
#endif
	اگر (raw) {
		اگر ((r = sshbuf_put(buf, kbuf, klen)) != 0)
			برو out;
	} وگرنه {
		اگر ((shared_secret = BN_new()) == پوچ) {
			r = SSH_ERR_ALLOC_FAIL;
			برو out;
		}
		اگر (BN_bin2bn(kbuf, klen, shared_secret) == پوچ) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			برو out;
		}
		اگر ((r = sshbuf_put_bignum2(buf, shared_secret)) != 0)
			برو out;
	}
	*shared_secretp = buf;
	buf = پوچ;
 out:
	EC_POINT_clear_free(dh_pub);
	BN_clear_free(shared_secret);
	freezero(kbuf, klen);
	sshbuf_free(buf);
	بازگشت r;
}

صحیح
kex_ecdh_dec(ساختار kex *kex, ثابت ساختار sshbuf *server_blob,
    ساختار sshbuf **shared_secretp)
{
	صحیح r;

	r = kex_ecdh_dec_کلید_group(kex, server_blob, kex->ec_client_کلید,
	    kex->ec_group, 0, shared_secretp);
	EC_کلید_free(kex->ec_client_کلید);
	kex->ec_client_کلید = پوچ;
	بازگشت r;
}

#endif /* WITH_OPENSSL */
