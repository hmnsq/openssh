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
	EC_کلیل *client_کلیل = عدم;
	ثابت EC_GROUP *group;
	ثابت EC_POINT *public_کلیل;
	بنية sshbuf *buf = عدم;
	صحيح r;

	إذا ((client_کلیل = EC_کلیل_new_by_curve_name(kex->ec_nid)) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب out;
	}
	إذا (EC_کلیل_generate_کلیل(client_کلیل) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		اذهب out;
	}
	group = EC_کلیل_get0_group(client_کلیل);
	public_کلیل = EC_کلیل_get0_public_کلیل(client_کلیل);

	إذا ((buf = sshbuf_new()) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب out;
	}
	إذا ((r = sshbuf_put_ec(buf, public_کلیل, group)) != 0 ||
	    (r = sshbuf_get_u32(buf, عدم)) != 0)
		اذهب out;
#ifdef DEBUG_KEXECDH
	fputs("client private key:\n", stderr);
	sshkey_dump_ec_کلیل(client_کلیل);
#endif
	kex->ec_client_کلیل = client_کلیل;
	kex->ec_group = group;
	client_کلیل = عدم;	/* owned by the kex */
	kex->client_pub = buf;
	buf = عدم;
 out:
	EC_کلیل_free(client_کلیل);
	sshbuf_free(buf);
	أرجع r;
}

صحيح
kex_ecdh_enc(بنية kex *kex, ثابت بنية sshbuf *client_blob,
    بنية sshbuf **server_blobp, بنية sshbuf **shared_secretp)
{
	ثابت EC_GROUP *group;
	ثابت EC_POINT *pub_کلیل;
	EC_کلیل *server_کلیل = عدم;
	بنية sshbuf *server_blob = عدم;
	صحيح r;

	*server_blobp = عدم;
	*shared_secretp = عدم;

	إذا ((server_کلیل = EC_کلیل_new_by_curve_name(kex->ec_nid)) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب out;
	}
	إذا (EC_کلیل_generate_کلیل(server_کلیل) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		اذهب out;
	}
	group = EC_کلیل_get0_group(server_کلیل);

#ifdef DEBUG_KEXECDH
	fputs("server private key:\n", stderr);
	sshkey_dump_ec_کلیل(server_کلیل);
#endif
	pub_کلیل = EC_کلیل_get0_public_کلیل(server_کلیل);
	إذا ((server_blob = sshbuf_new()) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب out;
	}
	إذا ((r = sshbuf_put_ec(server_blob, pub_کلیل, group)) != 0 ||
	    (r = sshbuf_get_u32(server_blob, عدم)) != 0)
		اذهب out;
	إذا ((r = kex_ecdh_dec_کلیل_group(kex, client_blob, server_کلیل, group,
	    0, shared_secretp)) != 0)
		اذهب out;
	*server_blobp = server_blob;
	server_blob = عدم;
 out:
	EC_کلیل_free(server_کلیل);
	sshbuf_free(server_blob);
	أرجع r;
}

صحيح
kex_ecdh_dec_کلیل_group(بنية kex *kex, ثابت بنية sshbuf *ec_blob,
    EC_کلیل *کلیل, ثابت EC_GROUP *group, صحيح raw, بنية sshbuf **shared_secretp)
{
	بنية sshbuf *buf = عدم;
	BIGNUM *shared_secret = عدم;
	EC_POINT *dh_pub = عدم;
	u_char *kbuf = عدم;
	size_t klen = 0;
	صحيح r;

	*shared_secretp = عدم;

	إذا ((buf = sshbuf_new()) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب out;
	}
	إذا ((r = sshbuf_put_stringb(buf, ec_blob)) != 0)
		اذهب out;
	إذا ((dh_pub = EC_POINT_new(group)) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب out;
	}
	إذا ((r = sshbuf_get_ec(buf, dh_pub, group)) != 0) {
		اذهب out;
	}
	sshbuf_reset(buf);

#ifdef DEBUG_KEXECDH
	fputs("public key:\n", stderr);
	sshkey_dump_ec_point(group, dh_pub);
#endif
	إذا (sshkey_ec_validate_public(group, dh_pub) != 0) {
		r = SSH_ERR_MESSAGE_INCOMPLETE;
		اذهب out;
	}
	klen = (EC_GROUP_get_degree(group) + 7) / 8;
	إذا ((kbuf = malloc(klen)) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب out;
	}
	إذا (ECDH_compute_کلیل(kbuf, klen, dh_pub, کلیل, عدم) != (صحيح)klen) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		اذهب out;
	}
#ifdef DEBUG_KEXECDH
	dump_digest("shared secret", kbuf, klen);
#endif
	إذا (raw) {
		إذا ((r = sshbuf_put(buf, kbuf, klen)) != 0)
			اذهب out;
	} وإلا {
		إذا ((shared_secret = BN_new()) == عدم) {
			r = SSH_ERR_ALLOC_FAIL;
			اذهب out;
		}
		إذا (BN_bin2bn(kbuf, klen, shared_secret) == عدم) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			اذهب out;
		}
		إذا ((r = sshbuf_put_bignum2(buf, shared_secret)) != 0)
			اذهب out;
	}
	*shared_secretp = buf;
	buf = عدم;
 out:
	EC_POINT_clear_free(dh_pub);
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

	r = kex_ecdh_dec_کلیل_group(kex, server_blob, kex->ec_client_کلیل,
	    kex->ec_group, 0, shared_secretp);
	EC_کلیل_free(kex->ec_client_کلیل);
	kex->ec_client_کلیل = عدم;
	أرجع r;
}

#endif /* WITH_OPENSSL */
