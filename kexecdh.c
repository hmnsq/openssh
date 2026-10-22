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
	EC_ڪنجي *client_ڪنجي = عدم;
	ثابت EC_گروهه *گروهه;
	ثابت EC_نقطو *عوامي_ڪنجي;
	بنية sshbuf *buf = عدم;
	صحيح r;

	إذا ((client_ڪنجي = EC_ڪنجي_new_by_وڪر_name(kex->ec_nid)) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب ٻاهريون;
	}
	إذا (EC_ڪنجي_generate_ڪنجي(client_ڪنجي) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		اذهب ٻاهريون;
	}
	گروهه = EC_ڪنجي_get0_گروهه(client_ڪنجي);
	عوامي_ڪنجي = EC_ڪنجي_get0_عوامي_ڪنجي(client_ڪنجي);

	إذا ((buf = sshbuf_new()) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب ٻاهريون;
	}
	إذا ((r = sshbuf_put_ec(buf, عوامي_ڪنجي, گروهه)) != 0 ||
	    (r = sshbuf_get_u32(buf, عدم)) != 0)
		اذهب ٻاهريون;
#جيڪڏهن_وصف_ٿيل DEBUG_KEXECDH
	fputs("client private key:\n", stderr);
	sshkey_dump_ec_ڪنجي(client_ڪنجي);
#جيڪڏهن_پورو
	kex->ec_client_ڪنجي = client_ڪنجي;
	kex->ec_گروهه = گروهه;
	client_ڪنجي = عدم;	/* owned by the kex */
	kex->client_pub = buf;
	buf = عدم;
 ٻاهريون:
	EC_ڪنجي_free(client_ڪنجي);
	sshbuf_free(buf);
	أرجع r;
}

صحيح
kex_ecdh_enc(بنية kex *kex, ثابت بنية sshbuf *client_blob,
    بنية sshbuf **server_blobp, بنية sshbuf **shared_secretp)
{
	ثابت EC_گروهه *گروهه;
	ثابت EC_نقطو *pub_ڪنجي;
	EC_ڪنجي *server_ڪنجي = عدم;
	بنية sshbuf *server_blob = عدم;
	صحيح r;

	*server_blobp = عدم;
	*shared_secretp = عدم;

	إذا ((server_ڪنجي = EC_ڪنجي_new_by_وڪر_name(kex->ec_nid)) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب ٻاهريون;
	}
	إذا (EC_ڪنجي_generate_ڪنجي(server_ڪنجي) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		اذهب ٻاهريون;
	}
	گروهه = EC_ڪنجي_get0_گروهه(server_ڪنجي);

#جيڪڏهن_وصف_ٿيل DEBUG_KEXECDH
	fputs("server private key:\n", stderr);
	sshkey_dump_ec_ڪنجي(server_ڪنجي);
#جيڪڏهن_پورو
	pub_ڪنجي = EC_ڪنجي_get0_عوامي_ڪنجي(server_ڪنجي);
	إذا ((server_blob = sshbuf_new()) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب ٻاهريون;
	}
	إذا ((r = sshbuf_put_ec(server_blob, pub_ڪنجي, گروهه)) != 0 ||
	    (r = sshbuf_get_u32(server_blob, عدم)) != 0)
		اذهب ٻاهريون;
	إذا ((r = kex_ecdh_dec_ڪنجي_گروهه(kex, client_blob, server_ڪنجي, گروهه,
	    0, shared_secretp)) != 0)
		اذهب ٻاهريون;
	*server_blobp = server_blob;
	server_blob = عدم;
 ٻاهريون:
	EC_ڪنجي_free(server_ڪنجي);
	sshbuf_free(server_blob);
	أرجع r;
}

صحيح
kex_ecdh_dec_ڪنجي_گروهه(بنية kex *kex, ثابت بنية sshbuf *ec_blob,
    EC_ڪنجي *ڪنجي, ثابت EC_گروهه *گروهه, صحيح raw, بنية sshbuf **shared_secretp)
{
	بنية sshbuf *buf = عدم;
	BIGNUM *shared_secret = عدم;
	EC_نقطو *dh_pub = عدم;
	u_char *kbuf = عدم;
	سائيز_t klen = 0;
	صحيح r;

	*shared_secretp = عدم;

	إذا ((buf = sshbuf_new()) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب ٻاهريون;
	}
	إذا ((r = sshbuf_put_stringb(buf, ec_blob)) != 0)
		اذهب ٻاهريون;
	إذا ((dh_pub = EC_نقطو_new(گروهه)) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب ٻاهريون;
	}
	إذا ((r = sshbuf_get_ec(buf, dh_pub, گروهه)) != 0) {
		اذهب ٻاهريون;
	}
	sshbuf_reset(buf);

#جيڪڏهن_وصف_ٿيل DEBUG_KEXECDH
	fputs("public key:\n", stderr);
	sshkey_dump_ec_نقطو(گروهه, dh_pub);
#جيڪڏهن_پورو
	إذا (sshkey_ec_validate_عوامي(گروهه, dh_pub) != 0) {
		r = SSH_ERR_پيغام_INCOMPLETE;
		اذهب ٻاهريون;
	}
	klen = (EC_گروهه_get_degree(گروهه) + 7) / 8;
	إذا ((kbuf = يادگيري_ڏيو(klen)) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب ٻاهريون;
	}
	إذا (ECDH_compute_ڪنجي(kbuf, klen, dh_pub, ڪنجي, عدم) != (صحيح)klen) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		اذهب ٻاهريون;
	}
#جيڪڏهن_وصف_ٿيل DEBUG_KEXECDH
	dump_digest("shared secret", kbuf, klen);
#جيڪڏهن_پورو
	إذا (raw) {
		إذا ((r = sshbuf_put(buf, kbuf, klen)) != 0)
			اذهب ٻاهريون;
	} وإلا {
		إذا ((shared_secret = BN_new()) == عدم) {
			r = SSH_ERR_ALLOC_FAIL;
			اذهب ٻاهريون;
		}
		إذا (BN_bin2bn(kbuf, klen, shared_secret) == عدم) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			اذهب ٻاهريون;
		}
		إذا ((r = sshbuf_put_bignum2(buf, shared_secret)) != 0)
			اذهب ٻاهريون;
	}
	*shared_secretp = buf;
	buf = عدم;
 ٻاهريون:
	EC_نقطو_clear_free(dh_pub);
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

	r = kex_ecdh_dec_ڪنجي_گروهه(kex, server_blob, kex->ec_client_ڪنجي,
	    kex->ec_گروهه, 0, shared_secretp);
	EC_ڪنجي_free(kex->ec_client_ڪنجي);
	kex->ec_client_ڪنجي = عدم;
	أرجع r;
}

#جيڪڏهن_پورو /* WITH_OPENSSL */
