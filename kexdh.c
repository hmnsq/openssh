/* $OpenBSD: kexdh.c,v 1.36 2026/02/14 00:18:34 jsg Exp $ */
/*
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

#اگر_تعریف_شده WITH_OPENSSL
#ضمن "openbsd-compat/openssl-compat.h"

#ضمن <sys/types.h>

#ضمن <stdio.h>
#ضمن <signal.h>

#ضمن <openssl/bn.h>
#ضمن <openssl/dh.h>

#ضمن "kex.h"
#ضمن "sshbuf.h"
#ضمن "ssherr.h"
#ضمن "dh.h"
#ضمن "log.h"

صحيح
kex_dh_keygen(بنية kex *kex)
{
	بدل (kex->kex_type) {
	حالة KEX_DH_GRP1_SHA1:
		kex->dh = dh_new_group1();
		اكسر;
	حالة KEX_DH_GRP14_SHA1:
	حالة KEX_DH_GRP14_SHA256:
		kex->dh = dh_new_group14();
		اكسر;
	حالة KEX_DH_GRP16_SHA512:
		kex->dh = dh_new_group16();
		اكسر;
	حالة KEX_DH_GRP18_SHA512:
		kex->dh = dh_new_group18();
		اكسر;
	افتراضي:
		أرجع SSH_ERR_INVALID_آرگومان;
	}
	إذا (kex->dh == عدم)
		أرجع SSH_ERR_ALLOC_FAIL;
	أرجع (dh_gen_کلید(kex->dh, kex->we_need * 8));
}

صحيح
kex_dh_compute_کلید(بنية kex *kex, BIGNUM *dh_pub, بنية sshbuf *بیرون)
{
	BIGNUM *shared_secret = عدم;
	u_char *kbuf = عدم;
	اندازه_t klen = 0;
	صحيح kout, r;

#اگر_تعریف_شده DEBUG_KEXDH
	fprintf(stderr, "dh_pub= ");
	BN_print_fp(stderr, dh_pub);
	fprintf(stderr, "\n");
	debug("bits %d", BN_رقم_بیتها(dh_pub));
	DHparams_print_fp(stderr, kex->dh);
	fprintf(stderr, "\n");
#پایان_اگر

	إذا (!dh_pub_is_valid(kex->dh, dh_pub)) {
		r = SSH_ERR_پیام_INCOMPLETE;
		اذهب بیرون;
	}
	klen = DH_اندازه(kex->dh);
	إذا ((kbuf = حافظه_بده(klen)) == عدم ||
	    (shared_secret = BN_new()) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب بیرون;
	}
	إذا ((kout = DH_compute_کلید(kbuf, dh_pub, kex->dh)) < 0 ||
	    BN_bin2bn(kbuf, kout, shared_secret) == عدم) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		اذهب بیرون;
	}
#اگر_تعریف_شده DEBUG_KEXDH
	dump_digest("shared secret", kbuf, kout);
#پایان_اگر
	r = sshbuf_put_bignum2(بیرون, shared_secret);
 بیرون:
	freezero(kbuf, klen);
	BN_clear_free(shared_secret);
	أرجع r;
}

صحيح
kex_dh_keypair(بنية kex *kex)
{
	ثابت BIGNUM *pub_کلید;
	بنية sshbuf *buf = عدم;
	صحيح r;

	إذا ((r = kex_dh_keygen(kex)) != 0)
		أرجع r;
	DH_get0_کلید(kex->dh, &pub_کلید, عدم);
	إذا ((buf = sshbuf_new()) == عدم)
		أرجع SSH_ERR_ALLOC_FAIL;
	إذا ((r = sshbuf_put_bignum2(buf, pub_کلید)) != 0 ||
	    (r = sshbuf_get_u32(buf, عدم)) != 0)
		اذهب بیرون;
#اگر_تعریف_شده DEBUG_KEXDH
	DHparams_print_fp(stderr, kex->dh);
	fprintf(stderr, "pub= ");
	BN_print_fp(stderr, pub_کلید);
	fprintf(stderr, "\n");
#پایان_اگر
	kex->client_pub = buf;
	buf = عدم;
 بیرون:
	sshbuf_free(buf);
	أرجع r;
}

صحيح
kex_dh_enc(بنية kex *kex, ثابت بنية sshbuf *client_blob,
    بنية sshbuf **server_blobp, بنية sshbuf **shared_secretp)
{
	ثابت BIGNUM *pub_کلید;
	بنية sshbuf *server_blob = عدم;
	صحيح r;

	*server_blobp = عدم;
	*shared_secretp = عدم;

	إذا ((r = kex_dh_keygen(kex)) != 0)
		اذهب بیرون;
	DH_get0_کلید(kex->dh, &pub_کلید, عدم);
	إذا ((server_blob = sshbuf_new()) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب بیرون;
	}
	إذا ((r = sshbuf_put_bignum2(server_blob, pub_کلید)) != 0 ||
	    (r = sshbuf_get_u32(server_blob, عدم)) != 0)
		اذهب بیرون;
	إذا ((r = kex_dh_dec(kex, client_blob, shared_secretp)) != 0)
		اذهب بیرون;
	*server_blobp = server_blob;
	server_blob = عدم;
 بیرون:
	DH_free(kex->dh);
	kex->dh = عدم;
	sshbuf_free(server_blob);
	أرجع r;
}

صحيح
kex_dh_dec(بنية kex *kex, ثابت بنية sshbuf *dh_blob,
    بنية sshbuf **shared_secretp)
{
	بنية sshbuf *buf = عدم;
	BIGNUM *dh_pub = عدم;
	صحيح r;

	*shared_secretp = عدم;

	إذا ((buf = sshbuf_new()) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب بیرون;
	}
	إذا ((r = sshbuf_put_stringb(buf, dh_blob)) != 0 ||
	    (r = sshbuf_get_bignum2(buf, &dh_pub)) != 0)
		اذهب بیرون;
	sshbuf_reset(buf);
	إذا ((r = kex_dh_compute_کلید(kex, dh_pub, buf)) != 0)
		اذهب بیرون;
	*shared_secretp = buf;
	buf = عدم;
 بیرون:
	BN_free(dh_pub);
	DH_free(kex->dh);
	kex->dh = عدم;
	sshbuf_free(buf);
	أرجع r;
}
#پایان_اگر /* WITH_OPENSSL */
