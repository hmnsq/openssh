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

#شامل "includes.h"

#اگر_تعریف_شدہ WITH_OPENSSL
#شامل "openbsd-compat/openssl-compat.h"

#شامل <sys/types.h>

#شامل <stdio.h>
#شامل <signal.h>

#شامل <openssl/bn.h>
#شامل <openssl/dh.h>

#شامل "kex.h"
#شامل "sshbuf.h"
#شامل "ssherr.h"
#شامل "dh.h"
#شامل "log.h"

صحیح
kex_dh_keygen(ساخت kex *kex)
{
	انتخاب (kex->kex_type) {
	حالت KEX_DH_GRP1_SHA1:
		kex->dh = dh_new_group1();
		توڑو;
	حالت KEX_DH_GRP14_SHA1:
	حالت KEX_DH_GRP14_SHA256:
		kex->dh = dh_new_group14();
		توڑو;
	حالت KEX_DH_GRP16_SHA512:
		kex->dh = dh_new_group16();
		توڑو;
	حالت KEX_DH_GRP18_SHA512:
		kex->dh = dh_new_group18();
		توڑو;
	طےشدہ:
		واپس SSH_ERR_INVALID_دلیل;
	}
	اگر (kex->dh == تہی)
		واپس SSH_ERR_ALLOC_FAIL;
	واپس (dh_gen_کلید(kex->dh, kex->we_need * 8));
}

صحیح
kex_dh_compute_کلید(ساخت kex *kex, BIGNUM *dh_pub, ساخت sshbuf *برآمد)
{
	BIGNUM *shared_secret = تہی;
	u_char *kbuf = تہی;
	سائز_t klen = 0;
	صحیح kout, r;

#اگر_تعریف_شدہ DEBUG_KEXDH
	fprintf(stderr, "dh_pub= ");
	BN_print_fp(stderr, dh_pub);
	fprintf(stderr, "\n");
	debug("bits %d", BN_عدد_بٹ(dh_pub));
	DHparams_print_fp(stderr, kex->dh);
	fprintf(stderr, "\n");
#اگر_ختم

	اگر (!dh_pub_is_valid(kex->dh, dh_pub)) {
		r = SSH_ERR_پیغام_INCOMPLETE;
		جاؤ برآمد;
	}
	klen = DH_سائز(kex->dh);
	اگر ((kbuf = حافظہ_دو(klen)) == تہی ||
	    (shared_secret = BN_new()) == تہی) {
		r = SSH_ERR_ALLOC_FAIL;
		جاؤ برآمد;
	}
	اگر ((kout = DH_compute_کلید(kbuf, dh_pub, kex->dh)) < 0 ||
	    BN_bin2bn(kbuf, kout, shared_secret) == تہی) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		جاؤ برآمد;
	}
#اگر_تعریف_شدہ DEBUG_KEXDH
	dump_digest("shared secret", kbuf, kout);
#اگر_ختم
	r = sshbuf_put_bignum2(برآمد, shared_secret);
 برآمد:
	freezero(kbuf, klen);
	BN_clear_free(shared_secret);
	واپس r;
}

صحیح
kex_dh_keypair(ساخت kex *kex)
{
	ثابت BIGNUM *pub_کلید;
	ساخت sshbuf *buf = تہی;
	صحیح r;

	اگر ((r = kex_dh_keygen(kex)) != 0)
		واپس r;
	DH_get0_کلید(kex->dh, &pub_کلید, تہی);
	اگر ((buf = sshbuf_new()) == تہی)
		واپس SSH_ERR_ALLOC_FAIL;
	اگر ((r = sshbuf_put_bignum2(buf, pub_کلید)) != 0 ||
	    (r = sshbuf_get_u32(buf, تہی)) != 0)
		جاؤ برآمد;
#اگر_تعریف_شدہ DEBUG_KEXDH
	DHparams_print_fp(stderr, kex->dh);
	fprintf(stderr, "pub= ");
	BN_print_fp(stderr, pub_کلید);
	fprintf(stderr, "\n");
#اگر_ختم
	kex->client_pub = buf;
	buf = تہی;
 برآمد:
	sshbuf_free(buf);
	واپس r;
}

صحیح
kex_dh_enc(ساخت kex *kex, ثابت ساخت sshbuf *client_blob,
    ساخت sshbuf **server_blobp, ساخت sshbuf **shared_secretp)
{
	ثابت BIGNUM *pub_کلید;
	ساخت sshbuf *server_blob = تہی;
	صحیح r;

	*server_blobp = تہی;
	*shared_secretp = تہی;

	اگر ((r = kex_dh_keygen(kex)) != 0)
		جاؤ برآمد;
	DH_get0_کلید(kex->dh, &pub_کلید, تہی);
	اگر ((server_blob = sshbuf_new()) == تہی) {
		r = SSH_ERR_ALLOC_FAIL;
		جاؤ برآمد;
	}
	اگر ((r = sshbuf_put_bignum2(server_blob, pub_کلید)) != 0 ||
	    (r = sshbuf_get_u32(server_blob, تہی)) != 0)
		جاؤ برآمد;
	اگر ((r = kex_dh_dec(kex, client_blob, shared_secretp)) != 0)
		جاؤ برآمد;
	*server_blobp = server_blob;
	server_blob = تہی;
 برآمد:
	DH_free(kex->dh);
	kex->dh = تہی;
	sshbuf_free(server_blob);
	واپس r;
}

صحیح
kex_dh_dec(ساخت kex *kex, ثابت ساخت sshbuf *dh_blob,
    ساخت sshbuf **shared_secretp)
{
	ساخت sshbuf *buf = تہی;
	BIGNUM *dh_pub = تہی;
	صحیح r;

	*shared_secretp = تہی;

	اگر ((buf = sshbuf_new()) == تہی) {
		r = SSH_ERR_ALLOC_FAIL;
		جاؤ برآمد;
	}
	اگر ((r = sshbuf_put_stringb(buf, dh_blob)) != 0 ||
	    (r = sshbuf_get_bignum2(buf, &dh_pub)) != 0)
		جاؤ برآمد;
	sshbuf_reset(buf);
	اگر ((r = kex_dh_compute_کلید(kex, dh_pub, buf)) != 0)
		جاؤ برآمد;
	*shared_secretp = buf;
	buf = تہی;
 برآمد:
	BN_free(dh_pub);
	DH_free(kex->dh);
	kex->dh = تہی;
	sshbuf_free(buf);
	واپس r;
}
#اگر_ختم /* WITH_OPENSSL */
