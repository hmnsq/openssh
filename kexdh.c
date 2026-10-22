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

#ifdef WITH_OPENSSL
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
kex_dh_keygen(ساختار kex *kex)
{
	انتخاب (kex->kex_type) {
	حالت KEX_DH_GRP1_SHA1:
		kex->dh = dh_new_group1();
		بشکن;
	حالت KEX_DH_GRP14_SHA1:
	حالت KEX_DH_GRP14_SHA256:
		kex->dh = dh_new_group14();
		بشکن;
	حالت KEX_DH_GRP16_SHA512:
		kex->dh = dh_new_group16();
		بشکن;
	حالت KEX_DH_GRP18_SHA512:
		kex->dh = dh_new_group18();
		بشکن;
	پیشفرض:
		بازگشت SSH_ERR_INVALID_ARGUMENT;
	}
	اگر (kex->dh == پوچ)
		بازگشت SSH_ERR_ALLOC_FAIL;
	بازگشت (dh_gen_کلید(kex->dh, kex->we_need * 8));
}

صحیح
kex_dh_compute_کلید(ساختار kex *kex, BIGNUM *dh_pub, ساختار sshbuf *out)
{
	BIGNUM *shared_secret = پوچ;
	u_char *kbuf = پوچ;
	size_t klen = 0;
	صحیح kout, r;

#ifdef DEBUG_KEXDH
	fprintf(stderr, "dh_pub= ");
	BN_print_fp(stderr, dh_pub);
	fprintf(stderr, "\n");
	debug("bits %d", BN_رقم_bits(dh_pub));
	DHparams_print_fp(stderr, kex->dh);
	fprintf(stderr, "\n");
#endif

	اگر (!dh_pub_is_valid(kex->dh, dh_pub)) {
		r = SSH_ERR_MESSAGE_INCOMPLETE;
		برو out;
	}
	klen = DH_size(kex->dh);
	اگر ((kbuf = malloc(klen)) == پوچ ||
	    (shared_secret = BN_new()) == پوچ) {
		r = SSH_ERR_ALLOC_FAIL;
		برو out;
	}
	اگر ((kout = DH_compute_کلید(kbuf, dh_pub, kex->dh)) < 0 ||
	    BN_bin2bn(kbuf, kout, shared_secret) == پوچ) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		برو out;
	}
#ifdef DEBUG_KEXDH
	dump_digest("shared secret", kbuf, kout);
#endif
	r = sshbuf_put_bignum2(out, shared_secret);
 out:
	freezero(kbuf, klen);
	BN_clear_free(shared_secret);
	بازگشت r;
}

صحیح
kex_dh_keypair(ساختار kex *kex)
{
	ثابت BIGNUM *pub_کلید;
	ساختار sshbuf *buf = پوچ;
	صحیح r;

	اگر ((r = kex_dh_keygen(kex)) != 0)
		بازگشت r;
	DH_get0_کلید(kex->dh, &pub_کلید, پوچ);
	اگر ((buf = sshbuf_new()) == پوچ)
		بازگشت SSH_ERR_ALLOC_FAIL;
	اگر ((r = sshbuf_put_bignum2(buf, pub_کلید)) != 0 ||
	    (r = sshbuf_get_u32(buf, پوچ)) != 0)
		برو out;
#ifdef DEBUG_KEXDH
	DHparams_print_fp(stderr, kex->dh);
	fprintf(stderr, "pub= ");
	BN_print_fp(stderr, pub_کلید);
	fprintf(stderr, "\n");
#endif
	kex->client_pub = buf;
	buf = پوچ;
 out:
	sshbuf_free(buf);
	بازگشت r;
}

صحیح
kex_dh_enc(ساختار kex *kex, ثابت ساختار sshbuf *client_blob,
    ساختار sshbuf **server_blobp, ساختار sshbuf **shared_secretp)
{
	ثابت BIGNUM *pub_کلید;
	ساختار sshbuf *server_blob = پوچ;
	صحیح r;

	*server_blobp = پوچ;
	*shared_secretp = پوچ;

	اگر ((r = kex_dh_keygen(kex)) != 0)
		برو out;
	DH_get0_کلید(kex->dh, &pub_کلید, پوچ);
	اگر ((server_blob = sshbuf_new()) == پوچ) {
		r = SSH_ERR_ALLOC_FAIL;
		برو out;
	}
	اگر ((r = sshbuf_put_bignum2(server_blob, pub_کلید)) != 0 ||
	    (r = sshbuf_get_u32(server_blob, پوچ)) != 0)
		برو out;
	اگر ((r = kex_dh_dec(kex, client_blob, shared_secretp)) != 0)
		برو out;
	*server_blobp = server_blob;
	server_blob = پوچ;
 out:
	DH_free(kex->dh);
	kex->dh = پوچ;
	sshbuf_free(server_blob);
	بازگشت r;
}

صحیح
kex_dh_dec(ساختار kex *kex, ثابت ساختار sshbuf *dh_blob,
    ساختار sshbuf **shared_secretp)
{
	ساختار sshbuf *buf = پوچ;
	BIGNUM *dh_pub = پوچ;
	صحیح r;

	*shared_secretp = پوچ;

	اگر ((buf = sshbuf_new()) == پوچ) {
		r = SSH_ERR_ALLOC_FAIL;
		برو out;
	}
	اگر ((r = sshbuf_put_stringb(buf, dh_blob)) != 0 ||
	    (r = sshbuf_get_bignum2(buf, &dh_pub)) != 0)
		برو out;
	sshbuf_reset(buf);
	اگر ((r = kex_dh_compute_کلید(kex, dh_pub, buf)) != 0)
		برو out;
	*shared_secretp = buf;
	buf = پوچ;
 out:
	BN_free(dh_pub);
	DH_free(kex->dh);
	kex->dh = پوچ;
	sshbuf_free(buf);
	بازگشت r;
}
#endif /* WITH_OPENSSL */
