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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
#ਅਨ੍ਤਰ੍ਭਾਵ "openbsd-compat/openssl-compat.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <signal.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <openssl/bn.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <openssl/dh.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "kex.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshbuf.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssherr.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "dh.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "log.h"

ਪੂਰਨ
kex_dh_keygen(ਬਣਤਰ kex *kex)
{
	ਚੋਣ (kex->kex_type) {
	ਹਾਲਤ KEX_DH_GRP1_SHA1:
		kex->dh = dh_new_group1();
		ਰੋਕੋ;
	ਹਾਲਤ KEX_DH_GRP14_SHA1:
	ਹਾਲਤ KEX_DH_GRP14_SHA256:
		kex->dh = dh_new_group14();
		ਰੋਕੋ;
	ਹਾਲਤ KEX_DH_GRP16_SHA512:
		kex->dh = dh_new_group16();
		ਰੋਕੋ;
	ਹਾਲਤ KEX_DH_GRP18_SHA512:
		kex->dh = dh_new_group18();
		ਰੋਕੋ;
	ਮੂਲ:
		ਵਾਪਸ SSH_ERR_INVALID_ਦਲੀਲ;
	}
	ਜੇ (kex->dh == ਨਿਰਾ)
		ਵਾਪਸ SSH_ERR_ALLOC_FAIL;
	ਵਾਪਸ (dh_gen_ਕੁੰਜੀ(kex->dh, kex->we_need * 8));
}

ਪੂਰਨ
kex_dh_compute_ਕੁੰਜੀ(ਬਣਤਰ kex *kex, BIGNUM *dh_pub, ਬਣਤਰ sshbuf *ਬਾਹਰਲਾ)
{
	BIGNUM *shared_secret = ਨਿਰਾ;
	u_char *kbuf = ਨਿਰਾ;
	ਮਾਪ_t klen = 0;
	ਪੂਰਨ kout, r;

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ DEBUG_KEXDH
	fprintf(stderr, "dh_pub= ");
	BN_print_fp(stderr, dh_pub);
	fprintf(stderr, "\n");
	debug("bits %d", BN_ਅੰਕ_ਬਿੱਟ(dh_pub));
	DHparams_print_fp(stderr, kex->dh);
	fprintf(stderr, "\n");
#ਜੇ_ਅੰਤ

	ਜੇ (!dh_pub_is_valid(kex->dh, dh_pub)) {
		r = SSH_ERR_ਸੁਨੇਹਾ_INCOMPLETE;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	klen = DH_ਮਾਪ(kex->dh);
	ਜੇ ((kbuf = ਸਮ੍ਰਿਤੀ_ਦਿਓ(klen)) == ਨਿਰਾ ||
	    (shared_secret = BN_new()) == ਨਿਰਾ) {
		r = SSH_ERR_ALLOC_FAIL;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((kout = DH_compute_ਕੁੰਜੀ(kbuf, dh_pub, kex->dh)) < 0 ||
	    BN_bin2bn(kbuf, kout, shared_secret) == ਨਿਰਾ) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ DEBUG_KEXDH
	dump_digest("shared secret", kbuf, kout);
#ਜੇ_ਅੰਤ
	r = sshbuf_put_bignum2(ਬਾਹਰਲਾ, shared_secret);
 ਬਾਹਰਲਾ:
	freezero(kbuf, klen);
	BN_clear_free(shared_secret);
	ਵਾਪਸ r;
}

ਪੂਰਨ
kex_dh_keypair(ਬਣਤਰ kex *kex)
{
	ਅਚਲ BIGNUM *pub_ਕੁੰਜੀ;
	ਬਣਤਰ sshbuf *buf = ਨਿਰਾ;
	ਪੂਰਨ r;

	ਜੇ ((r = kex_dh_keygen(kex)) != 0)
		ਵਾਪਸ r;
	DH_get0_ਕੁੰਜੀ(kex->dh, &pub_ਕੁੰਜੀ, ਨਿਰਾ);
	ਜੇ ((buf = sshbuf_new()) == ਨਿਰਾ)
		ਵਾਪਸ SSH_ERR_ALLOC_FAIL;
	ਜੇ ((r = sshbuf_put_bignum2(buf, pub_ਕੁੰਜੀ)) != 0 ||
	    (r = sshbuf_get_u32(buf, ਨਿਰਾ)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ DEBUG_KEXDH
	DHparams_print_fp(stderr, kex->dh);
	fprintf(stderr, "pub= ");
	BN_print_fp(stderr, pub_ਕੁੰਜੀ);
	fprintf(stderr, "\n");
#ਜੇ_ਅੰਤ
	kex->client_pub = buf;
	buf = ਨਿਰਾ;
 ਬਾਹਰਲਾ:
	sshbuf_free(buf);
	ਵਾਪਸ r;
}

ਪੂਰਨ
kex_dh_enc(ਬਣਤਰ kex *kex, ਅਚਲ ਬਣਤਰ sshbuf *client_blob,
    ਬਣਤਰ sshbuf **server_blobp, ਬਣਤਰ sshbuf **shared_secretp)
{
	ਅਚਲ BIGNUM *pub_ਕੁੰਜੀ;
	ਬਣਤਰ sshbuf *server_blob = ਨਿਰਾ;
	ਪੂਰਨ r;

	*server_blobp = ਨਿਰਾ;
	*shared_secretp = ਨਿਰਾ;

	ਜੇ ((r = kex_dh_keygen(kex)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	DH_get0_ਕੁੰਜੀ(kex->dh, &pub_ਕੁੰਜੀ, ਨਿਰਾ);
	ਜੇ ((server_blob = sshbuf_new()) == ਨਿਰਾ) {
		r = SSH_ERR_ALLOC_FAIL;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((r = sshbuf_put_bignum2(server_blob, pub_ਕੁੰਜੀ)) != 0 ||
	    (r = sshbuf_get_u32(server_blob, ਨਿਰਾ)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	ਜੇ ((r = kex_dh_dec(kex, client_blob, shared_secretp)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	*server_blobp = server_blob;
	server_blob = ਨਿਰਾ;
 ਬਾਹਰਲਾ:
	DH_free(kex->dh);
	kex->dh = ਨਿਰਾ;
	sshbuf_free(server_blob);
	ਵਾਪਸ r;
}

ਪੂਰਨ
kex_dh_dec(ਬਣਤਰ kex *kex, ਅਚਲ ਬਣਤਰ sshbuf *dh_blob,
    ਬਣਤਰ sshbuf **shared_secretp)
{
	ਬਣਤਰ sshbuf *buf = ਨਿਰਾ;
	BIGNUM *dh_pub = ਨਿਰਾ;
	ਪੂਰਨ r;

	*shared_secretp = ਨਿਰਾ;

	ਜੇ ((buf = sshbuf_new()) == ਨਿਰਾ) {
		r = SSH_ERR_ALLOC_FAIL;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((r = sshbuf_put_stringb(buf, dh_blob)) != 0 ||
	    (r = sshbuf_get_bignum2(buf, &dh_pub)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	sshbuf_reset(buf);
	ਜੇ ((r = kex_dh_compute_ਕੁੰਜੀ(kex, dh_pub, buf)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	*shared_secretp = buf;
	buf = ਨਿਰਾ;
 ਬਾਹਰਲਾ:
	BN_free(dh_pub);
	DH_free(kex->dh);
	kex->dh = ਨਿਰਾ;
	sshbuf_free(buf);
	ਵਾਪਸ r;
}
#ਜੇ_ਅੰਤ /* WITH_OPENSSL */
