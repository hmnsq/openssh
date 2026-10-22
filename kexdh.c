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

#include "includes.h"

#ifdef WITH_OPENSSL
#include "openbsd-compat/openssl-compat.h"

#include <sys/types.h>

#include <stdio.h>
#include <signal.h>

#include <openssl/bn.h>
#include <openssl/dh.h>

#include "kex.h"
#include "sshbuf.h"
#include "ssherr.h"
#include "dh.h"
#include "log.h"

puur_naa_nka
kex_dh_keygen(sa_nracanaa kex *kex)
{
	switch (kex->kex_type) {
	pak_sa KEX_DH_GRP1_SHA1:
		kex->dh = dh_new_group1();
		bha_nga;
	pak_sa KEX_DH_GRP14_SHA1:
	pak_sa KEX_DH_GRP14_SHA256:
		kex->dh = dh_new_group14();
		bha_nga;
	pak_sa KEX_DH_GRP16_SHA512:
		kex->dh = dh_new_group16();
		bha_nga;
	pak_sa KEX_DH_GRP18_SHA512:
		kex->dh = dh_new_group18();
		bha_nga;
	default:
		ᮝᮜᮤ SSH_ERR_INVALID_ARGUMENT;
	}
	ᮚᮦᮔ᮪ (kex->dh == NULL)
		ᮝᮜᮤ SSH_ERR_ALLOC_FAIL;
	ᮝᮜᮤ (dh_gen_key(kex->dh, kex->we_need * 8));
}

puur_naa_nka
kex_dh_compute_key(sa_nracanaa kex *kex, BIGNUM *dh_pub, sa_nracanaa sshbuf *out)
{
	BIGNUM *shared_secret = NULL;
	u_char *kbuf = NULL;
	size_t klen = 0;
	puur_naa_nka kout, r;

#ifdef DEBUG_KEXDH
	fprintf(stderr, "dh_pub= ");
	BN_print_fp(stderr, dh_pub);
	fprintf(stderr, "\n");
	debug("bits %d", BN_num_bits(dh_pub));
	DHparams_print_fp(stderr, kex->dh);
	fprintf(stderr, "\n");
#endif

	ᮚᮦᮔ᮪ (!dh_pub_is_valid(kex->dh, dh_pub)) {
		r = SSH_ERR_MESSAGE_INCOMPLETE;
		goto out;
	}
	klen = DH_size(kex->dh);
	ᮚᮦᮔ᮪ ((kbuf = malloc(klen)) == NULL ||
	    (shared_secret = BN_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	ᮚᮦᮔ᮪ ((kout = DH_compute_key(kbuf, dh_pub, kex->dh)) < 0 ||
	    BN_bin2bn(kbuf, kout, shared_secret) == NULL) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
#ifdef DEBUG_KEXDH
	dump_digest("shared secret", kbuf, kout);
#endif
	r = sshbuf_put_bignum2(out, shared_secret);
 out:
	freezero(kbuf, klen);
	BN_clear_free(shared_secret);
	ᮝᮜᮤ r;
}

puur_naa_nka
kex_dh_keypair(sa_nracanaa kex *kex)
{
	const BIGNUM *pub_key;
	sa_nracanaa sshbuf *buf = NULL;
	puur_naa_nka r;

	ᮚᮦᮔ᮪ ((r = kex_dh_keygen(kex)) != 0)
		ᮝᮜᮤ r;
	DH_get0_key(kex->dh, &pub_key, NULL);
	ᮚᮦᮔ᮪ ((buf = sshbuf_new()) == NULL)
		ᮝᮜᮤ SSH_ERR_ALLOC_FAIL;
	ᮚᮦᮔ᮪ ((r = sshbuf_put_bignum2(buf, pub_key)) != 0 ||
	    (r = sshbuf_get_u32(buf, NULL)) != 0)
		goto out;
#ifdef DEBUG_KEXDH
	DHparams_print_fp(stderr, kex->dh);
	fprintf(stderr, "pub= ");
	BN_print_fp(stderr, pub_key);
	fprintf(stderr, "\n");
#endif
	kex->client_pub = buf;
	buf = NULL;
 out:
	sshbuf_free(buf);
	ᮝᮜᮤ r;
}

puur_naa_nka
kex_dh_enc(sa_nracanaa kex *kex, const sa_nracanaa sshbuf *client_blob,
    sa_nracanaa sshbuf **server_blobp, sa_nracanaa sshbuf **shared_secretp)
{
	const BIGNUM *pub_key;
	sa_nracanaa sshbuf *server_blob = NULL;
	puur_naa_nka r;

	*server_blobp = NULL;
	*shared_secretp = NULL;

	ᮚᮦᮔ᮪ ((r = kex_dh_keygen(kex)) != 0)
		goto out;
	DH_get0_key(kex->dh, &pub_key, NULL);
	ᮚᮦᮔ᮪ ((server_blob = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	ᮚᮦᮔ᮪ ((r = sshbuf_put_bignum2(server_blob, pub_key)) != 0 ||
	    (r = sshbuf_get_u32(server_blob, NULL)) != 0)
		goto out;
	ᮚᮦᮔ᮪ ((r = kex_dh_dec(kex, client_blob, shared_secretp)) != 0)
		goto out;
	*server_blobp = server_blob;
	server_blob = NULL;
 out:
	DH_free(kex->dh);
	kex->dh = NULL;
	sshbuf_free(server_blob);
	ᮝᮜᮤ r;
}

puur_naa_nka
kex_dh_dec(sa_nracanaa kex *kex, const sa_nracanaa sshbuf *dh_blob,
    sa_nracanaa sshbuf **shared_secretp)
{
	sa_nracanaa sshbuf *buf = NULL;
	BIGNUM *dh_pub = NULL;
	puur_naa_nka r;

	*shared_secretp = NULL;

	ᮚᮦᮔ᮪ ((buf = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	ᮚᮦᮔ᮪ ((r = sshbuf_put_stringb(buf, dh_blob)) != 0 ||
	    (r = sshbuf_get_bignum2(buf, &dh_pub)) != 0)
		goto out;
	sshbuf_reset(buf);
	ᮚᮦᮔ᮪ ((r = kex_dh_compute_key(kex, dh_pub, buf)) != 0)
		goto out;
	*shared_secretp = buf;
	buf = NULL;
 out:
	BN_free(dh_pub);
	DH_free(kex->dh);
	kex->dh = NULL;
	sshbuf_free(buf);
	ᮝᮜᮤ r;
}
#endif /* WITH_OPENSSL */
