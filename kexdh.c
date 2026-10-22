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

#ಅನ್ತರ್ಭಾವ "includes.h"

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL
#ಅನ್ತರ್ಭಾವ "openbsd-compat/openssl-compat.h"

#ಅನ್ತರ್ಭಾವ <sys/types.h>

#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <signal.h>

#ಅನ್ತರ್ಭಾವ <openssl/bn.h>
#ಅನ್ತರ್ಭಾವ <openssl/dh.h>

#ಅನ್ತರ್ಭಾವ "kex.h"
#ಅನ್ತರ್ಭಾವ "sshbuf.h"
#ಅನ್ತರ್ಭಾವ "ssherr.h"
#ಅನ್ತರ್ಭಾವ "dh.h"
#ಅನ್ತರ್ಭಾವ "log.h"

ಪೂರ್ಣಾಂಕ
kex_dh_keygen(ರಚನೆ kex *kex)
{
	ಆಯ್ಕೆ (kex->kex_type) {
	ಸ್ಥಿತಿ KEX_DH_GRP1_SHA1:
		kex->dh = dh_new_group1();
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ KEX_DH_GRP14_SHA1:
	ಸ್ಥಿತಿ KEX_DH_GRP14_SHA256:
		kex->dh = dh_new_group14();
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ KEX_DH_GRP16_SHA512:
		kex->dh = dh_new_group16();
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ KEX_DH_GRP18_SHA512:
		kex->dh = dh_new_group18();
		ನಿಲ್ಲಿಸು;
	ಪೂರ್ವನಿಯೋಜಿತ:
		ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_ವಾದ;
	}
	ಆದರೆ (kex->dh == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ SSH_ERR_ALLOC_FAIL;
	ಹಿಂತಿರುಗಿ (dh_gen_ಕೀಲಿ(kex->dh, kex->we_need * 8));
}

ಪೂರ್ಣಾಂಕ
kex_dh_compute_ಕೀಲಿ(ರಚನೆ kex *kex, BIGNUM *dh_pub, ರಚನೆ sshbuf *ಹೊರಹೋಗು)
{
	BIGNUM *shared_secret = ಖಾಲಿ;
	u_char *kbuf = ಖಾಲಿ;
	ಗಾತ್ರ_t klen = 0;
	ಪೂರ್ಣಾಂಕ kout, r;

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ DEBUG_KEXDH
	fprintf(stderr, "dh_pub= ");
	BN_print_fp(stderr, dh_pub);
	fprintf(stderr, "\n");
	debug("bits %d", BN_ಅಂಕೆ_ಬಿಟ್ಟುಗಳು(dh_pub));
	DHparams_print_fp(stderr, kex->dh);
	fprintf(stderr, "\n");
#ಆದರೆ_ಅಂತ್ಯ

	ಆದರೆ (!dh_pub_is_valid(kex->dh, dh_pub)) {
		r = SSH_ERR_ಸಂದೇಶ_INCOMPLETE;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	klen = DH_ಗಾತ್ರ(kex->dh);
	ಆದರೆ ((kbuf = ಸ್ಮರಣೆ_ಕೊಡು(klen)) == ಖಾಲಿ ||
	    (shared_secret = BN_new()) == ಖಾಲಿ) {
		r = SSH_ERR_ALLOC_FAIL;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((kout = DH_compute_ಕೀಲಿ(kbuf, dh_pub, kex->dh)) < 0 ||
	    BN_bin2bn(kbuf, kout, shared_secret) == ಖಾಲಿ) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		ಹೋಗು ಹೊರಹೋಗು;
	}
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ DEBUG_KEXDH
	dump_digest("shared secret", kbuf, kout);
#ಆದರೆ_ಅಂತ್ಯ
	r = sshbuf_put_bignum2(ಹೊರಹೋಗು, shared_secret);
 ಹೊರಹೋಗು:
	freezero(kbuf, klen);
	BN_clear_free(shared_secret);
	ಹಿಂತಿರುಗಿ r;
}

ಪೂರ್ಣಾಂಕ
kex_dh_keypair(ರಚನೆ kex *kex)
{
	ಸ್ಥಿರಾಂಕ BIGNUM *pub_ಕೀಲಿ;
	ರಚನೆ sshbuf *buf = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ ((r = kex_dh_keygen(kex)) != 0)
		ಹಿಂತಿರುಗಿ r;
	DH_get0_ಕೀಲಿ(kex->dh, &pub_ಕೀಲಿ, ಖಾಲಿ);
	ಆದರೆ ((buf = sshbuf_new()) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ SSH_ERR_ALLOC_FAIL;
	ಆದರೆ ((r = sshbuf_put_bignum2(buf, pub_ಕೀಲಿ)) != 0 ||
	    (r = sshbuf_get_u32(buf, ಖಾಲಿ)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ DEBUG_KEXDH
	DHparams_print_fp(stderr, kex->dh);
	fprintf(stderr, "pub= ");
	BN_print_fp(stderr, pub_ಕೀಲಿ);
	fprintf(stderr, "\n");
#ಆದರೆ_ಅಂತ್ಯ
	kex->client_pub = buf;
	buf = ಖಾಲಿ;
 ಹೊರಹೋಗು:
	sshbuf_free(buf);
	ಹಿಂತಿರುಗಿ r;
}

ಪೂರ್ಣಾಂಕ
kex_dh_enc(ರಚನೆ kex *kex, ಸ್ಥಿರಾಂಕ ರಚನೆ sshbuf *client_blob,
    ರಚನೆ sshbuf **server_blobp, ರಚನೆ sshbuf **shared_secretp)
{
	ಸ್ಥಿರಾಂಕ BIGNUM *pub_ಕೀಲಿ;
	ರಚನೆ sshbuf *server_blob = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ r;

	*server_blobp = ಖಾಲಿ;
	*shared_secretp = ಖಾಲಿ;

	ಆದರೆ ((r = kex_dh_keygen(kex)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
	DH_get0_ಕೀಲಿ(kex->dh, &pub_ಕೀಲಿ, ಖಾಲಿ);
	ಆದರೆ ((server_blob = sshbuf_new()) == ಖಾಲಿ) {
		r = SSH_ERR_ALLOC_FAIL;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((r = sshbuf_put_bignum2(server_blob, pub_ಕೀಲಿ)) != 0 ||
	    (r = sshbuf_get_u32(server_blob, ಖಾಲಿ)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
	ಆದರೆ ((r = kex_dh_dec(kex, client_blob, shared_secretp)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
	*server_blobp = server_blob;
	server_blob = ಖಾಲಿ;
 ಹೊರಹೋಗು:
	DH_free(kex->dh);
	kex->dh = ಖಾಲಿ;
	sshbuf_free(server_blob);
	ಹಿಂತಿರುಗಿ r;
}

ಪೂರ್ಣಾಂಕ
kex_dh_dec(ರಚನೆ kex *kex, ಸ್ಥಿರಾಂಕ ರಚನೆ sshbuf *dh_blob,
    ರಚನೆ sshbuf **shared_secretp)
{
	ರಚನೆ sshbuf *buf = ಖಾಲಿ;
	BIGNUM *dh_pub = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ r;

	*shared_secretp = ಖಾಲಿ;

	ಆದರೆ ((buf = sshbuf_new()) == ಖಾಲಿ) {
		r = SSH_ERR_ALLOC_FAIL;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((r = sshbuf_put_stringb(buf, dh_blob)) != 0 ||
	    (r = sshbuf_get_bignum2(buf, &dh_pub)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
	sshbuf_reset(buf);
	ಆದರೆ ((r = kex_dh_compute_ಕೀಲಿ(kex, dh_pub, buf)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
	*shared_secretp = buf;
	buf = ಖಾಲಿ;
 ಹೊರಹೋಗು:
	BN_free(dh_pub);
	DH_free(kex->dh);
	kex->dh = ಖಾಲಿ;
	sshbuf_free(buf);
	ಹಿಂತಿರುಗಿ r;
}
#ಆದರೆ_ಅಂತ್ಯ /* WITH_OPENSSL */
