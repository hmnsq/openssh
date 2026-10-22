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

#ifdef WITH_OPENSSL
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

ಪೂರ್ಣಾಙ್ಕ
kex_dh_keygen(ಸಂರಚನಾ kex *kex)
{
	ವಿಕಲ್ಪ (kex->kex_type) {
	ಪಕ್ಷ KEX_DH_GRP1_SHA1:
		kex->dh = dh_new_group1();
		ಭಙ್ಗ;
	ಪಕ್ಷ KEX_DH_GRP14_SHA1:
	ಪಕ್ಷ KEX_DH_GRP14_SHA256:
		kex->dh = dh_new_group14();
		ಭಙ್ಗ;
	ಪಕ್ಷ KEX_DH_GRP16_SHA512:
		kex->dh = dh_new_group16();
		ಭಙ್ಗ;
	ಪಕ್ಷ KEX_DH_GRP18_SHA512:
		kex->dh = dh_new_group18();
		ಭಙ್ಗ;
	ಸ್ವಭಾವ:
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INVALID_ARGUMENT;
	}
	ಯದಿ (kex->dh == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_ALLOC_FAIL;
	ಪ್ರತ್ಯಾಗಮ (dh_gen_ಕೀಲಿ(kex->dh, kex->we_need * 8));
}

ಪೂರ್ಣಾಙ್ಕ
kex_dh_compute_ಕೀಲಿ(ಸಂರಚನಾ kex *kex, BIGNUM *dh_pub, ಸಂರಚನಾ sshbuf *out)
{
	BIGNUM *shared_secret = ರಿಕ್ತ;
	u_char *kbuf = ರಿಕ್ತ;
	size_t klen = 0;
	ಪೂರ್ಣಾಙ್ಕ kout, r;

#ifdef DEBUG_KEXDH
	fprintf(stderr, "dh_pub= ");
	BN_print_fp(stderr, dh_pub);
	fprintf(stderr, "\n");
	debug("bits %d", BN_ಅಂಕೆ_bits(dh_pub));
	DHparams_print_fp(stderr, kex->dh);
	fprintf(stderr, "\n");
#endif

	ಯದಿ (!dh_pub_is_valid(kex->dh, dh_pub)) {
		r = SSH_ERR_MESSAGE_INCOMPLETE;
		ಗಚ್ಛ out;
	}
	klen = DH_size(kex->dh);
	ಯದಿ ((kbuf = malloc(klen)) == ರಿಕ್ತ ||
	    (shared_secret = BN_new()) == ರಿಕ್ತ) {
		r = SSH_ERR_ALLOC_FAIL;
		ಗಚ್ಛ out;
	}
	ಯದಿ ((kout = DH_compute_ಕೀಲಿ(kbuf, dh_pub, kex->dh)) < 0 ||
	    BN_bin2bn(kbuf, kout, shared_secret) == ರಿಕ್ತ) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		ಗಚ್ಛ out;
	}
#ifdef DEBUG_KEXDH
	dump_digest("shared secret", kbuf, kout);
#endif
	r = sshbuf_put_bignum2(out, shared_secret);
 out:
	freezero(kbuf, klen);
	BN_clear_free(shared_secret);
	ಪ್ರತ್ಯಾಗಮ r;
}

ಪೂರ್ಣಾಙ್ಕ
kex_dh_keypair(ಸಂರಚನಾ kex *kex)
{
	ಧ್ರುವ BIGNUM *pub_ಕೀಲಿ;
	ಸಂರಚನಾ sshbuf *buf = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ ((r = kex_dh_keygen(kex)) != 0)
		ಪ್ರತ್ಯಾಗಮ r;
	DH_get0_ಕೀಲಿ(kex->dh, &pub_ಕೀಲಿ, ರಿಕ್ತ);
	ಯದಿ ((buf = sshbuf_new()) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_ALLOC_FAIL;
	ಯದಿ ((r = sshbuf_put_bignum2(buf, pub_ಕೀಲಿ)) != 0 ||
	    (r = sshbuf_get_u32(buf, ರಿಕ್ತ)) != 0)
		ಗಚ್ಛ out;
#ifdef DEBUG_KEXDH
	DHparams_print_fp(stderr, kex->dh);
	fprintf(stderr, "pub= ");
	BN_print_fp(stderr, pub_ಕೀಲಿ);
	fprintf(stderr, "\n");
#endif
	kex->client_pub = buf;
	buf = ರಿಕ್ತ;
 out:
	sshbuf_free(buf);
	ಪ್ರತ್ಯಾಗಮ r;
}

ಪೂರ್ಣಾಙ್ಕ
kex_dh_enc(ಸಂರಚನಾ kex *kex, ಧ್ರುವ ಸಂರಚನಾ sshbuf *client_blob,
    ಸಂರಚನಾ sshbuf **server_blobp, ಸಂರಚನಾ sshbuf **shared_secretp)
{
	ಧ್ರುವ BIGNUM *pub_ಕೀಲಿ;
	ಸಂರಚನಾ sshbuf *server_blob = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ r;

	*server_blobp = ರಿಕ್ತ;
	*shared_secretp = ರಿಕ್ತ;

	ಯದಿ ((r = kex_dh_keygen(kex)) != 0)
		ಗಚ್ಛ out;
	DH_get0_ಕೀಲಿ(kex->dh, &pub_ಕೀಲಿ, ರಿಕ್ತ);
	ಯದಿ ((server_blob = sshbuf_new()) == ರಿಕ್ತ) {
		r = SSH_ERR_ALLOC_FAIL;
		ಗಚ್ಛ out;
	}
	ಯದಿ ((r = sshbuf_put_bignum2(server_blob, pub_ಕೀಲಿ)) != 0 ||
	    (r = sshbuf_get_u32(server_blob, ರಿಕ್ತ)) != 0)
		ಗಚ್ಛ out;
	ಯದಿ ((r = kex_dh_dec(kex, client_blob, shared_secretp)) != 0)
		ಗಚ್ಛ out;
	*server_blobp = server_blob;
	server_blob = ರಿಕ್ತ;
 out:
	DH_free(kex->dh);
	kex->dh = ರಿಕ್ತ;
	sshbuf_free(server_blob);
	ಪ್ರತ್ಯಾಗಮ r;
}

ಪೂರ್ಣಾಙ್ಕ
kex_dh_dec(ಸಂರಚನಾ kex *kex, ಧ್ರುವ ಸಂರಚನಾ sshbuf *dh_blob,
    ಸಂರಚನಾ sshbuf **shared_secretp)
{
	ಸಂರಚನಾ sshbuf *buf = ರಿಕ್ತ;
	BIGNUM *dh_pub = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ r;

	*shared_secretp = ರಿಕ್ತ;

	ಯದಿ ((buf = sshbuf_new()) == ರಿಕ್ತ) {
		r = SSH_ERR_ALLOC_FAIL;
		ಗಚ್ಛ out;
	}
	ಯದಿ ((r = sshbuf_put_stringb(buf, dh_blob)) != 0 ||
	    (r = sshbuf_get_bignum2(buf, &dh_pub)) != 0)
		ಗಚ್ಛ out;
	sshbuf_reset(buf);
	ಯದಿ ((r = kex_dh_compute_ಕೀಲಿ(kex, dh_pub, buf)) != 0)
		ಗಚ್ಛ out;
	*shared_secretp = buf;
	buf = ರಿಕ್ತ;
 out:
	BN_free(dh_pub);
	DH_free(kex->dh);
	kex->dh = ರಿಕ್ತ;
	sshbuf_free(buf);
	ಪ್ರತ್ಯಾಗಮ r;
}
#endif /* WITH_OPENSSL */
