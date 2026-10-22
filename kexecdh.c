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

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಆದರೆ defined(WITH_OPENSSL)

#ಅನ್ತರ್ಭಾವ <sys/types.h>

#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <signal.h>

#ಅನ್ತರ್ಭಾವ <openssl/bn.h>
#ಅನ್ತರ್ಭಾವ <openssl/ecdh.h>

#ಅನ್ತರ್ಭಾವ "sshkey.h"
#ಅನ್ತರ್ಭಾವ "kex.h"
#ಅನ್ತರ್ಭಾವ "sshbuf.h"
#ಅನ್ತರ್ಭಾವ "ssherr.h"

ಪೂರ್ಣಾಂಕ
kex_ecdh_keypair(ರಚನೆ kex *kex)
{
	EC_ಕೀಲಿ *client_ಕೀಲಿ = ಖಾಲಿ;
	ಸ್ಥಿರಾಂಕ EC_ಗುಂಪು *ಗುಂಪು;
	ಸ್ಥಿರಾಂಕ EC_ಬಿಂದು *ಬಹಿರಂಗ_ಕೀಲಿ;
	ರಚನೆ sshbuf *buf = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ ((client_ಕೀಲಿ = EC_ಕೀಲಿ_new_by_ವಕ್ರ_name(kex->ec_nid)) == ಖಾಲಿ) {
		r = SSH_ERR_ALLOC_FAIL;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ (EC_ಕೀಲಿ_generate_ಕೀಲಿ(client_ಕೀಲಿ) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಗುಂಪು = EC_ಕೀಲಿ_get0_ಗುಂಪು(client_ಕೀಲಿ);
	ಬಹಿರಂಗ_ಕೀಲಿ = EC_ಕೀಲಿ_get0_ಬಹಿರಂಗ_ಕೀಲಿ(client_ಕೀಲಿ);

	ಆದರೆ ((buf = sshbuf_new()) == ಖಾಲಿ) {
		r = SSH_ERR_ALLOC_FAIL;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((r = sshbuf_put_ec(buf, ಬಹಿರಂಗ_ಕೀಲಿ, ಗುಂಪು)) != 0 ||
	    (r = sshbuf_get_u32(buf, ಖಾಲಿ)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ DEBUG_KEXECDH
	fputs("client private key:\n", stderr);
	sshkey_dump_ec_ಕೀಲಿ(client_ಕೀಲಿ);
#ಆದರೆ_ಅಂತ್ಯ
	kex->ec_client_ಕೀಲಿ = client_ಕೀಲಿ;
	kex->ec_ಗುಂಪು = ಗುಂಪು;
	client_ಕೀಲಿ = ಖಾಲಿ;	/* owned by the kex */
	kex->client_pub = buf;
	buf = ಖಾಲಿ;
 ಹೊರಹೋಗು:
	EC_ಕೀಲಿ_free(client_ಕೀಲಿ);
	sshbuf_free(buf);
	ಹಿಂತಿರುಗಿ r;
}

ಪೂರ್ಣಾಂಕ
kex_ecdh_enc(ರಚನೆ kex *kex, ಸ್ಥಿರಾಂಕ ರಚನೆ sshbuf *client_blob,
    ರಚನೆ sshbuf **server_blobp, ರಚನೆ sshbuf **shared_secretp)
{
	ಸ್ಥಿರಾಂಕ EC_ಗುಂಪು *ಗುಂಪು;
	ಸ್ಥಿರಾಂಕ EC_ಬಿಂದು *pub_ಕೀಲಿ;
	EC_ಕೀಲಿ *server_ಕೀಲಿ = ಖಾಲಿ;
	ರಚನೆ sshbuf *server_blob = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ r;

	*server_blobp = ಖಾಲಿ;
	*shared_secretp = ಖಾಲಿ;

	ಆದರೆ ((server_ಕೀಲಿ = EC_ಕೀಲಿ_new_by_ವಕ್ರ_name(kex->ec_nid)) == ಖಾಲಿ) {
		r = SSH_ERR_ALLOC_FAIL;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ (EC_ಕೀಲಿ_generate_ಕೀಲಿ(server_ಕೀಲಿ) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಗುಂಪು = EC_ಕೀಲಿ_get0_ಗುಂಪು(server_ಕೀಲಿ);

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ DEBUG_KEXECDH
	fputs("server private key:\n", stderr);
	sshkey_dump_ec_ಕೀಲಿ(server_ಕೀಲಿ);
#ಆದರೆ_ಅಂತ್ಯ
	pub_ಕೀಲಿ = EC_ಕೀಲಿ_get0_ಬಹಿರಂಗ_ಕೀಲಿ(server_ಕೀಲಿ);
	ಆದರೆ ((server_blob = sshbuf_new()) == ಖಾಲಿ) {
		r = SSH_ERR_ALLOC_FAIL;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((r = sshbuf_put_ec(server_blob, pub_ಕೀಲಿ, ಗುಂಪು)) != 0 ||
	    (r = sshbuf_get_u32(server_blob, ಖಾಲಿ)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
	ಆದರೆ ((r = kex_ecdh_dec_ಕೀಲಿ_ಗುಂಪು(kex, client_blob, server_ಕೀಲಿ, ಗುಂಪು,
	    0, shared_secretp)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
	*server_blobp = server_blob;
	server_blob = ಖಾಲಿ;
 ಹೊರಹೋಗು:
	EC_ಕೀಲಿ_free(server_ಕೀಲಿ);
	sshbuf_free(server_blob);
	ಹಿಂತಿರುಗಿ r;
}

ಪೂರ್ಣಾಂಕ
kex_ecdh_dec_ಕೀಲಿ_ಗುಂಪು(ರಚನೆ kex *kex, ಸ್ಥಿರಾಂಕ ರಚನೆ sshbuf *ec_blob,
    EC_ಕೀಲಿ *ಕೀಲಿ, ಸ್ಥಿರಾಂಕ EC_ಗುಂಪು *ಗುಂಪು, ಪೂರ್ಣಾಂಕ raw, ರಚನೆ sshbuf **shared_secretp)
{
	ರಚನೆ sshbuf *buf = ಖಾಲಿ;
	BIGNUM *shared_secret = ಖಾಲಿ;
	EC_ಬಿಂದು *dh_pub = ಖಾಲಿ;
	u_char *kbuf = ಖಾಲಿ;
	ಗಾತ್ರ_t klen = 0;
	ಪೂರ್ಣಾಂಕ r;

	*shared_secretp = ಖಾಲಿ;

	ಆದರೆ ((buf = sshbuf_new()) == ಖಾಲಿ) {
		r = SSH_ERR_ALLOC_FAIL;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((r = sshbuf_put_stringb(buf, ec_blob)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
	ಆದರೆ ((dh_pub = EC_ಬಿಂದು_new(ಗುಂಪು)) == ಖಾಲಿ) {
		r = SSH_ERR_ALLOC_FAIL;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((r = sshbuf_get_ec(buf, dh_pub, ಗುಂಪು)) != 0) {
		ಹೋಗು ಹೊರಹೋಗು;
	}
	sshbuf_reset(buf);

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ DEBUG_KEXECDH
	fputs("public key:\n", stderr);
	sshkey_dump_ec_ಬಿಂದು(ಗುಂಪು, dh_pub);
#ಆದರೆ_ಅಂತ್ಯ
	ಆದರೆ (sshkey_ec_validate_ಬಹಿರಂಗ(ಗುಂಪು, dh_pub) != 0) {
		r = SSH_ERR_ಸಂದೇಶ_INCOMPLETE;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	klen = (EC_ಗುಂಪು_get_degree(ಗುಂಪು) + 7) / 8;
	ಆದರೆ ((kbuf = ಸ್ಮರಣೆ_ಕೊಡು(klen)) == ಖಾಲಿ) {
		r = SSH_ERR_ALLOC_FAIL;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ (ECDH_compute_ಕೀಲಿ(kbuf, klen, dh_pub, ಕೀಲಿ, ಖಾಲಿ) != (ಪೂರ್ಣಾಂಕ)klen) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		ಹೋಗು ಹೊರಹೋಗು;
	}
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ DEBUG_KEXECDH
	dump_digest("shared secret", kbuf, klen);
#ಆದರೆ_ಅಂತ್ಯ
	ಆದರೆ (raw) {
		ಆದರೆ ((r = sshbuf_put(buf, kbuf, klen)) != 0)
			ಹೋಗು ಹೊರಹೋಗು;
	} ಇಲ್ಲದಿದ್ದರೆ {
		ಆದರೆ ((shared_secret = BN_new()) == ಖಾಲಿ) {
			r = SSH_ERR_ALLOC_FAIL;
			ಹೋಗು ಹೊರಹೋಗು;
		}
		ಆದರೆ (BN_bin2bn(kbuf, klen, shared_secret) == ಖಾಲಿ) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			ಹೋಗು ಹೊರಹೋಗು;
		}
		ಆದರೆ ((r = sshbuf_put_bignum2(buf, shared_secret)) != 0)
			ಹೋಗು ಹೊರಹೋಗು;
	}
	*shared_secretp = buf;
	buf = ಖಾಲಿ;
 ಹೊರಹೋಗು:
	EC_ಬಿಂದು_clear_free(dh_pub);
	BN_clear_free(shared_secret);
	freezero(kbuf, klen);
	sshbuf_free(buf);
	ಹಿಂತಿರುಗಿ r;
}

ಪೂರ್ಣಾಂಕ
kex_ecdh_dec(ರಚನೆ kex *kex, ಸ್ಥಿರಾಂಕ ರಚನೆ sshbuf *server_blob,
    ರಚನೆ sshbuf **shared_secretp)
{
	ಪೂರ್ಣಾಂಕ r;

	r = kex_ecdh_dec_ಕೀಲಿ_ಗುಂಪು(kex, server_blob, kex->ec_client_ಕೀಲಿ,
	    kex->ec_ಗುಂಪು, 0, shared_secretp);
	EC_ಕೀಲಿ_free(kex->ec_client_ಕೀಲಿ);
	kex->ec_client_ಕೀಲಿ = ಖಾಲಿ;
	ಹಿಂತಿರುಗಿ r;
}

#ಆದರೆ_ಅಂತ್ಯ /* WITH_OPENSSL */
