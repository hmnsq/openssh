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

#ಯದಿ defined(WITH_OPENSSL)

#ಅನ್ತರ್ಭಾವ <sys/types.h>

#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <signal.h>

#ಅನ್ತರ್ಭಾವ <openssl/bn.h>
#ಅನ್ತರ್ಭಾವ <openssl/ecdh.h>

#ಅನ್ತರ್ಭಾವ "sshkey.h"
#ಅನ್ತರ್ಭಾವ "kex.h"
#ಅನ್ತರ್ಭಾವ "sshbuf.h"
#ಅನ್ತರ್ಭಾವ "ssherr.h"

ಪೂರ್ಣಾಙ್ಕ
kex_ecdh_keypair(ಸಂರಚನಾ kex *kex)
{
	EC_ಕೀಲಿ *client_ಕೀಲಿ = ರಿಕ್ತ;
	ಧ್ರುವ EC_GROUP *group;
	ಧ್ರುವ EC_POINT *public_ಕೀಲಿ;
	ಸಂರಚನಾ sshbuf *buf = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ ((client_ಕೀಲಿ = EC_ಕೀಲಿ_new_by_curve_name(kex->ec_nid)) == ರಿಕ್ತ) {
		r = SSH_ERR_ALLOC_FAIL;
		ಗಚ್ಛ out;
	}
	ಯದಿ (EC_ಕೀಲಿ_generate_ಕೀಲಿ(client_ಕೀಲಿ) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		ಗಚ್ಛ out;
	}
	group = EC_ಕೀಲಿ_get0_group(client_ಕೀಲಿ);
	public_ಕೀಲಿ = EC_ಕೀಲಿ_get0_public_ಕೀಲಿ(client_ಕೀಲಿ);

	ಯದಿ ((buf = sshbuf_new()) == ರಿಕ್ತ) {
		r = SSH_ERR_ALLOC_FAIL;
		ಗಚ್ಛ out;
	}
	ಯದಿ ((r = sshbuf_put_ec(buf, public_ಕೀಲಿ, group)) != 0 ||
	    (r = sshbuf_get_u32(buf, ರಿಕ್ತ)) != 0)
		ಗಚ್ಛ out;
#ifdef DEBUG_KEXECDH
	fputs("client private key:\n", stderr);
	sshkey_dump_ec_ಕೀಲಿ(client_ಕೀಲಿ);
#endif
	kex->ec_client_ಕೀಲಿ = client_ಕೀಲಿ;
	kex->ec_group = group;
	client_ಕೀಲಿ = ರಿಕ್ತ;	/* owned by the kex */
	kex->client_pub = buf;
	buf = ರಿಕ್ತ;
 out:
	EC_ಕೀಲಿ_free(client_ಕೀಲಿ);
	sshbuf_free(buf);
	ಪ್ರತ್ಯಾಗಮ r;
}

ಪೂರ್ಣಾಙ್ಕ
kex_ecdh_enc(ಸಂರಚನಾ kex *kex, ಧ್ರುವ ಸಂರಚನಾ sshbuf *client_blob,
    ಸಂರಚನಾ sshbuf **server_blobp, ಸಂರಚನಾ sshbuf **shared_secretp)
{
	ಧ್ರುವ EC_GROUP *group;
	ಧ್ರುವ EC_POINT *pub_ಕೀಲಿ;
	EC_ಕೀಲಿ *server_ಕೀಲಿ = ರಿಕ್ತ;
	ಸಂರಚನಾ sshbuf *server_blob = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ r;

	*server_blobp = ರಿಕ್ತ;
	*shared_secretp = ರಿಕ್ತ;

	ಯದಿ ((server_ಕೀಲಿ = EC_ಕೀಲಿ_new_by_curve_name(kex->ec_nid)) == ರಿಕ್ತ) {
		r = SSH_ERR_ALLOC_FAIL;
		ಗಚ್ಛ out;
	}
	ಯದಿ (EC_ಕೀಲಿ_generate_ಕೀಲಿ(server_ಕೀಲಿ) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		ಗಚ್ಛ out;
	}
	group = EC_ಕೀಲಿ_get0_group(server_ಕೀಲಿ);

#ifdef DEBUG_KEXECDH
	fputs("server private key:\n", stderr);
	sshkey_dump_ec_ಕೀಲಿ(server_ಕೀಲಿ);
#endif
	pub_ಕೀಲಿ = EC_ಕೀಲಿ_get0_public_ಕೀಲಿ(server_ಕೀಲಿ);
	ಯದಿ ((server_blob = sshbuf_new()) == ರಿಕ್ತ) {
		r = SSH_ERR_ALLOC_FAIL;
		ಗಚ್ಛ out;
	}
	ಯದಿ ((r = sshbuf_put_ec(server_blob, pub_ಕೀಲಿ, group)) != 0 ||
	    (r = sshbuf_get_u32(server_blob, ರಿಕ್ತ)) != 0)
		ಗಚ್ಛ out;
	ಯದಿ ((r = kex_ecdh_dec_ಕೀಲಿ_group(kex, client_blob, server_ಕೀಲಿ, group,
	    0, shared_secretp)) != 0)
		ಗಚ್ಛ out;
	*server_blobp = server_blob;
	server_blob = ರಿಕ್ತ;
 out:
	EC_ಕೀಲಿ_free(server_ಕೀಲಿ);
	sshbuf_free(server_blob);
	ಪ್ರತ್ಯಾಗಮ r;
}

ಪೂರ್ಣಾಙ್ಕ
kex_ecdh_dec_ಕೀಲಿ_group(ಸಂರಚನಾ kex *kex, ಧ್ರುವ ಸಂರಚನಾ sshbuf *ec_blob,
    EC_ಕೀಲಿ *ಕೀಲಿ, ಧ್ರುವ EC_GROUP *group, ಪೂರ್ಣಾಙ್ಕ raw, ಸಂರಚನಾ sshbuf **shared_secretp)
{
	ಸಂರಚನಾ sshbuf *buf = ರಿಕ್ತ;
	BIGNUM *shared_secret = ರಿಕ್ತ;
	EC_POINT *dh_pub = ರಿಕ್ತ;
	u_char *kbuf = ರಿಕ್ತ;
	size_t klen = 0;
	ಪೂರ್ಣಾಙ್ಕ r;

	*shared_secretp = ರಿಕ್ತ;

	ಯದಿ ((buf = sshbuf_new()) == ರಿಕ್ತ) {
		r = SSH_ERR_ALLOC_FAIL;
		ಗಚ್ಛ out;
	}
	ಯದಿ ((r = sshbuf_put_stringb(buf, ec_blob)) != 0)
		ಗಚ್ಛ out;
	ಯದಿ ((dh_pub = EC_POINT_new(group)) == ರಿಕ್ತ) {
		r = SSH_ERR_ALLOC_FAIL;
		ಗಚ್ಛ out;
	}
	ಯದಿ ((r = sshbuf_get_ec(buf, dh_pub, group)) != 0) {
		ಗಚ್ಛ out;
	}
	sshbuf_reset(buf);

#ifdef DEBUG_KEXECDH
	fputs("public key:\n", stderr);
	sshkey_dump_ec_point(group, dh_pub);
#endif
	ಯದಿ (sshkey_ec_validate_public(group, dh_pub) != 0) {
		r = SSH_ERR_MESSAGE_INCOMPLETE;
		ಗಚ್ಛ out;
	}
	klen = (EC_GROUP_get_degree(group) + 7) / 8;
	ಯದಿ ((kbuf = malloc(klen)) == ರಿಕ್ತ) {
		r = SSH_ERR_ALLOC_FAIL;
		ಗಚ್ಛ out;
	}
	ಯದಿ (ECDH_compute_ಕೀಲಿ(kbuf, klen, dh_pub, ಕೀಲಿ, ರಿಕ್ತ) != (ಪೂರ್ಣಾಙ್ಕ)klen) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		ಗಚ್ಛ out;
	}
#ifdef DEBUG_KEXECDH
	dump_digest("shared secret", kbuf, klen);
#endif
	ಯದಿ (raw) {
		ಯದಿ ((r = sshbuf_put(buf, kbuf, klen)) != 0)
			ಗಚ್ಛ out;
	} ಅನ್ಯಥಾ {
		ಯದಿ ((shared_secret = BN_new()) == ರಿಕ್ತ) {
			r = SSH_ERR_ALLOC_FAIL;
			ಗಚ್ಛ out;
		}
		ಯದಿ (BN_bin2bn(kbuf, klen, shared_secret) == ರಿಕ್ತ) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			ಗಚ್ಛ out;
		}
		ಯದಿ ((r = sshbuf_put_bignum2(buf, shared_secret)) != 0)
			ಗಚ್ಛ out;
	}
	*shared_secretp = buf;
	buf = ರಿಕ್ತ;
 out:
	EC_POINT_clear_free(dh_pub);
	BN_clear_free(shared_secret);
	freezero(kbuf, klen);
	sshbuf_free(buf);
	ಪ್ರತ್ಯಾಗಮ r;
}

ಪೂರ್ಣಾಙ್ಕ
kex_ecdh_dec(ಸಂರಚನಾ kex *kex, ಧ್ರುವ ಸಂರಚನಾ sshbuf *server_blob,
    ಸಂರಚನಾ sshbuf **shared_secretp)
{
	ಪೂರ್ಣಾಙ್ಕ r;

	r = kex_ecdh_dec_ಕೀಲಿ_group(kex, server_blob, kex->ec_client_ಕೀಲಿ,
	    kex->ec_group, 0, shared_secretp);
	EC_ಕೀಲಿ_free(kex->ec_client_ಕೀಲಿ);
	kex->ec_client_ಕೀಲಿ = ರಿಕ್ತ;
	ಪ್ರತ್ಯಾಗಮ r;
}

#endif /* WITH_OPENSSL */
