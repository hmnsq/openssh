/* $OpenBSD: ssh-ed25519.c,v 1.24 2026/09/16 00:43:00 djm Exp $ */
/*
 * Copyright (c) 2013 Markus Friedl <markus@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <limits.h>

#ಅನ್ತರ್ಭಾವ "crypto_api.h"

#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <stdarg.h>

#ಅನ್ತರ್ಭಾವ "log.h"
#ಅನ್ತರ್ಭಾವ "sshbuf.h"
#define SSHKEY_INTERNAL
#ಅನ್ತರ್ಭಾವ "sshkey.h"
#ಅನ್ತರ್ಭಾವ "ssherr.h"

ಸ್ಥಿರ ಶೂನ್ಯ
ssh_ed25519_cleanup(ಸಂರಚನಾ sshkey *k)
{
	freezero(k->ed25519_pk, ED25519_PK_SZ);
	freezero(k->ed25519_sk, ED25519_SK_SZ);
	k->ed25519_pk = ರಿಕ್ತ;
	k->ed25519_sk = ರಿಕ್ತ;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
ssh_ed25519_equal(ಧ್ರುವ ಸಂರಚನಾ sshkey *a, ಧ್ರುವ ಸಂರಚನಾ sshkey *b)
{
	ಯದಿ (a->ed25519_pk == ರಿಕ್ತ || b->ed25519_pk == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ 0;
	ಯದಿ (memcmp(a->ed25519_pk, b->ed25519_pk, ED25519_PK_SZ) != 0)
		ಪ್ರತ್ಯಾಗಮ 0;
	ಪ್ರತ್ಯಾಗಮ 1;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
ssh_ed25519_serialize_public(ಧ್ರುವ ಸಂರಚನಾ sshkey *ಕೀಲಿ, ಸಂರಚನಾ sshbuf *b,
    ಗಣನಾ sshkey_serialize_rep opts)
{
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ (ಕೀಲಿ->ed25519_pk == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INVALID_ARGUMENT;
	ಯದಿ ((r = sshbuf_put_string(b, ಕೀಲಿ->ed25519_pk, ED25519_PK_SZ)) != 0)
		ಪ್ರತ್ಯಾಗಮ r;

	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
ssh_ed25519_serialize_private(ಧ್ರುವ ಸಂರಚನಾ sshkey *ಕೀಲಿ, ಸಂರಚನಾ sshbuf *b,
    ಗಣನಾ sshkey_serialize_rep opts)
{
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ ((r = sshbuf_put_string(b, ಕೀಲಿ->ed25519_pk, ED25519_PK_SZ)) != 0 ||
	    (r = sshbuf_put_string(b, ಕೀಲಿ->ed25519_sk, ED25519_SK_SZ)) != 0)
		ಪ್ರತ್ಯಾಗಮ r;

	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
ssh_ed25519_generate(ಸಂರಚನಾ sshkey *k, ಪೂರ್ಣಾಙ್ಕ bits)
{
	ಯದಿ ((k->ed25519_pk = malloc(ED25519_PK_SZ)) == ರಿಕ್ತ ||
	    (k->ed25519_sk = malloc(ED25519_SK_SZ)) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_ALLOC_FAIL;
	ಯದಿ (crypto_sign_ed25519_keypair(k->ed25519_pk, k->ed25519_sk) != 0)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_CRYPTO_ERROR;
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
ssh_ed25519_copy_public(ಧ್ರುವ ಸಂರಚನಾ sshkey *from, ಸಂರಚನಾ sshkey *to)
{
	ಯದಿ (from->ed25519_pk == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ 0; /* XXX SSH_ERR_INTERNAL_ERROR ? */
	ಯದಿ ((to->ed25519_pk = malloc(ED25519_PK_SZ)) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_ALLOC_FAIL;
	memcpy(to->ed25519_pk, from->ed25519_pk, ED25519_PK_SZ);
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
ssh_ed25519_deserialize_public(ಧ್ರುವ ವರ್ಣ *ktype, ಸಂರಚನಾ sshbuf *b,
    ಸಂರಚನಾ sshkey *ಕೀಲಿ)
{
	u_char *pk = ರಿಕ್ತ;
	size_t len = 0;
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ ((r = sshbuf_get_string(b, &pk, &len)) != 0)
		ಪ್ರತ್ಯಾಗಮ r;
	ಯದಿ (len != ED25519_PK_SZ) {
		freezero(pk, len);
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INVALID_FORMAT;
	}
	ಕೀಲಿ->ed25519_pk = pk;
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
ssh_ed25519_deserialize_private(ಧ್ರುವ ವರ್ಣ *ktype, ಸಂರಚನಾ sshbuf *b,
    ಸಂರಚನಾ sshkey *ಕೀಲಿ)
{
	ಪೂರ್ಣಾಙ್ಕ r;
	size_t sklen = 0;
	u_char *ed25519_sk = ರಿಕ್ತ;

	ಯದಿ ((r = ssh_ed25519_deserialize_public(ರಿಕ್ತ, b, ಕೀಲಿ)) != 0)
		ಗಚ್ಛ out;
	ಯದಿ ((r = sshbuf_get_string(b, &ed25519_sk, &sklen)) != 0)
		ಗಚ್ಛ out;
	ಯದಿ (sklen != ED25519_SK_SZ) {
		r = SSH_ERR_INVALID_FORMAT;
		ಗಚ್ಛ out;
	}
	ಕೀಲಿ->ed25519_sk = ed25519_sk;
	ed25519_sk = ರಿಕ್ತ; /* transferred */
	/* success */
	r = 0;
 out:
	freezero(ed25519_sk, sklen);
	ಪ್ರತ್ಯಾಗಮ r;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
ssh_ed25519_sign(ಸಂರಚನಾ sshkey *ಕೀಲಿ,
    u_char **sigp, size_t *lenp,
    ಧ್ರುವ u_char *data, size_t datalen,
    ಧ್ರುವ ವರ್ಣ *alg, ಧ್ರುವ ವರ್ಣ *sk_provider, ಧ್ರುವ ವರ್ಣ *sk_pin, u_int compat)
{
	u_char sig[crypto_sign_ed25519_BYTES];
	unsigned long long siglen = 0;
	ಪೂರ್ಣಾಙ್ಕ r, ret;

	ಯದಿ (lenp != ರಿಕ್ತ)
		*lenp = 0;
	ಯದಿ (sigp != ರಿಕ್ತ)
		*sigp = ರಿಕ್ತ;

	ಯದಿ (ಕೀಲಿ == ರಿಕ್ತ ||
	    sshkey_type_plain(ಕೀಲಿ->type) != ಕೀಲಿ_ED25519 ||
	    ಕೀಲಿ->ed25519_sk == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INVALID_ARGUMENT;

	ಯದಿ ((ret = crypto_sign_ed25519_detached(sig, &siglen, data, datalen,
	    ಕೀಲಿ->ed25519_sk)) != 0 || siglen != ಪರಿಮಾಣ(sig)) {
		r = SSH_ERR_INVALID_ARGUMENT; /* XXX better error? */
		ಗಚ್ಛ out;
	}
	ಯದಿ ((r = ssh_ed25519_encode_store_sig(sig, siglen,
	    sigp, lenp)) != 0)
		ಗಚ್ಛ out;

	/* success */
	r = 0;
 out:
	explicit_bzero(sig, ಪರಿಮಾಣ(sig));
	ಪ್ರತ್ಯಾಗಮ r;
}

ಪೂರ್ಣಾಙ್ಕ
ssh_ed25519_encode_store_sig(ಧ್ರುವ u_char *sig, size_t slen,
    u_char **sigp, size_t *lenp)
{
	ಸಂರಚನಾ sshbuf *b = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ r = -1;
	size_t len;

	ಯದಿ (lenp != ರಿಕ್ತ)
		*lenp = 0;
	ಯದಿ (sigp != ರಿಕ್ತ)
		*sigp = ರಿಕ್ತ;

	ಯದಿ (slen != crypto_sign_ed25519_BYTES)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INVALID_ARGUMENT;

	/* encode signature */
	ಯದಿ ((b = sshbuf_new()) == ರಿಕ್ತ) {
		r = SSH_ERR_ALLOC_FAIL;
		ಗಚ್ಛ out;
	}
	ಯದಿ ((r = sshbuf_put_cstring(b, "ssh-ed25519")) != 0 ||
	    (r = sshbuf_put_string(b, sig, slen)) != 0)
		ಗಚ್ಛ out;
	len = sshbuf_len(b);
	ಯದಿ (sigp != ರಿಕ್ತ) {
		ಯದಿ ((*sigp = malloc(len)) == ರಿಕ್ತ) {
			r = SSH_ERR_ALLOC_FAIL;
			ಗಚ್ಛ out;
		}
		memcpy(*sigp, sshbuf_ptr(b), len);
	}
	ಯದಿ (lenp != ರಿಕ್ತ)
		*lenp = len;
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	ಪ್ರತ್ಯಾಗಮ r;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
ssh_ed25519_verify(ಧ್ರುವ ಸಂರಚನಾ sshkey *ಕೀಲಿ,
    ಧ್ರುವ u_char *sig, size_t siglen,
    ಧ್ರುವ u_char *data, size_t dlen, ಧ್ರುವ ವರ್ಣ *alg, u_int compat,
    ಸಂರಚನಾ sshkey_sig_details **detailsp)
{
	ಸಂರಚನಾ sshbuf *b = ರಿಕ್ತ;
	ವರ್ಣ *ktype = ರಿಕ್ತ;
	ಧ್ರುವ u_char *sigblob;
	size_t len;
	ಪೂರ್ಣಾಙ್ಕ r, ret;

	ಯದಿ (ಕೀಲಿ == ರಿಕ್ತ ||
	    sshkey_type_plain(ಕೀಲಿ->type) != ಕೀಲಿ_ED25519 ||
	    ಕೀಲಿ->ed25519_pk == ರಿಕ್ತ ||
	    sig == ರಿಕ್ತ || siglen == 0)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INVALID_ARGUMENT;

	ಯದಿ ((b = sshbuf_from(sig, siglen)) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_ALLOC_FAIL;
	ಯದಿ ((r = sshbuf_get_cstring(b, &ktype, ರಿಕ್ತ)) != 0 ||
	    (r = sshbuf_get_string_direct(b, &sigblob, &len)) != 0)
		ಗಚ್ಛ out;
	ಯದಿ (strcmp("ssh-ed25519", ktype) != 0) {
		r = SSH_ERR_ಕೀಲಿ_TYPE_MISMATCH;
		ಗಚ್ಛ out;
	}
	ಯದಿ (sshbuf_len(b) != 0) {
		r = SSH_ERR_UNEXPECTED_TRAILING_DATA;
		ಗಚ್ಛ out;
	}
	ಯದಿ (len != crypto_sign_ed25519_BYTES) {
		r = SSH_ERR_INVALID_FORMAT;
		ಗಚ್ಛ out;
	}
	ಯದಿ ((ret = crypto_sign_ed25519_verify_detached(sigblob, data, dlen,
	    ಕೀಲಿ->ed25519_pk)) != 0) {
		debug2_f("crypto_sign_ed25519_verify_detached failed: %d", ret);
	}
	ಯದಿ (ret != 0) {
		r = SSH_ERR_SIGNATURE_INVALID;
		ಗಚ್ಛ out;
	}
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	ಮುಕ್ತ(ktype);
	ಪ್ರತ್ಯಾಗಮ r;
}

/* NB. not static; used by ED25519-SK */
ಧ್ರುವ ಸಂರಚನಾ sshkey_impl_funcs sshkey_ed25519_funcs = {
	/* .size = */		ರಿಕ್ತ,
	/* .alloc = */		ರಿಕ್ತ,
	/* .cleanup = */	ssh_ed25519_cleanup,
	/* .equal = */		ssh_ed25519_equal,
	/* .ssh_serialize_public = */ ssh_ed25519_serialize_public,
	/* .ssh_deserialize_public = */ ssh_ed25519_deserialize_public,
	/* .ssh_serialize_private = */ ssh_ed25519_serialize_private,
	/* .ssh_deserialize_private = */ ssh_ed25519_deserialize_private,
	/* .generate = */	ssh_ed25519_generate,
	/* .copy_public = */	ssh_ed25519_copy_public,
	/* .sign = */		ssh_ed25519_sign,
	/* .verify = */		ssh_ed25519_verify,
};

ಧ್ರುವ ಸಂರಚನಾ sshkey_impl sshkey_ed25519_impl = {
	/* .name = */		"ssh-ed25519",
	/* .shortname = */	"ED25519",
	/* .sigalg = */		ರಿಕ್ತ,
	/* .type = */		ಕೀಲಿ_ED25519,
	/* .nid = */		0,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	256,
	/* .funcs = */		&sshkey_ed25519_funcs,
};

ಧ್ರುವ ಸಂರಚನಾ sshkey_impl sshkey_ed25519_cert_impl = {
	/* .name = */		"ssh-ed25519-cert-v01@openssh.com",
	/* .shortname = */	"ED25519-CERT",
	/* .sigalg = */		ರಿಕ್ತ,
	/* .type = */		ಕೀಲಿ_ED25519_CERT,
	/* .nid = */		0,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	256,
	/* .funcs = */		&sshkey_ed25519_funcs,
};
