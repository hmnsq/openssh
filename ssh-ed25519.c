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
#ವ್ಯಾಖ್ಯಾನಿಸು SSHKEY_ಆಂತರಿಕ
#ಅನ್ತರ್ಭಾವ "sshkey.h"
#ಅನ್ತರ್ಭಾವ "ssherr.h"

ಸ್ಥಿರ ಶೂನ್ಯ
ssh_ed25519_cleanup(ರಚನೆ sshkey *k)
{
	freezero(k->ed25519_pk, ED25519_PK_SZ);
	freezero(k->ed25519_sk, ED25519_SK_SZ);
	k->ed25519_pk = ಖಾಲಿ;
	k->ed25519_sk = ಖಾಲಿ;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ssh_ed25519_equal(ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *a, ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *b)
{
	ಆದರೆ (a->ed25519_pk == ಖಾಲಿ || b->ed25519_pk == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ 0;
	ಆದರೆ (memcmp(a->ed25519_pk, b->ed25519_pk, ED25519_PK_SZ) != 0)
		ಹಿಂತಿರುಗಿ 0;
	ಹಿಂತಿರುಗಿ 1;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ssh_ed25519_serialize_ಬಹಿರಂಗ(ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *ಕೀಲಿ, ರಚನೆ sshbuf *b,
    ಎಣಿಕೆ sshkey_serialize_rep opts)
{
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ (ಕೀಲಿ->ed25519_pk == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_ವಾದ;
	ಆದರೆ ((r = sshbuf_put_string(b, ಕೀಲಿ->ed25519_pk, ED25519_PK_SZ)) != 0)
		ಹಿಂತಿರುಗಿ r;

	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ssh_ed25519_serialize_ಖಾಸಗಿ(ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *ಕೀಲಿ, ರಚನೆ sshbuf *b,
    ಎಣಿಕೆ sshkey_serialize_rep opts)
{
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ ((r = sshbuf_put_string(b, ಕೀಲಿ->ed25519_pk, ED25519_PK_SZ)) != 0 ||
	    (r = sshbuf_put_string(b, ಕೀಲಿ->ed25519_sk, ED25519_SK_SZ)) != 0)
		ಹಿಂತಿರುಗಿ r;

	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ssh_ed25519_generate(ರಚನೆ sshkey *k, ಪೂರ್ಣಾಂಕ ಬಿಟ್ಟುಗಳು)
{
	ಆದರೆ ((k->ed25519_pk = ಸ್ಮರಣೆ_ಕೊಡು(ED25519_PK_SZ)) == ಖಾಲಿ ||
	    (k->ed25519_sk = ಸ್ಮರಣೆ_ಕೊಡು(ED25519_SK_SZ)) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ SSH_ERR_ALLOC_FAIL;
	ಆದರೆ (crypto_sign_ed25519_keypair(k->ed25519_pk, k->ed25519_sk) != 0)
		ಹಿಂತಿರುಗಿ SSH_ERR_CRYPTO_ERROR;
	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ssh_ed25519_copy_ಬಹಿರಂಗ(ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *from, ರಚನೆ sshkey *ಗಮ್ಯ)
{
	ಆದರೆ (from->ed25519_pk == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ 0; /* XXX SSH_ERR_INTERNAL_ERROR ? */
	ಆದರೆ ((ಗಮ್ಯ->ed25519_pk = ಸ್ಮರಣೆ_ಕೊಡು(ED25519_PK_SZ)) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ SSH_ERR_ALLOC_FAIL;
	ಸ್ಮರಣೆ_ನಕಲು(ಗಮ್ಯ->ed25519_pk, from->ed25519_pk, ED25519_PK_SZ);
	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ssh_ed25519_deserialize_ಬಹಿರಂಗ(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ktype, ರಚನೆ sshbuf *b,
    ರಚನೆ sshkey *ಕೀಲಿ)
{
	u_char *pk = ಖಾಲಿ;
	ಗಾತ್ರ_t len = 0;
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ ((r = sshbuf_get_string(b, &pk, &len)) != 0)
		ಹಿಂತಿರುಗಿ r;
	ಆದರೆ (len != ED25519_PK_SZ) {
		freezero(pk, len);
		ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_FORMAT;
	}
	ಕೀಲಿ->ed25519_pk = pk;
	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ssh_ed25519_deserialize_ಖಾಸಗಿ(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ktype, ರಚನೆ sshbuf *b,
    ರಚನೆ sshkey *ಕೀಲಿ)
{
	ಪೂರ್ಣಾಂಕ r;
	ಗಾತ್ರ_t sklen = 0;
	u_char *ed25519_sk = ಖಾಲಿ;

	ಆದರೆ ((r = ssh_ed25519_deserialize_ಬಹಿರಂಗ(ಖಾಲಿ, b, ಕೀಲಿ)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
	ಆದರೆ ((r = sshbuf_get_string(b, &ed25519_sk, &sklen)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
	ಆದರೆ (sklen != ED25519_SK_SZ) {
		r = SSH_ERR_INVALID_FORMAT;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಕೀಲಿ->ed25519_sk = ed25519_sk;
	ed25519_sk = ಖಾಲಿ; /* transferred */
	/* success */
	r = 0;
 ಹೊರಹೋಗು:
	freezero(ed25519_sk, sklen);
	ಹಿಂತಿರುಗಿ r;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ssh_ed25519_sign(ರಚನೆ sshkey *ಕೀಲಿ,
    u_char **sigp, ಗಾತ್ರ_t *lenp,
    ಸ್ಥಿರಾಂಕ u_char *ದತ್ತಾಂಶ, ಗಾತ್ರ_t datalen,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *alg, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *sk_provider, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *sk_pin, u_int compat)
{
	u_char sig[crypto_sign_ed25519_ಬೈಟುಗಳು];
	ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದೀರ್ಘ siglen = 0;
	ಪೂರ್ಣಾಂಕ r, ret;

	ಆದರೆ (lenp != ಖಾಲಿ)
		*lenp = 0;
	ಆದರೆ (sigp != ಖಾಲಿ)
		*sigp = ಖಾಲಿ;

	ಆದರೆ (ಕೀಲಿ == ಖಾಲಿ ||
	    sshkey_type_plain(ಕೀಲಿ->type) != ಕೀಲಿ_ED25519 ||
	    ಕೀಲಿ->ed25519_sk == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_ವಾದ;

	ಆದರೆ ((ret = crypto_sign_ed25519_detached(sig, &siglen, ದತ್ತಾಂಶ, datalen,
	    ಕೀಲಿ->ed25519_sk)) != 0 || siglen != ಗಾತ್ರ(sig)) {
		r = SSH_ERR_INVALID_ವಾದ; /* XXX better error? */
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((r = ssh_ed25519_encode_store_sig(sig, siglen,
	    sigp, lenp)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;

	/* success */
	r = 0;
 ಹೊರಹೋಗು:
	explicit_bzero(sig, ಗಾತ್ರ(sig));
	ಹಿಂತಿರುಗಿ r;
}

ಪೂರ್ಣಾಂಕ
ssh_ed25519_encode_store_sig(ಸ್ಥಿರಾಂಕ u_char *sig, ಗಾತ್ರ_t slen,
    u_char **sigp, ಗಾತ್ರ_t *lenp)
{
	ರಚನೆ sshbuf *b = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ r = -1;
	ಗಾತ್ರ_t len;

	ಆದರೆ (lenp != ಖಾಲಿ)
		*lenp = 0;
	ಆದರೆ (sigp != ಖಾಲಿ)
		*sigp = ಖಾಲಿ;

	ಆದರೆ (slen != crypto_sign_ed25519_ಬೈಟುಗಳು)
		ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_ವಾದ;

	/* encode signature */
	ಆದರೆ ((b = sshbuf_new()) == ಖಾಲಿ) {
		r = SSH_ERR_ALLOC_FAIL;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((r = sshbuf_put_cstring(b, "ssh-ed25519")) != 0 ||
	    (r = sshbuf_put_string(b, sig, slen)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
	len = sshbuf_len(b);
	ಆದರೆ (sigp != ಖಾಲಿ) {
		ಆದರೆ ((*sigp = ಸ್ಮರಣೆ_ಕೊಡು(len)) == ಖಾಲಿ) {
			r = SSH_ERR_ALLOC_FAIL;
			ಹೋಗು ಹೊರಹೋಗು;
		}
		ಸ್ಮರಣೆ_ನಕಲು(*sigp, sshbuf_ptr(b), len);
	}
	ಆದರೆ (lenp != ಖಾಲಿ)
		*lenp = len;
	/* success */
	r = 0;
 ಹೊರಹೋಗು:
	sshbuf_free(b);
	ಹಿಂತಿರುಗಿ r;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ssh_ed25519_verify(ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *ಕೀಲಿ,
    ಸ್ಥಿರಾಂಕ u_char *sig, ಗಾತ್ರ_t siglen,
    ಸ್ಥಿರಾಂಕ u_char *ದತ್ತಾಂಶ, ಗಾತ್ರ_t dlen, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *alg, u_int compat,
    ರಚನೆ sshkey_sig_details **detailsp)
{
	ರಚನೆ sshbuf *b = ಖಾಲಿ;
	ಅಕ್ಷರ *ktype = ಖಾಲಿ;
	ಸ್ಥಿರಾಂಕ u_char *sigblob;
	ಗಾತ್ರ_t len;
	ಪೂರ್ಣಾಂಕ r, ret;

	ಆದರೆ (ಕೀಲಿ == ಖಾಲಿ ||
	    sshkey_type_plain(ಕೀಲಿ->type) != ಕೀಲಿ_ED25519 ||
	    ಕೀಲಿ->ed25519_pk == ಖಾಲಿ ||
	    sig == ಖಾಲಿ || siglen == 0)
		ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_ವಾದ;

	ಆದರೆ ((b = sshbuf_from(sig, siglen)) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ SSH_ERR_ALLOC_FAIL;
	ಆದರೆ ((r = sshbuf_get_cstring(b, &ktype, ಖಾಲಿ)) != 0 ||
	    (r = sshbuf_get_string_ನೇರ(b, &sigblob, &len)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
	ಆದರೆ (strcmp("ssh-ed25519", ktype) != 0) {
		r = SSH_ERR_ಕೀಲಿ_TYPE_MISMATCH;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ (sshbuf_len(b) != 0) {
		r = SSH_ERR_UNEXPECTED_TRAILING_ದತ್ತಾಂಶ;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ (len != crypto_sign_ed25519_ಬೈಟುಗಳು) {
		r = SSH_ERR_INVALID_FORMAT;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((ret = crypto_sign_ed25519_verify_detached(sigblob, ದತ್ತಾಂಶ, dlen,
	    ಕೀಲಿ->ed25519_pk)) != 0) {
		debug2_f("crypto_sign_ed25519_verify_detached failed: %d", ret);
	}
	ಆದರೆ (ret != 0) {
		r = SSH_ERR_SIGNATURE_INVALID;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	/* success */
	r = 0;
 ಹೊರಹೋಗು:
	sshbuf_free(b);
	ಬಿಡುಗಡೆ(ktype);
	ಹಿಂತಿರುಗಿ r;
}

/* NB. not static; used by ED25519-SK */
ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey_impl_funcs sshkey_ed25519_funcs = {
	/* .size = */		ಖಾಲಿ,
	/* .alloc = */		ಖಾಲಿ,
	/* .cleanup = */	ssh_ed25519_cleanup,
	/* .equal = */		ssh_ed25519_equal,
	/* .ssh_serialize_public = */ ssh_ed25519_serialize_ಬಹಿರಂಗ,
	/* .ssh_deserialize_public = */ ssh_ed25519_deserialize_ಬಹಿರಂಗ,
	/* .ssh_serialize_private = */ ssh_ed25519_serialize_ಖಾಸಗಿ,
	/* .ssh_deserialize_private = */ ssh_ed25519_deserialize_ಖಾಸಗಿ,
	/* .generate = */	ssh_ed25519_generate,
	/* .copy_public = */	ssh_ed25519_copy_ಬಹಿರಂಗ,
	/* .sign = */		ssh_ed25519_sign,
	/* .verify = */		ssh_ed25519_verify,
};

ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey_impl sshkey_ed25519_impl = {
	/* .name = */		"ssh-ed25519",
	/* .shortname = */	"ED25519",
	/* .sigalg = */		ಖಾಲಿ,
	/* .type = */		ಕೀಲಿ_ED25519,
	/* .nid = */		0,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	256,
	/* .funcs = */		&sshkey_ed25519_funcs,
};

ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey_impl sshkey_ed25519_cert_impl = {
	/* .name = */		"ssh-ed25519-cert-v01@openssh.com",
	/* .shortname = */	"ED25519-CERT",
	/* .sigalg = */		ಖಾಲಿ,
	/* .type = */		ಕೀಲಿ_ED25519_CERT,
	/* .nid = */		0,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	256,
	/* .funcs = */		&sshkey_ed25519_funcs,
};
