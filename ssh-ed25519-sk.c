/* $OpenBSD: ssh-ed25519-sk.c,v 1.17 2026/09/16 00:43:00 djm Exp $ */
/*
 * Copyright (c) 2019 Markus Friedl.  All rights reserved.
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

/* #define DEBUG_SK 1 */

#ಅನ್ತರ್ಭಾವ "includes.h"

#ವ್ಯಾಖ್ಯಾನಿಸು SSHKEY_ಆಂತರಿಕ
#ಅನ್ತರ್ಭಾವ <sys/types.h>

#ಅನ್ತರ್ಭಾವ "crypto_api.h"

#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <stdarg.h>

#ಅನ್ತರ್ಭಾವ "log.h"
#ಅನ್ತರ್ಭಾವ "sshbuf.h"
#ಅನ್ತರ್ಭಾವ "sshkey.h"
#ಅನ್ತರ್ಭಾವ "ssherr.h"
#ಅನ್ತರ್ಭಾವ "digest.h"

/* Reuse some ED25519 internals */
ಬಾಹ್ಯ ರಚನೆ sshkey_impl_funcs sshkey_ed25519_funcs;

ಸ್ಥಿರ ಶೂನ್ಯ
ssh_ed25519_sk_cleanup(ರಚನೆ sshkey *k)
{
	sshkey_sk_cleanup(k);
	sshkey_ed25519_funcs.cleanup(k);
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ssh_ed25519_sk_equal(ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *a, ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *b)
{
	ಆದರೆ (!sshkey_sk_fields_equal(a, b))
		ಹಿಂತಿರುಗಿ 0;
	ಆದರೆ (!sshkey_ed25519_funcs.equal(a, b))
		ಹಿಂತಿರುಗಿ 0;
	ಹಿಂತಿರುಗಿ 1;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ssh_ed25519_sk_serialize_ಬಹಿರಂಗ(ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *ಕೀಲಿ, ರಚನೆ sshbuf *b,
    ಎಣಿಕೆ sshkey_serialize_rep opts)
{
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ ((r = sshkey_ed25519_funcs.serialize_ಬಹಿರಂಗ(ಕೀಲಿ, b, opts)) != 0)
		ಹಿಂತಿರುಗಿ r;
	ಆದರೆ ((r = sshkey_serialize_sk(ಕೀಲಿ, b)) != 0)
		ಹಿಂತಿರುಗಿ r;

	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ssh_ed25519_sk_serialize_ಖಾಸಗಿ(ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *ಕೀಲಿ, ರಚನೆ sshbuf *b,
    ಎಣಿಕೆ sshkey_serialize_rep opts)
{
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ ((r = sshkey_ed25519_funcs.serialize_ಬಹಿರಂಗ(ಕೀಲಿ, b, opts)) != 0)
		ಹಿಂತಿರುಗಿ r;
	ಆದರೆ ((r = sshkey_serialize_ಖಾಸಗಿ_sk(ಕೀಲಿ, b)) != 0)
		ಹಿಂತಿರುಗಿ r;

	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ssh_ed25519_sk_copy_ಬಹಿರಂಗ(ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *from, ರಚನೆ sshkey *ಗಮ್ಯ)
{
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ ((r = sshkey_ed25519_funcs.copy_ಬಹಿರಂಗ(from, ಗಮ್ಯ)) != 0)
		ಹಿಂತಿರುಗಿ r;
	ಆದರೆ ((r = sshkey_copy_ಬಹಿರಂಗ_sk(from, ಗಮ್ಯ)) != 0)
		ಹಿಂತಿರುಗಿ r;
	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ssh_ed25519_sk_deserialize_ಬಹಿರಂಗ(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ktype, ರಚನೆ sshbuf *b,
    ರಚನೆ sshkey *ಕೀಲಿ)
{
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ ((r = sshkey_ed25519_funcs.deserialize_ಬಹಿರಂಗ(ktype, b, ಕೀಲಿ)) != 0)
		ಹಿಂತಿರುಗಿ r;
	ಆದರೆ ((r = sshkey_deserialize_sk(b, ಕೀಲಿ)) != 0)
		ಹಿಂತಿರುಗಿ r;
	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ssh_ed25519_sk_deserialize_ಖಾಸಗಿ(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ktype, ರಚನೆ sshbuf *b,
    ರಚನೆ sshkey *ಕೀಲಿ)
{
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ ((r = sshkey_ed25519_funcs.deserialize_ಬಹಿರಂಗ(ktype, b, ಕೀಲಿ)) != 0)
		ಹಿಂತಿರುಗಿ r;
	ಆದರೆ ((r = sshkey_ಖಾಸಗಿ_deserialize_sk(b, ಕೀಲಿ)) != 0)
		ಹಿಂತಿರುಗಿ r;
	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ssh_ed25519_sk_verify(ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *ಕೀಲಿ,
    ಸ್ಥಿರಾಂಕ u_char *sig, ಗಾತ್ರ_t siglen,
    ಸ್ಥಿರಾಂಕ u_char *ದತ್ತಾಂಶ, ಗಾತ್ರ_t dlen, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *alg, u_int compat,
    ರಚನೆ sshkey_sig_details **detailsp)
{
	ರಚನೆ sshbuf *b = ಖಾಲಿ;
	ರಚನೆ sshbuf *encoded = ಖಾಲಿ;
	ಅಕ್ಷರ *ktype = ಖಾಲಿ;
	ಸ್ಥಿರಾಂಕ u_char *sigblob;
	u_char apphash[32];
	u_char msghash[32];
	u_char sig_flags;
	u_int sig_counter;
	ಗಾತ್ರ_t len;
	ಪೂರ್ಣಾಂಕ r = SSH_ERR_ಆಂತರಿಕ_ERROR;
	ಪೂರ್ಣಾಂಕ ret;
	ರಚನೆ sshkey_sig_details *details = ಖಾಲಿ;

	ಆದರೆ (detailsp != ಖಾಲಿ)
		*detailsp = ಖಾಲಿ;

	ಆದರೆ (ಕೀಲಿ == ಖಾಲಿ ||
	    sshkey_type_plain(ಕೀಲಿ->type) != ಕೀಲಿ_ED25519_SK ||
	    ಕೀಲಿ->ed25519_pk == ಖಾಲಿ ||
	    sig == ಖಾಲಿ || siglen == 0)
		ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_ವಾದ;

	ಆದರೆ ((b = sshbuf_from(sig, siglen)) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ SSH_ERR_ALLOC_FAIL;
	ಆದರೆ (sshbuf_get_cstring(b, &ktype, ಖಾಲಿ) != 0 ||
	    sshbuf_get_string_ನೇರ(b, &sigblob, &len) != 0 ||
	    sshbuf_get_u8(b, &sig_flags) != 0 ||
	    sshbuf_get_u32(b, &sig_counter) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		ಹೋಗು ಹೊರಹೋಗು;
	}
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ DEBUG_SK
	fprintf(stderr, "%s: data:\n", __func__);
	/* sshbuf_dump_data(data, datalen, stderr); */
	fprintf(stderr, "%s: sigblob:\n", __func__);
	sshbuf_dump_ದತ್ತಾಂಶ(sigblob, len, stderr);
	fprintf(stderr, "%s: sig_flags = 0x%02x, sig_counter = %u\n",
	    __func__, sig_flags, sig_counter);
#ಆದರೆ_ಅಂತ್ಯ
	ಆದರೆ (strcmp(sshkey_ssh_name_plain(ಕೀಲಿ), ktype) != 0) {
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
	ಆದರೆ (ssh_digest_ಸ್ಮರಣೆ(SSH_DIGEST_SHA256, ಕೀಲಿ->sk_application,
	    ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(ಕೀಲಿ->sk_application), apphash, ಗಾತ್ರ(apphash)) != 0 ||
	    ssh_digest_ಸ್ಮರಣೆ(SSH_DIGEST_SHA256, ದತ್ತಾಂಶ, dlen,
	    msghash, ಗಾತ್ರ(msghash)) != 0) {
		r = SSH_ERR_INVALID_ವಾದ;
		ಹೋಗು ಹೊರಹೋಗು;
	}
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ DEBUG_SK
	fprintf(stderr, "%s: hashed application:\n", __func__);
	sshbuf_dump_ದತ್ತಾಂಶ(apphash, ಗಾತ್ರ(apphash), stderr);
	fprintf(stderr, "%s: hashed message:\n", __func__);
	sshbuf_dump_ದತ್ತಾಂಶ(msghash, ಗಾತ್ರ(msghash), stderr);
#ಆದರೆ_ಅಂತ್ಯ
	ಆದರೆ ((details = ಸೊನ್ನೆ_ಸ್ಮರಣೆ_ಕೊಡು(1, ಗಾತ್ರ(*details))) == ಖಾಲಿ) {
		r = SSH_ERR_ALLOC_FAIL;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	details->sk_counter = sig_counter;
	details->sk_flags = sig_flags;
	ಆದರೆ ((encoded = sshbuf_new()) == ಖಾಲಿ) {
		r = SSH_ERR_ALLOC_FAIL;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ (sshbuf_put(encoded, apphash, ಗಾತ್ರ(apphash)) != 0 ||
	    sshbuf_put_u8(encoded, sig_flags) != 0 ||
	    sshbuf_put_u32(encoded, sig_counter) != 0 ||
	    sshbuf_put(encoded, msghash, ಗಾತ್ರ(msghash)) != 0) {
		r = SSH_ERR_ALLOC_FAIL;
		ಹೋಗು ಹೊರಹೋಗು;
	}
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ DEBUG_SK
	fprintf(stderr, "%s: signed buf:\n", __func__);
	sshbuf_dump(encoded, stderr);
#ಆದರೆ_ಅಂತ್ಯ
	ಆದರೆ ((ret = crypto_sign_ed25519_verify_detached(sigblob,
	    sshbuf_ptr(encoded), sshbuf_len(encoded),
	    ಕೀಲಿ->ed25519_pk)) != 0) {
		debug2_f("crypto_sign_ed25519_verify_detached failed: %d", ret);
	}
	ಆದರೆ (ret != 0) {
		r = SSH_ERR_SIGNATURE_INVALID;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	/* success */
	r = 0;
	ಆದರೆ (detailsp != ಖಾಲಿ) {
		*detailsp = details;
		details = ಖಾಲಿ;
	}
 ಹೊರಹೋಗು:
	sshkey_sig_details_free(details);
	sshbuf_free(b);
	sshbuf_free(encoded);
	ಬಿಡುಗಡೆ(ktype);
	ಹಿಂತಿರುಗಿ r;
}

ಸ್ಥಿರ ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey_impl_funcs sshkey_ed25519_sk_funcs = {
	/* .size = */		ಖಾಲಿ,
	/* .alloc = */		ಖಾಲಿ,
	/* .cleanup = */	ssh_ed25519_sk_cleanup,
	/* .equal = */		ssh_ed25519_sk_equal,
	/* .ssh_serialize_public = */ ssh_ed25519_sk_serialize_ಬಹಿರಂಗ,
	/* .ssh_deserialize_public = */ ssh_ed25519_sk_deserialize_ಬಹಿರಂಗ,
	/* .ssh_serialize_private = */ ssh_ed25519_sk_serialize_ಖಾಸಗಿ,
	/* .ssh_deserialize_private = */ ssh_ed25519_sk_deserialize_ಖಾಸಗಿ,
	/* .generate = */	ಖಾಲಿ,
	/* .copy_public = */	ssh_ed25519_sk_copy_ಬಹಿರಂಗ,
	/* .sign = */		ಖಾಲಿ,
	/* .verify = */		ssh_ed25519_sk_verify,
};

ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey_impl sshkey_ed25519_sk_impl = {
	/* .name = */		"sk-ssh-ed25519@openssh.com",
	/* .shortname = */	"ED25519-SK",
	/* .sigalg = */		ಖಾಲಿ,
	/* .type = */		ಕೀಲಿ_ED25519_SK,
	/* .nid = */		0,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	256,
	/* .funcs = */		&sshkey_ed25519_sk_funcs,
};

ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey_impl sshkey_ed25519_sk_cert_impl = {
	/* .name = */		"sk-ssh-ed25519-cert-v01@openssh.com",
	/* .shortname = */	"ED25519-SK-CERT",
	/* .sigalg = */		ಖಾಲಿ,
	/* .type = */		ಕೀಲಿ_ED25519_SK_CERT,
	/* .nid = */		0,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	256,
	/* .funcs = */		&sshkey_ed25519_sk_funcs,
};
