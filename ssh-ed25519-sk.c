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

#define SSHKEY_INTERNAL
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
ಬಾಹ್ಯ ಸಂರಚನಾ sshkey_impl_funcs sshkey_ed25519_funcs;

ಸ್ಥಿರ ಶೂನ್ಯ
ssh_ed25519_sk_cleanup(ಸಂರಚನಾ sshkey *k)
{
	sshkey_sk_cleanup(k);
	sshkey_ed25519_funcs.cleanup(k);
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
ssh_ed25519_sk_equal(ಧ್ರುವ ಸಂರಚನಾ sshkey *a, ಧ್ರುವ ಸಂರಚನಾ sshkey *b)
{
	ಯದಿ (!sshkey_sk_fields_equal(a, b))
		ಪ್ರತ್ಯಾಗಮ 0;
	ಯದಿ (!sshkey_ed25519_funcs.equal(a, b))
		ಪ್ರತ್ಯಾಗಮ 0;
	ಪ್ರತ್ಯಾಗಮ 1;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
ssh_ed25519_sk_serialize_public(ಧ್ರುವ ಸಂರಚನಾ sshkey *ಕೀಲಿ, ಸಂರಚನಾ sshbuf *b,
    ಗಣನಾ sshkey_serialize_rep opts)
{
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ ((r = sshkey_ed25519_funcs.serialize_public(ಕೀಲಿ, b, opts)) != 0)
		ಪ್ರತ್ಯಾಗಮ r;
	ಯದಿ ((r = sshkey_serialize_sk(ಕೀಲಿ, b)) != 0)
		ಪ್ರತ್ಯಾಗಮ r;

	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
ssh_ed25519_sk_serialize_private(ಧ್ರುವ ಸಂರಚನಾ sshkey *ಕೀಲಿ, ಸಂರಚನಾ sshbuf *b,
    ಗಣನಾ sshkey_serialize_rep opts)
{
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ ((r = sshkey_ed25519_funcs.serialize_public(ಕೀಲಿ, b, opts)) != 0)
		ಪ್ರತ್ಯಾಗಮ r;
	ಯದಿ ((r = sshkey_serialize_private_sk(ಕೀಲಿ, b)) != 0)
		ಪ್ರತ್ಯಾಗಮ r;

	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
ssh_ed25519_sk_copy_public(ಧ್ರುವ ಸಂರಚನಾ sshkey *from, ಸಂರಚನಾ sshkey *to)
{
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ ((r = sshkey_ed25519_funcs.copy_public(from, to)) != 0)
		ಪ್ರತ್ಯಾಗಮ r;
	ಯದಿ ((r = sshkey_copy_public_sk(from, to)) != 0)
		ಪ್ರತ್ಯಾಗಮ r;
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
ssh_ed25519_sk_deserialize_public(ಧ್ರುವ ವರ್ಣ *ktype, ಸಂರಚನಾ sshbuf *b,
    ಸಂರಚನಾ sshkey *ಕೀಲಿ)
{
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ ((r = sshkey_ed25519_funcs.deserialize_public(ktype, b, ಕೀಲಿ)) != 0)
		ಪ್ರತ್ಯಾಗಮ r;
	ಯದಿ ((r = sshkey_deserialize_sk(b, ಕೀಲಿ)) != 0)
		ಪ್ರತ್ಯಾಗಮ r;
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
ssh_ed25519_sk_deserialize_private(ಧ್ರುವ ವರ್ಣ *ktype, ಸಂರಚನಾ sshbuf *b,
    ಸಂರಚನಾ sshkey *ಕೀಲಿ)
{
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ ((r = sshkey_ed25519_funcs.deserialize_public(ktype, b, ಕೀಲಿ)) != 0)
		ಪ್ರತ್ಯಾಗಮ r;
	ಯದಿ ((r = sshkey_private_deserialize_sk(b, ಕೀಲಿ)) != 0)
		ಪ್ರತ್ಯಾಗಮ r;
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
ssh_ed25519_sk_verify(ಧ್ರುವ ಸಂರಚನಾ sshkey *ಕೀಲಿ,
    ಧ್ರುವ u_char *sig, size_t siglen,
    ಧ್ರುವ u_char *data, size_t dlen, ಧ್ರುವ ವರ್ಣ *alg, u_int compat,
    ಸಂರಚನಾ sshkey_sig_details **detailsp)
{
	ಸಂರಚನಾ sshbuf *b = ರಿಕ್ತ;
	ಸಂರಚನಾ sshbuf *encoded = ರಿಕ್ತ;
	ವರ್ಣ *ktype = ರಿಕ್ತ;
	ಧ್ರುವ u_char *sigblob;
	u_char apphash[32];
	u_char msghash[32];
	u_char sig_flags;
	u_int sig_counter;
	size_t len;
	ಪೂರ್ಣಾಙ್ಕ r = SSH_ERR_INTERNAL_ERROR;
	ಪೂರ್ಣಾಙ್ಕ ret;
	ಸಂರಚನಾ sshkey_sig_details *details = ರಿಕ್ತ;

	ಯದಿ (detailsp != ರಿಕ್ತ)
		*detailsp = ರಿಕ್ತ;

	ಯದಿ (ಕೀಲಿ == ರಿಕ್ತ ||
	    sshkey_type_plain(ಕೀಲಿ->type) != ಕೀಲಿ_ED25519_SK ||
	    ಕೀಲಿ->ed25519_pk == ರಿಕ್ತ ||
	    sig == ರಿಕ್ತ || siglen == 0)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INVALID_ARGUMENT;

	ಯದಿ ((b = sshbuf_from(sig, siglen)) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_ALLOC_FAIL;
	ಯದಿ (sshbuf_get_cstring(b, &ktype, ರಿಕ್ತ) != 0 ||
	    sshbuf_get_string_direct(b, &sigblob, &len) != 0 ||
	    sshbuf_get_u8(b, &sig_flags) != 0 ||
	    sshbuf_get_u32(b, &sig_counter) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		ಗಚ್ಛ out;
	}
#ifdef DEBUG_SK
	fprintf(stderr, "%s: data:\n", __func__);
	/* sshbuf_dump_data(data, datalen, stderr); */
	fprintf(stderr, "%s: sigblob:\n", __func__);
	sshbuf_dump_data(sigblob, len, stderr);
	fprintf(stderr, "%s: sig_flags = 0x%02x, sig_counter = %u\n",
	    __func__, sig_flags, sig_counter);
#endif
	ಯದಿ (strcmp(sshkey_ssh_name_plain(ಕೀಲಿ), ktype) != 0) {
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
	ಯದಿ (ssh_digest_memory(SSH_DIGEST_SHA256, ಕೀಲಿ->sk_application,
	    strlen(ಕೀಲಿ->sk_application), apphash, ಪರಿಮಾಣ(apphash)) != 0 ||
	    ssh_digest_memory(SSH_DIGEST_SHA256, data, dlen,
	    msghash, ಪರಿಮಾಣ(msghash)) != 0) {
		r = SSH_ERR_INVALID_ARGUMENT;
		ಗಚ್ಛ out;
	}
#ifdef DEBUG_SK
	fprintf(stderr, "%s: hashed application:\n", __func__);
	sshbuf_dump_data(apphash, ಪರಿಮಾಣ(apphash), stderr);
	fprintf(stderr, "%s: hashed message:\n", __func__);
	sshbuf_dump_data(msghash, ಪರಿಮಾಣ(msghash), stderr);
#endif
	ಯದಿ ((details = calloc(1, ಪರಿಮಾಣ(*details))) == ರಿಕ್ತ) {
		r = SSH_ERR_ALLOC_FAIL;
		ಗಚ್ಛ out;
	}
	details->sk_counter = sig_counter;
	details->sk_flags = sig_flags;
	ಯದಿ ((encoded = sshbuf_new()) == ರಿಕ್ತ) {
		r = SSH_ERR_ALLOC_FAIL;
		ಗಚ್ಛ out;
	}
	ಯದಿ (sshbuf_put(encoded, apphash, ಪರಿಮಾಣ(apphash)) != 0 ||
	    sshbuf_put_u8(encoded, sig_flags) != 0 ||
	    sshbuf_put_u32(encoded, sig_counter) != 0 ||
	    sshbuf_put(encoded, msghash, ಪರಿಮಾಣ(msghash)) != 0) {
		r = SSH_ERR_ALLOC_FAIL;
		ಗಚ್ಛ out;
	}
#ifdef DEBUG_SK
	fprintf(stderr, "%s: signed buf:\n", __func__);
	sshbuf_dump(encoded, stderr);
#endif
	ಯದಿ ((ret = crypto_sign_ed25519_verify_detached(sigblob,
	    sshbuf_ptr(encoded), sshbuf_len(encoded),
	    ಕೀಲಿ->ed25519_pk)) != 0) {
		debug2_f("crypto_sign_ed25519_verify_detached failed: %d", ret);
	}
	ಯದಿ (ret != 0) {
		r = SSH_ERR_SIGNATURE_INVALID;
		ಗಚ್ಛ out;
	}
	/* success */
	r = 0;
	ಯದಿ (detailsp != ರಿಕ್ತ) {
		*detailsp = details;
		details = ರಿಕ್ತ;
	}
 out:
	sshkey_sig_details_free(details);
	sshbuf_free(b);
	sshbuf_free(encoded);
	ಮುಕ್ತ(ktype);
	ಪ್ರತ್ಯಾಗಮ r;
}

ಸ್ಥಿರ ಧ್ರುವ ಸಂರಚನಾ sshkey_impl_funcs sshkey_ed25519_sk_funcs = {
	/* .size = */		ರಿಕ್ತ,
	/* .alloc = */		ರಿಕ್ತ,
	/* .cleanup = */	ssh_ed25519_sk_cleanup,
	/* .equal = */		ssh_ed25519_sk_equal,
	/* .ssh_serialize_public = */ ssh_ed25519_sk_serialize_public,
	/* .ssh_deserialize_public = */ ssh_ed25519_sk_deserialize_public,
	/* .ssh_serialize_private = */ ssh_ed25519_sk_serialize_private,
	/* .ssh_deserialize_private = */ ssh_ed25519_sk_deserialize_private,
	/* .generate = */	ರಿಕ್ತ,
	/* .copy_public = */	ssh_ed25519_sk_copy_public,
	/* .sign = */		ರಿಕ್ತ,
	/* .verify = */		ssh_ed25519_sk_verify,
};

ಧ್ರುವ ಸಂರಚನಾ sshkey_impl sshkey_ed25519_sk_impl = {
	/* .name = */		"sk-ssh-ed25519@openssh.com",
	/* .shortname = */	"ED25519-SK",
	/* .sigalg = */		ರಿಕ್ತ,
	/* .type = */		ಕೀಲಿ_ED25519_SK,
	/* .nid = */		0,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	256,
	/* .funcs = */		&sshkey_ed25519_sk_funcs,
};

ಧ್ರುವ ಸಂರಚನಾ sshkey_impl sshkey_ed25519_sk_cert_impl = {
	/* .name = */		"sk-ssh-ed25519-cert-v01@openssh.com",
	/* .shortname = */	"ED25519-SK-CERT",
	/* .sigalg = */		ರಿಕ್ತ,
	/* .type = */		ಕೀಲಿ_ED25519_SK_CERT,
	/* .nid = */		0,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	256,
	/* .funcs = */		&sshkey_ed25519_sk_funcs,
};
