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

#अन्तर्भाव "includes.h"

#define SSHKEY_INTERNAL
#अन्तर्भाव <sys/types.h>

#अन्तर्भाव "crypto_api.h"

#अन्तर्भाव <string.h>
#अन्तर्भाव <stdarg.h>

#अन्तर्भाव "log.h"
#अन्तर्भाव "sshbuf.h"
#अन्तर्भाव "sshkey.h"
#अन्तर्भाव "ssherr.h"
#अन्तर्भाव "digest.h"

/* Reuse some ED25519 internals */
बाह्य संरचना sshkey_impl_funcs sshkey_ed25519_funcs;

स्थिर शून्य
ssh_ed25519_sk_cleanup(संरचना sshkey *k)
{
	sshkey_sk_cleanup(k);
	sshkey_ed25519_funcs.cleanup(k);
}

स्थिर पूर्णाङ्क
ssh_ed25519_sk_equal(ध्रुव संरचना sshkey *a, ध्रुव संरचना sshkey *b)
{
	यदि (!sshkey_sk_fields_equal(a, b))
		प्रत्यागम 0;
	यदि (!sshkey_ed25519_funcs.equal(a, b))
		प्रत्यागम 0;
	प्रत्यागम 1;
}

स्थिर पूर्णाङ्क
ssh_ed25519_sk_serialize_public(ध्रुव संरचना sshkey *कुंजी, संरचना sshbuf *b,
    गणना sshkey_serialize_rep opts)
{
	पूर्णाङ्क r;

	यदि ((r = sshkey_ed25519_funcs.serialize_public(कुंजी, b, opts)) != 0)
		प्रत्यागम r;
	यदि ((r = sshkey_serialize_sk(कुंजी, b)) != 0)
		प्रत्यागम r;

	प्रत्यागम 0;
}

स्थिर पूर्णाङ्क
ssh_ed25519_sk_serialize_private(ध्रुव संरचना sshkey *कुंजी, संरचना sshbuf *b,
    गणना sshkey_serialize_rep opts)
{
	पूर्णाङ्क r;

	यदि ((r = sshkey_ed25519_funcs.serialize_public(कुंजी, b, opts)) != 0)
		प्रत्यागम r;
	यदि ((r = sshkey_serialize_private_sk(कुंजी, b)) != 0)
		प्रत्यागम r;

	प्रत्यागम 0;
}

स्थिर पूर्णाङ्क
ssh_ed25519_sk_copy_public(ध्रुव संरचना sshkey *from, संरचना sshkey *to)
{
	पूर्णाङ्क r;

	यदि ((r = sshkey_ed25519_funcs.copy_public(from, to)) != 0)
		प्रत्यागम r;
	यदि ((r = sshkey_copy_public_sk(from, to)) != 0)
		प्रत्यागम r;
	प्रत्यागम 0;
}

स्थिर पूर्णाङ्क
ssh_ed25519_sk_deserialize_public(ध्रुव वर्ण *ktype, संरचना sshbuf *b,
    संरचना sshkey *कुंजी)
{
	पूर्णाङ्क r;

	यदि ((r = sshkey_ed25519_funcs.deserialize_public(ktype, b, कुंजी)) != 0)
		प्रत्यागम r;
	यदि ((r = sshkey_deserialize_sk(b, कुंजी)) != 0)
		प्रत्यागम r;
	प्रत्यागम 0;
}

स्थिर पूर्णाङ्क
ssh_ed25519_sk_deserialize_private(ध्रुव वर्ण *ktype, संरचना sshbuf *b,
    संरचना sshkey *कुंजी)
{
	पूर्णाङ्क r;

	यदि ((r = sshkey_ed25519_funcs.deserialize_public(ktype, b, कुंजी)) != 0)
		प्रत्यागम r;
	यदि ((r = sshkey_private_deserialize_sk(b, कुंजी)) != 0)
		प्रत्यागम r;
	प्रत्यागम 0;
}

स्थिर पूर्णाङ्क
ssh_ed25519_sk_verify(ध्रुव संरचना sshkey *कुंजी,
    ध्रुव u_char *sig, size_t siglen,
    ध्रुव u_char *data, size_t dlen, ध्रुव वर्ण *alg, u_int compat,
    संरचना sshkey_sig_details **detailsp)
{
	संरचना sshbuf *b = रिक्त;
	संरचना sshbuf *encoded = रिक्त;
	वर्ण *ktype = रिक्त;
	ध्रुव u_char *sigblob;
	u_char apphash[32];
	u_char msghash[32];
	u_char sig_flags;
	u_int sig_counter;
	size_t len;
	पूर्णाङ्क r = SSH_ERR_INTERNAL_ERROR;
	पूर्णाङ्क ret;
	संरचना sshkey_sig_details *details = रिक्त;

	यदि (detailsp != रिक्त)
		*detailsp = रिक्त;

	यदि (कुंजी == रिक्त ||
	    sshkey_type_plain(कुंजी->type) != कुंजी_ED25519_SK ||
	    कुंजी->ed25519_pk == रिक्त ||
	    sig == रिक्त || siglen == 0)
		प्रत्यागम SSH_ERR_INVALID_ARGUMENT;

	यदि ((b = sshbuf_from(sig, siglen)) == रिक्त)
		प्रत्यागम SSH_ERR_ALLOC_FAIL;
	यदि (sshbuf_get_cstring(b, &ktype, रिक्त) != 0 ||
	    sshbuf_get_string_direct(b, &sigblob, &len) != 0 ||
	    sshbuf_get_u8(b, &sig_flags) != 0 ||
	    sshbuf_get_u32(b, &sig_counter) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		गच्छ out;
	}
#ifdef DEBUG_SK
	fprintf(stderr, "%s: data:\n", __func__);
	/* sshbuf_dump_data(data, datalen, stderr); */
	fprintf(stderr, "%s: sigblob:\n", __func__);
	sshbuf_dump_data(sigblob, len, stderr);
	fprintf(stderr, "%s: sig_flags = 0x%02x, sig_counter = %u\n",
	    __func__, sig_flags, sig_counter);
#endif
	यदि (strcmp(sshkey_ssh_name_plain(कुंजी), ktype) != 0) {
		r = SSH_ERR_कुंजी_TYPE_MISMATCH;
		गच्छ out;
	}
	यदि (sshbuf_len(b) != 0) {
		r = SSH_ERR_UNEXPECTED_TRAILING_DATA;
		गच्छ out;
	}
	यदि (len != crypto_sign_ed25519_BYTES) {
		r = SSH_ERR_INVALID_FORMAT;
		गच्छ out;
	}
	यदि (ssh_digest_memory(SSH_DIGEST_SHA256, कुंजी->sk_application,
	    strlen(कुंजी->sk_application), apphash, परिमाण(apphash)) != 0 ||
	    ssh_digest_memory(SSH_DIGEST_SHA256, data, dlen,
	    msghash, परिमाण(msghash)) != 0) {
		r = SSH_ERR_INVALID_ARGUMENT;
		गच्छ out;
	}
#ifdef DEBUG_SK
	fprintf(stderr, "%s: hashed application:\n", __func__);
	sshbuf_dump_data(apphash, परिमाण(apphash), stderr);
	fprintf(stderr, "%s: hashed message:\n", __func__);
	sshbuf_dump_data(msghash, परिमाण(msghash), stderr);
#endif
	यदि ((details = calloc(1, परिमाण(*details))) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ out;
	}
	details->sk_counter = sig_counter;
	details->sk_flags = sig_flags;
	यदि ((encoded = sshbuf_new()) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ out;
	}
	यदि (sshbuf_put(encoded, apphash, परिमाण(apphash)) != 0 ||
	    sshbuf_put_u8(encoded, sig_flags) != 0 ||
	    sshbuf_put_u32(encoded, sig_counter) != 0 ||
	    sshbuf_put(encoded, msghash, परिमाण(msghash)) != 0) {
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ out;
	}
#ifdef DEBUG_SK
	fprintf(stderr, "%s: signed buf:\n", __func__);
	sshbuf_dump(encoded, stderr);
#endif
	यदि ((ret = crypto_sign_ed25519_verify_detached(sigblob,
	    sshbuf_ptr(encoded), sshbuf_len(encoded),
	    कुंजी->ed25519_pk)) != 0) {
		debug2_f("crypto_sign_ed25519_verify_detached failed: %d", ret);
	}
	यदि (ret != 0) {
		r = SSH_ERR_SIGNATURE_INVALID;
		गच्छ out;
	}
	/* success */
	r = 0;
	यदि (detailsp != रिक्त) {
		*detailsp = details;
		details = रिक्त;
	}
 out:
	sshkey_sig_details_free(details);
	sshbuf_free(b);
	sshbuf_free(encoded);
	मुक्त(ktype);
	प्रत्यागम r;
}

स्थिर ध्रुव संरचना sshkey_impl_funcs sshkey_ed25519_sk_funcs = {
	/* .size = */		रिक्त,
	/* .alloc = */		रिक्त,
	/* .cleanup = */	ssh_ed25519_sk_cleanup,
	/* .equal = */		ssh_ed25519_sk_equal,
	/* .ssh_serialize_public = */ ssh_ed25519_sk_serialize_public,
	/* .ssh_deserialize_public = */ ssh_ed25519_sk_deserialize_public,
	/* .ssh_serialize_private = */ ssh_ed25519_sk_serialize_private,
	/* .ssh_deserialize_private = */ ssh_ed25519_sk_deserialize_private,
	/* .generate = */	रिक्त,
	/* .copy_public = */	ssh_ed25519_sk_copy_public,
	/* .sign = */		रिक्त,
	/* .verify = */		ssh_ed25519_sk_verify,
};

ध्रुव संरचना sshkey_impl sshkey_ed25519_sk_impl = {
	/* .name = */		"sk-ssh-ed25519@openssh.com",
	/* .shortname = */	"ED25519-SK",
	/* .sigalg = */		रिक्त,
	/* .type = */		कुंजी_ED25519_SK,
	/* .nid = */		0,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	256,
	/* .funcs = */		&sshkey_ed25519_sk_funcs,
};

ध्रुव संरचना sshkey_impl sshkey_ed25519_sk_cert_impl = {
	/* .name = */		"sk-ssh-ed25519-cert-v01@openssh.com",
	/* .shortname = */	"ED25519-SK-CERT",
	/* .sigalg = */		रिक्त,
	/* .type = */		कुंजी_ED25519_SK_CERT,
	/* .nid = */		0,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	256,
	/* .funcs = */		&sshkey_ed25519_sk_funcs,
};
