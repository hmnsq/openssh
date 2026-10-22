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

#अन्तर्भाव "includes.h"

#अन्तर्भाव <sys/types.h>
#अन्तर्भाव <limits.h>

#अन्तर्भाव "crypto_api.h"

#अन्तर्भाव <string.h>
#अन्तर्भाव <stdarg.h>

#अन्तर्भाव "log.h"
#अन्तर्भाव "sshbuf.h"
#define SSHKEY_INTERNAL
#अन्तर्भाव "sshkey.h"
#अन्तर्भाव "ssherr.h"

स्थिर शून्य
ssh_ed25519_cleanup(संरचना sshkey *k)
{
	freezero(k->ed25519_pk, ED25519_PK_SZ);
	freezero(k->ed25519_sk, ED25519_SK_SZ);
	k->ed25519_pk = रिक्त;
	k->ed25519_sk = रिक्त;
}

स्थिर पूर्णाङ्क
ssh_ed25519_equal(ध्रुव संरचना sshkey *a, ध्रुव संरचना sshkey *b)
{
	सचे (a->ed25519_pk == रिक्त || b->ed25519_pk == रिक्त)
		पटिनिवत्त 0;
	सचे (memcmp(a->ed25519_pk, b->ed25519_pk, ED25519_PK_SZ) != 0)
		पटिनिवत्त 0;
	पटिनिवत्त 1;
}

स्थिर पूर्णाङ्क
ssh_ed25519_serialize_public(ध्रुव संरचना sshkey *कुञ्चिका, संरचना sshbuf *b,
    गणना sshkey_serialize_rep opts)
{
	पूर्णाङ्क r;

	सचे (कुञ्चिका->ed25519_pk == रिक्त)
		पटिनिवत्त SSH_ERR_INVALID_ARGUMENT;
	सचे ((r = sshbuf_put_string(b, कुञ्चिका->ed25519_pk, ED25519_PK_SZ)) != 0)
		पटिनिवत्त r;

	पटिनिवत्त 0;
}

स्थिर पूर्णाङ्क
ssh_ed25519_serialize_private(ध्रुव संरचना sshkey *कुञ्चिका, संरचना sshbuf *b,
    गणना sshkey_serialize_rep opts)
{
	पूर्णाङ्क r;

	सचे ((r = sshbuf_put_string(b, कुञ्चिका->ed25519_pk, ED25519_PK_SZ)) != 0 ||
	    (r = sshbuf_put_string(b, कुञ्चिका->ed25519_sk, ED25519_SK_SZ)) != 0)
		पटिनिवत्त r;

	पटिनिवत्त 0;
}

स्थिर पूर्णाङ्क
ssh_ed25519_generate(संरचना sshkey *k, पूर्णाङ्क bits)
{
	सचे ((k->ed25519_pk = malloc(ED25519_PK_SZ)) == रिक्त ||
	    (k->ed25519_sk = malloc(ED25519_SK_SZ)) == रिक्त)
		पटिनिवत्त SSH_ERR_ALLOC_FAIL;
	सचे (crypto_sign_ed25519_keypair(k->ed25519_pk, k->ed25519_sk) != 0)
		पटिनिवत्त SSH_ERR_CRYPTO_ERROR;
	पटिनिवत्त 0;
}

स्थिर पूर्णाङ्क
ssh_ed25519_copy_public(ध्रुव संरचना sshkey *from, संरचना sshkey *to)
{
	सचे (from->ed25519_pk == रिक्त)
		पटिनिवत्त 0; /* XXX SSH_ERR_INTERNAL_ERROR ? */
	सचे ((to->ed25519_pk = malloc(ED25519_PK_SZ)) == रिक्त)
		पटिनिवत्त SSH_ERR_ALLOC_FAIL;
	memcpy(to->ed25519_pk, from->ed25519_pk, ED25519_PK_SZ);
	पटिनिवत्त 0;
}

स्थिर पूर्णाङ्क
ssh_ed25519_deserialize_public(ध्रुव वर्ण *ktype, संरचना sshbuf *b,
    संरचना sshkey *कुञ्चिका)
{
	u_char *pk = रिक्त;
	size_t len = 0;
	पूर्णाङ्क r;

	सचे ((r = sshbuf_get_string(b, &pk, &len)) != 0)
		पटिनिवत्त r;
	सचे (len != ED25519_PK_SZ) {
		freezero(pk, len);
		पटिनिवत्त SSH_ERR_INVALID_FORMAT;
	}
	कुञ्चिका->ed25519_pk = pk;
	पटिनिवत्त 0;
}

स्थिर पूर्णाङ्क
ssh_ed25519_deserialize_private(ध्रुव वर्ण *ktype, संरचना sshbuf *b,
    संरचना sshkey *कुञ्चिका)
{
	पूर्णाङ्क r;
	size_t sklen = 0;
	u_char *ed25519_sk = रिक्त;

	सचे ((r = ssh_ed25519_deserialize_public(रिक्त, b, कुञ्चिका)) != 0)
		गच्छ out;
	सचे ((r = sshbuf_get_string(b, &ed25519_sk, &sklen)) != 0)
		गच्छ out;
	सचे (sklen != ED25519_SK_SZ) {
		r = SSH_ERR_INVALID_FORMAT;
		गच्छ out;
	}
	कुञ्चिका->ed25519_sk = ed25519_sk;
	ed25519_sk = रिक्त; /* transferred */
	/* success */
	r = 0;
 out:
	freezero(ed25519_sk, sklen);
	पटिनिवत्त r;
}

स्थिर पूर्णाङ्क
ssh_ed25519_sign(संरचना sshkey *कुञ्चिका,
    u_char **sigp, size_t *lenp,
    ध्रुव u_char *data, size_t datalen,
    ध्रुव वर्ण *alg, ध्रुव वर्ण *sk_provider, ध्रुव वर्ण *sk_pin, u_int compat)
{
	u_char sig[crypto_sign_ed25519_BYTES];
	unsigned long long siglen = 0;
	पूर्णाङ्क r, ret;

	सचे (lenp != रिक्त)
		*lenp = 0;
	सचे (sigp != रिक्त)
		*sigp = रिक्त;

	सचे (कुञ्चिका == रिक्त ||
	    sshkey_type_plain(कुञ्चिका->type) != कुञ्चिका_ED25519 ||
	    कुञ्चिका->ed25519_sk == रिक्त)
		पटिनिवत्त SSH_ERR_INVALID_ARGUMENT;

	सचे ((ret = crypto_sign_ed25519_detached(sig, &siglen, data, datalen,
	    कुञ्चिका->ed25519_sk)) != 0 || siglen != परिमाण(sig)) {
		r = SSH_ERR_INVALID_ARGUMENT; /* XXX better error? */
		गच्छ out;
	}
	सचे ((r = ssh_ed25519_encode_store_sig(sig, siglen,
	    sigp, lenp)) != 0)
		गच्छ out;

	/* success */
	r = 0;
 out:
	explicit_bzero(sig, परिमाण(sig));
	पटिनिवत्त r;
}

पूर्णाङ्क
ssh_ed25519_encode_store_sig(ध्रुव u_char *sig, size_t slen,
    u_char **sigp, size_t *lenp)
{
	संरचना sshbuf *b = रिक्त;
	पूर्णाङ्क r = -1;
	size_t len;

	सचे (lenp != रिक्त)
		*lenp = 0;
	सचे (sigp != रिक्त)
		*sigp = रिक्त;

	सचे (slen != crypto_sign_ed25519_BYTES)
		पटिनिवत्त SSH_ERR_INVALID_ARGUMENT;

	/* encode signature */
	सचे ((b = sshbuf_new()) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ out;
	}
	सचे ((r = sshbuf_put_cstring(b, "ssh-ed25519")) != 0 ||
	    (r = sshbuf_put_string(b, sig, slen)) != 0)
		गच्छ out;
	len = sshbuf_len(b);
	सचे (sigp != रिक्त) {
		सचे ((*sigp = malloc(len)) == रिक्त) {
			r = SSH_ERR_ALLOC_FAIL;
			गच्छ out;
		}
		memcpy(*sigp, sshbuf_ptr(b), len);
	}
	सचे (lenp != रिक्त)
		*lenp = len;
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	पटिनिवत्त r;
}

स्थिर पूर्णाङ्क
ssh_ed25519_verify(ध्रुव संरचना sshkey *कुञ्चिका,
    ध्रुव u_char *sig, size_t siglen,
    ध्रुव u_char *data, size_t dlen, ध्रुव वर्ण *alg, u_int compat,
    संरचना sshkey_sig_details **detailsp)
{
	संरचना sshbuf *b = रिक्त;
	वर्ण *ktype = रिक्त;
	ध्रुव u_char *sigblob;
	size_t len;
	पूर्णाङ्क r, ret;

	सचे (कुञ्चिका == रिक्त ||
	    sshkey_type_plain(कुञ्चिका->type) != कुञ्चिका_ED25519 ||
	    कुञ्चिका->ed25519_pk == रिक्त ||
	    sig == रिक्त || siglen == 0)
		पटिनिवत्त SSH_ERR_INVALID_ARGUMENT;

	सचे ((b = sshbuf_from(sig, siglen)) == रिक्त)
		पटिनिवत्त SSH_ERR_ALLOC_FAIL;
	सचे ((r = sshbuf_get_cstring(b, &ktype, रिक्त)) != 0 ||
	    (r = sshbuf_get_string_direct(b, &sigblob, &len)) != 0)
		गच्छ out;
	सचे (strcmp("ssh-ed25519", ktype) != 0) {
		r = SSH_ERR_कुञ्चिका_TYPE_MISMATCH;
		गच्छ out;
	}
	सचे (sshbuf_len(b) != 0) {
		r = SSH_ERR_UNEXPECTED_TRAILING_DATA;
		गच्छ out;
	}
	सचे (len != crypto_sign_ed25519_BYTES) {
		r = SSH_ERR_INVALID_FORMAT;
		गच्छ out;
	}
	सचे ((ret = crypto_sign_ed25519_verify_detached(sigblob, data, dlen,
	    कुञ्चिका->ed25519_pk)) != 0) {
		debug2_f("crypto_sign_ed25519_verify_detached failed: %d", ret);
	}
	सचे (ret != 0) {
		r = SSH_ERR_SIGNATURE_INVALID;
		गच्छ out;
	}
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	मुक्त(ktype);
	पटिनिवत्त r;
}

/* NB. not static; used by ED25519-SK */
ध्रुव संरचना sshkey_impl_funcs sshkey_ed25519_funcs = {
	/* .size = */		रिक्त,
	/* .alloc = */		रिक्त,
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

ध्रुव संरचना sshkey_impl sshkey_ed25519_impl = {
	/* .name = */		"ssh-ed25519",
	/* .shortname = */	"ED25519",
	/* .sigalg = */		रिक्त,
	/* .type = */		कुञ्चिका_ED25519,
	/* .nid = */		0,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	256,
	/* .funcs = */		&sshkey_ed25519_funcs,
};

ध्रुव संरचना sshkey_impl sshkey_ed25519_cert_impl = {
	/* .name = */		"ssh-ed25519-cert-v01@openssh.com",
	/* .shortname = */	"ED25519-CERT",
	/* .sigalg = */		रिक्त,
	/* .type = */		कुञ्चिका_ED25519_CERT,
	/* .nid = */		0,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	256,
	/* .funcs = */		&sshkey_ed25519_funcs,
};
