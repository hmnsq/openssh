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
#परिभाषय SSHKEY_आन्तरिकम्
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
	यदि (a->ed25519_pk == रिक्त || b->ed25519_pk == रिक्त)
		प्रत्यागम 0;
	यदि (memcmp(a->ed25519_pk, b->ed25519_pk, ED25519_PK_SZ) != 0)
		प्रत्यागम 0;
	प्रत्यागम 1;
}

स्थिर पूर्णाङ्क
ssh_ed25519_serialize_लौकिकम्(ध्रुव संरचना sshkey *कुञ्चिका, संरचना sshbuf *b,
    गणना sshkey_serialize_rep opts)
{
	पूर्णाङ्क r;

	यदि (कुञ्चिका->ed25519_pk == रिक्त)
		प्रत्यागम SSH_ERR_INVALID_तर्कः;
	यदि ((r = sshbuf_put_string(b, कुञ्चिका->ed25519_pk, ED25519_PK_SZ)) != 0)
		प्रत्यागम r;

	प्रत्यागम 0;
}

स्थिर पूर्णाङ्क
ssh_ed25519_serialize_वैयक्तिकम्(ध्रुव संरचना sshkey *कुञ्चिका, संरचना sshbuf *b,
    गणना sshkey_serialize_rep opts)
{
	पूर्णाङ्क r;

	यदि ((r = sshbuf_put_string(b, कुञ्चिका->ed25519_pk, ED25519_PK_SZ)) != 0 ||
	    (r = sshbuf_put_string(b, कुञ्चिका->ed25519_sk, ED25519_SK_SZ)) != 0)
		प्रत्यागम r;

	प्रत्यागम 0;
}

स्थिर पूर्णाङ्क
ssh_ed25519_generate(संरचना sshkey *k, पूर्णाङ्क द्वयङ्काः)
{
	यदि ((k->ed25519_pk = स्मृतिं_देहि(ED25519_PK_SZ)) == रिक्त ||
	    (k->ed25519_sk = स्मृतिं_देहि(ED25519_SK_SZ)) == रिक्त)
		प्रत्यागम SSH_ERR_ALLOC_FAIL;
	यदि (crypto_sign_ed25519_keypair(k->ed25519_pk, k->ed25519_sk) != 0)
		प्रत्यागम SSH_ERR_CRYPTO_ERROR;
	प्रत्यागम 0;
}

स्थिर पूर्णाङ्क
ssh_ed25519_copy_लौकिकम्(ध्रुव संरचना sshkey *from, संरचना sshkey *गन्तव्यम्)
{
	यदि (from->ed25519_pk == रिक्त)
		प्रत्यागम 0; /* XXX SSH_ERR_INTERNAL_ERROR ? */
	यदि ((गन्तव्यम्->ed25519_pk = स्मृतिं_देहि(ED25519_PK_SZ)) == रिक्त)
		प्रत्यागम SSH_ERR_ALLOC_FAIL;
	स्मृतिं_प्रतिलिख(गन्तव्यम्->ed25519_pk, from->ed25519_pk, ED25519_PK_SZ);
	प्रत्यागम 0;
}

स्थिर पूर्णाङ्क
ssh_ed25519_deserialize_लौकिकम्(ध्रुव वर्ण *ktype, संरचना sshbuf *b,
    संरचना sshkey *कुञ्चिका)
{
	u_char *pk = रिक्त;
	आकार_t len = 0;
	पूर्णाङ्क r;

	यदि ((r = sshbuf_get_string(b, &pk, &len)) != 0)
		प्रत्यागम r;
	यदि (len != ED25519_PK_SZ) {
		freezero(pk, len);
		प्रत्यागम SSH_ERR_INVALID_FORMAT;
	}
	कुञ्चिका->ed25519_pk = pk;
	प्रत्यागम 0;
}

स्थिर पूर्णाङ्क
ssh_ed25519_deserialize_वैयक्तिकम्(ध्रुव वर्ण *ktype, संरचना sshbuf *b,
    संरचना sshkey *कुञ्चिका)
{
	पूर्णाङ्क r;
	आकार_t sklen = 0;
	u_char *ed25519_sk = रिक्त;

	यदि ((r = ssh_ed25519_deserialize_लौकिकम्(रिक्त, b, कुञ्चिका)) != 0)
		गच्छ बहिर्गमनम्;
	यदि ((r = sshbuf_get_string(b, &ed25519_sk, &sklen)) != 0)
		गच्छ बहिर्गमनम्;
	यदि (sklen != ED25519_SK_SZ) {
		r = SSH_ERR_INVALID_FORMAT;
		गच्छ बहिर्गमनम्;
	}
	कुञ्चिका->ed25519_sk = ed25519_sk;
	ed25519_sk = रिक्त; /* transferred */
	/* success */
	r = 0;
 बहिर्गमनम्:
	freezero(ed25519_sk, sklen);
	प्रत्यागम r;
}

स्थिर पूर्णाङ्क
ssh_ed25519_sign(संरचना sshkey *कुञ्चिका,
    u_char **sigp, आकार_t *lenp,
    ध्रुव u_char *दत्त, आकार_t datalen,
    ध्रुव वर्ण *alg, ध्रुव वर्ण *sk_provider, ध्रुव वर्ण *sk_pin, u_int compat)
{
	u_char sig[crypto_sign_ed25519_अष्टकानि];
	अचिह्नित दीर्घ दीर्घ siglen = 0;
	पूर्णाङ्क r, ret;

	यदि (lenp != रिक्त)
		*lenp = 0;
	यदि (sigp != रिक्त)
		*sigp = रिक्त;

	यदि (कुञ्चिका == रिक्त ||
	    sshkey_type_plain(कुञ्चिका->type) != कुञ्चिका_ED25519 ||
	    कुञ्चिका->ed25519_sk == रिक्त)
		प्रत्यागम SSH_ERR_INVALID_तर्कः;

	यदि ((ret = crypto_sign_ed25519_detached(sig, &siglen, दत्त, datalen,
	    कुञ्चिका->ed25519_sk)) != 0 || siglen != परिमाण(sig)) {
		r = SSH_ERR_INVALID_तर्कः; /* XXX better error? */
		गच्छ बहिर्गमनम्;
	}
	यदि ((r = ssh_ed25519_encode_store_sig(sig, siglen,
	    sigp, lenp)) != 0)
		गच्छ बहिर्गमनम्;

	/* success */
	r = 0;
 बहिर्गमनम्:
	explicit_bzero(sig, परिमाण(sig));
	प्रत्यागम r;
}

पूर्णाङ्क
ssh_ed25519_encode_store_sig(ध्रुव u_char *sig, आकार_t slen,
    u_char **sigp, आकार_t *lenp)
{
	संरचना sshbuf *b = रिक्त;
	पूर्णाङ्क r = -1;
	आकार_t len;

	यदि (lenp != रिक्त)
		*lenp = 0;
	यदि (sigp != रिक्त)
		*sigp = रिक्त;

	यदि (slen != crypto_sign_ed25519_अष्टकानि)
		प्रत्यागम SSH_ERR_INVALID_तर्कः;

	/* encode signature */
	यदि ((b = sshbuf_new()) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ बहिर्गमनम्;
	}
	यदि ((r = sshbuf_put_cstring(b, "ssh-ed25519")) != 0 ||
	    (r = sshbuf_put_string(b, sig, slen)) != 0)
		गच्छ बहिर्गमनम्;
	len = sshbuf_len(b);
	यदि (sigp != रिक्त) {
		यदि ((*sigp = स्मृतिं_देहि(len)) == रिक्त) {
			r = SSH_ERR_ALLOC_FAIL;
			गच्छ बहिर्गमनम्;
		}
		स्मृतिं_प्रतिलिख(*sigp, sshbuf_ptr(b), len);
	}
	यदि (lenp != रिक्त)
		*lenp = len;
	/* success */
	r = 0;
 बहिर्गमनम्:
	sshbuf_free(b);
	प्रत्यागम r;
}

स्थिर पूर्णाङ्क
ssh_ed25519_verify(ध्रुव संरचना sshkey *कुञ्चिका,
    ध्रुव u_char *sig, आकार_t siglen,
    ध्रुव u_char *दत्त, आकार_t dlen, ध्रुव वर्ण *alg, u_int compat,
    संरचना sshkey_sig_details **detailsp)
{
	संरचना sshbuf *b = रिक्त;
	वर्ण *ktype = रिक्त;
	ध्रुव u_char *sigblob;
	आकार_t len;
	पूर्णाङ्क r, ret;

	यदि (कुञ्चिका == रिक्त ||
	    sshkey_type_plain(कुञ्चिका->type) != कुञ्चिका_ED25519 ||
	    कुञ्चिका->ed25519_pk == रिक्त ||
	    sig == रिक्त || siglen == 0)
		प्रत्यागम SSH_ERR_INVALID_तर्कः;

	यदि ((b = sshbuf_from(sig, siglen)) == रिक्त)
		प्रत्यागम SSH_ERR_ALLOC_FAIL;
	यदि ((r = sshbuf_get_cstring(b, &ktype, रिक्त)) != 0 ||
	    (r = sshbuf_get_string_प्रत्यक्षम्(b, &sigblob, &len)) != 0)
		गच्छ बहिर्गमनम्;
	यदि (वाक्यं_तुलय("ssh-ed25519", ktype) != 0) {
		r = SSH_ERR_कुञ्चिका_TYPE_MISMATCH;
		गच्छ बहिर्गमनम्;
	}
	यदि (sshbuf_len(b) != 0) {
		r = SSH_ERR_UNEXPECTED_TRAILING_दत्त;
		गच्छ बहिर्गमनम्;
	}
	यदि (len != crypto_sign_ed25519_अष्टकानि) {
		r = SSH_ERR_INVALID_FORMAT;
		गच्छ बहिर्गमनम्;
	}
	यदि ((ret = crypto_sign_ed25519_verify_detached(sigblob, दत्त, dlen,
	    कुञ्चिका->ed25519_pk)) != 0) {
		debug2_f("crypto_sign_ed25519_verify_detached failed: %d", ret);
	}
	यदि (ret != 0) {
		r = SSH_ERR_SIGNATURE_INVALID;
		गच्छ बहिर्गमनम्;
	}
	/* success */
	r = 0;
 बहिर्गमनम्:
	sshbuf_free(b);
	मुक्त(ktype);
	प्रत्यागम r;
}

/* NB. not static; used by ED25519-SK */
ध्रुव संरचना sshkey_impl_funcs sshkey_ed25519_funcs = {
	/* .size = */		रिक्त,
	/* .alloc = */		रिक्त,
	/* .cleanup = */	ssh_ed25519_cleanup,
	/* .equal = */		ssh_ed25519_equal,
	/* .ssh_serialize_public = */ ssh_ed25519_serialize_लौकिकम्,
	/* .ssh_deserialize_public = */ ssh_ed25519_deserialize_लौकिकम्,
	/* .ssh_serialize_private = */ ssh_ed25519_serialize_वैयक्तिकम्,
	/* .ssh_deserialize_private = */ ssh_ed25519_deserialize_वैयक्तिकम्,
	/* .generate = */	ssh_ed25519_generate,
	/* .copy_public = */	ssh_ed25519_copy_लौकिकम्,
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
