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

स्थिर पूर्णांक
ssh_ed25519_equal(स्थिरांक संरचना sshkey *a, स्थिरांक संरचना sshkey *b)
{
	जर (a->ed25519_pk == रिक्त || b->ed25519_pk == रिक्त)
		परत 0;
	जर (स_भेद(a->ed25519_pk, b->ed25519_pk, ED25519_PK_SZ) != 0)
		परत 0;
	परत 1;
}

स्थिर पूर्णांक
ssh_ed25519_serialize_public(स्थिरांक संरचना sshkey *किल्ली, संरचना sshbuf *b,
    गणना sshkey_serialize_rep opts)
{
	पूर्णांक r;

	जर (किल्ली->ed25519_pk == रिक्त)
		परत SSH_ERR_INVALID_ARGUMENT;
	जर ((r = sshbuf_put_string(b, किल्ली->ed25519_pk, ED25519_PK_SZ)) != 0)
		परत r;

	परत 0;
}

स्थिर पूर्णांक
ssh_ed25519_serialize_private(स्थिरांक संरचना sshkey *किल्ली, संरचना sshbuf *b,
    गणना sshkey_serialize_rep opts)
{
	पूर्णांक r;

	जर ((r = sshbuf_put_string(b, किल्ली->ed25519_pk, ED25519_PK_SZ)) != 0 ||
	    (r = sshbuf_put_string(b, किल्ली->ed25519_sk, ED25519_SK_SZ)) != 0)
		परत r;

	परत 0;
}

स्थिर पूर्णांक
ssh_ed25519_generate(संरचना sshkey *k, पूर्णांक bits)
{
	जर ((k->ed25519_pk = दो_स्मृति(ED25519_PK_SZ)) == रिक्त ||
	    (k->ed25519_sk = दो_स्मृति(ED25519_SK_SZ)) == रिक्त)
		परत SSH_ERR_ALLOC_FAIL;
	जर (crypto_sign_ed25519_keypair(k->ed25519_pk, k->ed25519_sk) != 0)
		परत SSH_ERR_CRYPTO_ERROR;
	परत 0;
}

स्थिर पूर्णांक
ssh_ed25519_copy_public(स्थिरांक संरचना sshkey *from, संरचना sshkey *to)
{
	जर (from->ed25519_pk == रिक्त)
		परत 0; /* XXX SSH_ERR_INTERNAL_ERROR ? */
	जर ((to->ed25519_pk = दो_स्मृति(ED25519_PK_SZ)) == रिक्त)
		परत SSH_ERR_ALLOC_FAIL;
	स_नकल(to->ed25519_pk, from->ed25519_pk, ED25519_PK_SZ);
	परत 0;
}

स्थिर पूर्णांक
ssh_ed25519_deserialize_public(स्थिरांक अक्षर *ktype, संरचना sshbuf *b,
    संरचना sshkey *किल्ली)
{
	u_char *pk = रिक्त;
	माप_प्रकार len = 0;
	पूर्णांक r;

	जर ((r = sshbuf_get_string(b, &pk, &len)) != 0)
		परत r;
	जर (len != ED25519_PK_SZ) {
		freezero(pk, len);
		परत SSH_ERR_INVALID_FORMAT;
	}
	किल्ली->ed25519_pk = pk;
	परत 0;
}

स्थिर पूर्णांक
ssh_ed25519_deserialize_private(स्थिरांक अक्षर *ktype, संरचना sshbuf *b,
    संरचना sshkey *किल्ली)
{
	पूर्णांक r;
	माप_प्रकार sklen = 0;
	u_char *ed25519_sk = रिक्त;

	जर ((r = ssh_ed25519_deserialize_public(रिक्त, b, किल्ली)) != 0)
		जा out;
	जर ((r = sshbuf_get_string(b, &ed25519_sk, &sklen)) != 0)
		जा out;
	जर (sklen != ED25519_SK_SZ) {
		r = SSH_ERR_INVALID_FORMAT;
		जा out;
	}
	किल्ली->ed25519_sk = ed25519_sk;
	ed25519_sk = रिक्त; /* transferred */
	/* success */
	r = 0;
 out:
	freezero(ed25519_sk, sklen);
	परत r;
}

स्थिर पूर्णांक
ssh_ed25519_sign(संरचना sshkey *किल्ली,
    u_char **sigp, माप_प्रकार *lenp,
    स्थिरांक u_char *data, माप_प्रकार datalen,
    स्थिरांक अक्षर *alg, स्थिरांक अक्षर *sk_provider, स्थिरांक अक्षर *sk_pin, u_int compat)
{
	u_char sig[crypto_sign_ed25519_BYTES];
	अचिन्हित दीर्घ दीर्घ siglen = 0;
	पूर्णांक r, ret;

	जर (lenp != रिक्त)
		*lenp = 0;
	जर (sigp != रिक्त)
		*sigp = रिक्त;

	जर (किल्ली == रिक्त ||
	    sshkey_type_plain(किल्ली->type) != किल्ली_ED25519 ||
	    किल्ली->ed25519_sk == रिक्त)
		परत SSH_ERR_INVALID_ARGUMENT;

	जर ((ret = crypto_sign_ed25519_detached(sig, &siglen, data, datalen,
	    किल्ली->ed25519_sk)) != 0 || siglen != आकार(sig)) {
		r = SSH_ERR_INVALID_ARGUMENT; /* XXX better error? */
		जा out;
	}
	जर ((r = ssh_ed25519_encode_store_sig(sig, siglen,
	    sigp, lenp)) != 0)
		जा out;

	/* success */
	r = 0;
 out:
	explicit_bzero(sig, आकार(sig));
	परत r;
}

पूर्णांक
ssh_ed25519_encode_store_sig(स्थिरांक u_char *sig, माप_प्रकार slen,
    u_char **sigp, माप_प्रकार *lenp)
{
	संरचना sshbuf *b = रिक्त;
	पूर्णांक r = -1;
	माप_प्रकार len;

	जर (lenp != रिक्त)
		*lenp = 0;
	जर (sigp != रिक्त)
		*sigp = रिक्त;

	जर (slen != crypto_sign_ed25519_BYTES)
		परत SSH_ERR_INVALID_ARGUMENT;

	/* encode signature */
	जर ((b = sshbuf_new()) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		जा out;
	}
	जर ((r = sshbuf_put_cstring(b, "ssh-ed25519")) != 0 ||
	    (r = sshbuf_put_string(b, sig, slen)) != 0)
		जा out;
	len = sshbuf_len(b);
	जर (sigp != रिक्त) {
		जर ((*sigp = दो_स्मृति(len)) == रिक्त) {
			r = SSH_ERR_ALLOC_FAIL;
			जा out;
		}
		स_नकल(*sigp, sshbuf_ptr(b), len);
	}
	जर (lenp != रिक्त)
		*lenp = len;
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	परत r;
}

स्थिर पूर्णांक
ssh_ed25519_verify(स्थिरांक संरचना sshkey *किल्ली,
    स्थिरांक u_char *sig, माप_प्रकार siglen,
    स्थिरांक u_char *data, माप_प्रकार dlen, स्थिरांक अक्षर *alg, u_int compat,
    संरचना sshkey_sig_details **detailsp)
{
	संरचना sshbuf *b = रिक्त;
	अक्षर *ktype = रिक्त;
	स्थिरांक u_char *sigblob;
	माप_प्रकार len;
	पूर्णांक r, ret;

	जर (किल्ली == रिक्त ||
	    sshkey_type_plain(किल्ली->type) != किल्ली_ED25519 ||
	    किल्ली->ed25519_pk == रिक्त ||
	    sig == रिक्त || siglen == 0)
		परत SSH_ERR_INVALID_ARGUMENT;

	जर ((b = sshbuf_from(sig, siglen)) == रिक्त)
		परत SSH_ERR_ALLOC_FAIL;
	जर ((r = sshbuf_get_cstring(b, &ktype, रिक्त)) != 0 ||
	    (r = sshbuf_get_string_direct(b, &sigblob, &len)) != 0)
		जा out;
	जर (म_भेद("ssh-ed25519", ktype) != 0) {
		r = SSH_ERR_किल्ली_TYPE_MISMATCH;
		जा out;
	}
	जर (sshbuf_len(b) != 0) {
		r = SSH_ERR_UNEXPECTED_TRAILING_DATA;
		जा out;
	}
	जर (len != crypto_sign_ed25519_BYTES) {
		r = SSH_ERR_INVALID_FORMAT;
		जा out;
	}
	जर ((ret = crypto_sign_ed25519_verify_detached(sigblob, data, dlen,
	    किल्ली->ed25519_pk)) != 0) {
		debug2_f("crypto_sign_ed25519_verify_detached failed: %d", ret);
	}
	जर (ret != 0) {
		r = SSH_ERR_SIGNATURE_INVALID;
		जा out;
	}
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	मुक्त(ktype);
	परत r;
}

/* NB. not static; used by ED25519-SK */
स्थिरांक संरचना sshkey_impl_funcs sshkey_ed25519_funcs = {
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

स्थिरांक संरचना sshkey_impl sshkey_ed25519_impl = {
	/* .name = */		"ssh-ed25519",
	/* .shortname = */	"ED25519",
	/* .sigalg = */		रिक्त,
	/* .type = */		किल्ली_ED25519,
	/* .nid = */		0,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	256,
	/* .funcs = */		&sshkey_ed25519_funcs,
};

स्थिरांक संरचना sshkey_impl sshkey_ed25519_cert_impl = {
	/* .name = */		"ssh-ed25519-cert-v01@openssh.com",
	/* .shortname = */	"ED25519-CERT",
	/* .sigalg = */		रिक्त,
	/* .type = */		किल्ली_ED25519_CERT,
	/* .nid = */		0,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	256,
	/* .funcs = */		&sshkey_ed25519_funcs,
};
