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
ssh_ed25519_equal(अचर संरचना sshkey *a, अचर संरचना sshkey *b)
{
	यदि (a->ed25519_pk == रिक्त || b->ed25519_pk == रिक्त)
		फर्काऊ 0;
	यदि (स_भेद(a->ed25519_pk, b->ed25519_pk, ED25519_PK_SZ) != 0)
		फर्काऊ 0;
	फर्काऊ 1;
}

स्थिर पूर्णाङ्क
ssh_ed25519_serialize_public(अचर संरचना sshkey *साँचो, संरचना sshbuf *b,
    गणना sshkey_serialize_rep opts)
{
	पूर्णाङ्क r;

	यदि (साँचो->ed25519_pk == रिक्त)
		फर्काऊ SSH_ERR_INVALID_ARGUMENT;
	यदि ((r = sshbuf_put_string(b, साँचो->ed25519_pk, ED25519_PK_SZ)) != 0)
		फर्काऊ r;

	फर्काऊ 0;
}

स्थिर पूर्णाङ्क
ssh_ed25519_serialize_private(अचर संरचना sshkey *साँचो, संरचना sshbuf *b,
    गणना sshkey_serialize_rep opts)
{
	पूर्णाङ्क r;

	यदि ((r = sshbuf_put_string(b, साँचो->ed25519_pk, ED25519_PK_SZ)) != 0 ||
	    (r = sshbuf_put_string(b, साँचो->ed25519_sk, ED25519_SK_SZ)) != 0)
		फर्काऊ r;

	फर्काऊ 0;
}

स्थिर पूर्णाङ्क
ssh_ed25519_generate(संरचना sshkey *k, पूर्णाङ्क bits)
{
	यदि ((k->ed25519_pk = दो_स्मृति(ED25519_PK_SZ)) == रिक्त ||
	    (k->ed25519_sk = दो_स्मृति(ED25519_SK_SZ)) == रिक्त)
		फर्काऊ SSH_ERR_ALLOC_FAIL;
	यदि (crypto_sign_ed25519_keypair(k->ed25519_pk, k->ed25519_sk) != 0)
		फर्काऊ SSH_ERR_CRYPTO_ERROR;
	फर्काऊ 0;
}

स्थिर पूर्णाङ्क
ssh_ed25519_copy_public(अचर संरचना sshkey *from, संरचना sshkey *to)
{
	यदि (from->ed25519_pk == रिक्त)
		फर्काऊ 0; /* XXX SSH_ERR_INTERNAL_ERROR ? */
	यदि ((to->ed25519_pk = दो_स्मृति(ED25519_PK_SZ)) == रिक्त)
		फर्काऊ SSH_ERR_ALLOC_FAIL;
	स_नकल(to->ed25519_pk, from->ed25519_pk, ED25519_PK_SZ);
	फर्काऊ 0;
}

स्थिर पूर्णाङ्क
ssh_ed25519_deserialize_public(अचर वर्ण *ktype, संरचना sshbuf *b,
    संरचना sshkey *साँचो)
{
	u_char *pk = रिक्त;
	माप_प्रकार len = 0;
	पूर्णाङ्क r;

	यदि ((r = sshbuf_get_string(b, &pk, &len)) != 0)
		फर्काऊ r;
	यदि (len != ED25519_PK_SZ) {
		freezero(pk, len);
		फर्काऊ SSH_ERR_INVALID_FORMAT;
	}
	साँचो->ed25519_pk = pk;
	फर्काऊ 0;
}

स्थिर पूर्णाङ्क
ssh_ed25519_deserialize_private(अचर वर्ण *ktype, संरचना sshbuf *b,
    संरचना sshkey *साँचो)
{
	पूर्णाङ्क r;
	माप_प्रकार sklen = 0;
	u_char *ed25519_sk = रिक्त;

	यदि ((r = ssh_ed25519_deserialize_public(रिक्त, b, साँचो)) != 0)
		गच्छ out;
	यदि ((r = sshbuf_get_string(b, &ed25519_sk, &sklen)) != 0)
		गच्छ out;
	यदि (sklen != ED25519_SK_SZ) {
		r = SSH_ERR_INVALID_FORMAT;
		गच्छ out;
	}
	साँचो->ed25519_sk = ed25519_sk;
	ed25519_sk = रिक्त; /* transferred */
	/* success */
	r = 0;
 out:
	freezero(ed25519_sk, sklen);
	फर्काऊ r;
}

स्थिर पूर्णाङ्क
ssh_ed25519_sign(संरचना sshkey *साँचो,
    u_char **sigp, माप_प्रकार *lenp,
    अचर u_char *data, माप_प्रकार datalen,
    अचर वर्ण *alg, अचर वर्ण *sk_provider, अचर वर्ण *sk_pin, u_int compat)
{
	u_char sig[crypto_sign_ed25519_BYTES];
	अचिन्हित दीर्घ दीर्घ siglen = 0;
	पूर्णाङ्क r, ret;

	यदि (lenp != रिक्त)
		*lenp = 0;
	यदि (sigp != रिक्त)
		*sigp = रिक्त;

	यदि (साँचो == रिक्त ||
	    sshkey_type_plain(साँचो->type) != साँचो_ED25519 ||
	    साँचो->ed25519_sk == रिक्त)
		फर्काऊ SSH_ERR_INVALID_ARGUMENT;

	यदि ((ret = crypto_sign_ed25519_detached(sig, &siglen, data, datalen,
	    साँचो->ed25519_sk)) != 0 || siglen != परिमाण(sig)) {
		r = SSH_ERR_INVALID_ARGUMENT; /* XXX better error? */
		गच्छ out;
	}
	यदि ((r = ssh_ed25519_encode_store_sig(sig, siglen,
	    sigp, lenp)) != 0)
		गच्छ out;

	/* success */
	r = 0;
 out:
	explicit_bzero(sig, परिमाण(sig));
	फर्काऊ r;
}

पूर्णाङ्क
ssh_ed25519_encode_store_sig(अचर u_char *sig, माप_प्रकार slen,
    u_char **sigp, माप_प्रकार *lenp)
{
	संरचना sshbuf *b = रिक्त;
	पूर्णाङ्क r = -1;
	माप_प्रकार len;

	यदि (lenp != रिक्त)
		*lenp = 0;
	यदि (sigp != रिक्त)
		*sigp = रिक्त;

	यदि (slen != crypto_sign_ed25519_BYTES)
		फर्काऊ SSH_ERR_INVALID_ARGUMENT;

	/* encode signature */
	यदि ((b = sshbuf_new()) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ out;
	}
	यदि ((r = sshbuf_put_cstring(b, "ssh-ed25519")) != 0 ||
	    (r = sshbuf_put_string(b, sig, slen)) != 0)
		गच्छ out;
	len = sshbuf_len(b);
	यदि (sigp != रिक्त) {
		यदि ((*sigp = दो_स्मृति(len)) == रिक्त) {
			r = SSH_ERR_ALLOC_FAIL;
			गच्छ out;
		}
		स_नकल(*sigp, sshbuf_ptr(b), len);
	}
	यदि (lenp != रिक्त)
		*lenp = len;
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	फर्काऊ r;
}

स्थिर पूर्णाङ्क
ssh_ed25519_verify(अचर संरचना sshkey *साँचो,
    अचर u_char *sig, माप_प्रकार siglen,
    अचर u_char *data, माप_प्रकार dlen, अचर वर्ण *alg, u_int compat,
    संरचना sshkey_sig_details **detailsp)
{
	संरचना sshbuf *b = रिक्त;
	वर्ण *ktype = रिक्त;
	अचर u_char *sigblob;
	माप_प्रकार len;
	पूर्णाङ्क r, ret;

	यदि (साँचो == रिक्त ||
	    sshkey_type_plain(साँचो->type) != साँचो_ED25519 ||
	    साँचो->ed25519_pk == रिक्त ||
	    sig == रिक्त || siglen == 0)
		फर्काऊ SSH_ERR_INVALID_ARGUMENT;

	यदि ((b = sshbuf_from(sig, siglen)) == रिक्त)
		फर्काऊ SSH_ERR_ALLOC_FAIL;
	यदि ((r = sshbuf_get_cstring(b, &ktype, रिक्त)) != 0 ||
	    (r = sshbuf_get_string_direct(b, &sigblob, &len)) != 0)
		गच्छ out;
	यदि (म_भेद("ssh-ed25519", ktype) != 0) {
		r = SSH_ERR_साँचो_TYPE_MISMATCH;
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
	यदि ((ret = crypto_sign_ed25519_verify_detached(sigblob, data, dlen,
	    साँचो->ed25519_pk)) != 0) {
		debug2_f("crypto_sign_ed25519_verify_detached failed: %d", ret);
	}
	यदि (ret != 0) {
		r = SSH_ERR_SIGNATURE_INVALID;
		गच्छ out;
	}
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	मुक्त(ktype);
	फर्काऊ r;
}

/* NB. not static; used by ED25519-SK */
अचर संरचना sshkey_impl_funcs sshkey_ed25519_funcs = {
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

अचर संरचना sshkey_impl sshkey_ed25519_impl = {
	/* .name = */		"ssh-ed25519",
	/* .shortname = */	"ED25519",
	/* .sigalg = */		रिक्त,
	/* .type = */		साँचो_ED25519,
	/* .nid = */		0,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	256,
	/* .funcs = */		&sshkey_ed25519_funcs,
};

अचर संरचना sshkey_impl sshkey_ed25519_cert_impl = {
	/* .name = */		"ssh-ed25519-cert-v01@openssh.com",
	/* .shortname = */	"ED25519-CERT",
	/* .sigalg = */		रिक्त,
	/* .type = */		साँचो_ED25519_CERT,
	/* .nid = */		0,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	256,
	/* .funcs = */		&sshkey_ed25519_funcs,
};
