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

#شامل "includes.h"

#شامل <sys/types.h>
#شامل <limits.h>

#شامل "crypto_api.h"

#شامل <string.h>
#شامل <stdarg.h>

#شامل "log.h"
#شامل "sshbuf.h"
#define SSHKEY_INTERNAL
#شامل "sshkey.h"
#شامل "ssherr.h"

ایستا تهی
ssh_ed25519_cleanup(ساختار sshkey *k)
{
	freezero(k->ed25519_pk, ED25519_PK_SZ);
	freezero(k->ed25519_sk, ED25519_SK_SZ);
	k->ed25519_pk = پوچ;
	k->ed25519_sk = پوچ;
}

ایستا صحیح
ssh_ed25519_equal(ثابت ساختار sshkey *a, ثابت ساختار sshkey *b)
{
	اگر (a->ed25519_pk == پوچ || b->ed25519_pk == پوچ)
		بازگشت 0;
	اگر (memcmp(a->ed25519_pk, b->ed25519_pk, ED25519_PK_SZ) != 0)
		بازگشت 0;
	بازگشت 1;
}

ایستا صحیح
ssh_ed25519_serialize_public(ثابت ساختار sshkey *کلید, ساختار sshbuf *b,
    شمارش sshkey_serialize_rep opts)
{
	صحیح r;

	اگر (کلید->ed25519_pk == پوچ)
		بازگشت SSH_ERR_INVALID_ARGUMENT;
	اگر ((r = sshbuf_put_string(b, کلید->ed25519_pk, ED25519_PK_SZ)) != 0)
		بازگشت r;

	بازگشت 0;
}

ایستا صحیح
ssh_ed25519_serialize_private(ثابت ساختار sshkey *کلید, ساختار sshbuf *b,
    شمارش sshkey_serialize_rep opts)
{
	صحیح r;

	اگر ((r = sshbuf_put_string(b, کلید->ed25519_pk, ED25519_PK_SZ)) != 0 ||
	    (r = sshbuf_put_string(b, کلید->ed25519_sk, ED25519_SK_SZ)) != 0)
		بازگشت r;

	بازگشت 0;
}

ایستا صحیح
ssh_ed25519_generate(ساختار sshkey *k, صحیح bits)
{
	اگر ((k->ed25519_pk = malloc(ED25519_PK_SZ)) == پوچ ||
	    (k->ed25519_sk = malloc(ED25519_SK_SZ)) == پوچ)
		بازگشت SSH_ERR_ALLOC_FAIL;
	اگر (crypto_sign_ed25519_keypair(k->ed25519_pk, k->ed25519_sk) != 0)
		بازگشت SSH_ERR_CRYPTO_ERROR;
	بازگشت 0;
}

ایستا صحیح
ssh_ed25519_copy_public(ثابت ساختار sshkey *from, ساختار sshkey *to)
{
	اگر (from->ed25519_pk == پوچ)
		بازگشت 0; /* XXX SSH_ERR_INTERNAL_ERROR ? */
	اگر ((to->ed25519_pk = malloc(ED25519_PK_SZ)) == پوچ)
		بازگشت SSH_ERR_ALLOC_FAIL;
	memcpy(to->ed25519_pk, from->ed25519_pk, ED25519_PK_SZ);
	بازگشت 0;
}

ایستا صحیح
ssh_ed25519_deserialize_public(ثابت نویسه *ktype, ساختار sshbuf *b,
    ساختار sshkey *کلید)
{
	u_char *pk = پوچ;
	size_t len = 0;
	صحیح r;

	اگر ((r = sshbuf_get_string(b, &pk, &len)) != 0)
		بازگشت r;
	اگر (len != ED25519_PK_SZ) {
		freezero(pk, len);
		بازگشت SSH_ERR_INVALID_FORMAT;
	}
	کلید->ed25519_pk = pk;
	بازگشت 0;
}

ایستا صحیح
ssh_ed25519_deserialize_private(ثابت نویسه *ktype, ساختار sshbuf *b,
    ساختار sshkey *کلید)
{
	صحیح r;
	size_t sklen = 0;
	u_char *ed25519_sk = پوچ;

	اگر ((r = ssh_ed25519_deserialize_public(پوچ, b, کلید)) != 0)
		برو out;
	اگر ((r = sshbuf_get_string(b, &ed25519_sk, &sklen)) != 0)
		برو out;
	اگر (sklen != ED25519_SK_SZ) {
		r = SSH_ERR_INVALID_FORMAT;
		برو out;
	}
	کلید->ed25519_sk = ed25519_sk;
	ed25519_sk = پوچ; /* transferred */
	/* success */
	r = 0;
 out:
	freezero(ed25519_sk, sklen);
	بازگشت r;
}

ایستا صحیح
ssh_ed25519_sign(ساختار sshkey *کلید,
    u_char **sigp, size_t *lenp,
    ثابت u_char *data, size_t datalen,
    ثابت نویسه *alg, ثابت نویسه *sk_provider, ثابت نویسه *sk_pin, u_int compat)
{
	u_char sig[crypto_sign_ed25519_BYTES];
	unsigned long long siglen = 0;
	صحیح r, ret;

	اگر (lenp != پوچ)
		*lenp = 0;
	اگر (sigp != پوچ)
		*sigp = پوچ;

	اگر (کلید == پوچ ||
	    sshkey_type_plain(کلید->type) != کلید_ED25519 ||
	    کلید->ed25519_sk == پوچ)
		بازگشت SSH_ERR_INVALID_ARGUMENT;

	اگر ((ret = crypto_sign_ed25519_detached(sig, &siglen, data, datalen,
	    کلید->ed25519_sk)) != 0 || siglen != اندازه(sig)) {
		r = SSH_ERR_INVALID_ARGUMENT; /* XXX better error? */
		برو out;
	}
	اگر ((r = ssh_ed25519_encode_store_sig(sig, siglen,
	    sigp, lenp)) != 0)
		برو out;

	/* success */
	r = 0;
 out:
	explicit_bzero(sig, اندازه(sig));
	بازگشت r;
}

صحیح
ssh_ed25519_encode_store_sig(ثابت u_char *sig, size_t slen,
    u_char **sigp, size_t *lenp)
{
	ساختار sshbuf *b = پوچ;
	صحیح r = -1;
	size_t len;

	اگر (lenp != پوچ)
		*lenp = 0;
	اگر (sigp != پوچ)
		*sigp = پوچ;

	اگر (slen != crypto_sign_ed25519_BYTES)
		بازگشت SSH_ERR_INVALID_ARGUMENT;

	/* encode signature */
	اگر ((b = sshbuf_new()) == پوچ) {
		r = SSH_ERR_ALLOC_FAIL;
		برو out;
	}
	اگر ((r = sshbuf_put_cstring(b, "ssh-ed25519")) != 0 ||
	    (r = sshbuf_put_string(b, sig, slen)) != 0)
		برو out;
	len = sshbuf_len(b);
	اگر (sigp != پوچ) {
		اگر ((*sigp = malloc(len)) == پوچ) {
			r = SSH_ERR_ALLOC_FAIL;
			برو out;
		}
		memcpy(*sigp, sshbuf_ptr(b), len);
	}
	اگر (lenp != پوچ)
		*lenp = len;
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	بازگشت r;
}

ایستا صحیح
ssh_ed25519_verify(ثابت ساختار sshkey *کلید,
    ثابت u_char *sig, size_t siglen,
    ثابت u_char *data, size_t dlen, ثابت نویسه *alg, u_int compat,
    ساختار sshkey_sig_details **detailsp)
{
	ساختار sshbuf *b = پوچ;
	نویسه *ktype = پوچ;
	ثابت u_char *sigblob;
	size_t len;
	صحیح r, ret;

	اگر (کلید == پوچ ||
	    sshkey_type_plain(کلید->type) != کلید_ED25519 ||
	    کلید->ed25519_pk == پوچ ||
	    sig == پوچ || siglen == 0)
		بازگشت SSH_ERR_INVALID_ARGUMENT;

	اگر ((b = sshbuf_from(sig, siglen)) == پوچ)
		بازگشت SSH_ERR_ALLOC_FAIL;
	اگر ((r = sshbuf_get_cstring(b, &ktype, پوچ)) != 0 ||
	    (r = sshbuf_get_string_direct(b, &sigblob, &len)) != 0)
		برو out;
	اگر (strcmp("ssh-ed25519", ktype) != 0) {
		r = SSH_ERR_کلید_TYPE_MISMATCH;
		برو out;
	}
	اگر (sshbuf_len(b) != 0) {
		r = SSH_ERR_UNEXPECTED_TRAILING_DATA;
		برو out;
	}
	اگر (len != crypto_sign_ed25519_BYTES) {
		r = SSH_ERR_INVALID_FORMAT;
		برو out;
	}
	اگر ((ret = crypto_sign_ed25519_verify_detached(sigblob, data, dlen,
	    کلید->ed25519_pk)) != 0) {
		debug2_f("crypto_sign_ed25519_verify_detached failed: %d", ret);
	}
	اگر (ret != 0) {
		r = SSH_ERR_SIGNATURE_INVALID;
		برو out;
	}
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	آزاد(ktype);
	بازگشت r;
}

/* NB. not static; used by ED25519-SK */
ثابت ساختار sshkey_impl_funcs sshkey_ed25519_funcs = {
	/* .size = */		پوچ,
	/* .alloc = */		پوچ,
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

ثابت ساختار sshkey_impl sshkey_ed25519_impl = {
	/* .name = */		"ssh-ed25519",
	/* .shortname = */	"ED25519",
	/* .sigalg = */		پوچ,
	/* .type = */		کلید_ED25519,
	/* .nid = */		0,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	256,
	/* .funcs = */		&sshkey_ed25519_funcs,
};

ثابت ساختار sshkey_impl sshkey_ed25519_cert_impl = {
	/* .name = */		"ssh-ed25519-cert-v01@openssh.com",
	/* .shortname = */	"ED25519-CERT",
	/* .sigalg = */		پوچ,
	/* .type = */		کلید_ED25519_CERT,
	/* .nid = */		0,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	256,
	/* .funcs = */		&sshkey_ed25519_funcs,
};
