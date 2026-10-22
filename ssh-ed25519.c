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

#ضمن "includes.h"

#ضمن <sys/types.h>
#ضمن <limits.h>

#ضمن "crypto_api.h"

#ضمن <string.h>
#ضمن <stdarg.h>

#ضمن "log.h"
#ضمن "sshbuf.h"
#define SSHKEY_INTERNAL
#ضمن "sshkey.h"
#ضمن "ssherr.h"

ساكن فراغ
ssh_ed25519_cleanup(بنية sshkey *k)
{
	freezero(k->ed25519_pk, ED25519_PK_SZ);
	freezero(k->ed25519_sk, ED25519_SK_SZ);
	k->ed25519_pk = عدم;
	k->ed25519_sk = عدم;
}

ساكن صحيح
ssh_ed25519_equal(ثابت بنية sshkey *a, ثابت بنية sshkey *b)
{
	إذا (a->ed25519_pk == عدم || b->ed25519_pk == عدم)
		أرجع 0;
	إذا (memcmp(a->ed25519_pk, b->ed25519_pk, ED25519_PK_SZ) != 0)
		أرجع 0;
	أرجع 1;
}

ساكن صحيح
ssh_ed25519_serialize_public(ثابت بنية sshkey *کلیل, بنية sshbuf *b,
    تعداد sshkey_serialize_rep opts)
{
	صحيح r;

	إذا (کلیل->ed25519_pk == عدم)
		أرجع SSH_ERR_INVALID_ARGUMENT;
	إذا ((r = sshbuf_put_string(b, کلیل->ed25519_pk, ED25519_PK_SZ)) != 0)
		أرجع r;

	أرجع 0;
}

ساكن صحيح
ssh_ed25519_serialize_private(ثابت بنية sshkey *کلیل, بنية sshbuf *b,
    تعداد sshkey_serialize_rep opts)
{
	صحيح r;

	إذا ((r = sshbuf_put_string(b, کلیل->ed25519_pk, ED25519_PK_SZ)) != 0 ||
	    (r = sshbuf_put_string(b, کلیل->ed25519_sk, ED25519_SK_SZ)) != 0)
		أرجع r;

	أرجع 0;
}

ساكن صحيح
ssh_ed25519_generate(بنية sshkey *k, صحيح bits)
{
	إذا ((k->ed25519_pk = malloc(ED25519_PK_SZ)) == عدم ||
	    (k->ed25519_sk = malloc(ED25519_SK_SZ)) == عدم)
		أرجع SSH_ERR_ALLOC_FAIL;
	إذا (crypto_sign_ed25519_keypair(k->ed25519_pk, k->ed25519_sk) != 0)
		أرجع SSH_ERR_CRYPTO_ERROR;
	أرجع 0;
}

ساكن صحيح
ssh_ed25519_copy_public(ثابت بنية sshkey *from, بنية sshkey *to)
{
	إذا (from->ed25519_pk == عدم)
		أرجع 0; /* XXX SSH_ERR_INTERNAL_ERROR ? */
	إذا ((to->ed25519_pk = malloc(ED25519_PK_SZ)) == عدم)
		أرجع SSH_ERR_ALLOC_FAIL;
	memcpy(to->ed25519_pk, from->ed25519_pk, ED25519_PK_SZ);
	أرجع 0;
}

ساكن صحيح
ssh_ed25519_deserialize_public(ثابت حرف *ktype, بنية sshbuf *b,
    بنية sshkey *کلیل)
{
	u_char *pk = عدم;
	size_t len = 0;
	صحيح r;

	إذا ((r = sshbuf_get_string(b, &pk, &len)) != 0)
		أرجع r;
	إذا (len != ED25519_PK_SZ) {
		freezero(pk, len);
		أرجع SSH_ERR_INVALID_FORMAT;
	}
	کلیل->ed25519_pk = pk;
	أرجع 0;
}

ساكن صحيح
ssh_ed25519_deserialize_private(ثابت حرف *ktype, بنية sshbuf *b,
    بنية sshkey *کلیل)
{
	صحيح r;
	size_t sklen = 0;
	u_char *ed25519_sk = عدم;

	إذا ((r = ssh_ed25519_deserialize_public(عدم, b, کلیل)) != 0)
		اذهب out;
	إذا ((r = sshbuf_get_string(b, &ed25519_sk, &sklen)) != 0)
		اذهب out;
	إذا (sklen != ED25519_SK_SZ) {
		r = SSH_ERR_INVALID_FORMAT;
		اذهب out;
	}
	کلیل->ed25519_sk = ed25519_sk;
	ed25519_sk = عدم; /* transferred */
	/* success */
	r = 0;
 out:
	freezero(ed25519_sk, sklen);
	أرجع r;
}

ساكن صحيح
ssh_ed25519_sign(بنية sshkey *کلیل,
    u_char **sigp, size_t *lenp,
    ثابت u_char *data, size_t datalen,
    ثابت حرف *alg, ثابت حرف *sk_provider, ثابت حرف *sk_pin, u_int compat)
{
	u_char sig[crypto_sign_ed25519_BYTES];
	unsigned long long siglen = 0;
	صحيح r, ret;

	إذا (lenp != عدم)
		*lenp = 0;
	إذا (sigp != عدم)
		*sigp = عدم;

	إذا (کلیل == عدم ||
	    sshkey_type_plain(کلیل->type) != کلیل_ED25519 ||
	    کلیل->ed25519_sk == عدم)
		أرجع SSH_ERR_INVALID_ARGUMENT;

	إذا ((ret = crypto_sign_ed25519_detached(sig, &siglen, data, datalen,
	    کلیل->ed25519_sk)) != 0 || siglen != حجم(sig)) {
		r = SSH_ERR_INVALID_ARGUMENT; /* XXX better error? */
		اذهب out;
	}
	إذا ((r = ssh_ed25519_encode_store_sig(sig, siglen,
	    sigp, lenp)) != 0)
		اذهب out;

	/* success */
	r = 0;
 out:
	explicit_bzero(sig, حجم(sig));
	أرجع r;
}

صحيح
ssh_ed25519_encode_store_sig(ثابت u_char *sig, size_t slen,
    u_char **sigp, size_t *lenp)
{
	بنية sshbuf *b = عدم;
	صحيح r = -1;
	size_t len;

	إذا (lenp != عدم)
		*lenp = 0;
	إذا (sigp != عدم)
		*sigp = عدم;

	إذا (slen != crypto_sign_ed25519_BYTES)
		أرجع SSH_ERR_INVALID_ARGUMENT;

	/* encode signature */
	إذا ((b = sshbuf_new()) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب out;
	}
	إذا ((r = sshbuf_put_cstring(b, "ssh-ed25519")) != 0 ||
	    (r = sshbuf_put_string(b, sig, slen)) != 0)
		اذهب out;
	len = sshbuf_len(b);
	إذا (sigp != عدم) {
		إذا ((*sigp = malloc(len)) == عدم) {
			r = SSH_ERR_ALLOC_FAIL;
			اذهب out;
		}
		memcpy(*sigp, sshbuf_ptr(b), len);
	}
	إذا (lenp != عدم)
		*lenp = len;
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	أرجع r;
}

ساكن صحيح
ssh_ed25519_verify(ثابت بنية sshkey *کلیل,
    ثابت u_char *sig, size_t siglen,
    ثابت u_char *data, size_t dlen, ثابت حرف *alg, u_int compat,
    بنية sshkey_sig_details **detailsp)
{
	بنية sshbuf *b = عدم;
	حرف *ktype = عدم;
	ثابت u_char *sigblob;
	size_t len;
	صحيح r, ret;

	إذا (کلیل == عدم ||
	    sshkey_type_plain(کلیل->type) != کلیل_ED25519 ||
	    کلیل->ed25519_pk == عدم ||
	    sig == عدم || siglen == 0)
		أرجع SSH_ERR_INVALID_ARGUMENT;

	إذا ((b = sshbuf_from(sig, siglen)) == عدم)
		أرجع SSH_ERR_ALLOC_FAIL;
	إذا ((r = sshbuf_get_cstring(b, &ktype, عدم)) != 0 ||
	    (r = sshbuf_get_string_direct(b, &sigblob, &len)) != 0)
		اذهب out;
	إذا (strcmp("ssh-ed25519", ktype) != 0) {
		r = SSH_ERR_کلیل_TYPE_MISMATCH;
		اذهب out;
	}
	إذا (sshbuf_len(b) != 0) {
		r = SSH_ERR_UNEXPECTED_TRAILING_DATA;
		اذهب out;
	}
	إذا (len != crypto_sign_ed25519_BYTES) {
		r = SSH_ERR_INVALID_FORMAT;
		اذهب out;
	}
	إذا ((ret = crypto_sign_ed25519_verify_detached(sigblob, data, dlen,
	    کلیل->ed25519_pk)) != 0) {
		debug2_f("crypto_sign_ed25519_verify_detached failed: %d", ret);
	}
	إذا (ret != 0) {
		r = SSH_ERR_SIGNATURE_INVALID;
		اذهب out;
	}
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	حرر(ktype);
	أرجع r;
}

/* NB. not static; used by ED25519-SK */
ثابت بنية sshkey_impl_funcs sshkey_ed25519_funcs = {
	/* .size = */		عدم,
	/* .alloc = */		عدم,
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

ثابت بنية sshkey_impl sshkey_ed25519_impl = {
	/* .name = */		"ssh-ed25519",
	/* .shortname = */	"ED25519",
	/* .sigalg = */		عدم,
	/* .type = */		کلیل_ED25519,
	/* .nid = */		0,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	256,
	/* .funcs = */		&sshkey_ed25519_funcs,
};

ثابت بنية sshkey_impl sshkey_ed25519_cert_impl = {
	/* .name = */		"ssh-ed25519-cert-v01@openssh.com",
	/* .shortname = */	"ED25519-CERT",
	/* .sigalg = */		عدم,
	/* .type = */		کلیل_ED25519_CERT,
	/* .nid = */		0,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	256,
	/* .funcs = */		&sshkey_ed25519_funcs,
};
