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
	אם (a->ed25519_pk == عدم || b->ed25519_pk == عدم)
		החזר 0;
	אם (memcmp(a->ed25519_pk, b->ed25519_pk, ED25519_PK_SZ) != 0)
		החזר 0;
	החזר 1;
}

ساكن صحيح
ssh_ed25519_serialize_public(ثابت بنية sshkey *key, بنية sshbuf *b,
    تعداد sshkey_serialize_rep opts)
{
	صحيح r;

	אם (key->ed25519_pk == عدم)
		החזר SSH_ERR_INVALID_ARGUMENT;
	אם ((r = sshbuf_put_string(b, key->ed25519_pk, ED25519_PK_SZ)) != 0)
		החזר r;

	החזר 0;
}

ساكن صحيح
ssh_ed25519_serialize_private(ثابت بنية sshkey *key, بنية sshbuf *b,
    تعداد sshkey_serialize_rep opts)
{
	صحيح r;

	אם ((r = sshbuf_put_string(b, key->ed25519_pk, ED25519_PK_SZ)) != 0 ||
	    (r = sshbuf_put_string(b, key->ed25519_sk, ED25519_SK_SZ)) != 0)
		החזר r;

	החזר 0;
}

ساكن صحيح
ssh_ed25519_generate(بنية sshkey *k, صحيح bits)
{
	אם ((k->ed25519_pk = malloc(ED25519_PK_SZ)) == عدم ||
	    (k->ed25519_sk = malloc(ED25519_SK_SZ)) == عدم)
		החזר SSH_ERR_ALLOC_FAIL;
	אם (crypto_sign_ed25519_keypair(k->ed25519_pk, k->ed25519_sk) != 0)
		החזר SSH_ERR_CRYPTO_ERROR;
	החזר 0;
}

ساكن صحيح
ssh_ed25519_copy_public(ثابت بنية sshkey *from, بنية sshkey *to)
{
	אם (from->ed25519_pk == عدم)
		החזר 0; /* XXX SSH_ERR_INTERNAL_ERROR ? */
	אם ((to->ed25519_pk = malloc(ED25519_PK_SZ)) == عدم)
		החזר SSH_ERR_ALLOC_FAIL;
	memcpy(to->ed25519_pk, from->ed25519_pk, ED25519_PK_SZ);
	החזר 0;
}

ساكن صحيح
ssh_ed25519_deserialize_public(ثابت حرف *ktype, بنية sshbuf *b,
    بنية sshkey *key)
{
	u_char *pk = عدم;
	size_t len = 0;
	صحيح r;

	אם ((r = sshbuf_get_string(b, &pk, &len)) != 0)
		החזר r;
	אם (len != ED25519_PK_SZ) {
		freezero(pk, len);
		החזר SSH_ERR_INVALID_FORMAT;
	}
	key->ed25519_pk = pk;
	החזר 0;
}

ساكن صحيح
ssh_ed25519_deserialize_private(ثابت حرف *ktype, بنية sshbuf *b,
    بنية sshkey *key)
{
	صحيح r;
	size_t sklen = 0;
	u_char *ed25519_sk = عدم;

	אם ((r = ssh_ed25519_deserialize_public(عدم, b, key)) != 0)
		اذهب out;
	אם ((r = sshbuf_get_string(b, &ed25519_sk, &sklen)) != 0)
		اذهب out;
	אם (sklen != ED25519_SK_SZ) {
		r = SSH_ERR_INVALID_FORMAT;
		اذهب out;
	}
	key->ed25519_sk = ed25519_sk;
	ed25519_sk = عدم; /* transferred */
	/* success */
	r = 0;
 out:
	freezero(ed25519_sk, sklen);
	החזר r;
}

ساكن صحيح
ssh_ed25519_sign(بنية sshkey *key,
    u_char **sigp, size_t *lenp,
    ثابت u_char *data, size_t datalen,
    ثابت حرف *alg, ثابت حرف *sk_provider, ثابت حرف *sk_pin, u_int compat)
{
	u_char sig[crypto_sign_ed25519_BYTES];
	unsigned long long siglen = 0;
	صحيح r, ret;

	אם (lenp != عدم)
		*lenp = 0;
	אם (sigp != عدم)
		*sigp = عدم;

	אם (key == عدم ||
	    sshkey_type_plain(key->type) != KEY_ED25519 ||
	    key->ed25519_sk == عدم)
		החזר SSH_ERR_INVALID_ARGUMENT;

	אם ((ret = crypto_sign_ed25519_detached(sig, &siglen, data, datalen,
	    key->ed25519_sk)) != 0 || siglen != حجم(sig)) {
		r = SSH_ERR_INVALID_ARGUMENT; /* XXX better error? */
		اذهب out;
	}
	אם ((r = ssh_ed25519_encode_store_sig(sig, siglen,
	    sigp, lenp)) != 0)
		اذهب out;

	/* success */
	r = 0;
 out:
	explicit_bzero(sig, حجم(sig));
	החזר r;
}

صحيح
ssh_ed25519_encode_store_sig(ثابت u_char *sig, size_t slen,
    u_char **sigp, size_t *lenp)
{
	بنية sshbuf *b = عدم;
	صحيح r = -1;
	size_t len;

	אם (lenp != عدم)
		*lenp = 0;
	אם (sigp != عدم)
		*sigp = عدم;

	אם (slen != crypto_sign_ed25519_BYTES)
		החזר SSH_ERR_INVALID_ARGUMENT;

	/* encode signature */
	אם ((b = sshbuf_new()) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب out;
	}
	אם ((r = sshbuf_put_cstring(b, "ssh-ed25519")) != 0 ||
	    (r = sshbuf_put_string(b, sig, slen)) != 0)
		اذهب out;
	len = sshbuf_len(b);
	אם (sigp != عدم) {
		אם ((*sigp = malloc(len)) == عدم) {
			r = SSH_ERR_ALLOC_FAIL;
			اذهب out;
		}
		memcpy(*sigp, sshbuf_ptr(b), len);
	}
	אם (lenp != عدم)
		*lenp = len;
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	החזר r;
}

ساكن صحيح
ssh_ed25519_verify(ثابت بنية sshkey *key,
    ثابت u_char *sig, size_t siglen,
    ثابت u_char *data, size_t dlen, ثابت حرف *alg, u_int compat,
    بنية sshkey_sig_details **detailsp)
{
	بنية sshbuf *b = عدم;
	حرف *ktype = عدم;
	ثابت u_char *sigblob;
	size_t len;
	صحيح r, ret;

	אם (key == عدم ||
	    sshkey_type_plain(key->type) != KEY_ED25519 ||
	    key->ed25519_pk == عدم ||
	    sig == عدم || siglen == 0)
		החזר SSH_ERR_INVALID_ARGUMENT;

	אם ((b = sshbuf_from(sig, siglen)) == عدم)
		החזר SSH_ERR_ALLOC_FAIL;
	אם ((r = sshbuf_get_cstring(b, &ktype, عدم)) != 0 ||
	    (r = sshbuf_get_string_direct(b, &sigblob, &len)) != 0)
		اذهب out;
	אם (strcmp("ssh-ed25519", ktype) != 0) {
		r = SSH_ERR_KEY_TYPE_MISMATCH;
		اذهب out;
	}
	אם (sshbuf_len(b) != 0) {
		r = SSH_ERR_UNEXPECTED_TRAILING_DATA;
		اذهب out;
	}
	אם (len != crypto_sign_ed25519_BYTES) {
		r = SSH_ERR_INVALID_FORMAT;
		اذهب out;
	}
	אם ((ret = crypto_sign_ed25519_verify_detached(sigblob, data, dlen,
	    key->ed25519_pk)) != 0) {
		debug2_f("crypto_sign_ed25519_verify_detached failed: %d", ret);
	}
	אם (ret != 0) {
		r = SSH_ERR_SIGNATURE_INVALID;
		اذهب out;
	}
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	حرر(ktype);
	החזר r;
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
	/* .type = */		KEY_ED25519,
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
	/* .type = */		KEY_ED25519_CERT,
	/* .nid = */		0,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	256,
	/* .funcs = */		&sshkey_ed25519_funcs,
};
