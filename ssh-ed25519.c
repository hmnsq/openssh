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

#include "includes.h"

#include <sys/types.h>
#include <limits.h>

#include "crypto_api.h"

#include <string.h>
#include <stdarg.h>

#include "log.h"
#include "sshbuf.h"
#define SSHKEY_INTERNAL
#include "sshkey.h"
#include "ssherr.h"

static void
ssh_ed25519_cleanup(struct sshkey *k)
{
	freezero(k->ed25519_pk, ED25519_PK_SZ);
	freezero(k->ed25519_sk, ED25519_SK_SZ);
	k->ed25519_pk = NULL;
	k->ed25519_sk = NULL;
}

static 정수
ssh_ed25519_equal(const struct sshkey *a, const struct sshkey *b)
{
	만약 (a->ed25519_pk == NULL || b->ed25519_pk == NULL)
		반환 0;
	만약 (memcmp(a->ed25519_pk, b->ed25519_pk, ED25519_PK_SZ) != 0)
		반환 0;
	반환 1;
}

static 정수
ssh_ed25519_serialize_public(const struct sshkey *key, struct sshbuf *b,
    enum sshkey_serialize_rep opts)
{
	정수 r;

	만약 (key->ed25519_pk == NULL)
		반환 SSH_ERR_INVALID_ARGUMENT;
	만약 ((r = sshbuf_put_string(b, key->ed25519_pk, ED25519_PK_SZ)) != 0)
		반환 r;

	반환 0;
}

static 정수
ssh_ed25519_serialize_private(const struct sshkey *key, struct sshbuf *b,
    enum sshkey_serialize_rep opts)
{
	정수 r;

	만약 ((r = sshbuf_put_string(b, key->ed25519_pk, ED25519_PK_SZ)) != 0 ||
	    (r = sshbuf_put_string(b, key->ed25519_sk, ED25519_SK_SZ)) != 0)
		반환 r;

	반환 0;
}

static 정수
ssh_ed25519_generate(struct sshkey *k, 정수 bits)
{
	만약 ((k->ed25519_pk = malloc(ED25519_PK_SZ)) == NULL ||
	    (k->ed25519_sk = malloc(ED25519_SK_SZ)) == NULL)
		반환 SSH_ERR_ALLOC_FAIL;
	만약 (crypto_sign_ed25519_keypair(k->ed25519_pk, k->ed25519_sk) != 0)
		반환 SSH_ERR_CRYPTO_ERROR;
	반환 0;
}

static 정수
ssh_ed25519_copy_public(const struct sshkey *from, struct sshkey *to)
{
	만약 (from->ed25519_pk == NULL)
		반환 0; /* XXX SSH_ERR_INTERNAL_ERROR ? */
	만약 ((to->ed25519_pk = malloc(ED25519_PK_SZ)) == NULL)
		반환 SSH_ERR_ALLOC_FAIL;
	memcpy(to->ed25519_pk, from->ed25519_pk, ED25519_PK_SZ);
	반환 0;
}

static 정수
ssh_ed25519_deserialize_public(const char *ktype, struct sshbuf *b,
    struct sshkey *key)
{
	u_char *pk = NULL;
	size_t len = 0;
	정수 r;

	만약 ((r = sshbuf_get_string(b, &pk, &len)) != 0)
		반환 r;
	만약 (len != ED25519_PK_SZ) {
		freezero(pk, len);
		반환 SSH_ERR_INVALID_FORMAT;
	}
	key->ed25519_pk = pk;
	반환 0;
}

static 정수
ssh_ed25519_deserialize_private(const char *ktype, struct sshbuf *b,
    struct sshkey *key)
{
	정수 r;
	size_t sklen = 0;
	u_char *ed25519_sk = NULL;

	만약 ((r = ssh_ed25519_deserialize_public(NULL, b, key)) != 0)
		goto out;
	만약 ((r = sshbuf_get_string(b, &ed25519_sk, &sklen)) != 0)
		goto out;
	만약 (sklen != ED25519_SK_SZ) {
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	key->ed25519_sk = ed25519_sk;
	ed25519_sk = NULL; /* transferred */
	/* success */
	r = 0;
 out:
	freezero(ed25519_sk, sklen);
	반환 r;
}

static 정수
ssh_ed25519_sign(struct sshkey *key,
    u_char **sigp, size_t *lenp,
    const u_char *data, size_t datalen,
    const char *alg, const char *sk_provider, const char *sk_pin, u_int compat)
{
	u_char sig[crypto_sign_ed25519_BYTES];
	unsigned long long siglen = 0;
	정수 r, ret;

	만약 (lenp != NULL)
		*lenp = 0;
	만약 (sigp != NULL)
		*sigp = NULL;

	만약 (key == NULL ||
	    sshkey_type_plain(key->type) != KEY_ED25519 ||
	    key->ed25519_sk == NULL)
		반환 SSH_ERR_INVALID_ARGUMENT;

	만약 ((ret = crypto_sign_ed25519_detached(sig, &siglen, data, datalen,
	    key->ed25519_sk)) != 0 || siglen != sizeof(sig)) {
		r = SSH_ERR_INVALID_ARGUMENT; /* XXX better error? */
		goto out;
	}
	만약 ((r = ssh_ed25519_encode_store_sig(sig, siglen,
	    sigp, lenp)) != 0)
		goto out;

	/* success */
	r = 0;
 out:
	explicit_bzero(sig, sizeof(sig));
	반환 r;
}

정수
ssh_ed25519_encode_store_sig(const u_char *sig, size_t slen,
    u_char **sigp, size_t *lenp)
{
	struct sshbuf *b = NULL;
	정수 r = -1;
	size_t len;

	만약 (lenp != NULL)
		*lenp = 0;
	만약 (sigp != NULL)
		*sigp = NULL;

	만약 (slen != crypto_sign_ed25519_BYTES)
		반환 SSH_ERR_INVALID_ARGUMENT;

	/* encode signature */
	만약 ((b = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	만약 ((r = sshbuf_put_cstring(b, "ssh-ed25519")) != 0 ||
	    (r = sshbuf_put_string(b, sig, slen)) != 0)
		goto out;
	len = sshbuf_len(b);
	만약 (sigp != NULL) {
		만약 ((*sigp = malloc(len)) == NULL) {
			r = SSH_ERR_ALLOC_FAIL;
			goto out;
		}
		memcpy(*sigp, sshbuf_ptr(b), len);
	}
	만약 (lenp != NULL)
		*lenp = len;
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	반환 r;
}

static 정수
ssh_ed25519_verify(const struct sshkey *key,
    const u_char *sig, size_t siglen,
    const u_char *data, size_t dlen, const char *alg, u_int compat,
    struct sshkey_sig_details **detailsp)
{
	struct sshbuf *b = NULL;
	char *ktype = NULL;
	const u_char *sigblob;
	size_t len;
	정수 r, ret;

	만약 (key == NULL ||
	    sshkey_type_plain(key->type) != KEY_ED25519 ||
	    key->ed25519_pk == NULL ||
	    sig == NULL || siglen == 0)
		반환 SSH_ERR_INVALID_ARGUMENT;

	만약 ((b = sshbuf_from(sig, siglen)) == NULL)
		반환 SSH_ERR_ALLOC_FAIL;
	만약 ((r = sshbuf_get_cstring(b, &ktype, NULL)) != 0 ||
	    (r = sshbuf_get_string_direct(b, &sigblob, &len)) != 0)
		goto out;
	만약 (strcmp("ssh-ed25519", ktype) != 0) {
		r = SSH_ERR_KEY_TYPE_MISMATCH;
		goto out;
	}
	만약 (sshbuf_len(b) != 0) {
		r = SSH_ERR_UNEXPECTED_TRAILING_DATA;
		goto out;
	}
	만약 (len != crypto_sign_ed25519_BYTES) {
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	만약 ((ret = crypto_sign_ed25519_verify_detached(sigblob, data, dlen,
	    key->ed25519_pk)) != 0) {
		debug2_f("crypto_sign_ed25519_verify_detached failed: %d", ret);
	}
	만약 (ret != 0) {
		r = SSH_ERR_SIGNATURE_INVALID;
		goto out;
	}
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	free(ktype);
	반환 r;
}

/* NB. not static; used by ED25519-SK */
const struct sshkey_impl_funcs sshkey_ed25519_funcs = {
	/* .size = */		NULL,
	/* .alloc = */		NULL,
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

const struct sshkey_impl sshkey_ed25519_impl = {
	/* .name = */		"ssh-ed25519",
	/* .shortname = */	"ED25519",
	/* .sigalg = */		NULL,
	/* .type = */		KEY_ED25519,
	/* .nid = */		0,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	256,
	/* .funcs = */		&sshkey_ed25519_funcs,
};

const struct sshkey_impl sshkey_ed25519_cert_impl = {
	/* .name = */		"ssh-ed25519-cert-v01@openssh.com",
	/* .shortname = */	"ED25519-CERT",
	/* .sigalg = */		NULL,
	/* .type = */		KEY_ED25519_CERT,
	/* .nid = */		0,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	256,
	/* .funcs = */		&sshkey_ed25519_funcs,
};
