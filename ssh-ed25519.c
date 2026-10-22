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

#அந்தர்பாவ "includes.h"

#அந்தர்பாவ <sys/types.h>
#அந்தர்பாவ <limits.h>

#அந்தர்பாவ "crypto_api.h"

#அந்தர்பாவ <string.h>
#அந்தர்பாவ <stdarg.h>

#அந்தர்பாவ "log.h"
#அந்தர்பாவ "sshbuf.h"
#define SSHKEY_INTERNAL
#அந்தர்பாவ "sshkey.h"
#அந்தர்பாவ "ssherr.h"

நிலையான வெறுமை
ssh_ed25519_cleanup(கட்டமைப்பு sshkey *k)
{
	freezero(k->ed25519_pk, ED25519_PK_SZ);
	freezero(k->ed25519_sk, ED25519_SK_SZ);
	k->ed25519_pk = வெற்று;
	k->ed25519_sk = வெற்று;
}

நிலையான முழு
ssh_ed25519_equal(மாறிலி கட்டமைப்பு sshkey *a, மாறிலி கட்டமைப்பு sshkey *b)
{
	எனில் (a->ed25519_pk == வெற்று || b->ed25519_pk == வெற்று)
		திரும்பு 0;
	எனில் (memcmp(a->ed25519_pk, b->ed25519_pk, ED25519_PK_SZ) != 0)
		திரும்பு 0;
	திரும்பு 1;
}

நிலையான முழு
ssh_ed25519_serialize_public(மாறிலி கட்டமைப்பு sshkey *சாவி, கட்டமைப்பு sshbuf *b,
    எண்ணிக்கை sshkey_serialize_rep opts)
{
	முழு r;

	எனில் (சாவி->ed25519_pk == வெற்று)
		திரும்பு SSH_ERR_INVALID_ARGUMENT;
	எனில் ((r = sshbuf_put_string(b, சாவி->ed25519_pk, ED25519_PK_SZ)) != 0)
		திரும்பு r;

	திரும்பு 0;
}

நிலையான முழு
ssh_ed25519_serialize_private(மாறிலி கட்டமைப்பு sshkey *சாவி, கட்டமைப்பு sshbuf *b,
    எண்ணிக்கை sshkey_serialize_rep opts)
{
	முழு r;

	எனில் ((r = sshbuf_put_string(b, சாவி->ed25519_pk, ED25519_PK_SZ)) != 0 ||
	    (r = sshbuf_put_string(b, சாவி->ed25519_sk, ED25519_SK_SZ)) != 0)
		திரும்பு r;

	திரும்பு 0;
}

நிலையான முழு
ssh_ed25519_generate(கட்டமைப்பு sshkey *k, முழு bits)
{
	எனில் ((k->ed25519_pk = malloc(ED25519_PK_SZ)) == வெற்று ||
	    (k->ed25519_sk = malloc(ED25519_SK_SZ)) == வெற்று)
		திரும்பு SSH_ERR_ALLOC_FAIL;
	எனில் (crypto_sign_ed25519_keypair(k->ed25519_pk, k->ed25519_sk) != 0)
		திரும்பு SSH_ERR_CRYPTO_ERROR;
	திரும்பு 0;
}

நிலையான முழு
ssh_ed25519_copy_public(மாறிலி கட்டமைப்பு sshkey *from, கட்டமைப்பு sshkey *to)
{
	எனில் (from->ed25519_pk == வெற்று)
		திரும்பு 0; /* XXX SSH_ERR_INTERNAL_ERROR ? */
	எனில் ((to->ed25519_pk = malloc(ED25519_PK_SZ)) == வெற்று)
		திரும்பு SSH_ERR_ALLOC_FAIL;
	memcpy(to->ed25519_pk, from->ed25519_pk, ED25519_PK_SZ);
	திரும்பு 0;
}

நிலையான முழு
ssh_ed25519_deserialize_public(மாறிலி எழுத்து *ktype, கட்டமைப்பு sshbuf *b,
    கட்டமைப்பு sshkey *சாவி)
{
	u_char *pk = வெற்று;
	size_t len = 0;
	முழு r;

	எனில் ((r = sshbuf_get_string(b, &pk, &len)) != 0)
		திரும்பு r;
	எனில் (len != ED25519_PK_SZ) {
		freezero(pk, len);
		திரும்பு SSH_ERR_INVALID_FORMAT;
	}
	சாவி->ed25519_pk = pk;
	திரும்பு 0;
}

நிலையான முழு
ssh_ed25519_deserialize_private(மாறிலி எழுத்து *ktype, கட்டமைப்பு sshbuf *b,
    கட்டமைப்பு sshkey *சாவி)
{
	முழு r;
	size_t sklen = 0;
	u_char *ed25519_sk = வெற்று;

	எனில் ((r = ssh_ed25519_deserialize_public(வெற்று, b, சாவி)) != 0)
		செல் out;
	எனில் ((r = sshbuf_get_string(b, &ed25519_sk, &sklen)) != 0)
		செல் out;
	எனில் (sklen != ED25519_SK_SZ) {
		r = SSH_ERR_INVALID_FORMAT;
		செல் out;
	}
	சாவி->ed25519_sk = ed25519_sk;
	ed25519_sk = வெற்று; /* transferred */
	/* success */
	r = 0;
 out:
	freezero(ed25519_sk, sklen);
	திரும்பு r;
}

நிலையான முழு
ssh_ed25519_sign(கட்டமைப்பு sshkey *சாவி,
    u_char **sigp, size_t *lenp,
    மாறிலி u_char *data, size_t datalen,
    மாறிலி எழுத்து *alg, மாறிலி எழுத்து *sk_provider, மாறிலி எழுத்து *sk_pin, u_int compat)
{
	u_char sig[crypto_sign_ed25519_BYTES];
	unsigned long long siglen = 0;
	முழு r, ret;

	எனில் (lenp != வெற்று)
		*lenp = 0;
	எனில் (sigp != வெற்று)
		*sigp = வெற்று;

	எனில் (சாவி == வெற்று ||
	    sshkey_type_plain(சாவி->type) != சாவி_ED25519 ||
	    சாவி->ed25519_sk == வெற்று)
		திரும்பு SSH_ERR_INVALID_ARGUMENT;

	எனில் ((ret = crypto_sign_ed25519_detached(sig, &siglen, data, datalen,
	    சாவி->ed25519_sk)) != 0 || siglen != அளவு(sig)) {
		r = SSH_ERR_INVALID_ARGUMENT; /* XXX better error? */
		செல் out;
	}
	எனில் ((r = ssh_ed25519_encode_store_sig(sig, siglen,
	    sigp, lenp)) != 0)
		செல் out;

	/* success */
	r = 0;
 out:
	explicit_bzero(sig, அளவு(sig));
	திரும்பு r;
}

முழு
ssh_ed25519_encode_store_sig(மாறிலி u_char *sig, size_t slen,
    u_char **sigp, size_t *lenp)
{
	கட்டமைப்பு sshbuf *b = வெற்று;
	முழு r = -1;
	size_t len;

	எனில் (lenp != வெற்று)
		*lenp = 0;
	எனில் (sigp != வெற்று)
		*sigp = வெற்று;

	எனில் (slen != crypto_sign_ed25519_BYTES)
		திரும்பு SSH_ERR_INVALID_ARGUMENT;

	/* encode signature */
	எனில் ((b = sshbuf_new()) == வெற்று) {
		r = SSH_ERR_ALLOC_FAIL;
		செல் out;
	}
	எனில் ((r = sshbuf_put_cstring(b, "ssh-ed25519")) != 0 ||
	    (r = sshbuf_put_string(b, sig, slen)) != 0)
		செல் out;
	len = sshbuf_len(b);
	எனில் (sigp != வெற்று) {
		எனில் ((*sigp = malloc(len)) == வெற்று) {
			r = SSH_ERR_ALLOC_FAIL;
			செல் out;
		}
		memcpy(*sigp, sshbuf_ptr(b), len);
	}
	எனில் (lenp != வெற்று)
		*lenp = len;
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	திரும்பு r;
}

நிலையான முழு
ssh_ed25519_verify(மாறிலி கட்டமைப்பு sshkey *சாவி,
    மாறிலி u_char *sig, size_t siglen,
    மாறிலி u_char *data, size_t dlen, மாறிலி எழுத்து *alg, u_int compat,
    கட்டமைப்பு sshkey_sig_details **detailsp)
{
	கட்டமைப்பு sshbuf *b = வெற்று;
	எழுத்து *ktype = வெற்று;
	மாறிலி u_char *sigblob;
	size_t len;
	முழு r, ret;

	எனில் (சாவி == வெற்று ||
	    sshkey_type_plain(சாவி->type) != சாவி_ED25519 ||
	    சாவி->ed25519_pk == வெற்று ||
	    sig == வெற்று || siglen == 0)
		திரும்பு SSH_ERR_INVALID_ARGUMENT;

	எனில் ((b = sshbuf_from(sig, siglen)) == வெற்று)
		திரும்பு SSH_ERR_ALLOC_FAIL;
	எனில் ((r = sshbuf_get_cstring(b, &ktype, வெற்று)) != 0 ||
	    (r = sshbuf_get_string_direct(b, &sigblob, &len)) != 0)
		செல் out;
	எனில் (strcmp("ssh-ed25519", ktype) != 0) {
		r = SSH_ERR_சாவி_TYPE_MISMATCH;
		செல் out;
	}
	எனில் (sshbuf_len(b) != 0) {
		r = SSH_ERR_UNEXPECTED_TRAILING_DATA;
		செல் out;
	}
	எனில் (len != crypto_sign_ed25519_BYTES) {
		r = SSH_ERR_INVALID_FORMAT;
		செல் out;
	}
	எனில் ((ret = crypto_sign_ed25519_verify_detached(sigblob, data, dlen,
	    சாவி->ed25519_pk)) != 0) {
		debug2_f("crypto_sign_ed25519_verify_detached failed: %d", ret);
	}
	எனில் (ret != 0) {
		r = SSH_ERR_SIGNATURE_INVALID;
		செல் out;
	}
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	விடுவி(ktype);
	திரும்பு r;
}

/* NB. not static; used by ED25519-SK */
மாறிலி கட்டமைப்பு sshkey_impl_funcs sshkey_ed25519_funcs = {
	/* .size = */		வெற்று,
	/* .alloc = */		வெற்று,
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

மாறிலி கட்டமைப்பு sshkey_impl sshkey_ed25519_impl = {
	/* .name = */		"ssh-ed25519",
	/* .shortname = */	"ED25519",
	/* .sigalg = */		வெற்று,
	/* .type = */		சாவி_ED25519,
	/* .nid = */		0,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	256,
	/* .funcs = */		&sshkey_ed25519_funcs,
};

மாறிலி கட்டமைப்பு sshkey_impl sshkey_ed25519_cert_impl = {
	/* .name = */		"ssh-ed25519-cert-v01@openssh.com",
	/* .shortname = */	"ED25519-CERT",
	/* .sigalg = */		வெற்று,
	/* .type = */		சாவி_ED25519_CERT,
	/* .nid = */		0,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	256,
	/* .funcs = */		&sshkey_ed25519_funcs,
};
