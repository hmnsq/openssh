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

#અન્તર્ભાવ "includes.h"

#અન્તર્ભાવ <sys/types.h>
#અન્તર્ભાવ <limits.h>

#અન્તર્ભાવ "crypto_api.h"

#અન્તર્ભાવ <string.h>
#અન્તર્ભાવ <stdarg.h>

#અન્તર્ભાવ "log.h"
#અન્તર્ભાવ "sshbuf.h"
#define SSHKEY_INTERNAL
#અન્તર્ભાવ "sshkey.h"
#અન્તર્ભાવ "ssherr.h"

સ્થિર શૂન્ય
ssh_ed25519_cleanup(સંરચના sshkey *k)
{
	freezero(k->ed25519_pk, ED25519_PK_SZ);
	freezero(k->ed25519_sk, ED25519_SK_SZ);
	k->ed25519_pk = ખાલી;
	k->ed25519_sk = ખાલી;
}

સ્થિર પૂર્ણાંક
ssh_ed25519_equal(અચલ સંરચના sshkey *a, અચલ સંરચના sshkey *b)
{
	જો (a->ed25519_pk == ખાલી || b->ed25519_pk == ખાલી)
		પાછા 0;
	જો (memcmp(a->ed25519_pk, b->ed25519_pk, ED25519_PK_SZ) != 0)
		પાછા 0;
	પાછા 1;
}

સ્થિર પૂર્ણાંક
ssh_ed25519_serialize_public(અચલ સંરચના sshkey *ચાવી, સંરચના sshbuf *b,
    ગણના sshkey_serialize_rep opts)
{
	પૂર્ણાંક r;

	જો (ચાવી->ed25519_pk == ખાલી)
		પાછા SSH_ERR_INVALID_ARGUMENT;
	જો ((r = sshbuf_put_string(b, ચાવી->ed25519_pk, ED25519_PK_SZ)) != 0)
		પાછા r;

	પાછા 0;
}

સ્થિર પૂર્ણાંક
ssh_ed25519_serialize_private(અચલ સંરચના sshkey *ચાવી, સંરચના sshbuf *b,
    ગણના sshkey_serialize_rep opts)
{
	પૂર્ણાંક r;

	જો ((r = sshbuf_put_string(b, ચાવી->ed25519_pk, ED25519_PK_SZ)) != 0 ||
	    (r = sshbuf_put_string(b, ચાવી->ed25519_sk, ED25519_SK_SZ)) != 0)
		પાછા r;

	પાછા 0;
}

સ્થિર પૂર્ણાંક
ssh_ed25519_generate(સંરચના sshkey *k, પૂર્ણાંક bits)
{
	જો ((k->ed25519_pk = malloc(ED25519_PK_SZ)) == ખાલી ||
	    (k->ed25519_sk = malloc(ED25519_SK_SZ)) == ખાલી)
		પાછા SSH_ERR_ALLOC_FAIL;
	જો (crypto_sign_ed25519_keypair(k->ed25519_pk, k->ed25519_sk) != 0)
		પાછા SSH_ERR_CRYPTO_ERROR;
	પાછા 0;
}

સ્થિર પૂર્ણાંક
ssh_ed25519_copy_public(અચલ સંરચના sshkey *from, સંરચના sshkey *to)
{
	જો (from->ed25519_pk == ખાલી)
		પાછા 0; /* XXX SSH_ERR_INTERNAL_ERROR ? */
	જો ((to->ed25519_pk = malloc(ED25519_PK_SZ)) == ખાલી)
		પાછા SSH_ERR_ALLOC_FAIL;
	memcpy(to->ed25519_pk, from->ed25519_pk, ED25519_PK_SZ);
	પાછા 0;
}

સ્થિર પૂર્ણાંક
ssh_ed25519_deserialize_public(અચલ અક્ષર *ktype, સંરચના sshbuf *b,
    સંરચના sshkey *ચાવી)
{
	u_char *pk = ખાલી;
	size_t len = 0;
	પૂર્ણાંક r;

	જો ((r = sshbuf_get_string(b, &pk, &len)) != 0)
		પાછા r;
	જો (len != ED25519_PK_SZ) {
		freezero(pk, len);
		પાછા SSH_ERR_INVALID_FORMAT;
	}
	ચાવી->ed25519_pk = pk;
	પાછા 0;
}

સ્થિર પૂર્ણાંક
ssh_ed25519_deserialize_private(અચલ અક્ષર *ktype, સંરચના sshbuf *b,
    સંરચના sshkey *ચાવી)
{
	પૂર્ણાંક r;
	size_t sklen = 0;
	u_char *ed25519_sk = ખાલી;

	જો ((r = ssh_ed25519_deserialize_public(ખાલી, b, ચાવી)) != 0)
		જાઓ out;
	જો ((r = sshbuf_get_string(b, &ed25519_sk, &sklen)) != 0)
		જાઓ out;
	જો (sklen != ED25519_SK_SZ) {
		r = SSH_ERR_INVALID_FORMAT;
		જાઓ out;
	}
	ચાવી->ed25519_sk = ed25519_sk;
	ed25519_sk = ખાલી; /* transferred */
	/* success */
	r = 0;
 out:
	freezero(ed25519_sk, sklen);
	પાછા r;
}

સ્થિર પૂર્ણાંક
ssh_ed25519_sign(સંરચના sshkey *ચાવી,
    u_char **sigp, size_t *lenp,
    અચલ u_char *data, size_t datalen,
    અચલ અક્ષર *alg, અચલ અક્ષર *sk_provider, અચલ અક્ષર *sk_pin, u_int compat)
{
	u_char sig[crypto_sign_ed25519_BYTES];
	unsigned long long siglen = 0;
	પૂર્ણાંક r, ret;

	જો (lenp != ખાલી)
		*lenp = 0;
	જો (sigp != ખાલી)
		*sigp = ખાલી;

	જો (ચાવી == ખાલી ||
	    sshkey_type_plain(ચાવી->type) != ચાવી_ED25519 ||
	    ચાવી->ed25519_sk == ખાલી)
		પાછા SSH_ERR_INVALID_ARGUMENT;

	જો ((ret = crypto_sign_ed25519_detached(sig, &siglen, data, datalen,
	    ચાવી->ed25519_sk)) != 0 || siglen != કદ(sig)) {
		r = SSH_ERR_INVALID_ARGUMENT; /* XXX better error? */
		જાઓ out;
	}
	જો ((r = ssh_ed25519_encode_store_sig(sig, siglen,
	    sigp, lenp)) != 0)
		જાઓ out;

	/* success */
	r = 0;
 out:
	explicit_bzero(sig, કદ(sig));
	પાછા r;
}

પૂર્ણાંક
ssh_ed25519_encode_store_sig(અચલ u_char *sig, size_t slen,
    u_char **sigp, size_t *lenp)
{
	સંરચના sshbuf *b = ખાલી;
	પૂર્ણાંક r = -1;
	size_t len;

	જો (lenp != ખાલી)
		*lenp = 0;
	જો (sigp != ખાલી)
		*sigp = ખાલી;

	જો (slen != crypto_sign_ed25519_BYTES)
		પાછા SSH_ERR_INVALID_ARGUMENT;

	/* encode signature */
	જો ((b = sshbuf_new()) == ખાલી) {
		r = SSH_ERR_ALLOC_FAIL;
		જાઓ out;
	}
	જો ((r = sshbuf_put_cstring(b, "ssh-ed25519")) != 0 ||
	    (r = sshbuf_put_string(b, sig, slen)) != 0)
		જાઓ out;
	len = sshbuf_len(b);
	જો (sigp != ખાલી) {
		જો ((*sigp = malloc(len)) == ખાલી) {
			r = SSH_ERR_ALLOC_FAIL;
			જાઓ out;
		}
		memcpy(*sigp, sshbuf_ptr(b), len);
	}
	જો (lenp != ખાલી)
		*lenp = len;
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	પાછા r;
}

સ્થિર પૂર્ણાંક
ssh_ed25519_verify(અચલ સંરચના sshkey *ચાવી,
    અચલ u_char *sig, size_t siglen,
    અચલ u_char *data, size_t dlen, અચલ અક્ષર *alg, u_int compat,
    સંરચના sshkey_sig_details **detailsp)
{
	સંરચના sshbuf *b = ખાલી;
	અક્ષર *ktype = ખાલી;
	અચલ u_char *sigblob;
	size_t len;
	પૂર્ણાંક r, ret;

	જો (ચાવી == ખાલી ||
	    sshkey_type_plain(ચાવી->type) != ચાવી_ED25519 ||
	    ચાવી->ed25519_pk == ખાલી ||
	    sig == ખાલી || siglen == 0)
		પાછા SSH_ERR_INVALID_ARGUMENT;

	જો ((b = sshbuf_from(sig, siglen)) == ખાલી)
		પાછા SSH_ERR_ALLOC_FAIL;
	જો ((r = sshbuf_get_cstring(b, &ktype, ખાલી)) != 0 ||
	    (r = sshbuf_get_string_direct(b, &sigblob, &len)) != 0)
		જાઓ out;
	જો (strcmp("ssh-ed25519", ktype) != 0) {
		r = SSH_ERR_ચાવી_TYPE_MISMATCH;
		જાઓ out;
	}
	જો (sshbuf_len(b) != 0) {
		r = SSH_ERR_UNEXPECTED_TRAILING_DATA;
		જાઓ out;
	}
	જો (len != crypto_sign_ed25519_BYTES) {
		r = SSH_ERR_INVALID_FORMAT;
		જાઓ out;
	}
	જો ((ret = crypto_sign_ed25519_verify_detached(sigblob, data, dlen,
	    ચાવી->ed25519_pk)) != 0) {
		debug2_f("crypto_sign_ed25519_verify_detached failed: %d", ret);
	}
	જો (ret != 0) {
		r = SSH_ERR_SIGNATURE_INVALID;
		જાઓ out;
	}
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	મુક્ત(ktype);
	પાછા r;
}

/* NB. not static; used by ED25519-SK */
અચલ સંરચના sshkey_impl_funcs sshkey_ed25519_funcs = {
	/* .size = */		ખાલી,
	/* .alloc = */		ખાલી,
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

અચલ સંરચના sshkey_impl sshkey_ed25519_impl = {
	/* .name = */		"ssh-ed25519",
	/* .shortname = */	"ED25519",
	/* .sigalg = */		ખાલી,
	/* .type = */		ચાવી_ED25519,
	/* .nid = */		0,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	256,
	/* .funcs = */		&sshkey_ed25519_funcs,
};

અચલ સંરચના sshkey_impl sshkey_ed25519_cert_impl = {
	/* .name = */		"ssh-ed25519-cert-v01@openssh.com",
	/* .shortname = */	"ED25519-CERT",
	/* .sigalg = */		ખાલી,
	/* .type = */		ચાવી_ED25519_CERT,
	/* .nid = */		0,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	256,
	/* .funcs = */		&sshkey_ed25519_funcs,
};
