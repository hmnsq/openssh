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

#অন্তর্ভাব "includes.h"

#অন্তর্ভাব <sys/types.h>
#অন্তর্ভাব <limits.h>

#অন্তর্ভাব "crypto_api.h"

#অন্তর্ভাব <string.h>
#অন্তর্ভাব <stdarg.h>

#অন্তর্ভাব "log.h"
#অন্তর্ভাব "sshbuf.h"
#define SSHKEY_INTERNAL
#অন্তর্ভাব "sshkey.h"
#অন্তর্ভাব "ssherr.h"

স্থির শূন্য
ssh_ed25519_cleanup(সংরচনা sshkey *k)
{
	freezero(k->ed25519_pk, ED25519_PK_SZ);
	freezero(k->ed25519_sk, ED25519_SK_SZ);
	k->ed25519_pk = রিক্ত;
	k->ed25519_sk = রিক্ত;
}

স্থির পূর্ণাঙ্ক
ssh_ed25519_equal(ধ্রুব সংরচনা sshkey *a, ধ্রুব সংরচনা sshkey *b)
{
	যদি (a->ed25519_pk == রিক্ত || b->ed25519_pk == রিক্ত)
		প্রত্যাগম 0;
	যদি (memcmp(a->ed25519_pk, b->ed25519_pk, ED25519_PK_SZ) != 0)
		প্রত্যাগম 0;
	প্রত্যাগম 1;
}

স্থির পূর্ণাঙ্ক
ssh_ed25519_serialize_public(ধ্রুব সংরচনা sshkey *চাবি, সংরচনা sshbuf *b,
    গণনা sshkey_serialize_rep opts)
{
	পূর্ণাঙ্ক r;

	যদি (চাবি->ed25519_pk == রিক্ত)
		প্রত্যাগম SSH_ERR_INVALID_ARGUMENT;
	যদি ((r = sshbuf_put_string(b, চাবি->ed25519_pk, ED25519_PK_SZ)) != 0)
		প্রত্যাগম r;

	প্রত্যাগম 0;
}

স্থির পূর্ণাঙ্ক
ssh_ed25519_serialize_private(ধ্রুব সংরচনা sshkey *চাবি, সংরচনা sshbuf *b,
    গণনা sshkey_serialize_rep opts)
{
	পূর্ণাঙ্ক r;

	যদি ((r = sshbuf_put_string(b, চাবি->ed25519_pk, ED25519_PK_SZ)) != 0 ||
	    (r = sshbuf_put_string(b, চাবি->ed25519_sk, ED25519_SK_SZ)) != 0)
		প্রত্যাগম r;

	প্রত্যাগম 0;
}

স্থির পূর্ণাঙ্ক
ssh_ed25519_generate(সংরচনা sshkey *k, পূর্ণাঙ্ক bits)
{
	যদি ((k->ed25519_pk = malloc(ED25519_PK_SZ)) == রিক্ত ||
	    (k->ed25519_sk = malloc(ED25519_SK_SZ)) == রিক্ত)
		প্রত্যাগম SSH_ERR_ALLOC_FAIL;
	যদি (crypto_sign_ed25519_keypair(k->ed25519_pk, k->ed25519_sk) != 0)
		প্রত্যাগম SSH_ERR_CRYPTO_ERROR;
	প্রত্যাগম 0;
}

স্থির পূর্ণাঙ্ক
ssh_ed25519_copy_public(ধ্রুব সংরচনা sshkey *from, সংরচনা sshkey *to)
{
	যদি (from->ed25519_pk == রিক্ত)
		প্রত্যাগম 0; /* XXX SSH_ERR_INTERNAL_ERROR ? */
	যদি ((to->ed25519_pk = malloc(ED25519_PK_SZ)) == রিক্ত)
		প্রত্যাগম SSH_ERR_ALLOC_FAIL;
	memcpy(to->ed25519_pk, from->ed25519_pk, ED25519_PK_SZ);
	প্রত্যাগম 0;
}

স্থির পূর্ণাঙ্ক
ssh_ed25519_deserialize_public(ধ্রুব বর্ণ *ktype, সংরচনা sshbuf *b,
    সংরচনা sshkey *চাবি)
{
	u_char *pk = রিক্ত;
	size_t len = 0;
	পূর্ণাঙ্ক r;

	যদি ((r = sshbuf_get_string(b, &pk, &len)) != 0)
		প্রত্যাগম r;
	যদি (len != ED25519_PK_SZ) {
		freezero(pk, len);
		প্রত্যাগম SSH_ERR_INVALID_FORMAT;
	}
	চাবি->ed25519_pk = pk;
	প্রত্যাগম 0;
}

স্থির পূর্ণাঙ্ক
ssh_ed25519_deserialize_private(ধ্রুব বর্ণ *ktype, সংরচনা sshbuf *b,
    সংরচনা sshkey *চাবি)
{
	পূর্ণাঙ্ক r;
	size_t sklen = 0;
	u_char *ed25519_sk = রিক্ত;

	যদি ((r = ssh_ed25519_deserialize_public(রিক্ত, b, চাবি)) != 0)
		গচ্ছ out;
	যদি ((r = sshbuf_get_string(b, &ed25519_sk, &sklen)) != 0)
		গচ্ছ out;
	যদি (sklen != ED25519_SK_SZ) {
		r = SSH_ERR_INVALID_FORMAT;
		গচ্ছ out;
	}
	চাবি->ed25519_sk = ed25519_sk;
	ed25519_sk = রিক্ত; /* transferred */
	/* success */
	r = 0;
 out:
	freezero(ed25519_sk, sklen);
	প্রত্যাগম r;
}

স্থির পূর্ণাঙ্ক
ssh_ed25519_sign(সংরচনা sshkey *চাবি,
    u_char **sigp, size_t *lenp,
    ধ্রুব u_char *data, size_t datalen,
    ধ্রুব বর্ণ *alg, ধ্রুব বর্ণ *sk_provider, ধ্রুব বর্ণ *sk_pin, u_int compat)
{
	u_char sig[crypto_sign_ed25519_BYTES];
	unsigned long long siglen = 0;
	পূর্ণাঙ্ক r, ret;

	যদি (lenp != রিক্ত)
		*lenp = 0;
	যদি (sigp != রিক্ত)
		*sigp = রিক্ত;

	যদি (চাবি == রিক্ত ||
	    sshkey_type_plain(চাবি->type) != চাবি_ED25519 ||
	    চাবি->ed25519_sk == রিক্ত)
		প্রত্যাগম SSH_ERR_INVALID_ARGUMENT;

	যদি ((ret = crypto_sign_ed25519_detached(sig, &siglen, data, datalen,
	    চাবি->ed25519_sk)) != 0 || siglen != পরিমাণ(sig)) {
		r = SSH_ERR_INVALID_ARGUMENT; /* XXX better error? */
		গচ্ছ out;
	}
	যদি ((r = ssh_ed25519_encode_store_sig(sig, siglen,
	    sigp, lenp)) != 0)
		গচ্ছ out;

	/* success */
	r = 0;
 out:
	explicit_bzero(sig, পরিমাণ(sig));
	প্রত্যাগম r;
}

পূর্ণাঙ্ক
ssh_ed25519_encode_store_sig(ধ্রুব u_char *sig, size_t slen,
    u_char **sigp, size_t *lenp)
{
	সংরচনা sshbuf *b = রিক্ত;
	পূর্ণাঙ্ক r = -1;
	size_t len;

	যদি (lenp != রিক্ত)
		*lenp = 0;
	যদি (sigp != রিক্ত)
		*sigp = রিক্ত;

	যদি (slen != crypto_sign_ed25519_BYTES)
		প্রত্যাগম SSH_ERR_INVALID_ARGUMENT;

	/* encode signature */
	যদি ((b = sshbuf_new()) == রিক্ত) {
		r = SSH_ERR_ALLOC_FAIL;
		গচ্ছ out;
	}
	যদি ((r = sshbuf_put_cstring(b, "ssh-ed25519")) != 0 ||
	    (r = sshbuf_put_string(b, sig, slen)) != 0)
		গচ্ছ out;
	len = sshbuf_len(b);
	যদি (sigp != রিক্ত) {
		যদি ((*sigp = malloc(len)) == রিক্ত) {
			r = SSH_ERR_ALLOC_FAIL;
			গচ্ছ out;
		}
		memcpy(*sigp, sshbuf_ptr(b), len);
	}
	যদি (lenp != রিক্ত)
		*lenp = len;
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	প্রত্যাগম r;
}

স্থির পূর্ণাঙ্ক
ssh_ed25519_verify(ধ্রুব সংরচনা sshkey *চাবি,
    ধ্রুব u_char *sig, size_t siglen,
    ধ্রুব u_char *data, size_t dlen, ধ্রুব বর্ণ *alg, u_int compat,
    সংরচনা sshkey_sig_details **detailsp)
{
	সংরচনা sshbuf *b = রিক্ত;
	বর্ণ *ktype = রিক্ত;
	ধ্রুব u_char *sigblob;
	size_t len;
	পূর্ণাঙ্ক r, ret;

	যদি (চাবি == রিক্ত ||
	    sshkey_type_plain(চাবি->type) != চাবি_ED25519 ||
	    চাবি->ed25519_pk == রিক্ত ||
	    sig == রিক্ত || siglen == 0)
		প্রত্যাগম SSH_ERR_INVALID_ARGUMENT;

	যদি ((b = sshbuf_from(sig, siglen)) == রিক্ত)
		প্রত্যাগম SSH_ERR_ALLOC_FAIL;
	যদি ((r = sshbuf_get_cstring(b, &ktype, রিক্ত)) != 0 ||
	    (r = sshbuf_get_string_direct(b, &sigblob, &len)) != 0)
		গচ্ছ out;
	যদি (strcmp("ssh-ed25519", ktype) != 0) {
		r = SSH_ERR_চাবি_TYPE_MISMATCH;
		গচ্ছ out;
	}
	যদি (sshbuf_len(b) != 0) {
		r = SSH_ERR_UNEXPECTED_TRAILING_DATA;
		গচ্ছ out;
	}
	যদি (len != crypto_sign_ed25519_BYTES) {
		r = SSH_ERR_INVALID_FORMAT;
		গচ্ছ out;
	}
	যদি ((ret = crypto_sign_ed25519_verify_detached(sigblob, data, dlen,
	    চাবি->ed25519_pk)) != 0) {
		debug2_f("crypto_sign_ed25519_verify_detached failed: %d", ret);
	}
	যদি (ret != 0) {
		r = SSH_ERR_SIGNATURE_INVALID;
		গচ্ছ out;
	}
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	মুক্ত(ktype);
	প্রত্যাগম r;
}

/* NB. not static; used by ED25519-SK */
ধ্রুব সংরচনা sshkey_impl_funcs sshkey_ed25519_funcs = {
	/* .size = */		রিক্ত,
	/* .alloc = */		রিক্ত,
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

ধ্রুব সংরচনা sshkey_impl sshkey_ed25519_impl = {
	/* .name = */		"ssh-ed25519",
	/* .shortname = */	"ED25519",
	/* .sigalg = */		রিক্ত,
	/* .type = */		চাবি_ED25519,
	/* .nid = */		0,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	256,
	/* .funcs = */		&sshkey_ed25519_funcs,
};

ধ্রুব সংরচনা sshkey_impl sshkey_ed25519_cert_impl = {
	/* .name = */		"ssh-ed25519-cert-v01@openssh.com",
	/* .shortname = */	"ED25519-CERT",
	/* .sigalg = */		রিক্ত,
	/* .type = */		চাবি_ED25519_CERT,
	/* .nid = */		0,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	256,
	/* .funcs = */		&sshkey_ed25519_funcs,
};
