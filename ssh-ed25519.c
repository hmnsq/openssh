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

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ଅନ୍ତର୍ଭାଵ <sys/types.h>
#ଅନ୍ତର୍ଭାଵ <limits.h>

#ଅନ୍ତର୍ଭାଵ "crypto_api.h"

#ଅନ୍ତର୍ଭାଵ <string.h>
#ଅନ୍ତର୍ଭାଵ <stdarg.h>

#ଅନ୍ତର୍ଭାଵ "log.h"
#ଅନ୍ତର୍ଭାଵ "sshbuf.h"
#define SSHKEY_INTERNAL
#ଅନ୍ତର୍ଭାଵ "sshkey.h"
#ଅନ୍ତର୍ଭାଵ "ssherr.h"

ସ୍ଥିର ଶୂନ୍ୟ
ssh_ed25519_cleanup(ସଂରଚନା sshkey *k)
{
	freezero(k->ed25519_pk, ED25519_PK_SZ);
	freezero(k->ed25519_sk, ED25519_SK_SZ);
	k->ed25519_pk = ଖାଲି;
	k->ed25519_sk = ଖାଲି;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_ed25519_equal(ଅଚଳ ସଂରଚନା sshkey *a, ଅଚଳ ସଂରଚନା sshkey *b)
{
	ଯଦି (a->ed25519_pk == ଖାଲି || b->ed25519_pk == ଖାଲି)
		ଫେରନ୍ତୁ 0;
	ଯଦି (memcmp(a->ed25519_pk, b->ed25519_pk, ED25519_PK_SZ) != 0)
		ଫେରନ୍ତୁ 0;
	ଫେରନ୍ତୁ 1;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_ed25519_serialize_public(ଅଚଳ ସଂରଚନା sshkey *ଚାବି, ସଂରଚନା sshbuf *b,
    ଗଣନା sshkey_serialize_rep opts)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି (ଚାବି->ed25519_pk == ଖାଲି)
		ଫେରନ୍ତୁ SSH_ERR_INVALID_ARGUMENT;
	ଯଦି ((r = sshbuf_put_string(b, ଚାବି->ed25519_pk, ED25519_PK_SZ)) != 0)
		ଫେରନ୍ତୁ r;

	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_ed25519_serialize_private(ଅଚଳ ସଂରଚନା sshkey *ଚାବି, ସଂରଚନା sshbuf *b,
    ଗଣନା sshkey_serialize_rep opts)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି ((r = sshbuf_put_string(b, ଚାବି->ed25519_pk, ED25519_PK_SZ)) != 0 ||
	    (r = sshbuf_put_string(b, ଚାବି->ed25519_sk, ED25519_SK_SZ)) != 0)
		ଫେରନ୍ତୁ r;

	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_ed25519_generate(ସଂରଚନା sshkey *k, ପୂର୍ଣ୍ଣସଂଖ୍ୟା bits)
{
	ଯଦି ((k->ed25519_pk = malloc(ED25519_PK_SZ)) == ଖାଲି ||
	    (k->ed25519_sk = malloc(ED25519_SK_SZ)) == ଖାଲି)
		ଫେରନ୍ତୁ SSH_ERR_ALLOC_FAIL;
	ଯଦି (crypto_sign_ed25519_keypair(k->ed25519_pk, k->ed25519_sk) != 0)
		ଫେରନ୍ତୁ SSH_ERR_CRYPTO_ERROR;
	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_ed25519_copy_public(ଅଚଳ ସଂରଚନା sshkey *from, ସଂରଚନା sshkey *to)
{
	ଯଦି (from->ed25519_pk == ଖାଲି)
		ଫେରନ୍ତୁ 0; /* XXX SSH_ERR_INTERNAL_ERROR ? */
	ଯଦି ((to->ed25519_pk = malloc(ED25519_PK_SZ)) == ଖାଲି)
		ଫେରନ୍ତୁ SSH_ERR_ALLOC_FAIL;
	memcpy(to->ed25519_pk, from->ed25519_pk, ED25519_PK_SZ);
	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_ed25519_deserialize_public(ଅଚଳ ଅକ୍ଷର *ktype, ସଂରଚନା sshbuf *b,
    ସଂରଚନା sshkey *ଚାବି)
{
	u_char *pk = ଖାଲି;
	size_t len = 0;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି ((r = sshbuf_get_string(b, &pk, &len)) != 0)
		ଫେରନ୍ତୁ r;
	ଯଦି (len != ED25519_PK_SZ) {
		freezero(pk, len);
		ଫେରନ୍ତୁ SSH_ERR_INVALID_FORMAT;
	}
	ଚାବି->ed25519_pk = pk;
	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_ed25519_deserialize_private(ଅଚଳ ଅକ୍ଷର *ktype, ସଂରଚନା sshbuf *b,
    ସଂରଚନା sshkey *ଚାବି)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;
	size_t sklen = 0;
	u_char *ed25519_sk = ଖାଲି;

	ଯଦି ((r = ssh_ed25519_deserialize_public(ଖାଲି, b, ଚାବି)) != 0)
		ଯାଅ out;
	ଯଦି ((r = sshbuf_get_string(b, &ed25519_sk, &sklen)) != 0)
		ଯାଅ out;
	ଯଦି (sklen != ED25519_SK_SZ) {
		r = SSH_ERR_INVALID_FORMAT;
		ଯାଅ out;
	}
	ଚାବି->ed25519_sk = ed25519_sk;
	ed25519_sk = ଖାଲି; /* transferred */
	/* success */
	r = 0;
 out:
	freezero(ed25519_sk, sklen);
	ଫେରନ୍ତୁ r;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_ed25519_sign(ସଂରଚନା sshkey *ଚାବି,
    u_char **sigp, size_t *lenp,
    ଅଚଳ u_char *data, size_t datalen,
    ଅଚଳ ଅକ୍ଷର *alg, ଅଚଳ ଅକ୍ଷର *sk_provider, ଅଚଳ ଅକ୍ଷର *sk_pin, u_int compat)
{
	u_char sig[crypto_sign_ed25519_BYTES];
	unsigned long long siglen = 0;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, ret;

	ଯଦି (lenp != ଖାଲି)
		*lenp = 0;
	ଯଦି (sigp != ଖାଲି)
		*sigp = ଖାଲି;

	ଯଦି (ଚାବି == ଖାଲି ||
	    sshkey_type_plain(ଚାବି->type) != ଚାବି_ED25519 ||
	    ଚାବି->ed25519_sk == ଖାଲି)
		ଫେରନ୍ତୁ SSH_ERR_INVALID_ARGUMENT;

	ଯଦି ((ret = crypto_sign_ed25519_detached(sig, &siglen, data, datalen,
	    ଚାବି->ed25519_sk)) != 0 || siglen != ଆକାର(sig)) {
		r = SSH_ERR_INVALID_ARGUMENT; /* XXX better error? */
		ଯାଅ out;
	}
	ଯଦି ((r = ssh_ed25519_encode_store_sig(sig, siglen,
	    sigp, lenp)) != 0)
		ଯାଅ out;

	/* success */
	r = 0;
 out:
	explicit_bzero(sig, ଆକାର(sig));
	ଫେରନ୍ତୁ r;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_ed25519_encode_store_sig(ଅଚଳ u_char *sig, size_t slen,
    u_char **sigp, size_t *lenp)
{
	ସଂରଚନା sshbuf *b = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r = -1;
	size_t len;

	ଯଦି (lenp != ଖାଲି)
		*lenp = 0;
	ଯଦି (sigp != ଖାଲି)
		*sigp = ଖାଲି;

	ଯଦି (slen != crypto_sign_ed25519_BYTES)
		ଫେରନ୍ତୁ SSH_ERR_INVALID_ARGUMENT;

	/* encode signature */
	ଯଦି ((b = sshbuf_new()) == ଖାଲି) {
		r = SSH_ERR_ALLOC_FAIL;
		ଯାଅ out;
	}
	ଯଦି ((r = sshbuf_put_cstring(b, "ssh-ed25519")) != 0 ||
	    (r = sshbuf_put_string(b, sig, slen)) != 0)
		ଯାଅ out;
	len = sshbuf_len(b);
	ଯଦି (sigp != ଖାଲି) {
		ଯଦି ((*sigp = malloc(len)) == ଖାଲି) {
			r = SSH_ERR_ALLOC_FAIL;
			ଯାଅ out;
		}
		memcpy(*sigp, sshbuf_ptr(b), len);
	}
	ଯଦି (lenp != ଖାଲି)
		*lenp = len;
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	ଫେରନ୍ତୁ r;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_ed25519_verify(ଅଚଳ ସଂରଚନା sshkey *ଚାବି,
    ଅଚଳ u_char *sig, size_t siglen,
    ଅଚଳ u_char *data, size_t dlen, ଅଚଳ ଅକ୍ଷର *alg, u_int compat,
    ସଂରଚନା sshkey_sig_details **detailsp)
{
	ସଂରଚନା sshbuf *b = ଖାଲି;
	ଅକ୍ଷର *ktype = ଖାଲି;
	ଅଚଳ u_char *sigblob;
	size_t len;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, ret;

	ଯଦି (ଚାବି == ଖାଲି ||
	    sshkey_type_plain(ଚାବି->type) != ଚାବି_ED25519 ||
	    ଚାବି->ed25519_pk == ଖାଲି ||
	    sig == ଖାଲି || siglen == 0)
		ଫେରନ୍ତୁ SSH_ERR_INVALID_ARGUMENT;

	ଯଦି ((b = sshbuf_from(sig, siglen)) == ଖାଲି)
		ଫେରନ୍ତୁ SSH_ERR_ALLOC_FAIL;
	ଯଦି ((r = sshbuf_get_cstring(b, &ktype, ଖାଲି)) != 0 ||
	    (r = sshbuf_get_string_direct(b, &sigblob, &len)) != 0)
		ଯାଅ out;
	ଯଦି (strcmp("ssh-ed25519", ktype) != 0) {
		r = SSH_ERR_ଚାବି_TYPE_MISMATCH;
		ଯାଅ out;
	}
	ଯଦି (sshbuf_len(b) != 0) {
		r = SSH_ERR_UNEXPECTED_TRAILING_DATA;
		ଯାଅ out;
	}
	ଯଦି (len != crypto_sign_ed25519_BYTES) {
		r = SSH_ERR_INVALID_FORMAT;
		ଯାଅ out;
	}
	ଯଦି ((ret = crypto_sign_ed25519_verify_detached(sigblob, data, dlen,
	    ଚାବି->ed25519_pk)) != 0) {
		debug2_f("crypto_sign_ed25519_verify_detached failed: %d", ret);
	}
	ଯଦି (ret != 0) {
		r = SSH_ERR_SIGNATURE_INVALID;
		ଯାଅ out;
	}
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	ମୁକ୍ତ(ktype);
	ଫେରନ୍ତୁ r;
}

/* NB. not static; used by ED25519-SK */
ଅଚଳ ସଂରଚନା sshkey_impl_funcs sshkey_ed25519_funcs = {
	/* .size = */		ଖାଲି,
	/* .alloc = */		ଖାଲି,
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

ଅଚଳ ସଂରଚନା sshkey_impl sshkey_ed25519_impl = {
	/* .name = */		"ssh-ed25519",
	/* .shortname = */	"ED25519",
	/* .sigalg = */		ଖାଲି,
	/* .type = */		ଚାବି_ED25519,
	/* .nid = */		0,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	256,
	/* .funcs = */		&sshkey_ed25519_funcs,
};

ଅଚଳ ସଂରଚନା sshkey_impl sshkey_ed25519_cert_impl = {
	/* .name = */		"ssh-ed25519-cert-v01@openssh.com",
	/* .shortname = */	"ED25519-CERT",
	/* .sigalg = */		ଖାଲି,
	/* .type = */		ଚାବି_ED25519_CERT,
	/* .nid = */		0,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	256,
	/* .funcs = */		&sshkey_ed25519_funcs,
};
