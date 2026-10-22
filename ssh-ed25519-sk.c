/* $OpenBSD: ssh-ed25519-sk.c,v 1.17 2026/09/16 00:43:00 djm Exp $ */
/*
 * Copyright (c) 2019 Markus Friedl.  All rights reserved.
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

/* #define DEBUG_SK 1 */

#ଅନ୍ତର୍ଭାଵ "includes.h"

#define SSHKEY_INTERNAL
#ଅନ୍ତର୍ଭାଵ <sys/types.h>

#ଅନ୍ତର୍ଭାଵ "crypto_api.h"

#ଅନ୍ତର୍ଭାଵ <string.h>
#ଅନ୍ତର୍ଭାଵ <stdarg.h>

#ଅନ୍ତର୍ଭାଵ "log.h"
#ଅନ୍ତର୍ଭାଵ "sshbuf.h"
#ଅନ୍ତର୍ଭାଵ "sshkey.h"
#ଅନ୍ତର୍ଭାଵ "ssherr.h"
#ଅନ୍ତର୍ଭାଵ "digest.h"

/* Reuse some ED25519 internals */
ବାହ୍ୟ ସଂରଚନା sshkey_impl_funcs sshkey_ed25519_funcs;

ସ୍ଥିର ଶୂନ୍ୟ
ssh_ed25519_sk_cleanup(ସଂରଚନା sshkey *k)
{
	sshkey_sk_cleanup(k);
	sshkey_ed25519_funcs.cleanup(k);
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_ed25519_sk_equal(ଅଚଳ ସଂରଚନା sshkey *a, ଅଚଳ ସଂରଚନା sshkey *b)
{
	ଯଦି (!sshkey_sk_fields_equal(a, b))
		ଫେରନ୍ତୁ 0;
	ଯଦି (!sshkey_ed25519_funcs.equal(a, b))
		ଫେରନ୍ତୁ 0;
	ଫେରନ୍ତୁ 1;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_ed25519_sk_serialize_public(ଅଚଳ ସଂରଚନା sshkey *ଚାବି, ସଂରଚନା sshbuf *b,
    ଗଣନା sshkey_serialize_rep opts)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି ((r = sshkey_ed25519_funcs.serialize_public(ଚାବି, b, opts)) != 0)
		ଫେରନ୍ତୁ r;
	ଯଦି ((r = sshkey_serialize_sk(ଚାବି, b)) != 0)
		ଫେରନ୍ତୁ r;

	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_ed25519_sk_serialize_private(ଅଚଳ ସଂରଚନା sshkey *ଚାବି, ସଂରଚନା sshbuf *b,
    ଗଣନା sshkey_serialize_rep opts)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି ((r = sshkey_ed25519_funcs.serialize_public(ଚାବି, b, opts)) != 0)
		ଫେରନ୍ତୁ r;
	ଯଦି ((r = sshkey_serialize_private_sk(ଚାବି, b)) != 0)
		ଫେରନ୍ତୁ r;

	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_ed25519_sk_copy_public(ଅଚଳ ସଂରଚନା sshkey *from, ସଂରଚନା sshkey *to)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି ((r = sshkey_ed25519_funcs.copy_public(from, to)) != 0)
		ଫେରନ୍ତୁ r;
	ଯଦି ((r = sshkey_copy_public_sk(from, to)) != 0)
		ଫେରନ୍ତୁ r;
	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_ed25519_sk_deserialize_public(ଅଚଳ ଅକ୍ଷର *ktype, ସଂରଚନା sshbuf *b,
    ସଂରଚନା sshkey *ଚାବି)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି ((r = sshkey_ed25519_funcs.deserialize_public(ktype, b, ଚାବି)) != 0)
		ଫେରନ୍ତୁ r;
	ଯଦି ((r = sshkey_deserialize_sk(b, ଚାବି)) != 0)
		ଫେରନ୍ତୁ r;
	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_ed25519_sk_deserialize_private(ଅଚଳ ଅକ୍ଷର *ktype, ସଂରଚନା sshbuf *b,
    ସଂରଚନା sshkey *ଚାବି)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି ((r = sshkey_ed25519_funcs.deserialize_public(ktype, b, ଚାବି)) != 0)
		ଫେରନ୍ତୁ r;
	ଯଦି ((r = sshkey_private_deserialize_sk(b, ଚାବି)) != 0)
		ଫେରନ୍ତୁ r;
	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_ed25519_sk_verify(ଅଚଳ ସଂରଚନା sshkey *ଚାବି,
    ଅଚଳ u_char *sig, size_t siglen,
    ଅଚଳ u_char *data, size_t dlen, ଅଚଳ ଅକ୍ଷର *alg, u_int compat,
    ସଂରଚନା sshkey_sig_details **detailsp)
{
	ସଂରଚନା sshbuf *b = ଖାଲି;
	ସଂରଚନା sshbuf *encoded = ଖାଲି;
	ଅକ୍ଷର *ktype = ଖାଲି;
	ଅଚଳ u_char *sigblob;
	u_char apphash[32];
	u_char msghash[32];
	u_char sig_flags;
	u_int sig_counter;
	size_t len;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r = SSH_ERR_INTERNAL_ERROR;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା ret;
	ସଂରଚନା sshkey_sig_details *details = ଖାଲି;

	ଯଦି (detailsp != ଖାଲି)
		*detailsp = ଖାଲି;

	ଯଦି (ଚାବି == ଖାଲି ||
	    sshkey_type_plain(ଚାବି->type) != ଚାବି_ED25519_SK ||
	    ଚାବି->ed25519_pk == ଖାଲି ||
	    sig == ଖାଲି || siglen == 0)
		ଫେରନ୍ତୁ SSH_ERR_INVALID_ARGUMENT;

	ଯଦି ((b = sshbuf_from(sig, siglen)) == ଖାଲି)
		ଫେରନ୍ତୁ SSH_ERR_ALLOC_FAIL;
	ଯଦି (sshbuf_get_cstring(b, &ktype, ଖାଲି) != 0 ||
	    sshbuf_get_string_direct(b, &sigblob, &len) != 0 ||
	    sshbuf_get_u8(b, &sig_flags) != 0 ||
	    sshbuf_get_u32(b, &sig_counter) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		ଯାଅ out;
	}
#ifdef DEBUG_SK
	fprintf(stderr, "%s: data:\n", __func__);
	/* sshbuf_dump_data(data, datalen, stderr); */
	fprintf(stderr, "%s: sigblob:\n", __func__);
	sshbuf_dump_data(sigblob, len, stderr);
	fprintf(stderr, "%s: sig_flags = 0x%02x, sig_counter = %u\n",
	    __func__, sig_flags, sig_counter);
#endif
	ଯଦି (strcmp(sshkey_ssh_name_plain(ଚାବି), ktype) != 0) {
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
	ଯଦି (ssh_digest_memory(SSH_DIGEST_SHA256, ଚାବି->sk_application,
	    strlen(ଚାବି->sk_application), apphash, ଆକାର(apphash)) != 0 ||
	    ssh_digest_memory(SSH_DIGEST_SHA256, data, dlen,
	    msghash, ଆକାର(msghash)) != 0) {
		r = SSH_ERR_INVALID_ARGUMENT;
		ଯାଅ out;
	}
#ifdef DEBUG_SK
	fprintf(stderr, "%s: hashed application:\n", __func__);
	sshbuf_dump_data(apphash, ଆକାର(apphash), stderr);
	fprintf(stderr, "%s: hashed message:\n", __func__);
	sshbuf_dump_data(msghash, ଆକାର(msghash), stderr);
#endif
	ଯଦି ((details = calloc(1, ଆକାର(*details))) == ଖାଲି) {
		r = SSH_ERR_ALLOC_FAIL;
		ଯାଅ out;
	}
	details->sk_counter = sig_counter;
	details->sk_flags = sig_flags;
	ଯଦି ((encoded = sshbuf_new()) == ଖାଲି) {
		r = SSH_ERR_ALLOC_FAIL;
		ଯାଅ out;
	}
	ଯଦି (sshbuf_put(encoded, apphash, ଆକାର(apphash)) != 0 ||
	    sshbuf_put_u8(encoded, sig_flags) != 0 ||
	    sshbuf_put_u32(encoded, sig_counter) != 0 ||
	    sshbuf_put(encoded, msghash, ଆକାର(msghash)) != 0) {
		r = SSH_ERR_ALLOC_FAIL;
		ଯାଅ out;
	}
#ifdef DEBUG_SK
	fprintf(stderr, "%s: signed buf:\n", __func__);
	sshbuf_dump(encoded, stderr);
#endif
	ଯଦି ((ret = crypto_sign_ed25519_verify_detached(sigblob,
	    sshbuf_ptr(encoded), sshbuf_len(encoded),
	    ଚାବି->ed25519_pk)) != 0) {
		debug2_f("crypto_sign_ed25519_verify_detached failed: %d", ret);
	}
	ଯଦି (ret != 0) {
		r = SSH_ERR_SIGNATURE_INVALID;
		ଯାଅ out;
	}
	/* success */
	r = 0;
	ଯଦି (detailsp != ଖାଲି) {
		*detailsp = details;
		details = ଖାଲି;
	}
 out:
	sshkey_sig_details_free(details);
	sshbuf_free(b);
	sshbuf_free(encoded);
	ମୁକ୍ତ(ktype);
	ଫେରନ୍ତୁ r;
}

ସ୍ଥିର ଅଚଳ ସଂରଚନା sshkey_impl_funcs sshkey_ed25519_sk_funcs = {
	/* .size = */		ଖାଲି,
	/* .alloc = */		ଖାଲି,
	/* .cleanup = */	ssh_ed25519_sk_cleanup,
	/* .equal = */		ssh_ed25519_sk_equal,
	/* .ssh_serialize_public = */ ssh_ed25519_sk_serialize_public,
	/* .ssh_deserialize_public = */ ssh_ed25519_sk_deserialize_public,
	/* .ssh_serialize_private = */ ssh_ed25519_sk_serialize_private,
	/* .ssh_deserialize_private = */ ssh_ed25519_sk_deserialize_private,
	/* .generate = */	ଖାଲି,
	/* .copy_public = */	ssh_ed25519_sk_copy_public,
	/* .sign = */		ଖାଲି,
	/* .verify = */		ssh_ed25519_sk_verify,
};

ଅଚଳ ସଂରଚନା sshkey_impl sshkey_ed25519_sk_impl = {
	/* .name = */		"sk-ssh-ed25519@openssh.com",
	/* .shortname = */	"ED25519-SK",
	/* .sigalg = */		ଖାଲି,
	/* .type = */		ଚାବି_ED25519_SK,
	/* .nid = */		0,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	256,
	/* .funcs = */		&sshkey_ed25519_sk_funcs,
};

ଅଚଳ ସଂରଚନା sshkey_impl sshkey_ed25519_sk_cert_impl = {
	/* .name = */		"sk-ssh-ed25519-cert-v01@openssh.com",
	/* .shortname = */	"ED25519-SK-CERT",
	/* .sigalg = */		ଖାଲି,
	/* .type = */		ଚାବି_ED25519_SK_CERT,
	/* .nid = */		0,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	256,
	/* .funcs = */		&sshkey_ed25519_sk_funcs,
};
