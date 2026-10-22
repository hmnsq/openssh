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

#અન્તર્ભાવ "includes.h"

#define SSHKEY_INTERNAL
#અન્તર્ભાવ <sys/types.h>

#અન્તર્ભાવ "crypto_api.h"

#અન્તર્ભાવ <string.h>
#અન્તર્ભાવ <stdarg.h>

#અન્તર્ભાવ "log.h"
#અન્તર્ભાવ "sshbuf.h"
#અન્તર્ભાવ "sshkey.h"
#અન્તર્ભાવ "ssherr.h"
#અન્તર્ભાવ "digest.h"

/* Reuse some ED25519 internals */
બાહ્ય સંરચના sshkey_impl_funcs sshkey_ed25519_funcs;

સ્થિર શૂન્ય
ssh_ed25519_sk_cleanup(સંરચના sshkey *k)
{
	sshkey_sk_cleanup(k);
	sshkey_ed25519_funcs.cleanup(k);
}

સ્થિર પૂર્ણાંક
ssh_ed25519_sk_equal(અચલ સંરચના sshkey *a, અચલ સંરચના sshkey *b)
{
	જો (!sshkey_sk_fields_equal(a, b))
		પાછા 0;
	જો (!sshkey_ed25519_funcs.equal(a, b))
		પાછા 0;
	પાછા 1;
}

સ્થિર પૂર્ણાંક
ssh_ed25519_sk_serialize_public(અચલ સંરચના sshkey *ચાવી, સંરચના sshbuf *b,
    ગણના sshkey_serialize_rep opts)
{
	પૂર્ણાંક r;

	જો ((r = sshkey_ed25519_funcs.serialize_public(ચાવી, b, opts)) != 0)
		પાછા r;
	જો ((r = sshkey_serialize_sk(ચાવી, b)) != 0)
		પાછા r;

	પાછા 0;
}

સ્થિર પૂર્ણાંક
ssh_ed25519_sk_serialize_private(અચલ સંરચના sshkey *ચાવી, સંરચના sshbuf *b,
    ગણના sshkey_serialize_rep opts)
{
	પૂર્ણાંક r;

	જો ((r = sshkey_ed25519_funcs.serialize_public(ચાવી, b, opts)) != 0)
		પાછા r;
	જો ((r = sshkey_serialize_private_sk(ચાવી, b)) != 0)
		પાછા r;

	પાછા 0;
}

સ્થિર પૂર્ણાંક
ssh_ed25519_sk_copy_public(અચલ સંરચના sshkey *from, સંરચના sshkey *to)
{
	પૂર્ણાંક r;

	જો ((r = sshkey_ed25519_funcs.copy_public(from, to)) != 0)
		પાછા r;
	જો ((r = sshkey_copy_public_sk(from, to)) != 0)
		પાછા r;
	પાછા 0;
}

સ્થિર પૂર્ણાંક
ssh_ed25519_sk_deserialize_public(અચલ અક્ષર *ktype, સંરચના sshbuf *b,
    સંરચના sshkey *ચાવી)
{
	પૂર્ણાંક r;

	જો ((r = sshkey_ed25519_funcs.deserialize_public(ktype, b, ચાવી)) != 0)
		પાછા r;
	જો ((r = sshkey_deserialize_sk(b, ચાવી)) != 0)
		પાછા r;
	પાછા 0;
}

સ્થિર પૂર્ણાંક
ssh_ed25519_sk_deserialize_private(અચલ અક્ષર *ktype, સંરચના sshbuf *b,
    સંરચના sshkey *ચાવી)
{
	પૂર્ણાંક r;

	જો ((r = sshkey_ed25519_funcs.deserialize_public(ktype, b, ચાવી)) != 0)
		પાછા r;
	જો ((r = sshkey_private_deserialize_sk(b, ચાવી)) != 0)
		પાછા r;
	પાછા 0;
}

સ્થિર પૂર્ણાંક
ssh_ed25519_sk_verify(અચલ સંરચના sshkey *ચાવી,
    અચલ u_char *sig, size_t siglen,
    અચલ u_char *data, size_t dlen, અચલ અક્ષર *alg, u_int compat,
    સંરચના sshkey_sig_details **detailsp)
{
	સંરચના sshbuf *b = ખાલી;
	સંરચના sshbuf *encoded = ખાલી;
	અક્ષર *ktype = ખાલી;
	અચલ u_char *sigblob;
	u_char apphash[32];
	u_char msghash[32];
	u_char sig_flags;
	u_int sig_counter;
	size_t len;
	પૂર્ણાંક r = SSH_ERR_INTERNAL_ERROR;
	પૂર્ણાંક ret;
	સંરચના sshkey_sig_details *details = ખાલી;

	જો (detailsp != ખાલી)
		*detailsp = ખાલી;

	જો (ચાવી == ખાલી ||
	    sshkey_type_plain(ચાવી->type) != ચાવી_ED25519_SK ||
	    ચાવી->ed25519_pk == ખાલી ||
	    sig == ખાલી || siglen == 0)
		પાછા SSH_ERR_INVALID_ARGUMENT;

	જો ((b = sshbuf_from(sig, siglen)) == ખાલી)
		પાછા SSH_ERR_ALLOC_FAIL;
	જો (sshbuf_get_cstring(b, &ktype, ખાલી) != 0 ||
	    sshbuf_get_string_direct(b, &sigblob, &len) != 0 ||
	    sshbuf_get_u8(b, &sig_flags) != 0 ||
	    sshbuf_get_u32(b, &sig_counter) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		જાઓ out;
	}
#ifdef DEBUG_SK
	fprintf(stderr, "%s: data:\n", __func__);
	/* sshbuf_dump_data(data, datalen, stderr); */
	fprintf(stderr, "%s: sigblob:\n", __func__);
	sshbuf_dump_data(sigblob, len, stderr);
	fprintf(stderr, "%s: sig_flags = 0x%02x, sig_counter = %u\n",
	    __func__, sig_flags, sig_counter);
#endif
	જો (strcmp(sshkey_ssh_name_plain(ચાવી), ktype) != 0) {
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
	જો (ssh_digest_memory(SSH_DIGEST_SHA256, ચાવી->sk_application,
	    strlen(ચાવી->sk_application), apphash, કદ(apphash)) != 0 ||
	    ssh_digest_memory(SSH_DIGEST_SHA256, data, dlen,
	    msghash, કદ(msghash)) != 0) {
		r = SSH_ERR_INVALID_ARGUMENT;
		જાઓ out;
	}
#ifdef DEBUG_SK
	fprintf(stderr, "%s: hashed application:\n", __func__);
	sshbuf_dump_data(apphash, કદ(apphash), stderr);
	fprintf(stderr, "%s: hashed message:\n", __func__);
	sshbuf_dump_data(msghash, કદ(msghash), stderr);
#endif
	જો ((details = calloc(1, કદ(*details))) == ખાલી) {
		r = SSH_ERR_ALLOC_FAIL;
		જાઓ out;
	}
	details->sk_counter = sig_counter;
	details->sk_flags = sig_flags;
	જો ((encoded = sshbuf_new()) == ખાલી) {
		r = SSH_ERR_ALLOC_FAIL;
		જાઓ out;
	}
	જો (sshbuf_put(encoded, apphash, કદ(apphash)) != 0 ||
	    sshbuf_put_u8(encoded, sig_flags) != 0 ||
	    sshbuf_put_u32(encoded, sig_counter) != 0 ||
	    sshbuf_put(encoded, msghash, કદ(msghash)) != 0) {
		r = SSH_ERR_ALLOC_FAIL;
		જાઓ out;
	}
#ifdef DEBUG_SK
	fprintf(stderr, "%s: signed buf:\n", __func__);
	sshbuf_dump(encoded, stderr);
#endif
	જો ((ret = crypto_sign_ed25519_verify_detached(sigblob,
	    sshbuf_ptr(encoded), sshbuf_len(encoded),
	    ચાવી->ed25519_pk)) != 0) {
		debug2_f("crypto_sign_ed25519_verify_detached failed: %d", ret);
	}
	જો (ret != 0) {
		r = SSH_ERR_SIGNATURE_INVALID;
		જાઓ out;
	}
	/* success */
	r = 0;
	જો (detailsp != ખાલી) {
		*detailsp = details;
		details = ખાલી;
	}
 out:
	sshkey_sig_details_free(details);
	sshbuf_free(b);
	sshbuf_free(encoded);
	મુક્ત(ktype);
	પાછા r;
}

સ્થિર અચલ સંરચના sshkey_impl_funcs sshkey_ed25519_sk_funcs = {
	/* .size = */		ખાલી,
	/* .alloc = */		ખાલી,
	/* .cleanup = */	ssh_ed25519_sk_cleanup,
	/* .equal = */		ssh_ed25519_sk_equal,
	/* .ssh_serialize_public = */ ssh_ed25519_sk_serialize_public,
	/* .ssh_deserialize_public = */ ssh_ed25519_sk_deserialize_public,
	/* .ssh_serialize_private = */ ssh_ed25519_sk_serialize_private,
	/* .ssh_deserialize_private = */ ssh_ed25519_sk_deserialize_private,
	/* .generate = */	ખાલી,
	/* .copy_public = */	ssh_ed25519_sk_copy_public,
	/* .sign = */		ખાલી,
	/* .verify = */		ssh_ed25519_sk_verify,
};

અચલ સંરચના sshkey_impl sshkey_ed25519_sk_impl = {
	/* .name = */		"sk-ssh-ed25519@openssh.com",
	/* .shortname = */	"ED25519-SK",
	/* .sigalg = */		ખાલી,
	/* .type = */		ચાવી_ED25519_SK,
	/* .nid = */		0,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	256,
	/* .funcs = */		&sshkey_ed25519_sk_funcs,
};

અચલ સંરચના sshkey_impl sshkey_ed25519_sk_cert_impl = {
	/* .name = */		"sk-ssh-ed25519-cert-v01@openssh.com",
	/* .shortname = */	"ED25519-SK-CERT",
	/* .sigalg = */		ખાલી,
	/* .type = */		ચાવી_ED25519_SK_CERT,
	/* .nid = */		0,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	256,
	/* .funcs = */		&sshkey_ed25519_sk_funcs,
};
