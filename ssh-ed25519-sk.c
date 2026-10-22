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

#অন্তর্ভাব "includes.h"

#define SSHKEY_INTERNAL
#অন্তর্ভাব <sys/types.h>

#অন্তর্ভাব "crypto_api.h"

#অন্তর্ভাব <string.h>
#অন্তর্ভাব <stdarg.h>

#অন্তর্ভাব "log.h"
#অন্তর্ভাব "sshbuf.h"
#অন্তর্ভাব "sshkey.h"
#অন্তর্ভাব "ssherr.h"
#অন্তর্ভাব "digest.h"

/* Reuse some ED25519 internals */
বাহ্য সংরচনা sshkey_impl_funcs sshkey_ed25519_funcs;

স্থির শূন্য
ssh_ed25519_sk_cleanup(সংরচনা sshkey *k)
{
	sshkey_sk_cleanup(k);
	sshkey_ed25519_funcs.cleanup(k);
}

স্থির পূর্ণাঙ্ক
ssh_ed25519_sk_equal(ধ্রুব সংরচনা sshkey *a, ধ্রুব সংরচনা sshkey *b)
{
	যদি (!sshkey_sk_fields_equal(a, b))
		প্রত্যাগম 0;
	যদি (!sshkey_ed25519_funcs.equal(a, b))
		প্রত্যাগম 0;
	প্রত্যাগম 1;
}

স্থির পূর্ণাঙ্ক
ssh_ed25519_sk_serialize_public(ধ্রুব সংরচনা sshkey *চাবি, সংরচনা sshbuf *b,
    গণনা sshkey_serialize_rep opts)
{
	পূর্ণাঙ্ক r;

	যদি ((r = sshkey_ed25519_funcs.serialize_public(চাবি, b, opts)) != 0)
		প্রত্যাগম r;
	যদি ((r = sshkey_serialize_sk(চাবি, b)) != 0)
		প্রত্যাগম r;

	প্রত্যাগম 0;
}

স্থির পূর্ণাঙ্ক
ssh_ed25519_sk_serialize_private(ধ্রুব সংরচনা sshkey *চাবি, সংরচনা sshbuf *b,
    গণনা sshkey_serialize_rep opts)
{
	পূর্ণাঙ্ক r;

	যদি ((r = sshkey_ed25519_funcs.serialize_public(চাবি, b, opts)) != 0)
		প্রত্যাগম r;
	যদি ((r = sshkey_serialize_private_sk(চাবি, b)) != 0)
		প্রত্যাগম r;

	প্রত্যাগম 0;
}

স্থির পূর্ণাঙ্ক
ssh_ed25519_sk_copy_public(ধ্রুব সংরচনা sshkey *from, সংরচনা sshkey *to)
{
	পূর্ণাঙ্ক r;

	যদি ((r = sshkey_ed25519_funcs.copy_public(from, to)) != 0)
		প্রত্যাগম r;
	যদি ((r = sshkey_copy_public_sk(from, to)) != 0)
		প্রত্যাগম r;
	প্রত্যাগম 0;
}

স্থির পূর্ণাঙ্ক
ssh_ed25519_sk_deserialize_public(ধ্রুব বর্ণ *ktype, সংরচনা sshbuf *b,
    সংরচনা sshkey *চাবি)
{
	পূর্ণাঙ্ক r;

	যদি ((r = sshkey_ed25519_funcs.deserialize_public(ktype, b, চাবি)) != 0)
		প্রত্যাগম r;
	যদি ((r = sshkey_deserialize_sk(b, চাবি)) != 0)
		প্রত্যাগম r;
	প্রত্যাগম 0;
}

স্থির পূর্ণাঙ্ক
ssh_ed25519_sk_deserialize_private(ধ্রুব বর্ণ *ktype, সংরচনা sshbuf *b,
    সংরচনা sshkey *চাবি)
{
	পূর্ণাঙ্ক r;

	যদি ((r = sshkey_ed25519_funcs.deserialize_public(ktype, b, চাবি)) != 0)
		প্রত্যাগম r;
	যদি ((r = sshkey_private_deserialize_sk(b, চাবি)) != 0)
		প্রত্যাগম r;
	প্রত্যাগম 0;
}

স্থির পূর্ণাঙ্ক
ssh_ed25519_sk_verify(ধ্রুব সংরচনা sshkey *চাবি,
    ধ্রুব u_char *sig, size_t siglen,
    ধ্রুব u_char *data, size_t dlen, ধ্রুব বর্ণ *alg, u_int compat,
    সংরচনা sshkey_sig_details **detailsp)
{
	সংরচনা sshbuf *b = রিক্ত;
	সংরচনা sshbuf *encoded = রিক্ত;
	বর্ণ *ktype = রিক্ত;
	ধ্রুব u_char *sigblob;
	u_char apphash[32];
	u_char msghash[32];
	u_char sig_flags;
	u_int sig_counter;
	size_t len;
	পূর্ণাঙ্ক r = SSH_ERR_INTERNAL_ERROR;
	পূর্ণাঙ্ক ret;
	সংরচনা sshkey_sig_details *details = রিক্ত;

	যদি (detailsp != রিক্ত)
		*detailsp = রিক্ত;

	যদি (চাবি == রিক্ত ||
	    sshkey_type_plain(চাবি->type) != চাবি_ED25519_SK ||
	    চাবি->ed25519_pk == রিক্ত ||
	    sig == রিক্ত || siglen == 0)
		প্রত্যাগম SSH_ERR_INVALID_ARGUMENT;

	যদি ((b = sshbuf_from(sig, siglen)) == রিক্ত)
		প্রত্যাগম SSH_ERR_ALLOC_FAIL;
	যদি (sshbuf_get_cstring(b, &ktype, রিক্ত) != 0 ||
	    sshbuf_get_string_direct(b, &sigblob, &len) != 0 ||
	    sshbuf_get_u8(b, &sig_flags) != 0 ||
	    sshbuf_get_u32(b, &sig_counter) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		গচ্ছ out;
	}
#ifdef DEBUG_SK
	fprintf(stderr, "%s: data:\n", __func__);
	/* sshbuf_dump_data(data, datalen, stderr); */
	fprintf(stderr, "%s: sigblob:\n", __func__);
	sshbuf_dump_data(sigblob, len, stderr);
	fprintf(stderr, "%s: sig_flags = 0x%02x, sig_counter = %u\n",
	    __func__, sig_flags, sig_counter);
#endif
	যদি (strcmp(sshkey_ssh_name_plain(চাবি), ktype) != 0) {
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
	যদি (ssh_digest_memory(SSH_DIGEST_SHA256, চাবি->sk_application,
	    strlen(চাবি->sk_application), apphash, পরিমাণ(apphash)) != 0 ||
	    ssh_digest_memory(SSH_DIGEST_SHA256, data, dlen,
	    msghash, পরিমাণ(msghash)) != 0) {
		r = SSH_ERR_INVALID_ARGUMENT;
		গচ্ছ out;
	}
#ifdef DEBUG_SK
	fprintf(stderr, "%s: hashed application:\n", __func__);
	sshbuf_dump_data(apphash, পরিমাণ(apphash), stderr);
	fprintf(stderr, "%s: hashed message:\n", __func__);
	sshbuf_dump_data(msghash, পরিমাণ(msghash), stderr);
#endif
	যদি ((details = calloc(1, পরিমাণ(*details))) == রিক্ত) {
		r = SSH_ERR_ALLOC_FAIL;
		গচ্ছ out;
	}
	details->sk_counter = sig_counter;
	details->sk_flags = sig_flags;
	যদি ((encoded = sshbuf_new()) == রিক্ত) {
		r = SSH_ERR_ALLOC_FAIL;
		গচ্ছ out;
	}
	যদি (sshbuf_put(encoded, apphash, পরিমাণ(apphash)) != 0 ||
	    sshbuf_put_u8(encoded, sig_flags) != 0 ||
	    sshbuf_put_u32(encoded, sig_counter) != 0 ||
	    sshbuf_put(encoded, msghash, পরিমাণ(msghash)) != 0) {
		r = SSH_ERR_ALLOC_FAIL;
		গচ্ছ out;
	}
#ifdef DEBUG_SK
	fprintf(stderr, "%s: signed buf:\n", __func__);
	sshbuf_dump(encoded, stderr);
#endif
	যদি ((ret = crypto_sign_ed25519_verify_detached(sigblob,
	    sshbuf_ptr(encoded), sshbuf_len(encoded),
	    চাবি->ed25519_pk)) != 0) {
		debug2_f("crypto_sign_ed25519_verify_detached failed: %d", ret);
	}
	যদি (ret != 0) {
		r = SSH_ERR_SIGNATURE_INVALID;
		গচ্ছ out;
	}
	/* success */
	r = 0;
	যদি (detailsp != রিক্ত) {
		*detailsp = details;
		details = রিক্ত;
	}
 out:
	sshkey_sig_details_free(details);
	sshbuf_free(b);
	sshbuf_free(encoded);
	মুক্ত(ktype);
	প্রত্যাগম r;
}

স্থির ধ্রুব সংরচনা sshkey_impl_funcs sshkey_ed25519_sk_funcs = {
	/* .size = */		রিক্ত,
	/* .alloc = */		রিক্ত,
	/* .cleanup = */	ssh_ed25519_sk_cleanup,
	/* .equal = */		ssh_ed25519_sk_equal,
	/* .ssh_serialize_public = */ ssh_ed25519_sk_serialize_public,
	/* .ssh_deserialize_public = */ ssh_ed25519_sk_deserialize_public,
	/* .ssh_serialize_private = */ ssh_ed25519_sk_serialize_private,
	/* .ssh_deserialize_private = */ ssh_ed25519_sk_deserialize_private,
	/* .generate = */	রিক্ত,
	/* .copy_public = */	ssh_ed25519_sk_copy_public,
	/* .sign = */		রিক্ত,
	/* .verify = */		ssh_ed25519_sk_verify,
};

ধ্রুব সংরচনা sshkey_impl sshkey_ed25519_sk_impl = {
	/* .name = */		"sk-ssh-ed25519@openssh.com",
	/* .shortname = */	"ED25519-SK",
	/* .sigalg = */		রিক্ত,
	/* .type = */		চাবি_ED25519_SK,
	/* .nid = */		0,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	256,
	/* .funcs = */		&sshkey_ed25519_sk_funcs,
};

ধ্রুব সংরচনা sshkey_impl sshkey_ed25519_sk_cert_impl = {
	/* .name = */		"sk-ssh-ed25519-cert-v01@openssh.com",
	/* .shortname = */	"ED25519-SK-CERT",
	/* .sigalg = */		রিক্ত,
	/* .type = */		চাবি_ED25519_SK_CERT,
	/* .nid = */		0,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	256,
	/* .funcs = */		&sshkey_ed25519_sk_funcs,
};
