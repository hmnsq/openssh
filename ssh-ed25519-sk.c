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

#அந்தர்பாவ "includes.h"

#define SSHKEY_INTERNAL
#அந்தர்பாவ <sys/types.h>

#அந்தர்பாவ "crypto_api.h"

#அந்தர்பாவ <string.h>
#அந்தர்பாவ <stdarg.h>

#அந்தர்பாவ "log.h"
#அந்தர்பாவ "sshbuf.h"
#அந்தர்பாவ "sshkey.h"
#அந்தர்பாவ "ssherr.h"
#அந்தர்பாவ "digest.h"

/* Reuse some ED25519 internals */
வெளி கட்டமைப்பு sshkey_impl_funcs sshkey_ed25519_funcs;

நிலையான வெறுமை
ssh_ed25519_sk_cleanup(கட்டமைப்பு sshkey *k)
{
	sshkey_sk_cleanup(k);
	sshkey_ed25519_funcs.cleanup(k);
}

நிலையான முழு
ssh_ed25519_sk_equal(மாறிலி கட்டமைப்பு sshkey *a, மாறிலி கட்டமைப்பு sshkey *b)
{
	எனில் (!sshkey_sk_fields_equal(a, b))
		திரும்பு 0;
	எனில் (!sshkey_ed25519_funcs.equal(a, b))
		திரும்பு 0;
	திரும்பு 1;
}

நிலையான முழு
ssh_ed25519_sk_serialize_public(மாறிலி கட்டமைப்பு sshkey *சாவி, கட்டமைப்பு sshbuf *b,
    எண்ணிக்கை sshkey_serialize_rep opts)
{
	முழு r;

	எனில் ((r = sshkey_ed25519_funcs.serialize_public(சாவி, b, opts)) != 0)
		திரும்பு r;
	எனில் ((r = sshkey_serialize_sk(சாவி, b)) != 0)
		திரும்பு r;

	திரும்பு 0;
}

நிலையான முழு
ssh_ed25519_sk_serialize_private(மாறிலி கட்டமைப்பு sshkey *சாவி, கட்டமைப்பு sshbuf *b,
    எண்ணிக்கை sshkey_serialize_rep opts)
{
	முழு r;

	எனில் ((r = sshkey_ed25519_funcs.serialize_public(சாவி, b, opts)) != 0)
		திரும்பு r;
	எனில் ((r = sshkey_serialize_private_sk(சாவி, b)) != 0)
		திரும்பு r;

	திரும்பு 0;
}

நிலையான முழு
ssh_ed25519_sk_copy_public(மாறிலி கட்டமைப்பு sshkey *from, கட்டமைப்பு sshkey *to)
{
	முழு r;

	எனில் ((r = sshkey_ed25519_funcs.copy_public(from, to)) != 0)
		திரும்பு r;
	எனில் ((r = sshkey_copy_public_sk(from, to)) != 0)
		திரும்பு r;
	திரும்பு 0;
}

நிலையான முழு
ssh_ed25519_sk_deserialize_public(மாறிலி எழுத்து *ktype, கட்டமைப்பு sshbuf *b,
    கட்டமைப்பு sshkey *சாவி)
{
	முழு r;

	எனில் ((r = sshkey_ed25519_funcs.deserialize_public(ktype, b, சாவி)) != 0)
		திரும்பு r;
	எனில் ((r = sshkey_deserialize_sk(b, சாவி)) != 0)
		திரும்பு r;
	திரும்பு 0;
}

நிலையான முழு
ssh_ed25519_sk_deserialize_private(மாறிலி எழுத்து *ktype, கட்டமைப்பு sshbuf *b,
    கட்டமைப்பு sshkey *சாவி)
{
	முழு r;

	எனில் ((r = sshkey_ed25519_funcs.deserialize_public(ktype, b, சாவி)) != 0)
		திரும்பு r;
	எனில் ((r = sshkey_private_deserialize_sk(b, சாவி)) != 0)
		திரும்பு r;
	திரும்பு 0;
}

நிலையான முழு
ssh_ed25519_sk_verify(மாறிலி கட்டமைப்பு sshkey *சாவி,
    மாறிலி u_char *sig, size_t siglen,
    மாறிலி u_char *data, size_t dlen, மாறிலி எழுத்து *alg, u_int compat,
    கட்டமைப்பு sshkey_sig_details **detailsp)
{
	கட்டமைப்பு sshbuf *b = வெற்று;
	கட்டமைப்பு sshbuf *encoded = வெற்று;
	எழுத்து *ktype = வெற்று;
	மாறிலி u_char *sigblob;
	u_char apphash[32];
	u_char msghash[32];
	u_char sig_flags;
	u_int sig_counter;
	size_t len;
	முழு r = SSH_ERR_INTERNAL_ERROR;
	முழு ret;
	கட்டமைப்பு sshkey_sig_details *details = வெற்று;

	எனில் (detailsp != வெற்று)
		*detailsp = வெற்று;

	எனில் (சாவி == வெற்று ||
	    sshkey_type_plain(சாவி->type) != சாவி_ED25519_SK ||
	    சாவி->ed25519_pk == வெற்று ||
	    sig == வெற்று || siglen == 0)
		திரும்பு SSH_ERR_INVALID_ARGUMENT;

	எனில் ((b = sshbuf_from(sig, siglen)) == வெற்று)
		திரும்பு SSH_ERR_ALLOC_FAIL;
	எனில் (sshbuf_get_cstring(b, &ktype, வெற்று) != 0 ||
	    sshbuf_get_string_direct(b, &sigblob, &len) != 0 ||
	    sshbuf_get_u8(b, &sig_flags) != 0 ||
	    sshbuf_get_u32(b, &sig_counter) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		செல் out;
	}
#ifdef DEBUG_SK
	fprintf(stderr, "%s: data:\n", __func__);
	/* sshbuf_dump_data(data, datalen, stderr); */
	fprintf(stderr, "%s: sigblob:\n", __func__);
	sshbuf_dump_data(sigblob, len, stderr);
	fprintf(stderr, "%s: sig_flags = 0x%02x, sig_counter = %u\n",
	    __func__, sig_flags, sig_counter);
#endif
	எனில் (strcmp(sshkey_ssh_name_plain(சாவி), ktype) != 0) {
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
	எனில் (ssh_digest_memory(SSH_DIGEST_SHA256, சாவி->sk_application,
	    strlen(சாவி->sk_application), apphash, அளவு(apphash)) != 0 ||
	    ssh_digest_memory(SSH_DIGEST_SHA256, data, dlen,
	    msghash, அளவு(msghash)) != 0) {
		r = SSH_ERR_INVALID_ARGUMENT;
		செல் out;
	}
#ifdef DEBUG_SK
	fprintf(stderr, "%s: hashed application:\n", __func__);
	sshbuf_dump_data(apphash, அளவு(apphash), stderr);
	fprintf(stderr, "%s: hashed message:\n", __func__);
	sshbuf_dump_data(msghash, அளவு(msghash), stderr);
#endif
	எனில் ((details = calloc(1, அளவு(*details))) == வெற்று) {
		r = SSH_ERR_ALLOC_FAIL;
		செல் out;
	}
	details->sk_counter = sig_counter;
	details->sk_flags = sig_flags;
	எனில் ((encoded = sshbuf_new()) == வெற்று) {
		r = SSH_ERR_ALLOC_FAIL;
		செல் out;
	}
	எனில் (sshbuf_put(encoded, apphash, அளவு(apphash)) != 0 ||
	    sshbuf_put_u8(encoded, sig_flags) != 0 ||
	    sshbuf_put_u32(encoded, sig_counter) != 0 ||
	    sshbuf_put(encoded, msghash, அளவு(msghash)) != 0) {
		r = SSH_ERR_ALLOC_FAIL;
		செல் out;
	}
#ifdef DEBUG_SK
	fprintf(stderr, "%s: signed buf:\n", __func__);
	sshbuf_dump(encoded, stderr);
#endif
	எனில் ((ret = crypto_sign_ed25519_verify_detached(sigblob,
	    sshbuf_ptr(encoded), sshbuf_len(encoded),
	    சாவி->ed25519_pk)) != 0) {
		debug2_f("crypto_sign_ed25519_verify_detached failed: %d", ret);
	}
	எனில் (ret != 0) {
		r = SSH_ERR_SIGNATURE_INVALID;
		செல் out;
	}
	/* success */
	r = 0;
	எனில் (detailsp != வெற்று) {
		*detailsp = details;
		details = வெற்று;
	}
 out:
	sshkey_sig_details_free(details);
	sshbuf_free(b);
	sshbuf_free(encoded);
	விடுவி(ktype);
	திரும்பு r;
}

நிலையான மாறிலி கட்டமைப்பு sshkey_impl_funcs sshkey_ed25519_sk_funcs = {
	/* .size = */		வெற்று,
	/* .alloc = */		வெற்று,
	/* .cleanup = */	ssh_ed25519_sk_cleanup,
	/* .equal = */		ssh_ed25519_sk_equal,
	/* .ssh_serialize_public = */ ssh_ed25519_sk_serialize_public,
	/* .ssh_deserialize_public = */ ssh_ed25519_sk_deserialize_public,
	/* .ssh_serialize_private = */ ssh_ed25519_sk_serialize_private,
	/* .ssh_deserialize_private = */ ssh_ed25519_sk_deserialize_private,
	/* .generate = */	வெற்று,
	/* .copy_public = */	ssh_ed25519_sk_copy_public,
	/* .sign = */		வெற்று,
	/* .verify = */		ssh_ed25519_sk_verify,
};

மாறிலி கட்டமைப்பு sshkey_impl sshkey_ed25519_sk_impl = {
	/* .name = */		"sk-ssh-ed25519@openssh.com",
	/* .shortname = */	"ED25519-SK",
	/* .sigalg = */		வெற்று,
	/* .type = */		சாவி_ED25519_SK,
	/* .nid = */		0,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	256,
	/* .funcs = */		&sshkey_ed25519_sk_funcs,
};

மாறிலி கட்டமைப்பு sshkey_impl sshkey_ed25519_sk_cert_impl = {
	/* .name = */		"sk-ssh-ed25519-cert-v01@openssh.com",
	/* .shortname = */	"ED25519-SK-CERT",
	/* .sigalg = */		வெற்று,
	/* .type = */		சாவி_ED25519_SK_CERT,
	/* .nid = */		0,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	256,
	/* .funcs = */		&sshkey_ed25519_sk_funcs,
};
