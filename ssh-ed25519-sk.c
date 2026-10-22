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

#شامل "includes.h"

#define SSHKEY_INTERNAL
#شامل <sys/types.h>

#شامل "crypto_api.h"

#شامل <string.h>
#شامل <stdarg.h>

#شامل "log.h"
#شامل "sshbuf.h"
#شامل "sshkey.h"
#شامل "ssherr.h"
#شامل "digest.h"

/* Reuse some ED25519 internals */
بیرونی ساختار sshkey_impl_funcs sshkey_ed25519_funcs;

ایستا تهی
ssh_ed25519_sk_cleanup(ساختار sshkey *k)
{
	sshkey_sk_cleanup(k);
	sshkey_ed25519_funcs.cleanup(k);
}

ایستا صحیح
ssh_ed25519_sk_equal(ثابت ساختار sshkey *a, ثابت ساختار sshkey *b)
{
	اگر (!sshkey_sk_fields_equal(a, b))
		بازگشت 0;
	اگر (!sshkey_ed25519_funcs.equal(a, b))
		بازگشت 0;
	بازگشت 1;
}

ایستا صحیح
ssh_ed25519_sk_serialize_public(ثابت ساختار sshkey *کلید, ساختار sshbuf *b,
    شمارش sshkey_serialize_rep opts)
{
	صحیح r;

	اگر ((r = sshkey_ed25519_funcs.serialize_public(کلید, b, opts)) != 0)
		بازگشت r;
	اگر ((r = sshkey_serialize_sk(کلید, b)) != 0)
		بازگشت r;

	بازگشت 0;
}

ایستا صحیح
ssh_ed25519_sk_serialize_private(ثابت ساختار sshkey *کلید, ساختار sshbuf *b,
    شمارش sshkey_serialize_rep opts)
{
	صحیح r;

	اگر ((r = sshkey_ed25519_funcs.serialize_public(کلید, b, opts)) != 0)
		بازگشت r;
	اگر ((r = sshkey_serialize_private_sk(کلید, b)) != 0)
		بازگشت r;

	بازگشت 0;
}

ایستا صحیح
ssh_ed25519_sk_copy_public(ثابت ساختار sshkey *from, ساختار sshkey *to)
{
	صحیح r;

	اگر ((r = sshkey_ed25519_funcs.copy_public(from, to)) != 0)
		بازگشت r;
	اگر ((r = sshkey_copy_public_sk(from, to)) != 0)
		بازگشت r;
	بازگشت 0;
}

ایستا صحیح
ssh_ed25519_sk_deserialize_public(ثابت نویسه *ktype, ساختار sshbuf *b,
    ساختار sshkey *کلید)
{
	صحیح r;

	اگر ((r = sshkey_ed25519_funcs.deserialize_public(ktype, b, کلید)) != 0)
		بازگشت r;
	اگر ((r = sshkey_deserialize_sk(b, کلید)) != 0)
		بازگشت r;
	بازگشت 0;
}

ایستا صحیح
ssh_ed25519_sk_deserialize_private(ثابت نویسه *ktype, ساختار sshbuf *b,
    ساختار sshkey *کلید)
{
	صحیح r;

	اگر ((r = sshkey_ed25519_funcs.deserialize_public(ktype, b, کلید)) != 0)
		بازگشت r;
	اگر ((r = sshkey_private_deserialize_sk(b, کلید)) != 0)
		بازگشت r;
	بازگشت 0;
}

ایستا صحیح
ssh_ed25519_sk_verify(ثابت ساختار sshkey *کلید,
    ثابت u_char *sig, size_t siglen,
    ثابت u_char *data, size_t dlen, ثابت نویسه *alg, u_int compat,
    ساختار sshkey_sig_details **detailsp)
{
	ساختار sshbuf *b = پوچ;
	ساختار sshbuf *encoded = پوچ;
	نویسه *ktype = پوچ;
	ثابت u_char *sigblob;
	u_char apphash[32];
	u_char msghash[32];
	u_char sig_flags;
	u_int sig_counter;
	size_t len;
	صحیح r = SSH_ERR_INTERNAL_ERROR;
	صحیح ret;
	ساختار sshkey_sig_details *details = پوچ;

	اگر (detailsp != پوچ)
		*detailsp = پوچ;

	اگر (کلید == پوچ ||
	    sshkey_type_plain(کلید->type) != کلید_ED25519_SK ||
	    کلید->ed25519_pk == پوچ ||
	    sig == پوچ || siglen == 0)
		بازگشت SSH_ERR_INVALID_ARGUMENT;

	اگر ((b = sshbuf_from(sig, siglen)) == پوچ)
		بازگشت SSH_ERR_ALLOC_FAIL;
	اگر (sshbuf_get_cstring(b, &ktype, پوچ) != 0 ||
	    sshbuf_get_string_direct(b, &sigblob, &len) != 0 ||
	    sshbuf_get_u8(b, &sig_flags) != 0 ||
	    sshbuf_get_u32(b, &sig_counter) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		برو out;
	}
#ifdef DEBUG_SK
	fprintf(stderr, "%s: data:\n", __func__);
	/* sshbuf_dump_data(data, datalen, stderr); */
	fprintf(stderr, "%s: sigblob:\n", __func__);
	sshbuf_dump_data(sigblob, len, stderr);
	fprintf(stderr, "%s: sig_flags = 0x%02x, sig_counter = %u\n",
	    __func__, sig_flags, sig_counter);
#endif
	اگر (strcmp(sshkey_ssh_name_plain(کلید), ktype) != 0) {
		r = SSH_ERR_کلید_TYPE_MISMATCH;
		برو out;
	}
	اگر (sshbuf_len(b) != 0) {
		r = SSH_ERR_UNEXPECTED_TRAILING_DATA;
		برو out;
	}
	اگر (len != crypto_sign_ed25519_BYTES) {
		r = SSH_ERR_INVALID_FORMAT;
		برو out;
	}
	اگر (ssh_digest_memory(SSH_DIGEST_SHA256, کلید->sk_application,
	    strlen(کلید->sk_application), apphash, اندازه(apphash)) != 0 ||
	    ssh_digest_memory(SSH_DIGEST_SHA256, data, dlen,
	    msghash, اندازه(msghash)) != 0) {
		r = SSH_ERR_INVALID_ARGUMENT;
		برو out;
	}
#ifdef DEBUG_SK
	fprintf(stderr, "%s: hashed application:\n", __func__);
	sshbuf_dump_data(apphash, اندازه(apphash), stderr);
	fprintf(stderr, "%s: hashed message:\n", __func__);
	sshbuf_dump_data(msghash, اندازه(msghash), stderr);
#endif
	اگر ((details = calloc(1, اندازه(*details))) == پوچ) {
		r = SSH_ERR_ALLOC_FAIL;
		برو out;
	}
	details->sk_counter = sig_counter;
	details->sk_flags = sig_flags;
	اگر ((encoded = sshbuf_new()) == پوچ) {
		r = SSH_ERR_ALLOC_FAIL;
		برو out;
	}
	اگر (sshbuf_put(encoded, apphash, اندازه(apphash)) != 0 ||
	    sshbuf_put_u8(encoded, sig_flags) != 0 ||
	    sshbuf_put_u32(encoded, sig_counter) != 0 ||
	    sshbuf_put(encoded, msghash, اندازه(msghash)) != 0) {
		r = SSH_ERR_ALLOC_FAIL;
		برو out;
	}
#ifdef DEBUG_SK
	fprintf(stderr, "%s: signed buf:\n", __func__);
	sshbuf_dump(encoded, stderr);
#endif
	اگر ((ret = crypto_sign_ed25519_verify_detached(sigblob,
	    sshbuf_ptr(encoded), sshbuf_len(encoded),
	    کلید->ed25519_pk)) != 0) {
		debug2_f("crypto_sign_ed25519_verify_detached failed: %d", ret);
	}
	اگر (ret != 0) {
		r = SSH_ERR_SIGNATURE_INVALID;
		برو out;
	}
	/* success */
	r = 0;
	اگر (detailsp != پوچ) {
		*detailsp = details;
		details = پوچ;
	}
 out:
	sshkey_sig_details_free(details);
	sshbuf_free(b);
	sshbuf_free(encoded);
	آزاد(ktype);
	بازگشت r;
}

ایستا ثابت ساختار sshkey_impl_funcs sshkey_ed25519_sk_funcs = {
	/* .size = */		پوچ,
	/* .alloc = */		پوچ,
	/* .cleanup = */	ssh_ed25519_sk_cleanup,
	/* .equal = */		ssh_ed25519_sk_equal,
	/* .ssh_serialize_public = */ ssh_ed25519_sk_serialize_public,
	/* .ssh_deserialize_public = */ ssh_ed25519_sk_deserialize_public,
	/* .ssh_serialize_private = */ ssh_ed25519_sk_serialize_private,
	/* .ssh_deserialize_private = */ ssh_ed25519_sk_deserialize_private,
	/* .generate = */	پوچ,
	/* .copy_public = */	ssh_ed25519_sk_copy_public,
	/* .sign = */		پوچ,
	/* .verify = */		ssh_ed25519_sk_verify,
};

ثابت ساختار sshkey_impl sshkey_ed25519_sk_impl = {
	/* .name = */		"sk-ssh-ed25519@openssh.com",
	/* .shortname = */	"ED25519-SK",
	/* .sigalg = */		پوچ,
	/* .type = */		کلید_ED25519_SK,
	/* .nid = */		0,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	256,
	/* .funcs = */		&sshkey_ed25519_sk_funcs,
};

ثابت ساختار sshkey_impl sshkey_ed25519_sk_cert_impl = {
	/* .name = */		"sk-ssh-ed25519-cert-v01@openssh.com",
	/* .shortname = */	"ED25519-SK-CERT",
	/* .sigalg = */		پوچ,
	/* .type = */		کلید_ED25519_SK_CERT,
	/* .nid = */		0,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	256,
	/* .funcs = */		&sshkey_ed25519_sk_funcs,
};
