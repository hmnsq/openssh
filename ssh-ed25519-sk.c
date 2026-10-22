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

#ضمن "includes.h"

#تعریف_کن SSHKEY_داخلی
#ضمن <sys/types.h>

#ضمن "crypto_api.h"

#ضمن <string.h>
#ضمن <stdarg.h>

#ضمن "log.h"
#ضمن "sshbuf.h"
#ضمن "sshkey.h"
#ضمن "ssherr.h"
#ضمن "digest.h"

/* Reuse some ED25519 internals */
خارجي بنية sshkey_impl_funcs sshkey_ed25519_funcs;

ساكن فراغ
ssh_ed25519_sk_cleanup(بنية sshkey *k)
{
	sshkey_sk_cleanup(k);
	sshkey_ed25519_funcs.cleanup(k);
}

ساكن صحيح
ssh_ed25519_sk_equal(ثابت بنية sshkey *a, ثابت بنية sshkey *b)
{
	إذا (!sshkey_sk_fields_equal(a, b))
		أرجع 0;
	إذا (!sshkey_ed25519_funcs.equal(a, b))
		أرجع 0;
	أرجع 1;
}

ساكن صحيح
ssh_ed25519_sk_serialize_عمومی(ثابت بنية sshkey *کلید, بنية sshbuf *b,
    تعداد sshkey_serialize_rep opts)
{
	صحيح r;

	إذا ((r = sshkey_ed25519_funcs.serialize_عمومی(کلید, b, opts)) != 0)
		أرجع r;
	إذا ((r = sshkey_serialize_sk(کلید, b)) != 0)
		أرجع r;

	أرجع 0;
}

ساكن صحيح
ssh_ed25519_sk_serialize_خصوصی(ثابت بنية sshkey *کلید, بنية sshbuf *b,
    تعداد sshkey_serialize_rep opts)
{
	صحيح r;

	إذا ((r = sshkey_ed25519_funcs.serialize_عمومی(کلید, b, opts)) != 0)
		أرجع r;
	إذا ((r = sshkey_serialize_خصوصی_sk(کلید, b)) != 0)
		أرجع r;

	أرجع 0;
}

ساكن صحيح
ssh_ed25519_sk_copy_عمومی(ثابت بنية sshkey *from, بنية sshkey *مقصد)
{
	صحيح r;

	إذا ((r = sshkey_ed25519_funcs.copy_عمومی(from, مقصد)) != 0)
		أرجع r;
	إذا ((r = sshkey_copy_عمومی_sk(from, مقصد)) != 0)
		أرجع r;
	أرجع 0;
}

ساكن صحيح
ssh_ed25519_sk_deserialize_عمومی(ثابت حرف *ktype, بنية sshbuf *b,
    بنية sshkey *کلید)
{
	صحيح r;

	إذا ((r = sshkey_ed25519_funcs.deserialize_عمومی(ktype, b, کلید)) != 0)
		أرجع r;
	إذا ((r = sshkey_deserialize_sk(b, کلید)) != 0)
		أرجع r;
	أرجع 0;
}

ساكن صحيح
ssh_ed25519_sk_deserialize_خصوصی(ثابت حرف *ktype, بنية sshbuf *b,
    بنية sshkey *کلید)
{
	صحيح r;

	إذا ((r = sshkey_ed25519_funcs.deserialize_عمومی(ktype, b, کلید)) != 0)
		أرجع r;
	إذا ((r = sshkey_خصوصی_deserialize_sk(b, کلید)) != 0)
		أرجع r;
	أرجع 0;
}

ساكن صحيح
ssh_ed25519_sk_verify(ثابت بنية sshkey *کلید,
    ثابت u_char *sig, اندازه_t siglen,
    ثابت u_char *داده, اندازه_t dlen, ثابت حرف *alg, u_int compat,
    بنية sshkey_sig_details **detailsp)
{
	بنية sshbuf *b = عدم;
	بنية sshbuf *encoded = عدم;
	حرف *ktype = عدم;
	ثابت u_char *sigblob;
	u_char apphash[32];
	u_char msghash[32];
	u_char sig_flags;
	u_int sig_counter;
	اندازه_t len;
	صحيح r = SSH_ERR_داخلی_ERROR;
	صحيح ret;
	بنية sshkey_sig_details *details = عدم;

	إذا (detailsp != عدم)
		*detailsp = عدم;

	إذا (کلید == عدم ||
	    sshkey_type_plain(کلید->type) != کلید_ED25519_SK ||
	    کلید->ed25519_pk == عدم ||
	    sig == عدم || siglen == 0)
		أرجع SSH_ERR_INVALID_آرگومان;

	إذا ((b = sshbuf_from(sig, siglen)) == عدم)
		أرجع SSH_ERR_ALLOC_FAIL;
	إذا (sshbuf_get_cstring(b, &ktype, عدم) != 0 ||
	    sshbuf_get_string_مستقیم(b, &sigblob, &len) != 0 ||
	    sshbuf_get_u8(b, &sig_flags) != 0 ||
	    sshbuf_get_u32(b, &sig_counter) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		اذهب بیرون;
	}
#اگر_تعریف_شده DEBUG_SK
	fprintf(stderr, "%s: data:\n", __func__);
	/* sshbuf_dump_data(data, datalen, stderr); */
	fprintf(stderr, "%s: sigblob:\n", __func__);
	sshbuf_dump_داده(sigblob, len, stderr);
	fprintf(stderr, "%s: sig_flags = 0x%02x, sig_counter = %u\n",
	    __func__, sig_flags, sig_counter);
#پایان_اگر
	إذا (strcmp(sshkey_ssh_name_plain(کلید), ktype) != 0) {
		r = SSH_ERR_کلید_TYPE_MISMATCH;
		اذهب بیرون;
	}
	إذا (sshbuf_len(b) != 0) {
		r = SSH_ERR_UNEXPECTED_TRAILING_داده;
		اذهب بیرون;
	}
	إذا (len != crypto_sign_ed25519_بایتها) {
		r = SSH_ERR_INVALID_FORMAT;
		اذهب بیرون;
	}
	إذا (ssh_digest_حافظه(SSH_DIGEST_SHA256, کلید->sk_application,
	    طول_رشته(کلید->sk_application), apphash, حجم(apphash)) != 0 ||
	    ssh_digest_حافظه(SSH_DIGEST_SHA256, داده, dlen,
	    msghash, حجم(msghash)) != 0) {
		r = SSH_ERR_INVALID_آرگومان;
		اذهب بیرون;
	}
#اگر_تعریف_شده DEBUG_SK
	fprintf(stderr, "%s: hashed application:\n", __func__);
	sshbuf_dump_داده(apphash, حجم(apphash), stderr);
	fprintf(stderr, "%s: hashed message:\n", __func__);
	sshbuf_dump_داده(msghash, حجم(msghash), stderr);
#پایان_اگر
	إذا ((details = حافظه_صفر_بده(1, حجم(*details))) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب بیرون;
	}
	details->sk_counter = sig_counter;
	details->sk_flags = sig_flags;
	إذا ((encoded = sshbuf_new()) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب بیرون;
	}
	إذا (sshbuf_put(encoded, apphash, حجم(apphash)) != 0 ||
	    sshbuf_put_u8(encoded, sig_flags) != 0 ||
	    sshbuf_put_u32(encoded, sig_counter) != 0 ||
	    sshbuf_put(encoded, msghash, حجم(msghash)) != 0) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب بیرون;
	}
#اگر_تعریف_شده DEBUG_SK
	fprintf(stderr, "%s: signed buf:\n", __func__);
	sshbuf_dump(encoded, stderr);
#پایان_اگر
	إذا ((ret = crypto_sign_ed25519_verify_detached(sigblob,
	    sshbuf_ptr(encoded), sshbuf_len(encoded),
	    کلید->ed25519_pk)) != 0) {
		debug2_f("crypto_sign_ed25519_verify_detached failed: %d", ret);
	}
	إذا (ret != 0) {
		r = SSH_ERR_SIGNATURE_INVALID;
		اذهب بیرون;
	}
	/* success */
	r = 0;
	إذا (detailsp != عدم) {
		*detailsp = details;
		details = عدم;
	}
 بیرون:
	sshkey_sig_details_free(details);
	sshbuf_free(b);
	sshbuf_free(encoded);
	حرر(ktype);
	أرجع r;
}

ساكن ثابت بنية sshkey_impl_funcs sshkey_ed25519_sk_funcs = {
	/* .size = */		عدم,
	/* .alloc = */		عدم,
	/* .cleanup = */	ssh_ed25519_sk_cleanup,
	/* .equal = */		ssh_ed25519_sk_equal,
	/* .ssh_serialize_public = */ ssh_ed25519_sk_serialize_عمومی,
	/* .ssh_deserialize_public = */ ssh_ed25519_sk_deserialize_عمومی,
	/* .ssh_serialize_private = */ ssh_ed25519_sk_serialize_خصوصی,
	/* .ssh_deserialize_private = */ ssh_ed25519_sk_deserialize_خصوصی,
	/* .generate = */	عدم,
	/* .copy_public = */	ssh_ed25519_sk_copy_عمومی,
	/* .sign = */		عدم,
	/* .verify = */		ssh_ed25519_sk_verify,
};

ثابت بنية sshkey_impl sshkey_ed25519_sk_impl = {
	/* .name = */		"sk-ssh-ed25519@openssh.com",
	/* .shortname = */	"ED25519-SK",
	/* .sigalg = */		عدم,
	/* .type = */		کلید_ED25519_SK,
	/* .nid = */		0,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	256,
	/* .funcs = */		&sshkey_ed25519_sk_funcs,
};

ثابت بنية sshkey_impl sshkey_ed25519_sk_cert_impl = {
	/* .name = */		"sk-ssh-ed25519-cert-v01@openssh.com",
	/* .shortname = */	"ED25519-SK-CERT",
	/* .sigalg = */		عدم,
	/* .type = */		کلید_ED25519_SK_CERT,
	/* .nid = */		0,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	256,
	/* .funcs = */		&sshkey_ed25519_sk_funcs,
};
