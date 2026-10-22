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

#تعریف_کړه SSHKEY_دننی
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
ssh_ed25519_sk_serialize_عامه(ثابت بنية sshkey *کلی, بنية sshbuf *b,
    تعداد sshkey_serialize_rep opts)
{
	صحيح r;

	إذا ((r = sshkey_ed25519_funcs.serialize_عامه(کلی, b, opts)) != 0)
		أرجع r;
	إذا ((r = sshkey_serialize_sk(کلی, b)) != 0)
		أرجع r;

	أرجع 0;
}

ساكن صحيح
ssh_ed25519_sk_serialize_شخصي(ثابت بنية sshkey *کلی, بنية sshbuf *b,
    تعداد sshkey_serialize_rep opts)
{
	صحيح r;

	إذا ((r = sshkey_ed25519_funcs.serialize_عامه(کلی, b, opts)) != 0)
		أرجع r;
	إذا ((r = sshkey_serialize_شخصي_sk(کلی, b)) != 0)
		أرجع r;

	أرجع 0;
}

ساكن صحيح
ssh_ed25519_sk_copy_عامه(ثابت بنية sshkey *from, بنية sshkey *منزل)
{
	صحيح r;

	إذا ((r = sshkey_ed25519_funcs.copy_عامه(from, منزل)) != 0)
		أرجع r;
	إذا ((r = sshkey_copy_عامه_sk(from, منزل)) != 0)
		أرجع r;
	أرجع 0;
}

ساكن صحيح
ssh_ed25519_sk_deserialize_عامه(ثابت حرف *ktype, بنية sshbuf *b,
    بنية sshkey *کلی)
{
	صحيح r;

	إذا ((r = sshkey_ed25519_funcs.deserialize_عامه(ktype, b, کلی)) != 0)
		أرجع r;
	إذا ((r = sshkey_deserialize_sk(b, کلی)) != 0)
		أرجع r;
	أرجع 0;
}

ساكن صحيح
ssh_ed25519_sk_deserialize_شخصي(ثابت حرف *ktype, بنية sshbuf *b,
    بنية sshkey *کلی)
{
	صحيح r;

	إذا ((r = sshkey_ed25519_funcs.deserialize_عامه(ktype, b, کلی)) != 0)
		أرجع r;
	إذا ((r = sshkey_شخصي_deserialize_sk(b, کلی)) != 0)
		أرجع r;
	أرجع 0;
}

ساكن صحيح
ssh_ed25519_sk_verify(ثابت بنية sshkey *کلی,
    ثابت u_char *sig, اندازه_t siglen,
    ثابت u_char *معلومات, اندازه_t dlen, ثابت حرف *alg, u_int compat,
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
	صحيح r = SSH_ERR_دننی_ERROR;
	صحيح ret;
	بنية sshkey_sig_details *details = عدم;

	إذا (detailsp != عدم)
		*detailsp = عدم;

	إذا (کلی == عدم ||
	    sshkey_type_plain(کلی->type) != کلی_ED25519_SK ||
	    کلی->ed25519_pk == عدم ||
	    sig == عدم || siglen == 0)
		أرجع SSH_ERR_INVALID_دلیل;

	إذا ((b = sshbuf_from(sig, siglen)) == عدم)
		أرجع SSH_ERR_ALLOC_FAIL;
	إذا (sshbuf_get_cstring(b, &ktype, عدم) != 0 ||
	    sshbuf_get_string_مستقیم(b, &sigblob, &len) != 0 ||
	    sshbuf_get_u8(b, &sig_flags) != 0 ||
	    sshbuf_get_u32(b, &sig_counter) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		اذهب بهر;
	}
#که_تعریف_شوی DEBUG_SK
	fprintf(stderr, "%s: data:\n", __func__);
	/* sshbuf_dump_data(data, datalen, stderr); */
	fprintf(stderr, "%s: sigblob:\n", __func__);
	sshbuf_dump_معلومات(sigblob, len, stderr);
	fprintf(stderr, "%s: sig_flags = 0x%02x, sig_counter = %u\n",
	    __func__, sig_flags, sig_counter);
#د_که_پای
	إذا (strcmp(sshkey_ssh_name_plain(کلی), ktype) != 0) {
		r = SSH_ERR_کلی_TYPE_MISMATCH;
		اذهب بهر;
	}
	إذا (sshbuf_len(b) != 0) {
		r = SSH_ERR_UNEXPECTED_TRAILING_معلومات;
		اذهب بهر;
	}
	إذا (len != crypto_sign_ed25519_بایټونه) {
		r = SSH_ERR_INVALID_FORMAT;
		اذهب بهر;
	}
	إذا (ssh_digest_حافظه(SSH_DIGEST_SHA256, کلی->sk_application,
	    مزي_اوږدوالی(کلی->sk_application), apphash, حجم(apphash)) != 0 ||
	    ssh_digest_حافظه(SSH_DIGEST_SHA256, معلومات, dlen,
	    msghash, حجم(msghash)) != 0) {
		r = SSH_ERR_INVALID_دلیل;
		اذهب بهر;
	}
#که_تعریف_شوی DEBUG_SK
	fprintf(stderr, "%s: hashed application:\n", __func__);
	sshbuf_dump_معلومات(apphash, حجم(apphash), stderr);
	fprintf(stderr, "%s: hashed message:\n", __func__);
	sshbuf_dump_معلومات(msghash, حجم(msghash), stderr);
#د_که_پای
	إذا ((details = حافظه_صفر_ورکړه(1, حجم(*details))) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب بهر;
	}
	details->sk_counter = sig_counter;
	details->sk_flags = sig_flags;
	إذا ((encoded = sshbuf_new()) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب بهر;
	}
	إذا (sshbuf_put(encoded, apphash, حجم(apphash)) != 0 ||
	    sshbuf_put_u8(encoded, sig_flags) != 0 ||
	    sshbuf_put_u32(encoded, sig_counter) != 0 ||
	    sshbuf_put(encoded, msghash, حجم(msghash)) != 0) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب بهر;
	}
#که_تعریف_شوی DEBUG_SK
	fprintf(stderr, "%s: signed buf:\n", __func__);
	sshbuf_dump(encoded, stderr);
#د_که_پای
	إذا ((ret = crypto_sign_ed25519_verify_detached(sigblob,
	    sshbuf_ptr(encoded), sshbuf_len(encoded),
	    کلی->ed25519_pk)) != 0) {
		debug2_f("crypto_sign_ed25519_verify_detached failed: %d", ret);
	}
	إذا (ret != 0) {
		r = SSH_ERR_SIGNATURE_INVALID;
		اذهب بهر;
	}
	/* success */
	r = 0;
	إذا (detailsp != عدم) {
		*detailsp = details;
		details = عدم;
	}
 بهر:
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
	/* .ssh_serialize_public = */ ssh_ed25519_sk_serialize_عامه,
	/* .ssh_deserialize_public = */ ssh_ed25519_sk_deserialize_عامه,
	/* .ssh_serialize_private = */ ssh_ed25519_sk_serialize_شخصي,
	/* .ssh_deserialize_private = */ ssh_ed25519_sk_deserialize_شخصي,
	/* .generate = */	عدم,
	/* .copy_public = */	ssh_ed25519_sk_copy_عامه,
	/* .sign = */		عدم,
	/* .verify = */		ssh_ed25519_sk_verify,
};

ثابت بنية sshkey_impl sshkey_ed25519_sk_impl = {
	/* .name = */		"sk-ssh-ed25519@openssh.com",
	/* .shortname = */	"ED25519-SK",
	/* .sigalg = */		عدم,
	/* .type = */		کلی_ED25519_SK,
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
	/* .type = */		کلی_ED25519_SK_CERT,
	/* .nid = */		0,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	256,
	/* .funcs = */		&sshkey_ed25519_sk_funcs,
};
