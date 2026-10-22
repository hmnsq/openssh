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

#تعریف_کرو SSHKEY_اندرونی
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
خارجی ساخت sshkey_impl_funcs sshkey_ed25519_funcs;

ساکن خالی
ssh_ed25519_sk_cleanup(ساخت sshkey *k)
{
	sshkey_sk_cleanup(k);
	sshkey_ed25519_funcs.cleanup(k);
}

ساکن صحیح
ssh_ed25519_sk_equal(ثابت ساخت sshkey *a, ثابت ساخت sshkey *b)
{
	اگر (!sshkey_sk_fields_equal(a, b))
		واپس 0;
	اگر (!sshkey_ed25519_funcs.equal(a, b))
		واپس 0;
	واپس 1;
}

ساکن صحیح
ssh_ed25519_sk_serialize_عوامی(ثابت ساخت sshkey *کلید, ساخت sshbuf *b,
    شمار sshkey_serialize_rep opts)
{
	صحیح r;

	اگر ((r = sshkey_ed25519_funcs.serialize_عوامی(کلید, b, opts)) != 0)
		واپس r;
	اگر ((r = sshkey_serialize_sk(کلید, b)) != 0)
		واپس r;

	واپس 0;
}

ساکن صحیح
ssh_ed25519_sk_serialize_نجی(ثابت ساخت sshkey *کلید, ساخت sshbuf *b,
    شمار sshkey_serialize_rep opts)
{
	صحیح r;

	اگر ((r = sshkey_ed25519_funcs.serialize_عوامی(کلید, b, opts)) != 0)
		واپس r;
	اگر ((r = sshkey_serialize_نجی_sk(کلید, b)) != 0)
		واپس r;

	واپس 0;
}

ساکن صحیح
ssh_ed25519_sk_copy_عوامی(ثابت ساخت sshkey *from, ساخت sshkey *مقصد)
{
	صحیح r;

	اگر ((r = sshkey_ed25519_funcs.copy_عوامی(from, مقصد)) != 0)
		واپس r;
	اگر ((r = sshkey_copy_عوامی_sk(from, مقصد)) != 0)
		واپس r;
	واپس 0;
}

ساکن صحیح
ssh_ed25519_sk_deserialize_عوامی(ثابت حرف *ktype, ساخت sshbuf *b,
    ساخت sshkey *کلید)
{
	صحیح r;

	اگر ((r = sshkey_ed25519_funcs.deserialize_عوامی(ktype, b, کلید)) != 0)
		واپس r;
	اگر ((r = sshkey_deserialize_sk(b, کلید)) != 0)
		واپس r;
	واپس 0;
}

ساکن صحیح
ssh_ed25519_sk_deserialize_نجی(ثابت حرف *ktype, ساخت sshbuf *b,
    ساخت sshkey *کلید)
{
	صحیح r;

	اگر ((r = sshkey_ed25519_funcs.deserialize_عوامی(ktype, b, کلید)) != 0)
		واپس r;
	اگر ((r = sshkey_نجی_deserialize_sk(b, کلید)) != 0)
		واپس r;
	واپس 0;
}

ساکن صحیح
ssh_ed25519_sk_verify(ثابت ساخت sshkey *کلید,
    ثابت u_char *sig, سائز_t siglen,
    ثابت u_char *ڈیٹا, سائز_t dlen, ثابت حرف *alg, u_int compat,
    ساخت sshkey_sig_details **detailsp)
{
	ساخت sshbuf *b = تہی;
	ساخت sshbuf *encoded = تہی;
	حرف *ktype = تہی;
	ثابت u_char *sigblob;
	u_char apphash[32];
	u_char msghash[32];
	u_char sig_flags;
	u_int sig_شمار;
	سائز_t len;
	صحیح r = SSH_ERR_اندرونی_ERROR;
	صحیح ret;
	ساخت sshkey_sig_details *details = تہی;

	اگر (detailsp != تہی)
		*detailsp = تہی;

	اگر (کلید == تہی ||
	    sshkey_type_plain(کلید->type) != کلید_ED25519_SK ||
	    کلید->ed25519_pk == تہی ||
	    sig == تہی || siglen == 0)
		واپس SSH_ERR_INVALID_دلیل;

	اگر ((b = sshbuf_from(sig, siglen)) == تہی)
		واپس SSH_ERR_ALLOC_FAIL;
	اگر (sshbuf_get_cstring(b, &ktype, تہی) != 0 ||
	    sshbuf_get_string_براہ_راست(b, &sigblob, &len) != 0 ||
	    sshbuf_get_u8(b, &sig_flags) != 0 ||
	    sshbuf_get_u32(b, &sig_شمار) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		جاؤ برآمد;
	}
#اگر_تعریف_شدہ DEBUG_SK
	fprintf(stderr, "%s: data:\n", __func__);
	/* sshbuf_dump_data(data, datalen, stderr); */
	fprintf(stderr, "%s: sigblob:\n", __func__);
	sshbuf_dump_ڈیٹا(sigblob, len, stderr);
	fprintf(stderr, "%s: sig_flags = 0x%02x, sig_counter = %u\n",
	    __func__, sig_flags, sig_شمار);
#اگر_ختم
	اگر (strcmp(sshkey_ssh_name_plain(کلید), ktype) != 0) {
		r = SSH_ERR_کلید_TYPE_MISMATCH;
		جاؤ برآمد;
	}
	اگر (sshbuf_len(b) != 0) {
		r = SSH_ERR_UNEXPECTED_TRAILING_ڈیٹا;
		جاؤ برآمد;
	}
	اگر (len != crypto_sign_ed25519_بائٹیں) {
		r = SSH_ERR_INVALID_FORMAT;
		جاؤ برآمد;
	}
	اگر (ssh_digest_حافظہ(SSH_DIGEST_SHA256, کلید->sk_application,
	    لڑی_لمبائی(کلید->sk_application), apphash, حجم(apphash)) != 0 ||
	    ssh_digest_حافظہ(SSH_DIGEST_SHA256, ڈیٹا, dlen,
	    msghash, حجم(msghash)) != 0) {
		r = SSH_ERR_INVALID_دلیل;
		جاؤ برآمد;
	}
#اگر_تعریف_شدہ DEBUG_SK
	fprintf(stderr, "%s: hashed application:\n", __func__);
	sshbuf_dump_ڈیٹا(apphash, حجم(apphash), stderr);
	fprintf(stderr, "%s: hashed message:\n", __func__);
	sshbuf_dump_ڈیٹا(msghash, حجم(msghash), stderr);
#اگر_ختم
	اگر ((details = صفر_حافظہ_دو(1, حجم(*details))) == تہی) {
		r = SSH_ERR_ALLOC_FAIL;
		جاؤ برآمد;
	}
	details->sk_شمار = sig_شمار;
	details->sk_flags = sig_flags;
	اگر ((encoded = sshbuf_new()) == تہی) {
		r = SSH_ERR_ALLOC_FAIL;
		جاؤ برآمد;
	}
	اگر (sshbuf_put(encoded, apphash, حجم(apphash)) != 0 ||
	    sshbuf_put_u8(encoded, sig_flags) != 0 ||
	    sshbuf_put_u32(encoded, sig_شمار) != 0 ||
	    sshbuf_put(encoded, msghash, حجم(msghash)) != 0) {
		r = SSH_ERR_ALLOC_FAIL;
		جاؤ برآمد;
	}
#اگر_تعریف_شدہ DEBUG_SK
	fprintf(stderr, "%s: signed buf:\n", __func__);
	sshbuf_dump(encoded, stderr);
#اگر_ختم
	اگر ((ret = crypto_sign_ed25519_verify_detached(sigblob,
	    sshbuf_ptr(encoded), sshbuf_len(encoded),
	    کلید->ed25519_pk)) != 0) {
		debug2_f("crypto_sign_ed25519_verify_detached failed: %d", ret);
	}
	اگر (ret != 0) {
		r = SSH_ERR_SIGNATURE_INVALID;
		جاؤ برآمد;
	}
	/* success */
	r = 0;
	اگر (detailsp != تہی) {
		*detailsp = details;
		details = تہی;
	}
 برآمد:
	sshkey_sig_details_free(details);
	sshbuf_free(b);
	sshbuf_free(encoded);
	آزاد(ktype);
	واپس r;
}

ساکن ثابت ساخت sshkey_impl_funcs sshkey_ed25519_sk_funcs = {
	/* .size = */		تہی,
	/* .alloc = */		تہی,
	/* .cleanup = */	ssh_ed25519_sk_cleanup,
	/* .equal = */		ssh_ed25519_sk_equal,
	/* .ssh_serialize_public = */ ssh_ed25519_sk_serialize_عوامی,
	/* .ssh_deserialize_public = */ ssh_ed25519_sk_deserialize_عوامی,
	/* .ssh_serialize_private = */ ssh_ed25519_sk_serialize_نجی,
	/* .ssh_deserialize_private = */ ssh_ed25519_sk_deserialize_نجی,
	/* .generate = */	تہی,
	/* .copy_public = */	ssh_ed25519_sk_copy_عوامی,
	/* .sign = */		تہی,
	/* .verify = */		ssh_ed25519_sk_verify,
};

ثابت ساخت sshkey_impl sshkey_ed25519_sk_impl = {
	/* .name = */		"sk-ssh-ed25519@openssh.com",
	/* .shortname = */	"ED25519-SK",
	/* .sigalg = */		تہی,
	/* .type = */		کلید_ED25519_SK,
	/* .nid = */		0,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	256,
	/* .funcs = */		&sshkey_ed25519_sk_funcs,
};

ثابت ساخت sshkey_impl sshkey_ed25519_sk_cert_impl = {
	/* .name = */		"sk-ssh-ed25519-cert-v01@openssh.com",
	/* .shortname = */	"ED25519-SK-CERT",
	/* .sigalg = */		تہی,
	/* .type = */		کلید_ED25519_SK_CERT,
	/* .nid = */		0,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	256,
	/* .funcs = */		&sshkey_ed25519_sk_funcs,
};
