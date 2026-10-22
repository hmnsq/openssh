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

#شامل "includes.h"

#شامل <sys/types.h>
#شامل <limits.h>

#شامل "crypto_api.h"

#شامل <string.h>
#شامل <stdarg.h>

#شامل "log.h"
#شامل "sshbuf.h"
#تعریف_کرو SSHKEY_اندرونی
#شامل "sshkey.h"
#شامل "ssherr.h"

ساکن خالی
ssh_ed25519_cleanup(ساخت sshkey *k)
{
	freezero(k->ed25519_pk, ED25519_PK_SZ);
	freezero(k->ed25519_sk, ED25519_SK_SZ);
	k->ed25519_pk = تہی;
	k->ed25519_sk = تہی;
}

ساکن صحیح
ssh_ed25519_equal(ثابت ساخت sshkey *a, ثابت ساخت sshkey *b)
{
	اگر (a->ed25519_pk == تہی || b->ed25519_pk == تہی)
		واپس 0;
	اگر (memcmp(a->ed25519_pk, b->ed25519_pk, ED25519_PK_SZ) != 0)
		واپس 0;
	واپس 1;
}

ساکن صحیح
ssh_ed25519_serialize_عوامی(ثابت ساخت sshkey *کلید, ساخت sshbuf *b,
    شمار sshkey_serialize_rep opts)
{
	صحیح r;

	اگر (کلید->ed25519_pk == تہی)
		واپس SSH_ERR_INVALID_دلیل;
	اگر ((r = sshbuf_put_string(b, کلید->ed25519_pk, ED25519_PK_SZ)) != 0)
		واپس r;

	واپس 0;
}

ساکن صحیح
ssh_ed25519_serialize_نجی(ثابت ساخت sshkey *کلید, ساخت sshbuf *b,
    شمار sshkey_serialize_rep opts)
{
	صحیح r;

	اگر ((r = sshbuf_put_string(b, کلید->ed25519_pk, ED25519_PK_SZ)) != 0 ||
	    (r = sshbuf_put_string(b, کلید->ed25519_sk, ED25519_SK_SZ)) != 0)
		واپس r;

	واپس 0;
}

ساکن صحیح
ssh_ed25519_generate(ساخت sshkey *k, صحیح بٹ)
{
	اگر ((k->ed25519_pk = حافظہ_دو(ED25519_PK_SZ)) == تہی ||
	    (k->ed25519_sk = حافظہ_دو(ED25519_SK_SZ)) == تہی)
		واپس SSH_ERR_ALLOC_FAIL;
	اگر (crypto_sign_ed25519_keypair(k->ed25519_pk, k->ed25519_sk) != 0)
		واپس SSH_ERR_CRYPTO_ERROR;
	واپس 0;
}

ساکن صحیح
ssh_ed25519_copy_عوامی(ثابت ساخت sshkey *from, ساخت sshkey *مقصد)
{
	اگر (from->ed25519_pk == تہی)
		واپس 0; /* XXX SSH_ERR_INTERNAL_ERROR ? */
	اگر ((مقصد->ed25519_pk = حافظہ_دو(ED25519_PK_SZ)) == تہی)
		واپس SSH_ERR_ALLOC_FAIL;
	حافظہ_نقل(مقصد->ed25519_pk, from->ed25519_pk, ED25519_PK_SZ);
	واپس 0;
}

ساکن صحیح
ssh_ed25519_deserialize_عوامی(ثابت حرف *ktype, ساخت sshbuf *b,
    ساخت sshkey *کلید)
{
	u_char *pk = تہی;
	سائز_t len = 0;
	صحیح r;

	اگر ((r = sshbuf_get_string(b, &pk, &len)) != 0)
		واپس r;
	اگر (len != ED25519_PK_SZ) {
		freezero(pk, len);
		واپس SSH_ERR_INVALID_FORMAT;
	}
	کلید->ed25519_pk = pk;
	واپس 0;
}

ساکن صحیح
ssh_ed25519_deserialize_نجی(ثابت حرف *ktype, ساخت sshbuf *b,
    ساخت sshkey *کلید)
{
	صحیح r;
	سائز_t sklen = 0;
	u_char *ed25519_sk = تہی;

	اگر ((r = ssh_ed25519_deserialize_عوامی(تہی, b, کلید)) != 0)
		جاؤ برآمد;
	اگر ((r = sshbuf_get_string(b, &ed25519_sk, &sklen)) != 0)
		جاؤ برآمد;
	اگر (sklen != ED25519_SK_SZ) {
		r = SSH_ERR_INVALID_FORMAT;
		جاؤ برآمد;
	}
	کلید->ed25519_sk = ed25519_sk;
	ed25519_sk = تہی; /* transferred */
	/* success */
	r = 0;
 برآمد:
	freezero(ed25519_sk, sklen);
	واپس r;
}

ساکن صحیح
ssh_ed25519_sign(ساخت sshkey *کلید,
    u_char **sigp, سائز_t *lenp,
    ثابت u_char *ڈیٹا, سائز_t datalen,
    ثابت حرف *alg, ثابت حرف *sk_provider, ثابت حرف *sk_pin, u_int compat)
{
	u_char sig[crypto_sign_ed25519_بائٹیں];
	غیرعلامتی طویل طویل siglen = 0;
	صحیح r, ret;

	اگر (lenp != تہی)
		*lenp = 0;
	اگر (sigp != تہی)
		*sigp = تہی;

	اگر (کلید == تہی ||
	    sshkey_type_plain(کلید->type) != کلید_ED25519 ||
	    کلید->ed25519_sk == تہی)
		واپس SSH_ERR_INVALID_دلیل;

	اگر ((ret = crypto_sign_ed25519_detached(sig, &siglen, ڈیٹا, datalen,
	    کلید->ed25519_sk)) != 0 || siglen != حجم(sig)) {
		r = SSH_ERR_INVALID_دلیل; /* XXX better error? */
		جاؤ برآمد;
	}
	اگر ((r = ssh_ed25519_encode_store_sig(sig, siglen,
	    sigp, lenp)) != 0)
		جاؤ برآمد;

	/* success */
	r = 0;
 برآمد:
	explicit_bzero(sig, حجم(sig));
	واپس r;
}

صحیح
ssh_ed25519_encode_store_sig(ثابت u_char *sig, سائز_t slen,
    u_char **sigp, سائز_t *lenp)
{
	ساخت sshbuf *b = تہی;
	صحیح r = -1;
	سائز_t len;

	اگر (lenp != تہی)
		*lenp = 0;
	اگر (sigp != تہی)
		*sigp = تہی;

	اگر (slen != crypto_sign_ed25519_بائٹیں)
		واپس SSH_ERR_INVALID_دلیل;

	/* encode signature */
	اگر ((b = sshbuf_new()) == تہی) {
		r = SSH_ERR_ALLOC_FAIL;
		جاؤ برآمد;
	}
	اگر ((r = sshbuf_put_cstring(b, "ssh-ed25519")) != 0 ||
	    (r = sshbuf_put_string(b, sig, slen)) != 0)
		جاؤ برآمد;
	len = sshbuf_len(b);
	اگر (sigp != تہی) {
		اگر ((*sigp = حافظہ_دو(len)) == تہی) {
			r = SSH_ERR_ALLOC_FAIL;
			جاؤ برآمد;
		}
		حافظہ_نقل(*sigp, sshbuf_ptr(b), len);
	}
	اگر (lenp != تہی)
		*lenp = len;
	/* success */
	r = 0;
 برآمد:
	sshbuf_free(b);
	واپس r;
}

ساکن صحیح
ssh_ed25519_verify(ثابت ساخت sshkey *کلید,
    ثابت u_char *sig, سائز_t siglen,
    ثابت u_char *ڈیٹا, سائز_t dlen, ثابت حرف *alg, u_int compat,
    ساخت sshkey_sig_details **detailsp)
{
	ساخت sshbuf *b = تہی;
	حرف *ktype = تہی;
	ثابت u_char *sigblob;
	سائز_t len;
	صحیح r, ret;

	اگر (کلید == تہی ||
	    sshkey_type_plain(کلید->type) != کلید_ED25519 ||
	    کلید->ed25519_pk == تہی ||
	    sig == تہی || siglen == 0)
		واپس SSH_ERR_INVALID_دلیل;

	اگر ((b = sshbuf_from(sig, siglen)) == تہی)
		واپس SSH_ERR_ALLOC_FAIL;
	اگر ((r = sshbuf_get_cstring(b, &ktype, تہی)) != 0 ||
	    (r = sshbuf_get_string_براہ_راست(b, &sigblob, &len)) != 0)
		جاؤ برآمد;
	اگر (strcmp("ssh-ed25519", ktype) != 0) {
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
	اگر ((ret = crypto_sign_ed25519_verify_detached(sigblob, ڈیٹا, dlen,
	    کلید->ed25519_pk)) != 0) {
		debug2_f("crypto_sign_ed25519_verify_detached failed: %d", ret);
	}
	اگر (ret != 0) {
		r = SSH_ERR_SIGNATURE_INVALID;
		جاؤ برآمد;
	}
	/* success */
	r = 0;
 برآمد:
	sshbuf_free(b);
	آزاد(ktype);
	واپس r;
}

/* NB. not static; used by ED25519-SK */
ثابت ساخت sshkey_impl_funcs sshkey_ed25519_funcs = {
	/* .size = */		تہی,
	/* .alloc = */		تہی,
	/* .cleanup = */	ssh_ed25519_cleanup,
	/* .equal = */		ssh_ed25519_equal,
	/* .ssh_serialize_public = */ ssh_ed25519_serialize_عوامی,
	/* .ssh_deserialize_public = */ ssh_ed25519_deserialize_عوامی,
	/* .ssh_serialize_private = */ ssh_ed25519_serialize_نجی,
	/* .ssh_deserialize_private = */ ssh_ed25519_deserialize_نجی,
	/* .generate = */	ssh_ed25519_generate,
	/* .copy_public = */	ssh_ed25519_copy_عوامی,
	/* .sign = */		ssh_ed25519_sign,
	/* .verify = */		ssh_ed25519_verify,
};

ثابت ساخت sshkey_impl sshkey_ed25519_impl = {
	/* .name = */		"ssh-ed25519",
	/* .shortname = */	"ED25519",
	/* .sigalg = */		تہی,
	/* .type = */		کلید_ED25519,
	/* .nid = */		0,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	256,
	/* .funcs = */		&sshkey_ed25519_funcs,
};

ثابت ساخت sshkey_impl sshkey_ed25519_cert_impl = {
	/* .name = */		"ssh-ed25519-cert-v01@openssh.com",
	/* .shortname = */	"ED25519-CERT",
	/* .sigalg = */		تہی,
	/* .type = */		کلید_ED25519_CERT,
	/* .nid = */		0,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	256,
	/* .funcs = */		&sshkey_ed25519_funcs,
};
