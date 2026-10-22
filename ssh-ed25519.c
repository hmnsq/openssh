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

#ضمن "includes.h"

#ضمن <sys/types.h>
#ضمن <limits.h>

#ضمن "crypto_api.h"

#ضمن <string.h>
#ضمن <stdarg.h>

#ضمن "log.h"
#ضمن "sshbuf.h"
#وصف_ڪريو SSHKEY_اندروني
#ضمن "sshkey.h"
#ضمن "ssherr.h"

ساكن فراغ
ssh_ed25519_cleanup(بنية sshkey *k)
{
	freezero(k->ed25519_pk, ED25519_PK_SZ);
	freezero(k->ed25519_sk, ED25519_SK_SZ);
	k->ed25519_pk = عدم;
	k->ed25519_sk = عدم;
}

ساكن صحيح
ssh_ed25519_equal(ثابت بنية sshkey *a, ثابت بنية sshkey *b)
{
	إذا (a->ed25519_pk == عدم || b->ed25519_pk == عدم)
		أرجع 0;
	إذا (memcmp(a->ed25519_pk, b->ed25519_pk, ED25519_PK_SZ) != 0)
		أرجع 0;
	أرجع 1;
}

ساكن صحيح
ssh_ed25519_serialize_عوامي(ثابت بنية sshkey *ڪنجي, بنية sshbuf *b,
    تعداد sshkey_serialize_rep opts)
{
	صحيح r;

	إذا (ڪنجي->ed25519_pk == عدم)
		أرجع SSH_ERR_INVALID_دليل;
	إذا ((r = sshbuf_put_string(b, ڪنجي->ed25519_pk, ED25519_PK_SZ)) != 0)
		أرجع r;

	أرجع 0;
}

ساكن صحيح
ssh_ed25519_serialize_ذاتي(ثابت بنية sshkey *ڪنجي, بنية sshbuf *b,
    تعداد sshkey_serialize_rep opts)
{
	صحيح r;

	إذا ((r = sshbuf_put_string(b, ڪنجي->ed25519_pk, ED25519_PK_SZ)) != 0 ||
	    (r = sshbuf_put_string(b, ڪنجي->ed25519_sk, ED25519_SK_SZ)) != 0)
		أرجع r;

	أرجع 0;
}

ساكن صحيح
ssh_ed25519_generate(بنية sshkey *k, صحيح بٽ)
{
	إذا ((k->ed25519_pk = يادگيري_ڏيو(ED25519_PK_SZ)) == عدم ||
	    (k->ed25519_sk = يادگيري_ڏيو(ED25519_SK_SZ)) == عدم)
		أرجع SSH_ERR_ALLOC_FAIL;
	إذا (crypto_sign_ed25519_keypair(k->ed25519_pk, k->ed25519_sk) != 0)
		أرجع SSH_ERR_CRYPTO_ERROR;
	أرجع 0;
}

ساكن صحيح
ssh_ed25519_copy_عوامي(ثابت بنية sshkey *from, بنية sshkey *منزل)
{
	إذا (from->ed25519_pk == عدم)
		أرجع 0; /* XXX SSH_ERR_INTERNAL_ERROR ? */
	إذا ((منزل->ed25519_pk = يادگيري_ڏيو(ED25519_PK_SZ)) == عدم)
		أرجع SSH_ERR_ALLOC_FAIL;
	يادگيري_نقل(منزل->ed25519_pk, from->ed25519_pk, ED25519_PK_SZ);
	أرجع 0;
}

ساكن صحيح
ssh_ed25519_deserialize_عوامي(ثابت حرف *ktype, بنية sshbuf *b,
    بنية sshkey *ڪنجي)
{
	u_char *pk = عدم;
	سائيز_t len = 0;
	صحيح r;

	إذا ((r = sshbuf_get_string(b, &pk, &len)) != 0)
		أرجع r;
	إذا (len != ED25519_PK_SZ) {
		freezero(pk, len);
		أرجع SSH_ERR_INVALID_FORMAT;
	}
	ڪنجي->ed25519_pk = pk;
	أرجع 0;
}

ساكن صحيح
ssh_ed25519_deserialize_ذاتي(ثابت حرف *ktype, بنية sshbuf *b,
    بنية sshkey *ڪنجي)
{
	صحيح r;
	سائيز_t sklen = 0;
	u_char *ed25519_sk = عدم;

	إذا ((r = ssh_ed25519_deserialize_عوامي(عدم, b, ڪنجي)) != 0)
		اذهب ٻاهريون;
	إذا ((r = sshbuf_get_string(b, &ed25519_sk, &sklen)) != 0)
		اذهب ٻاهريون;
	إذا (sklen != ED25519_SK_SZ) {
		r = SSH_ERR_INVALID_FORMAT;
		اذهب ٻاهريون;
	}
	ڪنجي->ed25519_sk = ed25519_sk;
	ed25519_sk = عدم; /* transferred */
	/* success */
	r = 0;
 ٻاهريون:
	freezero(ed25519_sk, sklen);
	أرجع r;
}

ساكن صحيح
ssh_ed25519_sign(بنية sshkey *ڪنجي,
    u_char **sigp, سائيز_t *lenp,
    ثابت u_char *معلومات, سائيز_t datalen,
    ثابت حرف *alg, ثابت حرف *sk_provider, ثابت حرف *sk_pin, u_int compat)
{
	u_char sig[crypto_sign_ed25519_بائيٽون];
	بنانشان ڊگهو ڊگهو siglen = 0;
	صحيح r, ret;

	إذا (lenp != عدم)
		*lenp = 0;
	إذا (sigp != عدم)
		*sigp = عدم;

	إذا (ڪنجي == عدم ||
	    sshkey_type_plain(ڪنجي->type) != ڪنجي_ED25519 ||
	    ڪنجي->ed25519_sk == عدم)
		أرجع SSH_ERR_INVALID_دليل;

	إذا ((ret = crypto_sign_ed25519_detached(sig, &siglen, معلومات, datalen,
	    ڪنجي->ed25519_sk)) != 0 || siglen != حجم(sig)) {
		r = SSH_ERR_INVALID_دليل; /* XXX better error? */
		اذهب ٻاهريون;
	}
	إذا ((r = ssh_ed25519_encode_store_sig(sig, siglen,
	    sigp, lenp)) != 0)
		اذهب ٻاهريون;

	/* success */
	r = 0;
 ٻاهريون:
	explicit_bzero(sig, حجم(sig));
	أرجع r;
}

صحيح
ssh_ed25519_encode_store_sig(ثابت u_char *sig, سائيز_t slen,
    u_char **sigp, سائيز_t *lenp)
{
	بنية sshbuf *b = عدم;
	صحيح r = -1;
	سائيز_t len;

	إذا (lenp != عدم)
		*lenp = 0;
	إذا (sigp != عدم)
		*sigp = عدم;

	إذا (slen != crypto_sign_ed25519_بائيٽون)
		أرجع SSH_ERR_INVALID_دليل;

	/* encode signature */
	إذا ((b = sshbuf_new()) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب ٻاهريون;
	}
	إذا ((r = sshbuf_put_cstring(b, "ssh-ed25519")) != 0 ||
	    (r = sshbuf_put_string(b, sig, slen)) != 0)
		اذهب ٻاهريون;
	len = sshbuf_len(b);
	إذا (sigp != عدم) {
		إذا ((*sigp = يادگيري_ڏيو(len)) == عدم) {
			r = SSH_ERR_ALLOC_FAIL;
			اذهب ٻاهريون;
		}
		يادگيري_نقل(*sigp, sshbuf_ptr(b), len);
	}
	إذا (lenp != عدم)
		*lenp = len;
	/* success */
	r = 0;
 ٻاهريون:
	sshbuf_free(b);
	أرجع r;
}

ساكن صحيح
ssh_ed25519_verify(ثابت بنية sshkey *ڪنجي,
    ثابت u_char *sig, سائيز_t siglen,
    ثابت u_char *معلومات, سائيز_t dlen, ثابت حرف *alg, u_int compat,
    بنية sshkey_sig_details **detailsp)
{
	بنية sshbuf *b = عدم;
	حرف *ktype = عدم;
	ثابت u_char *sigblob;
	سائيز_t len;
	صحيح r, ret;

	إذا (ڪنجي == عدم ||
	    sshkey_type_plain(ڪنجي->type) != ڪنجي_ED25519 ||
	    ڪنجي->ed25519_pk == عدم ||
	    sig == عدم || siglen == 0)
		أرجع SSH_ERR_INVALID_دليل;

	إذا ((b = sshbuf_from(sig, siglen)) == عدم)
		أرجع SSH_ERR_ALLOC_FAIL;
	إذا ((r = sshbuf_get_cstring(b, &ktype, عدم)) != 0 ||
	    (r = sshbuf_get_string_سڌو(b, &sigblob, &len)) != 0)
		اذهب ٻاهريون;
	إذا (strcmp("ssh-ed25519", ktype) != 0) {
		r = SSH_ERR_ڪنجي_TYPE_MISMATCH;
		اذهب ٻاهريون;
	}
	إذا (sshbuf_len(b) != 0) {
		r = SSH_ERR_UNEXPECTED_TRAILING_معلومات;
		اذهب ٻاهريون;
	}
	إذا (len != crypto_sign_ed25519_بائيٽون) {
		r = SSH_ERR_INVALID_FORMAT;
		اذهب ٻاهريون;
	}
	إذا ((ret = crypto_sign_ed25519_verify_detached(sigblob, معلومات, dlen,
	    ڪنجي->ed25519_pk)) != 0) {
		debug2_f("crypto_sign_ed25519_verify_detached failed: %d", ret);
	}
	إذا (ret != 0) {
		r = SSH_ERR_SIGNATURE_INVALID;
		اذهب ٻاهريون;
	}
	/* success */
	r = 0;
 ٻاهريون:
	sshbuf_free(b);
	حرر(ktype);
	أرجع r;
}

/* NB. not static; used by ED25519-SK */
ثابت بنية sshkey_impl_funcs sshkey_ed25519_funcs = {
	/* .size = */		عدم,
	/* .alloc = */		عدم,
	/* .cleanup = */	ssh_ed25519_cleanup,
	/* .equal = */		ssh_ed25519_equal,
	/* .ssh_serialize_public = */ ssh_ed25519_serialize_عوامي,
	/* .ssh_deserialize_public = */ ssh_ed25519_deserialize_عوامي,
	/* .ssh_serialize_private = */ ssh_ed25519_serialize_ذاتي,
	/* .ssh_deserialize_private = */ ssh_ed25519_deserialize_ذاتي,
	/* .generate = */	ssh_ed25519_generate,
	/* .copy_public = */	ssh_ed25519_copy_عوامي,
	/* .sign = */		ssh_ed25519_sign,
	/* .verify = */		ssh_ed25519_verify,
};

ثابت بنية sshkey_impl sshkey_ed25519_impl = {
	/* .name = */		"ssh-ed25519",
	/* .shortname = */	"ED25519",
	/* .sigalg = */		عدم,
	/* .type = */		ڪنجي_ED25519,
	/* .nid = */		0,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	256,
	/* .funcs = */		&sshkey_ed25519_funcs,
};

ثابت بنية sshkey_impl sshkey_ed25519_cert_impl = {
	/* .name = */		"ssh-ed25519-cert-v01@openssh.com",
	/* .shortname = */	"ED25519-CERT",
	/* .sigalg = */		عدم,
	/* .type = */		ڪنجي_ED25519_CERT,
	/* .nid = */		0,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	256,
	/* .funcs = */		&sshkey_ed25519_funcs,
};
