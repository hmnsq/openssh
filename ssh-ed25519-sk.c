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

#وصف_ڪريو SSHKEY_اندروني
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
ssh_ed25519_sk_serialize_عوامي(ثابت بنية sshkey *ڪنجي, بنية sshbuf *b,
    تعداد sshkey_serialize_rep opts)
{
	صحيح r;

	إذا ((r = sshkey_ed25519_funcs.serialize_عوامي(ڪنجي, b, opts)) != 0)
		أرجع r;
	إذا ((r = sshkey_serialize_sk(ڪنجي, b)) != 0)
		أرجع r;

	أرجع 0;
}

ساكن صحيح
ssh_ed25519_sk_serialize_ذاتي(ثابت بنية sshkey *ڪنجي, بنية sshbuf *b,
    تعداد sshkey_serialize_rep opts)
{
	صحيح r;

	إذا ((r = sshkey_ed25519_funcs.serialize_عوامي(ڪنجي, b, opts)) != 0)
		أرجع r;
	إذا ((r = sshkey_serialize_ذاتي_sk(ڪنجي, b)) != 0)
		أرجع r;

	أرجع 0;
}

ساكن صحيح
ssh_ed25519_sk_copy_عوامي(ثابت بنية sshkey *from, بنية sshkey *منزل)
{
	صحيح r;

	إذا ((r = sshkey_ed25519_funcs.copy_عوامي(from, منزل)) != 0)
		أرجع r;
	إذا ((r = sshkey_copy_عوامي_sk(from, منزل)) != 0)
		أرجع r;
	أرجع 0;
}

ساكن صحيح
ssh_ed25519_sk_deserialize_عوامي(ثابت حرف *ktype, بنية sshbuf *b,
    بنية sshkey *ڪنجي)
{
	صحيح r;

	إذا ((r = sshkey_ed25519_funcs.deserialize_عوامي(ktype, b, ڪنجي)) != 0)
		أرجع r;
	إذا ((r = sshkey_deserialize_sk(b, ڪنجي)) != 0)
		أرجع r;
	أرجع 0;
}

ساكن صحيح
ssh_ed25519_sk_deserialize_ذاتي(ثابت حرف *ktype, بنية sshbuf *b,
    بنية sshkey *ڪنجي)
{
	صحيح r;

	إذا ((r = sshkey_ed25519_funcs.deserialize_عوامي(ktype, b, ڪنجي)) != 0)
		أرجع r;
	إذا ((r = sshkey_ذاتي_deserialize_sk(b, ڪنجي)) != 0)
		أرجع r;
	أرجع 0;
}

ساكن صحيح
ssh_ed25519_sk_verify(ثابت بنية sshkey *ڪنجي,
    ثابت u_char *sig, سائيز_t siglen,
    ثابت u_char *معلومات, سائيز_t dlen, ثابت حرف *alg, u_int compat,
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
	سائيز_t len;
	صحيح r = SSH_ERR_اندروني_ERROR;
	صحيح ret;
	بنية sshkey_sig_details *details = عدم;

	إذا (detailsp != عدم)
		*detailsp = عدم;

	إذا (ڪنجي == عدم ||
	    sshkey_type_plain(ڪنجي->type) != ڪنجي_ED25519_SK ||
	    ڪنجي->ed25519_pk == عدم ||
	    sig == عدم || siglen == 0)
		أرجع SSH_ERR_INVALID_دليل;

	إذا ((b = sshbuf_from(sig, siglen)) == عدم)
		أرجع SSH_ERR_ALLOC_FAIL;
	إذا (sshbuf_get_cstring(b, &ktype, عدم) != 0 ||
	    sshbuf_get_string_سڌو(b, &sigblob, &len) != 0 ||
	    sshbuf_get_u8(b, &sig_flags) != 0 ||
	    sshbuf_get_u32(b, &sig_counter) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		اذهب ٻاهريون;
	}
#جيڪڏهن_وصف_ٿيل DEBUG_SK
	fprintf(stderr, "%s: data:\n", __func__);
	/* sshbuf_dump_data(data, datalen, stderr); */
	fprintf(stderr, "%s: sigblob:\n", __func__);
	sshbuf_dump_معلومات(sigblob, len, stderr);
	fprintf(stderr, "%s: sig_flags = 0x%02x, sig_counter = %u\n",
	    __func__, sig_flags, sig_counter);
#جيڪڏهن_پورو
	إذا (strcmp(sshkey_ssh_name_plain(ڪنجي), ktype) != 0) {
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
	إذا (ssh_digest_يادگيري(SSH_DIGEST_SHA256, ڪنجي->sk_application,
	    لڙي_ڊيگهه(ڪنجي->sk_application), apphash, حجم(apphash)) != 0 ||
	    ssh_digest_يادگيري(SSH_DIGEST_SHA256, معلومات, dlen,
	    msghash, حجم(msghash)) != 0) {
		r = SSH_ERR_INVALID_دليل;
		اذهب ٻاهريون;
	}
#جيڪڏهن_وصف_ٿيل DEBUG_SK
	fprintf(stderr, "%s: hashed application:\n", __func__);
	sshbuf_dump_معلومات(apphash, حجم(apphash), stderr);
	fprintf(stderr, "%s: hashed message:\n", __func__);
	sshbuf_dump_معلومات(msghash, حجم(msghash), stderr);
#جيڪڏهن_پورو
	إذا ((details = صفر_يادگيري_ڏيو(1, حجم(*details))) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب ٻاهريون;
	}
	details->sk_counter = sig_counter;
	details->sk_flags = sig_flags;
	إذا ((encoded = sshbuf_new()) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب ٻاهريون;
	}
	إذا (sshbuf_put(encoded, apphash, حجم(apphash)) != 0 ||
	    sshbuf_put_u8(encoded, sig_flags) != 0 ||
	    sshbuf_put_u32(encoded, sig_counter) != 0 ||
	    sshbuf_put(encoded, msghash, حجم(msghash)) != 0) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب ٻاهريون;
	}
#جيڪڏهن_وصف_ٿيل DEBUG_SK
	fprintf(stderr, "%s: signed buf:\n", __func__);
	sshbuf_dump(encoded, stderr);
#جيڪڏهن_پورو
	إذا ((ret = crypto_sign_ed25519_verify_detached(sigblob,
	    sshbuf_ptr(encoded), sshbuf_len(encoded),
	    ڪنجي->ed25519_pk)) != 0) {
		debug2_f("crypto_sign_ed25519_verify_detached failed: %d", ret);
	}
	إذا (ret != 0) {
		r = SSH_ERR_SIGNATURE_INVALID;
		اذهب ٻاهريون;
	}
	/* success */
	r = 0;
	إذا (detailsp != عدم) {
		*detailsp = details;
		details = عدم;
	}
 ٻاهريون:
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
	/* .ssh_serialize_public = */ ssh_ed25519_sk_serialize_عوامي,
	/* .ssh_deserialize_public = */ ssh_ed25519_sk_deserialize_عوامي,
	/* .ssh_serialize_private = */ ssh_ed25519_sk_serialize_ذاتي,
	/* .ssh_deserialize_private = */ ssh_ed25519_sk_deserialize_ذاتي,
	/* .generate = */	عدم,
	/* .copy_public = */	ssh_ed25519_sk_copy_عوامي,
	/* .sign = */		عدم,
	/* .verify = */		ssh_ed25519_sk_verify,
};

ثابت بنية sshkey_impl sshkey_ed25519_sk_impl = {
	/* .name = */		"sk-ssh-ed25519@openssh.com",
	/* .shortname = */	"ED25519-SK",
	/* .sigalg = */		عدم,
	/* .type = */		ڪنجي_ED25519_SK,
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
	/* .type = */		ڪنجي_ED25519_SK_CERT,
	/* .nid = */		0,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	256,
	/* .funcs = */		&sshkey_ed25519_sk_funcs,
};
