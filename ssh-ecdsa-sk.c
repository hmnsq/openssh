/* $OpenBSD: ssh-ecdsa-sk.c,v 1.21 2026/02/06 22:59:18 dtucker Exp $ */
/*
 * Copyright (c) 2000 Markus Friedl.  All rights reserved.
 * Copyright (c) 2010 Damien Miller.  All rights reserved.
 * Copyright (c) 2019 Google Inc.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/* #define DEBUG_SK 1 */

#شامل "includes.h"

#شامل <sys/types.h>

#اگر_تعریف_شدہ WITH_OPENSSL
#شامل "openbsd-compat/openssl-compat.h"
#شامل <openssl/bn.h>
#شامل <openssl/ec.h>
#شامل <openssl/ecdsa.h>
#شامل <openssl/evp.h>

#شامل <string.h>
#شامل <stdio.h> /* needed for DEBUG_SK only */

#شامل "sshbuf.h"
#شامل "ssherr.h"
#شامل "digest.h"
#تعریف_کرو SSHKEY_اندرونی
#شامل "sshkey.h"

/* Reuse some ECDSA internals */
خارجی ساخت sshkey_impl_funcs sshkey_ecdsa_funcs;

ساکن خالی
ssh_ecdsa_sk_cleanup(ساخت sshkey *k)
{
	sshkey_sk_cleanup(k);
	sshkey_ecdsa_funcs.cleanup(k);
}

ساکن صحیح
ssh_ecdsa_sk_equal(ثابت ساخت sshkey *a, ثابت ساخت sshkey *b)
{
	اگر (!sshkey_sk_fields_equal(a, b))
		واپس 0;
	اگر (!sshkey_ecdsa_funcs.equal(a, b))
		واپس 0;
	واپس 1;
}

ساکن صحیح
ssh_ecdsa_sk_serialize_عوامی(ثابت ساخت sshkey *کلید, ساخت sshbuf *b,
    شمار sshkey_serialize_rep opts)
{
	صحیح r;

	اگر ((r = sshkey_ecdsa_funcs.serialize_عوامی(کلید, b, opts)) != 0)
		واپس r;
	اگر ((r = sshkey_serialize_sk(کلید, b)) != 0)
		واپس r;

	واپس 0;
}

ساکن صحیح
ssh_ecdsa_sk_serialize_نجی(ثابت ساخت sshkey *کلید, ساخت sshbuf *b,
    شمار sshkey_serialize_rep opts)
{
	صحیح r;

	اگر (!sshkey_is_cert(کلید)) {
		اگر ((r = sshkey_ecdsa_funcs.serialize_عوامی(کلید,
		    b, opts)) != 0)
			واپس r;
	}
	اگر ((r = sshkey_serialize_نجی_sk(کلید, b)) != 0)
		واپس r;

	واپس 0;
}

ساکن صحیح
ssh_ecdsa_sk_copy_عوامی(ثابت ساخت sshkey *from, ساخت sshkey *مقصد)
{
	صحیح r;

	اگر ((r = sshkey_ecdsa_funcs.copy_عوامی(from, مقصد)) != 0)
		واپس r;
	اگر ((r = sshkey_copy_عوامی_sk(from, مقصد)) != 0)
		واپس r;
	واپس 0;
}

ساکن صحیح
ssh_ecdsa_sk_deserialize_عوامی(ثابت حرف *ktype, ساخت sshbuf *b,
    ساخت sshkey *کلید)
{
	صحیح r;

	اگر ((r = sshkey_ecdsa_funcs.deserialize_عوامی(ktype, b, کلید)) != 0)
		واپس r;
	اگر ((r = sshkey_deserialize_sk(b, کلید)) != 0)
		واپس r;
	واپس 0;
}

ساکن صحیح
ssh_ecdsa_sk_deserialize_نجی(ثابت حرف *ktype, ساخت sshbuf *b,
    ساخت sshkey *کلید)
{
	صحیح r;

	اگر (!sshkey_is_cert(کلید)) {
		اگر ((r = sshkey_ecdsa_funcs.deserialize_عوامی(ktype,
		    b, کلید)) != 0)
			واپس r;
	}
	اگر ((r = sshkey_نجی_deserialize_sk(b, کلید)) != 0)
		واپس r;

	واپس 0;
}

/*
 * Check FIDO/W3C webauthn signatures clientData field against the expected
 * format and prepare a hash of it for use in signature verification.
 *
 * webauthn signatures do not sign the hash of the message directly, but
 * instead sign a JSON-like "clientData" wrapper structure that contains the
 * message hash along with a other information.
 *
 * Fortunately this structure has a fixed format so it is possible to verify
 * that the hash of the signed message is present within the clientData
 * structure without needing to implement any JSON parsing.
 */
ساکن صحیح
webauthn_check_prepare_hash(ثابت u_char *ڈیٹا, سائز_t datalen,
    ثابت حرف *origin, ثابت ساخت sshbuf *wrapper,
    uint8_t flags, ثابت ساخت sshbuf *extensions,
    u_char *msghash, سائز_t msghashlen)
{
	صحیح r = SSH_ERR_اندرونی_ERROR;
	ساخت sshbuf *chall = تہی, *m = تہی;

	اگر ((m = sshbuf_new()) == تہی ||
	    (chall = sshbuf_from(ڈیٹا, datalen)) == تہی) {
		r = SSH_ERR_ALLOC_FAIL;
		جاؤ برآمد;
	}
	/*
	 * Ensure origin contains no quote character and that the flags are
	 * consistent with what we received
	 */
	اگر (strchr(origin, '\"') != تہی ||
	    (flags & 0x40) != 0 /* AD */ ||
	    ((flags & 0x80) == 0 /* ED */) != (sshbuf_len(extensions) == 0)) {
		r = SSH_ERR_INVALID_FORMAT;
		جاؤ برآمد;
	}

	/*
	 * Prepare the preamble to clientData that we expect, poking the
	 * challenge and origin into their canonical positions in the
	 * structure. The crossOrigin flag and any additional extension
	 * fields present are ignored.
	 */
#تعریف_کرو WEBAUTHN_0	"{\"type\":\"webauthn.get\",\"challenge\":\""
#تعریف_کرو WEBAUTHN_1	"\",\"origin\":\""
#تعریف_کرو WEBAUTHN_2	"\""
	اگر ((r = sshbuf_put(m, WEBAUTHN_0, حجم(WEBAUTHN_0) - 1)) != 0 ||
	    (r = sshbuf_dtourlb64(chall, m, 0)) != 0 ||
	    (r = sshbuf_put(m, WEBAUTHN_1, حجم(WEBAUTHN_1) - 1)) != 0 ||
	    (r = sshbuf_put(m, origin, لڑی_لمبائی(origin))) != 0 ||
	    (r = sshbuf_put(m, WEBAUTHN_2, حجم(WEBAUTHN_2) - 1)) != 0)
		جاؤ برآمد;
#اگر_تعریف_شدہ DEBUG_SK
	fprintf(stderr, "%s: received origin: %s\n", __func__, origin);
	fprintf(stderr, "%s: received clientData:\n", __func__);
	sshbuf_dump(wrapper, stderr);
	fprintf(stderr, "%s: expected clientData preamble:\n", __func__);
	sshbuf_dump(m, stderr);
#اگر_ختم
	/* Check that the supplied clientData has the preamble we expect */
	اگر ((r = sshbuf_cmp(wrapper, 0, sshbuf_ptr(m), sshbuf_len(m))) != 0)
		جاؤ برآمد;

	/* Prepare hash of clientData */
	اگر ((r = ssh_digest_بفر(SSH_DIGEST_SHA256, wrapper,
	    msghash, msghashlen)) != 0)
		جاؤ برآمد;

	/* success */
	r = 0;
 برآمد:
	sshbuf_free(chall);
	sshbuf_free(m);
	واپس r;
}

ساکن صحیح
ssh_ecdsa_sk_verify(ثابت ساخت sshkey *کلید,
    ثابت u_char *sig, سائز_t siglen,
    ثابت u_char *ڈیٹا, سائز_t dlen, ثابت حرف *alg, u_int compat,
    ساخت sshkey_sig_details **detailsp)
{
	ECDSA_SIG *esig = تہی;
	EVP_MD_CTX *md_ctx = تہی;
	BIGNUM *sig_r = تہی, *sig_s = تہی;
	u_char sig_flags;
	u_char msghash[32], apphash[32];
	u_int sig_شمار;
	u_char *sigb = تہی, *cp;
	صحیح is_webauthn = 0, ret = SSH_ERR_اندرونی_ERROR, len = 0;
	ساخت sshbuf *b = تہی, *sigbuf = تہی, *original_signed = تہی;
	ساخت sshbuf *webauthn_wrapper = تہی, *webauthn_exts = تہی;
	حرف *ktype = تہی, *webauthn_origin = تہی;
	ساخت sshkey_sig_details *details = تہی;
#اگر_تعریف_شدہ DEBUG_SK
	حرف *tmp = تہی;
#اگر_ختم

	اگر (detailsp != تہی)
		*detailsp = تہی;
	اگر (کلید == تہی || کلید->pkey == تہی ||
	    sshkey_type_plain(کلید->type) != کلید_ECDSA_SK ||
	    sig == تہی || siglen == 0)
		واپس SSH_ERR_INVALID_دلیل;

	اگر (کلید->ecdsa_nid != NID_X9_62_prime256v1)
		واپس SSH_ERR_اندرونی_ERROR;

	/* fetch signature */
	اگر ((b = sshbuf_from(sig, siglen)) == تہی)
		واپس SSH_ERR_ALLOC_FAIL;
	اگر ((details = صفر_حافظہ_دو(1, حجم(*details))) == تہی) {
		ret = SSH_ERR_ALLOC_FAIL;
		جاؤ برآمد;
	}
	اگر (sshbuf_get_cstring(b, &ktype, تہی) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		جاؤ برآمد;
	}
	اگر (strcmp(ktype, "webauthn-sk-ecdsa-sha2-nistp256@openssh.com") == 0 ||
	    strcmp(ktype, "webauthn-sk-ecdsa-sha2-nistp256-cert-v01@openssh.com")
	      == 0)
		is_webauthn = 1;
	ورنہ اگر (strcmp(ktype, "sk-ecdsa-sha2-nistp256@openssh.com") != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		جاؤ برآمد;
	}
	اگر (sshbuf_froms(b, &sigbuf) != 0 ||
	    sshbuf_get_u8(b, &sig_flags) != 0 ||
	    sshbuf_get_u32(b, &sig_شمار) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		جاؤ برآمد;
	}
	اگر (is_webauthn) {
		اگر (sshbuf_get_cstring(b, &webauthn_origin, تہی) != 0 ||
		    sshbuf_froms(b, &webauthn_wrapper) != 0 ||
		    sshbuf_froms(b, &webauthn_exts) != 0) {
			ret = SSH_ERR_INVALID_FORMAT;
			جاؤ برآمد;
		}
	}
	اگر (sshbuf_len(b) != 0) {
		ret = SSH_ERR_UNEXPECTED_TRAILING_ڈیٹا;
		جاؤ برآمد;
	}

	/* parse signature */
	اگر (sshbuf_get_bignum2(sigbuf, &sig_r) != 0 ||
	    sshbuf_get_bignum2(sigbuf, &sig_s) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		جاؤ برآمد;
	}
	اگر (sshbuf_len(sigbuf) != 0) {
		ret = SSH_ERR_UNEXPECTED_TRAILING_ڈیٹا;
		جاؤ برآمد;
	}

#اگر_تعریف_شدہ DEBUG_SK
	fprintf(stderr, "%s: data: (len %zu)\n", __func__, dlen);
	/* sshbuf_dump_data(data, datalen, stderr); */
	fprintf(stderr, "%s: sig_r: %s\n", __func__, (tmp = BN_bn2hex(sig_r)));
	آزاد(tmp);
	fprintf(stderr, "%s: sig_s: %s\n", __func__, (tmp = BN_bn2hex(sig_s)));
	آزاد(tmp);
	fprintf(stderr, "%s: sig_flags = 0x%02x, sig_counter = %u\n",
	    __func__, sig_flags, sig_شمار);
	اگر (is_webauthn) {
		fprintf(stderr, "%s: webauthn origin: %s\n", __func__,
		    webauthn_origin);
		fprintf(stderr, "%s: webauthn_wrapper:\n", __func__);
		sshbuf_dump(webauthn_wrapper, stderr);
	}
#اگر_ختم
	اگر ((esig = ECDSA_SIG_new()) == تہی) {
		ret = SSH_ERR_ALLOC_FAIL;
		جاؤ برآمد;
	}
	اگر (!ECDSA_SIG_set0(esig, sig_r, sig_s)) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		جاؤ برآمد;
	}
	sig_r = sig_s = تہی; /* transferred */

	/* Reconstruct data that was supposedly signed */
	اگر ((original_signed = sshbuf_new()) == تہی) {
		ret = SSH_ERR_ALLOC_FAIL;
		جاؤ برآمد;
	}
	اگر (is_webauthn) {
		اگر ((ret = webauthn_check_prepare_hash(ڈیٹا, dlen,
		    webauthn_origin, webauthn_wrapper, sig_flags, webauthn_exts,
		    msghash, حجم(msghash))) != 0)
			جاؤ برآمد;
	} ورنہ اگر ((ret = ssh_digest_حافظہ(SSH_DIGEST_SHA256, ڈیٹا, dlen,
	    msghash, حجم(msghash))) != 0)
		جاؤ برآمد;
	/* Application value is hashed before signature */
	اگر ((ret = ssh_digest_حافظہ(SSH_DIGEST_SHA256, کلید->sk_application,
	    لڑی_لمبائی(کلید->sk_application), apphash, حجم(apphash))) != 0)
		جاؤ برآمد;
#اگر_تعریف_شدہ DEBUG_SK
	fprintf(stderr, "%s: hashed application:\n", __func__);
	sshbuf_dump_ڈیٹا(apphash, حجم(apphash), stderr);
	fprintf(stderr, "%s: hashed message:\n", __func__);
	sshbuf_dump_ڈیٹا(msghash, حجم(msghash), stderr);
#اگر_ختم
	اگر ((ret = sshbuf_put(original_signed,
	    apphash, حجم(apphash))) != 0 ||
	    (ret = sshbuf_put_u8(original_signed, sig_flags)) != 0 ||
	    (ret = sshbuf_put_u32(original_signed, sig_شمار)) != 0 ||
	    (ret = sshbuf_putb(original_signed, webauthn_exts)) != 0 ||
	    (ret = sshbuf_put(original_signed, msghash, حجم(msghash))) != 0)
		جاؤ برآمد;
	details->sk_شمار = sig_شمار;
	details->sk_flags = sig_flags;
#اگر_تعریف_شدہ DEBUG_SK
	fprintf(stderr, "%s: signed buf:\n", __func__);
	sshbuf_dump(original_signed, stderr);
#اگر_ختم

	اگر ((md_ctx = EVP_MD_CTX_new()) == تہی) {
		ret = SSH_ERR_ALLOC_FAIL;
		جاؤ برآمد;
	}
	اگر ((len = i2d_ECDSA_SIG(esig, تہی)) <= 0) {
		len = 0;
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		جاؤ برآمد;
	}
	اگر ((sigb = صفر_حافظہ_دو(1, len)) == تہی) {
		ret = SSH_ERR_ALLOC_FAIL;
		جاؤ برآمد;
	}
	cp = sigb; /* ASN1_item_i2d increments the pointer past the object */
	اگر (i2d_ECDSA_SIG(esig, &cp) != len) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		جاؤ برآمد;
	}
#اگر_تعریف_شدہ DEBUG_SK
	fprintf(stderr, "%s: signed hash:\n", __func__);
	sshbuf_dump_ڈیٹا(sigb, len, stderr);
#اگر_ختم
	/* Verify it */
	اگر (EVP_DigestVerifyInit(md_ctx, تہی, EVP_sha256(), تہی,
	    کلید->pkey) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		جاؤ برآمد;
	}
	انتخاب (EVP_DigestVerify(md_ctx, sigb, len,
	    sshbuf_ptr(original_signed), sshbuf_len(original_signed))) {
	حالت 1:
		ret = 0;
		توڑو;
	حالت 0:
		ret = SSH_ERR_SIGNATURE_INVALID;
		جاؤ برآمد;
	طےشدہ:
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		جاؤ برآمد;
	}
	/* success */
	اگر (detailsp != تہی) {
		*detailsp = details;
		details = تہی;
	}
 برآمد:
	explicit_bzero(&sig_flags, حجم(sig_flags));
	explicit_bzero(&sig_شمار, حجم(sig_شمار));
	explicit_bzero(msghash, حجم(msghash));
	explicit_bzero(apphash, حجم(apphash));
	sshkey_sig_details_free(details);
	sshbuf_free(webauthn_wrapper);
	sshbuf_free(webauthn_exts);
	آزاد(webauthn_origin);
	sshbuf_free(original_signed);
	sshbuf_free(sigbuf);
	sshbuf_free(b);
	ECDSA_SIG_free(esig);
	BN_clear_free(sig_r);
	BN_clear_free(sig_s);
	آزاد(ktype);
	freezero(sigb, len);
	EVP_MD_CTX_free(md_ctx);
	واپس ret;
}

ساکن ثابت ساخت sshkey_impl_funcs sshkey_ecdsa_sk_funcs = {
	/* .size = */		تہی,
	/* .alloc = */		تہی,
	/* .cleanup = */	ssh_ecdsa_sk_cleanup,
	/* .equal = */		ssh_ecdsa_sk_equal,
	/* .ssh_serialize_public = */ ssh_ecdsa_sk_serialize_عوامی,
	/* .ssh_deserialize_public = */ ssh_ecdsa_sk_deserialize_عوامی,
	/* .ssh_serialize_private = */ ssh_ecdsa_sk_serialize_نجی,
	/* .ssh_deserialize_private = */ ssh_ecdsa_sk_deserialize_نجی,
	/* .generate = */	تہی,
	/* .copy_public = */	ssh_ecdsa_sk_copy_عوامی,
	/* .sign = */		تہی,
	/* .verify = */		ssh_ecdsa_sk_verify,
};

ثابت ساخت sshkey_impl sshkey_ecdsa_sk_impl = {
	/* .name = */		"sk-ecdsa-sha2-nistp256@openssh.com",
	/* .shortname = */	"ECDSA-SK",
	/* .sigalg = */		تہی,
	/* .type = */		کلید_ECDSA_SK,
	/* .nid = */		NID_X9_62_prime256v1,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	256,
	/* .funcs = */		&sshkey_ecdsa_sk_funcs,
};

ثابت ساخت sshkey_impl sshkey_ecdsa_sk_cert_impl = {
	/* .name = */		"sk-ecdsa-sha2-nistp256-cert-v01@openssh.com",
	/* .shortname = */	"ECDSA-SK-CERT",
	/* .sigalg = */		تہی,
	/* .type = */		کلید_ECDSA_SK_CERT,
	/* .nid = */		NID_X9_62_prime256v1,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	256,
	/* .funcs = */		&sshkey_ecdsa_sk_funcs,
};

ثابت ساخت sshkey_impl sshkey_ecdsa_sk_webauthn_impl = {
	/* .name = */		"webauthn-sk-ecdsa-sha2-nistp256@openssh.com",
	/* .shortname = */	"ECDSA-SK",
	/* .sigalg = */		تہی,
	/* .type = */		کلید_ECDSA_SK,
	/* .nid = */		NID_X9_62_prime256v1,
	/* .cert = */		0,
	/* .sigonly = */	1,
	/* .keybits = */	256,
	/* .funcs = */		&sshkey_ecdsa_sk_funcs,
};

ثابت ساخت sshkey_impl sshkey_ecdsa_sk_webauthn_cert_impl = {
	/* .name = */		"webauthn-sk-ecdsa-sha2-nistp256-cert-v01@openssh.com",
	/* .shortname = */	"ECDSA-SK-CERT",
	/* .sigalg = */		تہی,
	/* .type = */		کلید_ECDSA_SK_CERT,
	/* .nid = */		NID_X9_62_prime256v1,
	/* .cert = */		1,
	/* .sigonly = */	1,
	/* .keybits = */	256,
	/* .funcs = */		&sshkey_ecdsa_sk_funcs,
};
#اگر_ختم /* WITH_OPENSSL */
