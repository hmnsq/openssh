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

#ضمن "includes.h"

#ضمن <sys/types.h>

#ifdef WITH_OPENSSL
#ضمن "openbsd-compat/openssl-compat.h"
#ضمن <openssl/bn.h>
#ضمن <openssl/ec.h>
#ضمن <openssl/ecdsa.h>
#ضمن <openssl/evp.h>

#ضمن <string.h>
#ضمن <stdio.h> /* needed for DEBUG_SK only */

#ضمن "sshbuf.h"
#ضمن "ssherr.h"
#ضمن "digest.h"
#define SSHKEY_INTERNAL
#ضمن "sshkey.h"

/* Reuse some ECDSA internals */
خارجي بنية sshkey_impl_funcs sshkey_ecdsa_funcs;

ساكن فراغ
ssh_ecdsa_sk_cleanup(بنية sshkey *k)
{
	sshkey_sk_cleanup(k);
	sshkey_ecdsa_funcs.cleanup(k);
}

ساكن صحيح
ssh_ecdsa_sk_equal(ثابت بنية sshkey *a, ثابت بنية sshkey *b)
{
	إذا (!sshkey_sk_fields_equal(a, b))
		أرجع 0;
	إذا (!sshkey_ecdsa_funcs.equal(a, b))
		أرجع 0;
	أرجع 1;
}

ساكن صحيح
ssh_ecdsa_sk_serialize_public(ثابت بنية sshkey *کلید, بنية sshbuf *b,
    تعداد sshkey_serialize_rep opts)
{
	صحيح r;

	إذا ((r = sshkey_ecdsa_funcs.serialize_public(کلید, b, opts)) != 0)
		أرجع r;
	إذا ((r = sshkey_serialize_sk(کلید, b)) != 0)
		أرجع r;

	أرجع 0;
}

ساكن صحيح
ssh_ecdsa_sk_serialize_private(ثابت بنية sshkey *کلید, بنية sshbuf *b,
    تعداد sshkey_serialize_rep opts)
{
	صحيح r;

	إذا (!sshkey_is_cert(کلید)) {
		إذا ((r = sshkey_ecdsa_funcs.serialize_public(کلید,
		    b, opts)) != 0)
			أرجع r;
	}
	إذا ((r = sshkey_serialize_private_sk(کلید, b)) != 0)
		أرجع r;

	أرجع 0;
}

ساكن صحيح
ssh_ecdsa_sk_copy_public(ثابت بنية sshkey *from, بنية sshkey *to)
{
	صحيح r;

	إذا ((r = sshkey_ecdsa_funcs.copy_public(from, to)) != 0)
		أرجع r;
	إذا ((r = sshkey_copy_public_sk(from, to)) != 0)
		أرجع r;
	أرجع 0;
}

ساكن صحيح
ssh_ecdsa_sk_deserialize_public(ثابت حرف *ktype, بنية sshbuf *b,
    بنية sshkey *کلید)
{
	صحيح r;

	إذا ((r = sshkey_ecdsa_funcs.deserialize_public(ktype, b, کلید)) != 0)
		أرجع r;
	إذا ((r = sshkey_deserialize_sk(b, کلید)) != 0)
		أرجع r;
	أرجع 0;
}

ساكن صحيح
ssh_ecdsa_sk_deserialize_private(ثابت حرف *ktype, بنية sshbuf *b,
    بنية sshkey *کلید)
{
	صحيح r;

	إذا (!sshkey_is_cert(کلید)) {
		إذا ((r = sshkey_ecdsa_funcs.deserialize_public(ktype,
		    b, کلید)) != 0)
			أرجع r;
	}
	إذا ((r = sshkey_private_deserialize_sk(b, کلید)) != 0)
		أرجع r;

	أرجع 0;
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
ساكن صحيح
webauthn_check_prepare_hash(ثابت u_char *data, size_t datalen,
    ثابت حرف *origin, ثابت بنية sshbuf *wrapper,
    uint8_t flags, ثابت بنية sshbuf *extensions,
    u_char *msghash, size_t msghashlen)
{
	صحيح r = SSH_ERR_INTERNAL_ERROR;
	بنية sshbuf *chall = عدم, *m = عدم;

	إذا ((m = sshbuf_new()) == عدم ||
	    (chall = sshbuf_from(data, datalen)) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب out;
	}
	/*
	 * Ensure origin contains no quote character and that the flags are
	 * consistent with what we received
	 */
	إذا (strchr(origin, '\"') != عدم ||
	    (flags & 0x40) != 0 /* AD */ ||
	    ((flags & 0x80) == 0 /* ED */) != (sshbuf_len(extensions) == 0)) {
		r = SSH_ERR_INVALID_FORMAT;
		اذهب out;
	}

	/*
	 * Prepare the preamble to clientData that we expect, poking the
	 * challenge and origin into their canonical positions in the
	 * structure. The crossOrigin flag and any additional extension
	 * fields present are ignored.
	 */
#define WEBAUTHN_0	"{\"type\":\"webauthn.get\",\"challenge\":\""
#define WEBAUTHN_1	"\",\"origin\":\""
#define WEBAUTHN_2	"\""
	إذا ((r = sshbuf_put(m, WEBAUTHN_0, حجم(WEBAUTHN_0) - 1)) != 0 ||
	    (r = sshbuf_dtourlb64(chall, m, 0)) != 0 ||
	    (r = sshbuf_put(m, WEBAUTHN_1, حجم(WEBAUTHN_1) - 1)) != 0 ||
	    (r = sshbuf_put(m, origin, strlen(origin))) != 0 ||
	    (r = sshbuf_put(m, WEBAUTHN_2, حجم(WEBAUTHN_2) - 1)) != 0)
		اذهب out;
#ifdef DEBUG_SK
	fprintf(stderr, "%s: received origin: %s\n", __func__, origin);
	fprintf(stderr, "%s: received clientData:\n", __func__);
	sshbuf_dump(wrapper, stderr);
	fprintf(stderr, "%s: expected clientData preamble:\n", __func__);
	sshbuf_dump(m, stderr);
#endif
	/* Check that the supplied clientData has the preamble we expect */
	إذا ((r = sshbuf_cmp(wrapper, 0, sshbuf_ptr(m), sshbuf_len(m))) != 0)
		اذهب out;

	/* Prepare hash of clientData */
	إذا ((r = ssh_digest_buffer(SSH_DIGEST_SHA256, wrapper,
	    msghash, msghashlen)) != 0)
		اذهب out;

	/* success */
	r = 0;
 out:
	sshbuf_free(chall);
	sshbuf_free(m);
	أرجع r;
}

ساكن صحيح
ssh_ecdsa_sk_verify(ثابت بنية sshkey *کلید,
    ثابت u_char *sig, size_t siglen,
    ثابت u_char *data, size_t dlen, ثابت حرف *alg, u_int compat,
    بنية sshkey_sig_details **detailsp)
{
	ECDSA_SIG *esig = عدم;
	EVP_MD_CTX *md_ctx = عدم;
	BIGNUM *sig_r = عدم, *sig_s = عدم;
	u_char sig_flags;
	u_char msghash[32], apphash[32];
	u_int sig_counter;
	u_char *sigb = عدم, *cp;
	صحيح is_webauthn = 0, ret = SSH_ERR_INTERNAL_ERROR, len = 0;
	بنية sshbuf *b = عدم, *sigbuf = عدم, *original_signed = عدم;
	بنية sshbuf *webauthn_wrapper = عدم, *webauthn_exts = عدم;
	حرف *ktype = عدم, *webauthn_origin = عدم;
	بنية sshkey_sig_details *details = عدم;
#ifdef DEBUG_SK
	حرف *tmp = عدم;
#endif

	إذا (detailsp != عدم)
		*detailsp = عدم;
	إذا (کلید == عدم || کلید->pkey == عدم ||
	    sshkey_type_plain(کلید->type) != کلید_ECDSA_SK ||
	    sig == عدم || siglen == 0)
		أرجع SSH_ERR_INVALID_ARGUMENT;

	إذا (کلید->ecdsa_nid != NID_X9_62_prime256v1)
		أرجع SSH_ERR_INTERNAL_ERROR;

	/* fetch signature */
	إذا ((b = sshbuf_from(sig, siglen)) == عدم)
		أرجع SSH_ERR_ALLOC_FAIL;
	إذا ((details = calloc(1, حجم(*details))) == عدم) {
		ret = SSH_ERR_ALLOC_FAIL;
		اذهب out;
	}
	إذا (sshbuf_get_cstring(b, &ktype, عدم) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		اذهب out;
	}
	إذا (strcmp(ktype, "webauthn-sk-ecdsa-sha2-nistp256@openssh.com") == 0 ||
	    strcmp(ktype, "webauthn-sk-ecdsa-sha2-nistp256-cert-v01@openssh.com")
	      == 0)
		is_webauthn = 1;
	وإلا إذا (strcmp(ktype, "sk-ecdsa-sha2-nistp256@openssh.com") != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		اذهب out;
	}
	إذا (sshbuf_froms(b, &sigbuf) != 0 ||
	    sshbuf_get_u8(b, &sig_flags) != 0 ||
	    sshbuf_get_u32(b, &sig_counter) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		اذهب out;
	}
	إذا (is_webauthn) {
		إذا (sshbuf_get_cstring(b, &webauthn_origin, عدم) != 0 ||
		    sshbuf_froms(b, &webauthn_wrapper) != 0 ||
		    sshbuf_froms(b, &webauthn_exts) != 0) {
			ret = SSH_ERR_INVALID_FORMAT;
			اذهب out;
		}
	}
	إذا (sshbuf_len(b) != 0) {
		ret = SSH_ERR_UNEXPECTED_TRAILING_DATA;
		اذهب out;
	}

	/* parse signature */
	إذا (sshbuf_get_bignum2(sigbuf, &sig_r) != 0 ||
	    sshbuf_get_bignum2(sigbuf, &sig_s) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		اذهب out;
	}
	إذا (sshbuf_len(sigbuf) != 0) {
		ret = SSH_ERR_UNEXPECTED_TRAILING_DATA;
		اذهب out;
	}

#ifdef DEBUG_SK
	fprintf(stderr, "%s: data: (len %zu)\n", __func__, dlen);
	/* sshbuf_dump_data(data, datalen, stderr); */
	fprintf(stderr, "%s: sig_r: %s\n", __func__, (tmp = BN_bn2hex(sig_r)));
	حرر(tmp);
	fprintf(stderr, "%s: sig_s: %s\n", __func__, (tmp = BN_bn2hex(sig_s)));
	حرر(tmp);
	fprintf(stderr, "%s: sig_flags = 0x%02x, sig_counter = %u\n",
	    __func__, sig_flags, sig_counter);
	إذا (is_webauthn) {
		fprintf(stderr, "%s: webauthn origin: %s\n", __func__,
		    webauthn_origin);
		fprintf(stderr, "%s: webauthn_wrapper:\n", __func__);
		sshbuf_dump(webauthn_wrapper, stderr);
	}
#endif
	إذا ((esig = ECDSA_SIG_new()) == عدم) {
		ret = SSH_ERR_ALLOC_FAIL;
		اذهب out;
	}
	إذا (!ECDSA_SIG_set0(esig, sig_r, sig_s)) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		اذهب out;
	}
	sig_r = sig_s = عدم; /* transferred */

	/* Reconstruct data that was supposedly signed */
	إذا ((original_signed = sshbuf_new()) == عدم) {
		ret = SSH_ERR_ALLOC_FAIL;
		اذهب out;
	}
	إذا (is_webauthn) {
		إذا ((ret = webauthn_check_prepare_hash(data, dlen,
		    webauthn_origin, webauthn_wrapper, sig_flags, webauthn_exts,
		    msghash, حجم(msghash))) != 0)
			اذهب out;
	} وإلا إذا ((ret = ssh_digest_memory(SSH_DIGEST_SHA256, data, dlen,
	    msghash, حجم(msghash))) != 0)
		اذهب out;
	/* Application value is hashed before signature */
	إذا ((ret = ssh_digest_memory(SSH_DIGEST_SHA256, کلید->sk_application,
	    strlen(کلید->sk_application), apphash, حجم(apphash))) != 0)
		اذهب out;
#ifdef DEBUG_SK
	fprintf(stderr, "%s: hashed application:\n", __func__);
	sshbuf_dump_data(apphash, حجم(apphash), stderr);
	fprintf(stderr, "%s: hashed message:\n", __func__);
	sshbuf_dump_data(msghash, حجم(msghash), stderr);
#endif
	إذا ((ret = sshbuf_put(original_signed,
	    apphash, حجم(apphash))) != 0 ||
	    (ret = sshbuf_put_u8(original_signed, sig_flags)) != 0 ||
	    (ret = sshbuf_put_u32(original_signed, sig_counter)) != 0 ||
	    (ret = sshbuf_putb(original_signed, webauthn_exts)) != 0 ||
	    (ret = sshbuf_put(original_signed, msghash, حجم(msghash))) != 0)
		اذهب out;
	details->sk_counter = sig_counter;
	details->sk_flags = sig_flags;
#ifdef DEBUG_SK
	fprintf(stderr, "%s: signed buf:\n", __func__);
	sshbuf_dump(original_signed, stderr);
#endif

	إذا ((md_ctx = EVP_MD_CTX_new()) == عدم) {
		ret = SSH_ERR_ALLOC_FAIL;
		اذهب out;
	}
	إذا ((len = i2d_ECDSA_SIG(esig, عدم)) <= 0) {
		len = 0;
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		اذهب out;
	}
	إذا ((sigb = calloc(1, len)) == عدم) {
		ret = SSH_ERR_ALLOC_FAIL;
		اذهب out;
	}
	cp = sigb; /* ASN1_item_i2d increments the pointer past the object */
	إذا (i2d_ECDSA_SIG(esig, &cp) != len) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		اذهب out;
	}
#ifdef DEBUG_SK
	fprintf(stderr, "%s: signed hash:\n", __func__);
	sshbuf_dump_data(sigb, len, stderr);
#endif
	/* Verify it */
	إذا (EVP_DigestVerifyInit(md_ctx, عدم, EVP_sha256(), عدم,
	    کلید->pkey) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		اذهب out;
	}
	بدل (EVP_DigestVerify(md_ctx, sigb, len,
	    sshbuf_ptr(original_signed), sshbuf_len(original_signed))) {
	حالة 1:
		ret = 0;
		اكسر;
	حالة 0:
		ret = SSH_ERR_SIGNATURE_INVALID;
		اذهب out;
	افتراضي:
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		اذهب out;
	}
	/* success */
	إذا (detailsp != عدم) {
		*detailsp = details;
		details = عدم;
	}
 out:
	explicit_bzero(&sig_flags, حجم(sig_flags));
	explicit_bzero(&sig_counter, حجم(sig_counter));
	explicit_bzero(msghash, حجم(msghash));
	explicit_bzero(apphash, حجم(apphash));
	sshkey_sig_details_free(details);
	sshbuf_free(webauthn_wrapper);
	sshbuf_free(webauthn_exts);
	حرر(webauthn_origin);
	sshbuf_free(original_signed);
	sshbuf_free(sigbuf);
	sshbuf_free(b);
	ECDSA_SIG_free(esig);
	BN_clear_free(sig_r);
	BN_clear_free(sig_s);
	حرر(ktype);
	freezero(sigb, len);
	EVP_MD_CTX_free(md_ctx);
	أرجع ret;
}

ساكن ثابت بنية sshkey_impl_funcs sshkey_ecdsa_sk_funcs = {
	/* .size = */		عدم,
	/* .alloc = */		عدم,
	/* .cleanup = */	ssh_ecdsa_sk_cleanup,
	/* .equal = */		ssh_ecdsa_sk_equal,
	/* .ssh_serialize_public = */ ssh_ecdsa_sk_serialize_public,
	/* .ssh_deserialize_public = */ ssh_ecdsa_sk_deserialize_public,
	/* .ssh_serialize_private = */ ssh_ecdsa_sk_serialize_private,
	/* .ssh_deserialize_private = */ ssh_ecdsa_sk_deserialize_private,
	/* .generate = */	عدم,
	/* .copy_public = */	ssh_ecdsa_sk_copy_public,
	/* .sign = */		عدم,
	/* .verify = */		ssh_ecdsa_sk_verify,
};

ثابت بنية sshkey_impl sshkey_ecdsa_sk_impl = {
	/* .name = */		"sk-ecdsa-sha2-nistp256@openssh.com",
	/* .shortname = */	"ECDSA-SK",
	/* .sigalg = */		عدم,
	/* .type = */		کلید_ECDSA_SK,
	/* .nid = */		NID_X9_62_prime256v1,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	256,
	/* .funcs = */		&sshkey_ecdsa_sk_funcs,
};

ثابت بنية sshkey_impl sshkey_ecdsa_sk_cert_impl = {
	/* .name = */		"sk-ecdsa-sha2-nistp256-cert-v01@openssh.com",
	/* .shortname = */	"ECDSA-SK-CERT",
	/* .sigalg = */		عدم,
	/* .type = */		کلید_ECDSA_SK_CERT,
	/* .nid = */		NID_X9_62_prime256v1,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	256,
	/* .funcs = */		&sshkey_ecdsa_sk_funcs,
};

ثابت بنية sshkey_impl sshkey_ecdsa_sk_webauthn_impl = {
	/* .name = */		"webauthn-sk-ecdsa-sha2-nistp256@openssh.com",
	/* .shortname = */	"ECDSA-SK",
	/* .sigalg = */		عدم,
	/* .type = */		کلید_ECDSA_SK,
	/* .nid = */		NID_X9_62_prime256v1,
	/* .cert = */		0,
	/* .sigonly = */	1,
	/* .keybits = */	256,
	/* .funcs = */		&sshkey_ecdsa_sk_funcs,
};

ثابت بنية sshkey_impl sshkey_ecdsa_sk_webauthn_cert_impl = {
	/* .name = */		"webauthn-sk-ecdsa-sha2-nistp256-cert-v01@openssh.com",
	/* .shortname = */	"ECDSA-SK-CERT",
	/* .sigalg = */		عدم,
	/* .type = */		کلید_ECDSA_SK_CERT,
	/* .nid = */		NID_X9_62_prime256v1,
	/* .cert = */		1,
	/* .sigonly = */	1,
	/* .keybits = */	256,
	/* .funcs = */		&sshkey_ecdsa_sk_funcs,
};
#endif /* WITH_OPENSSL */
