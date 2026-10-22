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

#ifdef WITH_OPENSSL
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
#define SSHKEY_INTERNAL
#شامل "sshkey.h"

/* Reuse some ECDSA internals */
بیرونی ساختار sshkey_impl_funcs sshkey_ecdsa_funcs;

ایستا تهی
ssh_ecdsa_sk_cleanup(ساختار sshkey *k)
{
	sshkey_sk_cleanup(k);
	sshkey_ecdsa_funcs.cleanup(k);
}

ایستا صحیح
ssh_ecdsa_sk_equal(ثابت ساختار sshkey *a, ثابت ساختار sshkey *b)
{
	اگر (!sshkey_sk_fields_equal(a, b))
		بازگشت 0;
	اگر (!sshkey_ecdsa_funcs.equal(a, b))
		بازگشت 0;
	بازگشت 1;
}

ایستا صحیح
ssh_ecdsa_sk_serialize_public(ثابت ساختار sshkey *کلید, ساختار sshbuf *b,
    شمارش sshkey_serialize_rep opts)
{
	صحیح r;

	اگر ((r = sshkey_ecdsa_funcs.serialize_public(کلید, b, opts)) != 0)
		بازگشت r;
	اگر ((r = sshkey_serialize_sk(کلید, b)) != 0)
		بازگشت r;

	بازگشت 0;
}

ایستا صحیح
ssh_ecdsa_sk_serialize_private(ثابت ساختار sshkey *کلید, ساختار sshbuf *b,
    شمارش sshkey_serialize_rep opts)
{
	صحیح r;

	اگر (!sshkey_is_cert(کلید)) {
		اگر ((r = sshkey_ecdsa_funcs.serialize_public(کلید,
		    b, opts)) != 0)
			بازگشت r;
	}
	اگر ((r = sshkey_serialize_private_sk(کلید, b)) != 0)
		بازگشت r;

	بازگشت 0;
}

ایستا صحیح
ssh_ecdsa_sk_copy_public(ثابت ساختار sshkey *from, ساختار sshkey *to)
{
	صحیح r;

	اگر ((r = sshkey_ecdsa_funcs.copy_public(from, to)) != 0)
		بازگشت r;
	اگر ((r = sshkey_copy_public_sk(from, to)) != 0)
		بازگشت r;
	بازگشت 0;
}

ایستا صحیح
ssh_ecdsa_sk_deserialize_public(ثابت نویسه *ktype, ساختار sshbuf *b,
    ساختار sshkey *کلید)
{
	صحیح r;

	اگر ((r = sshkey_ecdsa_funcs.deserialize_public(ktype, b, کلید)) != 0)
		بازگشت r;
	اگر ((r = sshkey_deserialize_sk(b, کلید)) != 0)
		بازگشت r;
	بازگشت 0;
}

ایستا صحیح
ssh_ecdsa_sk_deserialize_private(ثابت نویسه *ktype, ساختار sshbuf *b,
    ساختار sshkey *کلید)
{
	صحیح r;

	اگر (!sshkey_is_cert(کلید)) {
		اگر ((r = sshkey_ecdsa_funcs.deserialize_public(ktype,
		    b, کلید)) != 0)
			بازگشت r;
	}
	اگر ((r = sshkey_private_deserialize_sk(b, کلید)) != 0)
		بازگشت r;

	بازگشت 0;
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
ایستا صحیح
webauthn_check_prepare_hash(ثابت u_char *data, size_t datalen,
    ثابت نویسه *origin, ثابت ساختار sshbuf *wrapper,
    uint8_t flags, ثابت ساختار sshbuf *extensions,
    u_char *msghash, size_t msghashlen)
{
	صحیح r = SSH_ERR_INTERNAL_ERROR;
	ساختار sshbuf *chall = پوچ, *m = پوچ;

	اگر ((m = sshbuf_new()) == پوچ ||
	    (chall = sshbuf_from(data, datalen)) == پوچ) {
		r = SSH_ERR_ALLOC_FAIL;
		برو out;
	}
	/*
	 * Ensure origin contains no quote character and that the flags are
	 * consistent with what we received
	 */
	اگر (strchr(origin, '\"') != پوچ ||
	    (flags & 0x40) != 0 /* AD */ ||
	    ((flags & 0x80) == 0 /* ED */) != (sshbuf_len(extensions) == 0)) {
		r = SSH_ERR_INVALID_FORMAT;
		برو out;
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
	اگر ((r = sshbuf_put(m, WEBAUTHN_0, اندازه(WEBAUTHN_0) - 1)) != 0 ||
	    (r = sshbuf_dtourlb64(chall, m, 0)) != 0 ||
	    (r = sshbuf_put(m, WEBAUTHN_1, اندازه(WEBAUTHN_1) - 1)) != 0 ||
	    (r = sshbuf_put(m, origin, strlen(origin))) != 0 ||
	    (r = sshbuf_put(m, WEBAUTHN_2, اندازه(WEBAUTHN_2) - 1)) != 0)
		برو out;
#ifdef DEBUG_SK
	fprintf(stderr, "%s: received origin: %s\n", __func__, origin);
	fprintf(stderr, "%s: received clientData:\n", __func__);
	sshbuf_dump(wrapper, stderr);
	fprintf(stderr, "%s: expected clientData preamble:\n", __func__);
	sshbuf_dump(m, stderr);
#endif
	/* Check that the supplied clientData has the preamble we expect */
	اگر ((r = sshbuf_cmp(wrapper, 0, sshbuf_ptr(m), sshbuf_len(m))) != 0)
		برو out;

	/* Prepare hash of clientData */
	اگر ((r = ssh_digest_buffer(SSH_DIGEST_SHA256, wrapper,
	    msghash, msghashlen)) != 0)
		برو out;

	/* success */
	r = 0;
 out:
	sshbuf_free(chall);
	sshbuf_free(m);
	بازگشت r;
}

ایستا صحیح
ssh_ecdsa_sk_verify(ثابت ساختار sshkey *کلید,
    ثابت u_char *sig, size_t siglen,
    ثابت u_char *data, size_t dlen, ثابت نویسه *alg, u_int compat,
    ساختار sshkey_sig_details **detailsp)
{
	ECDSA_SIG *esig = پوچ;
	EVP_MD_CTX *md_ctx = پوچ;
	BIGNUM *sig_r = پوچ, *sig_s = پوچ;
	u_char sig_flags;
	u_char msghash[32], apphash[32];
	u_int sig_counter;
	u_char *sigb = پوچ, *cp;
	صحیح is_webauthn = 0, ret = SSH_ERR_INTERNAL_ERROR, len = 0;
	ساختار sshbuf *b = پوچ, *sigbuf = پوچ, *original_signed = پوچ;
	ساختار sshbuf *webauthn_wrapper = پوچ, *webauthn_exts = پوچ;
	نویسه *ktype = پوچ, *webauthn_origin = پوچ;
	ساختار sshkey_sig_details *details = پوچ;
#ifdef DEBUG_SK
	نویسه *tmp = پوچ;
#endif

	اگر (detailsp != پوچ)
		*detailsp = پوچ;
	اگر (کلید == پوچ || کلید->pkey == پوچ ||
	    sshkey_type_plain(کلید->type) != کلید_ECDSA_SK ||
	    sig == پوچ || siglen == 0)
		بازگشت SSH_ERR_INVALID_ARGUMENT;

	اگر (کلید->ecdsa_nid != NID_X9_62_prime256v1)
		بازگشت SSH_ERR_INTERNAL_ERROR;

	/* fetch signature */
	اگر ((b = sshbuf_from(sig, siglen)) == پوچ)
		بازگشت SSH_ERR_ALLOC_FAIL;
	اگر ((details = calloc(1, اندازه(*details))) == پوچ) {
		ret = SSH_ERR_ALLOC_FAIL;
		برو out;
	}
	اگر (sshbuf_get_cstring(b, &ktype, پوچ) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		برو out;
	}
	اگر (strcmp(ktype, "webauthn-sk-ecdsa-sha2-nistp256@openssh.com") == 0 ||
	    strcmp(ktype, "webauthn-sk-ecdsa-sha2-nistp256-cert-v01@openssh.com")
	      == 0)
		is_webauthn = 1;
	وگرنه اگر (strcmp(ktype, "sk-ecdsa-sha2-nistp256@openssh.com") != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		برو out;
	}
	اگر (sshbuf_froms(b, &sigbuf) != 0 ||
	    sshbuf_get_u8(b, &sig_flags) != 0 ||
	    sshbuf_get_u32(b, &sig_counter) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		برو out;
	}
	اگر (is_webauthn) {
		اگر (sshbuf_get_cstring(b, &webauthn_origin, پوچ) != 0 ||
		    sshbuf_froms(b, &webauthn_wrapper) != 0 ||
		    sshbuf_froms(b, &webauthn_exts) != 0) {
			ret = SSH_ERR_INVALID_FORMAT;
			برو out;
		}
	}
	اگر (sshbuf_len(b) != 0) {
		ret = SSH_ERR_UNEXPECTED_TRAILING_DATA;
		برو out;
	}

	/* parse signature */
	اگر (sshbuf_get_bignum2(sigbuf, &sig_r) != 0 ||
	    sshbuf_get_bignum2(sigbuf, &sig_s) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		برو out;
	}
	اگر (sshbuf_len(sigbuf) != 0) {
		ret = SSH_ERR_UNEXPECTED_TRAILING_DATA;
		برو out;
	}

#ifdef DEBUG_SK
	fprintf(stderr, "%s: data: (len %zu)\n", __func__, dlen);
	/* sshbuf_dump_data(data, datalen, stderr); */
	fprintf(stderr, "%s: sig_r: %s\n", __func__, (tmp = BN_bn2hex(sig_r)));
	آزاد(tmp);
	fprintf(stderr, "%s: sig_s: %s\n", __func__, (tmp = BN_bn2hex(sig_s)));
	آزاد(tmp);
	fprintf(stderr, "%s: sig_flags = 0x%02x, sig_counter = %u\n",
	    __func__, sig_flags, sig_counter);
	اگر (is_webauthn) {
		fprintf(stderr, "%s: webauthn origin: %s\n", __func__,
		    webauthn_origin);
		fprintf(stderr, "%s: webauthn_wrapper:\n", __func__);
		sshbuf_dump(webauthn_wrapper, stderr);
	}
#endif
	اگر ((esig = ECDSA_SIG_new()) == پوچ) {
		ret = SSH_ERR_ALLOC_FAIL;
		برو out;
	}
	اگر (!ECDSA_SIG_set0(esig, sig_r, sig_s)) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		برو out;
	}
	sig_r = sig_s = پوچ; /* transferred */

	/* Reconstruct data that was supposedly signed */
	اگر ((original_signed = sshbuf_new()) == پوچ) {
		ret = SSH_ERR_ALLOC_FAIL;
		برو out;
	}
	اگر (is_webauthn) {
		اگر ((ret = webauthn_check_prepare_hash(data, dlen,
		    webauthn_origin, webauthn_wrapper, sig_flags, webauthn_exts,
		    msghash, اندازه(msghash))) != 0)
			برو out;
	} وگرنه اگر ((ret = ssh_digest_memory(SSH_DIGEST_SHA256, data, dlen,
	    msghash, اندازه(msghash))) != 0)
		برو out;
	/* Application value is hashed before signature */
	اگر ((ret = ssh_digest_memory(SSH_DIGEST_SHA256, کلید->sk_application,
	    strlen(کلید->sk_application), apphash, اندازه(apphash))) != 0)
		برو out;
#ifdef DEBUG_SK
	fprintf(stderr, "%s: hashed application:\n", __func__);
	sshbuf_dump_data(apphash, اندازه(apphash), stderr);
	fprintf(stderr, "%s: hashed message:\n", __func__);
	sshbuf_dump_data(msghash, اندازه(msghash), stderr);
#endif
	اگر ((ret = sshbuf_put(original_signed,
	    apphash, اندازه(apphash))) != 0 ||
	    (ret = sshbuf_put_u8(original_signed, sig_flags)) != 0 ||
	    (ret = sshbuf_put_u32(original_signed, sig_counter)) != 0 ||
	    (ret = sshbuf_putb(original_signed, webauthn_exts)) != 0 ||
	    (ret = sshbuf_put(original_signed, msghash, اندازه(msghash))) != 0)
		برو out;
	details->sk_counter = sig_counter;
	details->sk_flags = sig_flags;
#ifdef DEBUG_SK
	fprintf(stderr, "%s: signed buf:\n", __func__);
	sshbuf_dump(original_signed, stderr);
#endif

	اگر ((md_ctx = EVP_MD_CTX_new()) == پوچ) {
		ret = SSH_ERR_ALLOC_FAIL;
		برو out;
	}
	اگر ((len = i2d_ECDSA_SIG(esig, پوچ)) <= 0) {
		len = 0;
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		برو out;
	}
	اگر ((sigb = calloc(1, len)) == پوچ) {
		ret = SSH_ERR_ALLOC_FAIL;
		برو out;
	}
	cp = sigb; /* ASN1_item_i2d increments the pointer past the object */
	اگر (i2d_ECDSA_SIG(esig, &cp) != len) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		برو out;
	}
#ifdef DEBUG_SK
	fprintf(stderr, "%s: signed hash:\n", __func__);
	sshbuf_dump_data(sigb, len, stderr);
#endif
	/* Verify it */
	اگر (EVP_DigestVerifyInit(md_ctx, پوچ, EVP_sha256(), پوچ,
	    کلید->pkey) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		برو out;
	}
	انتخاب (EVP_DigestVerify(md_ctx, sigb, len,
	    sshbuf_ptr(original_signed), sshbuf_len(original_signed))) {
	حالت 1:
		ret = 0;
		بشکن;
	حالت 0:
		ret = SSH_ERR_SIGNATURE_INVALID;
		برو out;
	پیشفرض:
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		برو out;
	}
	/* success */
	اگر (detailsp != پوچ) {
		*detailsp = details;
		details = پوچ;
	}
 out:
	explicit_bzero(&sig_flags, اندازه(sig_flags));
	explicit_bzero(&sig_counter, اندازه(sig_counter));
	explicit_bzero(msghash, اندازه(msghash));
	explicit_bzero(apphash, اندازه(apphash));
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
	بازگشت ret;
}

ایستا ثابت ساختار sshkey_impl_funcs sshkey_ecdsa_sk_funcs = {
	/* .size = */		پوچ,
	/* .alloc = */		پوچ,
	/* .cleanup = */	ssh_ecdsa_sk_cleanup,
	/* .equal = */		ssh_ecdsa_sk_equal,
	/* .ssh_serialize_public = */ ssh_ecdsa_sk_serialize_public,
	/* .ssh_deserialize_public = */ ssh_ecdsa_sk_deserialize_public,
	/* .ssh_serialize_private = */ ssh_ecdsa_sk_serialize_private,
	/* .ssh_deserialize_private = */ ssh_ecdsa_sk_deserialize_private,
	/* .generate = */	پوچ,
	/* .copy_public = */	ssh_ecdsa_sk_copy_public,
	/* .sign = */		پوچ,
	/* .verify = */		ssh_ecdsa_sk_verify,
};

ثابت ساختار sshkey_impl sshkey_ecdsa_sk_impl = {
	/* .name = */		"sk-ecdsa-sha2-nistp256@openssh.com",
	/* .shortname = */	"ECDSA-SK",
	/* .sigalg = */		پوچ,
	/* .type = */		کلید_ECDSA_SK,
	/* .nid = */		NID_X9_62_prime256v1,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	256,
	/* .funcs = */		&sshkey_ecdsa_sk_funcs,
};

ثابت ساختار sshkey_impl sshkey_ecdsa_sk_cert_impl = {
	/* .name = */		"sk-ecdsa-sha2-nistp256-cert-v01@openssh.com",
	/* .shortname = */	"ECDSA-SK-CERT",
	/* .sigalg = */		پوچ,
	/* .type = */		کلید_ECDSA_SK_CERT,
	/* .nid = */		NID_X9_62_prime256v1,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	256,
	/* .funcs = */		&sshkey_ecdsa_sk_funcs,
};

ثابت ساختار sshkey_impl sshkey_ecdsa_sk_webauthn_impl = {
	/* .name = */		"webauthn-sk-ecdsa-sha2-nistp256@openssh.com",
	/* .shortname = */	"ECDSA-SK",
	/* .sigalg = */		پوچ,
	/* .type = */		کلید_ECDSA_SK,
	/* .nid = */		NID_X9_62_prime256v1,
	/* .cert = */		0,
	/* .sigonly = */	1,
	/* .keybits = */	256,
	/* .funcs = */		&sshkey_ecdsa_sk_funcs,
};

ثابت ساختار sshkey_impl sshkey_ecdsa_sk_webauthn_cert_impl = {
	/* .name = */		"webauthn-sk-ecdsa-sha2-nistp256-cert-v01@openssh.com",
	/* .shortname = */	"ECDSA-SK-CERT",
	/* .sigalg = */		پوچ,
	/* .type = */		کلید_ECDSA_SK_CERT,
	/* .nid = */		NID_X9_62_prime256v1,
	/* .cert = */		1,
	/* .sigonly = */	1,
	/* .keybits = */	256,
	/* .funcs = */		&sshkey_ecdsa_sk_funcs,
};
#endif /* WITH_OPENSSL */
