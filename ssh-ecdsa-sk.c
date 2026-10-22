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

#অন্তর্ভাৱ "includes.h"

#অন্তর্ভাৱ <sys/types.h>

#ifdef WITH_OPENSSL
#অন্তর্ভাৱ "openbsd-compat/openssl-compat.h"
#অন্তর্ভাৱ <openssl/bn.h>
#অন্তর্ভাৱ <openssl/ec.h>
#অন্তর্ভাৱ <openssl/ecdsa.h>
#অন্তর্ভাৱ <openssl/evp.h>

#অন্তর্ভাৱ <string.h>
#অন্তর্ভাৱ <stdio.h> /* needed for DEBUG_SK only */

#অন্তর্ভাৱ "sshbuf.h"
#অন্তর্ভাৱ "ssherr.h"
#অন্তর্ভাৱ "digest.h"
#define SSHKEY_INTERNAL
#অন্তর্ভাৱ "sshkey.h"

/* Reuse some ECDSA internals */
বাহ্য সংরচনা sshkey_impl_funcs sshkey_ecdsa_funcs;

স্থির শূন্য
ssh_ecdsa_sk_cleanup(সংরচনা sshkey *k)
{
	sshkey_sk_cleanup(k);
	sshkey_ecdsa_funcs.cleanup(k);
}

স্থির পূর্ণাঙ্ক
ssh_ecdsa_sk_equal(ধ্রুৱ সংরচনা sshkey *a, ধ্রুৱ সংরচনা sshkey *b)
{
	যদি (!sshkey_sk_fields_equal(a, b))
		ঘূৰাই 0;
	যদি (!sshkey_ecdsa_funcs.equal(a, b))
		ঘূৰাই 0;
	ঘূৰাই 1;
}

স্থির পূর্ণাঙ্ক
ssh_ecdsa_sk_serialize_public(ধ্রুৱ সংরচনা sshkey *চাবি, সংরচনা sshbuf *b,
    গণনা sshkey_serialize_rep opts)
{
	পূর্ণাঙ্ক r;

	যদি ((r = sshkey_ecdsa_funcs.serialize_public(চাবি, b, opts)) != 0)
		ঘূৰাই r;
	যদি ((r = sshkey_serialize_sk(চাবি, b)) != 0)
		ঘূৰাই r;

	ঘূৰাই 0;
}

স্থির পূর্ণাঙ্ক
ssh_ecdsa_sk_serialize_private(ধ্রুৱ সংরচনা sshkey *চাবি, সংরচনা sshbuf *b,
    গণনা sshkey_serialize_rep opts)
{
	পূর্ণাঙ্ক r;

	যদি (!sshkey_is_cert(চাবি)) {
		যদি ((r = sshkey_ecdsa_funcs.serialize_public(চাবি,
		    b, opts)) != 0)
			ঘূৰাই r;
	}
	যদি ((r = sshkey_serialize_private_sk(চাবি, b)) != 0)
		ঘূৰাই r;

	ঘূৰাই 0;
}

স্থির পূর্ণাঙ্ক
ssh_ecdsa_sk_copy_public(ধ্রুৱ সংরচনা sshkey *from, সংরচনা sshkey *to)
{
	পূর্ণাঙ্ক r;

	যদি ((r = sshkey_ecdsa_funcs.copy_public(from, to)) != 0)
		ঘূৰাই r;
	যদি ((r = sshkey_copy_public_sk(from, to)) != 0)
		ঘূৰাই r;
	ঘূৰাই 0;
}

স্থির পূর্ণাঙ্ক
ssh_ecdsa_sk_deserialize_public(ধ্রুৱ ৱর্ণ *ktype, সংরচনা sshbuf *b,
    সংরচনা sshkey *চাবি)
{
	পূর্ণাঙ্ক r;

	যদি ((r = sshkey_ecdsa_funcs.deserialize_public(ktype, b, চাবি)) != 0)
		ঘূৰাই r;
	যদি ((r = sshkey_deserialize_sk(b, চাবি)) != 0)
		ঘূৰাই r;
	ঘূৰাই 0;
}

স্থির পূর্ণাঙ্ক
ssh_ecdsa_sk_deserialize_private(ধ্রুৱ ৱর্ণ *ktype, সংরচনা sshbuf *b,
    সংরচনা sshkey *চাবি)
{
	পূর্ণাঙ্ক r;

	যদি (!sshkey_is_cert(চাবি)) {
		যদি ((r = sshkey_ecdsa_funcs.deserialize_public(ktype,
		    b, চাবি)) != 0)
			ঘূৰাই r;
	}
	যদি ((r = sshkey_private_deserialize_sk(b, চাবি)) != 0)
		ঘূৰাই r;

	ঘূৰাই 0;
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
স্থির পূর্ণাঙ্ক
webauthn_check_prepare_hash(ধ্রুৱ u_char *data, size_t datalen,
    ধ্রুৱ ৱর্ণ *origin, ধ্রুৱ সংরচনা sshbuf *wrapper,
    uint8_t flags, ধ্রুৱ সংরচনা sshbuf *extensions,
    u_char *msghash, size_t msghashlen)
{
	পূর্ণাঙ্ক r = SSH_ERR_INTERNAL_ERROR;
	সংরচনা sshbuf *chall = রিক্ত, *m = রিক্ত;

	যদি ((m = sshbuf_new()) == রিক্ত ||
	    (chall = sshbuf_from(data, datalen)) == রিক্ত) {
		r = SSH_ERR_ALLOC_FAIL;
		গচ্ছ out;
	}
	/*
	 * Ensure origin contains no quote character and that the flags are
	 * consistent with what we received
	 */
	যদি (strchr(origin, '\"') != রিক্ত ||
	    (flags & 0x40) != 0 /* AD */ ||
	    ((flags & 0x80) == 0 /* ED */) != (sshbuf_len(extensions) == 0)) {
		r = SSH_ERR_INVALID_FORMAT;
		গচ্ছ out;
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
	যদি ((r = sshbuf_put(m, WEBAUTHN_0, পরিমাণ(WEBAUTHN_0) - 1)) != 0 ||
	    (r = sshbuf_dtourlb64(chall, m, 0)) != 0 ||
	    (r = sshbuf_put(m, WEBAUTHN_1, পরিমাণ(WEBAUTHN_1) - 1)) != 0 ||
	    (r = sshbuf_put(m, origin, strlen(origin))) != 0 ||
	    (r = sshbuf_put(m, WEBAUTHN_2, পরিমাণ(WEBAUTHN_2) - 1)) != 0)
		গচ্ছ out;
#ifdef DEBUG_SK
	fprintf(stderr, "%s: received origin: %s\n", __func__, origin);
	fprintf(stderr, "%s: received clientData:\n", __func__);
	sshbuf_dump(wrapper, stderr);
	fprintf(stderr, "%s: expected clientData preamble:\n", __func__);
	sshbuf_dump(m, stderr);
#endif
	/* Check that the supplied clientData has the preamble we expect */
	যদি ((r = sshbuf_cmp(wrapper, 0, sshbuf_ptr(m), sshbuf_len(m))) != 0)
		গচ্ছ out;

	/* Prepare hash of clientData */
	যদি ((r = ssh_digest_buffer(SSH_DIGEST_SHA256, wrapper,
	    msghash, msghashlen)) != 0)
		গচ্ছ out;

	/* success */
	r = 0;
 out:
	sshbuf_free(chall);
	sshbuf_free(m);
	ঘূৰাই r;
}

স্থির পূর্ণাঙ্ক
ssh_ecdsa_sk_verify(ধ্রুৱ সংরচনা sshkey *চাবি,
    ধ্রুৱ u_char *sig, size_t siglen,
    ধ্রুৱ u_char *data, size_t dlen, ধ্রুৱ ৱর্ণ *alg, u_int compat,
    সংরচনা sshkey_sig_details **detailsp)
{
	ECDSA_SIG *esig = রিক্ত;
	EVP_MD_CTX *md_ctx = রিক্ত;
	BIGNUM *sig_r = রিক্ত, *sig_s = রিক্ত;
	u_char sig_flags;
	u_char msghash[32], apphash[32];
	u_int sig_counter;
	u_char *sigb = রিক্ত, *cp;
	পূর্ণাঙ্ক is_webauthn = 0, ret = SSH_ERR_INTERNAL_ERROR, len = 0;
	সংরচনা sshbuf *b = রিক্ত, *sigbuf = রিক্ত, *original_signed = রিক্ত;
	সংরচনা sshbuf *webauthn_wrapper = রিক্ত, *webauthn_exts = রিক্ত;
	ৱর্ণ *ktype = রিক্ত, *webauthn_origin = রিক্ত;
	সংরচনা sshkey_sig_details *details = রিক্ত;
#ifdef DEBUG_SK
	ৱর্ণ *tmp = রিক্ত;
#endif

	যদি (detailsp != রিক্ত)
		*detailsp = রিক্ত;
	যদি (চাবি == রিক্ত || চাবি->pkey == রিক্ত ||
	    sshkey_type_plain(চাবি->type) != চাবি_ECDSA_SK ||
	    sig == রিক্ত || siglen == 0)
		ঘূৰাই SSH_ERR_INVALID_ARGUMENT;

	যদি (চাবি->ecdsa_nid != NID_X9_62_prime256v1)
		ঘূৰাই SSH_ERR_INTERNAL_ERROR;

	/* fetch signature */
	যদি ((b = sshbuf_from(sig, siglen)) == রিক্ত)
		ঘূৰাই SSH_ERR_ALLOC_FAIL;
	যদি ((details = calloc(1, পরিমাণ(*details))) == রিক্ত) {
		ret = SSH_ERR_ALLOC_FAIL;
		গচ্ছ out;
	}
	যদি (sshbuf_get_cstring(b, &ktype, রিক্ত) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		গচ্ছ out;
	}
	যদি (strcmp(ktype, "webauthn-sk-ecdsa-sha2-nistp256@openssh.com") == 0 ||
	    strcmp(ktype, "webauthn-sk-ecdsa-sha2-nistp256-cert-v01@openssh.com")
	      == 0)
		is_webauthn = 1;
	অন্যথা যদি (strcmp(ktype, "sk-ecdsa-sha2-nistp256@openssh.com") != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		গচ্ছ out;
	}
	যদি (sshbuf_froms(b, &sigbuf) != 0 ||
	    sshbuf_get_u8(b, &sig_flags) != 0 ||
	    sshbuf_get_u32(b, &sig_counter) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		গচ্ছ out;
	}
	যদি (is_webauthn) {
		যদি (sshbuf_get_cstring(b, &webauthn_origin, রিক্ত) != 0 ||
		    sshbuf_froms(b, &webauthn_wrapper) != 0 ||
		    sshbuf_froms(b, &webauthn_exts) != 0) {
			ret = SSH_ERR_INVALID_FORMAT;
			গচ্ছ out;
		}
	}
	যদি (sshbuf_len(b) != 0) {
		ret = SSH_ERR_UNEXPECTED_TRAILING_DATA;
		গচ্ছ out;
	}

	/* parse signature */
	যদি (sshbuf_get_bignum2(sigbuf, &sig_r) != 0 ||
	    sshbuf_get_bignum2(sigbuf, &sig_s) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		গচ্ছ out;
	}
	যদি (sshbuf_len(sigbuf) != 0) {
		ret = SSH_ERR_UNEXPECTED_TRAILING_DATA;
		গচ্ছ out;
	}

#ifdef DEBUG_SK
	fprintf(stderr, "%s: data: (len %zu)\n", __func__, dlen);
	/* sshbuf_dump_data(data, datalen, stderr); */
	fprintf(stderr, "%s: sig_r: %s\n", __func__, (tmp = BN_bn2hex(sig_r)));
	মুক্ত(tmp);
	fprintf(stderr, "%s: sig_s: %s\n", __func__, (tmp = BN_bn2hex(sig_s)));
	মুক্ত(tmp);
	fprintf(stderr, "%s: sig_flags = 0x%02x, sig_counter = %u\n",
	    __func__, sig_flags, sig_counter);
	যদি (is_webauthn) {
		fprintf(stderr, "%s: webauthn origin: %s\n", __func__,
		    webauthn_origin);
		fprintf(stderr, "%s: webauthn_wrapper:\n", __func__);
		sshbuf_dump(webauthn_wrapper, stderr);
	}
#endif
	যদি ((esig = ECDSA_SIG_new()) == রিক্ত) {
		ret = SSH_ERR_ALLOC_FAIL;
		গচ্ছ out;
	}
	যদি (!ECDSA_SIG_set0(esig, sig_r, sig_s)) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		গচ্ছ out;
	}
	sig_r = sig_s = রিক্ত; /* transferred */

	/* Reconstruct data that was supposedly signed */
	যদি ((original_signed = sshbuf_new()) == রিক্ত) {
		ret = SSH_ERR_ALLOC_FAIL;
		গচ্ছ out;
	}
	যদি (is_webauthn) {
		যদি ((ret = webauthn_check_prepare_hash(data, dlen,
		    webauthn_origin, webauthn_wrapper, sig_flags, webauthn_exts,
		    msghash, পরিমাণ(msghash))) != 0)
			গচ্ছ out;
	} অন্যথা যদি ((ret = ssh_digest_memory(SSH_DIGEST_SHA256, data, dlen,
	    msghash, পরিমাণ(msghash))) != 0)
		গচ্ছ out;
	/* Application value is hashed before signature */
	যদি ((ret = ssh_digest_memory(SSH_DIGEST_SHA256, চাবি->sk_application,
	    strlen(চাবি->sk_application), apphash, পরিমাণ(apphash))) != 0)
		গচ্ছ out;
#ifdef DEBUG_SK
	fprintf(stderr, "%s: hashed application:\n", __func__);
	sshbuf_dump_data(apphash, পরিমাণ(apphash), stderr);
	fprintf(stderr, "%s: hashed message:\n", __func__);
	sshbuf_dump_data(msghash, পরিমাণ(msghash), stderr);
#endif
	যদি ((ret = sshbuf_put(original_signed,
	    apphash, পরিমাণ(apphash))) != 0 ||
	    (ret = sshbuf_put_u8(original_signed, sig_flags)) != 0 ||
	    (ret = sshbuf_put_u32(original_signed, sig_counter)) != 0 ||
	    (ret = sshbuf_putb(original_signed, webauthn_exts)) != 0 ||
	    (ret = sshbuf_put(original_signed, msghash, পরিমাণ(msghash))) != 0)
		গচ্ছ out;
	details->sk_counter = sig_counter;
	details->sk_flags = sig_flags;
#ifdef DEBUG_SK
	fprintf(stderr, "%s: signed buf:\n", __func__);
	sshbuf_dump(original_signed, stderr);
#endif

	যদি ((md_ctx = EVP_MD_CTX_new()) == রিক্ত) {
		ret = SSH_ERR_ALLOC_FAIL;
		গচ্ছ out;
	}
	যদি ((len = i2d_ECDSA_SIG(esig, রিক্ত)) <= 0) {
		len = 0;
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		গচ্ছ out;
	}
	যদি ((sigb = calloc(1, len)) == রিক্ত) {
		ret = SSH_ERR_ALLOC_FAIL;
		গচ্ছ out;
	}
	cp = sigb; /* ASN1_item_i2d increments the pointer past the object */
	যদি (i2d_ECDSA_SIG(esig, &cp) != len) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		গচ্ছ out;
	}
#ifdef DEBUG_SK
	fprintf(stderr, "%s: signed hash:\n", __func__);
	sshbuf_dump_data(sigb, len, stderr);
#endif
	/* Verify it */
	যদি (EVP_DigestVerifyInit(md_ctx, রিক্ত, EVP_sha256(), রিক্ত,
	    চাবি->pkey) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		গচ্ছ out;
	}
	ৱিকল্প (EVP_DigestVerify(md_ctx, sigb, len,
	    sshbuf_ptr(original_signed), sshbuf_len(original_signed))) {
	পক্ষ 1:
		ret = 0;
		ভঙ্গ;
	পক্ষ 0:
		ret = SSH_ERR_SIGNATURE_INVALID;
		গচ্ছ out;
	স্ৱভাৱ:
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		গচ্ছ out;
	}
	/* success */
	যদি (detailsp != রিক্ত) {
		*detailsp = details;
		details = রিক্ত;
	}
 out:
	explicit_bzero(&sig_flags, পরিমাণ(sig_flags));
	explicit_bzero(&sig_counter, পরিমাণ(sig_counter));
	explicit_bzero(msghash, পরিমাণ(msghash));
	explicit_bzero(apphash, পরিমাণ(apphash));
	sshkey_sig_details_free(details);
	sshbuf_free(webauthn_wrapper);
	sshbuf_free(webauthn_exts);
	মুক্ত(webauthn_origin);
	sshbuf_free(original_signed);
	sshbuf_free(sigbuf);
	sshbuf_free(b);
	ECDSA_SIG_free(esig);
	BN_clear_free(sig_r);
	BN_clear_free(sig_s);
	মুক্ত(ktype);
	freezero(sigb, len);
	EVP_MD_CTX_free(md_ctx);
	ঘূৰাই ret;
}

স্থির ধ্রুৱ সংরচনা sshkey_impl_funcs sshkey_ecdsa_sk_funcs = {
	/* .size = */		রিক্ত,
	/* .alloc = */		রিক্ত,
	/* .cleanup = */	ssh_ecdsa_sk_cleanup,
	/* .equal = */		ssh_ecdsa_sk_equal,
	/* .ssh_serialize_public = */ ssh_ecdsa_sk_serialize_public,
	/* .ssh_deserialize_public = */ ssh_ecdsa_sk_deserialize_public,
	/* .ssh_serialize_private = */ ssh_ecdsa_sk_serialize_private,
	/* .ssh_deserialize_private = */ ssh_ecdsa_sk_deserialize_private,
	/* .generate = */	রিক্ত,
	/* .copy_public = */	ssh_ecdsa_sk_copy_public,
	/* .sign = */		রিক্ত,
	/* .verify = */		ssh_ecdsa_sk_verify,
};

ধ্রুৱ সংরচনা sshkey_impl sshkey_ecdsa_sk_impl = {
	/* .name = */		"sk-ecdsa-sha2-nistp256@openssh.com",
	/* .shortname = */	"ECDSA-SK",
	/* .sigalg = */		রিক্ত,
	/* .type = */		চাবি_ECDSA_SK,
	/* .nid = */		NID_X9_62_prime256v1,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	256,
	/* .funcs = */		&sshkey_ecdsa_sk_funcs,
};

ধ্রুৱ সংরচনা sshkey_impl sshkey_ecdsa_sk_cert_impl = {
	/* .name = */		"sk-ecdsa-sha2-nistp256-cert-v01@openssh.com",
	/* .shortname = */	"ECDSA-SK-CERT",
	/* .sigalg = */		রিক্ত,
	/* .type = */		চাবি_ECDSA_SK_CERT,
	/* .nid = */		NID_X9_62_prime256v1,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	256,
	/* .funcs = */		&sshkey_ecdsa_sk_funcs,
};

ধ্রুৱ সংরচনা sshkey_impl sshkey_ecdsa_sk_webauthn_impl = {
	/* .name = */		"webauthn-sk-ecdsa-sha2-nistp256@openssh.com",
	/* .shortname = */	"ECDSA-SK",
	/* .sigalg = */		রিক্ত,
	/* .type = */		চাবি_ECDSA_SK,
	/* .nid = */		NID_X9_62_prime256v1,
	/* .cert = */		0,
	/* .sigonly = */	1,
	/* .keybits = */	256,
	/* .funcs = */		&sshkey_ecdsa_sk_funcs,
};

ধ্রুৱ সংরচনা sshkey_impl sshkey_ecdsa_sk_webauthn_cert_impl = {
	/* .name = */		"webauthn-sk-ecdsa-sha2-nistp256-cert-v01@openssh.com",
	/* .shortname = */	"ECDSA-SK-CERT",
	/* .sigalg = */		রিক্ত,
	/* .type = */		চাবি_ECDSA_SK_CERT,
	/* .nid = */		NID_X9_62_prime256v1,
	/* .cert = */		1,
	/* .sigonly = */	1,
	/* .keybits = */	256,
	/* .funcs = */		&sshkey_ecdsa_sk_funcs,
};
#endif /* WITH_OPENSSL */
