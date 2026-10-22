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

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ଅନ୍ତର୍ଭାଵ <sys/types.h>

#ifdef WITH_OPENSSL
#ଅନ୍ତର୍ଭାଵ "openbsd-compat/openssl-compat.h"
#ଅନ୍ତର୍ଭାଵ <openssl/bn.h>
#ଅନ୍ତର୍ଭାଵ <openssl/ec.h>
#ଅନ୍ତର୍ଭାଵ <openssl/ecdsa.h>
#ଅନ୍ତର୍ଭାଵ <openssl/evp.h>

#ଅନ୍ତର୍ଭାଵ <string.h>
#ଅନ୍ତର୍ଭାଵ <stdio.h> /* needed for DEBUG_SK only */

#ଅନ୍ତର୍ଭାଵ "sshbuf.h"
#ଅନ୍ତର୍ଭାଵ "ssherr.h"
#ଅନ୍ତର୍ଭାଵ "digest.h"
#define SSHKEY_INTERNAL
#ଅନ୍ତର୍ଭାଵ "sshkey.h"

/* Reuse some ECDSA internals */
ବାହ୍ୟ ସଂରଚନା sshkey_impl_funcs sshkey_ecdsa_funcs;

ସ୍ଥିର ଶୂନ୍ୟ
ssh_ecdsa_sk_cleanup(ସଂରଚନା sshkey *k)
{
	sshkey_sk_cleanup(k);
	sshkey_ecdsa_funcs.cleanup(k);
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_ecdsa_sk_equal(ଅଚଳ ସଂରଚନା sshkey *a, ଅଚଳ ସଂରଚନା sshkey *b)
{
	ଯଦି (!sshkey_sk_fields_equal(a, b))
		ଫେରନ୍ତୁ 0;
	ଯଦି (!sshkey_ecdsa_funcs.equal(a, b))
		ଫେରନ୍ତୁ 0;
	ଫେରନ୍ତୁ 1;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_ecdsa_sk_serialize_public(ଅଚଳ ସଂରଚନା sshkey *ଚାବି, ସଂରଚନା sshbuf *b,
    ଗଣନା sshkey_serialize_rep opts)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି ((r = sshkey_ecdsa_funcs.serialize_public(ଚାବି, b, opts)) != 0)
		ଫେରନ୍ତୁ r;
	ଯଦି ((r = sshkey_serialize_sk(ଚାବି, b)) != 0)
		ଫେରନ୍ତୁ r;

	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_ecdsa_sk_serialize_private(ଅଚଳ ସଂରଚନା sshkey *ଚାବି, ସଂରଚନା sshbuf *b,
    ଗଣନା sshkey_serialize_rep opts)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି (!sshkey_is_cert(ଚାବି)) {
		ଯଦି ((r = sshkey_ecdsa_funcs.serialize_public(ଚାବି,
		    b, opts)) != 0)
			ଫେରନ୍ତୁ r;
	}
	ଯଦି ((r = sshkey_serialize_private_sk(ଚାବି, b)) != 0)
		ଫେରନ୍ତୁ r;

	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_ecdsa_sk_copy_public(ଅଚଳ ସଂରଚନା sshkey *from, ସଂରଚନା sshkey *to)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି ((r = sshkey_ecdsa_funcs.copy_public(from, to)) != 0)
		ଫେରନ୍ତୁ r;
	ଯଦି ((r = sshkey_copy_public_sk(from, to)) != 0)
		ଫେରନ୍ତୁ r;
	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_ecdsa_sk_deserialize_public(ଅଚଳ ଅକ୍ଷର *ktype, ସଂରଚନା sshbuf *b,
    ସଂରଚନା sshkey *ଚାବି)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି ((r = sshkey_ecdsa_funcs.deserialize_public(ktype, b, ଚାବି)) != 0)
		ଫେରନ୍ତୁ r;
	ଯଦି ((r = sshkey_deserialize_sk(b, ଚାବି)) != 0)
		ଫେରନ୍ତୁ r;
	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_ecdsa_sk_deserialize_private(ଅଚଳ ଅକ୍ଷର *ktype, ସଂରଚନା sshbuf *b,
    ସଂରଚନା sshkey *ଚାବି)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି (!sshkey_is_cert(ଚାବି)) {
		ଯଦି ((r = sshkey_ecdsa_funcs.deserialize_public(ktype,
		    b, ଚାବି)) != 0)
			ଫେରନ୍ତୁ r;
	}
	ଯଦି ((r = sshkey_private_deserialize_sk(b, ଚାବି)) != 0)
		ଫେରନ୍ତୁ r;

	ଫେରନ୍ତୁ 0;
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
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
webauthn_check_prepare_hash(ଅଚଳ u_char *data, size_t datalen,
    ଅଚଳ ଅକ୍ଷର *origin, ଅଚଳ ସଂରଚନା sshbuf *wrapper,
    uint8_t flags, ଅଚଳ ସଂରଚନା sshbuf *extensions,
    u_char *msghash, size_t msghashlen)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r = SSH_ERR_INTERNAL_ERROR;
	ସଂରଚନା sshbuf *chall = ଖାଲି, *m = ଖାଲି;

	ଯଦି ((m = sshbuf_new()) == ଖାଲି ||
	    (chall = sshbuf_from(data, datalen)) == ଖାଲି) {
		r = SSH_ERR_ALLOC_FAIL;
		ଯାଅ out;
	}
	/*
	 * Ensure origin contains no quote character and that the flags are
	 * consistent with what we received
	 */
	ଯଦି (strchr(origin, '\"') != ଖାଲି ||
	    (flags & 0x40) != 0 /* AD */ ||
	    ((flags & 0x80) == 0 /* ED */) != (sshbuf_len(extensions) == 0)) {
		r = SSH_ERR_INVALID_FORMAT;
		ଯାଅ out;
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
	ଯଦି ((r = sshbuf_put(m, WEBAUTHN_0, ଆକାର(WEBAUTHN_0) - 1)) != 0 ||
	    (r = sshbuf_dtourlb64(chall, m, 0)) != 0 ||
	    (r = sshbuf_put(m, WEBAUTHN_1, ଆକାର(WEBAUTHN_1) - 1)) != 0 ||
	    (r = sshbuf_put(m, origin, strlen(origin))) != 0 ||
	    (r = sshbuf_put(m, WEBAUTHN_2, ଆକାର(WEBAUTHN_2) - 1)) != 0)
		ଯାଅ out;
#ifdef DEBUG_SK
	fprintf(stderr, "%s: received origin: %s\n", __func__, origin);
	fprintf(stderr, "%s: received clientData:\n", __func__);
	sshbuf_dump(wrapper, stderr);
	fprintf(stderr, "%s: expected clientData preamble:\n", __func__);
	sshbuf_dump(m, stderr);
#endif
	/* Check that the supplied clientData has the preamble we expect */
	ଯଦି ((r = sshbuf_cmp(wrapper, 0, sshbuf_ptr(m), sshbuf_len(m))) != 0)
		ଯାଅ out;

	/* Prepare hash of clientData */
	ଯଦି ((r = ssh_digest_buffer(SSH_DIGEST_SHA256, wrapper,
	    msghash, msghashlen)) != 0)
		ଯାଅ out;

	/* success */
	r = 0;
 out:
	sshbuf_free(chall);
	sshbuf_free(m);
	ଫେରନ୍ତୁ r;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_ecdsa_sk_verify(ଅଚଳ ସଂରଚନା sshkey *ଚାବି,
    ଅଚଳ u_char *sig, size_t siglen,
    ଅଚଳ u_char *data, size_t dlen, ଅଚଳ ଅକ୍ଷର *alg, u_int compat,
    ସଂରଚନା sshkey_sig_details **detailsp)
{
	ECDSA_SIG *esig = ଖାଲି;
	EVP_MD_CTX *md_ctx = ଖାଲି;
	BIGNUM *sig_r = ଖାଲି, *sig_s = ଖାଲି;
	u_char sig_flags;
	u_char msghash[32], apphash[32];
	u_int sig_counter;
	u_char *sigb = ଖାଲି, *cp;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା is_webauthn = 0, ret = SSH_ERR_INTERNAL_ERROR, len = 0;
	ସଂରଚନା sshbuf *b = ଖାଲି, *sigbuf = ଖାଲି, *original_signed = ଖାଲି;
	ସଂରଚନା sshbuf *webauthn_wrapper = ଖାଲି, *webauthn_exts = ଖାଲି;
	ଅକ୍ଷର *ktype = ଖାଲି, *webauthn_origin = ଖାଲି;
	ସଂରଚନା sshkey_sig_details *details = ଖାଲି;
#ifdef DEBUG_SK
	ଅକ୍ଷର *tmp = ଖାଲି;
#endif

	ଯଦି (detailsp != ଖାଲି)
		*detailsp = ଖାଲି;
	ଯଦି (ଚାବି == ଖାଲି || ଚାବି->pkey == ଖାଲି ||
	    sshkey_type_plain(ଚାବି->type) != ଚାବି_ECDSA_SK ||
	    sig == ଖାଲି || siglen == 0)
		ଫେରନ୍ତୁ SSH_ERR_INVALID_ARGUMENT;

	ଯଦି (ଚାବି->ecdsa_nid != NID_X9_62_prime256v1)
		ଫେରନ୍ତୁ SSH_ERR_INTERNAL_ERROR;

	/* fetch signature */
	ଯଦି ((b = sshbuf_from(sig, siglen)) == ଖାଲି)
		ଫେରନ୍ତୁ SSH_ERR_ALLOC_FAIL;
	ଯଦି ((details = calloc(1, ଆକାର(*details))) == ଖାଲି) {
		ret = SSH_ERR_ALLOC_FAIL;
		ଯାଅ out;
	}
	ଯଦି (sshbuf_get_cstring(b, &ktype, ଖାଲି) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		ଯାଅ out;
	}
	ଯଦି (strcmp(ktype, "webauthn-sk-ecdsa-sha2-nistp256@openssh.com") == 0 ||
	    strcmp(ktype, "webauthn-sk-ecdsa-sha2-nistp256-cert-v01@openssh.com")
	      == 0)
		is_webauthn = 1;
	ଅନ୍ୟଥା ଯଦି (strcmp(ktype, "sk-ecdsa-sha2-nistp256@openssh.com") != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		ଯାଅ out;
	}
	ଯଦି (sshbuf_froms(b, &sigbuf) != 0 ||
	    sshbuf_get_u8(b, &sig_flags) != 0 ||
	    sshbuf_get_u32(b, &sig_counter) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		ଯାଅ out;
	}
	ଯଦି (is_webauthn) {
		ଯଦି (sshbuf_get_cstring(b, &webauthn_origin, ଖାଲି) != 0 ||
		    sshbuf_froms(b, &webauthn_wrapper) != 0 ||
		    sshbuf_froms(b, &webauthn_exts) != 0) {
			ret = SSH_ERR_INVALID_FORMAT;
			ଯାଅ out;
		}
	}
	ଯଦି (sshbuf_len(b) != 0) {
		ret = SSH_ERR_UNEXPECTED_TRAILING_DATA;
		ଯାଅ out;
	}

	/* parse signature */
	ଯଦି (sshbuf_get_bignum2(sigbuf, &sig_r) != 0 ||
	    sshbuf_get_bignum2(sigbuf, &sig_s) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		ଯାଅ out;
	}
	ଯଦି (sshbuf_len(sigbuf) != 0) {
		ret = SSH_ERR_UNEXPECTED_TRAILING_DATA;
		ଯାଅ out;
	}

#ifdef DEBUG_SK
	fprintf(stderr, "%s: data: (len %zu)\n", __func__, dlen);
	/* sshbuf_dump_data(data, datalen, stderr); */
	fprintf(stderr, "%s: sig_r: %s\n", __func__, (tmp = BN_bn2hex(sig_r)));
	ମୁକ୍ତ(tmp);
	fprintf(stderr, "%s: sig_s: %s\n", __func__, (tmp = BN_bn2hex(sig_s)));
	ମୁକ୍ତ(tmp);
	fprintf(stderr, "%s: sig_flags = 0x%02x, sig_counter = %u\n",
	    __func__, sig_flags, sig_counter);
	ଯଦି (is_webauthn) {
		fprintf(stderr, "%s: webauthn origin: %s\n", __func__,
		    webauthn_origin);
		fprintf(stderr, "%s: webauthn_wrapper:\n", __func__);
		sshbuf_dump(webauthn_wrapper, stderr);
	}
#endif
	ଯଦି ((esig = ECDSA_SIG_new()) == ଖାଲି) {
		ret = SSH_ERR_ALLOC_FAIL;
		ଯାଅ out;
	}
	ଯଦି (!ECDSA_SIG_set0(esig, sig_r, sig_s)) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		ଯାଅ out;
	}
	sig_r = sig_s = ଖାଲି; /* transferred */

	/* Reconstruct data that was supposedly signed */
	ଯଦି ((original_signed = sshbuf_new()) == ଖାଲି) {
		ret = SSH_ERR_ALLOC_FAIL;
		ଯାଅ out;
	}
	ଯଦି (is_webauthn) {
		ଯଦି ((ret = webauthn_check_prepare_hash(data, dlen,
		    webauthn_origin, webauthn_wrapper, sig_flags, webauthn_exts,
		    msghash, ଆକାର(msghash))) != 0)
			ଯାଅ out;
	} ଅନ୍ୟଥା ଯଦି ((ret = ssh_digest_memory(SSH_DIGEST_SHA256, data, dlen,
	    msghash, ଆକାର(msghash))) != 0)
		ଯାଅ out;
	/* Application value is hashed before signature */
	ଯଦି ((ret = ssh_digest_memory(SSH_DIGEST_SHA256, ଚାବି->sk_application,
	    strlen(ଚାବି->sk_application), apphash, ଆକାର(apphash))) != 0)
		ଯାଅ out;
#ifdef DEBUG_SK
	fprintf(stderr, "%s: hashed application:\n", __func__);
	sshbuf_dump_data(apphash, ଆକାର(apphash), stderr);
	fprintf(stderr, "%s: hashed message:\n", __func__);
	sshbuf_dump_data(msghash, ଆକାର(msghash), stderr);
#endif
	ଯଦି ((ret = sshbuf_put(original_signed,
	    apphash, ଆକାର(apphash))) != 0 ||
	    (ret = sshbuf_put_u8(original_signed, sig_flags)) != 0 ||
	    (ret = sshbuf_put_u32(original_signed, sig_counter)) != 0 ||
	    (ret = sshbuf_putb(original_signed, webauthn_exts)) != 0 ||
	    (ret = sshbuf_put(original_signed, msghash, ଆକାର(msghash))) != 0)
		ଯାଅ out;
	details->sk_counter = sig_counter;
	details->sk_flags = sig_flags;
#ifdef DEBUG_SK
	fprintf(stderr, "%s: signed buf:\n", __func__);
	sshbuf_dump(original_signed, stderr);
#endif

	ଯଦି ((md_ctx = EVP_MD_CTX_new()) == ଖାଲି) {
		ret = SSH_ERR_ALLOC_FAIL;
		ଯାଅ out;
	}
	ଯଦି ((len = i2d_ECDSA_SIG(esig, ଖାଲି)) <= 0) {
		len = 0;
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		ଯାଅ out;
	}
	ଯଦି ((sigb = calloc(1, len)) == ଖାଲି) {
		ret = SSH_ERR_ALLOC_FAIL;
		ଯାଅ out;
	}
	cp = sigb; /* ASN1_item_i2d increments the pointer past the object */
	ଯଦି (i2d_ECDSA_SIG(esig, &cp) != len) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		ଯାଅ out;
	}
#ifdef DEBUG_SK
	fprintf(stderr, "%s: signed hash:\n", __func__);
	sshbuf_dump_data(sigb, len, stderr);
#endif
	/* Verify it */
	ଯଦି (EVP_DigestVerifyInit(md_ctx, ଖାଲି, EVP_sha256(), ଖାଲି,
	    ଚାବି->pkey) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		ଯାଅ out;
	}
	ବାଛ (EVP_DigestVerify(md_ctx, sigb, len,
	    sshbuf_ptr(original_signed), sshbuf_len(original_signed))) {
	ସ୍ଥିତି 1:
		ret = 0;
		ଭାଙ୍ଗ;
	ସ୍ଥିତି 0:
		ret = SSH_ERR_SIGNATURE_INVALID;
		ଯାଅ out;
	ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		ଯାଅ out;
	}
	/* success */
	ଯଦି (detailsp != ଖାଲି) {
		*detailsp = details;
		details = ଖାଲି;
	}
 out:
	explicit_bzero(&sig_flags, ଆକାର(sig_flags));
	explicit_bzero(&sig_counter, ଆକାର(sig_counter));
	explicit_bzero(msghash, ଆକାର(msghash));
	explicit_bzero(apphash, ଆକାର(apphash));
	sshkey_sig_details_free(details);
	sshbuf_free(webauthn_wrapper);
	sshbuf_free(webauthn_exts);
	ମୁକ୍ତ(webauthn_origin);
	sshbuf_free(original_signed);
	sshbuf_free(sigbuf);
	sshbuf_free(b);
	ECDSA_SIG_free(esig);
	BN_clear_free(sig_r);
	BN_clear_free(sig_s);
	ମୁକ୍ତ(ktype);
	freezero(sigb, len);
	EVP_MD_CTX_free(md_ctx);
	ଫେରନ୍ତୁ ret;
}

ସ୍ଥିର ଅଚଳ ସଂରଚନା sshkey_impl_funcs sshkey_ecdsa_sk_funcs = {
	/* .size = */		ଖାଲି,
	/* .alloc = */		ଖାଲି,
	/* .cleanup = */	ssh_ecdsa_sk_cleanup,
	/* .equal = */		ssh_ecdsa_sk_equal,
	/* .ssh_serialize_public = */ ssh_ecdsa_sk_serialize_public,
	/* .ssh_deserialize_public = */ ssh_ecdsa_sk_deserialize_public,
	/* .ssh_serialize_private = */ ssh_ecdsa_sk_serialize_private,
	/* .ssh_deserialize_private = */ ssh_ecdsa_sk_deserialize_private,
	/* .generate = */	ଖାଲି,
	/* .copy_public = */	ssh_ecdsa_sk_copy_public,
	/* .sign = */		ଖାଲି,
	/* .verify = */		ssh_ecdsa_sk_verify,
};

ଅଚଳ ସଂରଚନା sshkey_impl sshkey_ecdsa_sk_impl = {
	/* .name = */		"sk-ecdsa-sha2-nistp256@openssh.com",
	/* .shortname = */	"ECDSA-SK",
	/* .sigalg = */		ଖାଲି,
	/* .type = */		ଚାବି_ECDSA_SK,
	/* .nid = */		NID_X9_62_prime256v1,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	256,
	/* .funcs = */		&sshkey_ecdsa_sk_funcs,
};

ଅଚଳ ସଂରଚନା sshkey_impl sshkey_ecdsa_sk_cert_impl = {
	/* .name = */		"sk-ecdsa-sha2-nistp256-cert-v01@openssh.com",
	/* .shortname = */	"ECDSA-SK-CERT",
	/* .sigalg = */		ଖାଲି,
	/* .type = */		ଚାବି_ECDSA_SK_CERT,
	/* .nid = */		NID_X9_62_prime256v1,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	256,
	/* .funcs = */		&sshkey_ecdsa_sk_funcs,
};

ଅଚଳ ସଂରଚନା sshkey_impl sshkey_ecdsa_sk_webauthn_impl = {
	/* .name = */		"webauthn-sk-ecdsa-sha2-nistp256@openssh.com",
	/* .shortname = */	"ECDSA-SK",
	/* .sigalg = */		ଖାଲି,
	/* .type = */		ଚାବି_ECDSA_SK,
	/* .nid = */		NID_X9_62_prime256v1,
	/* .cert = */		0,
	/* .sigonly = */	1,
	/* .keybits = */	256,
	/* .funcs = */		&sshkey_ecdsa_sk_funcs,
};

ଅଚଳ ସଂରଚନା sshkey_impl sshkey_ecdsa_sk_webauthn_cert_impl = {
	/* .name = */		"webauthn-sk-ecdsa-sha2-nistp256-cert-v01@openssh.com",
	/* .shortname = */	"ECDSA-SK-CERT",
	/* .sigalg = */		ଖାଲି,
	/* .type = */		ଚାବି_ECDSA_SK_CERT,
	/* .nid = */		NID_X9_62_prime256v1,
	/* .cert = */		1,
	/* .sigonly = */	1,
	/* .keybits = */	256,
	/* .funcs = */		&sshkey_ecdsa_sk_funcs,
};
#endif /* WITH_OPENSSL */
