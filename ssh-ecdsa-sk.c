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

#അന്തര്ഭാവ "includes.h"

#അന്തര്ഭാവ <sys/types.h>

#ifdef WITH_OPENSSL
#അന്തര്ഭാവ "openbsd-compat/openssl-compat.h"
#അന്തര്ഭാവ <openssl/bn.h>
#അന്തര്ഭാവ <openssl/ec.h>
#അന്തര്ഭാവ <openssl/ecdsa.h>
#അന്തര്ഭാവ <openssl/evp.h>

#അന്തര്ഭാവ <string.h>
#അന്തര്ഭാവ <stdio.h> /* needed for DEBUG_SK only */

#അന്തര്ഭാവ "sshbuf.h"
#അന്തര്ഭാവ "ssherr.h"
#അന്തര്ഭാവ "digest.h"
#define SSHKEY_INTERNAL
#അന്തര്ഭാവ "sshkey.h"

/* Reuse some ECDSA internals */
ബാഹ്യ ഘടന sshkey_impl_funcs sshkey_ecdsa_funcs;

സ്ഥിതം ശൂന്യം
ssh_ecdsa_sk_cleanup(ഘടന sshkey *k)
{
	sshkey_sk_cleanup(k);
	sshkey_ecdsa_funcs.cleanup(k);
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
ssh_ecdsa_sk_equal(സ്ഥിരം ഘടന sshkey *a, സ്ഥിരം ഘടന sshkey *b)
{
	എങ്കിൽ (!sshkey_sk_fields_equal(a, b))
		തിരികെ 0;
	എങ്കിൽ (!sshkey_ecdsa_funcs.equal(a, b))
		തിരികെ 0;
	തിരികെ 1;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
ssh_ecdsa_sk_serialize_public(സ്ഥിരം ഘടന sshkey *താക്കോൽ, ഘടന sshbuf *b,
    എണ്ണൽ sshkey_serialize_rep opts)
{
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ ((r = sshkey_ecdsa_funcs.serialize_public(താക്കോൽ, b, opts)) != 0)
		തിരികെ r;
	എങ്കിൽ ((r = sshkey_serialize_sk(താക്കോൽ, b)) != 0)
		തിരികെ r;

	തിരികെ 0;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
ssh_ecdsa_sk_serialize_private(സ്ഥിരം ഘടന sshkey *താക്കോൽ, ഘടന sshbuf *b,
    എണ്ണൽ sshkey_serialize_rep opts)
{
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ (!sshkey_is_cert(താക്കോൽ)) {
		എങ്കിൽ ((r = sshkey_ecdsa_funcs.serialize_public(താക്കോൽ,
		    b, opts)) != 0)
			തിരികെ r;
	}
	എങ്കിൽ ((r = sshkey_serialize_private_sk(താക്കോൽ, b)) != 0)
		തിരികെ r;

	തിരികെ 0;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
ssh_ecdsa_sk_copy_public(സ്ഥിരം ഘടന sshkey *from, ഘടന sshkey *to)
{
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ ((r = sshkey_ecdsa_funcs.copy_public(from, to)) != 0)
		തിരികെ r;
	എങ്കിൽ ((r = sshkey_copy_public_sk(from, to)) != 0)
		തിരികെ r;
	തിരികെ 0;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
ssh_ecdsa_sk_deserialize_public(സ്ഥിരം അക്ഷരം *ktype, ഘടന sshbuf *b,
    ഘടന sshkey *താക്കോൽ)
{
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ ((r = sshkey_ecdsa_funcs.deserialize_public(ktype, b, താക്കോൽ)) != 0)
		തിരികെ r;
	എങ്കിൽ ((r = sshkey_deserialize_sk(b, താക്കോൽ)) != 0)
		തിരികെ r;
	തിരികെ 0;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
ssh_ecdsa_sk_deserialize_private(സ്ഥിരം അക്ഷരം *ktype, ഘടന sshbuf *b,
    ഘടന sshkey *താക്കോൽ)
{
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ (!sshkey_is_cert(താക്കോൽ)) {
		എങ്കിൽ ((r = sshkey_ecdsa_funcs.deserialize_public(ktype,
		    b, താക്കോൽ)) != 0)
			തിരികെ r;
	}
	എങ്കിൽ ((r = sshkey_private_deserialize_sk(b, താക്കോൽ)) != 0)
		തിരികെ r;

	തിരികെ 0;
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
സ്ഥിതം പൂർണ്ണസംഖ്യ
webauthn_check_prepare_hash(സ്ഥിരം u_char *data, size_t datalen,
    സ്ഥിരം അക്ഷരം *origin, സ്ഥിരം ഘടന sshbuf *wrapper,
    uint8_t flags, സ്ഥിരം ഘടന sshbuf *extensions,
    u_char *msghash, size_t msghashlen)
{
	പൂർണ്ണസംഖ്യ r = SSH_ERR_INTERNAL_ERROR;
	ഘടന sshbuf *chall = ശൂന്യ, *m = ശൂന്യ;

	എങ്കിൽ ((m = sshbuf_new()) == ശൂന്യ ||
	    (chall = sshbuf_from(data, datalen)) == ശൂന്യ) {
		r = SSH_ERR_ALLOC_FAIL;
		പോകുക out;
	}
	/*
	 * Ensure origin contains no quote character and that the flags are
	 * consistent with what we received
	 */
	എങ്കിൽ (strchr(origin, '\"') != ശൂന്യ ||
	    (flags & 0x40) != 0 /* AD */ ||
	    ((flags & 0x80) == 0 /* ED */) != (sshbuf_len(extensions) == 0)) {
		r = SSH_ERR_INVALID_FORMAT;
		പോകുക out;
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
	എങ്കിൽ ((r = sshbuf_put(m, WEBAUTHN_0, വലുപ്പം(WEBAUTHN_0) - 1)) != 0 ||
	    (r = sshbuf_dtourlb64(chall, m, 0)) != 0 ||
	    (r = sshbuf_put(m, WEBAUTHN_1, വലുപ്പം(WEBAUTHN_1) - 1)) != 0 ||
	    (r = sshbuf_put(m, origin, strlen(origin))) != 0 ||
	    (r = sshbuf_put(m, WEBAUTHN_2, വലുപ്പം(WEBAUTHN_2) - 1)) != 0)
		പോകുക out;
#ifdef DEBUG_SK
	fprintf(stderr, "%s: received origin: %s\n", __func__, origin);
	fprintf(stderr, "%s: received clientData:\n", __func__);
	sshbuf_dump(wrapper, stderr);
	fprintf(stderr, "%s: expected clientData preamble:\n", __func__);
	sshbuf_dump(m, stderr);
#endif
	/* Check that the supplied clientData has the preamble we expect */
	എങ്കിൽ ((r = sshbuf_cmp(wrapper, 0, sshbuf_ptr(m), sshbuf_len(m))) != 0)
		പോകുക out;

	/* Prepare hash of clientData */
	എങ്കിൽ ((r = ssh_digest_buffer(SSH_DIGEST_SHA256, wrapper,
	    msghash, msghashlen)) != 0)
		പോകുക out;

	/* success */
	r = 0;
 out:
	sshbuf_free(chall);
	sshbuf_free(m);
	തിരികെ r;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
ssh_ecdsa_sk_verify(സ്ഥിരം ഘടന sshkey *താക്കോൽ,
    സ്ഥിരം u_char *sig, size_t siglen,
    സ്ഥിരം u_char *data, size_t dlen, സ്ഥിരം അക്ഷരം *alg, u_int compat,
    ഘടന sshkey_sig_details **detailsp)
{
	ECDSA_SIG *esig = ശൂന്യ;
	EVP_MD_CTX *md_ctx = ശൂന്യ;
	BIGNUM *sig_r = ശൂന്യ, *sig_s = ശൂന്യ;
	u_char sig_flags;
	u_char msghash[32], apphash[32];
	u_int sig_counter;
	u_char *sigb = ശൂന്യ, *cp;
	പൂർണ്ണസംഖ്യ is_webauthn = 0, ret = SSH_ERR_INTERNAL_ERROR, len = 0;
	ഘടന sshbuf *b = ശൂന്യ, *sigbuf = ശൂന്യ, *original_signed = ശൂന്യ;
	ഘടന sshbuf *webauthn_wrapper = ശൂന്യ, *webauthn_exts = ശൂന്യ;
	അക്ഷരം *ktype = ശൂന്യ, *webauthn_origin = ശൂന്യ;
	ഘടന sshkey_sig_details *details = ശൂന്യ;
#ifdef DEBUG_SK
	അക്ഷരം *tmp = ശൂന്യ;
#endif

	എങ്കിൽ (detailsp != ശൂന്യ)
		*detailsp = ശൂന്യ;
	എങ്കിൽ (താക്കോൽ == ശൂന്യ || താക്കോൽ->pkey == ശൂന്യ ||
	    sshkey_type_plain(താക്കോൽ->type) != താക്കോൽ_ECDSA_SK ||
	    sig == ശൂന്യ || siglen == 0)
		തിരികെ SSH_ERR_INVALID_ARGUMENT;

	എങ്കിൽ (താക്കോൽ->ecdsa_nid != NID_X9_62_prime256v1)
		തിരികെ SSH_ERR_INTERNAL_ERROR;

	/* fetch signature */
	എങ്കിൽ ((b = sshbuf_from(sig, siglen)) == ശൂന്യ)
		തിരികെ SSH_ERR_ALLOC_FAIL;
	എങ്കിൽ ((details = calloc(1, വലുപ്പം(*details))) == ശൂന്യ) {
		ret = SSH_ERR_ALLOC_FAIL;
		പോകുക out;
	}
	എങ്കിൽ (sshbuf_get_cstring(b, &ktype, ശൂന്യ) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		പോകുക out;
	}
	എങ്കിൽ (strcmp(ktype, "webauthn-sk-ecdsa-sha2-nistp256@openssh.com") == 0 ||
	    strcmp(ktype, "webauthn-sk-ecdsa-sha2-nistp256-cert-v01@openssh.com")
	      == 0)
		is_webauthn = 1;
	അല്ലെങ്കിൽ എങ്കിൽ (strcmp(ktype, "sk-ecdsa-sha2-nistp256@openssh.com") != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		പോകുക out;
	}
	എങ്കിൽ (sshbuf_froms(b, &sigbuf) != 0 ||
	    sshbuf_get_u8(b, &sig_flags) != 0 ||
	    sshbuf_get_u32(b, &sig_counter) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		പോകുക out;
	}
	എങ്കിൽ (is_webauthn) {
		എങ്കിൽ (sshbuf_get_cstring(b, &webauthn_origin, ശൂന്യ) != 0 ||
		    sshbuf_froms(b, &webauthn_wrapper) != 0 ||
		    sshbuf_froms(b, &webauthn_exts) != 0) {
			ret = SSH_ERR_INVALID_FORMAT;
			പോകുക out;
		}
	}
	എങ്കിൽ (sshbuf_len(b) != 0) {
		ret = SSH_ERR_UNEXPECTED_TRAILING_DATA;
		പോകുക out;
	}

	/* parse signature */
	എങ്കിൽ (sshbuf_get_bignum2(sigbuf, &sig_r) != 0 ||
	    sshbuf_get_bignum2(sigbuf, &sig_s) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		പോകുക out;
	}
	എങ്കിൽ (sshbuf_len(sigbuf) != 0) {
		ret = SSH_ERR_UNEXPECTED_TRAILING_DATA;
		പോകുക out;
	}

#ifdef DEBUG_SK
	fprintf(stderr, "%s: data: (len %zu)\n", __func__, dlen);
	/* sshbuf_dump_data(data, datalen, stderr); */
	fprintf(stderr, "%s: sig_r: %s\n", __func__, (tmp = BN_bn2hex(sig_r)));
	സ്വതന്ത്രം(tmp);
	fprintf(stderr, "%s: sig_s: %s\n", __func__, (tmp = BN_bn2hex(sig_s)));
	സ്വതന്ത്രം(tmp);
	fprintf(stderr, "%s: sig_flags = 0x%02x, sig_counter = %u\n",
	    __func__, sig_flags, sig_counter);
	എങ്കിൽ (is_webauthn) {
		fprintf(stderr, "%s: webauthn origin: %s\n", __func__,
		    webauthn_origin);
		fprintf(stderr, "%s: webauthn_wrapper:\n", __func__);
		sshbuf_dump(webauthn_wrapper, stderr);
	}
#endif
	എങ്കിൽ ((esig = ECDSA_SIG_new()) == ശൂന്യ) {
		ret = SSH_ERR_ALLOC_FAIL;
		പോകുക out;
	}
	എങ്കിൽ (!ECDSA_SIG_set0(esig, sig_r, sig_s)) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		പോകുക out;
	}
	sig_r = sig_s = ശൂന്യ; /* transferred */

	/* Reconstruct data that was supposedly signed */
	എങ്കിൽ ((original_signed = sshbuf_new()) == ശൂന്യ) {
		ret = SSH_ERR_ALLOC_FAIL;
		പോകുക out;
	}
	എങ്കിൽ (is_webauthn) {
		എങ്കിൽ ((ret = webauthn_check_prepare_hash(data, dlen,
		    webauthn_origin, webauthn_wrapper, sig_flags, webauthn_exts,
		    msghash, വലുപ്പം(msghash))) != 0)
			പോകുക out;
	} അല്ലെങ്കിൽ എങ്കിൽ ((ret = ssh_digest_memory(SSH_DIGEST_SHA256, data, dlen,
	    msghash, വലുപ്പം(msghash))) != 0)
		പോകുക out;
	/* Application value is hashed before signature */
	എങ്കിൽ ((ret = ssh_digest_memory(SSH_DIGEST_SHA256, താക്കോൽ->sk_application,
	    strlen(താക്കോൽ->sk_application), apphash, വലുപ്പം(apphash))) != 0)
		പോകുക out;
#ifdef DEBUG_SK
	fprintf(stderr, "%s: hashed application:\n", __func__);
	sshbuf_dump_data(apphash, വലുപ്പം(apphash), stderr);
	fprintf(stderr, "%s: hashed message:\n", __func__);
	sshbuf_dump_data(msghash, വലുപ്പം(msghash), stderr);
#endif
	എങ്കിൽ ((ret = sshbuf_put(original_signed,
	    apphash, വലുപ്പം(apphash))) != 0 ||
	    (ret = sshbuf_put_u8(original_signed, sig_flags)) != 0 ||
	    (ret = sshbuf_put_u32(original_signed, sig_counter)) != 0 ||
	    (ret = sshbuf_putb(original_signed, webauthn_exts)) != 0 ||
	    (ret = sshbuf_put(original_signed, msghash, വലുപ്പം(msghash))) != 0)
		പോകുക out;
	details->sk_counter = sig_counter;
	details->sk_flags = sig_flags;
#ifdef DEBUG_SK
	fprintf(stderr, "%s: signed buf:\n", __func__);
	sshbuf_dump(original_signed, stderr);
#endif

	എങ്കിൽ ((md_ctx = EVP_MD_CTX_new()) == ശൂന്യ) {
		ret = SSH_ERR_ALLOC_FAIL;
		പോകുക out;
	}
	എങ്കിൽ ((len = i2d_ECDSA_SIG(esig, ശൂന്യ)) <= 0) {
		len = 0;
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		പോകുക out;
	}
	എങ്കിൽ ((sigb = calloc(1, len)) == ശൂന്യ) {
		ret = SSH_ERR_ALLOC_FAIL;
		പോകുക out;
	}
	cp = sigb; /* ASN1_item_i2d increments the pointer past the object */
	എങ്കിൽ (i2d_ECDSA_SIG(esig, &cp) != len) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		പോകുക out;
	}
#ifdef DEBUG_SK
	fprintf(stderr, "%s: signed hash:\n", __func__);
	sshbuf_dump_data(sigb, len, stderr);
#endif
	/* Verify it */
	എങ്കിൽ (EVP_DigestVerifyInit(md_ctx, ശൂന്യ, EVP_sha256(), ശൂന്യ,
	    താക്കോൽ->pkey) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		പോകുക out;
	}
	തിരഞ്ഞെടുപ്പ് (EVP_DigestVerify(md_ctx, sigb, len,
	    sshbuf_ptr(original_signed), sshbuf_len(original_signed))) {
	അവസ്ഥ 1:
		ret = 0;
		നിർത്തുക;
	അവസ്ഥ 0:
		ret = SSH_ERR_SIGNATURE_INVALID;
		പോകുക out;
	സ്ഥിരസ്ഥിതി:
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		പോകുക out;
	}
	/* success */
	എങ്കിൽ (detailsp != ശൂന്യ) {
		*detailsp = details;
		details = ശൂന്യ;
	}
 out:
	explicit_bzero(&sig_flags, വലുപ്പം(sig_flags));
	explicit_bzero(&sig_counter, വലുപ്പം(sig_counter));
	explicit_bzero(msghash, വലുപ്പം(msghash));
	explicit_bzero(apphash, വലുപ്പം(apphash));
	sshkey_sig_details_free(details);
	sshbuf_free(webauthn_wrapper);
	sshbuf_free(webauthn_exts);
	സ്വതന്ത്രം(webauthn_origin);
	sshbuf_free(original_signed);
	sshbuf_free(sigbuf);
	sshbuf_free(b);
	ECDSA_SIG_free(esig);
	BN_clear_free(sig_r);
	BN_clear_free(sig_s);
	സ്വതന്ത്രം(ktype);
	freezero(sigb, len);
	EVP_MD_CTX_free(md_ctx);
	തിരികെ ret;
}

സ്ഥിതം സ്ഥിരം ഘടന sshkey_impl_funcs sshkey_ecdsa_sk_funcs = {
	/* .size = */		ശൂന്യ,
	/* .alloc = */		ശൂന്യ,
	/* .cleanup = */	ssh_ecdsa_sk_cleanup,
	/* .equal = */		ssh_ecdsa_sk_equal,
	/* .ssh_serialize_public = */ ssh_ecdsa_sk_serialize_public,
	/* .ssh_deserialize_public = */ ssh_ecdsa_sk_deserialize_public,
	/* .ssh_serialize_private = */ ssh_ecdsa_sk_serialize_private,
	/* .ssh_deserialize_private = */ ssh_ecdsa_sk_deserialize_private,
	/* .generate = */	ശൂന്യ,
	/* .copy_public = */	ssh_ecdsa_sk_copy_public,
	/* .sign = */		ശൂന്യ,
	/* .verify = */		ssh_ecdsa_sk_verify,
};

സ്ഥിരം ഘടന sshkey_impl sshkey_ecdsa_sk_impl = {
	/* .name = */		"sk-ecdsa-sha2-nistp256@openssh.com",
	/* .shortname = */	"ECDSA-SK",
	/* .sigalg = */		ശൂന്യ,
	/* .type = */		താക്കോൽ_ECDSA_SK,
	/* .nid = */		NID_X9_62_prime256v1,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	256,
	/* .funcs = */		&sshkey_ecdsa_sk_funcs,
};

സ്ഥിരം ഘടന sshkey_impl sshkey_ecdsa_sk_cert_impl = {
	/* .name = */		"sk-ecdsa-sha2-nistp256-cert-v01@openssh.com",
	/* .shortname = */	"ECDSA-SK-CERT",
	/* .sigalg = */		ശൂന്യ,
	/* .type = */		താക്കോൽ_ECDSA_SK_CERT,
	/* .nid = */		NID_X9_62_prime256v1,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	256,
	/* .funcs = */		&sshkey_ecdsa_sk_funcs,
};

സ്ഥിരം ഘടന sshkey_impl sshkey_ecdsa_sk_webauthn_impl = {
	/* .name = */		"webauthn-sk-ecdsa-sha2-nistp256@openssh.com",
	/* .shortname = */	"ECDSA-SK",
	/* .sigalg = */		ശൂന്യ,
	/* .type = */		താക്കോൽ_ECDSA_SK,
	/* .nid = */		NID_X9_62_prime256v1,
	/* .cert = */		0,
	/* .sigonly = */	1,
	/* .keybits = */	256,
	/* .funcs = */		&sshkey_ecdsa_sk_funcs,
};

സ്ഥിരം ഘടന sshkey_impl sshkey_ecdsa_sk_webauthn_cert_impl = {
	/* .name = */		"webauthn-sk-ecdsa-sha2-nistp256-cert-v01@openssh.com",
	/* .shortname = */	"ECDSA-SK-CERT",
	/* .sigalg = */		ശൂന്യ,
	/* .type = */		താക്കോൽ_ECDSA_SK_CERT,
	/* .nid = */		NID_X9_62_prime256v1,
	/* .cert = */		1,
	/* .sigonly = */	1,
	/* .keybits = */	256,
	/* .funcs = */		&sshkey_ecdsa_sk_funcs,
};
#endif /* WITH_OPENSSL */
