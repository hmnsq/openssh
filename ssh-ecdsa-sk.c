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

#அந்தர்பாவ "includes.h"

#அந்தர்பாவ <sys/types.h>

#ifdef WITH_OPENSSL
#அந்தர்பாவ "openbsd-compat/openssl-compat.h"
#அந்தர்பாவ <openssl/bn.h>
#அந்தர்பாவ <openssl/ec.h>
#அந்தர்பாவ <openssl/ecdsa.h>
#அந்தர்பாவ <openssl/evp.h>

#அந்தர்பாவ <string.h>
#அந்தர்பாவ <stdio.h> /* needed for DEBUG_SK only */

#அந்தர்பாவ "sshbuf.h"
#அந்தர்பாவ "ssherr.h"
#அந்தர்பாவ "digest.h"
#define SSHKEY_INTERNAL
#அந்தர்பாவ "sshkey.h"

/* Reuse some ECDSA internals */
வெளி கட்டமைப்பு sshkey_impl_funcs sshkey_ecdsa_funcs;

நிலையான வெறுமை
ssh_ecdsa_sk_cleanup(கட்டமைப்பு sshkey *k)
{
	sshkey_sk_cleanup(k);
	sshkey_ecdsa_funcs.cleanup(k);
}

நிலையான முழு
ssh_ecdsa_sk_equal(மாறிலி கட்டமைப்பு sshkey *a, மாறிலி கட்டமைப்பு sshkey *b)
{
	எனில் (!sshkey_sk_fields_equal(a, b))
		திரும்பு 0;
	எனில் (!sshkey_ecdsa_funcs.equal(a, b))
		திரும்பு 0;
	திரும்பு 1;
}

நிலையான முழு
ssh_ecdsa_sk_serialize_public(மாறிலி கட்டமைப்பு sshkey *சாவி, கட்டமைப்பு sshbuf *b,
    எண்ணிக்கை sshkey_serialize_rep opts)
{
	முழு r;

	எனில் ((r = sshkey_ecdsa_funcs.serialize_public(சாவி, b, opts)) != 0)
		திரும்பு r;
	எனில் ((r = sshkey_serialize_sk(சாவி, b)) != 0)
		திரும்பு r;

	திரும்பு 0;
}

நிலையான முழு
ssh_ecdsa_sk_serialize_private(மாறிலி கட்டமைப்பு sshkey *சாவி, கட்டமைப்பு sshbuf *b,
    எண்ணிக்கை sshkey_serialize_rep opts)
{
	முழு r;

	எனில் (!sshkey_is_cert(சாவி)) {
		எனில் ((r = sshkey_ecdsa_funcs.serialize_public(சாவி,
		    b, opts)) != 0)
			திரும்பு r;
	}
	எனில் ((r = sshkey_serialize_private_sk(சாவி, b)) != 0)
		திரும்பு r;

	திரும்பு 0;
}

நிலையான முழு
ssh_ecdsa_sk_copy_public(மாறிலி கட்டமைப்பு sshkey *from, கட்டமைப்பு sshkey *to)
{
	முழு r;

	எனில் ((r = sshkey_ecdsa_funcs.copy_public(from, to)) != 0)
		திரும்பு r;
	எனில் ((r = sshkey_copy_public_sk(from, to)) != 0)
		திரும்பு r;
	திரும்பு 0;
}

நிலையான முழு
ssh_ecdsa_sk_deserialize_public(மாறிலி எழுத்து *ktype, கட்டமைப்பு sshbuf *b,
    கட்டமைப்பு sshkey *சாவி)
{
	முழு r;

	எனில் ((r = sshkey_ecdsa_funcs.deserialize_public(ktype, b, சாவி)) != 0)
		திரும்பு r;
	எனில் ((r = sshkey_deserialize_sk(b, சாவி)) != 0)
		திரும்பு r;
	திரும்பு 0;
}

நிலையான முழு
ssh_ecdsa_sk_deserialize_private(மாறிலி எழுத்து *ktype, கட்டமைப்பு sshbuf *b,
    கட்டமைப்பு sshkey *சாவி)
{
	முழு r;

	எனில் (!sshkey_is_cert(சாவி)) {
		எனில் ((r = sshkey_ecdsa_funcs.deserialize_public(ktype,
		    b, சாவி)) != 0)
			திரும்பு r;
	}
	எனில் ((r = sshkey_private_deserialize_sk(b, சாவி)) != 0)
		திரும்பு r;

	திரும்பு 0;
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
நிலையான முழு
webauthn_check_prepare_hash(மாறிலி u_char *data, size_t datalen,
    மாறிலி எழுத்து *origin, மாறிலி கட்டமைப்பு sshbuf *wrapper,
    uint8_t flags, மாறிலி கட்டமைப்பு sshbuf *extensions,
    u_char *msghash, size_t msghashlen)
{
	முழு r = SSH_ERR_INTERNAL_ERROR;
	கட்டமைப்பு sshbuf *chall = வெற்று, *m = வெற்று;

	எனில் ((m = sshbuf_new()) == வெற்று ||
	    (chall = sshbuf_from(data, datalen)) == வெற்று) {
		r = SSH_ERR_ALLOC_FAIL;
		செல் out;
	}
	/*
	 * Ensure origin contains no quote character and that the flags are
	 * consistent with what we received
	 */
	எனில் (strchr(origin, '\"') != வெற்று ||
	    (flags & 0x40) != 0 /* AD */ ||
	    ((flags & 0x80) == 0 /* ED */) != (sshbuf_len(extensions) == 0)) {
		r = SSH_ERR_INVALID_FORMAT;
		செல் out;
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
	எனில் ((r = sshbuf_put(m, WEBAUTHN_0, அளவு(WEBAUTHN_0) - 1)) != 0 ||
	    (r = sshbuf_dtourlb64(chall, m, 0)) != 0 ||
	    (r = sshbuf_put(m, WEBAUTHN_1, அளவு(WEBAUTHN_1) - 1)) != 0 ||
	    (r = sshbuf_put(m, origin, strlen(origin))) != 0 ||
	    (r = sshbuf_put(m, WEBAUTHN_2, அளவு(WEBAUTHN_2) - 1)) != 0)
		செல் out;
#ifdef DEBUG_SK
	fprintf(stderr, "%s: received origin: %s\n", __func__, origin);
	fprintf(stderr, "%s: received clientData:\n", __func__);
	sshbuf_dump(wrapper, stderr);
	fprintf(stderr, "%s: expected clientData preamble:\n", __func__);
	sshbuf_dump(m, stderr);
#endif
	/* Check that the supplied clientData has the preamble we expect */
	எனில் ((r = sshbuf_cmp(wrapper, 0, sshbuf_ptr(m), sshbuf_len(m))) != 0)
		செல் out;

	/* Prepare hash of clientData */
	எனில் ((r = ssh_digest_buffer(SSH_DIGEST_SHA256, wrapper,
	    msghash, msghashlen)) != 0)
		செல் out;

	/* success */
	r = 0;
 out:
	sshbuf_free(chall);
	sshbuf_free(m);
	திரும்பு r;
}

நிலையான முழு
ssh_ecdsa_sk_verify(மாறிலி கட்டமைப்பு sshkey *சாவி,
    மாறிலி u_char *sig, size_t siglen,
    மாறிலி u_char *data, size_t dlen, மாறிலி எழுத்து *alg, u_int compat,
    கட்டமைப்பு sshkey_sig_details **detailsp)
{
	ECDSA_SIG *esig = வெற்று;
	EVP_MD_CTX *md_ctx = வெற்று;
	BIGNUM *sig_r = வெற்று, *sig_s = வெற்று;
	u_char sig_flags;
	u_char msghash[32], apphash[32];
	u_int sig_counter;
	u_char *sigb = வெற்று, *cp;
	முழு is_webauthn = 0, ret = SSH_ERR_INTERNAL_ERROR, len = 0;
	கட்டமைப்பு sshbuf *b = வெற்று, *sigbuf = வெற்று, *original_signed = வெற்று;
	கட்டமைப்பு sshbuf *webauthn_wrapper = வெற்று, *webauthn_exts = வெற்று;
	எழுத்து *ktype = வெற்று, *webauthn_origin = வெற்று;
	கட்டமைப்பு sshkey_sig_details *details = வெற்று;
#ifdef DEBUG_SK
	எழுத்து *tmp = வெற்று;
#endif

	எனில் (detailsp != வெற்று)
		*detailsp = வெற்று;
	எனில் (சாவி == வெற்று || சாவி->pkey == வெற்று ||
	    sshkey_type_plain(சாவி->type) != சாவி_ECDSA_SK ||
	    sig == வெற்று || siglen == 0)
		திரும்பு SSH_ERR_INVALID_ARGUMENT;

	எனில் (சாவி->ecdsa_nid != NID_X9_62_prime256v1)
		திரும்பு SSH_ERR_INTERNAL_ERROR;

	/* fetch signature */
	எனில் ((b = sshbuf_from(sig, siglen)) == வெற்று)
		திரும்பு SSH_ERR_ALLOC_FAIL;
	எனில் ((details = calloc(1, அளவு(*details))) == வெற்று) {
		ret = SSH_ERR_ALLOC_FAIL;
		செல் out;
	}
	எனில் (sshbuf_get_cstring(b, &ktype, வெற்று) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		செல் out;
	}
	எனில் (strcmp(ktype, "webauthn-sk-ecdsa-sha2-nistp256@openssh.com") == 0 ||
	    strcmp(ktype, "webauthn-sk-ecdsa-sha2-nistp256-cert-v01@openssh.com")
	      == 0)
		is_webauthn = 1;
	இல்லையெனில் எனில் (strcmp(ktype, "sk-ecdsa-sha2-nistp256@openssh.com") != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		செல் out;
	}
	எனில் (sshbuf_froms(b, &sigbuf) != 0 ||
	    sshbuf_get_u8(b, &sig_flags) != 0 ||
	    sshbuf_get_u32(b, &sig_counter) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		செல் out;
	}
	எனில் (is_webauthn) {
		எனில் (sshbuf_get_cstring(b, &webauthn_origin, வெற்று) != 0 ||
		    sshbuf_froms(b, &webauthn_wrapper) != 0 ||
		    sshbuf_froms(b, &webauthn_exts) != 0) {
			ret = SSH_ERR_INVALID_FORMAT;
			செல் out;
		}
	}
	எனில் (sshbuf_len(b) != 0) {
		ret = SSH_ERR_UNEXPECTED_TRAILING_DATA;
		செல் out;
	}

	/* parse signature */
	எனில் (sshbuf_get_bignum2(sigbuf, &sig_r) != 0 ||
	    sshbuf_get_bignum2(sigbuf, &sig_s) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		செல் out;
	}
	எனில் (sshbuf_len(sigbuf) != 0) {
		ret = SSH_ERR_UNEXPECTED_TRAILING_DATA;
		செல் out;
	}

#ifdef DEBUG_SK
	fprintf(stderr, "%s: data: (len %zu)\n", __func__, dlen);
	/* sshbuf_dump_data(data, datalen, stderr); */
	fprintf(stderr, "%s: sig_r: %s\n", __func__, (tmp = BN_bn2hex(sig_r)));
	விடுவி(tmp);
	fprintf(stderr, "%s: sig_s: %s\n", __func__, (tmp = BN_bn2hex(sig_s)));
	விடுவி(tmp);
	fprintf(stderr, "%s: sig_flags = 0x%02x, sig_counter = %u\n",
	    __func__, sig_flags, sig_counter);
	எனில் (is_webauthn) {
		fprintf(stderr, "%s: webauthn origin: %s\n", __func__,
		    webauthn_origin);
		fprintf(stderr, "%s: webauthn_wrapper:\n", __func__);
		sshbuf_dump(webauthn_wrapper, stderr);
	}
#endif
	எனில் ((esig = ECDSA_SIG_new()) == வெற்று) {
		ret = SSH_ERR_ALLOC_FAIL;
		செல் out;
	}
	எனில் (!ECDSA_SIG_set0(esig, sig_r, sig_s)) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		செல் out;
	}
	sig_r = sig_s = வெற்று; /* transferred */

	/* Reconstruct data that was supposedly signed */
	எனில் ((original_signed = sshbuf_new()) == வெற்று) {
		ret = SSH_ERR_ALLOC_FAIL;
		செல் out;
	}
	எனில் (is_webauthn) {
		எனில் ((ret = webauthn_check_prepare_hash(data, dlen,
		    webauthn_origin, webauthn_wrapper, sig_flags, webauthn_exts,
		    msghash, அளவு(msghash))) != 0)
			செல் out;
	} இல்லையெனில் எனில் ((ret = ssh_digest_memory(SSH_DIGEST_SHA256, data, dlen,
	    msghash, அளவு(msghash))) != 0)
		செல் out;
	/* Application value is hashed before signature */
	எனில் ((ret = ssh_digest_memory(SSH_DIGEST_SHA256, சாவி->sk_application,
	    strlen(சாவி->sk_application), apphash, அளவு(apphash))) != 0)
		செல் out;
#ifdef DEBUG_SK
	fprintf(stderr, "%s: hashed application:\n", __func__);
	sshbuf_dump_data(apphash, அளவு(apphash), stderr);
	fprintf(stderr, "%s: hashed message:\n", __func__);
	sshbuf_dump_data(msghash, அளவு(msghash), stderr);
#endif
	எனில் ((ret = sshbuf_put(original_signed,
	    apphash, அளவு(apphash))) != 0 ||
	    (ret = sshbuf_put_u8(original_signed, sig_flags)) != 0 ||
	    (ret = sshbuf_put_u32(original_signed, sig_counter)) != 0 ||
	    (ret = sshbuf_putb(original_signed, webauthn_exts)) != 0 ||
	    (ret = sshbuf_put(original_signed, msghash, அளவு(msghash))) != 0)
		செல் out;
	details->sk_counter = sig_counter;
	details->sk_flags = sig_flags;
#ifdef DEBUG_SK
	fprintf(stderr, "%s: signed buf:\n", __func__);
	sshbuf_dump(original_signed, stderr);
#endif

	எனில் ((md_ctx = EVP_MD_CTX_new()) == வெற்று) {
		ret = SSH_ERR_ALLOC_FAIL;
		செல் out;
	}
	எனில் ((len = i2d_ECDSA_SIG(esig, வெற்று)) <= 0) {
		len = 0;
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		செல் out;
	}
	எனில் ((sigb = calloc(1, len)) == வெற்று) {
		ret = SSH_ERR_ALLOC_FAIL;
		செல் out;
	}
	cp = sigb; /* ASN1_item_i2d increments the pointer past the object */
	எனில் (i2d_ECDSA_SIG(esig, &cp) != len) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		செல் out;
	}
#ifdef DEBUG_SK
	fprintf(stderr, "%s: signed hash:\n", __func__);
	sshbuf_dump_data(sigb, len, stderr);
#endif
	/* Verify it */
	எனில் (EVP_DigestVerifyInit(md_ctx, வெற்று, EVP_sha256(), வெற்று,
	    சாவி->pkey) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		செல் out;
	}
	தேர்வு (EVP_DigestVerify(md_ctx, sigb, len,
	    sshbuf_ptr(original_signed), sshbuf_len(original_signed))) {
	நிலை 1:
		ret = 0;
		நிறுத்து;
	நிலை 0:
		ret = SSH_ERR_SIGNATURE_INVALID;
		செல் out;
	இயல்பு:
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		செல் out;
	}
	/* success */
	எனில் (detailsp != வெற்று) {
		*detailsp = details;
		details = வெற்று;
	}
 out:
	explicit_bzero(&sig_flags, அளவு(sig_flags));
	explicit_bzero(&sig_counter, அளவு(sig_counter));
	explicit_bzero(msghash, அளவு(msghash));
	explicit_bzero(apphash, அளவு(apphash));
	sshkey_sig_details_free(details);
	sshbuf_free(webauthn_wrapper);
	sshbuf_free(webauthn_exts);
	விடுவி(webauthn_origin);
	sshbuf_free(original_signed);
	sshbuf_free(sigbuf);
	sshbuf_free(b);
	ECDSA_SIG_free(esig);
	BN_clear_free(sig_r);
	BN_clear_free(sig_s);
	விடுவி(ktype);
	freezero(sigb, len);
	EVP_MD_CTX_free(md_ctx);
	திரும்பு ret;
}

நிலையான மாறிலி கட்டமைப்பு sshkey_impl_funcs sshkey_ecdsa_sk_funcs = {
	/* .size = */		வெற்று,
	/* .alloc = */		வெற்று,
	/* .cleanup = */	ssh_ecdsa_sk_cleanup,
	/* .equal = */		ssh_ecdsa_sk_equal,
	/* .ssh_serialize_public = */ ssh_ecdsa_sk_serialize_public,
	/* .ssh_deserialize_public = */ ssh_ecdsa_sk_deserialize_public,
	/* .ssh_serialize_private = */ ssh_ecdsa_sk_serialize_private,
	/* .ssh_deserialize_private = */ ssh_ecdsa_sk_deserialize_private,
	/* .generate = */	வெற்று,
	/* .copy_public = */	ssh_ecdsa_sk_copy_public,
	/* .sign = */		வெற்று,
	/* .verify = */		ssh_ecdsa_sk_verify,
};

மாறிலி கட்டமைப்பு sshkey_impl sshkey_ecdsa_sk_impl = {
	/* .name = */		"sk-ecdsa-sha2-nistp256@openssh.com",
	/* .shortname = */	"ECDSA-SK",
	/* .sigalg = */		வெற்று,
	/* .type = */		சாவி_ECDSA_SK,
	/* .nid = */		NID_X9_62_prime256v1,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	256,
	/* .funcs = */		&sshkey_ecdsa_sk_funcs,
};

மாறிலி கட்டமைப்பு sshkey_impl sshkey_ecdsa_sk_cert_impl = {
	/* .name = */		"sk-ecdsa-sha2-nistp256-cert-v01@openssh.com",
	/* .shortname = */	"ECDSA-SK-CERT",
	/* .sigalg = */		வெற்று,
	/* .type = */		சாவி_ECDSA_SK_CERT,
	/* .nid = */		NID_X9_62_prime256v1,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	256,
	/* .funcs = */		&sshkey_ecdsa_sk_funcs,
};

மாறிலி கட்டமைப்பு sshkey_impl sshkey_ecdsa_sk_webauthn_impl = {
	/* .name = */		"webauthn-sk-ecdsa-sha2-nistp256@openssh.com",
	/* .shortname = */	"ECDSA-SK",
	/* .sigalg = */		வெற்று,
	/* .type = */		சாவி_ECDSA_SK,
	/* .nid = */		NID_X9_62_prime256v1,
	/* .cert = */		0,
	/* .sigonly = */	1,
	/* .keybits = */	256,
	/* .funcs = */		&sshkey_ecdsa_sk_funcs,
};

மாறிலி கட்டமைப்பு sshkey_impl sshkey_ecdsa_sk_webauthn_cert_impl = {
	/* .name = */		"webauthn-sk-ecdsa-sha2-nistp256-cert-v01@openssh.com",
	/* .shortname = */	"ECDSA-SK-CERT",
	/* .sigalg = */		வெற்று,
	/* .type = */		சாவி_ECDSA_SK_CERT,
	/* .nid = */		NID_X9_62_prime256v1,
	/* .cert = */		1,
	/* .sigonly = */	1,
	/* .keybits = */	256,
	/* .funcs = */		&sshkey_ecdsa_sk_funcs,
};
#endif /* WITH_OPENSSL */
