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

#અન્તર્ભાવ "includes.h"

#અન્તર્ભાવ <sys/types.h>

#ifdef WITH_OPENSSL
#અન્તર્ભાવ "openbsd-compat/openssl-compat.h"
#અન્તર્ભાવ <openssl/bn.h>
#અન્તર્ભાવ <openssl/ec.h>
#અન્તર્ભાવ <openssl/ecdsa.h>
#અન્તર્ભાવ <openssl/evp.h>

#અન્તર્ભાવ <string.h>
#અન્તર્ભાવ <stdio.h> /* needed for DEBUG_SK only */

#અન્તર્ભાવ "sshbuf.h"
#અન્તર્ભાવ "ssherr.h"
#અન્તર્ભાવ "digest.h"
#define SSHKEY_INTERNAL
#અન્તર્ભાવ "sshkey.h"

/* Reuse some ECDSA internals */
બાહ્ય સંરચના sshkey_impl_funcs sshkey_ecdsa_funcs;

સ્થિર શૂન્ય
ssh_ecdsa_sk_cleanup(સંરચના sshkey *k)
{
	sshkey_sk_cleanup(k);
	sshkey_ecdsa_funcs.cleanup(k);
}

સ્થિર પૂર્ણાંક
ssh_ecdsa_sk_equal(અચલ સંરચના sshkey *a, અચલ સંરચના sshkey *b)
{
	જો (!sshkey_sk_fields_equal(a, b))
		પાછા 0;
	જો (!sshkey_ecdsa_funcs.equal(a, b))
		પાછા 0;
	પાછા 1;
}

સ્થિર પૂર્ણાંક
ssh_ecdsa_sk_serialize_public(અચલ સંરચના sshkey *ચાવી, સંરચના sshbuf *b,
    ગણના sshkey_serialize_rep opts)
{
	પૂર્ણાંક r;

	જો ((r = sshkey_ecdsa_funcs.serialize_public(ચાવી, b, opts)) != 0)
		પાછા r;
	જો ((r = sshkey_serialize_sk(ચાવી, b)) != 0)
		પાછા r;

	પાછા 0;
}

સ્થિર પૂર્ણાંક
ssh_ecdsa_sk_serialize_private(અચલ સંરચના sshkey *ચાવી, સંરચના sshbuf *b,
    ગણના sshkey_serialize_rep opts)
{
	પૂર્ણાંક r;

	જો (!sshkey_is_cert(ચાવી)) {
		જો ((r = sshkey_ecdsa_funcs.serialize_public(ચાવી,
		    b, opts)) != 0)
			પાછા r;
	}
	જો ((r = sshkey_serialize_private_sk(ચાવી, b)) != 0)
		પાછા r;

	પાછા 0;
}

સ્થિર પૂર્ણાંક
ssh_ecdsa_sk_copy_public(અચલ સંરચના sshkey *from, સંરચના sshkey *to)
{
	પૂર્ણાંક r;

	જો ((r = sshkey_ecdsa_funcs.copy_public(from, to)) != 0)
		પાછા r;
	જો ((r = sshkey_copy_public_sk(from, to)) != 0)
		પાછા r;
	પાછા 0;
}

સ્થિર પૂર્ણાંક
ssh_ecdsa_sk_deserialize_public(અચલ અક્ષર *ktype, સંરચના sshbuf *b,
    સંરચના sshkey *ચાવી)
{
	પૂર્ણાંક r;

	જો ((r = sshkey_ecdsa_funcs.deserialize_public(ktype, b, ચાવી)) != 0)
		પાછા r;
	જો ((r = sshkey_deserialize_sk(b, ચાવી)) != 0)
		પાછા r;
	પાછા 0;
}

સ્થિર પૂર્ણાંક
ssh_ecdsa_sk_deserialize_private(અચલ અક્ષર *ktype, સંરચના sshbuf *b,
    સંરચના sshkey *ચાવી)
{
	પૂર્ણાંક r;

	જો (!sshkey_is_cert(ચાવી)) {
		જો ((r = sshkey_ecdsa_funcs.deserialize_public(ktype,
		    b, ચાવી)) != 0)
			પાછા r;
	}
	જો ((r = sshkey_private_deserialize_sk(b, ચાવી)) != 0)
		પાછા r;

	પાછા 0;
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
સ્થિર પૂર્ણાંક
webauthn_check_prepare_hash(અચલ u_char *data, size_t datalen,
    અચલ અક્ષર *origin, અચલ સંરચના sshbuf *wrapper,
    uint8_t flags, અચલ સંરચના sshbuf *extensions,
    u_char *msghash, size_t msghashlen)
{
	પૂર્ણાંક r = SSH_ERR_INTERNAL_ERROR;
	સંરચના sshbuf *chall = ખાલી, *m = ખાલી;

	જો ((m = sshbuf_new()) == ખાલી ||
	    (chall = sshbuf_from(data, datalen)) == ખાલી) {
		r = SSH_ERR_ALLOC_FAIL;
		જાઓ out;
	}
	/*
	 * Ensure origin contains no quote character and that the flags are
	 * consistent with what we received
	 */
	જો (strchr(origin, '\"') != ખાલી ||
	    (flags & 0x40) != 0 /* AD */ ||
	    ((flags & 0x80) == 0 /* ED */) != (sshbuf_len(extensions) == 0)) {
		r = SSH_ERR_INVALID_FORMAT;
		જાઓ out;
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
	જો ((r = sshbuf_put(m, WEBAUTHN_0, કદ(WEBAUTHN_0) - 1)) != 0 ||
	    (r = sshbuf_dtourlb64(chall, m, 0)) != 0 ||
	    (r = sshbuf_put(m, WEBAUTHN_1, કદ(WEBAUTHN_1) - 1)) != 0 ||
	    (r = sshbuf_put(m, origin, strlen(origin))) != 0 ||
	    (r = sshbuf_put(m, WEBAUTHN_2, કદ(WEBAUTHN_2) - 1)) != 0)
		જાઓ out;
#ifdef DEBUG_SK
	fprintf(stderr, "%s: received origin: %s\n", __func__, origin);
	fprintf(stderr, "%s: received clientData:\n", __func__);
	sshbuf_dump(wrapper, stderr);
	fprintf(stderr, "%s: expected clientData preamble:\n", __func__);
	sshbuf_dump(m, stderr);
#endif
	/* Check that the supplied clientData has the preamble we expect */
	જો ((r = sshbuf_cmp(wrapper, 0, sshbuf_ptr(m), sshbuf_len(m))) != 0)
		જાઓ out;

	/* Prepare hash of clientData */
	જો ((r = ssh_digest_buffer(SSH_DIGEST_SHA256, wrapper,
	    msghash, msghashlen)) != 0)
		જાઓ out;

	/* success */
	r = 0;
 out:
	sshbuf_free(chall);
	sshbuf_free(m);
	પાછા r;
}

સ્થિર પૂર્ણાંક
ssh_ecdsa_sk_verify(અચલ સંરચના sshkey *ચાવી,
    અચલ u_char *sig, size_t siglen,
    અચલ u_char *data, size_t dlen, અચલ અક્ષર *alg, u_int compat,
    સંરચના sshkey_sig_details **detailsp)
{
	ECDSA_SIG *esig = ખાલી;
	EVP_MD_CTX *md_ctx = ખાલી;
	BIGNUM *sig_r = ખાલી, *sig_s = ખાલી;
	u_char sig_flags;
	u_char msghash[32], apphash[32];
	u_int sig_counter;
	u_char *sigb = ખાલી, *cp;
	પૂર્ણાંક is_webauthn = 0, ret = SSH_ERR_INTERNAL_ERROR, len = 0;
	સંરચના sshbuf *b = ખાલી, *sigbuf = ખાલી, *original_signed = ખાલી;
	સંરચના sshbuf *webauthn_wrapper = ખાલી, *webauthn_exts = ખાલી;
	અક્ષર *ktype = ખાલી, *webauthn_origin = ખાલી;
	સંરચના sshkey_sig_details *details = ખાલી;
#ifdef DEBUG_SK
	અક્ષર *tmp = ખાલી;
#endif

	જો (detailsp != ખાલી)
		*detailsp = ખાલી;
	જો (ચાવી == ખાલી || ચાવી->pkey == ખાલી ||
	    sshkey_type_plain(ચાવી->type) != ચાવી_ECDSA_SK ||
	    sig == ખાલી || siglen == 0)
		પાછા SSH_ERR_INVALID_ARGUMENT;

	જો (ચાવી->ecdsa_nid != NID_X9_62_prime256v1)
		પાછા SSH_ERR_INTERNAL_ERROR;

	/* fetch signature */
	જો ((b = sshbuf_from(sig, siglen)) == ખાલી)
		પાછા SSH_ERR_ALLOC_FAIL;
	જો ((details = calloc(1, કદ(*details))) == ખાલી) {
		ret = SSH_ERR_ALLOC_FAIL;
		જાઓ out;
	}
	જો (sshbuf_get_cstring(b, &ktype, ખાલી) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		જાઓ out;
	}
	જો (strcmp(ktype, "webauthn-sk-ecdsa-sha2-nistp256@openssh.com") == 0 ||
	    strcmp(ktype, "webauthn-sk-ecdsa-sha2-nistp256-cert-v01@openssh.com")
	      == 0)
		is_webauthn = 1;
	નહીંતર જો (strcmp(ktype, "sk-ecdsa-sha2-nistp256@openssh.com") != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		જાઓ out;
	}
	જો (sshbuf_froms(b, &sigbuf) != 0 ||
	    sshbuf_get_u8(b, &sig_flags) != 0 ||
	    sshbuf_get_u32(b, &sig_counter) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		જાઓ out;
	}
	જો (is_webauthn) {
		જો (sshbuf_get_cstring(b, &webauthn_origin, ખાલી) != 0 ||
		    sshbuf_froms(b, &webauthn_wrapper) != 0 ||
		    sshbuf_froms(b, &webauthn_exts) != 0) {
			ret = SSH_ERR_INVALID_FORMAT;
			જાઓ out;
		}
	}
	જો (sshbuf_len(b) != 0) {
		ret = SSH_ERR_UNEXPECTED_TRAILING_DATA;
		જાઓ out;
	}

	/* parse signature */
	જો (sshbuf_get_bignum2(sigbuf, &sig_r) != 0 ||
	    sshbuf_get_bignum2(sigbuf, &sig_s) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		જાઓ out;
	}
	જો (sshbuf_len(sigbuf) != 0) {
		ret = SSH_ERR_UNEXPECTED_TRAILING_DATA;
		જાઓ out;
	}

#ifdef DEBUG_SK
	fprintf(stderr, "%s: data: (len %zu)\n", __func__, dlen);
	/* sshbuf_dump_data(data, datalen, stderr); */
	fprintf(stderr, "%s: sig_r: %s\n", __func__, (tmp = BN_bn2hex(sig_r)));
	મુક્ત(tmp);
	fprintf(stderr, "%s: sig_s: %s\n", __func__, (tmp = BN_bn2hex(sig_s)));
	મુક્ત(tmp);
	fprintf(stderr, "%s: sig_flags = 0x%02x, sig_counter = %u\n",
	    __func__, sig_flags, sig_counter);
	જો (is_webauthn) {
		fprintf(stderr, "%s: webauthn origin: %s\n", __func__,
		    webauthn_origin);
		fprintf(stderr, "%s: webauthn_wrapper:\n", __func__);
		sshbuf_dump(webauthn_wrapper, stderr);
	}
#endif
	જો ((esig = ECDSA_SIG_new()) == ખાલી) {
		ret = SSH_ERR_ALLOC_FAIL;
		જાઓ out;
	}
	જો (!ECDSA_SIG_set0(esig, sig_r, sig_s)) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		જાઓ out;
	}
	sig_r = sig_s = ખાલી; /* transferred */

	/* Reconstruct data that was supposedly signed */
	જો ((original_signed = sshbuf_new()) == ખાલી) {
		ret = SSH_ERR_ALLOC_FAIL;
		જાઓ out;
	}
	જો (is_webauthn) {
		જો ((ret = webauthn_check_prepare_hash(data, dlen,
		    webauthn_origin, webauthn_wrapper, sig_flags, webauthn_exts,
		    msghash, કદ(msghash))) != 0)
			જાઓ out;
	} નહીંતર જો ((ret = ssh_digest_memory(SSH_DIGEST_SHA256, data, dlen,
	    msghash, કદ(msghash))) != 0)
		જાઓ out;
	/* Application value is hashed before signature */
	જો ((ret = ssh_digest_memory(SSH_DIGEST_SHA256, ચાવી->sk_application,
	    strlen(ચાવી->sk_application), apphash, કદ(apphash))) != 0)
		જાઓ out;
#ifdef DEBUG_SK
	fprintf(stderr, "%s: hashed application:\n", __func__);
	sshbuf_dump_data(apphash, કદ(apphash), stderr);
	fprintf(stderr, "%s: hashed message:\n", __func__);
	sshbuf_dump_data(msghash, કદ(msghash), stderr);
#endif
	જો ((ret = sshbuf_put(original_signed,
	    apphash, કદ(apphash))) != 0 ||
	    (ret = sshbuf_put_u8(original_signed, sig_flags)) != 0 ||
	    (ret = sshbuf_put_u32(original_signed, sig_counter)) != 0 ||
	    (ret = sshbuf_putb(original_signed, webauthn_exts)) != 0 ||
	    (ret = sshbuf_put(original_signed, msghash, કદ(msghash))) != 0)
		જાઓ out;
	details->sk_counter = sig_counter;
	details->sk_flags = sig_flags;
#ifdef DEBUG_SK
	fprintf(stderr, "%s: signed buf:\n", __func__);
	sshbuf_dump(original_signed, stderr);
#endif

	જો ((md_ctx = EVP_MD_CTX_new()) == ખાલી) {
		ret = SSH_ERR_ALLOC_FAIL;
		જાઓ out;
	}
	જો ((len = i2d_ECDSA_SIG(esig, ખાલી)) <= 0) {
		len = 0;
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		જાઓ out;
	}
	જો ((sigb = calloc(1, len)) == ખાલી) {
		ret = SSH_ERR_ALLOC_FAIL;
		જાઓ out;
	}
	cp = sigb; /* ASN1_item_i2d increments the pointer past the object */
	જો (i2d_ECDSA_SIG(esig, &cp) != len) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		જાઓ out;
	}
#ifdef DEBUG_SK
	fprintf(stderr, "%s: signed hash:\n", __func__);
	sshbuf_dump_data(sigb, len, stderr);
#endif
	/* Verify it */
	જો (EVP_DigestVerifyInit(md_ctx, ખાલી, EVP_sha256(), ખાલી,
	    ચાવી->pkey) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		જાઓ out;
	}
	પસંદગી (EVP_DigestVerify(md_ctx, sigb, len,
	    sshbuf_ptr(original_signed), sshbuf_len(original_signed))) {
	સ્થિતિ 1:
		ret = 0;
		તોડો;
	સ્થિતિ 0:
		ret = SSH_ERR_SIGNATURE_INVALID;
		જાઓ out;
	મૂળભૂત:
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		જાઓ out;
	}
	/* success */
	જો (detailsp != ખાલી) {
		*detailsp = details;
		details = ખાલી;
	}
 out:
	explicit_bzero(&sig_flags, કદ(sig_flags));
	explicit_bzero(&sig_counter, કદ(sig_counter));
	explicit_bzero(msghash, કદ(msghash));
	explicit_bzero(apphash, કદ(apphash));
	sshkey_sig_details_free(details);
	sshbuf_free(webauthn_wrapper);
	sshbuf_free(webauthn_exts);
	મુક્ત(webauthn_origin);
	sshbuf_free(original_signed);
	sshbuf_free(sigbuf);
	sshbuf_free(b);
	ECDSA_SIG_free(esig);
	BN_clear_free(sig_r);
	BN_clear_free(sig_s);
	મુક્ત(ktype);
	freezero(sigb, len);
	EVP_MD_CTX_free(md_ctx);
	પાછા ret;
}

સ્થિર અચલ સંરચના sshkey_impl_funcs sshkey_ecdsa_sk_funcs = {
	/* .size = */		ખાલી,
	/* .alloc = */		ખાલી,
	/* .cleanup = */	ssh_ecdsa_sk_cleanup,
	/* .equal = */		ssh_ecdsa_sk_equal,
	/* .ssh_serialize_public = */ ssh_ecdsa_sk_serialize_public,
	/* .ssh_deserialize_public = */ ssh_ecdsa_sk_deserialize_public,
	/* .ssh_serialize_private = */ ssh_ecdsa_sk_serialize_private,
	/* .ssh_deserialize_private = */ ssh_ecdsa_sk_deserialize_private,
	/* .generate = */	ખાલી,
	/* .copy_public = */	ssh_ecdsa_sk_copy_public,
	/* .sign = */		ખાલી,
	/* .verify = */		ssh_ecdsa_sk_verify,
};

અચલ સંરચના sshkey_impl sshkey_ecdsa_sk_impl = {
	/* .name = */		"sk-ecdsa-sha2-nistp256@openssh.com",
	/* .shortname = */	"ECDSA-SK",
	/* .sigalg = */		ખાલી,
	/* .type = */		ચાવી_ECDSA_SK,
	/* .nid = */		NID_X9_62_prime256v1,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	256,
	/* .funcs = */		&sshkey_ecdsa_sk_funcs,
};

અચલ સંરચના sshkey_impl sshkey_ecdsa_sk_cert_impl = {
	/* .name = */		"sk-ecdsa-sha2-nistp256-cert-v01@openssh.com",
	/* .shortname = */	"ECDSA-SK-CERT",
	/* .sigalg = */		ખાલી,
	/* .type = */		ચાવી_ECDSA_SK_CERT,
	/* .nid = */		NID_X9_62_prime256v1,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	256,
	/* .funcs = */		&sshkey_ecdsa_sk_funcs,
};

અચલ સંરચના sshkey_impl sshkey_ecdsa_sk_webauthn_impl = {
	/* .name = */		"webauthn-sk-ecdsa-sha2-nistp256@openssh.com",
	/* .shortname = */	"ECDSA-SK",
	/* .sigalg = */		ખાલી,
	/* .type = */		ચાવી_ECDSA_SK,
	/* .nid = */		NID_X9_62_prime256v1,
	/* .cert = */		0,
	/* .sigonly = */	1,
	/* .keybits = */	256,
	/* .funcs = */		&sshkey_ecdsa_sk_funcs,
};

અચલ સંરચના sshkey_impl sshkey_ecdsa_sk_webauthn_cert_impl = {
	/* .name = */		"webauthn-sk-ecdsa-sha2-nistp256-cert-v01@openssh.com",
	/* .shortname = */	"ECDSA-SK-CERT",
	/* .sigalg = */		ખાલી,
	/* .type = */		ચાવી_ECDSA_SK_CERT,
	/* .nid = */		NID_X9_62_prime256v1,
	/* .cert = */		1,
	/* .sigonly = */	1,
	/* .keybits = */	256,
	/* .funcs = */		&sshkey_ecdsa_sk_funcs,
};
#endif /* WITH_OPENSSL */
