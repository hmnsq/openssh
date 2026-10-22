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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
#ਅਨ੍ਤਰ੍ਭਾਵ "openbsd-compat/openssl-compat.h"
#ਅਨ੍ਤਰ੍ਭਾਵ <openssl/bn.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <openssl/ec.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <openssl/ecdsa.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <openssl/evp.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h> /* needed for DEBUG_SK only */

#ਅਨ੍ਤਰ੍ਭਾਵ "sshbuf.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssherr.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "digest.h"
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHKEY_ਅੰਦਰੂਨੀ
#ਅਨ੍ਤਰ੍ਭਾਵ "sshkey.h"

/* Reuse some ECDSA internals */
ਬਾਹਰੀ ਬਣਤਰ sshkey_impl_funcs sshkey_ecdsa_funcs;

ਸਥਿਰ ਖਾਲੀ
ssh_ecdsa_sk_cleanup(ਬਣਤਰ sshkey *k)
{
	sshkey_sk_cleanup(k);
	sshkey_ecdsa_funcs.cleanup(k);
}

ਸਥਿਰ ਪੂਰਨ
ssh_ecdsa_sk_equal(ਅਚਲ ਬਣਤਰ sshkey *a, ਅਚਲ ਬਣਤਰ sshkey *b)
{
	ਜੇ (!sshkey_sk_fields_equal(a, b))
		ਵਾਪਸ 0;
	ਜੇ (!sshkey_ecdsa_funcs.equal(a, b))
		ਵਾਪਸ 0;
	ਵਾਪਸ 1;
}

ਸਥਿਰ ਪੂਰਨ
ssh_ecdsa_sk_serialize_ਜਨਤਕ(ਅਚਲ ਬਣਤਰ sshkey *ਕੁੰਜੀ, ਬਣਤਰ sshbuf *b,
    ਗਿਣਤੀ sshkey_serialize_rep opts)
{
	ਪੂਰਨ r;

	ਜੇ ((r = sshkey_ecdsa_funcs.serialize_ਜਨਤਕ(ਕੁੰਜੀ, b, opts)) != 0)
		ਵਾਪਸ r;
	ਜੇ ((r = sshkey_serialize_sk(ਕੁੰਜੀ, b)) != 0)
		ਵਾਪਸ r;

	ਵਾਪਸ 0;
}

ਸਥਿਰ ਪੂਰਨ
ssh_ecdsa_sk_serialize_ਨਿੱਜੀ(ਅਚਲ ਬਣਤਰ sshkey *ਕੁੰਜੀ, ਬਣਤਰ sshbuf *b,
    ਗਿਣਤੀ sshkey_serialize_rep opts)
{
	ਪੂਰਨ r;

	ਜੇ (!sshkey_is_cert(ਕੁੰਜੀ)) {
		ਜੇ ((r = sshkey_ecdsa_funcs.serialize_ਜਨਤਕ(ਕੁੰਜੀ,
		    b, opts)) != 0)
			ਵਾਪਸ r;
	}
	ਜੇ ((r = sshkey_serialize_ਨਿੱਜੀ_sk(ਕੁੰਜੀ, b)) != 0)
		ਵਾਪਸ r;

	ਵਾਪਸ 0;
}

ਸਥਿਰ ਪੂਰਨ
ssh_ecdsa_sk_copy_ਜਨਤਕ(ਅਚਲ ਬਣਤਰ sshkey *from, ਬਣਤਰ sshkey *ਮੰਜ਼ਿਲ)
{
	ਪੂਰਨ r;

	ਜੇ ((r = sshkey_ecdsa_funcs.copy_ਜਨਤਕ(from, ਮੰਜ਼ਿਲ)) != 0)
		ਵਾਪਸ r;
	ਜੇ ((r = sshkey_copy_ਜਨਤਕ_sk(from, ਮੰਜ਼ਿਲ)) != 0)
		ਵਾਪਸ r;
	ਵਾਪਸ 0;
}

ਸਥਿਰ ਪੂਰਨ
ssh_ecdsa_sk_deserialize_ਜਨਤਕ(ਅਚਲ ਅੱਖਰ *ktype, ਬਣਤਰ sshbuf *b,
    ਬਣਤਰ sshkey *ਕੁੰਜੀ)
{
	ਪੂਰਨ r;

	ਜੇ ((r = sshkey_ecdsa_funcs.deserialize_ਜਨਤਕ(ktype, b, ਕੁੰਜੀ)) != 0)
		ਵਾਪਸ r;
	ਜੇ ((r = sshkey_deserialize_sk(b, ਕੁੰਜੀ)) != 0)
		ਵਾਪਸ r;
	ਵਾਪਸ 0;
}

ਸਥਿਰ ਪੂਰਨ
ssh_ecdsa_sk_deserialize_ਨਿੱਜੀ(ਅਚਲ ਅੱਖਰ *ktype, ਬਣਤਰ sshbuf *b,
    ਬਣਤਰ sshkey *ਕੁੰਜੀ)
{
	ਪੂਰਨ r;

	ਜੇ (!sshkey_is_cert(ਕੁੰਜੀ)) {
		ਜੇ ((r = sshkey_ecdsa_funcs.deserialize_ਜਨਤਕ(ktype,
		    b, ਕੁੰਜੀ)) != 0)
			ਵਾਪਸ r;
	}
	ਜੇ ((r = sshkey_ਨਿੱਜੀ_deserialize_sk(b, ਕੁੰਜੀ)) != 0)
		ਵਾਪਸ r;

	ਵਾਪਸ 0;
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
ਸਥਿਰ ਪੂਰਨ
webauthn_check_prepare_hash(ਅਚਲ u_char *ਅੰਕੜੇ, ਮਾਪ_t datalen,
    ਅਚਲ ਅੱਖਰ *origin, ਅਚਲ ਬਣਤਰ sshbuf *wrapper,
    uint8_t flags, ਅਚਲ ਬਣਤਰ sshbuf *extensions,
    u_char *msghash, ਮਾਪ_t msghashlen)
{
	ਪੂਰਨ r = SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;
	ਬਣਤਰ sshbuf *chall = ਨਿਰਾ, *m = ਨਿਰਾ;

	ਜੇ ((m = sshbuf_new()) == ਨਿਰਾ ||
	    (chall = sshbuf_from(ਅੰਕੜੇ, datalen)) == ਨਿਰਾ) {
		r = SSH_ERR_ALLOC_FAIL;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	/*
	 * Ensure origin contains no quote character and that the flags are
	 * consistent with what we received
	 */
	ਜੇ (strchr(origin, '\"') != ਨਿਰਾ ||
	    (flags & 0x40) != 0 /* AD */ ||
	    ((flags & 0x80) == 0 /* ED */) != (sshbuf_len(extensions) == 0)) {
		r = SSH_ERR_INVALID_FORMAT;
		ਜਾਓ ਬਾਹਰਲਾ;
	}

	/*
	 * Prepare the preamble to clientData that we expect, poking the
	 * challenge and origin into their canonical positions in the
	 * structure. The crossOrigin flag and any additional extension
	 * fields present are ignored.
	 */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ WEBAUTHN_0	"{\"type\":\"webauthn.get\",\"challenge\":\""
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ WEBAUTHN_1	"\",\"origin\":\""
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ WEBAUTHN_2	"\""
	ਜੇ ((r = sshbuf_put(m, WEBAUTHN_0, ਆਕਾਰ(WEBAUTHN_0) - 1)) != 0 ||
	    (r = sshbuf_dtourlb64(chall, m, 0)) != 0 ||
	    (r = sshbuf_put(m, WEBAUTHN_1, ਆਕਾਰ(WEBAUTHN_1) - 1)) != 0 ||
	    (r = sshbuf_put(m, origin, ਲੜੀ_ਲੰਬਾਈ(origin))) != 0 ||
	    (r = sshbuf_put(m, WEBAUTHN_2, ਆਕਾਰ(WEBAUTHN_2) - 1)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ DEBUG_SK
	fprintf(stderr, "%s: received origin: %s\n", __func__, origin);
	fprintf(stderr, "%s: received clientData:\n", __func__);
	sshbuf_dump(wrapper, stderr);
	fprintf(stderr, "%s: expected clientData preamble:\n", __func__);
	sshbuf_dump(m, stderr);
#ਜੇ_ਅੰਤ
	/* Check that the supplied clientData has the preamble we expect */
	ਜੇ ((r = sshbuf_cmp(wrapper, 0, sshbuf_ptr(m), sshbuf_len(m))) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;

	/* Prepare hash of clientData */
	ਜੇ ((r = ssh_digest_ਬਫਰ(SSH_DIGEST_SHA256, wrapper,
	    msghash, msghashlen)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;

	/* success */
	r = 0;
 ਬਾਹਰਲਾ:
	sshbuf_free(chall);
	sshbuf_free(m);
	ਵਾਪਸ r;
}

ਸਥਿਰ ਪੂਰਨ
ssh_ecdsa_sk_verify(ਅਚਲ ਬਣਤਰ sshkey *ਕੁੰਜੀ,
    ਅਚਲ u_char *sig, ਮਾਪ_t siglen,
    ਅਚਲ u_char *ਅੰਕੜੇ, ਮਾਪ_t dlen, ਅਚਲ ਅੱਖਰ *alg, u_int compat,
    ਬਣਤਰ sshkey_sig_details **detailsp)
{
	ECDSA_SIG *esig = ਨਿਰਾ;
	EVP_MD_CTX *md_ctx = ਨਿਰਾ;
	BIGNUM *sig_r = ਨਿਰਾ, *sig_s = ਨਿਰਾ;
	u_char sig_flags;
	u_char msghash[32], apphash[32];
	u_int sig_counter;
	u_char *sigb = ਨਿਰਾ, *cp;
	ਪੂਰਨ is_webauthn = 0, ret = SSH_ERR_ਅੰਦਰੂਨੀ_ERROR, len = 0;
	ਬਣਤਰ sshbuf *b = ਨਿਰਾ, *sigbuf = ਨਿਰਾ, *original_signed = ਨਿਰਾ;
	ਬਣਤਰ sshbuf *webauthn_wrapper = ਨਿਰਾ, *webauthn_exts = ਨਿਰਾ;
	ਅੱਖਰ *ktype = ਨਿਰਾ, *webauthn_origin = ਨਿਰਾ;
	ਬਣਤਰ sshkey_sig_details *details = ਨਿਰਾ;
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ DEBUG_SK
	ਅੱਖਰ *tmp = ਨਿਰਾ;
#ਜੇ_ਅੰਤ

	ਜੇ (detailsp != ਨਿਰਾ)
		*detailsp = ਨਿਰਾ;
	ਜੇ (ਕੁੰਜੀ == ਨਿਰਾ || ਕੁੰਜੀ->pkey == ਨਿਰਾ ||
	    sshkey_type_plain(ਕੁੰਜੀ->type) != ਕੁੰਜੀ_ECDSA_SK ||
	    sig == ਨਿਰਾ || siglen == 0)
		ਵਾਪਸ SSH_ERR_INVALID_ਦਲੀਲ;

	ਜੇ (ਕੁੰਜੀ->ecdsa_nid != NID_X9_62_prime256v1)
		ਵਾਪਸ SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;

	/* fetch signature */
	ਜੇ ((b = sshbuf_from(sig, siglen)) == ਨਿਰਾ)
		ਵਾਪਸ SSH_ERR_ALLOC_FAIL;
	ਜੇ ((details = ਸਿਫਰ_ਸਮ੍ਰਿਤੀ_ਦਿਓ(1, ਆਕਾਰ(*details))) == ਨਿਰਾ) {
		ret = SSH_ERR_ALLOC_FAIL;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ (sshbuf_get_cstring(b, &ktype, ਨਿਰਾ) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ (strcmp(ktype, "webauthn-sk-ecdsa-sha2-nistp256@openssh.com") == 0 ||
	    strcmp(ktype, "webauthn-sk-ecdsa-sha2-nistp256-cert-v01@openssh.com")
	      == 0)
		is_webauthn = 1;
	ਨਹੀਂਤਾਂ ਜੇ (strcmp(ktype, "sk-ecdsa-sha2-nistp256@openssh.com") != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ (sshbuf_froms(b, &sigbuf) != 0 ||
	    sshbuf_get_u8(b, &sig_flags) != 0 ||
	    sshbuf_get_u32(b, &sig_counter) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ (is_webauthn) {
		ਜੇ (sshbuf_get_cstring(b, &webauthn_origin, ਨਿਰਾ) != 0 ||
		    sshbuf_froms(b, &webauthn_wrapper) != 0 ||
		    sshbuf_froms(b, &webauthn_exts) != 0) {
			ret = SSH_ERR_INVALID_FORMAT;
			ਜਾਓ ਬਾਹਰਲਾ;
		}
	}
	ਜੇ (sshbuf_len(b) != 0) {
		ret = SSH_ERR_UNEXPECTED_TRAILING_ਅੰਕੜੇ;
		ਜਾਓ ਬਾਹਰਲਾ;
	}

	/* parse signature */
	ਜੇ (sshbuf_get_bignum2(sigbuf, &sig_r) != 0 ||
	    sshbuf_get_bignum2(sigbuf, &sig_s) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ (sshbuf_len(sigbuf) != 0) {
		ret = SSH_ERR_UNEXPECTED_TRAILING_ਅੰਕੜੇ;
		ਜਾਓ ਬਾਹਰਲਾ;
	}

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ DEBUG_SK
	fprintf(stderr, "%s: data: (len %zu)\n", __func__, dlen);
	/* sshbuf_dump_data(data, datalen, stderr); */
	fprintf(stderr, "%s: sig_r: %s\n", __func__, (tmp = BN_bn2hex(sig_r)));
	ਮੁਕਤ(tmp);
	fprintf(stderr, "%s: sig_s: %s\n", __func__, (tmp = BN_bn2hex(sig_s)));
	ਮੁਕਤ(tmp);
	fprintf(stderr, "%s: sig_flags = 0x%02x, sig_counter = %u\n",
	    __func__, sig_flags, sig_counter);
	ਜੇ (is_webauthn) {
		fprintf(stderr, "%s: webauthn origin: %s\n", __func__,
		    webauthn_origin);
		fprintf(stderr, "%s: webauthn_wrapper:\n", __func__);
		sshbuf_dump(webauthn_wrapper, stderr);
	}
#ਜੇ_ਅੰਤ
	ਜੇ ((esig = ECDSA_SIG_new()) == ਨਿਰਾ) {
		ret = SSH_ERR_ALLOC_FAIL;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ (!ECDSA_SIG_set0(esig, sig_r, sig_s)) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	sig_r = sig_s = ਨਿਰਾ; /* transferred */

	/* Reconstruct data that was supposedly signed */
	ਜੇ ((original_signed = sshbuf_new()) == ਨਿਰਾ) {
		ret = SSH_ERR_ALLOC_FAIL;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ (is_webauthn) {
		ਜੇ ((ret = webauthn_check_prepare_hash(ਅੰਕੜੇ, dlen,
		    webauthn_origin, webauthn_wrapper, sig_flags, webauthn_exts,
		    msghash, ਆਕਾਰ(msghash))) != 0)
			ਜਾਓ ਬਾਹਰਲਾ;
	} ਨਹੀਂਤਾਂ ਜੇ ((ret = ssh_digest_ਸਮ੍ਰਿਤੀ(SSH_DIGEST_SHA256, ਅੰਕੜੇ, dlen,
	    msghash, ਆਕਾਰ(msghash))) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	/* Application value is hashed before signature */
	ਜੇ ((ret = ssh_digest_ਸਮ੍ਰਿਤੀ(SSH_DIGEST_SHA256, ਕੁੰਜੀ->sk_application,
	    ਲੜੀ_ਲੰਬਾਈ(ਕੁੰਜੀ->sk_application), apphash, ਆਕਾਰ(apphash))) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ DEBUG_SK
	fprintf(stderr, "%s: hashed application:\n", __func__);
	sshbuf_dump_ਅੰਕੜੇ(apphash, ਆਕਾਰ(apphash), stderr);
	fprintf(stderr, "%s: hashed message:\n", __func__);
	sshbuf_dump_ਅੰਕੜੇ(msghash, ਆਕਾਰ(msghash), stderr);
#ਜੇ_ਅੰਤ
	ਜੇ ((ret = sshbuf_put(original_signed,
	    apphash, ਆਕਾਰ(apphash))) != 0 ||
	    (ret = sshbuf_put_u8(original_signed, sig_flags)) != 0 ||
	    (ret = sshbuf_put_u32(original_signed, sig_counter)) != 0 ||
	    (ret = sshbuf_putb(original_signed, webauthn_exts)) != 0 ||
	    (ret = sshbuf_put(original_signed, msghash, ਆਕਾਰ(msghash))) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	details->sk_counter = sig_counter;
	details->sk_flags = sig_flags;
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ DEBUG_SK
	fprintf(stderr, "%s: signed buf:\n", __func__);
	sshbuf_dump(original_signed, stderr);
#ਜੇ_ਅੰਤ

	ਜੇ ((md_ctx = EVP_MD_CTX_new()) == ਨਿਰਾ) {
		ret = SSH_ERR_ALLOC_FAIL;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((len = i2d_ECDSA_SIG(esig, ਨਿਰਾ)) <= 0) {
		len = 0;
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((sigb = ਸਿਫਰ_ਸਮ੍ਰਿਤੀ_ਦਿਓ(1, len)) == ਨਿਰਾ) {
		ret = SSH_ERR_ALLOC_FAIL;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	cp = sigb; /* ASN1_item_i2d increments the pointer past the object */
	ਜੇ (i2d_ECDSA_SIG(esig, &cp) != len) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ DEBUG_SK
	fprintf(stderr, "%s: signed hash:\n", __func__);
	sshbuf_dump_ਅੰਕੜੇ(sigb, len, stderr);
#ਜੇ_ਅੰਤ
	/* Verify it */
	ਜੇ (EVP_DigestVerifyInit(md_ctx, ਨਿਰਾ, EVP_sha256(), ਨਿਰਾ,
	    ਕੁੰਜੀ->pkey) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਚੋਣ (EVP_DigestVerify(md_ctx, sigb, len,
	    sshbuf_ptr(original_signed), sshbuf_len(original_signed))) {
	ਹਾਲਤ 1:
		ret = 0;
		ਰੋਕੋ;
	ਹਾਲਤ 0:
		ret = SSH_ERR_SIGNATURE_INVALID;
		ਜਾਓ ਬਾਹਰਲਾ;
	ਮੂਲ:
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	/* success */
	ਜੇ (detailsp != ਨਿਰਾ) {
		*detailsp = details;
		details = ਨਿਰਾ;
	}
 ਬਾਹਰਲਾ:
	explicit_bzero(&sig_flags, ਆਕਾਰ(sig_flags));
	explicit_bzero(&sig_counter, ਆਕਾਰ(sig_counter));
	explicit_bzero(msghash, ਆਕਾਰ(msghash));
	explicit_bzero(apphash, ਆਕਾਰ(apphash));
	sshkey_sig_details_free(details);
	sshbuf_free(webauthn_wrapper);
	sshbuf_free(webauthn_exts);
	ਮੁਕਤ(webauthn_origin);
	sshbuf_free(original_signed);
	sshbuf_free(sigbuf);
	sshbuf_free(b);
	ECDSA_SIG_free(esig);
	BN_clear_free(sig_r);
	BN_clear_free(sig_s);
	ਮੁਕਤ(ktype);
	freezero(sigb, len);
	EVP_MD_CTX_free(md_ctx);
	ਵਾਪਸ ret;
}

ਸਥਿਰ ਅਚਲ ਬਣਤਰ sshkey_impl_funcs sshkey_ecdsa_sk_funcs = {
	/* .size = */		ਨਿਰਾ,
	/* .alloc = */		ਨਿਰਾ,
	/* .cleanup = */	ssh_ecdsa_sk_cleanup,
	/* .equal = */		ssh_ecdsa_sk_equal,
	/* .ssh_serialize_public = */ ssh_ecdsa_sk_serialize_ਜਨਤਕ,
	/* .ssh_deserialize_public = */ ssh_ecdsa_sk_deserialize_ਜਨਤਕ,
	/* .ssh_serialize_private = */ ssh_ecdsa_sk_serialize_ਨਿੱਜੀ,
	/* .ssh_deserialize_private = */ ssh_ecdsa_sk_deserialize_ਨਿੱਜੀ,
	/* .generate = */	ਨਿਰਾ,
	/* .copy_public = */	ssh_ecdsa_sk_copy_ਜਨਤਕ,
	/* .sign = */		ਨਿਰਾ,
	/* .verify = */		ssh_ecdsa_sk_verify,
};

ਅਚਲ ਬਣਤਰ sshkey_impl sshkey_ecdsa_sk_impl = {
	/* .name = */		"sk-ecdsa-sha2-nistp256@openssh.com",
	/* .shortname = */	"ECDSA-SK",
	/* .sigalg = */		ਨਿਰਾ,
	/* .type = */		ਕੁੰਜੀ_ECDSA_SK,
	/* .nid = */		NID_X9_62_prime256v1,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	256,
	/* .funcs = */		&sshkey_ecdsa_sk_funcs,
};

ਅਚਲ ਬਣਤਰ sshkey_impl sshkey_ecdsa_sk_cert_impl = {
	/* .name = */		"sk-ecdsa-sha2-nistp256-cert-v01@openssh.com",
	/* .shortname = */	"ECDSA-SK-CERT",
	/* .sigalg = */		ਨਿਰਾ,
	/* .type = */		ਕੁੰਜੀ_ECDSA_SK_CERT,
	/* .nid = */		NID_X9_62_prime256v1,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	256,
	/* .funcs = */		&sshkey_ecdsa_sk_funcs,
};

ਅਚਲ ਬਣਤਰ sshkey_impl sshkey_ecdsa_sk_webauthn_impl = {
	/* .name = */		"webauthn-sk-ecdsa-sha2-nistp256@openssh.com",
	/* .shortname = */	"ECDSA-SK",
	/* .sigalg = */		ਨਿਰਾ,
	/* .type = */		ਕੁੰਜੀ_ECDSA_SK,
	/* .nid = */		NID_X9_62_prime256v1,
	/* .cert = */		0,
	/* .sigonly = */	1,
	/* .keybits = */	256,
	/* .funcs = */		&sshkey_ecdsa_sk_funcs,
};

ਅਚਲ ਬਣਤਰ sshkey_impl sshkey_ecdsa_sk_webauthn_cert_impl = {
	/* .name = */		"webauthn-sk-ecdsa-sha2-nistp256-cert-v01@openssh.com",
	/* .shortname = */	"ECDSA-SK-CERT",
	/* .sigalg = */		ਨਿਰਾ,
	/* .type = */		ਕੁੰਜੀ_ECDSA_SK_CERT,
	/* .nid = */		NID_X9_62_prime256v1,
	/* .cert = */		1,
	/* .sigonly = */	1,
	/* .keybits = */	256,
	/* .funcs = */		&sshkey_ecdsa_sk_funcs,
};
#ਜੇ_ਅੰਤ /* WITH_OPENSSL */
