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

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <sys/types.h>

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL
#ಅನ್ತರ್ಭಾವ "openbsd-compat/openssl-compat.h"
#ಅನ್ತರ್ಭಾವ <openssl/bn.h>
#ಅನ್ತರ್ಭಾವ <openssl/ec.h>
#ಅನ್ತರ್ಭಾವ <openssl/ecdsa.h>
#ಅನ್ತರ್ಭಾವ <openssl/evp.h>

#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <stdio.h> /* needed for DEBUG_SK only */

#ಅನ್ತರ್ಭಾವ "sshbuf.h"
#ಅನ್ತರ್ಭಾವ "ssherr.h"
#ಅನ್ತರ್ಭಾವ "digest.h"
#ವ್ಯಾಖ್ಯಾನಿಸು SSHKEY_ಆಂತರಿಕ
#ಅನ್ತರ್ಭಾವ "sshkey.h"

/* Reuse some ECDSA internals */
ಬಾಹ್ಯ ರಚನೆ sshkey_impl_funcs sshkey_ecdsa_funcs;

ಸ್ಥಿರ ಶೂನ್ಯ
ssh_ecdsa_sk_cleanup(ರಚನೆ sshkey *k)
{
	sshkey_sk_cleanup(k);
	sshkey_ecdsa_funcs.cleanup(k);
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ssh_ecdsa_sk_equal(ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *a, ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *b)
{
	ಆದರೆ (!sshkey_sk_fields_equal(a, b))
		ಹಿಂತಿರುಗಿ 0;
	ಆದರೆ (!sshkey_ecdsa_funcs.equal(a, b))
		ಹಿಂತಿರುಗಿ 0;
	ಹಿಂತಿರುಗಿ 1;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ssh_ecdsa_sk_serialize_ಬಹಿರಂಗ(ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *ಕೀಲಿ, ರಚನೆ sshbuf *b,
    ಎಣಿಕೆ sshkey_serialize_rep opts)
{
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ ((r = sshkey_ecdsa_funcs.serialize_ಬಹಿರಂಗ(ಕೀಲಿ, b, opts)) != 0)
		ಹಿಂತಿರುಗಿ r;
	ಆದರೆ ((r = sshkey_serialize_sk(ಕೀಲಿ, b)) != 0)
		ಹಿಂತಿರುಗಿ r;

	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ssh_ecdsa_sk_serialize_ಖಾಸಗಿ(ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *ಕೀಲಿ, ರಚನೆ sshbuf *b,
    ಎಣಿಕೆ sshkey_serialize_rep opts)
{
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ (!sshkey_is_cert(ಕೀಲಿ)) {
		ಆದರೆ ((r = sshkey_ecdsa_funcs.serialize_ಬಹಿರಂಗ(ಕೀಲಿ,
		    b, opts)) != 0)
			ಹಿಂತಿರುಗಿ r;
	}
	ಆದರೆ ((r = sshkey_serialize_ಖಾಸಗಿ_sk(ಕೀಲಿ, b)) != 0)
		ಹಿಂತಿರುಗಿ r;

	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ssh_ecdsa_sk_copy_ಬಹಿರಂಗ(ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *from, ರಚನೆ sshkey *ಗಮ್ಯ)
{
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ ((r = sshkey_ecdsa_funcs.copy_ಬಹಿರಂಗ(from, ಗಮ್ಯ)) != 0)
		ಹಿಂತಿರುಗಿ r;
	ಆದರೆ ((r = sshkey_copy_ಬಹಿರಂಗ_sk(from, ಗಮ್ಯ)) != 0)
		ಹಿಂತಿರುಗಿ r;
	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ssh_ecdsa_sk_deserialize_ಬಹಿರಂಗ(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ktype, ರಚನೆ sshbuf *b,
    ರಚನೆ sshkey *ಕೀಲಿ)
{
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ ((r = sshkey_ecdsa_funcs.deserialize_ಬಹಿರಂಗ(ktype, b, ಕೀಲಿ)) != 0)
		ಹಿಂತಿರುಗಿ r;
	ಆದರೆ ((r = sshkey_deserialize_sk(b, ಕೀಲಿ)) != 0)
		ಹಿಂತಿರುಗಿ r;
	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ssh_ecdsa_sk_deserialize_ಖಾಸಗಿ(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ktype, ರಚನೆ sshbuf *b,
    ರಚನೆ sshkey *ಕೀಲಿ)
{
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ (!sshkey_is_cert(ಕೀಲಿ)) {
		ಆದರೆ ((r = sshkey_ecdsa_funcs.deserialize_ಬಹಿರಂಗ(ktype,
		    b, ಕೀಲಿ)) != 0)
			ಹಿಂತಿರುಗಿ r;
	}
	ಆದರೆ ((r = sshkey_ಖಾಸಗಿ_deserialize_sk(b, ಕೀಲಿ)) != 0)
		ಹಿಂತಿರುಗಿ r;

	ಹಿಂತಿರುಗಿ 0;
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
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
webauthn_check_prepare_hash(ಸ್ಥಿರಾಂಕ u_char *ದತ್ತಾಂಶ, ಗಾತ್ರ_t datalen,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *origin, ಸ್ಥಿರಾಂಕ ರಚನೆ sshbuf *wrapper,
    uint8_t flags, ಸ್ಥಿರಾಂಕ ರಚನೆ sshbuf *extensions,
    u_char *msghash, ಗಾತ್ರ_t msghashlen)
{
	ಪೂರ್ಣಾಂಕ r = SSH_ERR_ಆಂತರಿಕ_ERROR;
	ರಚನೆ sshbuf *chall = ಖಾಲಿ, *m = ಖಾಲಿ;

	ಆದರೆ ((m = sshbuf_new()) == ಖಾಲಿ ||
	    (chall = sshbuf_from(ದತ್ತಾಂಶ, datalen)) == ಖಾಲಿ) {
		r = SSH_ERR_ALLOC_FAIL;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	/*
	 * Ensure origin contains no quote character and that the flags are
	 * consistent with what we received
	 */
	ಆದರೆ (strchr(origin, '\"') != ಖಾಲಿ ||
	    (flags & 0x40) != 0 /* AD */ ||
	    ((flags & 0x80) == 0 /* ED */) != (sshbuf_len(extensions) == 0)) {
		r = SSH_ERR_INVALID_FORMAT;
		ಹೋಗು ಹೊರಹೋಗು;
	}

	/*
	 * Prepare the preamble to clientData that we expect, poking the
	 * challenge and origin into their canonical positions in the
	 * structure. The crossOrigin flag and any additional extension
	 * fields present are ignored.
	 */
#ವ್ಯಾಖ್ಯಾನಿಸು WEBAUTHN_0	"{\"type\":\"webauthn.get\",\"challenge\":\""
#ವ್ಯಾಖ್ಯಾನಿಸು WEBAUTHN_1	"\",\"origin\":\""
#ವ್ಯಾಖ್ಯಾನಿಸು WEBAUTHN_2	"\""
	ಆದರೆ ((r = sshbuf_put(m, WEBAUTHN_0, ಗಾತ್ರ(WEBAUTHN_0) - 1)) != 0 ||
	    (r = sshbuf_dtourlb64(chall, m, 0)) != 0 ||
	    (r = sshbuf_put(m, WEBAUTHN_1, ಗಾತ್ರ(WEBAUTHN_1) - 1)) != 0 ||
	    (r = sshbuf_put(m, origin, ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(origin))) != 0 ||
	    (r = sshbuf_put(m, WEBAUTHN_2, ಗಾತ್ರ(WEBAUTHN_2) - 1)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ DEBUG_SK
	fprintf(stderr, "%s: received origin: %s\n", __func__, origin);
	fprintf(stderr, "%s: received clientData:\n", __func__);
	sshbuf_dump(wrapper, stderr);
	fprintf(stderr, "%s: expected clientData preamble:\n", __func__);
	sshbuf_dump(m, stderr);
#ಆದರೆ_ಅಂತ್ಯ
	/* Check that the supplied clientData has the preamble we expect */
	ಆದರೆ ((r = sshbuf_cmp(wrapper, 0, sshbuf_ptr(m), sshbuf_len(m))) != 0)
		ಹೋಗು ಹೊರಹೋಗು;

	/* Prepare hash of clientData */
	ಆದರೆ ((r = ssh_digest_ಬಫರ್(SSH_DIGEST_SHA256, wrapper,
	    msghash, msghashlen)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;

	/* success */
	r = 0;
 ಹೊರಹೋಗು:
	sshbuf_free(chall);
	sshbuf_free(m);
	ಹಿಂತಿರುಗಿ r;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ssh_ecdsa_sk_verify(ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *ಕೀಲಿ,
    ಸ್ಥಿರಾಂಕ u_char *sig, ಗಾತ್ರ_t siglen,
    ಸ್ಥಿರಾಂಕ u_char *ದತ್ತಾಂಶ, ಗಾತ್ರ_t dlen, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *alg, u_int compat,
    ರಚನೆ sshkey_sig_details **detailsp)
{
	ECDSA_SIG *esig = ಖಾಲಿ;
	EVP_MD_CTX *md_ctx = ಖಾಲಿ;
	BIGNUM *sig_r = ಖಾಲಿ, *sig_s = ಖಾಲಿ;
	u_char sig_flags;
	u_char msghash[32], apphash[32];
	u_int sig_counter;
	u_char *sigb = ಖಾಲಿ, *cp;
	ಪೂರ್ಣಾಂಕ is_webauthn = 0, ret = SSH_ERR_ಆಂತರಿಕ_ERROR, len = 0;
	ರಚನೆ sshbuf *b = ಖಾಲಿ, *sigbuf = ಖಾಲಿ, *original_signed = ಖಾಲಿ;
	ರಚನೆ sshbuf *webauthn_wrapper = ಖಾಲಿ, *webauthn_exts = ಖಾಲಿ;
	ಅಕ್ಷರ *ktype = ಖಾಲಿ, *webauthn_origin = ಖಾಲಿ;
	ರಚನೆ sshkey_sig_details *details = ಖಾಲಿ;
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ DEBUG_SK
	ಅಕ್ಷರ *tmp = ಖಾಲಿ;
#ಆದರೆ_ಅಂತ್ಯ

	ಆದರೆ (detailsp != ಖಾಲಿ)
		*detailsp = ಖಾಲಿ;
	ಆದರೆ (ಕೀಲಿ == ಖಾಲಿ || ಕೀಲಿ->pkey == ಖಾಲಿ ||
	    sshkey_type_plain(ಕೀಲಿ->type) != ಕೀಲಿ_ECDSA_SK ||
	    sig == ಖಾಲಿ || siglen == 0)
		ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_ವಾದ;

	ಆದರೆ (ಕೀಲಿ->ecdsa_nid != NID_X9_62_prime256v1)
		ಹಿಂತಿರುಗಿ SSH_ERR_ಆಂತರಿಕ_ERROR;

	/* fetch signature */
	ಆದರೆ ((b = sshbuf_from(sig, siglen)) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ SSH_ERR_ALLOC_FAIL;
	ಆದರೆ ((details = ಸೊನ್ನೆ_ಸ್ಮರಣೆ_ಕೊಡು(1, ಗಾತ್ರ(*details))) == ಖಾಲಿ) {
		ret = SSH_ERR_ALLOC_FAIL;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ (sshbuf_get_cstring(b, &ktype, ಖಾಲಿ) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ (strcmp(ktype, "webauthn-sk-ecdsa-sha2-nistp256@openssh.com") == 0 ||
	    strcmp(ktype, "webauthn-sk-ecdsa-sha2-nistp256-cert-v01@openssh.com")
	      == 0)
		is_webauthn = 1;
	ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strcmp(ktype, "sk-ecdsa-sha2-nistp256@openssh.com") != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ (sshbuf_froms(b, &sigbuf) != 0 ||
	    sshbuf_get_u8(b, &sig_flags) != 0 ||
	    sshbuf_get_u32(b, &sig_counter) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ (is_webauthn) {
		ಆದರೆ (sshbuf_get_cstring(b, &webauthn_origin, ಖಾಲಿ) != 0 ||
		    sshbuf_froms(b, &webauthn_wrapper) != 0 ||
		    sshbuf_froms(b, &webauthn_exts) != 0) {
			ret = SSH_ERR_INVALID_FORMAT;
			ಹೋಗು ಹೊರಹೋಗು;
		}
	}
	ಆದರೆ (sshbuf_len(b) != 0) {
		ret = SSH_ERR_UNEXPECTED_TRAILING_ದತ್ತಾಂಶ;
		ಹೋಗು ಹೊರಹೋಗು;
	}

	/* parse signature */
	ಆದರೆ (sshbuf_get_bignum2(sigbuf, &sig_r) != 0 ||
	    sshbuf_get_bignum2(sigbuf, &sig_s) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ (sshbuf_len(sigbuf) != 0) {
		ret = SSH_ERR_UNEXPECTED_TRAILING_ದತ್ತಾಂಶ;
		ಹೋಗು ಹೊರಹೋಗು;
	}

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ DEBUG_SK
	fprintf(stderr, "%s: data: (len %zu)\n", __func__, dlen);
	/* sshbuf_dump_data(data, datalen, stderr); */
	fprintf(stderr, "%s: sig_r: %s\n", __func__, (tmp = BN_bn2hex(sig_r)));
	ಬಿಡುಗಡೆ(tmp);
	fprintf(stderr, "%s: sig_s: %s\n", __func__, (tmp = BN_bn2hex(sig_s)));
	ಬಿಡುಗಡೆ(tmp);
	fprintf(stderr, "%s: sig_flags = 0x%02x, sig_counter = %u\n",
	    __func__, sig_flags, sig_counter);
	ಆದರೆ (is_webauthn) {
		fprintf(stderr, "%s: webauthn origin: %s\n", __func__,
		    webauthn_origin);
		fprintf(stderr, "%s: webauthn_wrapper:\n", __func__);
		sshbuf_dump(webauthn_wrapper, stderr);
	}
#ಆದರೆ_ಅಂತ್ಯ
	ಆದರೆ ((esig = ECDSA_SIG_new()) == ಖಾಲಿ) {
		ret = SSH_ERR_ALLOC_FAIL;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ (!ECDSA_SIG_set0(esig, sig_r, sig_s)) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	sig_r = sig_s = ಖಾಲಿ; /* transferred */

	/* Reconstruct data that was supposedly signed */
	ಆದರೆ ((original_signed = sshbuf_new()) == ಖಾಲಿ) {
		ret = SSH_ERR_ALLOC_FAIL;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ (is_webauthn) {
		ಆದರೆ ((ret = webauthn_check_prepare_hash(ದತ್ತಾಂಶ, dlen,
		    webauthn_origin, webauthn_wrapper, sig_flags, webauthn_exts,
		    msghash, ಗಾತ್ರ(msghash))) != 0)
			ಹೋಗು ಹೊರಹೋಗು;
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ ((ret = ssh_digest_ಸ್ಮರಣೆ(SSH_DIGEST_SHA256, ದತ್ತಾಂಶ, dlen,
	    msghash, ಗಾತ್ರ(msghash))) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
	/* Application value is hashed before signature */
	ಆದರೆ ((ret = ssh_digest_ಸ್ಮರಣೆ(SSH_DIGEST_SHA256, ಕೀಲಿ->sk_application,
	    ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(ಕೀಲಿ->sk_application), apphash, ಗಾತ್ರ(apphash))) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ DEBUG_SK
	fprintf(stderr, "%s: hashed application:\n", __func__);
	sshbuf_dump_ದತ್ತಾಂಶ(apphash, ಗಾತ್ರ(apphash), stderr);
	fprintf(stderr, "%s: hashed message:\n", __func__);
	sshbuf_dump_ದತ್ತಾಂಶ(msghash, ಗಾತ್ರ(msghash), stderr);
#ಆದರೆ_ಅಂತ್ಯ
	ಆದರೆ ((ret = sshbuf_put(original_signed,
	    apphash, ಗಾತ್ರ(apphash))) != 0 ||
	    (ret = sshbuf_put_u8(original_signed, sig_flags)) != 0 ||
	    (ret = sshbuf_put_u32(original_signed, sig_counter)) != 0 ||
	    (ret = sshbuf_putb(original_signed, webauthn_exts)) != 0 ||
	    (ret = sshbuf_put(original_signed, msghash, ಗಾತ್ರ(msghash))) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
	details->sk_counter = sig_counter;
	details->sk_flags = sig_flags;
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ DEBUG_SK
	fprintf(stderr, "%s: signed buf:\n", __func__);
	sshbuf_dump(original_signed, stderr);
#ಆದರೆ_ಅಂತ್ಯ

	ಆದರೆ ((md_ctx = EVP_MD_CTX_new()) == ಖಾಲಿ) {
		ret = SSH_ERR_ALLOC_FAIL;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((len = i2d_ECDSA_SIG(esig, ಖಾಲಿ)) <= 0) {
		len = 0;
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((sigb = ಸೊನ್ನೆ_ಸ್ಮರಣೆ_ಕೊಡು(1, len)) == ಖಾಲಿ) {
		ret = SSH_ERR_ALLOC_FAIL;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	cp = sigb; /* ASN1_item_i2d increments the pointer past the object */
	ಆದರೆ (i2d_ECDSA_SIG(esig, &cp) != len) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		ಹೋಗು ಹೊರಹೋಗು;
	}
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ DEBUG_SK
	fprintf(stderr, "%s: signed hash:\n", __func__);
	sshbuf_dump_ದತ್ತಾಂಶ(sigb, len, stderr);
#ಆದರೆ_ಅಂತ್ಯ
	/* Verify it */
	ಆದರೆ (EVP_DigestVerifyInit(md_ctx, ಖಾಲಿ, EVP_sha256(), ಖಾಲಿ,
	    ಕೀಲಿ->pkey) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆಯ್ಕೆ (EVP_DigestVerify(md_ctx, sigb, len,
	    sshbuf_ptr(original_signed), sshbuf_len(original_signed))) {
	ಸ್ಥಿತಿ 1:
		ret = 0;
		ನಿಲ್ಲಿಸು;
	ಸ್ಥಿತಿ 0:
		ret = SSH_ERR_SIGNATURE_INVALID;
		ಹೋಗು ಹೊರಹೋಗು;
	ಪೂರ್ವನಿಯೋಜಿತ:
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	/* success */
	ಆದರೆ (detailsp != ಖಾಲಿ) {
		*detailsp = details;
		details = ಖಾಲಿ;
	}
 ಹೊರಹೋಗು:
	explicit_bzero(&sig_flags, ಗಾತ್ರ(sig_flags));
	explicit_bzero(&sig_counter, ಗಾತ್ರ(sig_counter));
	explicit_bzero(msghash, ಗಾತ್ರ(msghash));
	explicit_bzero(apphash, ಗಾತ್ರ(apphash));
	sshkey_sig_details_free(details);
	sshbuf_free(webauthn_wrapper);
	sshbuf_free(webauthn_exts);
	ಬಿಡುಗಡೆ(webauthn_origin);
	sshbuf_free(original_signed);
	sshbuf_free(sigbuf);
	sshbuf_free(b);
	ECDSA_SIG_free(esig);
	BN_clear_free(sig_r);
	BN_clear_free(sig_s);
	ಬಿಡುಗಡೆ(ktype);
	freezero(sigb, len);
	EVP_MD_CTX_free(md_ctx);
	ಹಿಂತಿರುಗಿ ret;
}

ಸ್ಥಿರ ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey_impl_funcs sshkey_ecdsa_sk_funcs = {
	/* .size = */		ಖಾಲಿ,
	/* .alloc = */		ಖಾಲಿ,
	/* .cleanup = */	ssh_ecdsa_sk_cleanup,
	/* .equal = */		ssh_ecdsa_sk_equal,
	/* .ssh_serialize_public = */ ssh_ecdsa_sk_serialize_ಬಹಿರಂಗ,
	/* .ssh_deserialize_public = */ ssh_ecdsa_sk_deserialize_ಬಹಿರಂಗ,
	/* .ssh_serialize_private = */ ssh_ecdsa_sk_serialize_ಖಾಸಗಿ,
	/* .ssh_deserialize_private = */ ssh_ecdsa_sk_deserialize_ಖಾಸಗಿ,
	/* .generate = */	ಖಾಲಿ,
	/* .copy_public = */	ssh_ecdsa_sk_copy_ಬಹಿರಂಗ,
	/* .sign = */		ಖಾಲಿ,
	/* .verify = */		ssh_ecdsa_sk_verify,
};

ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey_impl sshkey_ecdsa_sk_impl = {
	/* .name = */		"sk-ecdsa-sha2-nistp256@openssh.com",
	/* .shortname = */	"ECDSA-SK",
	/* .sigalg = */		ಖಾಲಿ,
	/* .type = */		ಕೀಲಿ_ECDSA_SK,
	/* .nid = */		NID_X9_62_prime256v1,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	256,
	/* .funcs = */		&sshkey_ecdsa_sk_funcs,
};

ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey_impl sshkey_ecdsa_sk_cert_impl = {
	/* .name = */		"sk-ecdsa-sha2-nistp256-cert-v01@openssh.com",
	/* .shortname = */	"ECDSA-SK-CERT",
	/* .sigalg = */		ಖಾಲಿ,
	/* .type = */		ಕೀಲಿ_ECDSA_SK_CERT,
	/* .nid = */		NID_X9_62_prime256v1,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	256,
	/* .funcs = */		&sshkey_ecdsa_sk_funcs,
};

ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey_impl sshkey_ecdsa_sk_webauthn_impl = {
	/* .name = */		"webauthn-sk-ecdsa-sha2-nistp256@openssh.com",
	/* .shortname = */	"ECDSA-SK",
	/* .sigalg = */		ಖಾಲಿ,
	/* .type = */		ಕೀಲಿ_ECDSA_SK,
	/* .nid = */		NID_X9_62_prime256v1,
	/* .cert = */		0,
	/* .sigonly = */	1,
	/* .keybits = */	256,
	/* .funcs = */		&sshkey_ecdsa_sk_funcs,
};

ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey_impl sshkey_ecdsa_sk_webauthn_cert_impl = {
	/* .name = */		"webauthn-sk-ecdsa-sha2-nistp256-cert-v01@openssh.com",
	/* .shortname = */	"ECDSA-SK-CERT",
	/* .sigalg = */		ಖಾಲಿ,
	/* .type = */		ಕೀಲಿ_ECDSA_SK_CERT,
	/* .nid = */		NID_X9_62_prime256v1,
	/* .cert = */		1,
	/* .sigonly = */	1,
	/* .keybits = */	256,
	/* .funcs = */		&sshkey_ecdsa_sk_funcs,
};
#ಆದರೆ_ಅಂತ್ಯ /* WITH_OPENSSL */
