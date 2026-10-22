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

#अन्तर्भाव "includes.h"

#अन्तर्भाव <sys/types.h>

#ifdef WITH_OPENSSL
#अन्तर्भाव "openbsd-compat/openssl-compat.h"
#अन्तर्भाव <openssl/bn.h>
#अन्तर्भाव <openssl/ec.h>
#अन्तर्भाव <openssl/ecdsa.h>
#अन्तर्भाव <openssl/evp.h>

#अन्तर्भाव <string.h>
#अन्तर्भाव <stdio.h> /* needed for DEBUG_SK only */

#अन्तर्भाव "sshbuf.h"
#अन्तर्भाव "ssherr.h"
#अन्तर्भाव "digest.h"
#define SSHKEY_INTERNAL
#अन्तर्भाव "sshkey.h"

/* Reuse some ECDSA internals */
बाह्य संरचना sshkey_impl_funcs sshkey_ecdsa_funcs;

स्थिर शून्य
ssh_ecdsa_sk_cleanup(संरचना sshkey *k)
{
	sshkey_sk_cleanup(k);
	sshkey_ecdsa_funcs.cleanup(k);
}

स्थिर पूर्णाङ्क
ssh_ecdsa_sk_equal(ध्रुव संरचना sshkey *a, ध्रुव संरचना sshkey *b)
{
	यदि (!sshkey_sk_fields_equal(a, b))
		प्रत्यागम 0;
	यदि (!sshkey_ecdsa_funcs.equal(a, b))
		प्रत्यागम 0;
	प्रत्यागम 1;
}

स्थिर पूर्णाङ्क
ssh_ecdsa_sk_serialize_public(ध्रुव संरचना sshkey *कुंजी, संरचना sshbuf *b,
    गणना sshkey_serialize_rep opts)
{
	पूर्णाङ्क r;

	यदि ((r = sshkey_ecdsa_funcs.serialize_public(कुंजी, b, opts)) != 0)
		प्रत्यागम r;
	यदि ((r = sshkey_serialize_sk(कुंजी, b)) != 0)
		प्रत्यागम r;

	प्रत्यागम 0;
}

स्थिर पूर्णाङ्क
ssh_ecdsa_sk_serialize_private(ध्रुव संरचना sshkey *कुंजी, संरचना sshbuf *b,
    गणना sshkey_serialize_rep opts)
{
	पूर्णाङ्क r;

	यदि (!sshkey_is_cert(कुंजी)) {
		यदि ((r = sshkey_ecdsa_funcs.serialize_public(कुंजी,
		    b, opts)) != 0)
			प्रत्यागम r;
	}
	यदि ((r = sshkey_serialize_private_sk(कुंजी, b)) != 0)
		प्रत्यागम r;

	प्रत्यागम 0;
}

स्थिर पूर्णाङ्क
ssh_ecdsa_sk_copy_public(ध्रुव संरचना sshkey *from, संरचना sshkey *to)
{
	पूर्णाङ्क r;

	यदि ((r = sshkey_ecdsa_funcs.copy_public(from, to)) != 0)
		प्रत्यागम r;
	यदि ((r = sshkey_copy_public_sk(from, to)) != 0)
		प्रत्यागम r;
	प्रत्यागम 0;
}

स्थिर पूर्णाङ्क
ssh_ecdsa_sk_deserialize_public(ध्रुव वर्ण *ktype, संरचना sshbuf *b,
    संरचना sshkey *कुंजी)
{
	पूर्णाङ्क r;

	यदि ((r = sshkey_ecdsa_funcs.deserialize_public(ktype, b, कुंजी)) != 0)
		प्रत्यागम r;
	यदि ((r = sshkey_deserialize_sk(b, कुंजी)) != 0)
		प्रत्यागम r;
	प्रत्यागम 0;
}

स्थिर पूर्णाङ्क
ssh_ecdsa_sk_deserialize_private(ध्रुव वर्ण *ktype, संरचना sshbuf *b,
    संरचना sshkey *कुंजी)
{
	पूर्णाङ्क r;

	यदि (!sshkey_is_cert(कुंजी)) {
		यदि ((r = sshkey_ecdsa_funcs.deserialize_public(ktype,
		    b, कुंजी)) != 0)
			प्रत्यागम r;
	}
	यदि ((r = sshkey_private_deserialize_sk(b, कुंजी)) != 0)
		प्रत्यागम r;

	प्रत्यागम 0;
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
स्थिर पूर्णाङ्क
webauthn_check_prepare_hash(ध्रुव u_char *data, माप_प्रकार datalen,
    ध्रुव वर्ण *origin, ध्रुव संरचना sshbuf *wrapper,
    uint8_t flags, ध्रुव संरचना sshbuf *extensions,
    u_char *msghash, माप_प्रकार msghashlen)
{
	पूर्णाङ्क r = SSH_ERR_INTERNAL_ERROR;
	संरचना sshbuf *chall = रिक्त, *m = रिक्त;

	यदि ((m = sshbuf_new()) == रिक्त ||
	    (chall = sshbuf_from(data, datalen)) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ out;
	}
	/*
	 * Ensure origin contains no quote character and that the flags are
	 * consistent with what we received
	 */
	यदि (म_अक्षर(origin, '\"') != रिक्त ||
	    (flags & 0x40) != 0 /* AD */ ||
	    ((flags & 0x80) == 0 /* ED */) != (sshbuf_len(extensions) == 0)) {
		r = SSH_ERR_INVALID_FORMAT;
		गच्छ out;
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
	यदि ((r = sshbuf_put(m, WEBAUTHN_0, परिमाण(WEBAUTHN_0) - 1)) != 0 ||
	    (r = sshbuf_dtourlb64(chall, m, 0)) != 0 ||
	    (r = sshbuf_put(m, WEBAUTHN_1, परिमाण(WEBAUTHN_1) - 1)) != 0 ||
	    (r = sshbuf_put(m, origin, म_माप(origin))) != 0 ||
	    (r = sshbuf_put(m, WEBAUTHN_2, परिमाण(WEBAUTHN_2) - 1)) != 0)
		गच्छ out;
#ifdef DEBUG_SK
	ख_लिखो(मानक_त्रुटि, "%s: received origin: %s\n", __func__, origin);
	ख_लिखो(मानक_त्रुटि, "%s: received clientData:\n", __func__);
	sshbuf_dump(wrapper, मानक_त्रुटि);
	ख_लिखो(मानक_त्रुटि, "%s: expected clientData preamble:\n", __func__);
	sshbuf_dump(m, मानक_त्रुटि);
#endif
	/* Check that the supplied clientData has the preamble we expect */
	यदि ((r = sshbuf_cmp(wrapper, 0, sshbuf_ptr(m), sshbuf_len(m))) != 0)
		गच्छ out;

	/* Prepare hash of clientData */
	यदि ((r = ssh_digest_buffer(SSH_DIGEST_SHA256, wrapper,
	    msghash, msghashlen)) != 0)
		गच्छ out;

	/* success */
	r = 0;
 out:
	sshbuf_free(chall);
	sshbuf_free(m);
	प्रत्यागम r;
}

स्थिर पूर्णाङ्क
ssh_ecdsa_sk_verify(ध्रुव संरचना sshkey *कुंजी,
    ध्रुव u_char *sig, माप_प्रकार siglen,
    ध्रुव u_char *data, माप_प्रकार dlen, ध्रुव वर्ण *alg, u_int compat,
    संरचना sshkey_sig_details **detailsp)
{
	ECDSA_SIG *esig = रिक्त;
	EVP_MD_CTX *md_ctx = रिक्त;
	BIGNUM *sig_r = रिक्त, *sig_s = रिक्त;
	u_char sig_flags;
	u_char msghash[32], apphash[32];
	u_int sig_counter;
	u_char *sigb = रिक्त, *cp;
	पूर्णाङ्क is_webauthn = 0, ret = SSH_ERR_INTERNAL_ERROR, len = 0;
	संरचना sshbuf *b = रिक्त, *sigbuf = रिक्त, *original_signed = रिक्त;
	संरचना sshbuf *webauthn_wrapper = रिक्त, *webauthn_exts = रिक्त;
	वर्ण *ktype = रिक्त, *webauthn_origin = रिक्त;
	संरचना sshkey_sig_details *details = रिक्त;
#ifdef DEBUG_SK
	वर्ण *tmp = रिक्त;
#endif

	यदि (detailsp != रिक्त)
		*detailsp = रिक्त;
	यदि (कुंजी == रिक्त || कुंजी->pkey == रिक्त ||
	    sshkey_type_plain(कुंजी->type) != कुंजी_ECDSA_SK ||
	    sig == रिक्त || siglen == 0)
		प्रत्यागम SSH_ERR_INVALID_ARGUMENT;

	यदि (कुंजी->ecdsa_nid != NID_X9_62_prime256v1)
		प्रत्यागम SSH_ERR_INTERNAL_ERROR;

	/* fetch signature */
	यदि ((b = sshbuf_from(sig, siglen)) == रिक्त)
		प्रत्यागम SSH_ERR_ALLOC_FAIL;
	यदि ((details = सुस्मृति(1, परिमाण(*details))) == रिक्त) {
		ret = SSH_ERR_ALLOC_FAIL;
		गच्छ out;
	}
	यदि (sshbuf_get_cstring(b, &ktype, रिक्त) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		गच्छ out;
	}
	यदि (म_भेद(ktype, "webauthn-sk-ecdsa-sha2-nistp256@openssh.com") == 0 ||
	    म_भेद(ktype, "webauthn-sk-ecdsa-sha2-nistp256-cert-v01@openssh.com")
	      == 0)
		is_webauthn = 1;
	अन्यथा यदि (म_भेद(ktype, "sk-ecdsa-sha2-nistp256@openssh.com") != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		गच्छ out;
	}
	यदि (sshbuf_froms(b, &sigbuf) != 0 ||
	    sshbuf_get_u8(b, &sig_flags) != 0 ||
	    sshbuf_get_u32(b, &sig_counter) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		गच्छ out;
	}
	यदि (is_webauthn) {
		यदि (sshbuf_get_cstring(b, &webauthn_origin, रिक्त) != 0 ||
		    sshbuf_froms(b, &webauthn_wrapper) != 0 ||
		    sshbuf_froms(b, &webauthn_exts) != 0) {
			ret = SSH_ERR_INVALID_FORMAT;
			गच्छ out;
		}
	}
	यदि (sshbuf_len(b) != 0) {
		ret = SSH_ERR_UNEXPECTED_TRAILING_DATA;
		गच्छ out;
	}

	/* parse signature */
	यदि (sshbuf_get_bignum2(sigbuf, &sig_r) != 0 ||
	    sshbuf_get_bignum2(sigbuf, &sig_s) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		गच्छ out;
	}
	यदि (sshbuf_len(sigbuf) != 0) {
		ret = SSH_ERR_UNEXPECTED_TRAILING_DATA;
		गच्छ out;
	}

#ifdef DEBUG_SK
	ख_लिखो(मानक_त्रुटि, "%s: data: (len %zu)\n", __func__, dlen);
	/* sshbuf_dump_data(data, datalen, stderr); */
	ख_लिखो(मानक_त्रुटि, "%s: sig_r: %s\n", __func__, (tmp = BN_bn2hex(sig_r)));
	मुक्त(tmp);
	ख_लिखो(मानक_त्रुटि, "%s: sig_s: %s\n", __func__, (tmp = BN_bn2hex(sig_s)));
	मुक्त(tmp);
	ख_लिखो(मानक_त्रुटि, "%s: sig_flags = 0x%02x, sig_counter = %u\n",
	    __func__, sig_flags, sig_counter);
	यदि (is_webauthn) {
		ख_लिखो(मानक_त्रुटि, "%s: webauthn origin: %s\n", __func__,
		    webauthn_origin);
		ख_लिखो(मानक_त्रुटि, "%s: webauthn_wrapper:\n", __func__);
		sshbuf_dump(webauthn_wrapper, मानक_त्रुटि);
	}
#endif
	यदि ((esig = ECDSA_SIG_new()) == रिक्त) {
		ret = SSH_ERR_ALLOC_FAIL;
		गच्छ out;
	}
	यदि (!ECDSA_SIG_set0(esig, sig_r, sig_s)) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		गच्छ out;
	}
	sig_r = sig_s = रिक्त; /* transferred */

	/* Reconstruct data that was supposedly signed */
	यदि ((original_signed = sshbuf_new()) == रिक्त) {
		ret = SSH_ERR_ALLOC_FAIL;
		गच्छ out;
	}
	यदि (is_webauthn) {
		यदि ((ret = webauthn_check_prepare_hash(data, dlen,
		    webauthn_origin, webauthn_wrapper, sig_flags, webauthn_exts,
		    msghash, परिमाण(msghash))) != 0)
			गच्छ out;
	} अन्यथा यदि ((ret = ssh_digest_memory(SSH_DIGEST_SHA256, data, dlen,
	    msghash, परिमाण(msghash))) != 0)
		गच्छ out;
	/* Application value is hashed before signature */
	यदि ((ret = ssh_digest_memory(SSH_DIGEST_SHA256, कुंजी->sk_application,
	    म_माप(कुंजी->sk_application), apphash, परिमाण(apphash))) != 0)
		गच्छ out;
#ifdef DEBUG_SK
	ख_लिखो(मानक_त्रुटि, "%s: hashed application:\n", __func__);
	sshbuf_dump_data(apphash, परिमाण(apphash), मानक_त्रुटि);
	ख_लिखो(मानक_त्रुटि, "%s: hashed message:\n", __func__);
	sshbuf_dump_data(msghash, परिमाण(msghash), मानक_त्रुटि);
#endif
	यदि ((ret = sshbuf_put(original_signed,
	    apphash, परिमाण(apphash))) != 0 ||
	    (ret = sshbuf_put_u8(original_signed, sig_flags)) != 0 ||
	    (ret = sshbuf_put_u32(original_signed, sig_counter)) != 0 ||
	    (ret = sshbuf_putb(original_signed, webauthn_exts)) != 0 ||
	    (ret = sshbuf_put(original_signed, msghash, परिमाण(msghash))) != 0)
		गच्छ out;
	details->sk_counter = sig_counter;
	details->sk_flags = sig_flags;
#ifdef DEBUG_SK
	ख_लिखो(मानक_त्रुटि, "%s: signed buf:\n", __func__);
	sshbuf_dump(original_signed, मानक_त्रुटि);
#endif

	यदि ((md_ctx = EVP_MD_CTX_new()) == रिक्त) {
		ret = SSH_ERR_ALLOC_FAIL;
		गच्छ out;
	}
	यदि ((len = i2d_ECDSA_SIG(esig, रिक्त)) <= 0) {
		len = 0;
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		गच्छ out;
	}
	यदि ((sigb = सुस्मृति(1, len)) == रिक्त) {
		ret = SSH_ERR_ALLOC_FAIL;
		गच्छ out;
	}
	cp = sigb; /* ASN1_item_i2d increments the pointer past the object */
	यदि (i2d_ECDSA_SIG(esig, &cp) != len) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		गच्छ out;
	}
#ifdef DEBUG_SK
	ख_लिखो(मानक_त्रुटि, "%s: signed hash:\n", __func__);
	sshbuf_dump_data(sigb, len, मानक_त्रुटि);
#endif
	/* Verify it */
	यदि (EVP_DigestVerifyInit(md_ctx, रिक्त, EVP_sha256(), रिक्त,
	    कुंजी->pkey) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		गच्छ out;
	}
	विकल्प (EVP_DigestVerify(md_ctx, sigb, len,
	    sshbuf_ptr(original_signed), sshbuf_len(original_signed))) {
	पक्ष 1:
		ret = 0;
		भङ्ग;
	पक्ष 0:
		ret = SSH_ERR_SIGNATURE_INVALID;
		गच्छ out;
	स्वभाव:
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		गच्छ out;
	}
	/* success */
	यदि (detailsp != रिक्त) {
		*detailsp = details;
		details = रिक्त;
	}
 out:
	explicit_bzero(&sig_flags, परिमाण(sig_flags));
	explicit_bzero(&sig_counter, परिमाण(sig_counter));
	explicit_bzero(msghash, परिमाण(msghash));
	explicit_bzero(apphash, परिमाण(apphash));
	sshkey_sig_details_free(details);
	sshbuf_free(webauthn_wrapper);
	sshbuf_free(webauthn_exts);
	मुक्त(webauthn_origin);
	sshbuf_free(original_signed);
	sshbuf_free(sigbuf);
	sshbuf_free(b);
	ECDSA_SIG_free(esig);
	BN_clear_free(sig_r);
	BN_clear_free(sig_s);
	मुक्त(ktype);
	freezero(sigb, len);
	EVP_MD_CTX_free(md_ctx);
	प्रत्यागम ret;
}

स्थिर ध्रुव संरचना sshkey_impl_funcs sshkey_ecdsa_sk_funcs = {
	/* .size = */		रिक्त,
	/* .alloc = */		रिक्त,
	/* .cleanup = */	ssh_ecdsa_sk_cleanup,
	/* .equal = */		ssh_ecdsa_sk_equal,
	/* .ssh_serialize_public = */ ssh_ecdsa_sk_serialize_public,
	/* .ssh_deserialize_public = */ ssh_ecdsa_sk_deserialize_public,
	/* .ssh_serialize_private = */ ssh_ecdsa_sk_serialize_private,
	/* .ssh_deserialize_private = */ ssh_ecdsa_sk_deserialize_private,
	/* .generate = */	रिक्त,
	/* .copy_public = */	ssh_ecdsa_sk_copy_public,
	/* .sign = */		रिक्त,
	/* .verify = */		ssh_ecdsa_sk_verify,
};

ध्रुव संरचना sshkey_impl sshkey_ecdsa_sk_impl = {
	/* .name = */		"sk-ecdsa-sha2-nistp256@openssh.com",
	/* .shortname = */	"ECDSA-SK",
	/* .sigalg = */		रिक्त,
	/* .type = */		कुंजी_ECDSA_SK,
	/* .nid = */		NID_X9_62_prime256v1,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	256,
	/* .funcs = */		&sshkey_ecdsa_sk_funcs,
};

ध्रुव संरचना sshkey_impl sshkey_ecdsa_sk_cert_impl = {
	/* .name = */		"sk-ecdsa-sha2-nistp256-cert-v01@openssh.com",
	/* .shortname = */	"ECDSA-SK-CERT",
	/* .sigalg = */		रिक्त,
	/* .type = */		कुंजी_ECDSA_SK_CERT,
	/* .nid = */		NID_X9_62_prime256v1,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	256,
	/* .funcs = */		&sshkey_ecdsa_sk_funcs,
};

ध्रुव संरचना sshkey_impl sshkey_ecdsa_sk_webauthn_impl = {
	/* .name = */		"webauthn-sk-ecdsa-sha2-nistp256@openssh.com",
	/* .shortname = */	"ECDSA-SK",
	/* .sigalg = */		रिक्त,
	/* .type = */		कुंजी_ECDSA_SK,
	/* .nid = */		NID_X9_62_prime256v1,
	/* .cert = */		0,
	/* .sigonly = */	1,
	/* .keybits = */	256,
	/* .funcs = */		&sshkey_ecdsa_sk_funcs,
};

ध्रुव संरचना sshkey_impl sshkey_ecdsa_sk_webauthn_cert_impl = {
	/* .name = */		"webauthn-sk-ecdsa-sha2-nistp256-cert-v01@openssh.com",
	/* .shortname = */	"ECDSA-SK-CERT",
	/* .sigalg = */		रिक्त,
	/* .type = */		कुंजी_ECDSA_SK_CERT,
	/* .nid = */		NID_X9_62_prime256v1,
	/* .cert = */		1,
	/* .sigonly = */	1,
	/* .keybits = */	256,
	/* .funcs = */		&sshkey_ecdsa_sk_funcs,
};
#endif /* WITH_OPENSSL */
