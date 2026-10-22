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

स्थिर पूर्णांक
ssh_ecdsa_sk_equal(स्थिरांक संरचना sshkey *a, स्थिरांक संरचना sshkey *b)
{
	जर (!sshkey_sk_fields_equal(a, b))
		परत 0;
	जर (!sshkey_ecdsa_funcs.equal(a, b))
		परत 0;
	परत 1;
}

स्थिर पूर्णांक
ssh_ecdsa_sk_serialize_public(स्थिरांक संरचना sshkey *किल्ली, संरचना sshbuf *b,
    गणना sshkey_serialize_rep opts)
{
	पूर्णांक r;

	जर ((r = sshkey_ecdsa_funcs.serialize_public(किल्ली, b, opts)) != 0)
		परत r;
	जर ((r = sshkey_serialize_sk(किल्ली, b)) != 0)
		परत r;

	परत 0;
}

स्थिर पूर्णांक
ssh_ecdsa_sk_serialize_private(स्थिरांक संरचना sshkey *किल्ली, संरचना sshbuf *b,
    गणना sshkey_serialize_rep opts)
{
	पूर्णांक r;

	जर (!sshkey_is_cert(किल्ली)) {
		जर ((r = sshkey_ecdsa_funcs.serialize_public(किल्ली,
		    b, opts)) != 0)
			परत r;
	}
	जर ((r = sshkey_serialize_private_sk(किल्ली, b)) != 0)
		परत r;

	परत 0;
}

स्थिर पूर्णांक
ssh_ecdsa_sk_copy_public(स्थिरांक संरचना sshkey *from, संरचना sshkey *to)
{
	पूर्णांक r;

	जर ((r = sshkey_ecdsa_funcs.copy_public(from, to)) != 0)
		परत r;
	जर ((r = sshkey_copy_public_sk(from, to)) != 0)
		परत r;
	परत 0;
}

स्थिर पूर्णांक
ssh_ecdsa_sk_deserialize_public(स्थिरांक अक्षर *ktype, संरचना sshbuf *b,
    संरचना sshkey *किल्ली)
{
	पूर्णांक r;

	जर ((r = sshkey_ecdsa_funcs.deserialize_public(ktype, b, किल्ली)) != 0)
		परत r;
	जर ((r = sshkey_deserialize_sk(b, किल्ली)) != 0)
		परत r;
	परत 0;
}

स्थिर पूर्णांक
ssh_ecdsa_sk_deserialize_private(स्थिरांक अक्षर *ktype, संरचना sshbuf *b,
    संरचना sshkey *किल्ली)
{
	पूर्णांक r;

	जर (!sshkey_is_cert(किल्ली)) {
		जर ((r = sshkey_ecdsa_funcs.deserialize_public(ktype,
		    b, किल्ली)) != 0)
			परत r;
	}
	जर ((r = sshkey_private_deserialize_sk(b, किल्ली)) != 0)
		परत r;

	परत 0;
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
स्थिर पूर्णांक
webauthn_check_prepare_hash(स्थिरांक u_char *data, माप_प्रकार datalen,
    स्थिरांक अक्षर *origin, स्थिरांक संरचना sshbuf *wrapper,
    uint8_t flags, स्थिरांक संरचना sshbuf *extensions,
    u_char *msghash, माप_प्रकार msghashlen)
{
	पूर्णांक r = SSH_ERR_INTERNAL_ERROR;
	संरचना sshbuf *chall = रिक्त, *m = रिक्त;

	जर ((m = sshbuf_new()) == रिक्त ||
	    (chall = sshbuf_from(data, datalen)) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		जा out;
	}
	/*
	 * Ensure origin contains no quote character and that the flags are
	 * consistent with what we received
	 */
	जर (म_अक्षर(origin, '\"') != रिक्त ||
	    (flags & 0x40) != 0 /* AD */ ||
	    ((flags & 0x80) == 0 /* ED */) != (sshbuf_len(extensions) == 0)) {
		r = SSH_ERR_INVALID_FORMAT;
		जा out;
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
	जर ((r = sshbuf_put(m, WEBAUTHN_0, आकार(WEBAUTHN_0) - 1)) != 0 ||
	    (r = sshbuf_dtourlb64(chall, m, 0)) != 0 ||
	    (r = sshbuf_put(m, WEBAUTHN_1, आकार(WEBAUTHN_1) - 1)) != 0 ||
	    (r = sshbuf_put(m, origin, म_माप(origin))) != 0 ||
	    (r = sshbuf_put(m, WEBAUTHN_2, आकार(WEBAUTHN_2) - 1)) != 0)
		जा out;
#ifdef DEBUG_SK
	ख_लिखो(मानक_त्रुटि, "%s: received origin: %s\n", __func__, origin);
	ख_लिखो(मानक_त्रुटि, "%s: received clientData:\n", __func__);
	sshbuf_dump(wrapper, मानक_त्रुटि);
	ख_लिखो(मानक_त्रुटि, "%s: expected clientData preamble:\n", __func__);
	sshbuf_dump(m, मानक_त्रुटि);
#endif
	/* Check that the supplied clientData has the preamble we expect */
	जर ((r = sshbuf_cmp(wrapper, 0, sshbuf_ptr(m), sshbuf_len(m))) != 0)
		जा out;

	/* Prepare hash of clientData */
	जर ((r = ssh_digest_buffer(SSH_DIGEST_SHA256, wrapper,
	    msghash, msghashlen)) != 0)
		जा out;

	/* success */
	r = 0;
 out:
	sshbuf_free(chall);
	sshbuf_free(m);
	परत r;
}

स्थिर पूर्णांक
ssh_ecdsa_sk_verify(स्थिरांक संरचना sshkey *किल्ली,
    स्थिरांक u_char *sig, माप_प्रकार siglen,
    स्थिरांक u_char *data, माप_प्रकार dlen, स्थिरांक अक्षर *alg, u_int compat,
    संरचना sshkey_sig_details **detailsp)
{
	ECDSA_SIG *esig = रिक्त;
	EVP_MD_CTX *md_ctx = रिक्त;
	BIGNUM *sig_r = रिक्त, *sig_s = रिक्त;
	u_char sig_flags;
	u_char msghash[32], apphash[32];
	u_int sig_counter;
	u_char *sigb = रिक्त, *cp;
	पूर्णांक is_webauthn = 0, ret = SSH_ERR_INTERNAL_ERROR, len = 0;
	संरचना sshbuf *b = रिक्त, *sigbuf = रिक्त, *original_signed = रिक्त;
	संरचना sshbuf *webauthn_wrapper = रिक्त, *webauthn_exts = रिक्त;
	अक्षर *ktype = रिक्त, *webauthn_origin = रिक्त;
	संरचना sshkey_sig_details *details = रिक्त;
#ifdef DEBUG_SK
	अक्षर *tmp = रिक्त;
#endif

	जर (detailsp != रिक्त)
		*detailsp = रिक्त;
	जर (किल्ली == रिक्त || किल्ली->pkey == रिक्त ||
	    sshkey_type_plain(किल्ली->type) != किल्ली_ECDSA_SK ||
	    sig == रिक्त || siglen == 0)
		परत SSH_ERR_INVALID_ARGUMENT;

	जर (किल्ली->ecdsa_nid != NID_X9_62_prime256v1)
		परत SSH_ERR_INTERNAL_ERROR;

	/* fetch signature */
	जर ((b = sshbuf_from(sig, siglen)) == रिक्त)
		परत SSH_ERR_ALLOC_FAIL;
	जर ((details = सुस्मृति(1, आकार(*details))) == रिक्त) {
		ret = SSH_ERR_ALLOC_FAIL;
		जा out;
	}
	जर (sshbuf_get_cstring(b, &ktype, रिक्त) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		जा out;
	}
	जर (म_भेद(ktype, "webauthn-sk-ecdsa-sha2-nistp256@openssh.com") == 0 ||
	    म_भेद(ktype, "webauthn-sk-ecdsa-sha2-nistp256-cert-v01@openssh.com")
	      == 0)
		is_webauthn = 1;
	अन्यथा जर (म_भेद(ktype, "sk-ecdsa-sha2-nistp256@openssh.com") != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		जा out;
	}
	जर (sshbuf_froms(b, &sigbuf) != 0 ||
	    sshbuf_get_u8(b, &sig_flags) != 0 ||
	    sshbuf_get_u32(b, &sig_counter) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		जा out;
	}
	जर (is_webauthn) {
		जर (sshbuf_get_cstring(b, &webauthn_origin, रिक्त) != 0 ||
		    sshbuf_froms(b, &webauthn_wrapper) != 0 ||
		    sshbuf_froms(b, &webauthn_exts) != 0) {
			ret = SSH_ERR_INVALID_FORMAT;
			जा out;
		}
	}
	जर (sshbuf_len(b) != 0) {
		ret = SSH_ERR_UNEXPECTED_TRAILING_DATA;
		जा out;
	}

	/* parse signature */
	जर (sshbuf_get_bignum2(sigbuf, &sig_r) != 0 ||
	    sshbuf_get_bignum2(sigbuf, &sig_s) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		जा out;
	}
	जर (sshbuf_len(sigbuf) != 0) {
		ret = SSH_ERR_UNEXPECTED_TRAILING_DATA;
		जा out;
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
	जर (is_webauthn) {
		ख_लिखो(मानक_त्रुटि, "%s: webauthn origin: %s\n", __func__,
		    webauthn_origin);
		ख_लिखो(मानक_त्रुटि, "%s: webauthn_wrapper:\n", __func__);
		sshbuf_dump(webauthn_wrapper, मानक_त्रुटि);
	}
#endif
	जर ((esig = ECDSA_SIG_new()) == रिक्त) {
		ret = SSH_ERR_ALLOC_FAIL;
		जा out;
	}
	जर (!ECDSA_SIG_set0(esig, sig_r, sig_s)) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		जा out;
	}
	sig_r = sig_s = रिक्त; /* transferred */

	/* Reconstruct data that was supposedly signed */
	जर ((original_signed = sshbuf_new()) == रिक्त) {
		ret = SSH_ERR_ALLOC_FAIL;
		जा out;
	}
	जर (is_webauthn) {
		जर ((ret = webauthn_check_prepare_hash(data, dlen,
		    webauthn_origin, webauthn_wrapper, sig_flags, webauthn_exts,
		    msghash, आकार(msghash))) != 0)
			जा out;
	} अन्यथा जर ((ret = ssh_digest_memory(SSH_DIGEST_SHA256, data, dlen,
	    msghash, आकार(msghash))) != 0)
		जा out;
	/* Application value is hashed before signature */
	जर ((ret = ssh_digest_memory(SSH_DIGEST_SHA256, किल्ली->sk_application,
	    म_माप(किल्ली->sk_application), apphash, आकार(apphash))) != 0)
		जा out;
#ifdef DEBUG_SK
	ख_लिखो(मानक_त्रुटि, "%s: hashed application:\n", __func__);
	sshbuf_dump_data(apphash, आकार(apphash), मानक_त्रुटि);
	ख_लिखो(मानक_त्रुटि, "%s: hashed message:\n", __func__);
	sshbuf_dump_data(msghash, आकार(msghash), मानक_त्रुटि);
#endif
	जर ((ret = sshbuf_put(original_signed,
	    apphash, आकार(apphash))) != 0 ||
	    (ret = sshbuf_put_u8(original_signed, sig_flags)) != 0 ||
	    (ret = sshbuf_put_u32(original_signed, sig_counter)) != 0 ||
	    (ret = sshbuf_putb(original_signed, webauthn_exts)) != 0 ||
	    (ret = sshbuf_put(original_signed, msghash, आकार(msghash))) != 0)
		जा out;
	details->sk_counter = sig_counter;
	details->sk_flags = sig_flags;
#ifdef DEBUG_SK
	ख_लिखो(मानक_त्रुटि, "%s: signed buf:\n", __func__);
	sshbuf_dump(original_signed, मानक_त्रुटि);
#endif

	जर ((md_ctx = EVP_MD_CTX_new()) == रिक्त) {
		ret = SSH_ERR_ALLOC_FAIL;
		जा out;
	}
	जर ((len = i2d_ECDSA_SIG(esig, रिक्त)) <= 0) {
		len = 0;
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		जा out;
	}
	जर ((sigb = सुस्मृति(1, len)) == रिक्त) {
		ret = SSH_ERR_ALLOC_FAIL;
		जा out;
	}
	cp = sigb; /* ASN1_item_i2d increments the pointer past the object */
	जर (i2d_ECDSA_SIG(esig, &cp) != len) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		जा out;
	}
#ifdef DEBUG_SK
	ख_लिखो(मानक_त्रुटि, "%s: signed hash:\n", __func__);
	sshbuf_dump_data(sigb, len, मानक_त्रुटि);
#endif
	/* Verify it */
	जर (EVP_DigestVerifyInit(md_ctx, रिक्त, EVP_sha256(), रिक्त,
	    किल्ली->pkey) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		जा out;
	}
	निवड (EVP_DigestVerify(md_ctx, sigb, len,
	    sshbuf_ptr(original_signed), sshbuf_len(original_signed))) {
	स्थिती 1:
		ret = 0;
		थांबा;
	स्थिती 0:
		ret = SSH_ERR_SIGNATURE_INVALID;
		जा out;
	पूर्वनिर्धारित:
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		जा out;
	}
	/* success */
	जर (detailsp != रिक्त) {
		*detailsp = details;
		details = रिक्त;
	}
 out:
	explicit_bzero(&sig_flags, आकार(sig_flags));
	explicit_bzero(&sig_counter, आकार(sig_counter));
	explicit_bzero(msghash, आकार(msghash));
	explicit_bzero(apphash, आकार(apphash));
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
	परत ret;
}

स्थिर स्थिरांक संरचना sshkey_impl_funcs sshkey_ecdsa_sk_funcs = {
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

स्थिरांक संरचना sshkey_impl sshkey_ecdsa_sk_impl = {
	/* .name = */		"sk-ecdsa-sha2-nistp256@openssh.com",
	/* .shortname = */	"ECDSA-SK",
	/* .sigalg = */		रिक्त,
	/* .type = */		किल्ली_ECDSA_SK,
	/* .nid = */		NID_X9_62_prime256v1,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	256,
	/* .funcs = */		&sshkey_ecdsa_sk_funcs,
};

स्थिरांक संरचना sshkey_impl sshkey_ecdsa_sk_cert_impl = {
	/* .name = */		"sk-ecdsa-sha2-nistp256-cert-v01@openssh.com",
	/* .shortname = */	"ECDSA-SK-CERT",
	/* .sigalg = */		रिक्त,
	/* .type = */		किल्ली_ECDSA_SK_CERT,
	/* .nid = */		NID_X9_62_prime256v1,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	256,
	/* .funcs = */		&sshkey_ecdsa_sk_funcs,
};

स्थिरांक संरचना sshkey_impl sshkey_ecdsa_sk_webauthn_impl = {
	/* .name = */		"webauthn-sk-ecdsa-sha2-nistp256@openssh.com",
	/* .shortname = */	"ECDSA-SK",
	/* .sigalg = */		रिक्त,
	/* .type = */		किल्ली_ECDSA_SK,
	/* .nid = */		NID_X9_62_prime256v1,
	/* .cert = */		0,
	/* .sigonly = */	1,
	/* .keybits = */	256,
	/* .funcs = */		&sshkey_ecdsa_sk_funcs,
};

स्थिरांक संरचना sshkey_impl sshkey_ecdsa_sk_webauthn_cert_impl = {
	/* .name = */		"webauthn-sk-ecdsa-sha2-nistp256-cert-v01@openssh.com",
	/* .shortname = */	"ECDSA-SK-CERT",
	/* .sigalg = */		रिक्त,
	/* .type = */		किल्ली_ECDSA_SK_CERT,
	/* .nid = */		NID_X9_62_prime256v1,
	/* .cert = */		1,
	/* .sigonly = */	1,
	/* .keybits = */	256,
	/* .funcs = */		&sshkey_ecdsa_sk_funcs,
};
#endif /* WITH_OPENSSL */
