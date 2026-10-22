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

#समावेश "includes.h"

#समावेश <sys/types.h>

#अगर_घोषित WITH_OPENSSL
#समावेश "openbsd-compat/openssl-compat.h"
#समावेश <openssl/bn.h>
#समावेश <openssl/ec.h>
#समावेश <openssl/ecdsa.h>
#समावेश <openssl/evp.h>

#समावेश <string.h>
#समावेश <stdio.h> /* needed for DEBUG_SK only */

#समावेश "sshbuf.h"
#समावेश "ssherr.h"
#समावेश "digest.h"
#घोषणा SSHKEY_INTERNAL
#समावेश "sshkey.h"

/* Reuse some ECDSA internals */
बाह्य काष्ठा sshkey_impl_funcs sshkey_ecdsa_funcs;

अटल व्योम
ssh_ecdsa_sk_cleanup(काष्ठा sshkey *k)
{
	sshkey_sk_cleanup(k);
	sshkey_ecdsa_funcs.cleanup(k);
}

अटल पूर्णांक
ssh_ecdsa_sk_equal(स्थिर काष्ठा sshkey *a, स्थिर काष्ठा sshkey *b)
{
	अगर (!sshkey_sk_fields_equal(a, b))
		वापस 0;
	अगर (!sshkey_ecdsa_funcs.equal(a, b))
		वापस 0;
	वापस 1;
}

अटल पूर्णांक
ssh_ecdsa_sk_serialize_public(स्थिर काष्ठा sshkey *कुंजी, काष्ठा sshbuf *b,
    क्रमागत sshkey_serialize_rep opts)
{
	पूर्णांक r;

	अगर ((r = sshkey_ecdsa_funcs.serialize_public(कुंजी, b, opts)) != 0)
		वापस r;
	अगर ((r = sshkey_serialize_sk(कुंजी, b)) != 0)
		वापस r;

	वापस 0;
}

अटल पूर्णांक
ssh_ecdsa_sk_serialize_private(स्थिर काष्ठा sshkey *कुंजी, काष्ठा sshbuf *b,
    क्रमागत sshkey_serialize_rep opts)
{
	पूर्णांक r;

	अगर (!sshkey_is_cert(कुंजी)) {
		अगर ((r = sshkey_ecdsa_funcs.serialize_public(कुंजी,
		    b, opts)) != 0)
			वापस r;
	}
	अगर ((r = sshkey_serialize_private_sk(कुंजी, b)) != 0)
		वापस r;

	वापस 0;
}

अटल पूर्णांक
ssh_ecdsa_sk_copy_public(स्थिर काष्ठा sshkey *from, काष्ठा sshkey *to)
{
	पूर्णांक r;

	अगर ((r = sshkey_ecdsa_funcs.copy_public(from, to)) != 0)
		वापस r;
	अगर ((r = sshkey_copy_public_sk(from, to)) != 0)
		वापस r;
	वापस 0;
}

अटल पूर्णांक
ssh_ecdsa_sk_deserialize_public(स्थिर अक्षर *ktype, काष्ठा sshbuf *b,
    काष्ठा sshkey *कुंजी)
{
	पूर्णांक r;

	अगर ((r = sshkey_ecdsa_funcs.deserialize_public(ktype, b, कुंजी)) != 0)
		वापस r;
	अगर ((r = sshkey_deserialize_sk(b, कुंजी)) != 0)
		वापस r;
	वापस 0;
}

अटल पूर्णांक
ssh_ecdsa_sk_deserialize_private(स्थिर अक्षर *ktype, काष्ठा sshbuf *b,
    काष्ठा sshkey *कुंजी)
{
	पूर्णांक r;

	अगर (!sshkey_is_cert(कुंजी)) {
		अगर ((r = sshkey_ecdsa_funcs.deserialize_public(ktype,
		    b, कुंजी)) != 0)
			वापस r;
	}
	अगर ((r = sshkey_private_deserialize_sk(b, कुंजी)) != 0)
		वापस r;

	वापस 0;
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
अटल पूर्णांक
webauthn_check_prepare_hash(स्थिर u_char *तथ्य, माप_प्रकार datalen,
    स्थिर अक्षर *origin, स्थिर काष्ठा sshbuf *wrapper,
    uint8_t flags, स्थिर काष्ठा sshbuf *extensions,
    u_char *msghash, माप_प्रकार msghashlen)
{
	पूर्णांक r = SSH_ERR_INTERNAL_ERROR;
	काष्ठा sshbuf *chall = शून्य, *m = शून्य;

	अगर ((m = sshbuf_new()) == शून्य ||
	    (chall = sshbuf_from(तथ्य, datalen)) == शून्य) {
		r = SSH_ERR_ALLOC_FAIL;
		जाओ out;
	}
	/*
	 * Ensure origin contains no quote character and that the flags are
	 * consistent with what we received
	 */
	अगर (म_अक्षर(origin, '\"') != शून्य ||
	    (flags & 0x40) != 0 /* AD */ ||
	    ((flags & 0x80) == 0 /* ED */) != (sshbuf_len(extensions) == 0)) {
		r = SSH_ERR_INVALID_FORMAT;
		जाओ out;
	}

	/*
	 * Prepare the preamble to clientData that we expect, poking the
	 * challenge and origin into their canonical positions in the
	 * structure. The crossOrigin flag and any additional extension
	 * fields present are ignored.
	 */
#घोषणा WEBAUTHN_0	"{\"type\":\"webauthn.get\",\"challenge\":\""
#घोषणा WEBAUTHN_1	"\",\"origin\":\""
#घोषणा WEBAUTHN_2	"\""
	अगर ((r = sshbuf_put(m, WEBAUTHN_0, माप(WEBAUTHN_0) - 1)) != 0 ||
	    (r = sshbuf_dtourlb64(chall, m, 0)) != 0 ||
	    (r = sshbuf_put(m, WEBAUTHN_1, माप(WEBAUTHN_1) - 1)) != 0 ||
	    (r = sshbuf_put(m, origin, म_माप(origin))) != 0 ||
	    (r = sshbuf_put(m, WEBAUTHN_2, माप(WEBAUTHN_2) - 1)) != 0)
		जाओ out;
#अगर_घोषित DEBUG_SK
	ख_लिखो(मानक_त्रुटि, "%s: received origin: %s\n", __func__, origin);
	ख_लिखो(मानक_त्रुटि, "%s: received clientData:\n", __func__);
	sshbuf_dump(wrapper, मानक_त्रुटि);
	ख_लिखो(मानक_त्रुटि, "%s: expected clientData preamble:\n", __func__);
	sshbuf_dump(m, मानक_त्रुटि);
#पूर्ण_अगर
	/* Check that the supplied clientData has the preamble we expect */
	अगर ((r = sshbuf_cmp(wrapper, 0, sshbuf_ptr(m), sshbuf_len(m))) != 0)
		जाओ out;

	/* Prepare hash of clientData */
	अगर ((r = ssh_digest_बफर(SSH_DIGEST_SHA256, wrapper,
	    msghash, msghashlen)) != 0)
		जाओ out;

	/* success */
	r = 0;
 out:
	sshbuf_free(chall);
	sshbuf_free(m);
	वापस r;
}

अटल पूर्णांक
ssh_ecdsa_sk_verify(स्थिर काष्ठा sshkey *कुंजी,
    स्थिर u_char *sig, माप_प्रकार siglen,
    स्थिर u_char *तथ्य, माप_प्रकार dlen, स्थिर अक्षर *alg, u_int compat,
    काष्ठा sshkey_sig_details **detailsp)
{
	ECDSA_SIG *esig = शून्य;
	EVP_MD_CTX *md_ctx = शून्य;
	BIGNUM *sig_r = शून्य, *sig_s = शून्य;
	u_char sig_flags;
	u_char msghash[32], apphash[32];
	u_int sig_गणक;
	u_char *sigb = शून्य, *cp;
	पूर्णांक is_webauthn = 0, ret = SSH_ERR_INTERNAL_ERROR, len = 0;
	काष्ठा sshbuf *b = शून्य, *sigbuf = शून्य, *original_signed = शून्य;
	काष्ठा sshbuf *webauthn_wrapper = शून्य, *webauthn_exts = शून्य;
	अक्षर *ktype = शून्य, *webauthn_origin = शून्य;
	काष्ठा sshkey_sig_details *details = शून्य;
#अगर_घोषित DEBUG_SK
	अक्षर *tmp = शून्य;
#पूर्ण_अगर

	अगर (detailsp != शून्य)
		*detailsp = शून्य;
	अगर (कुंजी == शून्य || कुंजी->pkey == शून्य ||
	    sshkey_type_plain(कुंजी->type) != कुंजी_ECDSA_SK ||
	    sig == शून्य || siglen == 0)
		वापस SSH_ERR_INVALID_ARGUMENT;

	अगर (कुंजी->ecdsa_nid != NID_X9_62_prime256v1)
		वापस SSH_ERR_INTERNAL_ERROR;

	/* fetch signature */
	अगर ((b = sshbuf_from(sig, siglen)) == शून्य)
		वापस SSH_ERR_ALLOC_FAIL;
	अगर ((details = सुस्मृति(1, माप(*details))) == शून्य) {
		ret = SSH_ERR_ALLOC_FAIL;
		जाओ out;
	}
	अगर (sshbuf_get_cstring(b, &ktype, शून्य) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		जाओ out;
	}
	अगर (म_भेद(ktype, "webauthn-sk-ecdsa-sha2-nistp256@openssh.com") == 0 ||
	    म_भेद(ktype, "webauthn-sk-ecdsa-sha2-nistp256-cert-v01@openssh.com")
	      == 0)
		is_webauthn = 1;
	अन्यथा अगर (म_भेद(ktype, "sk-ecdsa-sha2-nistp256@openssh.com") != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		जाओ out;
	}
	अगर (sshbuf_froms(b, &sigbuf) != 0 ||
	    sshbuf_get_u8(b, &sig_flags) != 0 ||
	    sshbuf_get_u32(b, &sig_गणक) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		जाओ out;
	}
	अगर (is_webauthn) {
		अगर (sshbuf_get_cstring(b, &webauthn_origin, शून्य) != 0 ||
		    sshbuf_froms(b, &webauthn_wrapper) != 0 ||
		    sshbuf_froms(b, &webauthn_exts) != 0) {
			ret = SSH_ERR_INVALID_FORMAT;
			जाओ out;
		}
	}
	अगर (sshbuf_len(b) != 0) {
		ret = SSH_ERR_UNEXPECTED_TRAILING_तथ्य;
		जाओ out;
	}

	/* parse signature */
	अगर (sshbuf_get_bignum2(sigbuf, &sig_r) != 0 ||
	    sshbuf_get_bignum2(sigbuf, &sig_s) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		जाओ out;
	}
	अगर (sshbuf_len(sigbuf) != 0) {
		ret = SSH_ERR_UNEXPECTED_TRAILING_तथ्य;
		जाओ out;
	}

#अगर_घोषित DEBUG_SK
	ख_लिखो(मानक_त्रुटि, "%s: data: (len %zu)\n", __func__, dlen);
	/* sshbuf_dump_data(data, datalen, stderr); */
	ख_लिखो(मानक_त्रुटि, "%s: sig_r: %s\n", __func__, (tmp = BN_bn2hex(sig_r)));
	मुक्त(tmp);
	ख_लिखो(मानक_त्रुटि, "%s: sig_s: %s\n", __func__, (tmp = BN_bn2hex(sig_s)));
	मुक्त(tmp);
	ख_लिखो(मानक_त्रुटि, "%s: sig_flags = 0x%02x, sig_counter = %u\n",
	    __func__, sig_flags, sig_गणक);
	अगर (is_webauthn) {
		ख_लिखो(मानक_त्रुटि, "%s: webauthn origin: %s\n", __func__,
		    webauthn_origin);
		ख_लिखो(मानक_त्रुटि, "%s: webauthn_wrapper:\n", __func__);
		sshbuf_dump(webauthn_wrapper, मानक_त्रुटि);
	}
#पूर्ण_अगर
	अगर ((esig = ECDSA_SIG_new()) == शून्य) {
		ret = SSH_ERR_ALLOC_FAIL;
		जाओ out;
	}
	अगर (!ECDSA_SIG_set0(esig, sig_r, sig_s)) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		जाओ out;
	}
	sig_r = sig_s = शून्य; /* transferred */

	/* Reconstruct data that was supposedly signed */
	अगर ((original_signed = sshbuf_new()) == शून्य) {
		ret = SSH_ERR_ALLOC_FAIL;
		जाओ out;
	}
	अगर (is_webauthn) {
		अगर ((ret = webauthn_check_prepare_hash(तथ्य, dlen,
		    webauthn_origin, webauthn_wrapper, sig_flags, webauthn_exts,
		    msghash, माप(msghash))) != 0)
			जाओ out;
	} अन्यथा अगर ((ret = ssh_digest_memory(SSH_DIGEST_SHA256, तथ्य, dlen,
	    msghash, माप(msghash))) != 0)
		जाओ out;
	/* Application value is hashed before signature */
	अगर ((ret = ssh_digest_memory(SSH_DIGEST_SHA256, कुंजी->sk_application,
	    म_माप(कुंजी->sk_application), apphash, माप(apphash))) != 0)
		जाओ out;
#अगर_घोषित DEBUG_SK
	ख_लिखो(मानक_त्रुटि, "%s: hashed application:\n", __func__);
	sshbuf_dump_तथ्य(apphash, माप(apphash), मानक_त्रुटि);
	ख_लिखो(मानक_त्रुटि, "%s: hashed message:\n", __func__);
	sshbuf_dump_तथ्य(msghash, माप(msghash), मानक_त्रुटि);
#पूर्ण_अगर
	अगर ((ret = sshbuf_put(original_signed,
	    apphash, माप(apphash))) != 0 ||
	    (ret = sshbuf_put_u8(original_signed, sig_flags)) != 0 ||
	    (ret = sshbuf_put_u32(original_signed, sig_गणक)) != 0 ||
	    (ret = sshbuf_putb(original_signed, webauthn_exts)) != 0 ||
	    (ret = sshbuf_put(original_signed, msghash, माप(msghash))) != 0)
		जाओ out;
	details->sk_गणक = sig_गणक;
	details->sk_flags = sig_flags;
#अगर_घोषित DEBUG_SK
	ख_लिखो(मानक_त्रुटि, "%s: signed buf:\n", __func__);
	sshbuf_dump(original_signed, मानक_त्रुटि);
#पूर्ण_अगर

	अगर ((md_ctx = EVP_MD_CTX_new()) == शून्य) {
		ret = SSH_ERR_ALLOC_FAIL;
		जाओ out;
	}
	अगर ((len = i2d_ECDSA_SIG(esig, शून्य)) <= 0) {
		len = 0;
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		जाओ out;
	}
	अगर ((sigb = सुस्मृति(1, len)) == शून्य) {
		ret = SSH_ERR_ALLOC_FAIL;
		जाओ out;
	}
	cp = sigb; /* ASN1_item_i2d increments the pointer past the object */
	अगर (i2d_ECDSA_SIG(esig, &cp) != len) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		जाओ out;
	}
#अगर_घोषित DEBUG_SK
	ख_लिखो(मानक_त्रुटि, "%s: signed hash:\n", __func__);
	sshbuf_dump_तथ्य(sigb, len, मानक_त्रुटि);
#पूर्ण_अगर
	/* Verify it */
	अगर (EVP_DigestVerifyInit(md_ctx, शून्य, EVP_sha256(), शून्य,
	    कुंजी->pkey) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		जाओ out;
	}
	चयन (EVP_DigestVerify(md_ctx, sigb, len,
	    sshbuf_ptr(original_signed), sshbuf_len(original_signed))) {
	हाल 1:
		ret = 0;
		अवरोध;
	हाल 0:
		ret = SSH_ERR_SIGNATURE_INVALID;
		जाओ out;
	शेष:
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		जाओ out;
	}
	/* success */
	अगर (detailsp != शून्य) {
		*detailsp = details;
		details = शून्य;
	}
 out:
	explicit_bzero(&sig_flags, माप(sig_flags));
	explicit_bzero(&sig_गणक, माप(sig_गणक));
	explicit_bzero(msghash, माप(msghash));
	explicit_bzero(apphash, माप(apphash));
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
	वापस ret;
}

अटल स्थिर काष्ठा sshkey_impl_funcs sshkey_ecdsa_sk_funcs = {
	/* .size = */		शून्य,
	/* .alloc = */		शून्य,
	/* .cleanup = */	ssh_ecdsa_sk_cleanup,
	/* .equal = */		ssh_ecdsa_sk_equal,
	/* .ssh_serialize_public = */ ssh_ecdsa_sk_serialize_public,
	/* .ssh_deserialize_public = */ ssh_ecdsa_sk_deserialize_public,
	/* .ssh_serialize_private = */ ssh_ecdsa_sk_serialize_private,
	/* .ssh_deserialize_private = */ ssh_ecdsa_sk_deserialize_private,
	/* .generate = */	शून्य,
	/* .copy_public = */	ssh_ecdsa_sk_copy_public,
	/* .sign = */		शून्य,
	/* .verify = */		ssh_ecdsa_sk_verify,
};

स्थिर काष्ठा sshkey_impl sshkey_ecdsa_sk_impl = {
	/* .name = */		"sk-ecdsa-sha2-nistp256@openssh.com",
	/* .shortname = */	"ECDSA-SK",
	/* .sigalg = */		शून्य,
	/* .type = */		कुंजी_ECDSA_SK,
	/* .nid = */		NID_X9_62_prime256v1,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	256,
	/* .funcs = */		&sshkey_ecdsa_sk_funcs,
};

स्थिर काष्ठा sshkey_impl sshkey_ecdsa_sk_cert_impl = {
	/* .name = */		"sk-ecdsa-sha2-nistp256-cert-v01@openssh.com",
	/* .shortname = */	"ECDSA-SK-CERT",
	/* .sigalg = */		शून्य,
	/* .type = */		कुंजी_ECDSA_SK_CERT,
	/* .nid = */		NID_X9_62_prime256v1,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	256,
	/* .funcs = */		&sshkey_ecdsa_sk_funcs,
};

स्थिर काष्ठा sshkey_impl sshkey_ecdsa_sk_webauthn_impl = {
	/* .name = */		"webauthn-sk-ecdsa-sha2-nistp256@openssh.com",
	/* .shortname = */	"ECDSA-SK",
	/* .sigalg = */		शून्य,
	/* .type = */		कुंजी_ECDSA_SK,
	/* .nid = */		NID_X9_62_prime256v1,
	/* .cert = */		0,
	/* .sigonly = */	1,
	/* .keybits = */	256,
	/* .funcs = */		&sshkey_ecdsa_sk_funcs,
};

स्थिर काष्ठा sshkey_impl sshkey_ecdsa_sk_webauthn_cert_impl = {
	/* .name = */		"webauthn-sk-ecdsa-sha2-nistp256-cert-v01@openssh.com",
	/* .shortname = */	"ECDSA-SK-CERT",
	/* .sigalg = */		शून्य,
	/* .type = */		कुंजी_ECDSA_SK_CERT,
	/* .nid = */		NID_X9_62_prime256v1,
	/* .cert = */		1,
	/* .sigonly = */	1,
	/* .keybits = */	256,
	/* .funcs = */		&sshkey_ecdsa_sk_funcs,
};
#पूर्ण_अगर /* WITH_OPENSSL */
