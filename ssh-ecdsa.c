/* $OpenBSD: ssh-ecdsa.c,v 1.29 2026/02/14 00:18:34 jsg Exp $ */
/*
 * Copyright (c) 2000 Markus Friedl.  All rights reserved.
 * Copyright (c) 2010 Damien Miller.  All rights reserved.
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

#समावेश "includes.h"

#अगर defined(WITH_OPENSSL)
#समावेश "openbsd-compat/openssl-compat.h"

#समावेश <sys/types.h>

#समावेश <openssl/bn.h>
#समावेश <openssl/ec.h>
#समावेश <openssl/ecdsa.h>
#समावेश <openssl/evp.h>

#समावेश <string.h>

#समावेश "sshbuf.h"
#समावेश "ssherr.h"
#घोषणा SSHKEY_INTERNAL
#समावेश "sshkey.h"

पूर्णांक
sshkey_ecdsa_fixup_group(EVP_PKEY *k)
{
	पूर्णांक nids[] = {
		NID_X9_62_prime256v1,
		NID_secp384r1,
		NID_secp521r1,
		-1
	};
	पूर्णांक nid = -1;
	u_int i;
	स्थिर EC_GROUP *g;
	EC_कुंजी *ec = शून्य;
	EC_GROUP *eg = शून्य;

	अगर ((ec = EVP_PKEY_get1_EC_कुंजी(k)) == शून्य ||
	    (g = EC_कुंजी_get0_group(ec)) == शून्य)
		जाओ out;
	/*
	 * The group may be stored in a ASN.1 encoded private key in one of two
	 * ways: as a "named group", which is reconstituted by ASN.1 object ID
	 * or explicit group parameters encoded into the key blob. Only the
	 * "named group" case sets the group NID for us, but we can figure
	 * it out for the other case by comparing against all the groups that
	 * are supported.
	 */
	अगर ((nid = EC_GROUP_get_curve_name(g)) > 0)
		जाओ out;
	nid = -1;
	क्रम (i = 0; nids[i] != -1; i++) {
		अगर ((eg = EC_GROUP_new_by_curve_name(nids[i])) == शून्य)
			जाओ out;
		अगर (EC_GROUP_cmp(g, eg, शून्य) == 0)
			अवरोध;
		EC_GROUP_free(eg);
		eg = शून्य;
	}
	अगर (nids[i] == -1)
		जाओ out;

	/* Use the group with the NID attached */
	EC_GROUP_set_asn1_flag(eg, OPENSSL_EC_NAMED_CURVE);
	अगर (EC_कुंजी_set_group(ec, eg) != 1 ||
	    EVP_PKEY_set1_EC_कुंजी(k, ec) != 1)
		जाओ out;
	/* success */
	nid = nids[i];
 out:
	EC_कुंजी_free(ec);
	EC_GROUP_free(eg);
	वापस nid;
}

अटल u_int
ssh_ecdsa_आकार(स्थिर काष्ठा sshkey *कुंजी)
{
	चयन (कुंजी->ecdsa_nid) {
	हाल NID_X9_62_prime256v1:
		वापस 256;
	हाल NID_secp384r1:
		वापस 384;
	हाल NID_secp521r1:
		वापस 521;
	शेष:
		वापस 0;
	}
}

अटल व्योम
ssh_ecdsa_cleanup(काष्ठा sshkey *k)
{
	EVP_PKEY_free(k->pkey);
	k->pkey = शून्य;
}

अटल पूर्णांक
ssh_ecdsa_equal(स्थिर काष्ठा sshkey *a, स्थिर काष्ठा sshkey *b)
{
	अगर (a->pkey == शून्य || b->pkey == शून्य)
		वापस 0;
	वापस EVP_PKEY_cmp(a->pkey, b->pkey) == 1;
}

अटल पूर्णांक
ssh_ecdsa_serialize_public(स्थिर काष्ठा sshkey *कुंजी, काष्ठा sshbuf *b,
    क्रमागत sshkey_serialize_rep opts)
{
	पूर्णांक r;

	अगर (कुंजी->pkey == शून्य)
		वापस SSH_ERR_INVALID_ARGUMENT;
	अगर ((r = sshbuf_put_cstring(b,
	    sshkey_curve_nid_to_name(कुंजी->ecdsa_nid))) != 0 ||
	    (r = sshbuf_put_ec_pkey(b, कुंजी->pkey)) != 0)
		वापस r;

	वापस 0;
}

अटल पूर्णांक
ssh_ecdsa_serialize_private(स्थिर काष्ठा sshkey *कुंजी, काष्ठा sshbuf *b,
    क्रमागत sshkey_serialize_rep opts)
{
	पूर्णांक r;

	अगर (!sshkey_is_cert(कुंजी)) {
		अगर ((r = ssh_ecdsa_serialize_public(कुंजी, b, opts)) != 0)
			वापस r;
	}
	अगर ((r = sshbuf_put_bignum2(b,
	    EC_कुंजी_get0_private_कुंजी(EVP_PKEY_get0_EC_कुंजी(कुंजी->pkey)))) != 0)
		वापस r;
	वापस 0;
}

अटल पूर्णांक
ssh_ecdsa_generate(काष्ठा sshkey *k, पूर्णांक bits)
{
	EVP_PKEY *res = शून्य;
	EVP_PKEY_CTX *ctx = शून्य;
	पूर्णांक ret = SSH_ERR_INTERNAL_ERROR;

	अगर ((k->ecdsa_nid = sshkey_ecdsa_bits_to_nid(bits)) == -1)
		वापस SSH_ERR_कुंजी_लंबाई;

	अगर ((ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, शून्य)) == शून्य)
		वापस SSH_ERR_ALLOC_FAIL;

	अगर (EVP_PKEY_keygen_init(ctx) <= 0 ||
	    EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, k->ecdsa_nid) <= 0 ||
	    EVP_PKEY_keygen(ctx, &res) <= 0) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		जाओ out;
	}
	/* success */
	k->pkey = res;
	res = शून्य;
	ret = 0;
 out:
	EVP_PKEY_free(res);
	EVP_PKEY_CTX_free(ctx);
	वापस ret;
}

अटल पूर्णांक
ssh_ecdsa_copy_public(स्थिर काष्ठा sshkey *from, काष्ठा sshkey *to)
{
	स्थिर EC_कुंजी *ec_from;
	EC_कुंजी *ec_to = शून्य;
	पूर्णांक ret = SSH_ERR_INTERNAL_ERROR;

	ec_from = EVP_PKEY_get0_EC_कुंजी(from->pkey);
	अगर (ec_from == शून्य)
		वापस SSH_ERR_LIBCRYPTO_ERROR;

	to->ecdsa_nid = from->ecdsa_nid;
	अगर ((ec_to = EC_कुंजी_new_by_curve_name(from->ecdsa_nid)) == शून्य)
		वापस SSH_ERR_ALLOC_FAIL;
	अगर (EC_कुंजी_set_public_कुंजी(ec_to,
	    EC_कुंजी_get0_public_कुंजी(ec_from)) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		जाओ out;
	}
	EVP_PKEY_free(to->pkey);
	अगर ((to->pkey = EVP_PKEY_new()) == शून्य) {
		ret = SSH_ERR_ALLOC_FAIL;
		जाओ out;
	}
	अगर (EVP_PKEY_set1_EC_कुंजी(to->pkey, ec_to) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		जाओ out;
	}
	ret = 0;
 out:
	EC_कुंजी_free(ec_to);
	वापस ret;
}

अटल पूर्णांक
ssh_ecdsa_deserialize_public(स्थिर अक्षर *ktype, काष्ठा sshbuf *b,
    काष्ठा sshkey *कुंजी)
{
	पूर्णांक r;
	अक्षर *curve = शून्य;
	EVP_PKEY *pkey = शून्य;
	EC_कुंजी *ec = शून्य;

	अगर ((कुंजी->ecdsa_nid = sshkey_ecdsa_nid_from_name(ktype)) == -1)
		वापस SSH_ERR_INVALID_ARGUMENT;
	अगर ((r = sshbuf_get_cstring(b, &curve, शून्य)) != 0)
		जाओ out;
	अगर (कुंजी->ecdsa_nid != sshkey_curve_name_to_nid(curve)) {
		r = SSH_ERR_EC_CURVE_MISMATCH;
		जाओ out;
	}
	अगर ((ec = EC_कुंजी_new_by_curve_name(कुंजी->ecdsa_nid)) == शून्य) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		जाओ out;
	}
	अगर ((r = sshbuf_get_eckey(b, ec)) != 0)
		जाओ out;
	अगर (sshkey_ec_validate_public(EC_कुंजी_get0_group(ec),
	    EC_कुंजी_get0_public_कुंजी(ec)) != 0) {
		r = SSH_ERR_कुंजी_INVALID_EC_मूल्य;
		जाओ out;
	}
	अगर ((pkey = EVP_PKEY_new()) == शून्य) {
		r = SSH_ERR_ALLOC_FAIL;
		जाओ out;
	}
	अगर (EVP_PKEY_set1_EC_कुंजी(pkey, ec) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		जाओ out;
	}
	EVP_PKEY_free(कुंजी->pkey);
	कुंजी->pkey = pkey;
	pkey = शून्य;
	/* success */
	r = 0;
#अगर_घोषित DEBUG_PK
	sshkey_dump_ec_point(
	    EC_कुंजी_get0_group(EVP_PKEY_get0_EC_कुंजी(कुंजी->pkey)),
	    EC_कुंजी_get0_public_कुंजी(EVP_PKEY_get0_EC_कुंजी(कुंजी->pkey)));
#पूर्ण_अगर
 out:
	EC_कुंजी_free(ec);
	EVP_PKEY_free(pkey);
	मुक्त(curve);
	वापस r;
}

अटल पूर्णांक
ssh_ecdsa_deserialize_private(स्थिर अक्षर *ktype, काष्ठा sshbuf *b,
    काष्ठा sshkey *कुंजी)
{
	पूर्णांक r;
	BIGNUM *exponent = शून्य;
	EC_कुंजी *ec = शून्य;

	अगर (!sshkey_is_cert(कुंजी)) {
		अगर ((r = ssh_ecdsa_deserialize_public(ktype, b, कुंजी)) != 0)
			वापस r;
	}
	अगर ((r = sshbuf_get_bignum2(b, &exponent)) != 0)
		जाओ out;
	अगर ((ec = EVP_PKEY_get1_EC_कुंजी(कुंजी->pkey)) == शून्य) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		जाओ out;
	}
	अगर (EC_कुंजी_set_private_कुंजी(ec, exponent) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		जाओ out;
	}
	अगर ((r = sshkey_ec_validate_private(ec)) != 0)
		जाओ out;
	अगर (EVP_PKEY_set1_EC_कुंजी(कुंजी->pkey, ec) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		जाओ out;
	}
	/* success */
	r = 0;
 out:
	BN_clear_free(exponent);
	EC_कुंजी_free(ec);
	वापस r;
}

अटल पूर्णांक
ssh_ecdsa_sign(काष्ठा sshkey *कुंजी,
    u_char **sigp, माप_प्रकार *lenp,
    स्थिर u_char *तथ्य, माप_प्रकार dlen,
    स्थिर अक्षर *alg, स्थिर अक्षर *sk_provider, स्थिर अक्षर *sk_pin, u_int compat)
{
	ECDSA_SIG *esig = शून्य;
	अचिन्हित अक्षर *sigb = शून्य;
	स्थिर अचिन्हित अक्षर *psig;
	स्थिर BIGNUM *sig_r, *sig_s;
	पूर्णांक hash_alg;
	माप_प्रकार slen = 0;
	पूर्णांक ret = SSH_ERR_INTERNAL_ERROR;

	अगर (lenp != शून्य)
		*lenp = 0;
	अगर (sigp != शून्य)
		*sigp = शून्य;

	अगर (कुंजी == शून्य || कुंजी->pkey == शून्य ||
	    sshkey_type_plain(कुंजी->type) != कुंजी_ECDSA)
		वापस SSH_ERR_INVALID_ARGUMENT;

	अगर ((hash_alg = sshkey_ec_nid_to_hash_alg(कुंजी->ecdsa_nid)) == -1)
		वापस SSH_ERR_INTERNAL_ERROR;

	अगर ((ret = sshkey_pkey_digest_sign(कुंजी->pkey, hash_alg, &sigb, &slen,
	    तथ्य, dlen)) != 0)
		जाओ out;

	psig = sigb;
	अगर ((esig = d2i_ECDSA_SIG(शून्य, &psig, slen)) == शून्य) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		जाओ out;
	}
	ECDSA_SIG_get0(esig, &sig_r, &sig_s);

	अगर ((ret = ssh_ecdsa_encode_store_sig(कुंजी, sig_r, sig_s,
	    sigp, lenp)) != 0)
		जाओ out;
	/* success */
	ret = 0;
 out:
	freezero(sigb, slen);
	ECDSA_SIG_free(esig);
	वापस ret;
}

पूर्णांक
ssh_ecdsa_encode_store_sig(स्थिर काष्ठा sshkey *कुंजी,
    स्थिर BIGNUM *sig_r, स्थिर BIGNUM *sig_s,
    u_char **sigp, माप_प्रकार *lenp)
{
	काष्ठा sshbuf *b = शून्य, *bb = शून्य;
	पूर्णांक ret;
	माप_प्रकार len;

	अगर (lenp != शून्य)
		*lenp = 0;
	अगर (sigp != शून्य)
		*sigp = शून्य;

	अगर ((bb = sshbuf_new()) == शून्य || (b = sshbuf_new()) == शून्य) {
		ret = SSH_ERR_ALLOC_FAIL;
		जाओ out;
	}
	अगर ((ret = sshbuf_put_bignum2(bb, sig_r)) != 0 ||
	    (ret = sshbuf_put_bignum2(bb, sig_s)) != 0)
		जाओ out;
	अगर ((ret = sshbuf_put_cstring(b, sshkey_ssh_name_plain(कुंजी))) != 0 ||
	    (ret = sshbuf_put_stringb(b, bb)) != 0)
		जाओ out;
	len = sshbuf_len(b);
	अगर (sigp != शून्य) {
		अगर ((*sigp = दो_स्मृति(len)) == शून्य) {
			ret = SSH_ERR_ALLOC_FAIL;
			जाओ out;
		}
		स_नकल(*sigp, sshbuf_ptr(b), len);
	}
	अगर (lenp != शून्य)
		*lenp = len;
	ret = 0;
 out:
	sshbuf_free(b);
	sshbuf_free(bb);
	वापस ret;
}

अटल पूर्णांक
ssh_ecdsa_verify(स्थिर काष्ठा sshkey *कुंजी,
    स्थिर u_char *sig, माप_प्रकार siglen,
    स्थिर u_char *तथ्य, माप_प्रकार dlen, स्थिर अक्षर *alg, u_int compat,
    काष्ठा sshkey_sig_details **detailsp)
{
	ECDSA_SIG *esig = शून्य;
	BIGNUM *sig_r = शून्य, *sig_s = शून्य;
	पूर्णांक hash_alg, len = 0;
	पूर्णांक ret = SSH_ERR_INTERNAL_ERROR;
	काष्ठा sshbuf *b = शून्य, *sigbuf = शून्य;
	अक्षर *ktype = शून्य;
	अचिन्हित अक्षर *sigb = शून्य, *cp;

	अगर (कुंजी == शून्य || कुंजी->pkey == शून्य ||
	    sshkey_type_plain(कुंजी->type) != कुंजी_ECDSA ||
	    sig == शून्य || siglen == 0)
		वापस SSH_ERR_INVALID_ARGUMENT;

	अगर ((hash_alg = sshkey_ec_nid_to_hash_alg(कुंजी->ecdsa_nid)) == -1)
		वापस SSH_ERR_INTERNAL_ERROR;

	/* fetch signature */
	अगर ((b = sshbuf_from(sig, siglen)) == शून्य)
		वापस SSH_ERR_ALLOC_FAIL;
	अगर (sshbuf_get_cstring(b, &ktype, शून्य) != 0 ||
	    sshbuf_froms(b, &sigbuf) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		जाओ out;
	}
	अगर (म_भेद(sshkey_ssh_name_plain(कुंजी), ktype) != 0) {
		ret = SSH_ERR_कुंजी_TYPE_MISMATCH;
		जाओ out;
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

	अगर ((esig = ECDSA_SIG_new()) == शून्य) {
		ret = SSH_ERR_ALLOC_FAIL;
		जाओ out;
	}
	अगर (!ECDSA_SIG_set0(esig, sig_r, sig_s)) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		जाओ out;
	}
	sig_r = sig_s = शून्य; /* transferred */

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
	अगर ((ret = sshkey_pkey_digest_verify(कुंजी->pkey, hash_alg,
	    तथ्य, dlen, sigb, len)) != 0)
		जाओ out;
	/* success */
 out:
	freezero(sigb, len);
	sshbuf_free(sigbuf);
	sshbuf_free(b);
	ECDSA_SIG_free(esig);
	BN_clear_free(sig_r);
	BN_clear_free(sig_s);
	मुक्त(ktype);
	वापस ret;
}

/* NB. not static; used by ECDSA-SK */
स्थिर काष्ठा sshkey_impl_funcs sshkey_ecdsa_funcs = {
	/* .size = */		ssh_ecdsa_आकार,
	/* .alloc = */		शून्य,
	/* .cleanup = */	ssh_ecdsa_cleanup,
	/* .equal = */		ssh_ecdsa_equal,
	/* .ssh_serialize_public = */ ssh_ecdsa_serialize_public,
	/* .ssh_deserialize_public = */ ssh_ecdsa_deserialize_public,
	/* .ssh_serialize_private = */ ssh_ecdsa_serialize_private,
	/* .ssh_deserialize_private = */ ssh_ecdsa_deserialize_private,
	/* .generate = */	ssh_ecdsa_generate,
	/* .copy_public = */	ssh_ecdsa_copy_public,
	/* .sign = */		ssh_ecdsa_sign,
	/* .verify = */		ssh_ecdsa_verify,
};

स्थिर काष्ठा sshkey_impl sshkey_ecdsa_nistp256_impl = {
	/* .name = */		"ecdsa-sha2-nistp256",
	/* .shortname = */	"ECDSA",
	/* .sigalg = */		शून्य,
	/* .type = */		कुंजी_ECDSA,
	/* .nid = */		NID_X9_62_prime256v1,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_ecdsa_funcs,
};

स्थिर काष्ठा sshkey_impl sshkey_ecdsa_nistp256_cert_impl = {
	/* .name = */		"ecdsa-sha2-nistp256-cert-v01@openssh.com",
	/* .shortname = */	"ECDSA-CERT",
	/* .sigalg = */		शून्य,
	/* .type = */		कुंजी_ECDSA_CERT,
	/* .nid = */		NID_X9_62_prime256v1,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_ecdsa_funcs,
};

स्थिर काष्ठा sshkey_impl sshkey_ecdsa_nistp384_impl = {
	/* .name = */		"ecdsa-sha2-nistp384",
	/* .shortname = */	"ECDSA",
	/* .sigalg = */		शून्य,
	/* .type = */		कुंजी_ECDSA,
	/* .nid = */		NID_secp384r1,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_ecdsa_funcs,
};

स्थिर काष्ठा sshkey_impl sshkey_ecdsa_nistp384_cert_impl = {
	/* .name = */		"ecdsa-sha2-nistp384-cert-v01@openssh.com",
	/* .shortname = */	"ECDSA-CERT",
	/* .sigalg = */		शून्य,
	/* .type = */		कुंजी_ECDSA_CERT,
	/* .nid = */		NID_secp384r1,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_ecdsa_funcs,
};

स्थिर काष्ठा sshkey_impl sshkey_ecdsa_nistp521_impl = {
	/* .name = */		"ecdsa-sha2-nistp521",
	/* .shortname = */	"ECDSA",
	/* .sigalg = */		शून्य,
	/* .type = */		कुंजी_ECDSA,
	/* .nid = */		NID_secp521r1,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_ecdsa_funcs,
};

स्थिर काष्ठा sshkey_impl sshkey_ecdsa_nistp521_cert_impl = {
	/* .name = */		"ecdsa-sha2-nistp521-cert-v01@openssh.com",
	/* .shortname = */	"ECDSA-CERT",
	/* .sigalg = */		शून्य,
	/* .type = */		कुंजी_ECDSA_CERT,
	/* .nid = */		NID_secp521r1,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_ecdsa_funcs,
};

#पूर्ण_अगर /* WITH_OPENSSL */
