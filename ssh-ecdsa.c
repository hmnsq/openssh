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

#include "includes.h"

#ако defined(WITH_OPENSSL)
#include "openbsd-compat/openssl-compat.h"

#include <sys/types.h>

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>

#include <string.h>

#include "sshbuf.h"
#include "ssherr.h"
#define SSHKEY_INTERNAL
#include "sshkey.h"

цяло
sshkey_ecdsa_fixup_group(EVP_PKEY *k)
{
	цяло nids[] = {
		NID_X9_62_prime256v1,
		NID_secp384r1,
		NID_secp521r1,
		-1
	};
	цяло nid = -1;
	u_int i;
	const EC_GROUP *g;
	EC_KEY *ec = NULL;
	EC_GROUP *eg = NULL;

	ако ((ec = EVP_PKEY_get1_EC_KEY(k)) == NULL ||
	    (g = EC_KEY_get0_group(ec)) == NULL)
		goto out;
	/*
	 * The group may be stored in a ASN.1 encoded private key in one of two
	 * ways: as a "named group", which is reconstituted by ASN.1 object ID
	 * or explicit group parameters encoded into the key blob. Only the
	 * "named group" case sets the group NID for us, but we can figure
	 * it out for the other case by comparing against all the groups that
	 * are supported.
	 */
	ако ((nid = EC_GROUP_get_curve_name(g)) > 0)
		goto out;
	nid = -1;
	за (i = 0; nids[i] != -1; i++) {
		ако ((eg = EC_GROUP_new_by_curve_name(nids[i])) == NULL)
			goto out;
		ако (EC_GROUP_cmp(g, eg, NULL) == 0)
			break;
		EC_GROUP_free(eg);
		eg = NULL;
	}
	ако (nids[i] == -1)
		goto out;

	/* Use the group with the NID attached */
	EC_GROUP_set_asn1_flag(eg, OPENSSL_EC_NAMED_CURVE);
	ако (EC_KEY_set_group(ec, eg) != 1 ||
	    EVP_PKEY_set1_EC_KEY(k, ec) != 1)
		goto out;
	/* success */
	nid = nids[i];
 out:
	EC_KEY_free(ec);
	EC_GROUP_free(eg);
	върни nid;
}

static u_int
ssh_ecdsa_size(const struct sshkey *key)
{
	switch (key->ecdsa_nid) {
	case NID_X9_62_prime256v1:
		върни 256;
	case NID_secp384r1:
		върни 384;
	case NID_secp521r1:
		върни 521;
	default:
		върни 0;
	}
}

static void
ssh_ecdsa_cleanup(struct sshkey *k)
{
	EVP_PKEY_free(k->pkey);
	k->pkey = NULL;
}

static цяло
ssh_ecdsa_equal(const struct sshkey *a, const struct sshkey *b)
{
	ако (a->pkey == NULL || b->pkey == NULL)
		върни 0;
	върни EVP_PKEY_cmp(a->pkey, b->pkey) == 1;
}

static цяло
ssh_ecdsa_serialize_public(const struct sshkey *key, struct sshbuf *b,
    enum sshkey_serialize_rep opts)
{
	цяло r;

	ако (key->pkey == NULL)
		върни SSH_ERR_INVALID_ARGUMENT;
	ако ((r = sshbuf_put_cstring(b,
	    sshkey_curve_nid_to_name(key->ecdsa_nid))) != 0 ||
	    (r = sshbuf_put_ec_pkey(b, key->pkey)) != 0)
		върни r;

	върни 0;
}

static цяло
ssh_ecdsa_serialize_private(const struct sshkey *key, struct sshbuf *b,
    enum sshkey_serialize_rep opts)
{
	цяло r;

	ако (!sshkey_is_cert(key)) {
		ако ((r = ssh_ecdsa_serialize_public(key, b, opts)) != 0)
			върни r;
	}
	ако ((r = sshbuf_put_bignum2(b,
	    EC_KEY_get0_private_key(EVP_PKEY_get0_EC_KEY(key->pkey)))) != 0)
		върни r;
	върни 0;
}

static цяло
ssh_ecdsa_generate(struct sshkey *k, цяло bits)
{
	EVP_PKEY *res = NULL;
	EVP_PKEY_CTX *ctx = NULL;
	цяло ret = SSH_ERR_INTERNAL_ERROR;

	ако ((k->ecdsa_nid = sshkey_ecdsa_bits_to_nid(bits)) == -1)
		върни SSH_ERR_KEY_LENGTH;

	ако ((ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL)) == NULL)
		върни SSH_ERR_ALLOC_FAIL;

	ако (EVP_PKEY_keygen_init(ctx) <= 0 ||
	    EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, k->ecdsa_nid) <= 0 ||
	    EVP_PKEY_keygen(ctx, &res) <= 0) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	/* success */
	k->pkey = res;
	res = NULL;
	ret = 0;
 out:
	EVP_PKEY_free(res);
	EVP_PKEY_CTX_free(ctx);
	върни ret;
}

static цяло
ssh_ecdsa_copy_public(const struct sshkey *from, struct sshkey *to)
{
	const EC_KEY *ec_from;
	EC_KEY *ec_to = NULL;
	цяло ret = SSH_ERR_INTERNAL_ERROR;

	ec_from = EVP_PKEY_get0_EC_KEY(from->pkey);
	ако (ec_from == NULL)
		върни SSH_ERR_LIBCRYPTO_ERROR;

	to->ecdsa_nid = from->ecdsa_nid;
	ако ((ec_to = EC_KEY_new_by_curve_name(from->ecdsa_nid)) == NULL)
		върни SSH_ERR_ALLOC_FAIL;
	ако (EC_KEY_set_public_key(ec_to,
	    EC_KEY_get0_public_key(ec_from)) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	EVP_PKEY_free(to->pkey);
	ако ((to->pkey = EVP_PKEY_new()) == NULL) {
		ret = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	ако (EVP_PKEY_set1_EC_KEY(to->pkey, ec_to) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	ret = 0;
 out:
	EC_KEY_free(ec_to);
	върни ret;
}

static цяло
ssh_ecdsa_deserialize_public(const char *ktype, struct sshbuf *b,
    struct sshkey *key)
{
	цяло r;
	char *curve = NULL;
	EVP_PKEY *pkey = NULL;
	EC_KEY *ec = NULL;

	ако ((key->ecdsa_nid = sshkey_ecdsa_nid_from_name(ktype)) == -1)
		върни SSH_ERR_INVALID_ARGUMENT;
	ако ((r = sshbuf_get_cstring(b, &curve, NULL)) != 0)
		goto out;
	ако (key->ecdsa_nid != sshkey_curve_name_to_nid(curve)) {
		r = SSH_ERR_EC_CURVE_MISMATCH;
		goto out;
	}
	ако ((ec = EC_KEY_new_by_curve_name(key->ecdsa_nid)) == NULL) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	ако ((r = sshbuf_get_eckey(b, ec)) != 0)
		goto out;
	ако (sshkey_ec_validate_public(EC_KEY_get0_group(ec),
	    EC_KEY_get0_public_key(ec)) != 0) {
		r = SSH_ERR_KEY_INVALID_EC_VALUE;
		goto out;
	}
	ако ((pkey = EVP_PKEY_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	ако (EVP_PKEY_set1_EC_KEY(pkey, ec) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	EVP_PKEY_free(key->pkey);
	key->pkey = pkey;
	pkey = NULL;
	/* success */
	r = 0;
#ifdef DEBUG_PK
	sshkey_dump_ec_point(
	    EC_KEY_get0_group(EVP_PKEY_get0_EC_KEY(key->pkey)),
	    EC_KEY_get0_public_key(EVP_PKEY_get0_EC_KEY(key->pkey)));
#endif
 out:
	EC_KEY_free(ec);
	EVP_PKEY_free(pkey);
	free(curve);
	върни r;
}

static цяло
ssh_ecdsa_deserialize_private(const char *ktype, struct sshbuf *b,
    struct sshkey *key)
{
	цяло r;
	BIGNUM *exponent = NULL;
	EC_KEY *ec = NULL;

	ако (!sshkey_is_cert(key)) {
		ако ((r = ssh_ecdsa_deserialize_public(ktype, b, key)) != 0)
			върни r;
	}
	ако ((r = sshbuf_get_bignum2(b, &exponent)) != 0)
		goto out;
	ако ((ec = EVP_PKEY_get1_EC_KEY(key->pkey)) == NULL) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	ако (EC_KEY_set_private_key(ec, exponent) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	ако ((r = sshkey_ec_validate_private(ec)) != 0)
		goto out;
	ако (EVP_PKEY_set1_EC_KEY(key->pkey, ec) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	/* success */
	r = 0;
 out:
	BN_clear_free(exponent);
	EC_KEY_free(ec);
	върни r;
}

static цяло
ssh_ecdsa_sign(struct sshkey *key,
    u_char **sigp, size_t *lenp,
    const u_char *data, size_t dlen,
    const char *alg, const char *sk_provider, const char *sk_pin, u_int compat)
{
	ECDSA_SIG *esig = NULL;
	unsigned char *sigb = NULL;
	const unsigned char *psig;
	const BIGNUM *sig_r, *sig_s;
	цяло hash_alg;
	size_t slen = 0;
	цяло ret = SSH_ERR_INTERNAL_ERROR;

	ако (lenp != NULL)
		*lenp = 0;
	ако (sigp != NULL)
		*sigp = NULL;

	ако (key == NULL || key->pkey == NULL ||
	    sshkey_type_plain(key->type) != KEY_ECDSA)
		върни SSH_ERR_INVALID_ARGUMENT;

	ако ((hash_alg = sshkey_ec_nid_to_hash_alg(key->ecdsa_nid)) == -1)
		върни SSH_ERR_INTERNAL_ERROR;

	ако ((ret = sshkey_pkey_digest_sign(key->pkey, hash_alg, &sigb, &slen,
	    data, dlen)) != 0)
		goto out;

	psig = sigb;
	ако ((esig = d2i_ECDSA_SIG(NULL, &psig, slen)) == NULL) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	ECDSA_SIG_get0(esig, &sig_r, &sig_s);

	ако ((ret = ssh_ecdsa_encode_store_sig(key, sig_r, sig_s,
	    sigp, lenp)) != 0)
		goto out;
	/* success */
	ret = 0;
 out:
	freezero(sigb, slen);
	ECDSA_SIG_free(esig);
	върни ret;
}

цяло
ssh_ecdsa_encode_store_sig(const struct sshkey *key,
    const BIGNUM *sig_r, const BIGNUM *sig_s,
    u_char **sigp, size_t *lenp)
{
	struct sshbuf *b = NULL, *bb = NULL;
	цяло ret;
	size_t len;

	ако (lenp != NULL)
		*lenp = 0;
	ако (sigp != NULL)
		*sigp = NULL;

	ако ((bb = sshbuf_new()) == NULL || (b = sshbuf_new()) == NULL) {
		ret = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	ако ((ret = sshbuf_put_bignum2(bb, sig_r)) != 0 ||
	    (ret = sshbuf_put_bignum2(bb, sig_s)) != 0)
		goto out;
	ако ((ret = sshbuf_put_cstring(b, sshkey_ssh_name_plain(key))) != 0 ||
	    (ret = sshbuf_put_stringb(b, bb)) != 0)
		goto out;
	len = sshbuf_len(b);
	ако (sigp != NULL) {
		ако ((*sigp = malloc(len)) == NULL) {
			ret = SSH_ERR_ALLOC_FAIL;
			goto out;
		}
		memcpy(*sigp, sshbuf_ptr(b), len);
	}
	ако (lenp != NULL)
		*lenp = len;
	ret = 0;
 out:
	sshbuf_free(b);
	sshbuf_free(bb);
	върни ret;
}

static цяло
ssh_ecdsa_verify(const struct sshkey *key,
    const u_char *sig, size_t siglen,
    const u_char *data, size_t dlen, const char *alg, u_int compat,
    struct sshkey_sig_details **detailsp)
{
	ECDSA_SIG *esig = NULL;
	BIGNUM *sig_r = NULL, *sig_s = NULL;
	цяло hash_alg, len = 0;
	цяло ret = SSH_ERR_INTERNAL_ERROR;
	struct sshbuf *b = NULL, *sigbuf = NULL;
	char *ktype = NULL;
	unsigned char *sigb = NULL, *cp;

	ако (key == NULL || key->pkey == NULL ||
	    sshkey_type_plain(key->type) != KEY_ECDSA ||
	    sig == NULL || siglen == 0)
		върни SSH_ERR_INVALID_ARGUMENT;

	ако ((hash_alg = sshkey_ec_nid_to_hash_alg(key->ecdsa_nid)) == -1)
		върни SSH_ERR_INTERNAL_ERROR;

	/* fetch signature */
	ако ((b = sshbuf_from(sig, siglen)) == NULL)
		върни SSH_ERR_ALLOC_FAIL;
	ако (sshbuf_get_cstring(b, &ktype, NULL) != 0 ||
	    sshbuf_froms(b, &sigbuf) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	ако (strcmp(sshkey_ssh_name_plain(key), ktype) != 0) {
		ret = SSH_ERR_KEY_TYPE_MISMATCH;
		goto out;
	}
	ако (sshbuf_len(b) != 0) {
		ret = SSH_ERR_UNEXPECTED_TRAILING_DATA;
		goto out;
	}

	/* parse signature */
	ако (sshbuf_get_bignum2(sigbuf, &sig_r) != 0 ||
	    sshbuf_get_bignum2(sigbuf, &sig_s) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	ако (sshbuf_len(sigbuf) != 0) {
		ret = SSH_ERR_UNEXPECTED_TRAILING_DATA;
		goto out;
	}

	ако ((esig = ECDSA_SIG_new()) == NULL) {
		ret = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	ако (!ECDSA_SIG_set0(esig, sig_r, sig_s)) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	sig_r = sig_s = NULL; /* transferred */

	ако ((len = i2d_ECDSA_SIG(esig, NULL)) <= 0) {
		len = 0;
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	ако ((sigb = calloc(1, len)) == NULL) {
		ret = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	cp = sigb; /* ASN1_item_i2d increments the pointer past the object */
	ако (i2d_ECDSA_SIG(esig, &cp) != len) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	ако ((ret = sshkey_pkey_digest_verify(key->pkey, hash_alg,
	    data, dlen, sigb, len)) != 0)
		goto out;
	/* success */
 out:
	freezero(sigb, len);
	sshbuf_free(sigbuf);
	sshbuf_free(b);
	ECDSA_SIG_free(esig);
	BN_clear_free(sig_r);
	BN_clear_free(sig_s);
	free(ktype);
	върни ret;
}

/* NB. not static; used by ECDSA-SK */
const struct sshkey_impl_funcs sshkey_ecdsa_funcs = {
	/* .size = */		ssh_ecdsa_size,
	/* .alloc = */		NULL,
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

const struct sshkey_impl sshkey_ecdsa_nistp256_impl = {
	/* .name = */		"ecdsa-sha2-nistp256",
	/* .shortname = */	"ECDSA",
	/* .sigalg = */		NULL,
	/* .type = */		KEY_ECDSA,
	/* .nid = */		NID_X9_62_prime256v1,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_ecdsa_funcs,
};

const struct sshkey_impl sshkey_ecdsa_nistp256_cert_impl = {
	/* .name = */		"ecdsa-sha2-nistp256-cert-v01@openssh.com",
	/* .shortname = */	"ECDSA-CERT",
	/* .sigalg = */		NULL,
	/* .type = */		KEY_ECDSA_CERT,
	/* .nid = */		NID_X9_62_prime256v1,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_ecdsa_funcs,
};

const struct sshkey_impl sshkey_ecdsa_nistp384_impl = {
	/* .name = */		"ecdsa-sha2-nistp384",
	/* .shortname = */	"ECDSA",
	/* .sigalg = */		NULL,
	/* .type = */		KEY_ECDSA,
	/* .nid = */		NID_secp384r1,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_ecdsa_funcs,
};

const struct sshkey_impl sshkey_ecdsa_nistp384_cert_impl = {
	/* .name = */		"ecdsa-sha2-nistp384-cert-v01@openssh.com",
	/* .shortname = */	"ECDSA-CERT",
	/* .sigalg = */		NULL,
	/* .type = */		KEY_ECDSA_CERT,
	/* .nid = */		NID_secp384r1,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_ecdsa_funcs,
};

const struct sshkey_impl sshkey_ecdsa_nistp521_impl = {
	/* .name = */		"ecdsa-sha2-nistp521",
	/* .shortname = */	"ECDSA",
	/* .sigalg = */		NULL,
	/* .type = */		KEY_ECDSA,
	/* .nid = */		NID_secp521r1,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_ecdsa_funcs,
};

const struct sshkey_impl sshkey_ecdsa_nistp521_cert_impl = {
	/* .name = */		"ecdsa-sha2-nistp521-cert-v01@openssh.com",
	/* .shortname = */	"ECDSA-CERT",
	/* .sigalg = */		NULL,
	/* .type = */		KEY_ECDSA_CERT,
	/* .nid = */		NID_secp521r1,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_ecdsa_funcs,
};

#endif /* WITH_OPENSSL */
