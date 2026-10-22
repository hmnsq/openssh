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

#якщо defined(WITH_OPENSSL)
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

ціле
sshkey_ecdsa_fixup_group(EVP_PKEY *k)
{
	ціле nids[] = {
		NID_X9_62_prime256v1,
		NID_secp384r1,
		NID_secp521r1,
		-1
	};
	ціле nid = -1;
	u_int i;
	const EC_GROUP *g;
	EC_KEY *ec = NULL;
	EC_GROUP *eg = NULL;

	якщо ((ec = EVP_PKEY_get1_EC_KEY(k)) == NULL ||
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
	якщо ((nid = EC_GROUP_get_curve_name(g)) > 0)
		goto out;
	nid = -1;
	для (i = 0; nids[i] != -1; i++) {
		якщо ((eg = EC_GROUP_new_by_curve_name(nids[i])) == NULL)
			goto out;
		якщо (EC_GROUP_cmp(g, eg, NULL) == 0)
			break;
		EC_GROUP_free(eg);
		eg = NULL;
	}
	якщо (nids[i] == -1)
		goto out;

	/* Use the group with the NID attached */
	EC_GROUP_set_asn1_flag(eg, OPENSSL_EC_NAMED_CURVE);
	якщо (EC_KEY_set_group(ec, eg) != 1 ||
	    EVP_PKEY_set1_EC_KEY(k, ec) != 1)
		goto out;
	/* success */
	nid = nids[i];
 out:
	EC_KEY_free(ec);
	EC_GROUP_free(eg);
	повернути nid;
}

static u_int
ssh_ecdsa_size(const struct sshkey *key)
{
	switch (key->ecdsa_nid) {
	case NID_X9_62_prime256v1:
		повернути 256;
	case NID_secp384r1:
		повернути 384;
	case NID_secp521r1:
		повернути 521;
	default:
		повернути 0;
	}
}

static void
ssh_ecdsa_cleanup(struct sshkey *k)
{
	EVP_PKEY_free(k->pkey);
	k->pkey = NULL;
}

static ціле
ssh_ecdsa_equal(const struct sshkey *a, const struct sshkey *b)
{
	якщо (a->pkey == NULL || b->pkey == NULL)
		повернути 0;
	повернути EVP_PKEY_cmp(a->pkey, b->pkey) == 1;
}

static ціле
ssh_ecdsa_serialize_public(const struct sshkey *key, struct sshbuf *b,
    enum sshkey_serialize_rep opts)
{
	ціле r;

	якщо (key->pkey == NULL)
		повернути SSH_ERR_INVALID_ARGUMENT;
	якщо ((r = sshbuf_put_cstring(b,
	    sshkey_curve_nid_to_name(key->ecdsa_nid))) != 0 ||
	    (r = sshbuf_put_ec_pkey(b, key->pkey)) != 0)
		повернути r;

	повернути 0;
}

static ціле
ssh_ecdsa_serialize_private(const struct sshkey *key, struct sshbuf *b,
    enum sshkey_serialize_rep opts)
{
	ціле r;

	якщо (!sshkey_is_cert(key)) {
		якщо ((r = ssh_ecdsa_serialize_public(key, b, opts)) != 0)
			повернути r;
	}
	якщо ((r = sshbuf_put_bignum2(b,
	    EC_KEY_get0_private_key(EVP_PKEY_get0_EC_KEY(key->pkey)))) != 0)
		повернути r;
	повернути 0;
}

static ціле
ssh_ecdsa_generate(struct sshkey *k, ціле bits)
{
	EVP_PKEY *res = NULL;
	EVP_PKEY_CTX *ctx = NULL;
	ціле ret = SSH_ERR_INTERNAL_ERROR;

	якщо ((k->ecdsa_nid = sshkey_ecdsa_bits_to_nid(bits)) == -1)
		повернути SSH_ERR_KEY_LENGTH;

	якщо ((ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL)) == NULL)
		повернути SSH_ERR_ALLOC_FAIL;

	якщо (EVP_PKEY_keygen_init(ctx) <= 0 ||
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
	повернути ret;
}

static ціле
ssh_ecdsa_copy_public(const struct sshkey *from, struct sshkey *to)
{
	const EC_KEY *ec_from;
	EC_KEY *ec_to = NULL;
	ціле ret = SSH_ERR_INTERNAL_ERROR;

	ec_from = EVP_PKEY_get0_EC_KEY(from->pkey);
	якщо (ec_from == NULL)
		повернути SSH_ERR_LIBCRYPTO_ERROR;

	to->ecdsa_nid = from->ecdsa_nid;
	якщо ((ec_to = EC_KEY_new_by_curve_name(from->ecdsa_nid)) == NULL)
		повернути SSH_ERR_ALLOC_FAIL;
	якщо (EC_KEY_set_public_key(ec_to,
	    EC_KEY_get0_public_key(ec_from)) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	EVP_PKEY_free(to->pkey);
	якщо ((to->pkey = EVP_PKEY_new()) == NULL) {
		ret = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	якщо (EVP_PKEY_set1_EC_KEY(to->pkey, ec_to) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	ret = 0;
 out:
	EC_KEY_free(ec_to);
	повернути ret;
}

static ціле
ssh_ecdsa_deserialize_public(const char *ktype, struct sshbuf *b,
    struct sshkey *key)
{
	ціле r;
	char *curve = NULL;
	EVP_PKEY *pkey = NULL;
	EC_KEY *ec = NULL;

	якщо ((key->ecdsa_nid = sshkey_ecdsa_nid_from_name(ktype)) == -1)
		повернути SSH_ERR_INVALID_ARGUMENT;
	якщо ((r = sshbuf_get_cstring(b, &curve, NULL)) != 0)
		goto out;
	якщо (key->ecdsa_nid != sshkey_curve_name_to_nid(curve)) {
		r = SSH_ERR_EC_CURVE_MISMATCH;
		goto out;
	}
	якщо ((ec = EC_KEY_new_by_curve_name(key->ecdsa_nid)) == NULL) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	якщо ((r = sshbuf_get_eckey(b, ec)) != 0)
		goto out;
	якщо (sshkey_ec_validate_public(EC_KEY_get0_group(ec),
	    EC_KEY_get0_public_key(ec)) != 0) {
		r = SSH_ERR_KEY_INVALID_EC_VALUE;
		goto out;
	}
	якщо ((pkey = EVP_PKEY_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	якщо (EVP_PKEY_set1_EC_KEY(pkey, ec) != 1) {
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
	повернути r;
}

static ціле
ssh_ecdsa_deserialize_private(const char *ktype, struct sshbuf *b,
    struct sshkey *key)
{
	ціле r;
	BIGNUM *exponent = NULL;
	EC_KEY *ec = NULL;

	якщо (!sshkey_is_cert(key)) {
		якщо ((r = ssh_ecdsa_deserialize_public(ktype, b, key)) != 0)
			повернути r;
	}
	якщо ((r = sshbuf_get_bignum2(b, &exponent)) != 0)
		goto out;
	якщо ((ec = EVP_PKEY_get1_EC_KEY(key->pkey)) == NULL) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	якщо (EC_KEY_set_private_key(ec, exponent) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	якщо ((r = sshkey_ec_validate_private(ec)) != 0)
		goto out;
	якщо (EVP_PKEY_set1_EC_KEY(key->pkey, ec) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	/* success */
	r = 0;
 out:
	BN_clear_free(exponent);
	EC_KEY_free(ec);
	повернути r;
}

static ціле
ssh_ecdsa_sign(struct sshkey *key,
    u_char **sigp, size_t *lenp,
    const u_char *data, size_t dlen,
    const char *alg, const char *sk_provider, const char *sk_pin, u_int compat)
{
	ECDSA_SIG *esig = NULL;
	unsigned char *sigb = NULL;
	const unsigned char *psig;
	const BIGNUM *sig_r, *sig_s;
	ціле hash_alg;
	size_t slen = 0;
	ціле ret = SSH_ERR_INTERNAL_ERROR;

	якщо (lenp != NULL)
		*lenp = 0;
	якщо (sigp != NULL)
		*sigp = NULL;

	якщо (key == NULL || key->pkey == NULL ||
	    sshkey_type_plain(key->type) != KEY_ECDSA)
		повернути SSH_ERR_INVALID_ARGUMENT;

	якщо ((hash_alg = sshkey_ec_nid_to_hash_alg(key->ecdsa_nid)) == -1)
		повернути SSH_ERR_INTERNAL_ERROR;

	якщо ((ret = sshkey_pkey_digest_sign(key->pkey, hash_alg, &sigb, &slen,
	    data, dlen)) != 0)
		goto out;

	psig = sigb;
	якщо ((esig = d2i_ECDSA_SIG(NULL, &psig, slen)) == NULL) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	ECDSA_SIG_get0(esig, &sig_r, &sig_s);

	якщо ((ret = ssh_ecdsa_encode_store_sig(key, sig_r, sig_s,
	    sigp, lenp)) != 0)
		goto out;
	/* success */
	ret = 0;
 out:
	freezero(sigb, slen);
	ECDSA_SIG_free(esig);
	повернути ret;
}

ціле
ssh_ecdsa_encode_store_sig(const struct sshkey *key,
    const BIGNUM *sig_r, const BIGNUM *sig_s,
    u_char **sigp, size_t *lenp)
{
	struct sshbuf *b = NULL, *bb = NULL;
	ціле ret;
	size_t len;

	якщо (lenp != NULL)
		*lenp = 0;
	якщо (sigp != NULL)
		*sigp = NULL;

	якщо ((bb = sshbuf_new()) == NULL || (b = sshbuf_new()) == NULL) {
		ret = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	якщо ((ret = sshbuf_put_bignum2(bb, sig_r)) != 0 ||
	    (ret = sshbuf_put_bignum2(bb, sig_s)) != 0)
		goto out;
	якщо ((ret = sshbuf_put_cstring(b, sshkey_ssh_name_plain(key))) != 0 ||
	    (ret = sshbuf_put_stringb(b, bb)) != 0)
		goto out;
	len = sshbuf_len(b);
	якщо (sigp != NULL) {
		якщо ((*sigp = malloc(len)) == NULL) {
			ret = SSH_ERR_ALLOC_FAIL;
			goto out;
		}
		memcpy(*sigp, sshbuf_ptr(b), len);
	}
	якщо (lenp != NULL)
		*lenp = len;
	ret = 0;
 out:
	sshbuf_free(b);
	sshbuf_free(bb);
	повернути ret;
}

static ціле
ssh_ecdsa_verify(const struct sshkey *key,
    const u_char *sig, size_t siglen,
    const u_char *data, size_t dlen, const char *alg, u_int compat,
    struct sshkey_sig_details **detailsp)
{
	ECDSA_SIG *esig = NULL;
	BIGNUM *sig_r = NULL, *sig_s = NULL;
	ціле hash_alg, len = 0;
	ціле ret = SSH_ERR_INTERNAL_ERROR;
	struct sshbuf *b = NULL, *sigbuf = NULL;
	char *ktype = NULL;
	unsigned char *sigb = NULL, *cp;

	якщо (key == NULL || key->pkey == NULL ||
	    sshkey_type_plain(key->type) != KEY_ECDSA ||
	    sig == NULL || siglen == 0)
		повернути SSH_ERR_INVALID_ARGUMENT;

	якщо ((hash_alg = sshkey_ec_nid_to_hash_alg(key->ecdsa_nid)) == -1)
		повернути SSH_ERR_INTERNAL_ERROR;

	/* fetch signature */
	якщо ((b = sshbuf_from(sig, siglen)) == NULL)
		повернути SSH_ERR_ALLOC_FAIL;
	якщо (sshbuf_get_cstring(b, &ktype, NULL) != 0 ||
	    sshbuf_froms(b, &sigbuf) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	якщо (strcmp(sshkey_ssh_name_plain(key), ktype) != 0) {
		ret = SSH_ERR_KEY_TYPE_MISMATCH;
		goto out;
	}
	якщо (sshbuf_len(b) != 0) {
		ret = SSH_ERR_UNEXPECTED_TRAILING_DATA;
		goto out;
	}

	/* parse signature */
	якщо (sshbuf_get_bignum2(sigbuf, &sig_r) != 0 ||
	    sshbuf_get_bignum2(sigbuf, &sig_s) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	якщо (sshbuf_len(sigbuf) != 0) {
		ret = SSH_ERR_UNEXPECTED_TRAILING_DATA;
		goto out;
	}

	якщо ((esig = ECDSA_SIG_new()) == NULL) {
		ret = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	якщо (!ECDSA_SIG_set0(esig, sig_r, sig_s)) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	sig_r = sig_s = NULL; /* transferred */

	якщо ((len = i2d_ECDSA_SIG(esig, NULL)) <= 0) {
		len = 0;
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	якщо ((sigb = calloc(1, len)) == NULL) {
		ret = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	cp = sigb; /* ASN1_item_i2d increments the pointer past the object */
	якщо (i2d_ECDSA_SIG(esig, &cp) != len) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	якщо ((ret = sshkey_pkey_digest_verify(key->pkey, hash_alg,
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
	повернути ret;
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
