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

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ଯଦି defined(WITH_OPENSSL)
#ଅନ୍ତର୍ଭାଵ "openbsd-compat/openssl-compat.h"

#ଅନ୍ତର୍ଭାଵ <sys/types.h>

#ଅନ୍ତର୍ଭାଵ <openssl/bn.h>
#ଅନ୍ତର୍ଭାଵ <openssl/ec.h>
#ଅନ୍ତର୍ଭାଵ <openssl/ecdsa.h>
#ଅନ୍ତର୍ଭାଵ <openssl/evp.h>

#ଅନ୍ତର୍ଭାଵ <string.h>

#ଅନ୍ତର୍ଭାଵ "sshbuf.h"
#ଅନ୍ତର୍ଭାଵ "ssherr.h"
#define SSHKEY_INTERNAL
#ଅନ୍ତର୍ଭାଵ "sshkey.h"

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshkey_ecdsa_fixup_group(EVP_PKEY *k)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା nids[] = {
		NID_X9_62_prime256v1,
		NID_secp384r1,
		NID_secp521r1,
		-1
	};
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା nid = -1;
	u_int i;
	ଅଚଳ EC_GROUP *g;
	EC_ଚାବି *ec = ଖାଲି;
	EC_GROUP *eg = ଖାଲି;

	ଯଦି ((ec = EVP_PKEY_get1_EC_ଚାବି(k)) == ଖାଲି ||
	    (g = EC_ଚାବି_get0_group(ec)) == ଖାଲି)
		ଯାଅ out;
	/*
	 * The group may be stored in a ASN.1 encoded private key in one of two
	 * ways: as a "named group", which is reconstituted by ASN.1 object ID
	 * or explicit group parameters encoded into the key blob. Only the
	 * "named group" case sets the group NID for us, but we can figure
	 * it out for the other case by comparing against all the groups that
	 * are supported.
	 */
	ଯଦି ((nid = EC_GROUP_get_curve_name(g)) > 0)
		ଯାଅ out;
	nid = -1;
	ପାଇଁ (i = 0; nids[i] != -1; i++) {
		ଯଦି ((eg = EC_GROUP_new_by_curve_name(nids[i])) == ଖାଲି)
			ଯାଅ out;
		ଯଦି (EC_GROUP_cmp(g, eg, ଖାଲି) == 0)
			ଭାଙ୍ଗ;
		EC_GROUP_free(eg);
		eg = ଖାଲି;
	}
	ଯଦି (nids[i] == -1)
		ଯାଅ out;

	/* Use the group with the NID attached */
	EC_GROUP_set_asn1_flag(eg, OPENSSL_EC_NAMED_CURVE);
	ଯଦି (EC_ଚାବି_set_group(ec, eg) != 1 ||
	    EVP_PKEY_set1_EC_ଚାବି(k, ec) != 1)
		ଯାଅ out;
	/* success */
	nid = nids[i];
 out:
	EC_ଚାବି_free(ec);
	EC_GROUP_free(eg);
	ଫେରନ୍ତୁ nid;
}

ସ୍ଥିର u_int
ssh_ecdsa_size(ଅଚଳ ସଂରଚନା sshkey *ଚାବି)
{
	ବାଛ (ଚାବି->ecdsa_nid) {
	ସ୍ଥିତି NID_X9_62_prime256v1:
		ଫେରନ୍ତୁ 256;
	ସ୍ଥିତି NID_secp384r1:
		ଫେରନ୍ତୁ 384;
	ସ୍ଥିତି NID_secp521r1:
		ଫେରନ୍ତୁ 521;
	ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
		ଫେରନ୍ତୁ 0;
	}
}

ସ୍ଥିର ଶୂନ୍ୟ
ssh_ecdsa_cleanup(ସଂରଚନା sshkey *k)
{
	EVP_PKEY_free(k->pkey);
	k->pkey = ଖାଲି;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_ecdsa_equal(ଅଚଳ ସଂରଚନା sshkey *a, ଅଚଳ ସଂରଚନା sshkey *b)
{
	ଯଦି (a->pkey == ଖାଲି || b->pkey == ଖାଲି)
		ଫେରନ୍ତୁ 0;
	ଫେରନ୍ତୁ EVP_PKEY_cmp(a->pkey, b->pkey) == 1;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_ecdsa_serialize_public(ଅଚଳ ସଂରଚନା sshkey *ଚାବି, ସଂରଚନା sshbuf *b,
    ଗଣନା sshkey_serialize_rep opts)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି (ଚାବି->pkey == ଖାଲି)
		ଫେରନ୍ତୁ SSH_ERR_INVALID_ARGUMENT;
	ଯଦି ((r = sshbuf_put_cstring(b,
	    sshkey_curve_nid_to_name(ଚାବି->ecdsa_nid))) != 0 ||
	    (r = sshbuf_put_ec_pkey(b, ଚାବି->pkey)) != 0)
		ଫେରନ୍ତୁ r;

	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_ecdsa_serialize_private(ଅଚଳ ସଂରଚନା sshkey *ଚାବି, ସଂରଚନା sshbuf *b,
    ଗଣନା sshkey_serialize_rep opts)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି (!sshkey_is_cert(ଚାବି)) {
		ଯଦି ((r = ssh_ecdsa_serialize_public(ଚାବି, b, opts)) != 0)
			ଫେରନ୍ତୁ r;
	}
	ଯଦି ((r = sshbuf_put_bignum2(b,
	    EC_ଚାବି_get0_private_ଚାବି(EVP_PKEY_get0_EC_ଚାବି(ଚାବି->pkey)))) != 0)
		ଫେରନ୍ତୁ r;
	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_ecdsa_generate(ସଂରଚନା sshkey *k, ପୂର୍ଣ୍ଣସଂଖ୍ୟା bits)
{
	EVP_PKEY *res = ଖାଲି;
	EVP_PKEY_CTX *ctx = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା ret = SSH_ERR_INTERNAL_ERROR;

	ଯଦି ((k->ecdsa_nid = sshkey_ecdsa_bits_to_nid(bits)) == -1)
		ଫେରନ୍ତୁ SSH_ERR_ଚାବି_LENGTH;

	ଯଦି ((ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, ଖାଲି)) == ଖାଲି)
		ଫେରନ୍ତୁ SSH_ERR_ALLOC_FAIL;

	ଯଦି (EVP_PKEY_keygen_init(ctx) <= 0 ||
	    EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, k->ecdsa_nid) <= 0 ||
	    EVP_PKEY_keygen(ctx, &res) <= 0) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		ଯାଅ out;
	}
	/* success */
	k->pkey = res;
	res = ଖାଲି;
	ret = 0;
 out:
	EVP_PKEY_free(res);
	EVP_PKEY_CTX_free(ctx);
	ଫେରନ୍ତୁ ret;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_ecdsa_copy_public(ଅଚଳ ସଂରଚନା sshkey *from, ସଂରଚନା sshkey *to)
{
	ଅଚଳ EC_ଚାବି *ec_from;
	EC_ଚାବି *ec_to = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା ret = SSH_ERR_INTERNAL_ERROR;

	ec_from = EVP_PKEY_get0_EC_ଚାବି(from->pkey);
	ଯଦି (ec_from == ଖାଲି)
		ଫେରନ୍ତୁ SSH_ERR_LIBCRYPTO_ERROR;

	to->ecdsa_nid = from->ecdsa_nid;
	ଯଦି ((ec_to = EC_ଚାବି_new_by_curve_name(from->ecdsa_nid)) == ଖାଲି)
		ଫେରନ୍ତୁ SSH_ERR_ALLOC_FAIL;
	ଯଦି (EC_ଚାବି_set_public_ଚାବି(ec_to,
	    EC_ଚାବି_get0_public_ଚାବି(ec_from)) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		ଯାଅ out;
	}
	EVP_PKEY_free(to->pkey);
	ଯଦି ((to->pkey = EVP_PKEY_new()) == ଖାଲି) {
		ret = SSH_ERR_ALLOC_FAIL;
		ଯାଅ out;
	}
	ଯଦି (EVP_PKEY_set1_EC_ଚାବି(to->pkey, ec_to) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		ଯାଅ out;
	}
	ret = 0;
 out:
	EC_ଚାବି_free(ec_to);
	ଫେରନ୍ତୁ ret;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_ecdsa_deserialize_public(ଅଚଳ ଅକ୍ଷର *ktype, ସଂରଚନା sshbuf *b,
    ସଂରଚନା sshkey *ଚାବି)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;
	ଅକ୍ଷର *curve = ଖାଲି;
	EVP_PKEY *pkey = ଖାଲି;
	EC_ଚାବି *ec = ଖାଲି;

	ଯଦି ((ଚାବି->ecdsa_nid = sshkey_ecdsa_nid_from_name(ktype)) == -1)
		ଫେରନ୍ତୁ SSH_ERR_INVALID_ARGUMENT;
	ଯଦି ((r = sshbuf_get_cstring(b, &curve, ଖାଲି)) != 0)
		ଯାଅ out;
	ଯଦି (ଚାବି->ecdsa_nid != sshkey_curve_name_to_nid(curve)) {
		r = SSH_ERR_EC_CURVE_MISMATCH;
		ଯାଅ out;
	}
	ଯଦି ((ec = EC_ଚାବି_new_by_curve_name(ଚାବି->ecdsa_nid)) == ଖାଲି) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		ଯାଅ out;
	}
	ଯଦି ((r = sshbuf_get_eckey(b, ec)) != 0)
		ଯାଅ out;
	ଯଦି (sshkey_ec_validate_public(EC_ଚାବି_get0_group(ec),
	    EC_ଚାବି_get0_public_ଚାବି(ec)) != 0) {
		r = SSH_ERR_ଚାବି_INVALID_EC_ମୂଲ୍ୟ;
		ଯାଅ out;
	}
	ଯଦି ((pkey = EVP_PKEY_new()) == ଖାଲି) {
		r = SSH_ERR_ALLOC_FAIL;
		ଯାଅ out;
	}
	ଯଦି (EVP_PKEY_set1_EC_ଚାବି(pkey, ec) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		ଯାଅ out;
	}
	EVP_PKEY_free(ଚାବି->pkey);
	ଚାବି->pkey = pkey;
	pkey = ଖାଲି;
	/* success */
	r = 0;
#ifdef DEBUG_PK
	sshkey_dump_ec_point(
	    EC_ଚାବି_get0_group(EVP_PKEY_get0_EC_ଚାବି(ଚାବି->pkey)),
	    EC_ଚାବି_get0_public_ଚାବି(EVP_PKEY_get0_EC_ଚାବି(ଚାବି->pkey)));
#endif
 out:
	EC_ଚାବି_free(ec);
	EVP_PKEY_free(pkey);
	ମୁକ୍ତ(curve);
	ଫେରନ୍ତୁ r;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_ecdsa_deserialize_private(ଅଚଳ ଅକ୍ଷର *ktype, ସଂରଚନା sshbuf *b,
    ସଂରଚନା sshkey *ଚାବି)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;
	BIGNUM *exponent = ଖାଲି;
	EC_ଚାବି *ec = ଖାଲି;

	ଯଦି (!sshkey_is_cert(ଚାବି)) {
		ଯଦି ((r = ssh_ecdsa_deserialize_public(ktype, b, ଚାବି)) != 0)
			ଫେରନ୍ତୁ r;
	}
	ଯଦି ((r = sshbuf_get_bignum2(b, &exponent)) != 0)
		ଯାଅ out;
	ଯଦି ((ec = EVP_PKEY_get1_EC_ଚାବି(ଚାବି->pkey)) == ଖାଲି) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		ଯାଅ out;
	}
	ଯଦି (EC_ଚାବି_set_private_ଚାବି(ec, exponent) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		ଯାଅ out;
	}
	ଯଦି ((r = sshkey_ec_validate_private(ec)) != 0)
		ଯାଅ out;
	ଯଦି (EVP_PKEY_set1_EC_ଚାବି(ଚାବି->pkey, ec) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		ଯାଅ out;
	}
	/* success */
	r = 0;
 out:
	BN_clear_free(exponent);
	EC_ଚାବି_free(ec);
	ଫେରନ୍ତୁ r;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_ecdsa_sign(ସଂରଚନା sshkey *ଚାବି,
    u_char **sigp, size_t *lenp,
    ଅଚଳ u_char *data, size_t dlen,
    ଅଚଳ ଅକ୍ଷର *alg, ଅଚଳ ଅକ୍ଷର *sk_provider, ଅଚଳ ଅକ୍ଷର *sk_pin, u_int compat)
{
	ECDSA_SIG *esig = ଖାଲି;
	unsigned ଅକ୍ଷର *sigb = ଖାଲି;
	ଅଚଳ unsigned ଅକ୍ଷର *psig;
	ଅଚଳ BIGNUM *sig_r, *sig_s;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା hash_alg;
	size_t slen = 0;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା ret = SSH_ERR_INTERNAL_ERROR;

	ଯଦି (lenp != ଖାଲି)
		*lenp = 0;
	ଯଦି (sigp != ଖାଲି)
		*sigp = ଖାଲି;

	ଯଦି (ଚାବି == ଖାଲି || ଚାବି->pkey == ଖାଲି ||
	    sshkey_type_plain(ଚାବି->type) != ଚାବି_ECDSA)
		ଫେରନ୍ତୁ SSH_ERR_INVALID_ARGUMENT;

	ଯଦି ((hash_alg = sshkey_ec_nid_to_hash_alg(ଚାବି->ecdsa_nid)) == -1)
		ଫେରନ୍ତୁ SSH_ERR_INTERNAL_ERROR;

	ଯଦି ((ret = sshkey_pkey_digest_sign(ଚାବି->pkey, hash_alg, &sigb, &slen,
	    data, dlen)) != 0)
		ଯାଅ out;

	psig = sigb;
	ଯଦି ((esig = d2i_ECDSA_SIG(ଖାଲି, &psig, slen)) == ଖାଲି) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		ଯାଅ out;
	}
	ECDSA_SIG_get0(esig, &sig_r, &sig_s);

	ଯଦି ((ret = ssh_ecdsa_encode_store_sig(ଚାବି, sig_r, sig_s,
	    sigp, lenp)) != 0)
		ଯାଅ out;
	/* success */
	ret = 0;
 out:
	freezero(sigb, slen);
	ECDSA_SIG_free(esig);
	ଫେରନ୍ତୁ ret;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_ecdsa_encode_store_sig(ଅଚଳ ସଂରଚନା sshkey *ଚାବି,
    ଅଚଳ BIGNUM *sig_r, ଅଚଳ BIGNUM *sig_s,
    u_char **sigp, size_t *lenp)
{
	ସଂରଚନା sshbuf *b = ଖାଲି, *bb = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା ret;
	size_t len;

	ଯଦି (lenp != ଖାଲି)
		*lenp = 0;
	ଯଦି (sigp != ଖାଲି)
		*sigp = ଖାଲି;

	ଯଦି ((bb = sshbuf_new()) == ଖାଲି || (b = sshbuf_new()) == ଖାଲି) {
		ret = SSH_ERR_ALLOC_FAIL;
		ଯାଅ out;
	}
	ଯଦି ((ret = sshbuf_put_bignum2(bb, sig_r)) != 0 ||
	    (ret = sshbuf_put_bignum2(bb, sig_s)) != 0)
		ଯାଅ out;
	ଯଦି ((ret = sshbuf_put_cstring(b, sshkey_ssh_name_plain(ଚାବି))) != 0 ||
	    (ret = sshbuf_put_stringb(b, bb)) != 0)
		ଯାଅ out;
	len = sshbuf_len(b);
	ଯଦି (sigp != ଖାଲି) {
		ଯଦି ((*sigp = malloc(len)) == ଖାଲି) {
			ret = SSH_ERR_ALLOC_FAIL;
			ଯାଅ out;
		}
		memcpy(*sigp, sshbuf_ptr(b), len);
	}
	ଯଦି (lenp != ଖାଲି)
		*lenp = len;
	ret = 0;
 out:
	sshbuf_free(b);
	sshbuf_free(bb);
	ଫେରନ୍ତୁ ret;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_ecdsa_verify(ଅଚଳ ସଂରଚନା sshkey *ଚାବି,
    ଅଚଳ u_char *sig, size_t siglen,
    ଅଚଳ u_char *data, size_t dlen, ଅଚଳ ଅକ୍ଷର *alg, u_int compat,
    ସଂରଚନା sshkey_sig_details **detailsp)
{
	ECDSA_SIG *esig = ଖାଲି;
	BIGNUM *sig_r = ଖାଲି, *sig_s = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା hash_alg, len = 0;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା ret = SSH_ERR_INTERNAL_ERROR;
	ସଂରଚନା sshbuf *b = ଖାଲି, *sigbuf = ଖାଲି;
	ଅକ୍ଷର *ktype = ଖାଲି;
	unsigned ଅକ୍ଷର *sigb = ଖାଲି, *cp;

	ଯଦି (ଚାବି == ଖାଲି || ଚାବି->pkey == ଖାଲି ||
	    sshkey_type_plain(ଚାବି->type) != ଚାବି_ECDSA ||
	    sig == ଖାଲି || siglen == 0)
		ଫେରନ୍ତୁ SSH_ERR_INVALID_ARGUMENT;

	ଯଦି ((hash_alg = sshkey_ec_nid_to_hash_alg(ଚାବି->ecdsa_nid)) == -1)
		ଫେରନ୍ତୁ SSH_ERR_INTERNAL_ERROR;

	/* fetch signature */
	ଯଦି ((b = sshbuf_from(sig, siglen)) == ଖାଲି)
		ଫେରନ୍ତୁ SSH_ERR_ALLOC_FAIL;
	ଯଦି (sshbuf_get_cstring(b, &ktype, ଖାଲି) != 0 ||
	    sshbuf_froms(b, &sigbuf) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		ଯାଅ out;
	}
	ଯଦି (strcmp(sshkey_ssh_name_plain(ଚାବି), ktype) != 0) {
		ret = SSH_ERR_ଚାବି_TYPE_MISMATCH;
		ଯାଅ out;
	}
	ଯଦି (sshbuf_len(b) != 0) {
		ret = SSH_ERR_UNEXPECTED_TRAILING_DATA;
		ଯାଅ out;
	}

	/* parse signature */
	ଯଦି (sshbuf_get_bignum2(sigbuf, &sig_r) != 0 ||
	    sshbuf_get_bignum2(sigbuf, &sig_s) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		ଯାଅ out;
	}
	ଯଦି (sshbuf_len(sigbuf) != 0) {
		ret = SSH_ERR_UNEXPECTED_TRAILING_DATA;
		ଯାଅ out;
	}

	ଯଦି ((esig = ECDSA_SIG_new()) == ଖାଲି) {
		ret = SSH_ERR_ALLOC_FAIL;
		ଯାଅ out;
	}
	ଯଦି (!ECDSA_SIG_set0(esig, sig_r, sig_s)) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		ଯାଅ out;
	}
	sig_r = sig_s = ଖାଲି; /* transferred */

	ଯଦି ((len = i2d_ECDSA_SIG(esig, ଖାଲି)) <= 0) {
		len = 0;
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		ଯାଅ out;
	}
	ଯଦି ((sigb = calloc(1, len)) == ଖାଲି) {
		ret = SSH_ERR_ALLOC_FAIL;
		ଯାଅ out;
	}
	cp = sigb; /* ASN1_item_i2d increments the pointer past the object */
	ଯଦି (i2d_ECDSA_SIG(esig, &cp) != len) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		ଯାଅ out;
	}
	ଯଦି ((ret = sshkey_pkey_digest_verify(ଚାବି->pkey, hash_alg,
	    data, dlen, sigb, len)) != 0)
		ଯାଅ out;
	/* success */
 out:
	freezero(sigb, len);
	sshbuf_free(sigbuf);
	sshbuf_free(b);
	ECDSA_SIG_free(esig);
	BN_clear_free(sig_r);
	BN_clear_free(sig_s);
	ମୁକ୍ତ(ktype);
	ଫେରନ୍ତୁ ret;
}

/* NB. not static; used by ECDSA-SK */
ଅଚଳ ସଂରଚନା sshkey_impl_funcs sshkey_ecdsa_funcs = {
	/* .size = */		ssh_ecdsa_size,
	/* .alloc = */		ଖାଲି,
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

ଅଚଳ ସଂରଚନା sshkey_impl sshkey_ecdsa_nistp256_impl = {
	/* .name = */		"ecdsa-sha2-nistp256",
	/* .shortname = */	"ECDSA",
	/* .sigalg = */		ଖାଲି,
	/* .type = */		ଚାବି_ECDSA,
	/* .nid = */		NID_X9_62_prime256v1,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_ecdsa_funcs,
};

ଅଚଳ ସଂରଚନା sshkey_impl sshkey_ecdsa_nistp256_cert_impl = {
	/* .name = */		"ecdsa-sha2-nistp256-cert-v01@openssh.com",
	/* .shortname = */	"ECDSA-CERT",
	/* .sigalg = */		ଖାଲି,
	/* .type = */		ଚାବି_ECDSA_CERT,
	/* .nid = */		NID_X9_62_prime256v1,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_ecdsa_funcs,
};

ଅଚଳ ସଂରଚନା sshkey_impl sshkey_ecdsa_nistp384_impl = {
	/* .name = */		"ecdsa-sha2-nistp384",
	/* .shortname = */	"ECDSA",
	/* .sigalg = */		ଖାଲି,
	/* .type = */		ଚାବି_ECDSA,
	/* .nid = */		NID_secp384r1,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_ecdsa_funcs,
};

ଅଚଳ ସଂରଚନା sshkey_impl sshkey_ecdsa_nistp384_cert_impl = {
	/* .name = */		"ecdsa-sha2-nistp384-cert-v01@openssh.com",
	/* .shortname = */	"ECDSA-CERT",
	/* .sigalg = */		ଖାଲି,
	/* .type = */		ଚାବି_ECDSA_CERT,
	/* .nid = */		NID_secp384r1,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_ecdsa_funcs,
};

ଅଚଳ ସଂରଚନା sshkey_impl sshkey_ecdsa_nistp521_impl = {
	/* .name = */		"ecdsa-sha2-nistp521",
	/* .shortname = */	"ECDSA",
	/* .sigalg = */		ଖାଲି,
	/* .type = */		ଚାବି_ECDSA,
	/* .nid = */		NID_secp521r1,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_ecdsa_funcs,
};

ଅଚଳ ସଂରଚନା sshkey_impl sshkey_ecdsa_nistp521_cert_impl = {
	/* .name = */		"ecdsa-sha2-nistp521-cert-v01@openssh.com",
	/* .shortname = */	"ECDSA-CERT",
	/* .sigalg = */		ଖାଲି,
	/* .type = */		ଚାବି_ECDSA_CERT,
	/* .nid = */		NID_secp521r1,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_ecdsa_funcs,
};

#endif /* WITH_OPENSSL */
