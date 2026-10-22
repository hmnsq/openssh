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

#شامل "includes.h"

#اگر defined(WITH_OPENSSL)
#شامل "openbsd-compat/openssl-compat.h"

#شامل <sys/types.h>

#شامل <openssl/bn.h>
#شامل <openssl/ec.h>
#شامل <openssl/ecdsa.h>
#شامل <openssl/evp.h>

#شامل <string.h>

#شامل "sshbuf.h"
#شامل "ssherr.h"
#تعریف_کرو SSHKEY_اندرونی
#شامل "sshkey.h"

صحیح
sshkey_ecdsa_fixup_گروہ(EVP_PKEY *k)
{
	صحیح nids[] = {
		NID_X9_62_prime256v1,
		NID_secp384r1,
		NID_secp521r1,
		-1
	};
	صحیح nid = -1;
	u_int i;
	ثابت EC_گروہ *g;
	EC_کلید *ec = تہی;
	EC_گروہ *eg = تہی;

	اگر ((ec = EVP_PKEY_get1_EC_کلید(k)) == تہی ||
	    (g = EC_کلید_get0_گروہ(ec)) == تہی)
		جاؤ برآمد;
	/*
	 * The group may be stored in a ASN.1 encoded private key in one of two
	 * ways: as a "named group", which is reconstituted by ASN.1 object ID
	 * or explicit group parameters encoded into the key blob. Only the
	 * "named group" case sets the group NID for us, but we can figure
	 * it out for the other case by comparing against all the groups that
	 * are supported.
	 */
	اگر ((nid = EC_گروہ_get_خم_name(g)) > 0)
		جاؤ برآمد;
	nid = -1;
	برائے (i = 0; nids[i] != -1; i++) {
		اگر ((eg = EC_گروہ_new_by_خم_name(nids[i])) == تہی)
			جاؤ برآمد;
		اگر (EC_گروہ_cmp(g, eg, تہی) == 0)
			توڑو;
		EC_گروہ_free(eg);
		eg = تہی;
	}
	اگر (nids[i] == -1)
		جاؤ برآمد;

	/* Use the group with the NID attached */
	EC_گروہ_سیٹ_asn1_flag(eg, OPENSSL_EC_NAMED_خم);
	اگر (EC_کلید_سیٹ_گروہ(ec, eg) != 1 ||
	    EVP_PKEY_set1_EC_کلید(k, ec) != 1)
		جاؤ برآمد;
	/* success */
	nid = nids[i];
 برآمد:
	EC_کلید_free(ec);
	EC_گروہ_free(eg);
	واپس nid;
}

ساکن u_int
ssh_ecdsa_سائز(ثابت ساخت sshkey *کلید)
{
	انتخاب (کلید->ecdsa_nid) {
	حالت NID_X9_62_prime256v1:
		واپس 256;
	حالت NID_secp384r1:
		واپس 384;
	حالت NID_secp521r1:
		واپس 521;
	طےشدہ:
		واپس 0;
	}
}

ساکن خالی
ssh_ecdsa_cleanup(ساخت sshkey *k)
{
	EVP_PKEY_free(k->pkey);
	k->pkey = تہی;
}

ساکن صحیح
ssh_ecdsa_equal(ثابت ساخت sshkey *a, ثابت ساخت sshkey *b)
{
	اگر (a->pkey == تہی || b->pkey == تہی)
		واپس 0;
	واپس EVP_PKEY_cmp(a->pkey, b->pkey) == 1;
}

ساکن صحیح
ssh_ecdsa_serialize_عوامی(ثابت ساخت sshkey *کلید, ساخت sshbuf *b,
    شمار sshkey_serialize_rep opts)
{
	صحیح r;

	اگر (کلید->pkey == تہی)
		واپس SSH_ERR_INVALID_دلیل;
	اگر ((r = sshbuf_put_cstring(b,
	    sshkey_خم_nid_مقصد_name(کلید->ecdsa_nid))) != 0 ||
	    (r = sshbuf_put_ec_pkey(b, کلید->pkey)) != 0)
		واپس r;

	واپس 0;
}

ساکن صحیح
ssh_ecdsa_serialize_نجی(ثابت ساخت sshkey *کلید, ساخت sshbuf *b,
    شمار sshkey_serialize_rep opts)
{
	صحیح r;

	اگر (!sshkey_is_cert(کلید)) {
		اگر ((r = ssh_ecdsa_serialize_عوامی(کلید, b, opts)) != 0)
			واپس r;
	}
	اگر ((r = sshbuf_put_bignum2(b,
	    EC_کلید_get0_نجی_کلید(EVP_PKEY_get0_EC_کلید(کلید->pkey)))) != 0)
		واپس r;
	واپس 0;
}

ساکن صحیح
ssh_ecdsa_generate(ساخت sshkey *k, صحیح بٹ)
{
	EVP_PKEY *res = تہی;
	EVP_PKEY_CTX *ctx = تہی;
	صحیح ret = SSH_ERR_اندرونی_ERROR;

	اگر ((k->ecdsa_nid = sshkey_ecdsa_بٹ_مقصد_nid(بٹ)) == -1)
		واپس SSH_ERR_کلید_لمبائی;

	اگر ((ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, تہی)) == تہی)
		واپس SSH_ERR_ALLOC_FAIL;

	اگر (EVP_PKEY_keygen_init(ctx) <= 0 ||
	    EVP_PKEY_CTX_سیٹ_ec_paramgen_خم_nid(ctx, k->ecdsa_nid) <= 0 ||
	    EVP_PKEY_keygen(ctx, &res) <= 0) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		جاؤ برآمد;
	}
	/* success */
	k->pkey = res;
	res = تہی;
	ret = 0;
 برآمد:
	EVP_PKEY_free(res);
	EVP_PKEY_CTX_free(ctx);
	واپس ret;
}

ساکن صحیح
ssh_ecdsa_copy_عوامی(ثابت ساخت sshkey *from, ساخت sshkey *مقصد)
{
	ثابت EC_کلید *ec_from;
	EC_کلید *ec_مقصد = تہی;
	صحیح ret = SSH_ERR_اندرونی_ERROR;

	ec_from = EVP_PKEY_get0_EC_کلید(from->pkey);
	اگر (ec_from == تہی)
		واپس SSH_ERR_LIBCRYPTO_ERROR;

	مقصد->ecdsa_nid = from->ecdsa_nid;
	اگر ((ec_مقصد = EC_کلید_new_by_خم_name(from->ecdsa_nid)) == تہی)
		واپس SSH_ERR_ALLOC_FAIL;
	اگر (EC_کلید_سیٹ_عوامی_کلید(ec_مقصد,
	    EC_کلید_get0_عوامی_کلید(ec_from)) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		جاؤ برآمد;
	}
	EVP_PKEY_free(مقصد->pkey);
	اگر ((مقصد->pkey = EVP_PKEY_new()) == تہی) {
		ret = SSH_ERR_ALLOC_FAIL;
		جاؤ برآمد;
	}
	اگر (EVP_PKEY_set1_EC_کلید(مقصد->pkey, ec_مقصد) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		جاؤ برآمد;
	}
	ret = 0;
 برآمد:
	EC_کلید_free(ec_مقصد);
	واپس ret;
}

ساکن صحیح
ssh_ecdsa_deserialize_عوامی(ثابت حرف *ktype, ساخت sshbuf *b,
    ساخت sshkey *کلید)
{
	صحیح r;
	حرف *خم = تہی;
	EVP_PKEY *pkey = تہی;
	EC_کلید *ec = تہی;

	اگر ((کلید->ecdsa_nid = sshkey_ecdsa_nid_from_name(ktype)) == -1)
		واپس SSH_ERR_INVALID_دلیل;
	اگر ((r = sshbuf_get_cstring(b, &خم, تہی)) != 0)
		جاؤ برآمد;
	اگر (کلید->ecdsa_nid != sshkey_خم_name_مقصد_nid(خم)) {
		r = SSH_ERR_EC_خم_MISMATCH;
		جاؤ برآمد;
	}
	اگر ((ec = EC_کلید_new_by_خم_name(کلید->ecdsa_nid)) == تہی) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		جاؤ برآمد;
	}
	اگر ((r = sshbuf_get_eckey(b, ec)) != 0)
		جاؤ برآمد;
	اگر (sshkey_ec_validate_عوامی(EC_کلید_get0_گروہ(ec),
	    EC_کلید_get0_عوامی_کلید(ec)) != 0) {
		r = SSH_ERR_کلید_INVALID_EC_قدر;
		جاؤ برآمد;
	}
	اگر ((pkey = EVP_PKEY_new()) == تہی) {
		r = SSH_ERR_ALLOC_FAIL;
		جاؤ برآمد;
	}
	اگر (EVP_PKEY_set1_EC_کلید(pkey, ec) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		جاؤ برآمد;
	}
	EVP_PKEY_free(کلید->pkey);
	کلید->pkey = pkey;
	pkey = تہی;
	/* success */
	r = 0;
#اگر_تعریف_شدہ DEBUG_PK
	sshkey_dump_ec_نقطہ(
	    EC_کلید_get0_گروہ(EVP_PKEY_get0_EC_کلید(کلید->pkey)),
	    EC_کلید_get0_عوامی_کلید(EVP_PKEY_get0_EC_کلید(کلید->pkey)));
#اگر_ختم
 برآمد:
	EC_کلید_free(ec);
	EVP_PKEY_free(pkey);
	آزاد(خم);
	واپس r;
}

ساکن صحیح
ssh_ecdsa_deserialize_نجی(ثابت حرف *ktype, ساخت sshbuf *b,
    ساخت sshkey *کلید)
{
	صحیح r;
	BIGNUM *exponent = تہی;
	EC_کلید *ec = تہی;

	اگر (!sshkey_is_cert(کلید)) {
		اگر ((r = ssh_ecdsa_deserialize_عوامی(ktype, b, کلید)) != 0)
			واپس r;
	}
	اگر ((r = sshbuf_get_bignum2(b, &exponent)) != 0)
		جاؤ برآمد;
	اگر ((ec = EVP_PKEY_get1_EC_کلید(کلید->pkey)) == تہی) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		جاؤ برآمد;
	}
	اگر (EC_کلید_سیٹ_نجی_کلید(ec, exponent) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		جاؤ برآمد;
	}
	اگر ((r = sshkey_ec_validate_نجی(ec)) != 0)
		جاؤ برآمد;
	اگر (EVP_PKEY_set1_EC_کلید(کلید->pkey, ec) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		جاؤ برآمد;
	}
	/* success */
	r = 0;
 برآمد:
	BN_clear_free(exponent);
	EC_کلید_free(ec);
	واپس r;
}

ساکن صحیح
ssh_ecdsa_sign(ساخت sshkey *کلید,
    u_char **sigp, سائز_t *lenp,
    ثابت u_char *ڈیٹا, سائز_t dlen,
    ثابت حرف *alg, ثابت حرف *sk_provider, ثابت حرف *sk_pin, u_int compat)
{
	ECDSA_SIG *esig = تہی;
	غیرعلامتی حرف *sigb = تہی;
	ثابت غیرعلامتی حرف *psig;
	ثابت BIGNUM *sig_r, *sig_s;
	صحیح hash_alg;
	سائز_t slen = 0;
	صحیح ret = SSH_ERR_اندرونی_ERROR;

	اگر (lenp != تہی)
		*lenp = 0;
	اگر (sigp != تہی)
		*sigp = تہی;

	اگر (کلید == تہی || کلید->pkey == تہی ||
	    sshkey_type_plain(کلید->type) != کلید_ECDSA)
		واپس SSH_ERR_INVALID_دلیل;

	اگر ((hash_alg = sshkey_ec_nid_مقصد_hash_alg(کلید->ecdsa_nid)) == -1)
		واپس SSH_ERR_اندرونی_ERROR;

	اگر ((ret = sshkey_pkey_digest_sign(کلید->pkey, hash_alg, &sigb, &slen,
	    ڈیٹا, dlen)) != 0)
		جاؤ برآمد;

	psig = sigb;
	اگر ((esig = d2i_ECDSA_SIG(تہی, &psig, slen)) == تہی) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		جاؤ برآمد;
	}
	ECDSA_SIG_get0(esig, &sig_r, &sig_s);

	اگر ((ret = ssh_ecdsa_encode_store_sig(کلید, sig_r, sig_s,
	    sigp, lenp)) != 0)
		جاؤ برآمد;
	/* success */
	ret = 0;
 برآمد:
	freezero(sigb, slen);
	ECDSA_SIG_free(esig);
	واپس ret;
}

صحیح
ssh_ecdsa_encode_store_sig(ثابت ساخت sshkey *کلید,
    ثابت BIGNUM *sig_r, ثابت BIGNUM *sig_s,
    u_char **sigp, سائز_t *lenp)
{
	ساخت sshbuf *b = تہی, *bb = تہی;
	صحیح ret;
	سائز_t len;

	اگر (lenp != تہی)
		*lenp = 0;
	اگر (sigp != تہی)
		*sigp = تہی;

	اگر ((bb = sshbuf_new()) == تہی || (b = sshbuf_new()) == تہی) {
		ret = SSH_ERR_ALLOC_FAIL;
		جاؤ برآمد;
	}
	اگر ((ret = sshbuf_put_bignum2(bb, sig_r)) != 0 ||
	    (ret = sshbuf_put_bignum2(bb, sig_s)) != 0)
		جاؤ برآمد;
	اگر ((ret = sshbuf_put_cstring(b, sshkey_ssh_name_plain(کلید))) != 0 ||
	    (ret = sshbuf_put_stringb(b, bb)) != 0)
		جاؤ برآمد;
	len = sshbuf_len(b);
	اگر (sigp != تہی) {
		اگر ((*sigp = حافظہ_دو(len)) == تہی) {
			ret = SSH_ERR_ALLOC_FAIL;
			جاؤ برآمد;
		}
		حافظہ_نقل(*sigp, sshbuf_ptr(b), len);
	}
	اگر (lenp != تہی)
		*lenp = len;
	ret = 0;
 برآمد:
	sshbuf_free(b);
	sshbuf_free(bb);
	واپس ret;
}

ساکن صحیح
ssh_ecdsa_verify(ثابت ساخت sshkey *کلید,
    ثابت u_char *sig, سائز_t siglen,
    ثابت u_char *ڈیٹا, سائز_t dlen, ثابت حرف *alg, u_int compat,
    ساخت sshkey_sig_details **detailsp)
{
	ECDSA_SIG *esig = تہی;
	BIGNUM *sig_r = تہی, *sig_s = تہی;
	صحیح hash_alg, len = 0;
	صحیح ret = SSH_ERR_اندرونی_ERROR;
	ساخت sshbuf *b = تہی, *sigbuf = تہی;
	حرف *ktype = تہی;
	غیرعلامتی حرف *sigb = تہی, *cp;

	اگر (کلید == تہی || کلید->pkey == تہی ||
	    sshkey_type_plain(کلید->type) != کلید_ECDSA ||
	    sig == تہی || siglen == 0)
		واپس SSH_ERR_INVALID_دلیل;

	اگر ((hash_alg = sshkey_ec_nid_مقصد_hash_alg(کلید->ecdsa_nid)) == -1)
		واپس SSH_ERR_اندرونی_ERROR;

	/* fetch signature */
	اگر ((b = sshbuf_from(sig, siglen)) == تہی)
		واپس SSH_ERR_ALLOC_FAIL;
	اگر (sshbuf_get_cstring(b, &ktype, تہی) != 0 ||
	    sshbuf_froms(b, &sigbuf) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		جاؤ برآمد;
	}
	اگر (strcmp(sshkey_ssh_name_plain(کلید), ktype) != 0) {
		ret = SSH_ERR_کلید_TYPE_MISMATCH;
		جاؤ برآمد;
	}
	اگر (sshbuf_len(b) != 0) {
		ret = SSH_ERR_UNEXPECTED_TRAILING_ڈیٹا;
		جاؤ برآمد;
	}

	/* parse signature */
	اگر (sshbuf_get_bignum2(sigbuf, &sig_r) != 0 ||
	    sshbuf_get_bignum2(sigbuf, &sig_s) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		جاؤ برآمد;
	}
	اگر (sshbuf_len(sigbuf) != 0) {
		ret = SSH_ERR_UNEXPECTED_TRAILING_ڈیٹا;
		جاؤ برآمد;
	}

	اگر ((esig = ECDSA_SIG_new()) == تہی) {
		ret = SSH_ERR_ALLOC_FAIL;
		جاؤ برآمد;
	}
	اگر (!ECDSA_SIG_set0(esig, sig_r, sig_s)) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		جاؤ برآمد;
	}
	sig_r = sig_s = تہی; /* transferred */

	اگر ((len = i2d_ECDSA_SIG(esig, تہی)) <= 0) {
		len = 0;
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		جاؤ برآمد;
	}
	اگر ((sigb = صفر_حافظہ_دو(1, len)) == تہی) {
		ret = SSH_ERR_ALLOC_FAIL;
		جاؤ برآمد;
	}
	cp = sigb; /* ASN1_item_i2d increments the pointer past the object */
	اگر (i2d_ECDSA_SIG(esig, &cp) != len) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		جاؤ برآمد;
	}
	اگر ((ret = sshkey_pkey_digest_verify(کلید->pkey, hash_alg,
	    ڈیٹا, dlen, sigb, len)) != 0)
		جاؤ برآمد;
	/* success */
 برآمد:
	freezero(sigb, len);
	sshbuf_free(sigbuf);
	sshbuf_free(b);
	ECDSA_SIG_free(esig);
	BN_clear_free(sig_r);
	BN_clear_free(sig_s);
	آزاد(ktype);
	واپس ret;
}

/* NB. not static; used by ECDSA-SK */
ثابت ساخت sshkey_impl_funcs sshkey_ecdsa_funcs = {
	/* .size = */		ssh_ecdsa_سائز,
	/* .alloc = */		تہی,
	/* .cleanup = */	ssh_ecdsa_cleanup,
	/* .equal = */		ssh_ecdsa_equal,
	/* .ssh_serialize_public = */ ssh_ecdsa_serialize_عوامی,
	/* .ssh_deserialize_public = */ ssh_ecdsa_deserialize_عوامی,
	/* .ssh_serialize_private = */ ssh_ecdsa_serialize_نجی,
	/* .ssh_deserialize_private = */ ssh_ecdsa_deserialize_نجی,
	/* .generate = */	ssh_ecdsa_generate,
	/* .copy_public = */	ssh_ecdsa_copy_عوامی,
	/* .sign = */		ssh_ecdsa_sign,
	/* .verify = */		ssh_ecdsa_verify,
};

ثابت ساخت sshkey_impl sshkey_ecdsa_nistp256_impl = {
	/* .name = */		"ecdsa-sha2-nistp256",
	/* .shortname = */	"ECDSA",
	/* .sigalg = */		تہی,
	/* .type = */		کلید_ECDSA,
	/* .nid = */		NID_X9_62_prime256v1,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_ecdsa_funcs,
};

ثابت ساخت sshkey_impl sshkey_ecdsa_nistp256_cert_impl = {
	/* .name = */		"ecdsa-sha2-nistp256-cert-v01@openssh.com",
	/* .shortname = */	"ECDSA-CERT",
	/* .sigalg = */		تہی,
	/* .type = */		کلید_ECDSA_CERT,
	/* .nid = */		NID_X9_62_prime256v1,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_ecdsa_funcs,
};

ثابت ساخت sshkey_impl sshkey_ecdsa_nistp384_impl = {
	/* .name = */		"ecdsa-sha2-nistp384",
	/* .shortname = */	"ECDSA",
	/* .sigalg = */		تہی,
	/* .type = */		کلید_ECDSA,
	/* .nid = */		NID_secp384r1,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_ecdsa_funcs,
};

ثابت ساخت sshkey_impl sshkey_ecdsa_nistp384_cert_impl = {
	/* .name = */		"ecdsa-sha2-nistp384-cert-v01@openssh.com",
	/* .shortname = */	"ECDSA-CERT",
	/* .sigalg = */		تہی,
	/* .type = */		کلید_ECDSA_CERT,
	/* .nid = */		NID_secp384r1,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_ecdsa_funcs,
};

ثابت ساخت sshkey_impl sshkey_ecdsa_nistp521_impl = {
	/* .name = */		"ecdsa-sha2-nistp521",
	/* .shortname = */	"ECDSA",
	/* .sigalg = */		تہی,
	/* .type = */		کلید_ECDSA,
	/* .nid = */		NID_secp521r1,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_ecdsa_funcs,
};

ثابت ساخت sshkey_impl sshkey_ecdsa_nistp521_cert_impl = {
	/* .name = */		"ecdsa-sha2-nistp521-cert-v01@openssh.com",
	/* .shortname = */	"ECDSA-CERT",
	/* .sigalg = */		تہی,
	/* .type = */		کلید_ECDSA_CERT,
	/* .nid = */		NID_secp521r1,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_ecdsa_funcs,
};

#اگر_ختم /* WITH_OPENSSL */
