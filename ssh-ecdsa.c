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

#ضمن "includes.h"

#إذا defined(WITH_OPENSSL)
#ضمن "openbsd-compat/openssl-compat.h"

#ضمن <sys/types.h>

#ضمن <openssl/bn.h>
#ضمن <openssl/ec.h>
#ضمن <openssl/ecdsa.h>
#ضمن <openssl/evp.h>

#ضمن <string.h>

#ضمن "sshbuf.h"
#ضمن "ssherr.h"
#تعریف_کړه SSHKEY_دننی
#ضمن "sshkey.h"

صحيح
sshkey_ecdsa_fixup_ډله(EVP_PKEY *k)
{
	صحيح nids[] = {
		NID_X9_62_prime256v1,
		NID_secp384r1,
		NID_secp521r1,
		-1
	};
	صحيح nid = -1;
	u_int i;
	ثابت EC_ډله *g;
	EC_کلی *ec = عدم;
	EC_ډله *eg = عدم;

	إذا ((ec = EVP_PKEY_get1_EC_کلی(k)) == عدم ||
	    (g = EC_کلی_get0_ډله(ec)) == عدم)
		اذهب بهر;
	/*
	 * The group may be stored in a ASN.1 encoded private key in one of two
	 * ways: as a "named group", which is reconstituted by ASN.1 object ID
	 * or explicit group parameters encoded into the key blob. Only the
	 * "named group" case sets the group NID for us, but we can figure
	 * it out for the other case by comparing against all the groups that
	 * are supported.
	 */
	إذا ((nid = EC_ډله_get_منحني_name(g)) > 0)
		اذهب بهر;
	nid = -1;
	لكل (i = 0; nids[i] != -1; i++) {
		إذا ((eg = EC_ډله_new_by_منحني_name(nids[i])) == عدم)
			اذهب بهر;
		إذا (EC_ډله_cmp(g, eg, عدم) == 0)
			اكسر;
		EC_ډله_free(eg);
		eg = عدم;
	}
	إذا (nids[i] == -1)
		اذهب بهر;

	/* Use the group with the NID attached */
	EC_ډله_سېټ_asn1_flag(eg, OPENSSL_EC_NAMED_منحني);
	إذا (EC_کلی_سېټ_ډله(ec, eg) != 1 ||
	    EVP_PKEY_set1_EC_کلی(k, ec) != 1)
		اذهب بهر;
	/* success */
	nid = nids[i];
 بهر:
	EC_کلی_free(ec);
	EC_ډله_free(eg);
	أرجع nid;
}

ساكن u_int
ssh_ecdsa_اندازه(ثابت بنية sshkey *کلی)
{
	بدل (کلی->ecdsa_nid) {
	حالة NID_X9_62_prime256v1:
		أرجع 256;
	حالة NID_secp384r1:
		أرجع 384;
	حالة NID_secp521r1:
		أرجع 521;
	افتراضي:
		أرجع 0;
	}
}

ساكن فراغ
ssh_ecdsa_cleanup(بنية sshkey *k)
{
	EVP_PKEY_free(k->pkey);
	k->pkey = عدم;
}

ساكن صحيح
ssh_ecdsa_equal(ثابت بنية sshkey *a, ثابت بنية sshkey *b)
{
	إذا (a->pkey == عدم || b->pkey == عدم)
		أرجع 0;
	أرجع EVP_PKEY_cmp(a->pkey, b->pkey) == 1;
}

ساكن صحيح
ssh_ecdsa_serialize_عامه(ثابت بنية sshkey *کلی, بنية sshbuf *b,
    تعداد sshkey_serialize_rep opts)
{
	صحيح r;

	إذا (کلی->pkey == عدم)
		أرجع SSH_ERR_INVALID_دلیل;
	إذا ((r = sshbuf_put_cstring(b,
	    sshkey_منحني_nid_منزل_name(کلی->ecdsa_nid))) != 0 ||
	    (r = sshbuf_put_ec_pkey(b, کلی->pkey)) != 0)
		أرجع r;

	أرجع 0;
}

ساكن صحيح
ssh_ecdsa_serialize_شخصي(ثابت بنية sshkey *کلی, بنية sshbuf *b,
    تعداد sshkey_serialize_rep opts)
{
	صحيح r;

	إذا (!sshkey_is_cert(کلی)) {
		إذا ((r = ssh_ecdsa_serialize_عامه(کلی, b, opts)) != 0)
			أرجع r;
	}
	إذا ((r = sshbuf_put_bignum2(b,
	    EC_کلی_get0_شخصي_کلی(EVP_PKEY_get0_EC_کلی(کلی->pkey)))) != 0)
		أرجع r;
	أرجع 0;
}

ساكن صحيح
ssh_ecdsa_generate(بنية sshkey *k, صحيح بټونه)
{
	EVP_PKEY *res = عدم;
	EVP_PKEY_CTX *ctx = عدم;
	صحيح ret = SSH_ERR_دننی_ERROR;

	إذا ((k->ecdsa_nid = sshkey_ecdsa_بټونه_منزل_nid(بټونه)) == -1)
		أرجع SSH_ERR_کلی_اوږدتیا;

	إذا ((ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, عدم)) == عدم)
		أرجع SSH_ERR_ALLOC_FAIL;

	إذا (EVP_PKEY_keygen_init(ctx) <= 0 ||
	    EVP_PKEY_CTX_سېټ_ec_paramgen_منحني_nid(ctx, k->ecdsa_nid) <= 0 ||
	    EVP_PKEY_keygen(ctx, &res) <= 0) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		اذهب بهر;
	}
	/* success */
	k->pkey = res;
	res = عدم;
	ret = 0;
 بهر:
	EVP_PKEY_free(res);
	EVP_PKEY_CTX_free(ctx);
	أرجع ret;
}

ساكن صحيح
ssh_ecdsa_copy_عامه(ثابت بنية sshkey *from, بنية sshkey *منزل)
{
	ثابت EC_کلی *ec_from;
	EC_کلی *ec_منزل = عدم;
	صحيح ret = SSH_ERR_دننی_ERROR;

	ec_from = EVP_PKEY_get0_EC_کلی(from->pkey);
	إذا (ec_from == عدم)
		أرجع SSH_ERR_LIBCRYPTO_ERROR;

	منزل->ecdsa_nid = from->ecdsa_nid;
	إذا ((ec_منزل = EC_کلی_new_by_منحني_name(from->ecdsa_nid)) == عدم)
		أرجع SSH_ERR_ALLOC_FAIL;
	إذا (EC_کلی_سېټ_عامه_کلی(ec_منزل,
	    EC_کلی_get0_عامه_کلی(ec_from)) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		اذهب بهر;
	}
	EVP_PKEY_free(منزل->pkey);
	إذا ((منزل->pkey = EVP_PKEY_new()) == عدم) {
		ret = SSH_ERR_ALLOC_FAIL;
		اذهب بهر;
	}
	إذا (EVP_PKEY_set1_EC_کلی(منزل->pkey, ec_منزل) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		اذهب بهر;
	}
	ret = 0;
 بهر:
	EC_کلی_free(ec_منزل);
	أرجع ret;
}

ساكن صحيح
ssh_ecdsa_deserialize_عامه(ثابت حرف *ktype, بنية sshbuf *b,
    بنية sshkey *کلی)
{
	صحيح r;
	حرف *منحني = عدم;
	EVP_PKEY *pkey = عدم;
	EC_کلی *ec = عدم;

	إذا ((کلی->ecdsa_nid = sshkey_ecdsa_nid_from_name(ktype)) == -1)
		أرجع SSH_ERR_INVALID_دلیل;
	إذا ((r = sshbuf_get_cstring(b, &منحني, عدم)) != 0)
		اذهب بهر;
	إذا (کلی->ecdsa_nid != sshkey_منحني_name_منزل_nid(منحني)) {
		r = SSH_ERR_EC_منحني_MISMATCH;
		اذهب بهر;
	}
	إذا ((ec = EC_کلی_new_by_منحني_name(کلی->ecdsa_nid)) == عدم) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		اذهب بهر;
	}
	إذا ((r = sshbuf_get_eckey(b, ec)) != 0)
		اذهب بهر;
	إذا (sshkey_ec_validate_عامه(EC_کلی_get0_ډله(ec),
	    EC_کلی_get0_عامه_کلی(ec)) != 0) {
		r = SSH_ERR_کلی_INVALID_EC_ارزښت;
		اذهب بهر;
	}
	إذا ((pkey = EVP_PKEY_new()) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب بهر;
	}
	إذا (EVP_PKEY_set1_EC_کلی(pkey, ec) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		اذهب بهر;
	}
	EVP_PKEY_free(کلی->pkey);
	کلی->pkey = pkey;
	pkey = عدم;
	/* success */
	r = 0;
#که_تعریف_شوی DEBUG_PK
	sshkey_dump_ec_ټکی(
	    EC_کلی_get0_ډله(EVP_PKEY_get0_EC_کلی(کلی->pkey)),
	    EC_کلی_get0_عامه_کلی(EVP_PKEY_get0_EC_کلی(کلی->pkey)));
#د_که_پای
 بهر:
	EC_کلی_free(ec);
	EVP_PKEY_free(pkey);
	حرر(منحني);
	أرجع r;
}

ساكن صحيح
ssh_ecdsa_deserialize_شخصي(ثابت حرف *ktype, بنية sshbuf *b,
    بنية sshkey *کلی)
{
	صحيح r;
	BIGNUM *exponent = عدم;
	EC_کلی *ec = عدم;

	إذا (!sshkey_is_cert(کلی)) {
		إذا ((r = ssh_ecdsa_deserialize_عامه(ktype, b, کلی)) != 0)
			أرجع r;
	}
	إذا ((r = sshbuf_get_bignum2(b, &exponent)) != 0)
		اذهب بهر;
	إذا ((ec = EVP_PKEY_get1_EC_کلی(کلی->pkey)) == عدم) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		اذهب بهر;
	}
	إذا (EC_کلی_سېټ_شخصي_کلی(ec, exponent) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		اذهب بهر;
	}
	إذا ((r = sshkey_ec_validate_شخصي(ec)) != 0)
		اذهب بهر;
	إذا (EVP_PKEY_set1_EC_کلی(کلی->pkey, ec) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		اذهب بهر;
	}
	/* success */
	r = 0;
 بهر:
	BN_clear_free(exponent);
	EC_کلی_free(ec);
	أرجع r;
}

ساكن صحيح
ssh_ecdsa_sign(بنية sshkey *کلی,
    u_char **sigp, اندازه_t *lenp,
    ثابت u_char *معلومات, اندازه_t dlen,
    ثابت حرف *alg, ثابت حرف *sk_provider, ثابت حرف *sk_pin, u_int compat)
{
	ECDSA_SIG *esig = عدم;
	بینښه حرف *sigb = عدم;
	ثابت بینښه حرف *psig;
	ثابت BIGNUM *sig_r, *sig_s;
	صحيح hash_alg;
	اندازه_t slen = 0;
	صحيح ret = SSH_ERR_دننی_ERROR;

	إذا (lenp != عدم)
		*lenp = 0;
	إذا (sigp != عدم)
		*sigp = عدم;

	إذا (کلی == عدم || کلی->pkey == عدم ||
	    sshkey_type_plain(کلی->type) != کلی_ECDSA)
		أرجع SSH_ERR_INVALID_دلیل;

	إذا ((hash_alg = sshkey_ec_nid_منزل_hash_alg(کلی->ecdsa_nid)) == -1)
		أرجع SSH_ERR_دننی_ERROR;

	إذا ((ret = sshkey_pkey_digest_sign(کلی->pkey, hash_alg, &sigb, &slen,
	    معلومات, dlen)) != 0)
		اذهب بهر;

	psig = sigb;
	إذا ((esig = d2i_ECDSA_SIG(عدم, &psig, slen)) == عدم) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		اذهب بهر;
	}
	ECDSA_SIG_get0(esig, &sig_r, &sig_s);

	إذا ((ret = ssh_ecdsa_encode_store_sig(کلی, sig_r, sig_s,
	    sigp, lenp)) != 0)
		اذهب بهر;
	/* success */
	ret = 0;
 بهر:
	freezero(sigb, slen);
	ECDSA_SIG_free(esig);
	أرجع ret;
}

صحيح
ssh_ecdsa_encode_store_sig(ثابت بنية sshkey *کلی,
    ثابت BIGNUM *sig_r, ثابت BIGNUM *sig_s,
    u_char **sigp, اندازه_t *lenp)
{
	بنية sshbuf *b = عدم, *bb = عدم;
	صحيح ret;
	اندازه_t len;

	إذا (lenp != عدم)
		*lenp = 0;
	إذا (sigp != عدم)
		*sigp = عدم;

	إذا ((bb = sshbuf_new()) == عدم || (b = sshbuf_new()) == عدم) {
		ret = SSH_ERR_ALLOC_FAIL;
		اذهب بهر;
	}
	إذا ((ret = sshbuf_put_bignum2(bb, sig_r)) != 0 ||
	    (ret = sshbuf_put_bignum2(bb, sig_s)) != 0)
		اذهب بهر;
	إذا ((ret = sshbuf_put_cstring(b, sshkey_ssh_name_plain(کلی))) != 0 ||
	    (ret = sshbuf_put_stringb(b, bb)) != 0)
		اذهب بهر;
	len = sshbuf_len(b);
	إذا (sigp != عدم) {
		إذا ((*sigp = حافظه_ورکړه(len)) == عدم) {
			ret = SSH_ERR_ALLOC_FAIL;
			اذهب بهر;
		}
		حافظه_نقل(*sigp, sshbuf_ptr(b), len);
	}
	إذا (lenp != عدم)
		*lenp = len;
	ret = 0;
 بهر:
	sshbuf_free(b);
	sshbuf_free(bb);
	أرجع ret;
}

ساكن صحيح
ssh_ecdsa_verify(ثابت بنية sshkey *کلی,
    ثابت u_char *sig, اندازه_t siglen,
    ثابت u_char *معلومات, اندازه_t dlen, ثابت حرف *alg, u_int compat,
    بنية sshkey_sig_details **detailsp)
{
	ECDSA_SIG *esig = عدم;
	BIGNUM *sig_r = عدم, *sig_s = عدم;
	صحيح hash_alg, len = 0;
	صحيح ret = SSH_ERR_دننی_ERROR;
	بنية sshbuf *b = عدم, *sigbuf = عدم;
	حرف *ktype = عدم;
	بینښه حرف *sigb = عدم, *cp;

	إذا (کلی == عدم || کلی->pkey == عدم ||
	    sshkey_type_plain(کلی->type) != کلی_ECDSA ||
	    sig == عدم || siglen == 0)
		أرجع SSH_ERR_INVALID_دلیل;

	إذا ((hash_alg = sshkey_ec_nid_منزل_hash_alg(کلی->ecdsa_nid)) == -1)
		أرجع SSH_ERR_دننی_ERROR;

	/* fetch signature */
	إذا ((b = sshbuf_from(sig, siglen)) == عدم)
		أرجع SSH_ERR_ALLOC_FAIL;
	إذا (sshbuf_get_cstring(b, &ktype, عدم) != 0 ||
	    sshbuf_froms(b, &sigbuf) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		اذهب بهر;
	}
	إذا (strcmp(sshkey_ssh_name_plain(کلی), ktype) != 0) {
		ret = SSH_ERR_کلی_TYPE_MISMATCH;
		اذهب بهر;
	}
	إذا (sshbuf_len(b) != 0) {
		ret = SSH_ERR_UNEXPECTED_TRAILING_معلومات;
		اذهب بهر;
	}

	/* parse signature */
	إذا (sshbuf_get_bignum2(sigbuf, &sig_r) != 0 ||
	    sshbuf_get_bignum2(sigbuf, &sig_s) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		اذهب بهر;
	}
	إذا (sshbuf_len(sigbuf) != 0) {
		ret = SSH_ERR_UNEXPECTED_TRAILING_معلومات;
		اذهب بهر;
	}

	إذا ((esig = ECDSA_SIG_new()) == عدم) {
		ret = SSH_ERR_ALLOC_FAIL;
		اذهب بهر;
	}
	إذا (!ECDSA_SIG_set0(esig, sig_r, sig_s)) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		اذهب بهر;
	}
	sig_r = sig_s = عدم; /* transferred */

	إذا ((len = i2d_ECDSA_SIG(esig, عدم)) <= 0) {
		len = 0;
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		اذهب بهر;
	}
	إذا ((sigb = حافظه_صفر_ورکړه(1, len)) == عدم) {
		ret = SSH_ERR_ALLOC_FAIL;
		اذهب بهر;
	}
	cp = sigb; /* ASN1_item_i2d increments the pointer past the object */
	إذا (i2d_ECDSA_SIG(esig, &cp) != len) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		اذهب بهر;
	}
	إذا ((ret = sshkey_pkey_digest_verify(کلی->pkey, hash_alg,
	    معلومات, dlen, sigb, len)) != 0)
		اذهب بهر;
	/* success */
 بهر:
	freezero(sigb, len);
	sshbuf_free(sigbuf);
	sshbuf_free(b);
	ECDSA_SIG_free(esig);
	BN_clear_free(sig_r);
	BN_clear_free(sig_s);
	حرر(ktype);
	أرجع ret;
}

/* NB. not static; used by ECDSA-SK */
ثابت بنية sshkey_impl_funcs sshkey_ecdsa_funcs = {
	/* .size = */		ssh_ecdsa_اندازه,
	/* .alloc = */		عدم,
	/* .cleanup = */	ssh_ecdsa_cleanup,
	/* .equal = */		ssh_ecdsa_equal,
	/* .ssh_serialize_public = */ ssh_ecdsa_serialize_عامه,
	/* .ssh_deserialize_public = */ ssh_ecdsa_deserialize_عامه,
	/* .ssh_serialize_private = */ ssh_ecdsa_serialize_شخصي,
	/* .ssh_deserialize_private = */ ssh_ecdsa_deserialize_شخصي,
	/* .generate = */	ssh_ecdsa_generate,
	/* .copy_public = */	ssh_ecdsa_copy_عامه,
	/* .sign = */		ssh_ecdsa_sign,
	/* .verify = */		ssh_ecdsa_verify,
};

ثابت بنية sshkey_impl sshkey_ecdsa_nistp256_impl = {
	/* .name = */		"ecdsa-sha2-nistp256",
	/* .shortname = */	"ECDSA",
	/* .sigalg = */		عدم,
	/* .type = */		کلی_ECDSA,
	/* .nid = */		NID_X9_62_prime256v1,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_ecdsa_funcs,
};

ثابت بنية sshkey_impl sshkey_ecdsa_nistp256_cert_impl = {
	/* .name = */		"ecdsa-sha2-nistp256-cert-v01@openssh.com",
	/* .shortname = */	"ECDSA-CERT",
	/* .sigalg = */		عدم,
	/* .type = */		کلی_ECDSA_CERT,
	/* .nid = */		NID_X9_62_prime256v1,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_ecdsa_funcs,
};

ثابت بنية sshkey_impl sshkey_ecdsa_nistp384_impl = {
	/* .name = */		"ecdsa-sha2-nistp384",
	/* .shortname = */	"ECDSA",
	/* .sigalg = */		عدم,
	/* .type = */		کلی_ECDSA,
	/* .nid = */		NID_secp384r1,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_ecdsa_funcs,
};

ثابت بنية sshkey_impl sshkey_ecdsa_nistp384_cert_impl = {
	/* .name = */		"ecdsa-sha2-nistp384-cert-v01@openssh.com",
	/* .shortname = */	"ECDSA-CERT",
	/* .sigalg = */		عدم,
	/* .type = */		کلی_ECDSA_CERT,
	/* .nid = */		NID_secp384r1,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_ecdsa_funcs,
};

ثابت بنية sshkey_impl sshkey_ecdsa_nistp521_impl = {
	/* .name = */		"ecdsa-sha2-nistp521",
	/* .shortname = */	"ECDSA",
	/* .sigalg = */		عدم,
	/* .type = */		کلی_ECDSA,
	/* .nid = */		NID_secp521r1,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_ecdsa_funcs,
};

ثابت بنية sshkey_impl sshkey_ecdsa_nistp521_cert_impl = {
	/* .name = */		"ecdsa-sha2-nistp521-cert-v01@openssh.com",
	/* .shortname = */	"ECDSA-CERT",
	/* .sigalg = */		عدم,
	/* .type = */		کلی_ECDSA_CERT,
	/* .nid = */		NID_secp521r1,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_ecdsa_funcs,
};

#د_که_پای /* WITH_OPENSSL */
