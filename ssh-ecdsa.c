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
#وصف_ڪريو SSHKEY_اندروني
#ضمن "sshkey.h"

صحيح
sshkey_ecdsa_fixup_گروهه(EVP_PKEY *k)
{
	صحيح nids[] = {
		NID_X9_62_prime256v1,
		NID_secp384r1,
		NID_secp521r1,
		-1
	};
	صحيح nid = -1;
	u_int i;
	ثابت EC_گروهه *g;
	EC_ڪنجي *ec = عدم;
	EC_گروهه *eg = عدم;

	إذا ((ec = EVP_PKEY_get1_EC_ڪنجي(k)) == عدم ||
	    (g = EC_ڪنجي_get0_گروهه(ec)) == عدم)
		اذهب ٻاهريون;
	/*
	 * The group may be stored in a ASN.1 encoded private key in one of two
	 * ways: as a "named group", which is reconstituted by ASN.1 object ID
	 * or explicit group parameters encoded into the key blob. Only the
	 * "named group" case sets the group NID for us, but we can figure
	 * it out for the other case by comparing against all the groups that
	 * are supported.
	 */
	إذا ((nid = EC_گروهه_get_وڪر_name(g)) > 0)
		اذهب ٻاهريون;
	nid = -1;
	لكل (i = 0; nids[i] != -1; i++) {
		إذا ((eg = EC_گروهه_new_by_وڪر_name(nids[i])) == عدم)
			اذهب ٻاهريون;
		إذا (EC_گروهه_cmp(g, eg, عدم) == 0)
			اكسر;
		EC_گروهه_free(eg);
		eg = عدم;
	}
	إذا (nids[i] == -1)
		اذهب ٻاهريون;

	/* Use the group with the NID attached */
	EC_گروهه_سيٽ_asn1_flag(eg, OPENSSL_EC_NAMED_وڪر);
	إذا (EC_ڪنجي_سيٽ_گروهه(ec, eg) != 1 ||
	    EVP_PKEY_set1_EC_ڪنجي(k, ec) != 1)
		اذهب ٻاهريون;
	/* success */
	nid = nids[i];
 ٻاهريون:
	EC_ڪنجي_free(ec);
	EC_گروهه_free(eg);
	أرجع nid;
}

ساكن u_int
ssh_ecdsa_سائيز(ثابت بنية sshkey *ڪنجي)
{
	بدل (ڪنجي->ecdsa_nid) {
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
ssh_ecdsa_serialize_عوامي(ثابت بنية sshkey *ڪنجي, بنية sshbuf *b,
    تعداد sshkey_serialize_rep opts)
{
	صحيح r;

	إذا (ڪنجي->pkey == عدم)
		أرجع SSH_ERR_INVALID_دليل;
	إذا ((r = sshbuf_put_cstring(b,
	    sshkey_وڪر_nid_منزل_name(ڪنجي->ecdsa_nid))) != 0 ||
	    (r = sshbuf_put_ec_pkey(b, ڪنجي->pkey)) != 0)
		أرجع r;

	أرجع 0;
}

ساكن صحيح
ssh_ecdsa_serialize_ذاتي(ثابت بنية sshkey *ڪنجي, بنية sshbuf *b,
    تعداد sshkey_serialize_rep opts)
{
	صحيح r;

	إذا (!sshkey_is_cert(ڪنجي)) {
		إذا ((r = ssh_ecdsa_serialize_عوامي(ڪنجي, b, opts)) != 0)
			أرجع r;
	}
	إذا ((r = sshbuf_put_bignum2(b,
	    EC_ڪنجي_get0_ذاتي_ڪنجي(EVP_PKEY_get0_EC_ڪنجي(ڪنجي->pkey)))) != 0)
		أرجع r;
	أرجع 0;
}

ساكن صحيح
ssh_ecdsa_generate(بنية sshkey *k, صحيح بٽ)
{
	EVP_PKEY *res = عدم;
	EVP_PKEY_CTX *ctx = عدم;
	صحيح ret = SSH_ERR_اندروني_ERROR;

	إذا ((k->ecdsa_nid = sshkey_ecdsa_بٽ_منزل_nid(بٽ)) == -1)
		أرجع SSH_ERR_ڪنجي_ڊيگهائي;

	إذا ((ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, عدم)) == عدم)
		أرجع SSH_ERR_ALLOC_FAIL;

	إذا (EVP_PKEY_keygen_init(ctx) <= 0 ||
	    EVP_PKEY_CTX_سيٽ_ec_paramgen_وڪر_nid(ctx, k->ecdsa_nid) <= 0 ||
	    EVP_PKEY_keygen(ctx, &res) <= 0) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		اذهب ٻاهريون;
	}
	/* success */
	k->pkey = res;
	res = عدم;
	ret = 0;
 ٻاهريون:
	EVP_PKEY_free(res);
	EVP_PKEY_CTX_free(ctx);
	أرجع ret;
}

ساكن صحيح
ssh_ecdsa_copy_عوامي(ثابت بنية sshkey *from, بنية sshkey *منزل)
{
	ثابت EC_ڪنجي *ec_from;
	EC_ڪنجي *ec_منزل = عدم;
	صحيح ret = SSH_ERR_اندروني_ERROR;

	ec_from = EVP_PKEY_get0_EC_ڪنجي(from->pkey);
	إذا (ec_from == عدم)
		أرجع SSH_ERR_LIBCRYPTO_ERROR;

	منزل->ecdsa_nid = from->ecdsa_nid;
	إذا ((ec_منزل = EC_ڪنجي_new_by_وڪر_name(from->ecdsa_nid)) == عدم)
		أرجع SSH_ERR_ALLOC_FAIL;
	إذا (EC_ڪنجي_سيٽ_عوامي_ڪنجي(ec_منزل,
	    EC_ڪنجي_get0_عوامي_ڪنجي(ec_from)) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		اذهب ٻاهريون;
	}
	EVP_PKEY_free(منزل->pkey);
	إذا ((منزل->pkey = EVP_PKEY_new()) == عدم) {
		ret = SSH_ERR_ALLOC_FAIL;
		اذهب ٻاهريون;
	}
	إذا (EVP_PKEY_set1_EC_ڪنجي(منزل->pkey, ec_منزل) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		اذهب ٻاهريون;
	}
	ret = 0;
 ٻاهريون:
	EC_ڪنجي_free(ec_منزل);
	أرجع ret;
}

ساكن صحيح
ssh_ecdsa_deserialize_عوامي(ثابت حرف *ktype, بنية sshbuf *b,
    بنية sshkey *ڪنجي)
{
	صحيح r;
	حرف *وڪر = عدم;
	EVP_PKEY *pkey = عدم;
	EC_ڪنجي *ec = عدم;

	إذا ((ڪنجي->ecdsa_nid = sshkey_ecdsa_nid_from_name(ktype)) == -1)
		أرجع SSH_ERR_INVALID_دليل;
	إذا ((r = sshbuf_get_cstring(b, &وڪر, عدم)) != 0)
		اذهب ٻاهريون;
	إذا (ڪنجي->ecdsa_nid != sshkey_وڪر_name_منزل_nid(وڪر)) {
		r = SSH_ERR_EC_وڪر_MISMATCH;
		اذهب ٻاهريون;
	}
	إذا ((ec = EC_ڪنجي_new_by_وڪر_name(ڪنجي->ecdsa_nid)) == عدم) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		اذهب ٻاهريون;
	}
	إذا ((r = sshbuf_get_eckey(b, ec)) != 0)
		اذهب ٻاهريون;
	إذا (sshkey_ec_validate_عوامي(EC_ڪنجي_get0_گروهه(ec),
	    EC_ڪنجي_get0_عوامي_ڪنجي(ec)) != 0) {
		r = SSH_ERR_ڪنجي_INVALID_EC_قدر;
		اذهب ٻاهريون;
	}
	إذا ((pkey = EVP_PKEY_new()) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب ٻاهريون;
	}
	إذا (EVP_PKEY_set1_EC_ڪنجي(pkey, ec) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		اذهب ٻاهريون;
	}
	EVP_PKEY_free(ڪنجي->pkey);
	ڪنجي->pkey = pkey;
	pkey = عدم;
	/* success */
	r = 0;
#جيڪڏهن_وصف_ٿيل DEBUG_PK
	sshkey_dump_ec_نقطو(
	    EC_ڪنجي_get0_گروهه(EVP_PKEY_get0_EC_ڪنجي(ڪنجي->pkey)),
	    EC_ڪنجي_get0_عوامي_ڪنجي(EVP_PKEY_get0_EC_ڪنجي(ڪنجي->pkey)));
#جيڪڏهن_پورو
 ٻاهريون:
	EC_ڪنجي_free(ec);
	EVP_PKEY_free(pkey);
	حرر(وڪر);
	أرجع r;
}

ساكن صحيح
ssh_ecdsa_deserialize_ذاتي(ثابت حرف *ktype, بنية sshbuf *b,
    بنية sshkey *ڪنجي)
{
	صحيح r;
	BIGNUM *exponent = عدم;
	EC_ڪنجي *ec = عدم;

	إذا (!sshkey_is_cert(ڪنجي)) {
		إذا ((r = ssh_ecdsa_deserialize_عوامي(ktype, b, ڪنجي)) != 0)
			أرجع r;
	}
	إذا ((r = sshbuf_get_bignum2(b, &exponent)) != 0)
		اذهب ٻاهريون;
	إذا ((ec = EVP_PKEY_get1_EC_ڪنجي(ڪنجي->pkey)) == عدم) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		اذهب ٻاهريون;
	}
	إذا (EC_ڪنجي_سيٽ_ذاتي_ڪنجي(ec, exponent) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		اذهب ٻاهريون;
	}
	إذا ((r = sshkey_ec_validate_ذاتي(ec)) != 0)
		اذهب ٻاهريون;
	إذا (EVP_PKEY_set1_EC_ڪنجي(ڪنجي->pkey, ec) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		اذهب ٻاهريون;
	}
	/* success */
	r = 0;
 ٻاهريون:
	BN_clear_free(exponent);
	EC_ڪنجي_free(ec);
	أرجع r;
}

ساكن صحيح
ssh_ecdsa_sign(بنية sshkey *ڪنجي,
    u_char **sigp, سائيز_t *lenp,
    ثابت u_char *معلومات, سائيز_t dlen,
    ثابت حرف *alg, ثابت حرف *sk_provider, ثابت حرف *sk_pin, u_int compat)
{
	ECDSA_SIG *esig = عدم;
	بنانشان حرف *sigb = عدم;
	ثابت بنانشان حرف *psig;
	ثابت BIGNUM *sig_r, *sig_s;
	صحيح hash_alg;
	سائيز_t slen = 0;
	صحيح ret = SSH_ERR_اندروني_ERROR;

	إذا (lenp != عدم)
		*lenp = 0;
	إذا (sigp != عدم)
		*sigp = عدم;

	إذا (ڪنجي == عدم || ڪنجي->pkey == عدم ||
	    sshkey_type_plain(ڪنجي->type) != ڪنجي_ECDSA)
		أرجع SSH_ERR_INVALID_دليل;

	إذا ((hash_alg = sshkey_ec_nid_منزل_hash_alg(ڪنجي->ecdsa_nid)) == -1)
		أرجع SSH_ERR_اندروني_ERROR;

	إذا ((ret = sshkey_pkey_digest_sign(ڪنجي->pkey, hash_alg, &sigb, &slen,
	    معلومات, dlen)) != 0)
		اذهب ٻاهريون;

	psig = sigb;
	إذا ((esig = d2i_ECDSA_SIG(عدم, &psig, slen)) == عدم) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		اذهب ٻاهريون;
	}
	ECDSA_SIG_get0(esig, &sig_r, &sig_s);

	إذا ((ret = ssh_ecdsa_encode_store_sig(ڪنجي, sig_r, sig_s,
	    sigp, lenp)) != 0)
		اذهب ٻاهريون;
	/* success */
	ret = 0;
 ٻاهريون:
	freezero(sigb, slen);
	ECDSA_SIG_free(esig);
	أرجع ret;
}

صحيح
ssh_ecdsa_encode_store_sig(ثابت بنية sshkey *ڪنجي,
    ثابت BIGNUM *sig_r, ثابت BIGNUM *sig_s,
    u_char **sigp, سائيز_t *lenp)
{
	بنية sshbuf *b = عدم, *bb = عدم;
	صحيح ret;
	سائيز_t len;

	إذا (lenp != عدم)
		*lenp = 0;
	إذا (sigp != عدم)
		*sigp = عدم;

	إذا ((bb = sshbuf_new()) == عدم || (b = sshbuf_new()) == عدم) {
		ret = SSH_ERR_ALLOC_FAIL;
		اذهب ٻاهريون;
	}
	إذا ((ret = sshbuf_put_bignum2(bb, sig_r)) != 0 ||
	    (ret = sshbuf_put_bignum2(bb, sig_s)) != 0)
		اذهب ٻاهريون;
	إذا ((ret = sshbuf_put_cstring(b, sshkey_ssh_name_plain(ڪنجي))) != 0 ||
	    (ret = sshbuf_put_stringb(b, bb)) != 0)
		اذهب ٻاهريون;
	len = sshbuf_len(b);
	إذا (sigp != عدم) {
		إذا ((*sigp = يادگيري_ڏيو(len)) == عدم) {
			ret = SSH_ERR_ALLOC_FAIL;
			اذهب ٻاهريون;
		}
		يادگيري_نقل(*sigp, sshbuf_ptr(b), len);
	}
	إذا (lenp != عدم)
		*lenp = len;
	ret = 0;
 ٻاهريون:
	sshbuf_free(b);
	sshbuf_free(bb);
	أرجع ret;
}

ساكن صحيح
ssh_ecdsa_verify(ثابت بنية sshkey *ڪنجي,
    ثابت u_char *sig, سائيز_t siglen,
    ثابت u_char *معلومات, سائيز_t dlen, ثابت حرف *alg, u_int compat,
    بنية sshkey_sig_details **detailsp)
{
	ECDSA_SIG *esig = عدم;
	BIGNUM *sig_r = عدم, *sig_s = عدم;
	صحيح hash_alg, len = 0;
	صحيح ret = SSH_ERR_اندروني_ERROR;
	بنية sshbuf *b = عدم, *sigbuf = عدم;
	حرف *ktype = عدم;
	بنانشان حرف *sigb = عدم, *cp;

	إذا (ڪنجي == عدم || ڪنجي->pkey == عدم ||
	    sshkey_type_plain(ڪنجي->type) != ڪنجي_ECDSA ||
	    sig == عدم || siglen == 0)
		أرجع SSH_ERR_INVALID_دليل;

	إذا ((hash_alg = sshkey_ec_nid_منزل_hash_alg(ڪنجي->ecdsa_nid)) == -1)
		أرجع SSH_ERR_اندروني_ERROR;

	/* fetch signature */
	إذا ((b = sshbuf_from(sig, siglen)) == عدم)
		أرجع SSH_ERR_ALLOC_FAIL;
	إذا (sshbuf_get_cstring(b, &ktype, عدم) != 0 ||
	    sshbuf_froms(b, &sigbuf) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		اذهب ٻاهريون;
	}
	إذا (strcmp(sshkey_ssh_name_plain(ڪنجي), ktype) != 0) {
		ret = SSH_ERR_ڪنجي_TYPE_MISMATCH;
		اذهب ٻاهريون;
	}
	إذا (sshbuf_len(b) != 0) {
		ret = SSH_ERR_UNEXPECTED_TRAILING_معلومات;
		اذهب ٻاهريون;
	}

	/* parse signature */
	إذا (sshbuf_get_bignum2(sigbuf, &sig_r) != 0 ||
	    sshbuf_get_bignum2(sigbuf, &sig_s) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		اذهب ٻاهريون;
	}
	إذا (sshbuf_len(sigbuf) != 0) {
		ret = SSH_ERR_UNEXPECTED_TRAILING_معلومات;
		اذهب ٻاهريون;
	}

	إذا ((esig = ECDSA_SIG_new()) == عدم) {
		ret = SSH_ERR_ALLOC_FAIL;
		اذهب ٻاهريون;
	}
	إذا (!ECDSA_SIG_set0(esig, sig_r, sig_s)) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		اذهب ٻاهريون;
	}
	sig_r = sig_s = عدم; /* transferred */

	إذا ((len = i2d_ECDSA_SIG(esig, عدم)) <= 0) {
		len = 0;
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		اذهب ٻاهريون;
	}
	إذا ((sigb = صفر_يادگيري_ڏيو(1, len)) == عدم) {
		ret = SSH_ERR_ALLOC_FAIL;
		اذهب ٻاهريون;
	}
	cp = sigb; /* ASN1_item_i2d increments the pointer past the object */
	إذا (i2d_ECDSA_SIG(esig, &cp) != len) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		اذهب ٻاهريون;
	}
	إذا ((ret = sshkey_pkey_digest_verify(ڪنجي->pkey, hash_alg,
	    معلومات, dlen, sigb, len)) != 0)
		اذهب ٻاهريون;
	/* success */
 ٻاهريون:
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
	/* .size = */		ssh_ecdsa_سائيز,
	/* .alloc = */		عدم,
	/* .cleanup = */	ssh_ecdsa_cleanup,
	/* .equal = */		ssh_ecdsa_equal,
	/* .ssh_serialize_public = */ ssh_ecdsa_serialize_عوامي,
	/* .ssh_deserialize_public = */ ssh_ecdsa_deserialize_عوامي,
	/* .ssh_serialize_private = */ ssh_ecdsa_serialize_ذاتي,
	/* .ssh_deserialize_private = */ ssh_ecdsa_deserialize_ذاتي,
	/* .generate = */	ssh_ecdsa_generate,
	/* .copy_public = */	ssh_ecdsa_copy_عوامي,
	/* .sign = */		ssh_ecdsa_sign,
	/* .verify = */		ssh_ecdsa_verify,
};

ثابت بنية sshkey_impl sshkey_ecdsa_nistp256_impl = {
	/* .name = */		"ecdsa-sha2-nistp256",
	/* .shortname = */	"ECDSA",
	/* .sigalg = */		عدم,
	/* .type = */		ڪنجي_ECDSA,
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
	/* .type = */		ڪنجي_ECDSA_CERT,
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
	/* .type = */		ڪنجي_ECDSA,
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
	/* .type = */		ڪنجي_ECDSA_CERT,
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
	/* .type = */		ڪنجي_ECDSA,
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
	/* .type = */		ڪنجي_ECDSA_CERT,
	/* .nid = */		NID_secp521r1,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_ecdsa_funcs,
};

#جيڪڏهن_پورو /* WITH_OPENSSL */
