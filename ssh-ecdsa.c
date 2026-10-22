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

#అన్తర్భావ "includes.h"

#ఒకవేళ defined(WITH_OPENSSL)
#అన్తర్భావ "openbsd-compat/openssl-compat.h"

#అన్తర్భావ <sys/types.h>

#అన్తర్భావ <openssl/bn.h>
#అన్తర్భావ <openssl/ec.h>
#అన్తర్భావ <openssl/ecdsa.h>
#అన్తర్భావ <openssl/evp.h>

#అన్తర్భావ <string.h>

#అన్తర్భావ "sshbuf.h"
#అన్తర్భావ "ssherr.h"
#నిర్వచించు SSHKEY_అంతర్గత
#అన్తర్భావ "sshkey.h"

పూర్ణాంకం
sshkey_ecdsa_fixup_సమూహం(EVP_PKEY *k)
{
	పూర్ణాంకం nids[] = {
		NID_X9_62_prime256v1,
		NID_secp384r1,
		NID_secp521r1,
		-1
	};
	పూర్ణాంకం nid = -1;
	u_int i;
	స్థిరరాశి EC_సమూహం *g;
	EC_కీలకం *ec = ఖాళీ;
	EC_సమూహం *eg = ఖాళీ;

	ఒకవేళ ((ec = EVP_PKEY_get1_EC_కీలకం(k)) == ఖాళీ ||
	    (g = EC_కీలకం_get0_సమూహం(ec)) == ఖాళీ)
		వెళ్ళు బహిర్గతం;
	/*
	 * The group may be stored in a ASN.1 encoded private key in one of two
	 * ways: as a "named group", which is reconstituted by ASN.1 object ID
	 * or explicit group parameters encoded into the key blob. Only the
	 * "named group" case sets the group NID for us, but we can figure
	 * it out for the other case by comparing against all the groups that
	 * are supported.
	 */
	ఒకవేళ ((nid = EC_సమూహం_get_వక్రం_name(g)) > 0)
		వెళ్ళు బహిర్గతం;
	nid = -1;
	కొరకు (i = 0; nids[i] != -1; i++) {
		ఒకవేళ ((eg = EC_సమూహం_new_by_వక్రం_name(nids[i])) == ఖాళీ)
			వెళ్ళు బహిర్గతం;
		ఒకవేళ (EC_సమూహం_cmp(g, eg, ఖాళీ) == 0)
			ఆపు;
		EC_సమూహం_free(eg);
		eg = ఖాళీ;
	}
	ఒకవేళ (nids[i] == -1)
		వెళ్ళు బహిర్గతం;

	/* Use the group with the NID attached */
	EC_సమూహం_సమితి_asn1_flag(eg, OPENSSL_EC_NAMED_వక్రం);
	ఒకవేళ (EC_కీలకం_సమితి_సమూహం(ec, eg) != 1 ||
	    EVP_PKEY_set1_EC_కీలకం(k, ec) != 1)
		వెళ్ళు బహిర్గతం;
	/* success */
	nid = nids[i];
 బహిర్గతం:
	EC_కీలకం_free(ec);
	EC_సమూహం_free(eg);
	తిరిగి nid;
}

స్థిర u_int
ssh_ecdsa_కొలత(స్థిరరాశి నిర్మాణం sshkey *కీలకం)
{
	ఎంపిక (కీలకం->ecdsa_nid) {
	స్థితి NID_X9_62_prime256v1:
		తిరిగి 256;
	స్థితి NID_secp384r1:
		తిరిగి 384;
	స్థితి NID_secp521r1:
		తిరిగి 521;
	అప్రమేయ:
		తిరిగి 0;
	}
}

స్థిర శూన్య
ssh_ecdsa_cleanup(నిర్మాణం sshkey *k)
{
	EVP_PKEY_free(k->pkey);
	k->pkey = ఖాళీ;
}

స్థిర పూర్ణాంకం
ssh_ecdsa_equal(స్థిరరాశి నిర్మాణం sshkey *a, స్థిరరాశి నిర్మాణం sshkey *b)
{
	ఒకవేళ (a->pkey == ఖాళీ || b->pkey == ఖాళీ)
		తిరిగి 0;
	తిరిగి EVP_PKEY_cmp(a->pkey, b->pkey) == 1;
}

స్థిర పూర్ణాంకం
ssh_ecdsa_serialize_ప్రజా(స్థిరరాశి నిర్మాణం sshkey *కీలకం, నిర్మాణం sshbuf *b,
    గణన sshkey_serialize_rep opts)
{
	పూర్ణాంకం r;

	ఒకవేళ (కీలకం->pkey == ఖాళీ)
		తిరిగి SSH_ERR_INVALID_వాదం;
	ఒకవేళ ((r = sshbuf_put_cstring(b,
	    sshkey_వక్రం_nid_గమ్యం_name(కీలకం->ecdsa_nid))) != 0 ||
	    (r = sshbuf_put_ec_pkey(b, కీలకం->pkey)) != 0)
		తిరిగి r;

	తిరిగి 0;
}

స్థిర పూర్ణాంకం
ssh_ecdsa_serialize_వ్యక్తిగత(స్థిరరాశి నిర్మాణం sshkey *కీలకం, నిర్మాణం sshbuf *b,
    గణన sshkey_serialize_rep opts)
{
	పూర్ణాంకం r;

	ఒకవేళ (!sshkey_is_cert(కీలకం)) {
		ఒకవేళ ((r = ssh_ecdsa_serialize_ప్రజా(కీలకం, b, opts)) != 0)
			తిరిగి r;
	}
	ఒకవేళ ((r = sshbuf_put_bignum2(b,
	    EC_కీలకం_get0_వ్యక్తిగత_కీలకం(EVP_PKEY_get0_EC_కీలకం(కీలకం->pkey)))) != 0)
		తిరిగి r;
	తిరిగి 0;
}

స్థిర పూర్ణాంకం
ssh_ecdsa_generate(నిర్మాణం sshkey *k, పూర్ణాంకం బిట్లు)
{
	EVP_PKEY *res = ఖాళీ;
	EVP_PKEY_CTX *ctx = ఖాళీ;
	పూర్ణాంకం ret = SSH_ERR_అంతర్గత_ERROR;

	ఒకవేళ ((k->ecdsa_nid = sshkey_ecdsa_బిట్లు_గమ్యం_nid(బిట్లు)) == -1)
		తిరిగి SSH_ERR_కీలకం_నిడివి;

	ఒకవేళ ((ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, ఖాళీ)) == ఖాళీ)
		తిరిగి SSH_ERR_ALLOC_FAIL;

	ఒకవేళ (EVP_PKEY_keygen_init(ctx) <= 0 ||
	    EVP_PKEY_CTX_సమితి_ec_paramgen_వక్రం_nid(ctx, k->ecdsa_nid) <= 0 ||
	    EVP_PKEY_keygen(ctx, &res) <= 0) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		వెళ్ళు బహిర్గతం;
	}
	/* success */
	k->pkey = res;
	res = ఖాళీ;
	ret = 0;
 బహిర్గతం:
	EVP_PKEY_free(res);
	EVP_PKEY_CTX_free(ctx);
	తిరిగి ret;
}

స్థిర పూర్ణాంకం
ssh_ecdsa_copy_ప్రజా(స్థిరరాశి నిర్మాణం sshkey *from, నిర్మాణం sshkey *గమ్యం)
{
	స్థిరరాశి EC_కీలకం *ec_from;
	EC_కీలకం *ec_గమ్యం = ఖాళీ;
	పూర్ణాంకం ret = SSH_ERR_అంతర్గత_ERROR;

	ec_from = EVP_PKEY_get0_EC_కీలకం(from->pkey);
	ఒకవేళ (ec_from == ఖాళీ)
		తిరిగి SSH_ERR_LIBCRYPTO_ERROR;

	గమ్యం->ecdsa_nid = from->ecdsa_nid;
	ఒకవేళ ((ec_గమ్యం = EC_కీలకం_new_by_వక్రం_name(from->ecdsa_nid)) == ఖాళీ)
		తిరిగి SSH_ERR_ALLOC_FAIL;
	ఒకవేళ (EC_కీలకం_సమితి_ప్రజా_కీలకం(ec_గమ్యం,
	    EC_కీలకం_get0_ప్రజా_కీలకం(ec_from)) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		వెళ్ళు బహిర్గతం;
	}
	EVP_PKEY_free(గమ్యం->pkey);
	ఒకవేళ ((గమ్యం->pkey = EVP_PKEY_new()) == ఖాళీ) {
		ret = SSH_ERR_ALLOC_FAIL;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ (EVP_PKEY_set1_EC_కీలకం(గమ్యం->pkey, ec_గమ్యం) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		వెళ్ళు బహిర్గతం;
	}
	ret = 0;
 బహిర్గతం:
	EC_కీలకం_free(ec_గమ్యం);
	తిరిగి ret;
}

స్థిర పూర్ణాంకం
ssh_ecdsa_deserialize_ప్రజా(స్థిరరాశి అక్షరం *ktype, నిర్మాణం sshbuf *b,
    నిర్మాణం sshkey *కీలకం)
{
	పూర్ణాంకం r;
	అక్షరం *వక్రం = ఖాళీ;
	EVP_PKEY *pkey = ఖాళీ;
	EC_కీలకం *ec = ఖాళీ;

	ఒకవేళ ((కీలకం->ecdsa_nid = sshkey_ecdsa_nid_from_name(ktype)) == -1)
		తిరిగి SSH_ERR_INVALID_వాదం;
	ఒకవేళ ((r = sshbuf_get_cstring(b, &వక్రం, ఖాళీ)) != 0)
		వెళ్ళు బహిర్గతం;
	ఒకవేళ (కీలకం->ecdsa_nid != sshkey_వక్రం_name_గమ్యం_nid(వక్రం)) {
		r = SSH_ERR_EC_వక్రం_MISMATCH;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((ec = EC_కీలకం_new_by_వక్రం_name(కీలకం->ecdsa_nid)) == ఖాళీ) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((r = sshbuf_get_eckey(b, ec)) != 0)
		వెళ్ళు బహిర్గతం;
	ఒకవేళ (sshkey_ec_validate_ప్రజా(EC_కీలకం_get0_సమూహం(ec),
	    EC_కీలకం_get0_ప్రజా_కీలకం(ec)) != 0) {
		r = SSH_ERR_కీలకం_INVALID_EC_విలువ;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((pkey = EVP_PKEY_new()) == ఖాళీ) {
		r = SSH_ERR_ALLOC_FAIL;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ (EVP_PKEY_set1_EC_కీలకం(pkey, ec) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		వెళ్ళు బహిర్గతం;
	}
	EVP_PKEY_free(కీలకం->pkey);
	కీలకం->pkey = pkey;
	pkey = ఖాళీ;
	/* success */
	r = 0;
#నిర్వచితమైతే DEBUG_PK
	sshkey_dump_ec_బిందువు(
	    EC_కీలకం_get0_సమూహం(EVP_PKEY_get0_EC_కీలకం(కీలకం->pkey)),
	    EC_కీలకం_get0_ప్రజా_కీలకం(EVP_PKEY_get0_EC_కీలకం(కీలకం->pkey)));
#అయితే_ముగింపు
 బహిర్గతం:
	EC_కీలకం_free(ec);
	EVP_PKEY_free(pkey);
	విడుదల(వక్రం);
	తిరిగి r;
}

స్థిర పూర్ణాంకం
ssh_ecdsa_deserialize_వ్యక్తిగత(స్థిరరాశి అక్షరం *ktype, నిర్మాణం sshbuf *b,
    నిర్మాణం sshkey *కీలకం)
{
	పూర్ణాంకం r;
	BIGNUM *exponent = ఖాళీ;
	EC_కీలకం *ec = ఖాళీ;

	ఒకవేళ (!sshkey_is_cert(కీలకం)) {
		ఒకవేళ ((r = ssh_ecdsa_deserialize_ప్రజా(ktype, b, కీలకం)) != 0)
			తిరిగి r;
	}
	ఒకవేళ ((r = sshbuf_get_bignum2(b, &exponent)) != 0)
		వెళ్ళు బహిర్గతం;
	ఒకవేళ ((ec = EVP_PKEY_get1_EC_కీలకం(కీలకం->pkey)) == ఖాళీ) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ (EC_కీలకం_సమితి_వ్యక్తిగత_కీలకం(ec, exponent) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((r = sshkey_ec_validate_వ్యక్తిగత(ec)) != 0)
		వెళ్ళు బహిర్గతం;
	ఒకవేళ (EVP_PKEY_set1_EC_కీలకం(కీలకం->pkey, ec) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		వెళ్ళు బహిర్గతం;
	}
	/* success */
	r = 0;
 బహిర్గతం:
	BN_clear_free(exponent);
	EC_కీలకం_free(ec);
	తిరిగి r;
}

స్థిర పూర్ణాంకం
ssh_ecdsa_sign(నిర్మాణం sshkey *కీలకం,
    u_char **sigp, కొలత_t *lenp,
    స్థిరరాశి u_char *దత్తాంశం, కొలత_t dlen,
    స్థిరరాశి అక్షరం *alg, స్థిరరాశి అక్షరం *sk_provider, స్థిరరాశి అక్షరం *sk_pin, u_int compat)
{
	ECDSA_SIG *esig = ఖాళీ;
	గుర్తులేని అక్షరం *sigb = ఖాళీ;
	స్థిరరాశి గుర్తులేని అక్షరం *psig;
	స్థిరరాశి BIGNUM *sig_r, *sig_s;
	పూర్ణాంకం hash_alg;
	కొలత_t slen = 0;
	పూర్ణాంకం ret = SSH_ERR_అంతర్గత_ERROR;

	ఒకవేళ (lenp != ఖాళీ)
		*lenp = 0;
	ఒకవేళ (sigp != ఖాళీ)
		*sigp = ఖాళీ;

	ఒకవేళ (కీలకం == ఖాళీ || కీలకం->pkey == ఖాళీ ||
	    sshkey_type_plain(కీలకం->type) != కీలకం_ECDSA)
		తిరిగి SSH_ERR_INVALID_వాదం;

	ఒకవేళ ((hash_alg = sshkey_ec_nid_గమ్యం_hash_alg(కీలకం->ecdsa_nid)) == -1)
		తిరిగి SSH_ERR_అంతర్గత_ERROR;

	ఒకవేళ ((ret = sshkey_pkey_digest_sign(కీలకం->pkey, hash_alg, &sigb, &slen,
	    దత్తాంశం, dlen)) != 0)
		వెళ్ళు బహిర్గతం;

	psig = sigb;
	ఒకవేళ ((esig = d2i_ECDSA_SIG(ఖాళీ, &psig, slen)) == ఖాళీ) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		వెళ్ళు బహిర్గతం;
	}
	ECDSA_SIG_get0(esig, &sig_r, &sig_s);

	ఒకవేళ ((ret = ssh_ecdsa_encode_store_sig(కీలకం, sig_r, sig_s,
	    sigp, lenp)) != 0)
		వెళ్ళు బహిర్గతం;
	/* success */
	ret = 0;
 బహిర్గతం:
	freezero(sigb, slen);
	ECDSA_SIG_free(esig);
	తిరిగి ret;
}

పూర్ణాంకం
ssh_ecdsa_encode_store_sig(స్థిరరాశి నిర్మాణం sshkey *కీలకం,
    స్థిరరాశి BIGNUM *sig_r, స్థిరరాశి BIGNUM *sig_s,
    u_char **sigp, కొలత_t *lenp)
{
	నిర్మాణం sshbuf *b = ఖాళీ, *bb = ఖాళీ;
	పూర్ణాంకం ret;
	కొలత_t len;

	ఒకవేళ (lenp != ఖాళీ)
		*lenp = 0;
	ఒకవేళ (sigp != ఖాళీ)
		*sigp = ఖాళీ;

	ఒకవేళ ((bb = sshbuf_new()) == ఖాళీ || (b = sshbuf_new()) == ఖాళీ) {
		ret = SSH_ERR_ALLOC_FAIL;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((ret = sshbuf_put_bignum2(bb, sig_r)) != 0 ||
	    (ret = sshbuf_put_bignum2(bb, sig_s)) != 0)
		వెళ్ళు బహిర్గతం;
	ఒకవేళ ((ret = sshbuf_put_cstring(b, sshkey_ssh_name_plain(కీలకం))) != 0 ||
	    (ret = sshbuf_put_stringb(b, bb)) != 0)
		వెళ్ళు బహిర్గతం;
	len = sshbuf_len(b);
	ఒకవేళ (sigp != ఖాళీ) {
		ఒకవేళ ((*sigp = జ్ఞాపకం_ఇవ్వు(len)) == ఖాళీ) {
			ret = SSH_ERR_ALLOC_FAIL;
			వెళ్ళు బహిర్గతం;
		}
		జ్ఞాపకం_నకలు(*sigp, sshbuf_ptr(b), len);
	}
	ఒకవేళ (lenp != ఖాళీ)
		*lenp = len;
	ret = 0;
 బహిర్గతం:
	sshbuf_free(b);
	sshbuf_free(bb);
	తిరిగి ret;
}

స్థిర పూర్ణాంకం
ssh_ecdsa_verify(స్థిరరాశి నిర్మాణం sshkey *కీలకం,
    స్థిరరాశి u_char *sig, కొలత_t siglen,
    స్థిరరాశి u_char *దత్తాంశం, కొలత_t dlen, స్థిరరాశి అక్షరం *alg, u_int compat,
    నిర్మాణం sshkey_sig_details **detailsp)
{
	ECDSA_SIG *esig = ఖాళీ;
	BIGNUM *sig_r = ఖాళీ, *sig_s = ఖాళీ;
	పూర్ణాంకం hash_alg, len = 0;
	పూర్ణాంకం ret = SSH_ERR_అంతర్గత_ERROR;
	నిర్మాణం sshbuf *b = ఖాళీ, *sigbuf = ఖాళీ;
	అక్షరం *ktype = ఖాళీ;
	గుర్తులేని అక్షరం *sigb = ఖాళీ, *cp;

	ఒకవేళ (కీలకం == ఖాళీ || కీలకం->pkey == ఖాళీ ||
	    sshkey_type_plain(కీలకం->type) != కీలకం_ECDSA ||
	    sig == ఖాళీ || siglen == 0)
		తిరిగి SSH_ERR_INVALID_వాదం;

	ఒకవేళ ((hash_alg = sshkey_ec_nid_గమ్యం_hash_alg(కీలకం->ecdsa_nid)) == -1)
		తిరిగి SSH_ERR_అంతర్గత_ERROR;

	/* fetch signature */
	ఒకవేళ ((b = sshbuf_from(sig, siglen)) == ఖాళీ)
		తిరిగి SSH_ERR_ALLOC_FAIL;
	ఒకవేళ (sshbuf_get_cstring(b, &ktype, ఖాళీ) != 0 ||
	    sshbuf_froms(b, &sigbuf) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ (strcmp(sshkey_ssh_name_plain(కీలకం), ktype) != 0) {
		ret = SSH_ERR_కీలకం_TYPE_MISMATCH;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ (sshbuf_len(b) != 0) {
		ret = SSH_ERR_UNEXPECTED_TRAILING_దత్తాంశం;
		వెళ్ళు బహిర్గతం;
	}

	/* parse signature */
	ఒకవేళ (sshbuf_get_bignum2(sigbuf, &sig_r) != 0 ||
	    sshbuf_get_bignum2(sigbuf, &sig_s) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ (sshbuf_len(sigbuf) != 0) {
		ret = SSH_ERR_UNEXPECTED_TRAILING_దత్తాంశం;
		వెళ్ళు బహిర్గతం;
	}

	ఒకవేళ ((esig = ECDSA_SIG_new()) == ఖాళీ) {
		ret = SSH_ERR_ALLOC_FAIL;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ (!ECDSA_SIG_set0(esig, sig_r, sig_s)) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		వెళ్ళు బహిర్గతం;
	}
	sig_r = sig_s = ఖాళీ; /* transferred */

	ఒకవేళ ((len = i2d_ECDSA_SIG(esig, ఖాళీ)) <= 0) {
		len = 0;
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((sigb = సున్నా_జ్ఞాపకం_ఇవ్వు(1, len)) == ఖాళీ) {
		ret = SSH_ERR_ALLOC_FAIL;
		వెళ్ళు బహిర్గతం;
	}
	cp = sigb; /* ASN1_item_i2d increments the pointer past the object */
	ఒకవేళ (i2d_ECDSA_SIG(esig, &cp) != len) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((ret = sshkey_pkey_digest_verify(కీలకం->pkey, hash_alg,
	    దత్తాంశం, dlen, sigb, len)) != 0)
		వెళ్ళు బహిర్గతం;
	/* success */
 బహిర్గతం:
	freezero(sigb, len);
	sshbuf_free(sigbuf);
	sshbuf_free(b);
	ECDSA_SIG_free(esig);
	BN_clear_free(sig_r);
	BN_clear_free(sig_s);
	విడుదల(ktype);
	తిరిగి ret;
}

/* NB. not static; used by ECDSA-SK */
స్థిరరాశి నిర్మాణం sshkey_impl_funcs sshkey_ecdsa_funcs = {
	/* .size = */		ssh_ecdsa_కొలత,
	/* .alloc = */		ఖాళీ,
	/* .cleanup = */	ssh_ecdsa_cleanup,
	/* .equal = */		ssh_ecdsa_equal,
	/* .ssh_serialize_public = */ ssh_ecdsa_serialize_ప్రజా,
	/* .ssh_deserialize_public = */ ssh_ecdsa_deserialize_ప్రజా,
	/* .ssh_serialize_private = */ ssh_ecdsa_serialize_వ్యక్తిగత,
	/* .ssh_deserialize_private = */ ssh_ecdsa_deserialize_వ్యక్తిగత,
	/* .generate = */	ssh_ecdsa_generate,
	/* .copy_public = */	ssh_ecdsa_copy_ప్రజా,
	/* .sign = */		ssh_ecdsa_sign,
	/* .verify = */		ssh_ecdsa_verify,
};

స్థిరరాశి నిర్మాణం sshkey_impl sshkey_ecdsa_nistp256_impl = {
	/* .name = */		"ecdsa-sha2-nistp256",
	/* .shortname = */	"ECDSA",
	/* .sigalg = */		ఖాళీ,
	/* .type = */		కీలకం_ECDSA,
	/* .nid = */		NID_X9_62_prime256v1,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_ecdsa_funcs,
};

స్థిరరాశి నిర్మాణం sshkey_impl sshkey_ecdsa_nistp256_cert_impl = {
	/* .name = */		"ecdsa-sha2-nistp256-cert-v01@openssh.com",
	/* .shortname = */	"ECDSA-CERT",
	/* .sigalg = */		ఖాళీ,
	/* .type = */		కీలకం_ECDSA_CERT,
	/* .nid = */		NID_X9_62_prime256v1,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_ecdsa_funcs,
};

స్థిరరాశి నిర్మాణం sshkey_impl sshkey_ecdsa_nistp384_impl = {
	/* .name = */		"ecdsa-sha2-nistp384",
	/* .shortname = */	"ECDSA",
	/* .sigalg = */		ఖాళీ,
	/* .type = */		కీలకం_ECDSA,
	/* .nid = */		NID_secp384r1,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_ecdsa_funcs,
};

స్థిరరాశి నిర్మాణం sshkey_impl sshkey_ecdsa_nistp384_cert_impl = {
	/* .name = */		"ecdsa-sha2-nistp384-cert-v01@openssh.com",
	/* .shortname = */	"ECDSA-CERT",
	/* .sigalg = */		ఖాళీ,
	/* .type = */		కీలకం_ECDSA_CERT,
	/* .nid = */		NID_secp384r1,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_ecdsa_funcs,
};

స్థిరరాశి నిర్మాణం sshkey_impl sshkey_ecdsa_nistp521_impl = {
	/* .name = */		"ecdsa-sha2-nistp521",
	/* .shortname = */	"ECDSA",
	/* .sigalg = */		ఖాళీ,
	/* .type = */		కీలకం_ECDSA,
	/* .nid = */		NID_secp521r1,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_ecdsa_funcs,
};

స్థిరరాశి నిర్మాణం sshkey_impl sshkey_ecdsa_nistp521_cert_impl = {
	/* .name = */		"ecdsa-sha2-nistp521-cert-v01@openssh.com",
	/* .shortname = */	"ECDSA-CERT",
	/* .sigalg = */		ఖాళీ,
	/* .type = */		కీలకం_ECDSA_CERT,
	/* .nid = */		NID_secp521r1,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_ecdsa_funcs,
};

#అయితే_ముగింపు /* WITH_OPENSSL */
