/* $OpenBSD: ssh-rsa.c,v 1.84 2026/02/14 00:18:34 jsg Exp $ */
/*
 * Copyright (c) 2000, 2003 Markus Friedl <markus@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#అన్తర్భావ "includes.h"

#నిర్వచితమైతే WITH_OPENSSL
#అన్తర్భావ "openbsd-compat/openssl-compat.h"

#అన్తర్భావ <sys/types.h>

#అన్తర్భావ <openssl/bn.h>
#అన్తర్భావ <openssl/evp.h>

#అన్తర్భావ <stdarg.h>
#అన్తర్భావ <string.h>

#అన్తర్భావ "sshbuf.h"
#అన్తర్భావ "ssherr.h"
#నిర్వచించు SSHKEY_అంతర్గత
#అన్తర్భావ "sshkey.h"
#అన్తర్భావ "digest.h"

స్థిర u_int
ssh_rsa_కొలత(స్థిరరాశి నిర్మాణం sshkey *k)
{
	ఒకవేళ (k->pkey == ఖాళీ)
		తిరిగి 0;
	తిరిగి EVP_PKEY_బిట్లు(k->pkey);
}

స్థిర పూర్ణాంకం
ssh_rsa_alloc(నిర్మాణం sshkey *k)
{
	ఒకవేళ ((k->pkey = EVP_PKEY_new()) == ఖాళీ)
		తిరిగి SSH_ERR_ALLOC_FAIL;
	తిరిగి 0;
}

స్థిర శూన్య
ssh_rsa_cleanup(నిర్మాణం sshkey *k)
{
	EVP_PKEY_free(k->pkey);
	k->pkey = ఖాళీ;
}

స్థిర పూర్ణాంకం
ssh_rsa_equal(స్థిరరాశి నిర్మాణం sshkey *a, స్థిరరాశి నిర్మాణం sshkey *b)
{
	ఒకవేళ (a->pkey == ఖాళీ || b->pkey == ఖాళీ)
		తిరిగి 0;
	తిరిగి EVP_PKEY_cmp(a->pkey, b->pkey) == 1;
}

స్థిర పూర్ణాంకం
ssh_rsa_serialize_ప్రజా(స్థిరరాశి నిర్మాణం sshkey *కీలకం, నిర్మాణం sshbuf *b,
    గణన sshkey_serialize_rep opts)
{
	పూర్ణాంకం r;
	స్థిరరాశి BIGNUM *rsa_n, *rsa_e;
	స్థిరరాశి RSA *rsa;

	ఒకవేళ (కీలకం->pkey == ఖాళీ)
		తిరిగి SSH_ERR_INVALID_వాదం;
	ఒకవేళ ((rsa = EVP_PKEY_get0_RSA(కీలకం->pkey)) == ఖాళీ)
		తిరిగి SSH_ERR_LIBCRYPTO_ERROR;

	RSA_get0_కీలకం(rsa, &rsa_n, &rsa_e, ఖాళీ);
	ఒకవేళ ((r = sshbuf_put_bignum2(b, rsa_e)) != 0 ||
	    (r = sshbuf_put_bignum2(b, rsa_n)) != 0)
		తిరిగి r;

	తిరిగి 0;
}

స్థిర పూర్ణాంకం
ssh_rsa_serialize_వ్యక్తిగత(స్థిరరాశి నిర్మాణం sshkey *కీలకం, నిర్మాణం sshbuf *b,
    గణన sshkey_serialize_rep opts)
{
	పూర్ణాంకం r;
	స్థిరరాశి BIGNUM *rsa_n, *rsa_e, *rsa_d, *rsa_iqmp, *rsa_p, *rsa_q;
	స్థిరరాశి RSA *rsa;

	ఒకవేళ ((rsa = EVP_PKEY_get0_RSA(కీలకం->pkey)) == ఖాళీ)
		తిరిగి SSH_ERR_LIBCRYPTO_ERROR;
	RSA_get0_కీలకం(rsa, &rsa_n, &rsa_e, &rsa_d);
	RSA_get0_factors(rsa, &rsa_p, &rsa_q);
	RSA_get0_crt_params(rsa, ఖాళీ, ఖాళీ, &rsa_iqmp);

	ఒకవేళ (!sshkey_is_cert(కీలకం)) {
		/* Note: can't reuse ssh_rsa_serialize_public: e, n vs. n, e */
		ఒకవేళ ((r = sshbuf_put_bignum2(b, rsa_n)) != 0 ||
		    (r = sshbuf_put_bignum2(b, rsa_e)) != 0)
			తిరిగి r;
	}
	ఒకవేళ ((r = sshbuf_put_bignum2(b, rsa_d)) != 0 ||
	    (r = sshbuf_put_bignum2(b, rsa_iqmp)) != 0 ||
	    (r = sshbuf_put_bignum2(b, rsa_p)) != 0 ||
	    (r = sshbuf_put_bignum2(b, rsa_q)) != 0)
		తిరిగి r;

	తిరిగి 0;
}

స్థిర పూర్ణాంకం
ssh_rsa_generate(నిర్మాణం sshkey *k, పూర్ణాంకం బిట్లు)
{
	EVP_PKEY_CTX *ctx = ఖాళీ;
	EVP_PKEY *res = ఖాళీ;

	పూర్ణాంకం ret = SSH_ERR_అంతర్గత_ERROR;

	ఒకవేళ (బిట్లు < SSH_RSA_MINIMUM_MODULUS_కొలత ||
	    బిట్లు > SSHBUF_MAX_BIGNUM * 8)
		తిరిగి SSH_ERR_కీలకం_నిడివి;

	ఒకవేళ ((ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, ఖాళీ)) == ఖాళీ) {
		ret = SSH_ERR_ALLOC_FAIL;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ (EVP_PKEY_keygen_init(ctx) <= 0) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ (EVP_PKEY_CTX_సమితి_rsa_keygen_బిట్లు(ctx, బిట్లు) <= 0) {
		ret = SSH_ERR_కీలకం_నిడివి;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ (EVP_PKEY_keygen(ctx, &res) <= 0 || res == ఖాళీ) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		వెళ్ళు బహిర్గతం;
	}
	/* success */
	k->pkey = res;
	ret = 0;
 బహిర్గతం:
	EVP_PKEY_CTX_free(ctx);
	తిరిగి ret;
}

స్థిర పూర్ణాంకం
ssh_rsa_copy_ప్రజా(స్థిరరాశి నిర్మాణం sshkey *from, నిర్మాణం sshkey *గమ్యం)
{
	స్థిరరాశి BIGNUM *rsa_n, *rsa_e;
	BIGNUM *rsa_n_dup = ఖాళీ, *rsa_e_dup = ఖాళీ;
	పూర్ణాంకం r = SSH_ERR_అంతర్గత_ERROR;
	స్థిరరాశి RSA *rsa_from;
	RSA *rsa_గమ్యం = ఖాళీ;

	ఒకవేళ ((rsa_from = EVP_PKEY_get0_RSA(from->pkey)) == ఖాళీ ||
	    (rsa_గమ్యం = RSA_new()) == ఖాళీ)
		తిరిగి SSH_ERR_LIBCRYPTO_ERROR;

	RSA_get0_కీలకం(rsa_from, &rsa_n, &rsa_e, ఖాళీ);
	ఒకవేళ ((rsa_n_dup = BN_dup(rsa_n)) == ఖాళీ ||
	    (rsa_e_dup = BN_dup(rsa_e)) == ఖాళీ) {
		r = SSH_ERR_ALLOC_FAIL;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ (!RSA_set0_కీలకం(rsa_గమ్యం, rsa_n_dup, rsa_e_dup, ఖాళీ)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		వెళ్ళు బహిర్గతం;
	}
	rsa_n_dup = rsa_e_dup = ఖాళీ; /* transferred */

	ఒకవేళ (EVP_PKEY_set1_RSA(గమ్యం->pkey, rsa_గమ్యం) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		వెళ్ళు బహిర్గతం;
	}
	/* success */
	r = 0;
 బహిర్గతం:
	RSA_free(rsa_గమ్యం);
	BN_clear_free(rsa_n_dup);
	BN_clear_free(rsa_e_dup);
	తిరిగి r;
}

స్థిర పూర్ణాంకం
ssh_rsa_deserialize_ప్రజా(స్థిరరాశి అక్షరం *ktype, నిర్మాణం sshbuf *b,
    నిర్మాణం sshkey *కీలకం)
{
	పూర్ణాంకం ret = SSH_ERR_అంతర్గత_ERROR;
	BIGNUM *rsa_n = ఖాళీ, *rsa_e = ఖాళీ;
	RSA *rsa = ఖాళీ;

	ఒకవేళ ((rsa = RSA_new()) == ఖాళీ)
		తిరిగి SSH_ERR_LIBCRYPTO_ERROR;

	ఒకవేళ (sshbuf_get_bignum2(b, &rsa_e) != 0 ||
	    sshbuf_get_bignum2(b, &rsa_n) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ (!RSA_set0_కీలకం(rsa, rsa_n, rsa_e, ఖాళీ)) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		వెళ్ళు బహిర్గతం;
	}
	rsa_n = rsa_e = ఖాళీ; /* transferred */
	ఒకవేళ (EVP_PKEY_set1_RSA(కీలకం->pkey, rsa) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((ret = sshkey_check_rsa_నిడివి(కీలకం, 0)) != 0)
		వెళ్ళు బహిర్గతం;
#నిర్వచితమైతే DEBUG_PK
	RSA_print_fp(stderr, rsa, 8);
#అయితే_ముగింపు
	/* success */
	ret = 0;
 బహిర్గతం:
	RSA_free(rsa);
	BN_clear_free(rsa_n);
	BN_clear_free(rsa_e);
	తిరిగి ret;
}

స్థిర పూర్ణాంకం
ssh_rsa_deserialize_వ్యక్తిగత(స్థిరరాశి అక్షరం *ktype, నిర్మాణం sshbuf *b,
    నిర్మాణం sshkey *కీలకం)
{
	పూర్ణాంకం r;
	BIGNUM *rsa_n = ఖాళీ, *rsa_e = ఖాళీ, *rsa_d = ఖాళీ;
	BIGNUM *rsa_iqmp = ఖాళీ, *rsa_p = ఖాళీ, *rsa_q = ఖాళీ;
	BIGNUM *rsa_dmp1 = ఖాళీ, *rsa_dmq1 = ఖాళీ;
	RSA *rsa = ఖాళీ;

	ఒకవేళ (sshkey_is_cert(కీలకం)) {
		/* sshkey_private_deserialize already has pubkey from cert */
		ఒకవేళ ((rsa = EVP_PKEY_get1_RSA(కీలకం->pkey)) == ఖాళీ) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			వెళ్ళు బహిర్గతం;
		}
	} లేకపోతే {
		ఒకవేళ ((rsa = RSA_new()) == ఖాళీ) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			వెళ్ళు బహిర్గతం;
		}
		/* Note: can't reuse ssh_rsa_deserialize_public: e,n vs. n,e */
		ఒకవేళ ((r = sshbuf_get_bignum2(b, &rsa_n)) != 0 ||
		    (r = sshbuf_get_bignum2(b, &rsa_e)) != 0)
			వెళ్ళు బహిర్గతం;
		ఒకవేళ (!RSA_set0_కీలకం(rsa, rsa_n, rsa_e, ఖాళీ)) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			వెళ్ళు బహిర్గతం;
		}
		rsa_n = rsa_e = ఖాళీ; /* transferred */
	}
	ఒకవేళ ((r = sshbuf_get_bignum2(b, &rsa_d)) != 0 ||
	    (r = sshbuf_get_bignum2(b, &rsa_iqmp)) != 0 ||
	    (r = sshbuf_get_bignum2(b, &rsa_p)) != 0 ||
	    (r = sshbuf_get_bignum2(b, &rsa_q)) != 0)
		వెళ్ళు బహిర్గతం;
	ఒకవేళ ((r = ssh_rsa_complete_crt_parameters(rsa_d, rsa_p, rsa_q,
	    rsa_iqmp, &rsa_dmp1, &rsa_dmq1)) != 0)
		వెళ్ళు బహిర్గతం;
	ఒకవేళ (!RSA_set0_కీలకం(rsa, ఖాళీ, ఖాళీ, rsa_d)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		వెళ్ళు బహిర్గతం;
	}
	rsa_d = ఖాళీ; /* transferred */
	ఒకవేళ (!RSA_set0_factors(rsa, rsa_p, rsa_q)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		వెళ్ళు బహిర్గతం;
	}
	rsa_p = rsa_q = ఖాళీ; /* transferred */
	ఒకవేళ (!RSA_set0_crt_params(rsa, rsa_dmp1, rsa_dmq1, rsa_iqmp)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		వెళ్ళు బహిర్గతం;
	}
	rsa_dmp1 = rsa_dmq1 = rsa_iqmp = ఖాళీ;
	ఒకవేళ (RSA_blinding_on(rsa, ఖాళీ) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ (EVP_PKEY_set1_RSA(కీలకం->pkey, rsa) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((r = sshkey_check_rsa_నిడివి(కీలకం, 0)) != 0)
		వెళ్ళు బహిర్గతం;
	/* success */
	r = 0;
 బహిర్గతం:
	RSA_free(rsa);
	BN_clear_free(rsa_n);
	BN_clear_free(rsa_e);
	BN_clear_free(rsa_d);
	BN_clear_free(rsa_p);
	BN_clear_free(rsa_q);
	BN_clear_free(rsa_iqmp);
	BN_clear_free(rsa_dmp1);
	BN_clear_free(rsa_dmq1);
	తిరిగి r;
}

స్థిరరాశి అక్షరం *
ssh_rsa_hash_alg_ident(పూర్ణాంకం hash_alg)
{
	ఎంపిక (hash_alg) {
	స్థితి SSH_DIGEST_SHA1:
		తిరిగి "ssh-rsa";
	స్థితి SSH_DIGEST_SHA256:
		తిరిగి "rsa-sha2-256";
	స్థితి SSH_DIGEST_SHA512:
		తిరిగి "rsa-sha2-512";
	}
	తిరిగి ఖాళీ;
}

/*
 * Returns the hash algorithm ID for a given algorithm identifier as used
 * inside the signature blob,
 */
స్థిర పూర్ణాంకం
rsa_hash_id_from_ident(స్థిరరాశి అక్షరం *ident)
{
	ఒకవేళ (strcmp(ident, "ssh-rsa") == 0)
		తిరిగి SSH_DIGEST_SHA1;
	ఒకవేళ (strcmp(ident, "rsa-sha2-256") == 0)
		తిరిగి SSH_DIGEST_SHA256;
	ఒకవేళ (strcmp(ident, "rsa-sha2-512") == 0)
		తిరిగి SSH_DIGEST_SHA512;
	తిరిగి -1;
}

/*
 * Return the hash algorithm ID for the specified key name. This includes
 * all the cases of rsa_hash_id_from_ident() but also the certificate key
 * types.
 */
పూర్ణాంకం
ssh_rsa_hash_id_from_keyname(స్థిరరాశి అక్షరం *alg)
{
	పూర్ణాంకం r;

	ఒకవేళ ((r = rsa_hash_id_from_ident(alg)) != -1)
		తిరిగి r;
	ఒకవేళ (strcmp(alg, "ssh-rsa-cert-v01@openssh.com") == 0)
		తిరిగి SSH_DIGEST_SHA1;
	ఒకవేళ (strcmp(alg, "rsa-sha2-256-cert-v01@openssh.com") == 0)
		తిరిగి SSH_DIGEST_SHA256;
	ఒకవేళ (strcmp(alg, "rsa-sha2-512-cert-v01@openssh.com") == 0)
		తిరిగి SSH_DIGEST_SHA512;
	తిరిగి -1;
}

పూర్ణాంకం
ssh_rsa_complete_crt_parameters(స్థిరరాశి BIGNUM *rsa_d, స్థిరరాశి BIGNUM *rsa_p,
    స్థిరరాశి BIGNUM *rsa_q, స్థిరరాశి BIGNUM *rsa_iqmp, BIGNUM **rsa_dmp1,
    BIGNUM **rsa_dmq1)
{
	BIGNUM *aux = ఖాళీ, *d_consttime = ఖాళీ;
	BN_CTX *ctx = ఖాళీ;
	పూర్ణాంకం r;

	*rsa_dmq1 = *rsa_dmp1 = ఖాళీ;
	ఒకవేళ ((ctx = BN_CTX_new()) == ఖాళీ)
		తిరిగి SSH_ERR_ALLOC_FAIL;
	ఒకవేళ ((aux = BN_new()) == ఖాళీ ||
	    (*rsa_dmq1 = BN_new()) == ఖాళీ ||
	    (*rsa_dmp1 = BN_new()) == ఖాళీ)
		తిరిగి SSH_ERR_ALLOC_FAIL;
	ఒకవేళ ((d_consttime = BN_dup(rsa_d)) == ఖాళీ) {
		r = SSH_ERR_ALLOC_FAIL;
		వెళ్ళు బహిర్గతం;
	}
	BN_సమితి_flags(aux, BN_FLG_CONSTTIME);
	BN_సమితి_flags(d_consttime, BN_FLG_CONSTTIME);

	ఒకవేళ ((BN_sub(aux, rsa_q, BN_విలువ_one()) == 0) ||
	    (BN_mod(*rsa_dmq1, d_consttime, aux, ctx) == 0) ||
	    (BN_sub(aux, rsa_p, BN_విలువ_one()) == 0) ||
	    (BN_mod(*rsa_dmp1, d_consttime, aux, ctx) == 0)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		వెళ్ళు బహిర్గతం;
	}
	/* success */
	r = 0;
 బహిర్గతం:
	BN_clear_free(aux);
	BN_clear_free(d_consttime);
	BN_CTX_free(ctx);
	తిరిగి r;
}

/* RSASSA-PKCS1-v1_5 (PKCS #1 v2.0 signature) with SHA1 */
స్థిర పూర్ణాంకం
ssh_rsa_sign(నిర్మాణం sshkey *కీలకం,
    u_char **sigp, కొలత_t *lenp,
    స్థిరరాశి u_char *దత్తాంశం, కొలత_t datalen,
    స్థిరరాశి అక్షరం *alg, స్థిరరాశి అక్షరం *sk_provider, స్థిరరాశి అక్షరం *sk_pin, u_int compat)
{
	u_char *sig = ఖాళీ;
	కొలత_t diff, len = 0;
	పూర్ణాంకం slen = 0;
	పూర్ణాంకం hash_alg, ret = SSH_ERR_అంతర్గత_ERROR;

	ఒకవేళ (lenp != ఖాళీ)
		*lenp = 0;
	ఒకవేళ (sigp != ఖాళీ)
		*sigp = ఖాళీ;

	ఒకవేళ (alg == ఖాళీ || అక్షరశ్రేణి_పొడవు(alg) == 0)
		hash_alg = SSH_DIGEST_SHA1;
	లేకపోతే
		hash_alg = ssh_rsa_hash_id_from_keyname(alg);

	ఒకవేళ (కీలకం == ఖాళీ || కీలకం->pkey == ఖాళీ || hash_alg == -1 ||
	    sshkey_type_plain(కీలకం->type) != కీలకం_RSA)
		తిరిగి SSH_ERR_INVALID_వాదం;
	slen = EVP_PKEY_కొలత(కీలకం->pkey);
	ఒకవేళ (slen <= 0 || slen > SSHBUF_MAX_BIGNUM)
		తిరిగి SSH_ERR_INVALID_వాదం;
	ఒకవేళ (EVP_PKEY_బిట్లు(కీలకం->pkey) < SSH_RSA_MINIMUM_MODULUS_కొలత)
		తిరిగి SSH_ERR_కీలకం_నిడివి;

	ఒకవేళ ((ret = sshkey_pkey_digest_sign(కీలకం->pkey, hash_alg, &sig, &len,
	    దత్తాంశం, datalen)) < 0)
		వెళ్ళు బహిర్గతం;
	ఒకవేళ (len < (కొలత_t)slen) {
		diff = slen - len;
		memmove(sig + diff, sig, len);
		explicit_bzero(sig, diff);
	} లేకపోతే ఒకవేళ (len > (కొలత_t)slen) {
		ret = SSH_ERR_అంతర్గత_ERROR;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((ret = ssh_rsa_encode_store_sig(hash_alg, sig, slen,
	    sigp, lenp)) != 0)
		వెళ్ళు బహిర్గతం;

	/* success */
	ret = 0;
 బహిర్గతం:
	freezero(sig, slen);
	తిరిగి ret;
}

పూర్ణాంకం
ssh_rsa_encode_store_sig(పూర్ణాంకం hash_alg, స్థిరరాశి u_char *sig, కొలత_t slen,
    u_char **sigp, కొలత_t *lenp)
{
	నిర్మాణం sshbuf *b = ఖాళీ;
	పూర్ణాంకం ret = SSH_ERR_అంతర్గత_ERROR;
	కొలత_t len;

	ఒకవేళ (lenp != ఖాళీ)
		*lenp = 0;
	ఒకవేళ (sigp != ఖాళీ)
		*sigp = ఖాళీ;

	/* Encode signature */
	ఒకవేళ ((b = sshbuf_new()) == ఖాళీ) {
		ret = SSH_ERR_ALLOC_FAIL;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((ret = sshbuf_put_cstring(b,
	    ssh_rsa_hash_alg_ident(hash_alg))) != 0 ||
	    (ret = sshbuf_put_string(b, sig, slen)) != 0)
		వెళ్ళు బహిర్గతం;
	len = sshbuf_len(b);

	/* Store signature */
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
	తిరిగి ret;
}

స్థిర పూర్ణాంకం
ssh_rsa_verify(స్థిరరాశి నిర్మాణం sshkey *కీలకం,
    స్థిరరాశి u_char *sig, కొలత_t siglen,
    స్థిరరాశి u_char *దత్తాంశం, కొలత_t dlen, స్థిరరాశి అక్షరం *alg, u_int compat,
    నిర్మాణం sshkey_sig_details **detailsp)
{
	అక్షరం *sigtype = ఖాళీ;
	పూర్ణాంకం hash_alg, want_alg, ret = SSH_ERR_అంతర్గత_ERROR;
	కొలత_t len = 0, diff, modlen, rsasize;
	నిర్మాణం sshbuf *b = ఖాళీ;
	u_char digest[SSH_DIGEST_MAX_నిడివి], *osigblob, *sigblob = ఖాళీ;

	ఒకవేళ (కీలకం == ఖాళీ || కీలకం->pkey == ఖాళీ ||
	    sshkey_type_plain(కీలకం->type) != కీలకం_RSA ||
	    sig == ఖాళీ || siglen == 0)
		తిరిగి SSH_ERR_INVALID_వాదం;
	ఒకవేళ (EVP_PKEY_బిట్లు(కీలకం->pkey) < SSH_RSA_MINIMUM_MODULUS_కొలత)
		తిరిగి SSH_ERR_కీలకం_నిడివి;

	ఒకవేళ ((b = sshbuf_from(sig, siglen)) == ఖాళీ)
		తిరిగి SSH_ERR_ALLOC_FAIL;
	ఒకవేళ (sshbuf_get_cstring(b, &sigtype, ఖాళీ) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((hash_alg = rsa_hash_id_from_ident(sigtype)) == -1) {
		ret = SSH_ERR_కీలకం_TYPE_MISMATCH;
		వెళ్ళు బహిర్గతం;
	}
	/*
	 * Allow ssh-rsa-cert-v01 certs to generate SHA2 signatures for
	 * legacy reasons, but otherwise the signature type should match.
	 */
	ఒకవేళ (alg != ఖాళీ && strcmp(alg, "ssh-rsa-cert-v01@openssh.com") != 0) {
		ఒకవేళ ((want_alg = ssh_rsa_hash_id_from_keyname(alg)) == -1) {
			ret = SSH_ERR_INVALID_వాదం;
			వెళ్ళు బహిర్గతం;
		}
		ఒకవేళ (hash_alg != want_alg) {
			ret = SSH_ERR_SIGNATURE_INVALID;
			వెళ్ళు బహిర్గతం;
		}
	}
	ఒకవేళ (sshbuf_get_string(b, &sigblob, &len) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ (sshbuf_len(b) != 0) {
		ret = SSH_ERR_UNEXPECTED_TRAILING_దత్తాంశం;
		వెళ్ళు బహిర్గతం;
	}
	/* RSA_verify expects a signature of RSA_size */
	modlen = EVP_PKEY_కొలత(కీలకం->pkey);
	ఒకవేళ (len > modlen) {
		ret = SSH_ERR_కీలకం_బిట్లు_MISMATCH;
		వెళ్ళు బహిర్గతం;
	} లేకపోతే ఒకవేళ (len < modlen) {
		diff = modlen - len;
		osigblob = sigblob;
		ఒకవేళ ((sigblob = realloc(sigblob, modlen)) == ఖాళీ) {
			sigblob = osigblob; /* put it back for clear/free */
			ret = SSH_ERR_ALLOC_FAIL;
			వెళ్ళు బహిర్గతం;
		}
		memmove(sigblob + diff, sigblob, len);
		explicit_bzero(sigblob, diff);
		len = modlen;
	}

	rsasize = EVP_PKEY_కొలత(కీలకం->pkey);
	ఒకవేళ (rsasize <= 0 || rsasize > SSHBUF_MAX_BIGNUM ||
	    len == 0 || len > rsasize) {
		ret = SSH_ERR_INVALID_వాదం;
		వెళ్ళు బహిర్గతం;
	}
	ret = sshkey_pkey_digest_verify(కీలకం->pkey, hash_alg, దత్తాంశం, dlen,
	    sigblob, len);

 బహిర్గతం:
	freezero(sigblob, len);
	విడుదల(sigtype);
	sshbuf_free(b);
	explicit_bzero(digest, పరిమాణం(digest));
	తిరిగి ret;
}

స్థిర స్థిరరాశి నిర్మాణం sshkey_impl_funcs sshkey_rsa_funcs = {
	/* .size = */		ssh_rsa_కొలత,
	/* .alloc = */		ssh_rsa_alloc,
	/* .cleanup = */	ssh_rsa_cleanup,
	/* .equal = */		ssh_rsa_equal,
	/* .ssh_serialize_public = */ ssh_rsa_serialize_ప్రజా,
	/* .ssh_deserialize_public = */ ssh_rsa_deserialize_ప్రజా,
	/* .ssh_serialize_private = */ ssh_rsa_serialize_వ్యక్తిగత,
	/* .ssh_deserialize_private = */ ssh_rsa_deserialize_వ్యక్తిగత,
	/* .generate = */	ssh_rsa_generate,
	/* .copy_public = */	ssh_rsa_copy_ప్రజా,
	/* .sign = */		ssh_rsa_sign,
	/* .verify = */		ssh_rsa_verify,
};

స్థిరరాశి నిర్మాణం sshkey_impl sshkey_rsa_impl = {
	/* .name = */		"ssh-rsa",
	/* .shortname = */	"RSA",
	/* .sigalg = */		ఖాళీ,
	/* .type = */		కీలకం_RSA,
	/* .nid = */		0,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_rsa_funcs,
};

స్థిరరాశి నిర్మాణం sshkey_impl sshkey_rsa_cert_impl = {
	/* .name = */		"ssh-rsa-cert-v01@openssh.com",
	/* .shortname = */	"RSA-CERT",
	/* .sigalg = */		ఖాళీ,
	/* .type = */		కీలకం_RSA_CERT,
	/* .nid = */		0,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_rsa_funcs,
};

/* SHA2 signature algorithms */

స్థిరరాశి నిర్మాణం sshkey_impl sshkey_rsa_sha256_impl = {
	/* .name = */		"rsa-sha2-256",
	/* .shortname = */	"RSA",
	/* .sigalg = */		ఖాళీ,
	/* .type = */		కీలకం_RSA,
	/* .nid = */		0,
	/* .cert = */		0,
	/* .sigonly = */	1,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_rsa_funcs,
};

స్థిరరాశి నిర్మాణం sshkey_impl sshkey_rsa_sha512_impl = {
	/* .name = */		"rsa-sha2-512",
	/* .shortname = */	"RSA",
	/* .sigalg = */		ఖాళీ,
	/* .type = */		కీలకం_RSA,
	/* .nid = */		0,
	/* .cert = */		0,
	/* .sigonly = */	1,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_rsa_funcs,
};

స్థిరరాశి నిర్మాణం sshkey_impl sshkey_rsa_sha256_cert_impl = {
	/* .name = */		"rsa-sha2-256-cert-v01@openssh.com",
	/* .shortname = */	"RSA-CERT",
	/* .sigalg = */		"rsa-sha2-256",
	/* .type = */		కీలకం_RSA_CERT,
	/* .nid = */		0,
	/* .cert = */		1,
	/* .sigonly = */	1,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_rsa_funcs,
};

స్థిరరాశి నిర్మాణం sshkey_impl sshkey_rsa_sha512_cert_impl = {
	/* .name = */		"rsa-sha2-512-cert-v01@openssh.com",
	/* .shortname = */	"RSA-CERT",
	/* .sigalg = */		"rsa-sha2-512",
	/* .type = */		కీలకం_RSA_CERT,
	/* .nid = */		0,
	/* .cert = */		1,
	/* .sigonly = */	1,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_rsa_funcs,
};
#అయితే_ముగింపు /* WITH_OPENSSL */
