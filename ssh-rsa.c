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

#ضمن "includes.h"

#جيڪڏهن_وصف_ٿيل WITH_OPENSSL
#ضمن "openbsd-compat/openssl-compat.h"

#ضمن <sys/types.h>

#ضمن <openssl/bn.h>
#ضمن <openssl/evp.h>

#ضمن <stdarg.h>
#ضمن <string.h>

#ضمن "sshbuf.h"
#ضمن "ssherr.h"
#وصف_ڪريو SSHKEY_اندروني
#ضمن "sshkey.h"
#ضمن "digest.h"

ساكن u_int
ssh_rsa_سائيز(ثابت بنية sshkey *k)
{
	إذا (k->pkey == عدم)
		أرجع 0;
	أرجع EVP_PKEY_بٽ(k->pkey);
}

ساكن صحيح
ssh_rsa_alloc(بنية sshkey *k)
{
	إذا ((k->pkey = EVP_PKEY_new()) == عدم)
		أرجع SSH_ERR_ALLOC_FAIL;
	أرجع 0;
}

ساكن فراغ
ssh_rsa_cleanup(بنية sshkey *k)
{
	EVP_PKEY_free(k->pkey);
	k->pkey = عدم;
}

ساكن صحيح
ssh_rsa_equal(ثابت بنية sshkey *a, ثابت بنية sshkey *b)
{
	إذا (a->pkey == عدم || b->pkey == عدم)
		أرجع 0;
	أرجع EVP_PKEY_cmp(a->pkey, b->pkey) == 1;
}

ساكن صحيح
ssh_rsa_serialize_عوامي(ثابت بنية sshkey *ڪنجي, بنية sshbuf *b,
    تعداد sshkey_serialize_rep opts)
{
	صحيح r;
	ثابت BIGNUM *rsa_n, *rsa_e;
	ثابت RSA *rsa;

	إذا (ڪنجي->pkey == عدم)
		أرجع SSH_ERR_INVALID_دليل;
	إذا ((rsa = EVP_PKEY_get0_RSA(ڪنجي->pkey)) == عدم)
		أرجع SSH_ERR_LIBCRYPTO_ERROR;

	RSA_get0_ڪنجي(rsa, &rsa_n, &rsa_e, عدم);
	إذا ((r = sshbuf_put_bignum2(b, rsa_e)) != 0 ||
	    (r = sshbuf_put_bignum2(b, rsa_n)) != 0)
		أرجع r;

	أرجع 0;
}

ساكن صحيح
ssh_rsa_serialize_ذاتي(ثابت بنية sshkey *ڪنجي, بنية sshbuf *b,
    تعداد sshkey_serialize_rep opts)
{
	صحيح r;
	ثابت BIGNUM *rsa_n, *rsa_e, *rsa_d, *rsa_iqmp, *rsa_p, *rsa_q;
	ثابت RSA *rsa;

	إذا ((rsa = EVP_PKEY_get0_RSA(ڪنجي->pkey)) == عدم)
		أرجع SSH_ERR_LIBCRYPTO_ERROR;
	RSA_get0_ڪنجي(rsa, &rsa_n, &rsa_e, &rsa_d);
	RSA_get0_factors(rsa, &rsa_p, &rsa_q);
	RSA_get0_crt_params(rsa, عدم, عدم, &rsa_iqmp);

	إذا (!sshkey_is_cert(ڪنجي)) {
		/* Note: can't reuse ssh_rsa_serialize_public: e, n vs. n, e */
		إذا ((r = sshbuf_put_bignum2(b, rsa_n)) != 0 ||
		    (r = sshbuf_put_bignum2(b, rsa_e)) != 0)
			أرجع r;
	}
	إذا ((r = sshbuf_put_bignum2(b, rsa_d)) != 0 ||
	    (r = sshbuf_put_bignum2(b, rsa_iqmp)) != 0 ||
	    (r = sshbuf_put_bignum2(b, rsa_p)) != 0 ||
	    (r = sshbuf_put_bignum2(b, rsa_q)) != 0)
		أرجع r;

	أرجع 0;
}

ساكن صحيح
ssh_rsa_generate(بنية sshkey *k, صحيح بٽ)
{
	EVP_PKEY_CTX *ctx = عدم;
	EVP_PKEY *res = عدم;

	صحيح ret = SSH_ERR_اندروني_ERROR;

	إذا (بٽ < SSH_RSA_MINIMUM_MODULUS_سائيز ||
	    بٽ > SSHBUF_MAX_BIGNUM * 8)
		أرجع SSH_ERR_ڪنجي_ڊيگهائي;

	إذا ((ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, عدم)) == عدم) {
		ret = SSH_ERR_ALLOC_FAIL;
		اذهب ٻاهريون;
	}
	إذا (EVP_PKEY_keygen_init(ctx) <= 0) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		اذهب ٻاهريون;
	}
	إذا (EVP_PKEY_CTX_سيٽ_rsa_keygen_بٽ(ctx, بٽ) <= 0) {
		ret = SSH_ERR_ڪنجي_ڊيگهائي;
		اذهب ٻاهريون;
	}
	إذا (EVP_PKEY_keygen(ctx, &res) <= 0 || res == عدم) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		اذهب ٻاهريون;
	}
	/* success */
	k->pkey = res;
	ret = 0;
 ٻاهريون:
	EVP_PKEY_CTX_free(ctx);
	أرجع ret;
}

ساكن صحيح
ssh_rsa_copy_عوامي(ثابت بنية sshkey *from, بنية sshkey *منزل)
{
	ثابت BIGNUM *rsa_n, *rsa_e;
	BIGNUM *rsa_n_dup = عدم, *rsa_e_dup = عدم;
	صحيح r = SSH_ERR_اندروني_ERROR;
	ثابت RSA *rsa_from;
	RSA *rsa_منزل = عدم;

	إذا ((rsa_from = EVP_PKEY_get0_RSA(from->pkey)) == عدم ||
	    (rsa_منزل = RSA_new()) == عدم)
		أرجع SSH_ERR_LIBCRYPTO_ERROR;

	RSA_get0_ڪنجي(rsa_from, &rsa_n, &rsa_e, عدم);
	إذا ((rsa_n_dup = BN_dup(rsa_n)) == عدم ||
	    (rsa_e_dup = BN_dup(rsa_e)) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب ٻاهريون;
	}
	إذا (!RSA_set0_ڪنجي(rsa_منزل, rsa_n_dup, rsa_e_dup, عدم)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		اذهب ٻاهريون;
	}
	rsa_n_dup = rsa_e_dup = عدم; /* transferred */

	إذا (EVP_PKEY_set1_RSA(منزل->pkey, rsa_منزل) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		اذهب ٻاهريون;
	}
	/* success */
	r = 0;
 ٻاهريون:
	RSA_free(rsa_منزل);
	BN_clear_free(rsa_n_dup);
	BN_clear_free(rsa_e_dup);
	أرجع r;
}

ساكن صحيح
ssh_rsa_deserialize_عوامي(ثابت حرف *ktype, بنية sshbuf *b,
    بنية sshkey *ڪنجي)
{
	صحيح ret = SSH_ERR_اندروني_ERROR;
	BIGNUM *rsa_n = عدم, *rsa_e = عدم;
	RSA *rsa = عدم;

	إذا ((rsa = RSA_new()) == عدم)
		أرجع SSH_ERR_LIBCRYPTO_ERROR;

	إذا (sshbuf_get_bignum2(b, &rsa_e) != 0 ||
	    sshbuf_get_bignum2(b, &rsa_n) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		اذهب ٻاهريون;
	}
	إذا (!RSA_set0_ڪنجي(rsa, rsa_n, rsa_e, عدم)) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		اذهب ٻاهريون;
	}
	rsa_n = rsa_e = عدم; /* transferred */
	إذا (EVP_PKEY_set1_RSA(ڪنجي->pkey, rsa) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		اذهب ٻاهريون;
	}
	إذا ((ret = sshkey_check_rsa_ڊيگهائي(ڪنجي, 0)) != 0)
		اذهب ٻاهريون;
#جيڪڏهن_وصف_ٿيل DEBUG_PK
	RSA_print_fp(stderr, rsa, 8);
#جيڪڏهن_پورو
	/* success */
	ret = 0;
 ٻاهريون:
	RSA_free(rsa);
	BN_clear_free(rsa_n);
	BN_clear_free(rsa_e);
	أرجع ret;
}

ساكن صحيح
ssh_rsa_deserialize_ذاتي(ثابت حرف *ktype, بنية sshbuf *b,
    بنية sshkey *ڪنجي)
{
	صحيح r;
	BIGNUM *rsa_n = عدم, *rsa_e = عدم, *rsa_d = عدم;
	BIGNUM *rsa_iqmp = عدم, *rsa_p = عدم, *rsa_q = عدم;
	BIGNUM *rsa_dmp1 = عدم, *rsa_dmq1 = عدم;
	RSA *rsa = عدم;

	إذا (sshkey_is_cert(ڪنجي)) {
		/* sshkey_private_deserialize already has pubkey from cert */
		إذا ((rsa = EVP_PKEY_get1_RSA(ڪنجي->pkey)) == عدم) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			اذهب ٻاهريون;
		}
	} وإلا {
		إذا ((rsa = RSA_new()) == عدم) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			اذهب ٻاهريون;
		}
		/* Note: can't reuse ssh_rsa_deserialize_public: e,n vs. n,e */
		إذا ((r = sshbuf_get_bignum2(b, &rsa_n)) != 0 ||
		    (r = sshbuf_get_bignum2(b, &rsa_e)) != 0)
			اذهب ٻاهريون;
		إذا (!RSA_set0_ڪنجي(rsa, rsa_n, rsa_e, عدم)) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			اذهب ٻاهريون;
		}
		rsa_n = rsa_e = عدم; /* transferred */
	}
	إذا ((r = sshbuf_get_bignum2(b, &rsa_d)) != 0 ||
	    (r = sshbuf_get_bignum2(b, &rsa_iqmp)) != 0 ||
	    (r = sshbuf_get_bignum2(b, &rsa_p)) != 0 ||
	    (r = sshbuf_get_bignum2(b, &rsa_q)) != 0)
		اذهب ٻاهريون;
	إذا ((r = ssh_rsa_complete_crt_parameters(rsa_d, rsa_p, rsa_q,
	    rsa_iqmp, &rsa_dmp1, &rsa_dmq1)) != 0)
		اذهب ٻاهريون;
	إذا (!RSA_set0_ڪنجي(rsa, عدم, عدم, rsa_d)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		اذهب ٻاهريون;
	}
	rsa_d = عدم; /* transferred */
	إذا (!RSA_set0_factors(rsa, rsa_p, rsa_q)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		اذهب ٻاهريون;
	}
	rsa_p = rsa_q = عدم; /* transferred */
	إذا (!RSA_set0_crt_params(rsa, rsa_dmp1, rsa_dmq1, rsa_iqmp)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		اذهب ٻاهريون;
	}
	rsa_dmp1 = rsa_dmq1 = rsa_iqmp = عدم;
	إذا (RSA_blinding_on(rsa, عدم) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		اذهب ٻاهريون;
	}
	إذا (EVP_PKEY_set1_RSA(ڪنجي->pkey, rsa) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		اذهب ٻاهريون;
	}
	إذا ((r = sshkey_check_rsa_ڊيگهائي(ڪنجي, 0)) != 0)
		اذهب ٻاهريون;
	/* success */
	r = 0;
 ٻاهريون:
	RSA_free(rsa);
	BN_clear_free(rsa_n);
	BN_clear_free(rsa_e);
	BN_clear_free(rsa_d);
	BN_clear_free(rsa_p);
	BN_clear_free(rsa_q);
	BN_clear_free(rsa_iqmp);
	BN_clear_free(rsa_dmp1);
	BN_clear_free(rsa_dmq1);
	أرجع r;
}

ثابت حرف *
ssh_rsa_hash_alg_ident(صحيح hash_alg)
{
	بدل (hash_alg) {
	حالة SSH_DIGEST_SHA1:
		أرجع "ssh-rsa";
	حالة SSH_DIGEST_SHA256:
		أرجع "rsa-sha2-256";
	حالة SSH_DIGEST_SHA512:
		أرجع "rsa-sha2-512";
	}
	أرجع عدم;
}

/*
 * Returns the hash algorithm ID for a given algorithm identifier as used
 * inside the signature blob,
 */
ساكن صحيح
rsa_hash_id_from_ident(ثابت حرف *ident)
{
	إذا (strcmp(ident, "ssh-rsa") == 0)
		أرجع SSH_DIGEST_SHA1;
	إذا (strcmp(ident, "rsa-sha2-256") == 0)
		أرجع SSH_DIGEST_SHA256;
	إذا (strcmp(ident, "rsa-sha2-512") == 0)
		أرجع SSH_DIGEST_SHA512;
	أرجع -1;
}

/*
 * Return the hash algorithm ID for the specified key name. This includes
 * all the cases of rsa_hash_id_from_ident() but also the certificate key
 * types.
 */
صحيح
ssh_rsa_hash_id_from_keyname(ثابت حرف *alg)
{
	صحيح r;

	إذا ((r = rsa_hash_id_from_ident(alg)) != -1)
		أرجع r;
	إذا (strcmp(alg, "ssh-rsa-cert-v01@openssh.com") == 0)
		أرجع SSH_DIGEST_SHA1;
	إذا (strcmp(alg, "rsa-sha2-256-cert-v01@openssh.com") == 0)
		أرجع SSH_DIGEST_SHA256;
	إذا (strcmp(alg, "rsa-sha2-512-cert-v01@openssh.com") == 0)
		أرجع SSH_DIGEST_SHA512;
	أرجع -1;
}

صحيح
ssh_rsa_complete_crt_parameters(ثابت BIGNUM *rsa_d, ثابت BIGNUM *rsa_p,
    ثابت BIGNUM *rsa_q, ثابت BIGNUM *rsa_iqmp, BIGNUM **rsa_dmp1,
    BIGNUM **rsa_dmq1)
{
	BIGNUM *aux = عدم, *d_consttime = عدم;
	BN_CTX *ctx = عدم;
	صحيح r;

	*rsa_dmq1 = *rsa_dmp1 = عدم;
	إذا ((ctx = BN_CTX_new()) == عدم)
		أرجع SSH_ERR_ALLOC_FAIL;
	إذا ((aux = BN_new()) == عدم ||
	    (*rsa_dmq1 = BN_new()) == عدم ||
	    (*rsa_dmp1 = BN_new()) == عدم)
		أرجع SSH_ERR_ALLOC_FAIL;
	إذا ((d_consttime = BN_dup(rsa_d)) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب ٻاهريون;
	}
	BN_سيٽ_flags(aux, BN_FLG_CONSTTIME);
	BN_سيٽ_flags(d_consttime, BN_FLG_CONSTTIME);

	إذا ((BN_sub(aux, rsa_q, BN_قدر_one()) == 0) ||
	    (BN_mod(*rsa_dmq1, d_consttime, aux, ctx) == 0) ||
	    (BN_sub(aux, rsa_p, BN_قدر_one()) == 0) ||
	    (BN_mod(*rsa_dmp1, d_consttime, aux, ctx) == 0)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		اذهب ٻاهريون;
	}
	/* success */
	r = 0;
 ٻاهريون:
	BN_clear_free(aux);
	BN_clear_free(d_consttime);
	BN_CTX_free(ctx);
	أرجع r;
}

/* RSASSA-PKCS1-v1_5 (PKCS #1 v2.0 signature) with SHA1 */
ساكن صحيح
ssh_rsa_sign(بنية sshkey *ڪنجي,
    u_char **sigp, سائيز_t *lenp,
    ثابت u_char *معلومات, سائيز_t datalen,
    ثابت حرف *alg, ثابت حرف *sk_provider, ثابت حرف *sk_pin, u_int compat)
{
	u_char *sig = عدم;
	سائيز_t diff, len = 0;
	صحيح slen = 0;
	صحيح hash_alg, ret = SSH_ERR_اندروني_ERROR;

	إذا (lenp != عدم)
		*lenp = 0;
	إذا (sigp != عدم)
		*sigp = عدم;

	إذا (alg == عدم || لڙي_ڊيگهه(alg) == 0)
		hash_alg = SSH_DIGEST_SHA1;
	وإلا
		hash_alg = ssh_rsa_hash_id_from_keyname(alg);

	إذا (ڪنجي == عدم || ڪنجي->pkey == عدم || hash_alg == -1 ||
	    sshkey_type_plain(ڪنجي->type) != ڪنجي_RSA)
		أرجع SSH_ERR_INVALID_دليل;
	slen = EVP_PKEY_سائيز(ڪنجي->pkey);
	إذا (slen <= 0 || slen > SSHBUF_MAX_BIGNUM)
		أرجع SSH_ERR_INVALID_دليل;
	إذا (EVP_PKEY_بٽ(ڪنجي->pkey) < SSH_RSA_MINIMUM_MODULUS_سائيز)
		أرجع SSH_ERR_ڪنجي_ڊيگهائي;

	إذا ((ret = sshkey_pkey_digest_sign(ڪنجي->pkey, hash_alg, &sig, &len,
	    معلومات, datalen)) < 0)
		اذهب ٻاهريون;
	إذا (len < (سائيز_t)slen) {
		diff = slen - len;
		memmove(sig + diff, sig, len);
		explicit_bzero(sig, diff);
	} وإلا إذا (len > (سائيز_t)slen) {
		ret = SSH_ERR_اندروني_ERROR;
		اذهب ٻاهريون;
	}
	إذا ((ret = ssh_rsa_encode_store_sig(hash_alg, sig, slen,
	    sigp, lenp)) != 0)
		اذهب ٻاهريون;

	/* success */
	ret = 0;
 ٻاهريون:
	freezero(sig, slen);
	أرجع ret;
}

صحيح
ssh_rsa_encode_store_sig(صحيح hash_alg, ثابت u_char *sig, سائيز_t slen,
    u_char **sigp, سائيز_t *lenp)
{
	بنية sshbuf *b = عدم;
	صحيح ret = SSH_ERR_اندروني_ERROR;
	سائيز_t len;

	إذا (lenp != عدم)
		*lenp = 0;
	إذا (sigp != عدم)
		*sigp = عدم;

	/* Encode signature */
	إذا ((b = sshbuf_new()) == عدم) {
		ret = SSH_ERR_ALLOC_FAIL;
		اذهب ٻاهريون;
	}
	إذا ((ret = sshbuf_put_cstring(b,
	    ssh_rsa_hash_alg_ident(hash_alg))) != 0 ||
	    (ret = sshbuf_put_string(b, sig, slen)) != 0)
		اذهب ٻاهريون;
	len = sshbuf_len(b);

	/* Store signature */
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
	أرجع ret;
}

ساكن صحيح
ssh_rsa_verify(ثابت بنية sshkey *ڪنجي,
    ثابت u_char *sig, سائيز_t siglen,
    ثابت u_char *معلومات, سائيز_t dlen, ثابت حرف *alg, u_int compat,
    بنية sshkey_sig_details **detailsp)
{
	حرف *sigtype = عدم;
	صحيح hash_alg, want_alg, ret = SSH_ERR_اندروني_ERROR;
	سائيز_t len = 0, diff, modlen, rsasize;
	بنية sshbuf *b = عدم;
	u_char digest[SSH_DIGEST_MAX_ڊيگهائي], *osigblob, *sigblob = عدم;

	إذا (ڪنجي == عدم || ڪنجي->pkey == عدم ||
	    sshkey_type_plain(ڪنجي->type) != ڪنجي_RSA ||
	    sig == عدم || siglen == 0)
		أرجع SSH_ERR_INVALID_دليل;
	إذا (EVP_PKEY_بٽ(ڪنجي->pkey) < SSH_RSA_MINIMUM_MODULUS_سائيز)
		أرجع SSH_ERR_ڪنجي_ڊيگهائي;

	إذا ((b = sshbuf_from(sig, siglen)) == عدم)
		أرجع SSH_ERR_ALLOC_FAIL;
	إذا (sshbuf_get_cstring(b, &sigtype, عدم) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		اذهب ٻاهريون;
	}
	إذا ((hash_alg = rsa_hash_id_from_ident(sigtype)) == -1) {
		ret = SSH_ERR_ڪنجي_TYPE_MISMATCH;
		اذهب ٻاهريون;
	}
	/*
	 * Allow ssh-rsa-cert-v01 certs to generate SHA2 signatures for
	 * legacy reasons, but otherwise the signature type should match.
	 */
	إذا (alg != عدم && strcmp(alg, "ssh-rsa-cert-v01@openssh.com") != 0) {
		إذا ((want_alg = ssh_rsa_hash_id_from_keyname(alg)) == -1) {
			ret = SSH_ERR_INVALID_دليل;
			اذهب ٻاهريون;
		}
		إذا (hash_alg != want_alg) {
			ret = SSH_ERR_SIGNATURE_INVALID;
			اذهب ٻاهريون;
		}
	}
	إذا (sshbuf_get_string(b, &sigblob, &len) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		اذهب ٻاهريون;
	}
	إذا (sshbuf_len(b) != 0) {
		ret = SSH_ERR_UNEXPECTED_TRAILING_معلومات;
		اذهب ٻاهريون;
	}
	/* RSA_verify expects a signature of RSA_size */
	modlen = EVP_PKEY_سائيز(ڪنجي->pkey);
	إذا (len > modlen) {
		ret = SSH_ERR_ڪنجي_بٽ_MISMATCH;
		اذهب ٻاهريون;
	} وإلا إذا (len < modlen) {
		diff = modlen - len;
		osigblob = sigblob;
		إذا ((sigblob = realloc(sigblob, modlen)) == عدم) {
			sigblob = osigblob; /* put it back for clear/free */
			ret = SSH_ERR_ALLOC_FAIL;
			اذهب ٻاهريون;
		}
		memmove(sigblob + diff, sigblob, len);
		explicit_bzero(sigblob, diff);
		len = modlen;
	}

	rsasize = EVP_PKEY_سائيز(ڪنجي->pkey);
	إذا (rsasize <= 0 || rsasize > SSHBUF_MAX_BIGNUM ||
	    len == 0 || len > rsasize) {
		ret = SSH_ERR_INVALID_دليل;
		اذهب ٻاهريون;
	}
	ret = sshkey_pkey_digest_verify(ڪنجي->pkey, hash_alg, معلومات, dlen,
	    sigblob, len);

 ٻاهريون:
	freezero(sigblob, len);
	حرر(sigtype);
	sshbuf_free(b);
	explicit_bzero(digest, حجم(digest));
	أرجع ret;
}

ساكن ثابت بنية sshkey_impl_funcs sshkey_rsa_funcs = {
	/* .size = */		ssh_rsa_سائيز,
	/* .alloc = */		ssh_rsa_alloc,
	/* .cleanup = */	ssh_rsa_cleanup,
	/* .equal = */		ssh_rsa_equal,
	/* .ssh_serialize_public = */ ssh_rsa_serialize_عوامي,
	/* .ssh_deserialize_public = */ ssh_rsa_deserialize_عوامي,
	/* .ssh_serialize_private = */ ssh_rsa_serialize_ذاتي,
	/* .ssh_deserialize_private = */ ssh_rsa_deserialize_ذاتي,
	/* .generate = */	ssh_rsa_generate,
	/* .copy_public = */	ssh_rsa_copy_عوامي,
	/* .sign = */		ssh_rsa_sign,
	/* .verify = */		ssh_rsa_verify,
};

ثابت بنية sshkey_impl sshkey_rsa_impl = {
	/* .name = */		"ssh-rsa",
	/* .shortname = */	"RSA",
	/* .sigalg = */		عدم,
	/* .type = */		ڪنجي_RSA,
	/* .nid = */		0,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_rsa_funcs,
};

ثابت بنية sshkey_impl sshkey_rsa_cert_impl = {
	/* .name = */		"ssh-rsa-cert-v01@openssh.com",
	/* .shortname = */	"RSA-CERT",
	/* .sigalg = */		عدم,
	/* .type = */		ڪنجي_RSA_CERT,
	/* .nid = */		0,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_rsa_funcs,
};

/* SHA2 signature algorithms */

ثابت بنية sshkey_impl sshkey_rsa_sha256_impl = {
	/* .name = */		"rsa-sha2-256",
	/* .shortname = */	"RSA",
	/* .sigalg = */		عدم,
	/* .type = */		ڪنجي_RSA,
	/* .nid = */		0,
	/* .cert = */		0,
	/* .sigonly = */	1,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_rsa_funcs,
};

ثابت بنية sshkey_impl sshkey_rsa_sha512_impl = {
	/* .name = */		"rsa-sha2-512",
	/* .shortname = */	"RSA",
	/* .sigalg = */		عدم,
	/* .type = */		ڪنجي_RSA,
	/* .nid = */		0,
	/* .cert = */		0,
	/* .sigonly = */	1,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_rsa_funcs,
};

ثابت بنية sshkey_impl sshkey_rsa_sha256_cert_impl = {
	/* .name = */		"rsa-sha2-256-cert-v01@openssh.com",
	/* .shortname = */	"RSA-CERT",
	/* .sigalg = */		"rsa-sha2-256",
	/* .type = */		ڪنجي_RSA_CERT,
	/* .nid = */		0,
	/* .cert = */		1,
	/* .sigonly = */	1,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_rsa_funcs,
};

ثابت بنية sshkey_impl sshkey_rsa_sha512_cert_impl = {
	/* .name = */		"rsa-sha2-512-cert-v01@openssh.com",
	/* .shortname = */	"RSA-CERT",
	/* .sigalg = */		"rsa-sha2-512",
	/* .type = */		ڪنجي_RSA_CERT,
	/* .nid = */		0,
	/* .cert = */		1,
	/* .sigonly = */	1,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_rsa_funcs,
};
#جيڪڏهن_پورو /* WITH_OPENSSL */
