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

#شامل "includes.h"

#اگر_تعریف_شدہ WITH_OPENSSL
#شامل "openbsd-compat/openssl-compat.h"

#شامل <sys/types.h>

#شامل <openssl/bn.h>
#شامل <openssl/evp.h>

#شامل <stdarg.h>
#شامل <string.h>

#شامل "sshbuf.h"
#شامل "ssherr.h"
#تعریف_کرو SSHKEY_اندرونی
#شامل "sshkey.h"
#شامل "digest.h"

ساکن u_int
ssh_rsa_سائز(ثابت ساخت sshkey *k)
{
	اگر (k->pkey == تہی)
		واپس 0;
	واپس EVP_PKEY_بٹ(k->pkey);
}

ساکن صحیح
ssh_rsa_alloc(ساخت sshkey *k)
{
	اگر ((k->pkey = EVP_PKEY_new()) == تہی)
		واپس SSH_ERR_ALLOC_FAIL;
	واپس 0;
}

ساکن خالی
ssh_rsa_cleanup(ساخت sshkey *k)
{
	EVP_PKEY_free(k->pkey);
	k->pkey = تہی;
}

ساکن صحیح
ssh_rsa_equal(ثابت ساخت sshkey *a, ثابت ساخت sshkey *b)
{
	اگر (a->pkey == تہی || b->pkey == تہی)
		واپس 0;
	واپس EVP_PKEY_cmp(a->pkey, b->pkey) == 1;
}

ساکن صحیح
ssh_rsa_serialize_عوامی(ثابت ساخت sshkey *کلید, ساخت sshbuf *b,
    شمار sshkey_serialize_rep opts)
{
	صحیح r;
	ثابت BIGNUM *rsa_n, *rsa_e;
	ثابت RSA *rsa;

	اگر (کلید->pkey == تہی)
		واپس SSH_ERR_INVALID_دلیل;
	اگر ((rsa = EVP_PKEY_get0_RSA(کلید->pkey)) == تہی)
		واپس SSH_ERR_LIBCRYPTO_ERROR;

	RSA_get0_کلید(rsa, &rsa_n, &rsa_e, تہی);
	اگر ((r = sshbuf_put_bignum2(b, rsa_e)) != 0 ||
	    (r = sshbuf_put_bignum2(b, rsa_n)) != 0)
		واپس r;

	واپس 0;
}

ساکن صحیح
ssh_rsa_serialize_نجی(ثابت ساخت sshkey *کلید, ساخت sshbuf *b,
    شمار sshkey_serialize_rep opts)
{
	صحیح r;
	ثابت BIGNUM *rsa_n, *rsa_e, *rsa_d, *rsa_iqmp, *rsa_p, *rsa_q;
	ثابت RSA *rsa;

	اگر ((rsa = EVP_PKEY_get0_RSA(کلید->pkey)) == تہی)
		واپس SSH_ERR_LIBCRYPTO_ERROR;
	RSA_get0_کلید(rsa, &rsa_n, &rsa_e, &rsa_d);
	RSA_get0_factors(rsa, &rsa_p, &rsa_q);
	RSA_get0_crt_params(rsa, تہی, تہی, &rsa_iqmp);

	اگر (!sshkey_is_cert(کلید)) {
		/* Note: can't reuse ssh_rsa_serialize_public: e, n vs. n, e */
		اگر ((r = sshbuf_put_bignum2(b, rsa_n)) != 0 ||
		    (r = sshbuf_put_bignum2(b, rsa_e)) != 0)
			واپس r;
	}
	اگر ((r = sshbuf_put_bignum2(b, rsa_d)) != 0 ||
	    (r = sshbuf_put_bignum2(b, rsa_iqmp)) != 0 ||
	    (r = sshbuf_put_bignum2(b, rsa_p)) != 0 ||
	    (r = sshbuf_put_bignum2(b, rsa_q)) != 0)
		واپس r;

	واپس 0;
}

ساکن صحیح
ssh_rsa_generate(ساخت sshkey *k, صحیح بٹ)
{
	EVP_PKEY_CTX *ctx = تہی;
	EVP_PKEY *res = تہی;

	صحیح ret = SSH_ERR_اندرونی_ERROR;

	اگر (بٹ < SSH_RSA_MINIMUM_MODULUS_سائز ||
	    بٹ > SSHBUF_MAX_BIGNUM * 8)
		واپس SSH_ERR_کلید_لمبائی;

	اگر ((ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, تہی)) == تہی) {
		ret = SSH_ERR_ALLOC_FAIL;
		جاؤ برآمد;
	}
	اگر (EVP_PKEY_keygen_init(ctx) <= 0) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		جاؤ برآمد;
	}
	اگر (EVP_PKEY_CTX_سیٹ_rsa_keygen_بٹ(ctx, بٹ) <= 0) {
		ret = SSH_ERR_کلید_لمبائی;
		جاؤ برآمد;
	}
	اگر (EVP_PKEY_keygen(ctx, &res) <= 0 || res == تہی) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		جاؤ برآمد;
	}
	/* success */
	k->pkey = res;
	ret = 0;
 برآمد:
	EVP_PKEY_CTX_free(ctx);
	واپس ret;
}

ساکن صحیح
ssh_rsa_copy_عوامی(ثابت ساخت sshkey *from, ساخت sshkey *مقصد)
{
	ثابت BIGNUM *rsa_n, *rsa_e;
	BIGNUM *rsa_n_dup = تہی, *rsa_e_dup = تہی;
	صحیح r = SSH_ERR_اندرونی_ERROR;
	ثابت RSA *rsa_from;
	RSA *rsa_مقصد = تہی;

	اگر ((rsa_from = EVP_PKEY_get0_RSA(from->pkey)) == تہی ||
	    (rsa_مقصد = RSA_new()) == تہی)
		واپس SSH_ERR_LIBCRYPTO_ERROR;

	RSA_get0_کلید(rsa_from, &rsa_n, &rsa_e, تہی);
	اگر ((rsa_n_dup = BN_dup(rsa_n)) == تہی ||
	    (rsa_e_dup = BN_dup(rsa_e)) == تہی) {
		r = SSH_ERR_ALLOC_FAIL;
		جاؤ برآمد;
	}
	اگر (!RSA_set0_کلید(rsa_مقصد, rsa_n_dup, rsa_e_dup, تہی)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		جاؤ برآمد;
	}
	rsa_n_dup = rsa_e_dup = تہی; /* transferred */

	اگر (EVP_PKEY_set1_RSA(مقصد->pkey, rsa_مقصد) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		جاؤ برآمد;
	}
	/* success */
	r = 0;
 برآمد:
	RSA_free(rsa_مقصد);
	BN_clear_free(rsa_n_dup);
	BN_clear_free(rsa_e_dup);
	واپس r;
}

ساکن صحیح
ssh_rsa_deserialize_عوامی(ثابت حرف *ktype, ساخت sshbuf *b,
    ساخت sshkey *کلید)
{
	صحیح ret = SSH_ERR_اندرونی_ERROR;
	BIGNUM *rsa_n = تہی, *rsa_e = تہی;
	RSA *rsa = تہی;

	اگر ((rsa = RSA_new()) == تہی)
		واپس SSH_ERR_LIBCRYPTO_ERROR;

	اگر (sshbuf_get_bignum2(b, &rsa_e) != 0 ||
	    sshbuf_get_bignum2(b, &rsa_n) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		جاؤ برآمد;
	}
	اگر (!RSA_set0_کلید(rsa, rsa_n, rsa_e, تہی)) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		جاؤ برآمد;
	}
	rsa_n = rsa_e = تہی; /* transferred */
	اگر (EVP_PKEY_set1_RSA(کلید->pkey, rsa) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		جاؤ برآمد;
	}
	اگر ((ret = sshkey_check_rsa_لمبائی(کلید, 0)) != 0)
		جاؤ برآمد;
#اگر_تعریف_شدہ DEBUG_PK
	RSA_print_fp(stderr, rsa, 8);
#اگر_ختم
	/* success */
	ret = 0;
 برآمد:
	RSA_free(rsa);
	BN_clear_free(rsa_n);
	BN_clear_free(rsa_e);
	واپس ret;
}

ساکن صحیح
ssh_rsa_deserialize_نجی(ثابت حرف *ktype, ساخت sshbuf *b,
    ساخت sshkey *کلید)
{
	صحیح r;
	BIGNUM *rsa_n = تہی, *rsa_e = تہی, *rsa_d = تہی;
	BIGNUM *rsa_iqmp = تہی, *rsa_p = تہی, *rsa_q = تہی;
	BIGNUM *rsa_dmp1 = تہی, *rsa_dmq1 = تہی;
	RSA *rsa = تہی;

	اگر (sshkey_is_cert(کلید)) {
		/* sshkey_private_deserialize already has pubkey from cert */
		اگر ((rsa = EVP_PKEY_get1_RSA(کلید->pkey)) == تہی) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			جاؤ برآمد;
		}
	} ورنہ {
		اگر ((rsa = RSA_new()) == تہی) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			جاؤ برآمد;
		}
		/* Note: can't reuse ssh_rsa_deserialize_public: e,n vs. n,e */
		اگر ((r = sshbuf_get_bignum2(b, &rsa_n)) != 0 ||
		    (r = sshbuf_get_bignum2(b, &rsa_e)) != 0)
			جاؤ برآمد;
		اگر (!RSA_set0_کلید(rsa, rsa_n, rsa_e, تہی)) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			جاؤ برآمد;
		}
		rsa_n = rsa_e = تہی; /* transferred */
	}
	اگر ((r = sshbuf_get_bignum2(b, &rsa_d)) != 0 ||
	    (r = sshbuf_get_bignum2(b, &rsa_iqmp)) != 0 ||
	    (r = sshbuf_get_bignum2(b, &rsa_p)) != 0 ||
	    (r = sshbuf_get_bignum2(b, &rsa_q)) != 0)
		جاؤ برآمد;
	اگر ((r = ssh_rsa_complete_crt_parameters(rsa_d, rsa_p, rsa_q,
	    rsa_iqmp, &rsa_dmp1, &rsa_dmq1)) != 0)
		جاؤ برآمد;
	اگر (!RSA_set0_کلید(rsa, تہی, تہی, rsa_d)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		جاؤ برآمد;
	}
	rsa_d = تہی; /* transferred */
	اگر (!RSA_set0_factors(rsa, rsa_p, rsa_q)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		جاؤ برآمد;
	}
	rsa_p = rsa_q = تہی; /* transferred */
	اگر (!RSA_set0_crt_params(rsa, rsa_dmp1, rsa_dmq1, rsa_iqmp)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		جاؤ برآمد;
	}
	rsa_dmp1 = rsa_dmq1 = rsa_iqmp = تہی;
	اگر (RSA_blinding_on(rsa, تہی) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		جاؤ برآمد;
	}
	اگر (EVP_PKEY_set1_RSA(کلید->pkey, rsa) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		جاؤ برآمد;
	}
	اگر ((r = sshkey_check_rsa_لمبائی(کلید, 0)) != 0)
		جاؤ برآمد;
	/* success */
	r = 0;
 برآمد:
	RSA_free(rsa);
	BN_clear_free(rsa_n);
	BN_clear_free(rsa_e);
	BN_clear_free(rsa_d);
	BN_clear_free(rsa_p);
	BN_clear_free(rsa_q);
	BN_clear_free(rsa_iqmp);
	BN_clear_free(rsa_dmp1);
	BN_clear_free(rsa_dmq1);
	واپس r;
}

ثابت حرف *
ssh_rsa_hash_alg_ident(صحیح hash_alg)
{
	انتخاب (hash_alg) {
	حالت SSH_DIGEST_SHA1:
		واپس "ssh-rsa";
	حالت SSH_DIGEST_SHA256:
		واپس "rsa-sha2-256";
	حالت SSH_DIGEST_SHA512:
		واپس "rsa-sha2-512";
	}
	واپس تہی;
}

/*
 * Returns the hash algorithm ID for a given algorithm identifier as used
 * inside the signature blob,
 */
ساکن صحیح
rsa_hash_id_from_ident(ثابت حرف *ident)
{
	اگر (strcmp(ident, "ssh-rsa") == 0)
		واپس SSH_DIGEST_SHA1;
	اگر (strcmp(ident, "rsa-sha2-256") == 0)
		واپس SSH_DIGEST_SHA256;
	اگر (strcmp(ident, "rsa-sha2-512") == 0)
		واپس SSH_DIGEST_SHA512;
	واپس -1;
}

/*
 * Return the hash algorithm ID for the specified key name. This includes
 * all the cases of rsa_hash_id_from_ident() but also the certificate key
 * types.
 */
صحیح
ssh_rsa_hash_id_from_keyname(ثابت حرف *alg)
{
	صحیح r;

	اگر ((r = rsa_hash_id_from_ident(alg)) != -1)
		واپس r;
	اگر (strcmp(alg, "ssh-rsa-cert-v01@openssh.com") == 0)
		واپس SSH_DIGEST_SHA1;
	اگر (strcmp(alg, "rsa-sha2-256-cert-v01@openssh.com") == 0)
		واپس SSH_DIGEST_SHA256;
	اگر (strcmp(alg, "rsa-sha2-512-cert-v01@openssh.com") == 0)
		واپس SSH_DIGEST_SHA512;
	واپس -1;
}

صحیح
ssh_rsa_complete_crt_parameters(ثابت BIGNUM *rsa_d, ثابت BIGNUM *rsa_p,
    ثابت BIGNUM *rsa_q, ثابت BIGNUM *rsa_iqmp, BIGNUM **rsa_dmp1,
    BIGNUM **rsa_dmq1)
{
	BIGNUM *aux = تہی, *d_consttime = تہی;
	BN_CTX *ctx = تہی;
	صحیح r;

	*rsa_dmq1 = *rsa_dmp1 = تہی;
	اگر ((ctx = BN_CTX_new()) == تہی)
		واپس SSH_ERR_ALLOC_FAIL;
	اگر ((aux = BN_new()) == تہی ||
	    (*rsa_dmq1 = BN_new()) == تہی ||
	    (*rsa_dmp1 = BN_new()) == تہی)
		واپس SSH_ERR_ALLOC_FAIL;
	اگر ((d_consttime = BN_dup(rsa_d)) == تہی) {
		r = SSH_ERR_ALLOC_FAIL;
		جاؤ برآمد;
	}
	BN_سیٹ_flags(aux, BN_FLG_CONSTTIME);
	BN_سیٹ_flags(d_consttime, BN_FLG_CONSTTIME);

	اگر ((BN_sub(aux, rsa_q, BN_قدر_one()) == 0) ||
	    (BN_mod(*rsa_dmq1, d_consttime, aux, ctx) == 0) ||
	    (BN_sub(aux, rsa_p, BN_قدر_one()) == 0) ||
	    (BN_mod(*rsa_dmp1, d_consttime, aux, ctx) == 0)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		جاؤ برآمد;
	}
	/* success */
	r = 0;
 برآمد:
	BN_clear_free(aux);
	BN_clear_free(d_consttime);
	BN_CTX_free(ctx);
	واپس r;
}

/* RSASSA-PKCS1-v1_5 (PKCS #1 v2.0 signature) with SHA1 */
ساکن صحیح
ssh_rsa_sign(ساخت sshkey *کلید,
    u_char **sigp, سائز_t *lenp,
    ثابت u_char *ڈیٹا, سائز_t datalen,
    ثابت حرف *alg, ثابت حرف *sk_provider, ثابت حرف *sk_pin, u_int compat)
{
	u_char *sig = تہی;
	سائز_t diff, len = 0;
	صحیح slen = 0;
	صحیح hash_alg, ret = SSH_ERR_اندرونی_ERROR;

	اگر (lenp != تہی)
		*lenp = 0;
	اگر (sigp != تہی)
		*sigp = تہی;

	اگر (alg == تہی || لڑی_لمبائی(alg) == 0)
		hash_alg = SSH_DIGEST_SHA1;
	ورنہ
		hash_alg = ssh_rsa_hash_id_from_keyname(alg);

	اگر (کلید == تہی || کلید->pkey == تہی || hash_alg == -1 ||
	    sshkey_type_plain(کلید->type) != کلید_RSA)
		واپس SSH_ERR_INVALID_دلیل;
	slen = EVP_PKEY_سائز(کلید->pkey);
	اگر (slen <= 0 || slen > SSHBUF_MAX_BIGNUM)
		واپس SSH_ERR_INVALID_دلیل;
	اگر (EVP_PKEY_بٹ(کلید->pkey) < SSH_RSA_MINIMUM_MODULUS_سائز)
		واپس SSH_ERR_کلید_لمبائی;

	اگر ((ret = sshkey_pkey_digest_sign(کلید->pkey, hash_alg, &sig, &len,
	    ڈیٹا, datalen)) < 0)
		جاؤ برآمد;
	اگر (len < (سائز_t)slen) {
		diff = slen - len;
		memmove(sig + diff, sig, len);
		explicit_bzero(sig, diff);
	} ورنہ اگر (len > (سائز_t)slen) {
		ret = SSH_ERR_اندرونی_ERROR;
		جاؤ برآمد;
	}
	اگر ((ret = ssh_rsa_encode_store_sig(hash_alg, sig, slen,
	    sigp, lenp)) != 0)
		جاؤ برآمد;

	/* success */
	ret = 0;
 برآمد:
	freezero(sig, slen);
	واپس ret;
}

صحیح
ssh_rsa_encode_store_sig(صحیح hash_alg, ثابت u_char *sig, سائز_t slen,
    u_char **sigp, سائز_t *lenp)
{
	ساخت sshbuf *b = تہی;
	صحیح ret = SSH_ERR_اندرونی_ERROR;
	سائز_t len;

	اگر (lenp != تہی)
		*lenp = 0;
	اگر (sigp != تہی)
		*sigp = تہی;

	/* Encode signature */
	اگر ((b = sshbuf_new()) == تہی) {
		ret = SSH_ERR_ALLOC_FAIL;
		جاؤ برآمد;
	}
	اگر ((ret = sshbuf_put_cstring(b,
	    ssh_rsa_hash_alg_ident(hash_alg))) != 0 ||
	    (ret = sshbuf_put_string(b, sig, slen)) != 0)
		جاؤ برآمد;
	len = sshbuf_len(b);

	/* Store signature */
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
	واپس ret;
}

ساکن صحیح
ssh_rsa_verify(ثابت ساخت sshkey *کلید,
    ثابت u_char *sig, سائز_t siglen,
    ثابت u_char *ڈیٹا, سائز_t dlen, ثابت حرف *alg, u_int compat,
    ساخت sshkey_sig_details **detailsp)
{
	حرف *sigtype = تہی;
	صحیح hash_alg, want_alg, ret = SSH_ERR_اندرونی_ERROR;
	سائز_t len = 0, diff, modlen, rsasize;
	ساخت sshbuf *b = تہی;
	u_char digest[SSH_DIGEST_MAX_لمبائی], *osigblob, *sigblob = تہی;

	اگر (کلید == تہی || کلید->pkey == تہی ||
	    sshkey_type_plain(کلید->type) != کلید_RSA ||
	    sig == تہی || siglen == 0)
		واپس SSH_ERR_INVALID_دلیل;
	اگر (EVP_PKEY_بٹ(کلید->pkey) < SSH_RSA_MINIMUM_MODULUS_سائز)
		واپس SSH_ERR_کلید_لمبائی;

	اگر ((b = sshbuf_from(sig, siglen)) == تہی)
		واپس SSH_ERR_ALLOC_FAIL;
	اگر (sshbuf_get_cstring(b, &sigtype, تہی) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		جاؤ برآمد;
	}
	اگر ((hash_alg = rsa_hash_id_from_ident(sigtype)) == -1) {
		ret = SSH_ERR_کلید_TYPE_MISMATCH;
		جاؤ برآمد;
	}
	/*
	 * Allow ssh-rsa-cert-v01 certs to generate SHA2 signatures for
	 * legacy reasons, but otherwise the signature type should match.
	 */
	اگر (alg != تہی && strcmp(alg, "ssh-rsa-cert-v01@openssh.com") != 0) {
		اگر ((want_alg = ssh_rsa_hash_id_from_keyname(alg)) == -1) {
			ret = SSH_ERR_INVALID_دلیل;
			جاؤ برآمد;
		}
		اگر (hash_alg != want_alg) {
			ret = SSH_ERR_SIGNATURE_INVALID;
			جاؤ برآمد;
		}
	}
	اگر (sshbuf_get_string(b, &sigblob, &len) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		جاؤ برآمد;
	}
	اگر (sshbuf_len(b) != 0) {
		ret = SSH_ERR_UNEXPECTED_TRAILING_ڈیٹا;
		جاؤ برآمد;
	}
	/* RSA_verify expects a signature of RSA_size */
	modlen = EVP_PKEY_سائز(کلید->pkey);
	اگر (len > modlen) {
		ret = SSH_ERR_کلید_بٹ_MISMATCH;
		جاؤ برآمد;
	} ورنہ اگر (len < modlen) {
		diff = modlen - len;
		osigblob = sigblob;
		اگر ((sigblob = realloc(sigblob, modlen)) == تہی) {
			sigblob = osigblob; /* put it back for clear/free */
			ret = SSH_ERR_ALLOC_FAIL;
			جاؤ برآمد;
		}
		memmove(sigblob + diff, sigblob, len);
		explicit_bzero(sigblob, diff);
		len = modlen;
	}

	rsasize = EVP_PKEY_سائز(کلید->pkey);
	اگر (rsasize <= 0 || rsasize > SSHBUF_MAX_BIGNUM ||
	    len == 0 || len > rsasize) {
		ret = SSH_ERR_INVALID_دلیل;
		جاؤ برآمد;
	}
	ret = sshkey_pkey_digest_verify(کلید->pkey, hash_alg, ڈیٹا, dlen,
	    sigblob, len);

 برآمد:
	freezero(sigblob, len);
	آزاد(sigtype);
	sshbuf_free(b);
	explicit_bzero(digest, حجم(digest));
	واپس ret;
}

ساکن ثابت ساخت sshkey_impl_funcs sshkey_rsa_funcs = {
	/* .size = */		ssh_rsa_سائز,
	/* .alloc = */		ssh_rsa_alloc,
	/* .cleanup = */	ssh_rsa_cleanup,
	/* .equal = */		ssh_rsa_equal,
	/* .ssh_serialize_public = */ ssh_rsa_serialize_عوامی,
	/* .ssh_deserialize_public = */ ssh_rsa_deserialize_عوامی,
	/* .ssh_serialize_private = */ ssh_rsa_serialize_نجی,
	/* .ssh_deserialize_private = */ ssh_rsa_deserialize_نجی,
	/* .generate = */	ssh_rsa_generate,
	/* .copy_public = */	ssh_rsa_copy_عوامی,
	/* .sign = */		ssh_rsa_sign,
	/* .verify = */		ssh_rsa_verify,
};

ثابت ساخت sshkey_impl sshkey_rsa_impl = {
	/* .name = */		"ssh-rsa",
	/* .shortname = */	"RSA",
	/* .sigalg = */		تہی,
	/* .type = */		کلید_RSA,
	/* .nid = */		0,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_rsa_funcs,
};

ثابت ساخت sshkey_impl sshkey_rsa_cert_impl = {
	/* .name = */		"ssh-rsa-cert-v01@openssh.com",
	/* .shortname = */	"RSA-CERT",
	/* .sigalg = */		تہی,
	/* .type = */		کلید_RSA_CERT,
	/* .nid = */		0,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_rsa_funcs,
};

/* SHA2 signature algorithms */

ثابت ساخت sshkey_impl sshkey_rsa_sha256_impl = {
	/* .name = */		"rsa-sha2-256",
	/* .shortname = */	"RSA",
	/* .sigalg = */		تہی,
	/* .type = */		کلید_RSA,
	/* .nid = */		0,
	/* .cert = */		0,
	/* .sigonly = */	1,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_rsa_funcs,
};

ثابت ساخت sshkey_impl sshkey_rsa_sha512_impl = {
	/* .name = */		"rsa-sha2-512",
	/* .shortname = */	"RSA",
	/* .sigalg = */		تہی,
	/* .type = */		کلید_RSA,
	/* .nid = */		0,
	/* .cert = */		0,
	/* .sigonly = */	1,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_rsa_funcs,
};

ثابت ساخت sshkey_impl sshkey_rsa_sha256_cert_impl = {
	/* .name = */		"rsa-sha2-256-cert-v01@openssh.com",
	/* .shortname = */	"RSA-CERT",
	/* .sigalg = */		"rsa-sha2-256",
	/* .type = */		کلید_RSA_CERT,
	/* .nid = */		0,
	/* .cert = */		1,
	/* .sigonly = */	1,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_rsa_funcs,
};

ثابت ساخت sshkey_impl sshkey_rsa_sha512_cert_impl = {
	/* .name = */		"rsa-sha2-512-cert-v01@openssh.com",
	/* .shortname = */	"RSA-CERT",
	/* .sigalg = */		"rsa-sha2-512",
	/* .type = */		کلید_RSA_CERT,
	/* .nid = */		0,
	/* .cert = */		1,
	/* .sigonly = */	1,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_rsa_funcs,
};
#اگر_ختم /* WITH_OPENSSL */
