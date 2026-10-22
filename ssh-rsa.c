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

#അന്തര്ഭാവ "includes.h"

#ifdef WITH_OPENSSL
#അന്തര്ഭാവ "openbsd-compat/openssl-compat.h"

#അന്തര്ഭാവ <sys/types.h>

#അന്തര്ഭാവ <openssl/bn.h>
#അന്തര്ഭാവ <openssl/evp.h>

#അന്തര്ഭാവ <stdarg.h>
#അന്തര്ഭാവ <string.h>

#അന്തര്ഭാവ "sshbuf.h"
#അന്തര്ഭാവ "ssherr.h"
#define SSHKEY_INTERNAL
#അന്തര്ഭാവ "sshkey.h"
#അന്തര്ഭാവ "digest.h"

സ്ഥിതം u_int
ssh_rsa_size(സ്ഥിരം ഘടന sshkey *k)
{
	എങ്കിൽ (k->pkey == ശൂന്യ)
		തിരികെ 0;
	തിരികെ EVP_PKEY_bits(k->pkey);
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
ssh_rsa_alloc(ഘടന sshkey *k)
{
	എങ്കിൽ ((k->pkey = EVP_PKEY_new()) == ശൂന്യ)
		തിരികെ SSH_ERR_ALLOC_FAIL;
	തിരികെ 0;
}

സ്ഥിതം ശൂന്യം
ssh_rsa_cleanup(ഘടന sshkey *k)
{
	EVP_PKEY_free(k->pkey);
	k->pkey = ശൂന്യ;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
ssh_rsa_equal(സ്ഥിരം ഘടന sshkey *a, സ്ഥിരം ഘടന sshkey *b)
{
	എങ്കിൽ (a->pkey == ശൂന്യ || b->pkey == ശൂന്യ)
		തിരികെ 0;
	തിരികെ EVP_PKEY_cmp(a->pkey, b->pkey) == 1;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
ssh_rsa_serialize_public(സ്ഥിരം ഘടന sshkey *താക്കോൽ, ഘടന sshbuf *b,
    എണ്ണൽ sshkey_serialize_rep opts)
{
	പൂർണ്ണസംഖ്യ r;
	സ്ഥിരം BIGNUM *rsa_n, *rsa_e;
	സ്ഥിരം RSA *rsa;

	എങ്കിൽ (താക്കോൽ->pkey == ശൂന്യ)
		തിരികെ SSH_ERR_INVALID_ARGUMENT;
	എങ്കിൽ ((rsa = EVP_PKEY_get0_RSA(താക്കോൽ->pkey)) == ശൂന്യ)
		തിരികെ SSH_ERR_LIBCRYPTO_ERROR;

	RSA_get0_താക്കോൽ(rsa, &rsa_n, &rsa_e, ശൂന്യ);
	എങ്കിൽ ((r = sshbuf_put_bignum2(b, rsa_e)) != 0 ||
	    (r = sshbuf_put_bignum2(b, rsa_n)) != 0)
		തിരികെ r;

	തിരികെ 0;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
ssh_rsa_serialize_private(സ്ഥിരം ഘടന sshkey *താക്കോൽ, ഘടന sshbuf *b,
    എണ്ണൽ sshkey_serialize_rep opts)
{
	പൂർണ്ണസംഖ്യ r;
	സ്ഥിരം BIGNUM *rsa_n, *rsa_e, *rsa_d, *rsa_iqmp, *rsa_p, *rsa_q;
	സ്ഥിരം RSA *rsa;

	എങ്കിൽ ((rsa = EVP_PKEY_get0_RSA(താക്കോൽ->pkey)) == ശൂന്യ)
		തിരികെ SSH_ERR_LIBCRYPTO_ERROR;
	RSA_get0_താക്കോൽ(rsa, &rsa_n, &rsa_e, &rsa_d);
	RSA_get0_factors(rsa, &rsa_p, &rsa_q);
	RSA_get0_crt_params(rsa, ശൂന്യ, ശൂന്യ, &rsa_iqmp);

	എങ്കിൽ (!sshkey_is_cert(താക്കോൽ)) {
		/* Note: can't reuse ssh_rsa_serialize_public: e, n vs. n, e */
		എങ്കിൽ ((r = sshbuf_put_bignum2(b, rsa_n)) != 0 ||
		    (r = sshbuf_put_bignum2(b, rsa_e)) != 0)
			തിരികെ r;
	}
	എങ്കിൽ ((r = sshbuf_put_bignum2(b, rsa_d)) != 0 ||
	    (r = sshbuf_put_bignum2(b, rsa_iqmp)) != 0 ||
	    (r = sshbuf_put_bignum2(b, rsa_p)) != 0 ||
	    (r = sshbuf_put_bignum2(b, rsa_q)) != 0)
		തിരികെ r;

	തിരികെ 0;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
ssh_rsa_generate(ഘടന sshkey *k, പൂർണ്ണസംഖ്യ bits)
{
	EVP_PKEY_CTX *ctx = ശൂന്യ;
	EVP_PKEY *res = ശൂന്യ;

	പൂർണ്ണസംഖ്യ ret = SSH_ERR_INTERNAL_ERROR;

	എങ്കിൽ (bits < SSH_RSA_MINIMUM_MODULUS_SIZE ||
	    bits > SSHBUF_MAX_BIGNUM * 8)
		തിരികെ SSH_ERR_താക്കോൽ_LENGTH;

	എങ്കിൽ ((ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, ശൂന്യ)) == ശൂന്യ) {
		ret = SSH_ERR_ALLOC_FAIL;
		പോകുക out;
	}
	എങ്കിൽ (EVP_PKEY_keygen_init(ctx) <= 0) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		പോകുക out;
	}
	എങ്കിൽ (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) <= 0) {
		ret = SSH_ERR_താക്കോൽ_LENGTH;
		പോകുക out;
	}
	എങ്കിൽ (EVP_PKEY_keygen(ctx, &res) <= 0 || res == ശൂന്യ) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		പോകുക out;
	}
	/* success */
	k->pkey = res;
	ret = 0;
 out:
	EVP_PKEY_CTX_free(ctx);
	തിരികെ ret;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
ssh_rsa_copy_public(സ്ഥിരം ഘടന sshkey *from, ഘടന sshkey *to)
{
	സ്ഥിരം BIGNUM *rsa_n, *rsa_e;
	BIGNUM *rsa_n_dup = ശൂന്യ, *rsa_e_dup = ശൂന്യ;
	പൂർണ്ണസംഖ്യ r = SSH_ERR_INTERNAL_ERROR;
	സ്ഥിരം RSA *rsa_from;
	RSA *rsa_to = ശൂന്യ;

	എങ്കിൽ ((rsa_from = EVP_PKEY_get0_RSA(from->pkey)) == ശൂന്യ ||
	    (rsa_to = RSA_new()) == ശൂന്യ)
		തിരികെ SSH_ERR_LIBCRYPTO_ERROR;

	RSA_get0_താക്കോൽ(rsa_from, &rsa_n, &rsa_e, ശൂന്യ);
	എങ്കിൽ ((rsa_n_dup = BN_dup(rsa_n)) == ശൂന്യ ||
	    (rsa_e_dup = BN_dup(rsa_e)) == ശൂന്യ) {
		r = SSH_ERR_ALLOC_FAIL;
		പോകുക out;
	}
	എങ്കിൽ (!RSA_set0_താക്കോൽ(rsa_to, rsa_n_dup, rsa_e_dup, ശൂന്യ)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		പോകുക out;
	}
	rsa_n_dup = rsa_e_dup = ശൂന്യ; /* transferred */

	എങ്കിൽ (EVP_PKEY_set1_RSA(to->pkey, rsa_to) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		പോകുക out;
	}
	/* success */
	r = 0;
 out:
	RSA_free(rsa_to);
	BN_clear_free(rsa_n_dup);
	BN_clear_free(rsa_e_dup);
	തിരികെ r;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
ssh_rsa_deserialize_public(സ്ഥിരം അക്ഷരം *ktype, ഘടന sshbuf *b,
    ഘടന sshkey *താക്കോൽ)
{
	പൂർണ്ണസംഖ്യ ret = SSH_ERR_INTERNAL_ERROR;
	BIGNUM *rsa_n = ശൂന്യ, *rsa_e = ശൂന്യ;
	RSA *rsa = ശൂന്യ;

	എങ്കിൽ ((rsa = RSA_new()) == ശൂന്യ)
		തിരികെ SSH_ERR_LIBCRYPTO_ERROR;

	എങ്കിൽ (sshbuf_get_bignum2(b, &rsa_e) != 0 ||
	    sshbuf_get_bignum2(b, &rsa_n) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		പോകുക out;
	}
	എങ്കിൽ (!RSA_set0_താക്കോൽ(rsa, rsa_n, rsa_e, ശൂന്യ)) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		പോകുക out;
	}
	rsa_n = rsa_e = ശൂന്യ; /* transferred */
	എങ്കിൽ (EVP_PKEY_set1_RSA(താക്കോൽ->pkey, rsa) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		പോകുക out;
	}
	എങ്കിൽ ((ret = sshkey_check_rsa_length(താക്കോൽ, 0)) != 0)
		പോകുക out;
#ifdef DEBUG_PK
	RSA_print_fp(stderr, rsa, 8);
#endif
	/* success */
	ret = 0;
 out:
	RSA_free(rsa);
	BN_clear_free(rsa_n);
	BN_clear_free(rsa_e);
	തിരികെ ret;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
ssh_rsa_deserialize_private(സ്ഥിരം അക്ഷരം *ktype, ഘടന sshbuf *b,
    ഘടന sshkey *താക്കോൽ)
{
	പൂർണ്ണസംഖ്യ r;
	BIGNUM *rsa_n = ശൂന്യ, *rsa_e = ശൂന്യ, *rsa_d = ശൂന്യ;
	BIGNUM *rsa_iqmp = ശൂന്യ, *rsa_p = ശൂന്യ, *rsa_q = ശൂന്യ;
	BIGNUM *rsa_dmp1 = ശൂന്യ, *rsa_dmq1 = ശൂന്യ;
	RSA *rsa = ശൂന്യ;

	എങ്കിൽ (sshkey_is_cert(താക്കോൽ)) {
		/* sshkey_private_deserialize already has pubkey from cert */
		എങ്കിൽ ((rsa = EVP_PKEY_get1_RSA(താക്കോൽ->pkey)) == ശൂന്യ) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			പോകുക out;
		}
	} അല്ലെങ്കിൽ {
		എങ്കിൽ ((rsa = RSA_new()) == ശൂന്യ) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			പോകുക out;
		}
		/* Note: can't reuse ssh_rsa_deserialize_public: e,n vs. n,e */
		എങ്കിൽ ((r = sshbuf_get_bignum2(b, &rsa_n)) != 0 ||
		    (r = sshbuf_get_bignum2(b, &rsa_e)) != 0)
			പോകുക out;
		എങ്കിൽ (!RSA_set0_താക്കോൽ(rsa, rsa_n, rsa_e, ശൂന്യ)) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			പോകുക out;
		}
		rsa_n = rsa_e = ശൂന്യ; /* transferred */
	}
	എങ്കിൽ ((r = sshbuf_get_bignum2(b, &rsa_d)) != 0 ||
	    (r = sshbuf_get_bignum2(b, &rsa_iqmp)) != 0 ||
	    (r = sshbuf_get_bignum2(b, &rsa_p)) != 0 ||
	    (r = sshbuf_get_bignum2(b, &rsa_q)) != 0)
		പോകുക out;
	എങ്കിൽ ((r = ssh_rsa_complete_crt_parameters(rsa_d, rsa_p, rsa_q,
	    rsa_iqmp, &rsa_dmp1, &rsa_dmq1)) != 0)
		പോകുക out;
	എങ്കിൽ (!RSA_set0_താക്കോൽ(rsa, ശൂന്യ, ശൂന്യ, rsa_d)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		പോകുക out;
	}
	rsa_d = ശൂന്യ; /* transferred */
	എങ്കിൽ (!RSA_set0_factors(rsa, rsa_p, rsa_q)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		പോകുക out;
	}
	rsa_p = rsa_q = ശൂന്യ; /* transferred */
	എങ്കിൽ (!RSA_set0_crt_params(rsa, rsa_dmp1, rsa_dmq1, rsa_iqmp)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		പോകുക out;
	}
	rsa_dmp1 = rsa_dmq1 = rsa_iqmp = ശൂന്യ;
	എങ്കിൽ (RSA_blinding_on(rsa, ശൂന്യ) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		പോകുക out;
	}
	എങ്കിൽ (EVP_PKEY_set1_RSA(താക്കോൽ->pkey, rsa) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		പോകുക out;
	}
	എങ്കിൽ ((r = sshkey_check_rsa_length(താക്കോൽ, 0)) != 0)
		പോകുക out;
	/* success */
	r = 0;
 out:
	RSA_free(rsa);
	BN_clear_free(rsa_n);
	BN_clear_free(rsa_e);
	BN_clear_free(rsa_d);
	BN_clear_free(rsa_p);
	BN_clear_free(rsa_q);
	BN_clear_free(rsa_iqmp);
	BN_clear_free(rsa_dmp1);
	BN_clear_free(rsa_dmq1);
	തിരികെ r;
}

സ്ഥിരം അക്ഷരം *
ssh_rsa_hash_alg_ident(പൂർണ്ണസംഖ്യ hash_alg)
{
	തിരഞ്ഞെടുപ്പ് (hash_alg) {
	അവസ്ഥ SSH_DIGEST_SHA1:
		തിരികെ "ssh-rsa";
	അവസ്ഥ SSH_DIGEST_SHA256:
		തിരികെ "rsa-sha2-256";
	അവസ്ഥ SSH_DIGEST_SHA512:
		തിരികെ "rsa-sha2-512";
	}
	തിരികെ ശൂന്യ;
}

/*
 * Returns the hash algorithm ID for a given algorithm identifier as used
 * inside the signature blob,
 */
സ്ഥിതം പൂർണ്ണസംഖ്യ
rsa_hash_id_from_ident(സ്ഥിരം അക്ഷരം *ident)
{
	എങ്കിൽ (strcmp(ident, "ssh-rsa") == 0)
		തിരികെ SSH_DIGEST_SHA1;
	എങ്കിൽ (strcmp(ident, "rsa-sha2-256") == 0)
		തിരികെ SSH_DIGEST_SHA256;
	എങ്കിൽ (strcmp(ident, "rsa-sha2-512") == 0)
		തിരികെ SSH_DIGEST_SHA512;
	തിരികെ -1;
}

/*
 * Return the hash algorithm ID for the specified key name. This includes
 * all the cases of rsa_hash_id_from_ident() but also the certificate key
 * types.
 */
പൂർണ്ണസംഖ്യ
ssh_rsa_hash_id_from_keyname(സ്ഥിരം അക്ഷരം *alg)
{
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ ((r = rsa_hash_id_from_ident(alg)) != -1)
		തിരികെ r;
	എങ്കിൽ (strcmp(alg, "ssh-rsa-cert-v01@openssh.com") == 0)
		തിരികെ SSH_DIGEST_SHA1;
	എങ്കിൽ (strcmp(alg, "rsa-sha2-256-cert-v01@openssh.com") == 0)
		തിരികെ SSH_DIGEST_SHA256;
	എങ്കിൽ (strcmp(alg, "rsa-sha2-512-cert-v01@openssh.com") == 0)
		തിരികെ SSH_DIGEST_SHA512;
	തിരികെ -1;
}

പൂർണ്ണസംഖ്യ
ssh_rsa_complete_crt_parameters(സ്ഥിരം BIGNUM *rsa_d, സ്ഥിരം BIGNUM *rsa_p,
    സ്ഥിരം BIGNUM *rsa_q, സ്ഥിരം BIGNUM *rsa_iqmp, BIGNUM **rsa_dmp1,
    BIGNUM **rsa_dmq1)
{
	BIGNUM *aux = ശൂന്യ, *d_consttime = ശൂന്യ;
	BN_CTX *ctx = ശൂന്യ;
	പൂർണ്ണസംഖ്യ r;

	*rsa_dmq1 = *rsa_dmp1 = ശൂന്യ;
	എങ്കിൽ ((ctx = BN_CTX_new()) == ശൂന്യ)
		തിരികെ SSH_ERR_ALLOC_FAIL;
	എങ്കിൽ ((aux = BN_new()) == ശൂന്യ ||
	    (*rsa_dmq1 = BN_new()) == ശൂന്യ ||
	    (*rsa_dmp1 = BN_new()) == ശൂന്യ)
		തിരികെ SSH_ERR_ALLOC_FAIL;
	എങ്കിൽ ((d_consttime = BN_dup(rsa_d)) == ശൂന്യ) {
		r = SSH_ERR_ALLOC_FAIL;
		പോകുക out;
	}
	BN_set_flags(aux, BN_FLG_CONSTTIME);
	BN_set_flags(d_consttime, BN_FLG_CONSTTIME);

	എങ്കിൽ ((BN_sub(aux, rsa_q, BN_മൂല്യം_one()) == 0) ||
	    (BN_mod(*rsa_dmq1, d_consttime, aux, ctx) == 0) ||
	    (BN_sub(aux, rsa_p, BN_മൂല്യം_one()) == 0) ||
	    (BN_mod(*rsa_dmp1, d_consttime, aux, ctx) == 0)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		പോകുക out;
	}
	/* success */
	r = 0;
 out:
	BN_clear_free(aux);
	BN_clear_free(d_consttime);
	BN_CTX_free(ctx);
	തിരികെ r;
}

/* RSASSA-PKCS1-v1_5 (PKCS #1 v2.0 signature) with SHA1 */
സ്ഥിതം പൂർണ്ണസംഖ്യ
ssh_rsa_sign(ഘടന sshkey *താക്കോൽ,
    u_char **sigp, size_t *lenp,
    സ്ഥിരം u_char *data, size_t datalen,
    സ്ഥിരം അക്ഷരം *alg, സ്ഥിരം അക്ഷരം *sk_provider, സ്ഥിരം അക്ഷരം *sk_pin, u_int compat)
{
	u_char *sig = ശൂന്യ;
	size_t diff, len = 0;
	പൂർണ്ണസംഖ്യ slen = 0;
	പൂർണ്ണസംഖ്യ hash_alg, ret = SSH_ERR_INTERNAL_ERROR;

	എങ്കിൽ (lenp != ശൂന്യ)
		*lenp = 0;
	എങ്കിൽ (sigp != ശൂന്യ)
		*sigp = ശൂന്യ;

	എങ്കിൽ (alg == ശൂന്യ || strlen(alg) == 0)
		hash_alg = SSH_DIGEST_SHA1;
	അല്ലെങ്കിൽ
		hash_alg = ssh_rsa_hash_id_from_keyname(alg);

	എങ്കിൽ (താക്കോൽ == ശൂന്യ || താക്കോൽ->pkey == ശൂന്യ || hash_alg == -1 ||
	    sshkey_type_plain(താക്കോൽ->type) != താക്കോൽ_RSA)
		തിരികെ SSH_ERR_INVALID_ARGUMENT;
	slen = EVP_PKEY_size(താക്കോൽ->pkey);
	എങ്കിൽ (slen <= 0 || slen > SSHBUF_MAX_BIGNUM)
		തിരികെ SSH_ERR_INVALID_ARGUMENT;
	എങ്കിൽ (EVP_PKEY_bits(താക്കോൽ->pkey) < SSH_RSA_MINIMUM_MODULUS_SIZE)
		തിരികെ SSH_ERR_താക്കോൽ_LENGTH;

	എങ്കിൽ ((ret = sshkey_pkey_digest_sign(താക്കോൽ->pkey, hash_alg, &sig, &len,
	    data, datalen)) < 0)
		പോകുക out;
	എങ്കിൽ (len < (size_t)slen) {
		diff = slen - len;
		memmove(sig + diff, sig, len);
		explicit_bzero(sig, diff);
	} അല്ലെങ്കിൽ എങ്കിൽ (len > (size_t)slen) {
		ret = SSH_ERR_INTERNAL_ERROR;
		പോകുക out;
	}
	എങ്കിൽ ((ret = ssh_rsa_encode_store_sig(hash_alg, sig, slen,
	    sigp, lenp)) != 0)
		പോകുക out;

	/* success */
	ret = 0;
 out:
	freezero(sig, slen);
	തിരികെ ret;
}

പൂർണ്ണസംഖ്യ
ssh_rsa_encode_store_sig(പൂർണ്ണസംഖ്യ hash_alg, സ്ഥിരം u_char *sig, size_t slen,
    u_char **sigp, size_t *lenp)
{
	ഘടന sshbuf *b = ശൂന്യ;
	പൂർണ്ണസംഖ്യ ret = SSH_ERR_INTERNAL_ERROR;
	size_t len;

	എങ്കിൽ (lenp != ശൂന്യ)
		*lenp = 0;
	എങ്കിൽ (sigp != ശൂന്യ)
		*sigp = ശൂന്യ;

	/* Encode signature */
	എങ്കിൽ ((b = sshbuf_new()) == ശൂന്യ) {
		ret = SSH_ERR_ALLOC_FAIL;
		പോകുക out;
	}
	എങ്കിൽ ((ret = sshbuf_put_cstring(b,
	    ssh_rsa_hash_alg_ident(hash_alg))) != 0 ||
	    (ret = sshbuf_put_string(b, sig, slen)) != 0)
		പോകുക out;
	len = sshbuf_len(b);

	/* Store signature */
	എങ്കിൽ (sigp != ശൂന്യ) {
		എങ്കിൽ ((*sigp = malloc(len)) == ശൂന്യ) {
			ret = SSH_ERR_ALLOC_FAIL;
			പോകുക out;
		}
		memcpy(*sigp, sshbuf_ptr(b), len);
	}
	എങ്കിൽ (lenp != ശൂന്യ)
		*lenp = len;
	ret = 0;
 out:
	sshbuf_free(b);
	തിരികെ ret;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
ssh_rsa_verify(സ്ഥിരം ഘടന sshkey *താക്കോൽ,
    സ്ഥിരം u_char *sig, size_t siglen,
    സ്ഥിരം u_char *data, size_t dlen, സ്ഥിരം അക്ഷരം *alg, u_int compat,
    ഘടന sshkey_sig_details **detailsp)
{
	അക്ഷരം *sigtype = ശൂന്യ;
	പൂർണ്ണസംഖ്യ hash_alg, want_alg, ret = SSH_ERR_INTERNAL_ERROR;
	size_t len = 0, diff, modlen, rsasize;
	ഘടന sshbuf *b = ശൂന്യ;
	u_char digest[SSH_DIGEST_MAX_LENGTH], *osigblob, *sigblob = ശൂന്യ;

	എങ്കിൽ (താക്കോൽ == ശൂന്യ || താക്കോൽ->pkey == ശൂന്യ ||
	    sshkey_type_plain(താക്കോൽ->type) != താക്കോൽ_RSA ||
	    sig == ശൂന്യ || siglen == 0)
		തിരികെ SSH_ERR_INVALID_ARGUMENT;
	എങ്കിൽ (EVP_PKEY_bits(താക്കോൽ->pkey) < SSH_RSA_MINIMUM_MODULUS_SIZE)
		തിരികെ SSH_ERR_താക്കോൽ_LENGTH;

	എങ്കിൽ ((b = sshbuf_from(sig, siglen)) == ശൂന്യ)
		തിരികെ SSH_ERR_ALLOC_FAIL;
	എങ്കിൽ (sshbuf_get_cstring(b, &sigtype, ശൂന്യ) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		പോകുക out;
	}
	എങ്കിൽ ((hash_alg = rsa_hash_id_from_ident(sigtype)) == -1) {
		ret = SSH_ERR_താക്കോൽ_TYPE_MISMATCH;
		പോകുക out;
	}
	/*
	 * Allow ssh-rsa-cert-v01 certs to generate SHA2 signatures for
	 * legacy reasons, but otherwise the signature type should match.
	 */
	എങ്കിൽ (alg != ശൂന്യ && strcmp(alg, "ssh-rsa-cert-v01@openssh.com") != 0) {
		എങ്കിൽ ((want_alg = ssh_rsa_hash_id_from_keyname(alg)) == -1) {
			ret = SSH_ERR_INVALID_ARGUMENT;
			പോകുക out;
		}
		എങ്കിൽ (hash_alg != want_alg) {
			ret = SSH_ERR_SIGNATURE_INVALID;
			പോകുക out;
		}
	}
	എങ്കിൽ (sshbuf_get_string(b, &sigblob, &len) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		പോകുക out;
	}
	എങ്കിൽ (sshbuf_len(b) != 0) {
		ret = SSH_ERR_UNEXPECTED_TRAILING_DATA;
		പോകുക out;
	}
	/* RSA_verify expects a signature of RSA_size */
	modlen = EVP_PKEY_size(താക്കോൽ->pkey);
	എങ്കിൽ (len > modlen) {
		ret = SSH_ERR_താക്കോൽ_BITS_MISMATCH;
		പോകുക out;
	} അല്ലെങ്കിൽ എങ്കിൽ (len < modlen) {
		diff = modlen - len;
		osigblob = sigblob;
		എങ്കിൽ ((sigblob = realloc(sigblob, modlen)) == ശൂന്യ) {
			sigblob = osigblob; /* put it back for clear/free */
			ret = SSH_ERR_ALLOC_FAIL;
			പോകുക out;
		}
		memmove(sigblob + diff, sigblob, len);
		explicit_bzero(sigblob, diff);
		len = modlen;
	}

	rsasize = EVP_PKEY_size(താക്കോൽ->pkey);
	എങ്കിൽ (rsasize <= 0 || rsasize > SSHBUF_MAX_BIGNUM ||
	    len == 0 || len > rsasize) {
		ret = SSH_ERR_INVALID_ARGUMENT;
		പോകുക out;
	}
	ret = sshkey_pkey_digest_verify(താക്കോൽ->pkey, hash_alg, data, dlen,
	    sigblob, len);

 out:
	freezero(sigblob, len);
	സ്വതന്ത്രം(sigtype);
	sshbuf_free(b);
	explicit_bzero(digest, വലുപ്പം(digest));
	തിരികെ ret;
}

സ്ഥിതം സ്ഥിരം ഘടന sshkey_impl_funcs sshkey_rsa_funcs = {
	/* .size = */		ssh_rsa_size,
	/* .alloc = */		ssh_rsa_alloc,
	/* .cleanup = */	ssh_rsa_cleanup,
	/* .equal = */		ssh_rsa_equal,
	/* .ssh_serialize_public = */ ssh_rsa_serialize_public,
	/* .ssh_deserialize_public = */ ssh_rsa_deserialize_public,
	/* .ssh_serialize_private = */ ssh_rsa_serialize_private,
	/* .ssh_deserialize_private = */ ssh_rsa_deserialize_private,
	/* .generate = */	ssh_rsa_generate,
	/* .copy_public = */	ssh_rsa_copy_public,
	/* .sign = */		ssh_rsa_sign,
	/* .verify = */		ssh_rsa_verify,
};

സ്ഥിരം ഘടന sshkey_impl sshkey_rsa_impl = {
	/* .name = */		"ssh-rsa",
	/* .shortname = */	"RSA",
	/* .sigalg = */		ശൂന്യ,
	/* .type = */		താക്കോൽ_RSA,
	/* .nid = */		0,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_rsa_funcs,
};

സ്ഥിരം ഘടന sshkey_impl sshkey_rsa_cert_impl = {
	/* .name = */		"ssh-rsa-cert-v01@openssh.com",
	/* .shortname = */	"RSA-CERT",
	/* .sigalg = */		ശൂന്യ,
	/* .type = */		താക്കോൽ_RSA_CERT,
	/* .nid = */		0,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_rsa_funcs,
};

/* SHA2 signature algorithms */

സ്ഥിരം ഘടന sshkey_impl sshkey_rsa_sha256_impl = {
	/* .name = */		"rsa-sha2-256",
	/* .shortname = */	"RSA",
	/* .sigalg = */		ശൂന്യ,
	/* .type = */		താക്കോൽ_RSA,
	/* .nid = */		0,
	/* .cert = */		0,
	/* .sigonly = */	1,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_rsa_funcs,
};

സ്ഥിരം ഘടന sshkey_impl sshkey_rsa_sha512_impl = {
	/* .name = */		"rsa-sha2-512",
	/* .shortname = */	"RSA",
	/* .sigalg = */		ശൂന്യ,
	/* .type = */		താക്കോൽ_RSA,
	/* .nid = */		0,
	/* .cert = */		0,
	/* .sigonly = */	1,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_rsa_funcs,
};

സ്ഥിരം ഘടന sshkey_impl sshkey_rsa_sha256_cert_impl = {
	/* .name = */		"rsa-sha2-256-cert-v01@openssh.com",
	/* .shortname = */	"RSA-CERT",
	/* .sigalg = */		"rsa-sha2-256",
	/* .type = */		താക്കോൽ_RSA_CERT,
	/* .nid = */		0,
	/* .cert = */		1,
	/* .sigonly = */	1,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_rsa_funcs,
};

സ്ഥിരം ഘടന sshkey_impl sshkey_rsa_sha512_cert_impl = {
	/* .name = */		"rsa-sha2-512-cert-v01@openssh.com",
	/* .shortname = */	"RSA-CERT",
	/* .sigalg = */		"rsa-sha2-512",
	/* .type = */		താക്കോൽ_RSA_CERT,
	/* .nid = */		0,
	/* .cert = */		1,
	/* .sigonly = */	1,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_rsa_funcs,
};
#endif /* WITH_OPENSSL */
