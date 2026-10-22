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

#અન્તર્ભાવ "includes.h"

#ifdef WITH_OPENSSL
#અન્તર્ભાવ "openbsd-compat/openssl-compat.h"

#અન્તર્ભાવ <sys/types.h>

#અન્તર્ભાવ <openssl/bn.h>
#અન્તર્ભાવ <openssl/evp.h>

#અન્તર્ભાવ <stdarg.h>
#અન્તર્ભાવ <string.h>

#અન્તર્ભાવ "sshbuf.h"
#અન્તર્ભાવ "ssherr.h"
#define SSHKEY_INTERNAL
#અન્તર્ભાવ "sshkey.h"
#અન્તર્ભાવ "digest.h"

સ્થિર u_int
ssh_rsa_size(અચલ સંરચના sshkey *k)
{
	જો (k->pkey == ખાલી)
		પાછા 0;
	પાછા EVP_PKEY_bits(k->pkey);
}

સ્થિર પૂર્ણાંક
ssh_rsa_alloc(સંરચના sshkey *k)
{
	જો ((k->pkey = EVP_PKEY_new()) == ખાલી)
		પાછા SSH_ERR_ALLOC_FAIL;
	પાછા 0;
}

સ્થિર શૂન્ય
ssh_rsa_cleanup(સંરચના sshkey *k)
{
	EVP_PKEY_free(k->pkey);
	k->pkey = ખાલી;
}

સ્થિર પૂર્ણાંક
ssh_rsa_equal(અચલ સંરચના sshkey *a, અચલ સંરચના sshkey *b)
{
	જો (a->pkey == ખાલી || b->pkey == ખાલી)
		પાછા 0;
	પાછા EVP_PKEY_cmp(a->pkey, b->pkey) == 1;
}

સ્થિર પૂર્ણાંક
ssh_rsa_serialize_public(અચલ સંરચના sshkey *ચાવી, સંરચના sshbuf *b,
    ગણના sshkey_serialize_rep opts)
{
	પૂર્ણાંક r;
	અચલ BIGNUM *rsa_n, *rsa_e;
	અચલ RSA *rsa;

	જો (ચાવી->pkey == ખાલી)
		પાછા SSH_ERR_INVALID_ARGUMENT;
	જો ((rsa = EVP_PKEY_get0_RSA(ચાવી->pkey)) == ખાલી)
		પાછા SSH_ERR_LIBCRYPTO_ERROR;

	RSA_get0_ચાવી(rsa, &rsa_n, &rsa_e, ખાલી);
	જો ((r = sshbuf_put_bignum2(b, rsa_e)) != 0 ||
	    (r = sshbuf_put_bignum2(b, rsa_n)) != 0)
		પાછા r;

	પાછા 0;
}

સ્થિર પૂર્ણાંક
ssh_rsa_serialize_private(અચલ સંરચના sshkey *ચાવી, સંરચના sshbuf *b,
    ગણના sshkey_serialize_rep opts)
{
	પૂર્ણાંક r;
	અચલ BIGNUM *rsa_n, *rsa_e, *rsa_d, *rsa_iqmp, *rsa_p, *rsa_q;
	અચલ RSA *rsa;

	જો ((rsa = EVP_PKEY_get0_RSA(ચાવી->pkey)) == ખાલી)
		પાછા SSH_ERR_LIBCRYPTO_ERROR;
	RSA_get0_ચાવી(rsa, &rsa_n, &rsa_e, &rsa_d);
	RSA_get0_factors(rsa, &rsa_p, &rsa_q);
	RSA_get0_crt_params(rsa, ખાલી, ખાલી, &rsa_iqmp);

	જો (!sshkey_is_cert(ચાવી)) {
		/* Note: can't reuse ssh_rsa_serialize_public: e, n vs. n, e */
		જો ((r = sshbuf_put_bignum2(b, rsa_n)) != 0 ||
		    (r = sshbuf_put_bignum2(b, rsa_e)) != 0)
			પાછા r;
	}
	જો ((r = sshbuf_put_bignum2(b, rsa_d)) != 0 ||
	    (r = sshbuf_put_bignum2(b, rsa_iqmp)) != 0 ||
	    (r = sshbuf_put_bignum2(b, rsa_p)) != 0 ||
	    (r = sshbuf_put_bignum2(b, rsa_q)) != 0)
		પાછા r;

	પાછા 0;
}

સ્થિર પૂર્ણાંક
ssh_rsa_generate(સંરચના sshkey *k, પૂર્ણાંક bits)
{
	EVP_PKEY_CTX *ctx = ખાલી;
	EVP_PKEY *res = ખાલી;

	પૂર્ણાંક ret = SSH_ERR_INTERNAL_ERROR;

	જો (bits < SSH_RSA_MINIMUM_MODULUS_SIZE ||
	    bits > SSHBUF_MAX_BIGNUM * 8)
		પાછા SSH_ERR_ચાવી_LENGTH;

	જો ((ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, ખાલી)) == ખાલી) {
		ret = SSH_ERR_ALLOC_FAIL;
		જાઓ out;
	}
	જો (EVP_PKEY_keygen_init(ctx) <= 0) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		જાઓ out;
	}
	જો (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) <= 0) {
		ret = SSH_ERR_ચાવી_LENGTH;
		જાઓ out;
	}
	જો (EVP_PKEY_keygen(ctx, &res) <= 0 || res == ખાલી) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		જાઓ out;
	}
	/* success */
	k->pkey = res;
	ret = 0;
 out:
	EVP_PKEY_CTX_free(ctx);
	પાછા ret;
}

સ્થિર પૂર્ણાંક
ssh_rsa_copy_public(અચલ સંરચના sshkey *from, સંરચના sshkey *to)
{
	અચલ BIGNUM *rsa_n, *rsa_e;
	BIGNUM *rsa_n_dup = ખાલી, *rsa_e_dup = ખાલી;
	પૂર્ણાંક r = SSH_ERR_INTERNAL_ERROR;
	અચલ RSA *rsa_from;
	RSA *rsa_to = ખાલી;

	જો ((rsa_from = EVP_PKEY_get0_RSA(from->pkey)) == ખાલી ||
	    (rsa_to = RSA_new()) == ખાલી)
		પાછા SSH_ERR_LIBCRYPTO_ERROR;

	RSA_get0_ચાવી(rsa_from, &rsa_n, &rsa_e, ખાલી);
	જો ((rsa_n_dup = BN_dup(rsa_n)) == ખાલી ||
	    (rsa_e_dup = BN_dup(rsa_e)) == ખાલી) {
		r = SSH_ERR_ALLOC_FAIL;
		જાઓ out;
	}
	જો (!RSA_set0_ચાવી(rsa_to, rsa_n_dup, rsa_e_dup, ખાલી)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		જાઓ out;
	}
	rsa_n_dup = rsa_e_dup = ખાલી; /* transferred */

	જો (EVP_PKEY_set1_RSA(to->pkey, rsa_to) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		જાઓ out;
	}
	/* success */
	r = 0;
 out:
	RSA_free(rsa_to);
	BN_clear_free(rsa_n_dup);
	BN_clear_free(rsa_e_dup);
	પાછા r;
}

સ્થિર પૂર્ણાંક
ssh_rsa_deserialize_public(અચલ અક્ષર *ktype, સંરચના sshbuf *b,
    સંરચના sshkey *ચાવી)
{
	પૂર્ણાંક ret = SSH_ERR_INTERNAL_ERROR;
	BIGNUM *rsa_n = ખાલી, *rsa_e = ખાલી;
	RSA *rsa = ખાલી;

	જો ((rsa = RSA_new()) == ખાલી)
		પાછા SSH_ERR_LIBCRYPTO_ERROR;

	જો (sshbuf_get_bignum2(b, &rsa_e) != 0 ||
	    sshbuf_get_bignum2(b, &rsa_n) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		જાઓ out;
	}
	જો (!RSA_set0_ચાવી(rsa, rsa_n, rsa_e, ખાલી)) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		જાઓ out;
	}
	rsa_n = rsa_e = ખાલી; /* transferred */
	જો (EVP_PKEY_set1_RSA(ચાવી->pkey, rsa) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		જાઓ out;
	}
	જો ((ret = sshkey_check_rsa_length(ચાવી, 0)) != 0)
		જાઓ out;
#ifdef DEBUG_PK
	RSA_print_fp(stderr, rsa, 8);
#endif
	/* success */
	ret = 0;
 out:
	RSA_free(rsa);
	BN_clear_free(rsa_n);
	BN_clear_free(rsa_e);
	પાછા ret;
}

સ્થિર પૂર્ણાંક
ssh_rsa_deserialize_private(અચલ અક્ષર *ktype, સંરચના sshbuf *b,
    સંરચના sshkey *ચાવી)
{
	પૂર્ણાંક r;
	BIGNUM *rsa_n = ખાલી, *rsa_e = ખાલી, *rsa_d = ખાલી;
	BIGNUM *rsa_iqmp = ખાલી, *rsa_p = ખાલી, *rsa_q = ખાલી;
	BIGNUM *rsa_dmp1 = ખાલી, *rsa_dmq1 = ખાલી;
	RSA *rsa = ખાલી;

	જો (sshkey_is_cert(ચાવી)) {
		/* sshkey_private_deserialize already has pubkey from cert */
		જો ((rsa = EVP_PKEY_get1_RSA(ચાવી->pkey)) == ખાલી) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			જાઓ out;
		}
	} નહીંતર {
		જો ((rsa = RSA_new()) == ખાલી) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			જાઓ out;
		}
		/* Note: can't reuse ssh_rsa_deserialize_public: e,n vs. n,e */
		જો ((r = sshbuf_get_bignum2(b, &rsa_n)) != 0 ||
		    (r = sshbuf_get_bignum2(b, &rsa_e)) != 0)
			જાઓ out;
		જો (!RSA_set0_ચાવી(rsa, rsa_n, rsa_e, ખાલી)) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			જાઓ out;
		}
		rsa_n = rsa_e = ખાલી; /* transferred */
	}
	જો ((r = sshbuf_get_bignum2(b, &rsa_d)) != 0 ||
	    (r = sshbuf_get_bignum2(b, &rsa_iqmp)) != 0 ||
	    (r = sshbuf_get_bignum2(b, &rsa_p)) != 0 ||
	    (r = sshbuf_get_bignum2(b, &rsa_q)) != 0)
		જાઓ out;
	જો ((r = ssh_rsa_complete_crt_parameters(rsa_d, rsa_p, rsa_q,
	    rsa_iqmp, &rsa_dmp1, &rsa_dmq1)) != 0)
		જાઓ out;
	જો (!RSA_set0_ચાવી(rsa, ખાલી, ખાલી, rsa_d)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		જાઓ out;
	}
	rsa_d = ખાલી; /* transferred */
	જો (!RSA_set0_factors(rsa, rsa_p, rsa_q)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		જાઓ out;
	}
	rsa_p = rsa_q = ખાલી; /* transferred */
	જો (!RSA_set0_crt_params(rsa, rsa_dmp1, rsa_dmq1, rsa_iqmp)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		જાઓ out;
	}
	rsa_dmp1 = rsa_dmq1 = rsa_iqmp = ખાલી;
	જો (RSA_blinding_on(rsa, ખાલી) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		જાઓ out;
	}
	જો (EVP_PKEY_set1_RSA(ચાવી->pkey, rsa) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		જાઓ out;
	}
	જો ((r = sshkey_check_rsa_length(ચાવી, 0)) != 0)
		જાઓ out;
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
	પાછા r;
}

અચલ અક્ષર *
ssh_rsa_hash_alg_ident(પૂર્ણાંક hash_alg)
{
	પસંદગી (hash_alg) {
	સ્થિતિ SSH_DIGEST_SHA1:
		પાછા "ssh-rsa";
	સ્થિતિ SSH_DIGEST_SHA256:
		પાછા "rsa-sha2-256";
	સ્થિતિ SSH_DIGEST_SHA512:
		પાછા "rsa-sha2-512";
	}
	પાછા ખાલી;
}

/*
 * Returns the hash algorithm ID for a given algorithm identifier as used
 * inside the signature blob,
 */
સ્થિર પૂર્ણાંક
rsa_hash_id_from_ident(અચલ અક્ષર *ident)
{
	જો (strcmp(ident, "ssh-rsa") == 0)
		પાછા SSH_DIGEST_SHA1;
	જો (strcmp(ident, "rsa-sha2-256") == 0)
		પાછા SSH_DIGEST_SHA256;
	જો (strcmp(ident, "rsa-sha2-512") == 0)
		પાછા SSH_DIGEST_SHA512;
	પાછા -1;
}

/*
 * Return the hash algorithm ID for the specified key name. This includes
 * all the cases of rsa_hash_id_from_ident() but also the certificate key
 * types.
 */
પૂર્ણાંક
ssh_rsa_hash_id_from_keyname(અચલ અક્ષર *alg)
{
	પૂર્ણાંક r;

	જો ((r = rsa_hash_id_from_ident(alg)) != -1)
		પાછા r;
	જો (strcmp(alg, "ssh-rsa-cert-v01@openssh.com") == 0)
		પાછા SSH_DIGEST_SHA1;
	જો (strcmp(alg, "rsa-sha2-256-cert-v01@openssh.com") == 0)
		પાછા SSH_DIGEST_SHA256;
	જો (strcmp(alg, "rsa-sha2-512-cert-v01@openssh.com") == 0)
		પાછા SSH_DIGEST_SHA512;
	પાછા -1;
}

પૂર્ણાંક
ssh_rsa_complete_crt_parameters(અચલ BIGNUM *rsa_d, અચલ BIGNUM *rsa_p,
    અચલ BIGNUM *rsa_q, અચલ BIGNUM *rsa_iqmp, BIGNUM **rsa_dmp1,
    BIGNUM **rsa_dmq1)
{
	BIGNUM *aux = ખાલી, *d_consttime = ખાલી;
	BN_CTX *ctx = ખાલી;
	પૂર્ણાંક r;

	*rsa_dmq1 = *rsa_dmp1 = ખાલી;
	જો ((ctx = BN_CTX_new()) == ખાલી)
		પાછા SSH_ERR_ALLOC_FAIL;
	જો ((aux = BN_new()) == ખાલી ||
	    (*rsa_dmq1 = BN_new()) == ખાલી ||
	    (*rsa_dmp1 = BN_new()) == ખાલી)
		પાછા SSH_ERR_ALLOC_FAIL;
	જો ((d_consttime = BN_dup(rsa_d)) == ખાલી) {
		r = SSH_ERR_ALLOC_FAIL;
		જાઓ out;
	}
	BN_set_flags(aux, BN_FLG_CONSTTIME);
	BN_set_flags(d_consttime, BN_FLG_CONSTTIME);

	જો ((BN_sub(aux, rsa_q, BN_કિંમત_one()) == 0) ||
	    (BN_mod(*rsa_dmq1, d_consttime, aux, ctx) == 0) ||
	    (BN_sub(aux, rsa_p, BN_કિંમત_one()) == 0) ||
	    (BN_mod(*rsa_dmp1, d_consttime, aux, ctx) == 0)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		જાઓ out;
	}
	/* success */
	r = 0;
 out:
	BN_clear_free(aux);
	BN_clear_free(d_consttime);
	BN_CTX_free(ctx);
	પાછા r;
}

/* RSASSA-PKCS1-v1_5 (PKCS #1 v2.0 signature) with SHA1 */
સ્થિર પૂર્ણાંક
ssh_rsa_sign(સંરચના sshkey *ચાવી,
    u_char **sigp, size_t *lenp,
    અચલ u_char *data, size_t datalen,
    અચલ અક્ષર *alg, અચલ અક્ષર *sk_provider, અચલ અક્ષર *sk_pin, u_int compat)
{
	u_char *sig = ખાલી;
	size_t diff, len = 0;
	પૂર્ણાંક slen = 0;
	પૂર્ણાંક hash_alg, ret = SSH_ERR_INTERNAL_ERROR;

	જો (lenp != ખાલી)
		*lenp = 0;
	જો (sigp != ખાલી)
		*sigp = ખાલી;

	જો (alg == ખાલી || strlen(alg) == 0)
		hash_alg = SSH_DIGEST_SHA1;
	નહીંતર
		hash_alg = ssh_rsa_hash_id_from_keyname(alg);

	જો (ચાવી == ખાલી || ચાવી->pkey == ખાલી || hash_alg == -1 ||
	    sshkey_type_plain(ચાવી->type) != ચાવી_RSA)
		પાછા SSH_ERR_INVALID_ARGUMENT;
	slen = EVP_PKEY_size(ચાવી->pkey);
	જો (slen <= 0 || slen > SSHBUF_MAX_BIGNUM)
		પાછા SSH_ERR_INVALID_ARGUMENT;
	જો (EVP_PKEY_bits(ચાવી->pkey) < SSH_RSA_MINIMUM_MODULUS_SIZE)
		પાછા SSH_ERR_ચાવી_LENGTH;

	જો ((ret = sshkey_pkey_digest_sign(ચાવી->pkey, hash_alg, &sig, &len,
	    data, datalen)) < 0)
		જાઓ out;
	જો (len < (size_t)slen) {
		diff = slen - len;
		memmove(sig + diff, sig, len);
		explicit_bzero(sig, diff);
	} નહીંતર જો (len > (size_t)slen) {
		ret = SSH_ERR_INTERNAL_ERROR;
		જાઓ out;
	}
	જો ((ret = ssh_rsa_encode_store_sig(hash_alg, sig, slen,
	    sigp, lenp)) != 0)
		જાઓ out;

	/* success */
	ret = 0;
 out:
	freezero(sig, slen);
	પાછા ret;
}

પૂર્ણાંક
ssh_rsa_encode_store_sig(પૂર્ણાંક hash_alg, અચલ u_char *sig, size_t slen,
    u_char **sigp, size_t *lenp)
{
	સંરચના sshbuf *b = ખાલી;
	પૂર્ણાંક ret = SSH_ERR_INTERNAL_ERROR;
	size_t len;

	જો (lenp != ખાલી)
		*lenp = 0;
	જો (sigp != ખાલી)
		*sigp = ખાલી;

	/* Encode signature */
	જો ((b = sshbuf_new()) == ખાલી) {
		ret = SSH_ERR_ALLOC_FAIL;
		જાઓ out;
	}
	જો ((ret = sshbuf_put_cstring(b,
	    ssh_rsa_hash_alg_ident(hash_alg))) != 0 ||
	    (ret = sshbuf_put_string(b, sig, slen)) != 0)
		જાઓ out;
	len = sshbuf_len(b);

	/* Store signature */
	જો (sigp != ખાલી) {
		જો ((*sigp = malloc(len)) == ખાલી) {
			ret = SSH_ERR_ALLOC_FAIL;
			જાઓ out;
		}
		memcpy(*sigp, sshbuf_ptr(b), len);
	}
	જો (lenp != ખાલી)
		*lenp = len;
	ret = 0;
 out:
	sshbuf_free(b);
	પાછા ret;
}

સ્થિર પૂર્ણાંક
ssh_rsa_verify(અચલ સંરચના sshkey *ચાવી,
    અચલ u_char *sig, size_t siglen,
    અચલ u_char *data, size_t dlen, અચલ અક્ષર *alg, u_int compat,
    સંરચના sshkey_sig_details **detailsp)
{
	અક્ષર *sigtype = ખાલી;
	પૂર્ણાંક hash_alg, want_alg, ret = SSH_ERR_INTERNAL_ERROR;
	size_t len = 0, diff, modlen, rsasize;
	સંરચના sshbuf *b = ખાલી;
	u_char digest[SSH_DIGEST_MAX_LENGTH], *osigblob, *sigblob = ખાલી;

	જો (ચાવી == ખાલી || ચાવી->pkey == ખાલી ||
	    sshkey_type_plain(ચાવી->type) != ચાવી_RSA ||
	    sig == ખાલી || siglen == 0)
		પાછા SSH_ERR_INVALID_ARGUMENT;
	જો (EVP_PKEY_bits(ચાવી->pkey) < SSH_RSA_MINIMUM_MODULUS_SIZE)
		પાછા SSH_ERR_ચાવી_LENGTH;

	જો ((b = sshbuf_from(sig, siglen)) == ખાલી)
		પાછા SSH_ERR_ALLOC_FAIL;
	જો (sshbuf_get_cstring(b, &sigtype, ખાલી) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		જાઓ out;
	}
	જો ((hash_alg = rsa_hash_id_from_ident(sigtype)) == -1) {
		ret = SSH_ERR_ચાવી_TYPE_MISMATCH;
		જાઓ out;
	}
	/*
	 * Allow ssh-rsa-cert-v01 certs to generate SHA2 signatures for
	 * legacy reasons, but otherwise the signature type should match.
	 */
	જો (alg != ખાલી && strcmp(alg, "ssh-rsa-cert-v01@openssh.com") != 0) {
		જો ((want_alg = ssh_rsa_hash_id_from_keyname(alg)) == -1) {
			ret = SSH_ERR_INVALID_ARGUMENT;
			જાઓ out;
		}
		જો (hash_alg != want_alg) {
			ret = SSH_ERR_SIGNATURE_INVALID;
			જાઓ out;
		}
	}
	જો (sshbuf_get_string(b, &sigblob, &len) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		જાઓ out;
	}
	જો (sshbuf_len(b) != 0) {
		ret = SSH_ERR_UNEXPECTED_TRAILING_DATA;
		જાઓ out;
	}
	/* RSA_verify expects a signature of RSA_size */
	modlen = EVP_PKEY_size(ચાવી->pkey);
	જો (len > modlen) {
		ret = SSH_ERR_ચાવી_BITS_MISMATCH;
		જાઓ out;
	} નહીંતર જો (len < modlen) {
		diff = modlen - len;
		osigblob = sigblob;
		જો ((sigblob = realloc(sigblob, modlen)) == ખાલી) {
			sigblob = osigblob; /* put it back for clear/free */
			ret = SSH_ERR_ALLOC_FAIL;
			જાઓ out;
		}
		memmove(sigblob + diff, sigblob, len);
		explicit_bzero(sigblob, diff);
		len = modlen;
	}

	rsasize = EVP_PKEY_size(ચાવી->pkey);
	જો (rsasize <= 0 || rsasize > SSHBUF_MAX_BIGNUM ||
	    len == 0 || len > rsasize) {
		ret = SSH_ERR_INVALID_ARGUMENT;
		જાઓ out;
	}
	ret = sshkey_pkey_digest_verify(ચાવી->pkey, hash_alg, data, dlen,
	    sigblob, len);

 out:
	freezero(sigblob, len);
	મુક્ત(sigtype);
	sshbuf_free(b);
	explicit_bzero(digest, કદ(digest));
	પાછા ret;
}

સ્થિર અચલ સંરચના sshkey_impl_funcs sshkey_rsa_funcs = {
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

અચલ સંરચના sshkey_impl sshkey_rsa_impl = {
	/* .name = */		"ssh-rsa",
	/* .shortname = */	"RSA",
	/* .sigalg = */		ખાલી,
	/* .type = */		ચાવી_RSA,
	/* .nid = */		0,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_rsa_funcs,
};

અચલ સંરચના sshkey_impl sshkey_rsa_cert_impl = {
	/* .name = */		"ssh-rsa-cert-v01@openssh.com",
	/* .shortname = */	"RSA-CERT",
	/* .sigalg = */		ખાલી,
	/* .type = */		ચાવી_RSA_CERT,
	/* .nid = */		0,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_rsa_funcs,
};

/* SHA2 signature algorithms */

અચલ સંરચના sshkey_impl sshkey_rsa_sha256_impl = {
	/* .name = */		"rsa-sha2-256",
	/* .shortname = */	"RSA",
	/* .sigalg = */		ખાલી,
	/* .type = */		ચાવી_RSA,
	/* .nid = */		0,
	/* .cert = */		0,
	/* .sigonly = */	1,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_rsa_funcs,
};

અચલ સંરચના sshkey_impl sshkey_rsa_sha512_impl = {
	/* .name = */		"rsa-sha2-512",
	/* .shortname = */	"RSA",
	/* .sigalg = */		ખાલી,
	/* .type = */		ચાવી_RSA,
	/* .nid = */		0,
	/* .cert = */		0,
	/* .sigonly = */	1,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_rsa_funcs,
};

અચલ સંરચના sshkey_impl sshkey_rsa_sha256_cert_impl = {
	/* .name = */		"rsa-sha2-256-cert-v01@openssh.com",
	/* .shortname = */	"RSA-CERT",
	/* .sigalg = */		"rsa-sha2-256",
	/* .type = */		ચાવી_RSA_CERT,
	/* .nid = */		0,
	/* .cert = */		1,
	/* .sigonly = */	1,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_rsa_funcs,
};

અચલ સંરચના sshkey_impl sshkey_rsa_sha512_cert_impl = {
	/* .name = */		"rsa-sha2-512-cert-v01@openssh.com",
	/* .shortname = */	"RSA-CERT",
	/* .sigalg = */		"rsa-sha2-512",
	/* .type = */		ચાવી_RSA_CERT,
	/* .nid = */		0,
	/* .cert = */		1,
	/* .sigonly = */	1,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_rsa_funcs,
};
#endif /* WITH_OPENSSL */
