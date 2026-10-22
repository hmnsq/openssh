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

#ifdef WITH_OPENSSL
#ضمن "openbsd-compat/openssl-compat.h"

#ضمن <sys/types.h>

#ضمن <openssl/bn.h>
#ضمن <openssl/evp.h>

#ضمن <stdarg.h>
#ضمن <string.h>

#ضمن "sshbuf.h"
#ضمن "ssherr.h"
#define SSHKEY_INTERNAL
#ضمن "sshkey.h"
#ضمن "digest.h"

ساكن u_int
ssh_rsa_size(ثابت بنية sshkey *k)
{
	אם (k->pkey == عدم)
		החזר 0;
	החזר EVP_PKEY_bits(k->pkey);
}

ساكن صحيح
ssh_rsa_alloc(بنية sshkey *k)
{
	אם ((k->pkey = EVP_PKEY_new()) == عدم)
		החזר SSH_ERR_ALLOC_FAIL;
	החזר 0;
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
	אם (a->pkey == عدم || b->pkey == عدم)
		החזר 0;
	החזר EVP_PKEY_cmp(a->pkey, b->pkey) == 1;
}

ساكن صحيح
ssh_rsa_serialize_public(ثابت بنية sshkey *key, بنية sshbuf *b,
    تعداد sshkey_serialize_rep opts)
{
	صحيح r;
	ثابت BIGNUM *rsa_n, *rsa_e;
	ثابت RSA *rsa;

	אם (key->pkey == عدم)
		החזר SSH_ERR_INVALID_ARGUMENT;
	אם ((rsa = EVP_PKEY_get0_RSA(key->pkey)) == عدم)
		החזר SSH_ERR_LIBCRYPTO_ERROR;

	RSA_get0_key(rsa, &rsa_n, &rsa_e, عدم);
	אם ((r = sshbuf_put_bignum2(b, rsa_e)) != 0 ||
	    (r = sshbuf_put_bignum2(b, rsa_n)) != 0)
		החזר r;

	החזר 0;
}

ساكن صحيح
ssh_rsa_serialize_private(ثابت بنية sshkey *key, بنية sshbuf *b,
    تعداد sshkey_serialize_rep opts)
{
	صحيح r;
	ثابت BIGNUM *rsa_n, *rsa_e, *rsa_d, *rsa_iqmp, *rsa_p, *rsa_q;
	ثابت RSA *rsa;

	אם ((rsa = EVP_PKEY_get0_RSA(key->pkey)) == عدم)
		החזר SSH_ERR_LIBCRYPTO_ERROR;
	RSA_get0_key(rsa, &rsa_n, &rsa_e, &rsa_d);
	RSA_get0_factors(rsa, &rsa_p, &rsa_q);
	RSA_get0_crt_params(rsa, عدم, عدم, &rsa_iqmp);

	אם (!sshkey_is_cert(key)) {
		/* Note: can't reuse ssh_rsa_serialize_public: e, n vs. n, e */
		אם ((r = sshbuf_put_bignum2(b, rsa_n)) != 0 ||
		    (r = sshbuf_put_bignum2(b, rsa_e)) != 0)
			החזר r;
	}
	אם ((r = sshbuf_put_bignum2(b, rsa_d)) != 0 ||
	    (r = sshbuf_put_bignum2(b, rsa_iqmp)) != 0 ||
	    (r = sshbuf_put_bignum2(b, rsa_p)) != 0 ||
	    (r = sshbuf_put_bignum2(b, rsa_q)) != 0)
		החזר r;

	החזר 0;
}

ساكن صحيح
ssh_rsa_generate(بنية sshkey *k, صحيح bits)
{
	EVP_PKEY_CTX *ctx = عدم;
	EVP_PKEY *res = عدم;

	صحيح ret = SSH_ERR_INTERNAL_ERROR;

	אם (bits < SSH_RSA_MINIMUM_MODULUS_SIZE ||
	    bits > SSHBUF_MAX_BIGNUM * 8)
		החזר SSH_ERR_KEY_LENGTH;

	אם ((ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, عدم)) == عدم) {
		ret = SSH_ERR_ALLOC_FAIL;
		اذهب out;
	}
	אם (EVP_PKEY_keygen_init(ctx) <= 0) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		اذهب out;
	}
	אם (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) <= 0) {
		ret = SSH_ERR_KEY_LENGTH;
		اذهب out;
	}
	אם (EVP_PKEY_keygen(ctx, &res) <= 0 || res == عدم) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		اذهب out;
	}
	/* success */
	k->pkey = res;
	ret = 0;
 out:
	EVP_PKEY_CTX_free(ctx);
	החזר ret;
}

ساكن صحيح
ssh_rsa_copy_public(ثابت بنية sshkey *from, بنية sshkey *to)
{
	ثابت BIGNUM *rsa_n, *rsa_e;
	BIGNUM *rsa_n_dup = عدم, *rsa_e_dup = عدم;
	صحيح r = SSH_ERR_INTERNAL_ERROR;
	ثابت RSA *rsa_from;
	RSA *rsa_to = عدم;

	אם ((rsa_from = EVP_PKEY_get0_RSA(from->pkey)) == عدم ||
	    (rsa_to = RSA_new()) == عدم)
		החזר SSH_ERR_LIBCRYPTO_ERROR;

	RSA_get0_key(rsa_from, &rsa_n, &rsa_e, عدم);
	אם ((rsa_n_dup = BN_dup(rsa_n)) == عدم ||
	    (rsa_e_dup = BN_dup(rsa_e)) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب out;
	}
	אם (!RSA_set0_key(rsa_to, rsa_n_dup, rsa_e_dup, عدم)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		اذهب out;
	}
	rsa_n_dup = rsa_e_dup = عدم; /* transferred */

	אם (EVP_PKEY_set1_RSA(to->pkey, rsa_to) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		اذهب out;
	}
	/* success */
	r = 0;
 out:
	RSA_free(rsa_to);
	BN_clear_free(rsa_n_dup);
	BN_clear_free(rsa_e_dup);
	החזר r;
}

ساكن صحيح
ssh_rsa_deserialize_public(ثابت حرف *ktype, بنية sshbuf *b,
    بنية sshkey *key)
{
	صحيح ret = SSH_ERR_INTERNAL_ERROR;
	BIGNUM *rsa_n = عدم, *rsa_e = عدم;
	RSA *rsa = عدم;

	אם ((rsa = RSA_new()) == عدم)
		החזר SSH_ERR_LIBCRYPTO_ERROR;

	אם (sshbuf_get_bignum2(b, &rsa_e) != 0 ||
	    sshbuf_get_bignum2(b, &rsa_n) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		اذهب out;
	}
	אם (!RSA_set0_key(rsa, rsa_n, rsa_e, عدم)) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		اذهب out;
	}
	rsa_n = rsa_e = عدم; /* transferred */
	אם (EVP_PKEY_set1_RSA(key->pkey, rsa) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		اذهب out;
	}
	אם ((ret = sshkey_check_rsa_length(key, 0)) != 0)
		اذهب out;
#ifdef DEBUG_PK
	RSA_print_fp(stderr, rsa, 8);
#endif
	/* success */
	ret = 0;
 out:
	RSA_free(rsa);
	BN_clear_free(rsa_n);
	BN_clear_free(rsa_e);
	החזר ret;
}

ساكن صحيح
ssh_rsa_deserialize_private(ثابت حرف *ktype, بنية sshbuf *b,
    بنية sshkey *key)
{
	صحيح r;
	BIGNUM *rsa_n = عدم, *rsa_e = عدم, *rsa_d = عدم;
	BIGNUM *rsa_iqmp = عدم, *rsa_p = عدم, *rsa_q = عدم;
	BIGNUM *rsa_dmp1 = عدم, *rsa_dmq1 = عدم;
	RSA *rsa = عدم;

	אם (sshkey_is_cert(key)) {
		/* sshkey_private_deserialize already has pubkey from cert */
		אם ((rsa = EVP_PKEY_get1_RSA(key->pkey)) == عدم) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			اذهب out;
		}
	} אחרת {
		אם ((rsa = RSA_new()) == عدم) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			اذهب out;
		}
		/* Note: can't reuse ssh_rsa_deserialize_public: e,n vs. n,e */
		אם ((r = sshbuf_get_bignum2(b, &rsa_n)) != 0 ||
		    (r = sshbuf_get_bignum2(b, &rsa_e)) != 0)
			اذهب out;
		אם (!RSA_set0_key(rsa, rsa_n, rsa_e, عدم)) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			اذهب out;
		}
		rsa_n = rsa_e = عدم; /* transferred */
	}
	אם ((r = sshbuf_get_bignum2(b, &rsa_d)) != 0 ||
	    (r = sshbuf_get_bignum2(b, &rsa_iqmp)) != 0 ||
	    (r = sshbuf_get_bignum2(b, &rsa_p)) != 0 ||
	    (r = sshbuf_get_bignum2(b, &rsa_q)) != 0)
		اذهب out;
	אם ((r = ssh_rsa_complete_crt_parameters(rsa_d, rsa_p, rsa_q,
	    rsa_iqmp, &rsa_dmp1, &rsa_dmq1)) != 0)
		اذهب out;
	אם (!RSA_set0_key(rsa, عدم, عدم, rsa_d)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		اذهب out;
	}
	rsa_d = عدم; /* transferred */
	אם (!RSA_set0_factors(rsa, rsa_p, rsa_q)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		اذهب out;
	}
	rsa_p = rsa_q = عدم; /* transferred */
	אם (!RSA_set0_crt_params(rsa, rsa_dmp1, rsa_dmq1, rsa_iqmp)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		اذهب out;
	}
	rsa_dmp1 = rsa_dmq1 = rsa_iqmp = عدم;
	אם (RSA_blinding_on(rsa, عدم) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		اذهب out;
	}
	אם (EVP_PKEY_set1_RSA(key->pkey, rsa) != 1) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		اذهب out;
	}
	אם ((r = sshkey_check_rsa_length(key, 0)) != 0)
		اذهب out;
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
	החזר r;
}

ثابت حرف *
ssh_rsa_hash_alg_ident(صحيح hash_alg)
{
	بدل (hash_alg) {
	حالة SSH_DIGEST_SHA1:
		החזר "ssh-rsa";
	حالة SSH_DIGEST_SHA256:
		החזר "rsa-sha2-256";
	حالة SSH_DIGEST_SHA512:
		החזר "rsa-sha2-512";
	}
	החזר عدم;
}

/*
 * Returns the hash algorithm ID for a given algorithm identifier as used
 * inside the signature blob,
 */
ساكن صحيح
rsa_hash_id_from_ident(ثابت حرف *ident)
{
	אם (strcmp(ident, "ssh-rsa") == 0)
		החזר SSH_DIGEST_SHA1;
	אם (strcmp(ident, "rsa-sha2-256") == 0)
		החזר SSH_DIGEST_SHA256;
	אם (strcmp(ident, "rsa-sha2-512") == 0)
		החזר SSH_DIGEST_SHA512;
	החזר -1;
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

	אם ((r = rsa_hash_id_from_ident(alg)) != -1)
		החזר r;
	אם (strcmp(alg, "ssh-rsa-cert-v01@openssh.com") == 0)
		החזר SSH_DIGEST_SHA1;
	אם (strcmp(alg, "rsa-sha2-256-cert-v01@openssh.com") == 0)
		החזר SSH_DIGEST_SHA256;
	אם (strcmp(alg, "rsa-sha2-512-cert-v01@openssh.com") == 0)
		החזר SSH_DIGEST_SHA512;
	החזר -1;
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
	אם ((ctx = BN_CTX_new()) == عدم)
		החזר SSH_ERR_ALLOC_FAIL;
	אם ((aux = BN_new()) == عدم ||
	    (*rsa_dmq1 = BN_new()) == عدم ||
	    (*rsa_dmp1 = BN_new()) == عدم)
		החזר SSH_ERR_ALLOC_FAIL;
	אם ((d_consttime = BN_dup(rsa_d)) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب out;
	}
	BN_set_flags(aux, BN_FLG_CONSTTIME);
	BN_set_flags(d_consttime, BN_FLG_CONSTTIME);

	אם ((BN_sub(aux, rsa_q, BN_value_one()) == 0) ||
	    (BN_mod(*rsa_dmq1, d_consttime, aux, ctx) == 0) ||
	    (BN_sub(aux, rsa_p, BN_value_one()) == 0) ||
	    (BN_mod(*rsa_dmp1, d_consttime, aux, ctx) == 0)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		اذهب out;
	}
	/* success */
	r = 0;
 out:
	BN_clear_free(aux);
	BN_clear_free(d_consttime);
	BN_CTX_free(ctx);
	החזר r;
}

/* RSASSA-PKCS1-v1_5 (PKCS #1 v2.0 signature) with SHA1 */
ساكن صحيح
ssh_rsa_sign(بنية sshkey *key,
    u_char **sigp, size_t *lenp,
    ثابت u_char *data, size_t datalen,
    ثابت حرف *alg, ثابت حرف *sk_provider, ثابت حرف *sk_pin, u_int compat)
{
	u_char *sig = عدم;
	size_t diff, len = 0;
	صحيح slen = 0;
	صحيح hash_alg, ret = SSH_ERR_INTERNAL_ERROR;

	אם (lenp != عدم)
		*lenp = 0;
	אם (sigp != عدم)
		*sigp = عدم;

	אם (alg == عدم || strlen(alg) == 0)
		hash_alg = SSH_DIGEST_SHA1;
	אחרת
		hash_alg = ssh_rsa_hash_id_from_keyname(alg);

	אם (key == عدم || key->pkey == عدم || hash_alg == -1 ||
	    sshkey_type_plain(key->type) != KEY_RSA)
		החזר SSH_ERR_INVALID_ARGUMENT;
	slen = EVP_PKEY_size(key->pkey);
	אם (slen <= 0 || slen > SSHBUF_MAX_BIGNUM)
		החזר SSH_ERR_INVALID_ARGUMENT;
	אם (EVP_PKEY_bits(key->pkey) < SSH_RSA_MINIMUM_MODULUS_SIZE)
		החזר SSH_ERR_KEY_LENGTH;

	אם ((ret = sshkey_pkey_digest_sign(key->pkey, hash_alg, &sig, &len,
	    data, datalen)) < 0)
		اذهب out;
	אם (len < (size_t)slen) {
		diff = slen - len;
		memmove(sig + diff, sig, len);
		explicit_bzero(sig, diff);
	} אחרת אם (len > (size_t)slen) {
		ret = SSH_ERR_INTERNAL_ERROR;
		اذهب out;
	}
	אם ((ret = ssh_rsa_encode_store_sig(hash_alg, sig, slen,
	    sigp, lenp)) != 0)
		اذهب out;

	/* success */
	ret = 0;
 out:
	freezero(sig, slen);
	החזר ret;
}

صحيح
ssh_rsa_encode_store_sig(صحيح hash_alg, ثابت u_char *sig, size_t slen,
    u_char **sigp, size_t *lenp)
{
	بنية sshbuf *b = عدم;
	صحيح ret = SSH_ERR_INTERNAL_ERROR;
	size_t len;

	אם (lenp != عدم)
		*lenp = 0;
	אם (sigp != عدم)
		*sigp = عدم;

	/* Encode signature */
	אם ((b = sshbuf_new()) == عدم) {
		ret = SSH_ERR_ALLOC_FAIL;
		اذهب out;
	}
	אם ((ret = sshbuf_put_cstring(b,
	    ssh_rsa_hash_alg_ident(hash_alg))) != 0 ||
	    (ret = sshbuf_put_string(b, sig, slen)) != 0)
		اذهب out;
	len = sshbuf_len(b);

	/* Store signature */
	אם (sigp != عدم) {
		אם ((*sigp = malloc(len)) == عدم) {
			ret = SSH_ERR_ALLOC_FAIL;
			اذهب out;
		}
		memcpy(*sigp, sshbuf_ptr(b), len);
	}
	אם (lenp != عدم)
		*lenp = len;
	ret = 0;
 out:
	sshbuf_free(b);
	החזר ret;
}

ساكن صحيح
ssh_rsa_verify(ثابت بنية sshkey *key,
    ثابت u_char *sig, size_t siglen,
    ثابت u_char *data, size_t dlen, ثابت حرف *alg, u_int compat,
    بنية sshkey_sig_details **detailsp)
{
	حرف *sigtype = عدم;
	صحيح hash_alg, want_alg, ret = SSH_ERR_INTERNAL_ERROR;
	size_t len = 0, diff, modlen, rsasize;
	بنية sshbuf *b = عدم;
	u_char digest[SSH_DIGEST_MAX_LENGTH], *osigblob, *sigblob = عدم;

	אם (key == عدم || key->pkey == عدم ||
	    sshkey_type_plain(key->type) != KEY_RSA ||
	    sig == عدم || siglen == 0)
		החזר SSH_ERR_INVALID_ARGUMENT;
	אם (EVP_PKEY_bits(key->pkey) < SSH_RSA_MINIMUM_MODULUS_SIZE)
		החזר SSH_ERR_KEY_LENGTH;

	אם ((b = sshbuf_from(sig, siglen)) == عدم)
		החזר SSH_ERR_ALLOC_FAIL;
	אם (sshbuf_get_cstring(b, &sigtype, عدم) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		اذهب out;
	}
	אם ((hash_alg = rsa_hash_id_from_ident(sigtype)) == -1) {
		ret = SSH_ERR_KEY_TYPE_MISMATCH;
		اذهب out;
	}
	/*
	 * Allow ssh-rsa-cert-v01 certs to generate SHA2 signatures for
	 * legacy reasons, but otherwise the signature type should match.
	 */
	אם (alg != عدم && strcmp(alg, "ssh-rsa-cert-v01@openssh.com") != 0) {
		אם ((want_alg = ssh_rsa_hash_id_from_keyname(alg)) == -1) {
			ret = SSH_ERR_INVALID_ARGUMENT;
			اذهب out;
		}
		אם (hash_alg != want_alg) {
			ret = SSH_ERR_SIGNATURE_INVALID;
			اذهب out;
		}
	}
	אם (sshbuf_get_string(b, &sigblob, &len) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		اذهب out;
	}
	אם (sshbuf_len(b) != 0) {
		ret = SSH_ERR_UNEXPECTED_TRAILING_DATA;
		اذهب out;
	}
	/* RSA_verify expects a signature of RSA_size */
	modlen = EVP_PKEY_size(key->pkey);
	אם (len > modlen) {
		ret = SSH_ERR_KEY_BITS_MISMATCH;
		اذهب out;
	} אחרת אם (len < modlen) {
		diff = modlen - len;
		osigblob = sigblob;
		אם ((sigblob = realloc(sigblob, modlen)) == عدم) {
			sigblob = osigblob; /* put it back for clear/free */
			ret = SSH_ERR_ALLOC_FAIL;
			اذهب out;
		}
		memmove(sigblob + diff, sigblob, len);
		explicit_bzero(sigblob, diff);
		len = modlen;
	}

	rsasize = EVP_PKEY_size(key->pkey);
	אם (rsasize <= 0 || rsasize > SSHBUF_MAX_BIGNUM ||
	    len == 0 || len > rsasize) {
		ret = SSH_ERR_INVALID_ARGUMENT;
		اذهب out;
	}
	ret = sshkey_pkey_digest_verify(key->pkey, hash_alg, data, dlen,
	    sigblob, len);

 out:
	freezero(sigblob, len);
	حرر(sigtype);
	sshbuf_free(b);
	explicit_bzero(digest, حجم(digest));
	החזר ret;
}

ساكن ثابت بنية sshkey_impl_funcs sshkey_rsa_funcs = {
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

ثابت بنية sshkey_impl sshkey_rsa_impl = {
	/* .name = */		"ssh-rsa",
	/* .shortname = */	"RSA",
	/* .sigalg = */		عدم,
	/* .type = */		KEY_RSA,
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
	/* .type = */		KEY_RSA_CERT,
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
	/* .type = */		KEY_RSA,
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
	/* .type = */		KEY_RSA,
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
	/* .type = */		KEY_RSA_CERT,
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
	/* .type = */		KEY_RSA_CERT,
	/* .nid = */		0,
	/* .cert = */		1,
	/* .sigonly = */	1,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_rsa_funcs,
};
#endif /* WITH_OPENSSL */
