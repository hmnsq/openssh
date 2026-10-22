/* $OpenBSD: ssh-mldsa-eddsa.c,v 1.7 2026/10/01 04:17:39 djm Exp $ */
/*
 * Copyright (c) 2026 Damien Miller <djm@mindrot.org>
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

/* draft-miller-sshm-mldsa44-ed25519-composite-sigs-00 */

#അന്തര്ഭാവ "includes.h"

#ifdef USE_MLDSA

#അന്തര്ഭാവ <sys/types.h>
#അന്തര്ഭാവ <stdint.h>
#അന്തര്ഭാവ <string.h>
#അന്തര്ഭാവ <stdlib.h>

#അന്തര്ഭാവ "crypto_api.h"
#അന്തര്ഭാവ "sshbuf.h"
#അന്തര്ഭാവ "ssherr.h"
#അന്തര്ഭാവ "digest.h"
#define SSHKEY_INTERNAL
#അന്തര്ഭാവ "sshkey.h"
#അന്തര്ഭാവ "log.h"

#define COMPOSITE_PREFIX "CompositeAlgorithmSignatures2025"
#define COMPOSITE_LABEL  "COMPSIG-MLDSA44-Ed25519-SHA512"
#define SSH_MLDSA44_ED25519_ALG_NAME   "ssh-mldsa44-ed25519"

/*
 * raw_* functions implement the draft-ietf-lamps-pq-composite-sigs-18
 * composite signature scheme. These are exposed (i.e. not static) so
 * we can test them separately in unittests/crypto.
 */

പൂർണ്ണസംഖ്യ
crypto_sign_mldsa44_ed25519_keygen(uint8_t pk[MLDSA44_ED25519_PK_SZ],
    uint8_t sk[MLDSA44_ED25519_SK_SZ])
{
	uint8_t mldsa_seed[MLDSA44_SEEDBYTES];
	uint8_t ed25519_seed[crypto_sign_ed25519_SEEDBYTES];
	പൂർണ്ണസംഖ്യ r;

	arc4random_buf(mldsa_seed, വലുപ്പം(mldsa_seed));
	arc4random_buf(ed25519_seed, വലുപ്പം(ed25519_seed));

	r = crypto_sign_mldsa44_ed25519_keygen_seeded(pk, sk, mldsa_seed,
	    ed25519_seed);
	explicit_bzero(mldsa_seed, വലുപ്പം(mldsa_seed));
	explicit_bzero(ed25519_seed, വലുപ്പം(ed25519_seed));
	തിരികെ r;
}

പൂർണ്ണസംഖ്യ
crypto_sign_mldsa44_ed25519_keygen_seeded(uint8_t pk[MLDSA44_ED25519_PK_SZ],
    uint8_t sk[MLDSA44_ED25519_SK_SZ],
    സ്ഥിരം uint8_t mldsa_seed[MLDSA44_SEEDBYTES],
    സ്ഥിരം uint8_t ed25519_seed[crypto_sign_ed25519_SEEDBYTES])
{
	uint8_t ed25519_pk[MLDSA44_SEEDBYTES];
	uint8_t ed25519_sk[crypto_sign_ed25519_SECRETKEYBYTES];
	uint8_t mldsa_sk[MLDSA44_SECRETKEYBYTES];
	പൂർണ്ണസംഖ്യ ret = -1;

	എങ്കിൽ (crypto_sign_mldsa44_keypair_seeded(pk, mldsa_sk, mldsa_seed) != 0)
		പോകുക out;
	എങ്കിൽ (crypto_sign_ed25519_seed_keypair(ed25519_pk, ed25519_sk,
	    ed25519_seed) != 0)
		പോകുക out;

	/* Serialize PK: mldsaPK || ed25519PK */
	memcpy(pk + MLDSA44_PUBLICKEYBYTES, ed25519_pk,
	    crypto_sign_ed25519_SEEDBYTES);

	/* Serialize SK: mldsaSeed || ed25519Seed */
	memcpy(sk, mldsa_seed, MLDSA44_SEEDBYTES);
	memcpy(sk + MLDSA44_SEEDBYTES, ed25519_seed,
	    crypto_sign_ed25519_SEEDBYTES);

	/* success */
	ret = 0;
 out:
	explicit_bzero(mldsa_sk, വലുപ്പം(mldsa_sk));
	explicit_bzero(ed25519_sk, വലുപ്പം(ed25519_sk));
	തിരികെ ret;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
construct_m_അഭാജ്യം(uint8_t **m_primep, size_t *m_അഭാജ്യം_lenp,
    സ്ഥിരം uint8_t *സന്ദേശം, size_t msglen,
    സ്ഥിരം uint8_t *ctx, size_t ctxlen)
{
	പൂർണ്ണസംഖ്യ r;
	uint8_t hash[64];
	ഘടന sshbuf *m_അഭാജ്യം;

	*m_primep = ശൂന്യ;
	*m_അഭാജ്യം_lenp = 0;

	എങ്കിൽ (ctxlen > 255)
		തിരികെ SSH_ERR_INVALID_ARGUMENT;
	എങ്കിൽ ((r = ssh_digest_memory(SSH_DIGEST_SHA512, സന്ദേശം, msglen,
	    hash, വലുപ്പം(hash))) != 0)
		തിരികെ r;
	എങ്കിൽ ((m_അഭാജ്യം = sshbuf_new()) == ശൂന്യ)
		തിരികെ SSH_ERR_ALLOC_FAIL;
	എങ്കിൽ ((r = sshbuf_put(m_അഭാജ്യം, COMPOSITE_PREFIX,
	    വലുപ്പം(COMPOSITE_PREFIX) - 1)) != 0 ||
	    (r = sshbuf_put(m_അഭാജ്യം, COMPOSITE_LABEL,
	    വലുപ്പം(COMPOSITE_LABEL) - 1)) != 0 ||
	    (r = sshbuf_put_u8(m_അഭാജ്യം, (uint8_t)ctxlen)) != 0 ||
	    (r = sshbuf_put(m_അഭാജ്യം, ctx, ctxlen)) != 0 ||
	    (r = sshbuf_put(m_അഭാജ്യം, hash, വലുപ്പം(hash))) != 0) {
		sshbuf_free(m_അഭാജ്യം);
		തിരികെ r;
	}
	എങ്കിൽ ((*m_primep = malloc(sshbuf_len(m_അഭാജ്യം))) == ശൂന്യ) {
		sshbuf_free(m_അഭാജ്യം);
		തിരികെ SSH_ERR_ALLOC_FAIL;
	}
	memcpy(*m_primep, sshbuf_ptr(m_അഭാജ്യം), sshbuf_len(m_അഭാജ്യം));
	*m_അഭാജ്യം_lenp = sshbuf_len(m_അഭാജ്യം);
	/* success */
	sshbuf_free(m_അഭാജ്യം);
	തിരികെ 0;
}

പൂർണ്ണസംഖ്യ
crypto_sign_mldsa44_ed25519_sign(uint8_t sig[MLDSA44_ED25519_SIG_SZ],
    സ്ഥിരം uint8_t *സന്ദേശം, size_t msglen,
    സ്ഥിരം uint8_t *ctx, size_t ctxlen,
    സ്ഥിരം uint8_t sk[MLDSA44_ED25519_SK_SZ])
{
	uint8_t *m_അഭാജ്യം = ശൂന്യ;
	size_t m_അഭാജ്യം_len = 0;
	uint8_t mldsa_sk[MLDSA44_SECRETKEYBYTES];
	uint8_t mldsa_pk_dummy[MLDSA44_PUBLICKEYBYTES];
	uint8_t ed25519_pk[crypto_sign_ed25519_PUBLICKEYBYTES];
	uint8_t ed25519_sk[crypto_sign_ed25519_SECRETKEYBYTES];
	uint8_t mldsa_rnd[MLDSA44_SEEDBYTES];
	unsigned long long smlen;
	പൂർണ്ണസംഖ്യ r = -1;

	എങ്കിൽ (construct_m_അഭാജ്യം(&m_അഭാജ്യം, &m_അഭാജ്യം_len, സന്ദേശം, msglen,
	    ctx, ctxlen) != 0)
		തിരികെ -1;

	/* Expand ML-DSA key from seed */
	എങ്കിൽ (crypto_sign_mldsa44_keypair_seeded(mldsa_pk_dummy, mldsa_sk, sk) != 0)
		പോകുക out;

	/* Sign with ML-DSA */
	arc4random_buf(mldsa_rnd, വലുപ്പം(mldsa_rnd));
	എങ്കിൽ (crypto_sign_mldsa44_seeded(sig, m_അഭാജ്യം, m_അഭാജ്യം_len,
	    (സ്ഥിരം uint8_t *)COMPOSITE_LABEL, വലുപ്പം(COMPOSITE_LABEL) - 1,
	    mldsa_sk, mldsa_rnd) != 0)
		പോകുക out;

	/* Expand Ed25519 key from seed */
	എങ്കിൽ (crypto_sign_ed25519_seed_keypair(ed25519_pk, ed25519_sk,
	    sk + MLDSA44_SEEDBYTES) != 0)
		പോകുക out;

	/* Sign with Ed25519 */
	എങ്കിൽ (crypto_sign_ed25519_detached(sig + MLDSA44_SIGBYTES, &smlen,
	    m_അഭാജ്യം, m_അഭാജ്യം_len, ed25519_sk) != 0 ||
	    smlen != crypto_sign_ed25519_BYTES)
		പോകുക out;

	r = 0;
 out:
	സ്വതന്ത്രം(m_അഭാജ്യം);
	explicit_bzero(mldsa_rnd, വലുപ്പം(mldsa_rnd));
	explicit_bzero(mldsa_sk, വലുപ്പം(mldsa_sk));
	explicit_bzero(ed25519_sk, വലുപ്പം(ed25519_sk));
	തിരികെ r;
}

പൂർണ്ണസംഖ്യ
crypto_sign_mldsa44_ed25519_verify(സ്ഥിരം uint8_t sig[MLDSA44_ED25519_SIG_SZ],
    സ്ഥിരം uint8_t *സന്ദേശം, size_t msglen,
    സ്ഥിരം uint8_t *ctx, size_t ctxlen,
    സ്ഥിരം uint8_t pk[MLDSA44_ED25519_PK_SZ])
{
	uint8_t *m_അഭാജ്യം = ശൂന്യ;
	size_t m_അഭാജ്യം_len = 0;
	പൂർണ്ണസംഖ്യ r = -1;

	എങ്കിൽ (construct_m_അഭാജ്യം(&m_അഭാജ്യം, &m_അഭാജ്യം_len, സന്ദേശം, msglen,
	    ctx, ctxlen) != 0)
		തിരികെ -1;

	/* Verify ML-DSA */
	എങ്കിൽ (crypto_sign_mldsa44_verify(sig, m_അഭാജ്യം, m_അഭാജ്യം_len,
	    (സ്ഥിരം uint8_t *)COMPOSITE_LABEL, വലുപ്പം(COMPOSITE_LABEL) - 1,
	    pk) != 0)
		പോകുക out;

	/* Verify Ed25519 */
	എങ്കിൽ (crypto_sign_ed25519_verify_detached(sig + MLDSA44_SIGBYTES,
	    m_അഭാജ്യം, m_അഭാജ്യം_len, pk + MLDSA44_PUBLICKEYBYTES) != 0)
		പോകുക out;

	r = 0;
 out:
	സ്വതന്ത്രം(m_അഭാജ്യം);
	തിരികെ r;
}

/* sshkey integration */

സ്ഥിതം ശൂന്യം
ssh_mldsa44_ed25519_cleanup(ഘടന sshkey *k)
{
	freezero(k->mldsa_ed25519_pk, MLDSA44_ED25519_PK_SZ);
	freezero(k->mldsa_ed25519_sk, MLDSA44_ED25519_SK_SZ);
	k->mldsa_ed25519_pk = ശൂന്യ;
	k->mldsa_ed25519_sk = ശൂന്യ;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
ssh_mldsa44_ed25519_equal(സ്ഥിരം ഘടന sshkey *a, സ്ഥിരം ഘടന sshkey *b)
{
	എങ്കിൽ (a->mldsa_ed25519_pk == ശൂന്യ || b->mldsa_ed25519_pk == ശൂന്യ)
		തിരികെ 0;
	എങ്കിൽ (memcmp(a->mldsa_ed25519_pk, b->mldsa_ed25519_pk,
	    MLDSA44_ED25519_PK_SZ) != 0)
		തിരികെ 0;
	തിരികെ 1;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
ssh_mldsa44_ed25519_serialize_public(സ്ഥിരം ഘടന sshkey *താക്കോൽ, ഘടന sshbuf *b,
    എണ്ണൽ sshkey_serialize_rep opts)
{
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ (താക്കോൽ->mldsa_ed25519_pk == ശൂന്യ)
		തിരികെ SSH_ERR_INVALID_ARGUMENT;
	എങ്കിൽ ((r = sshbuf_put_string(b, താക്കോൽ->mldsa_ed25519_pk,
	    MLDSA44_ED25519_PK_SZ)) != 0)
		തിരികെ r;

	തിരികെ 0;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
ssh_mldsa44_ed25519_serialize_private(സ്ഥിരം ഘടന sshkey *താക്കോൽ, ഘടന sshbuf *b,
    എണ്ണൽ sshkey_serialize_rep opts)
{
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ (താക്കോൽ->mldsa_ed25519_sk == ശൂന്യ)
		തിരികെ SSH_ERR_INVALID_ARGUMENT;
	എങ്കിൽ (!sshkey_is_cert(താക്കോൽ)) {
		എങ്കിൽ ((r = ssh_mldsa44_ed25519_serialize_public(താക്കോൽ,
		    b, opts)) != 0)
			തിരികെ r;
	}
	എങ്കിൽ ((r = sshbuf_put_string(b, താക്കോൽ->mldsa_ed25519_sk,
	    MLDSA44_ED25519_SK_SZ)) != 0)
		തിരികെ r;

	തിരികെ 0;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
ssh_mldsa44_ed25519_deserialize_public(സ്ഥിരം അക്ഷരം *ktype, ഘടന sshbuf *b,
    ഘടന sshkey *താക്കോൽ)
{
	u_char *pk = ശൂന്യ;
	size_t len = 0;
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ ((r = sshbuf_get_string(b, &pk, &len)) != 0)
		തിരികെ r;
	എങ്കിൽ (len != MLDSA44_ED25519_PK_SZ) {
		freezero(pk, len);
		തിരികെ SSH_ERR_INVALID_FORMAT;
	}
	താക്കോൽ->mldsa_ed25519_pk = pk;
	തിരികെ 0;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
ssh_mldsa44_ed25519_deserialize_private(സ്ഥിരം അക്ഷരം *ktype, ഘടന sshbuf *b,
    ഘടന sshkey *താക്കോൽ)
{
	പൂർണ്ണസംഖ്യ r;
	size_t sklen = 0;
	u_char *sk = ശൂന്യ;

	എങ്കിൽ (!sshkey_is_cert(താക്കോൽ)) {
		എങ്കിൽ ((r = ssh_mldsa44_ed25519_deserialize_public(ktype,
		    b, താക്കോൽ)) != 0)
			തിരികെ r;
	}
	എങ്കിൽ ((r = sshbuf_get_string(b, &sk, &sklen)) != 0)
		പോകുക out;
	എങ്കിൽ (sklen != MLDSA44_ED25519_SK_SZ) {
		r = SSH_ERR_INVALID_FORMAT;
		പോകുക out;
	}
	താക്കോൽ->mldsa_ed25519_sk = sk;
	sk = ശൂന്യ; /* transferred */
	r = 0;
 out:
	freezero(sk, sklen);
	തിരികെ r;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
ssh_mldsa44_ed25519_generate(ഘടന sshkey *k, പൂർണ്ണസംഖ്യ bits)
{
	ssh_mldsa44_ed25519_cleanup(k);
	എങ്കിൽ ((k->mldsa_ed25519_pk = malloc(MLDSA44_ED25519_PK_SZ)) == ശൂന്യ ||
	    (k->mldsa_ed25519_sk = malloc(MLDSA44_ED25519_SK_SZ)) == ശൂന്യ) {
		ssh_mldsa44_ed25519_cleanup(k);
		തിരികെ SSH_ERR_ALLOC_FAIL;
	}
	എങ്കിൽ (crypto_sign_mldsa44_ed25519_keygen(k->mldsa_ed25519_pk,
	    k->mldsa_ed25519_sk) != 0) {
		ssh_mldsa44_ed25519_cleanup(k);
		തിരികെ SSH_ERR_CRYPTO_ERROR;
	}
	തിരികെ 0;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
ssh_mldsa44_ed25519_copy_public(സ്ഥിരം ഘടന sshkey *from, ഘടന sshkey *to)
{
	എങ്കിൽ (from->mldsa_ed25519_pk == ശൂന്യ)
		തിരികെ SSH_ERR_INVALID_ARGUMENT;
	എങ്കിൽ ((to->mldsa_ed25519_pk = malloc(MLDSA44_ED25519_PK_SZ)) == ശൂന്യ)
		തിരികെ SSH_ERR_ALLOC_FAIL;
	memcpy(to->mldsa_ed25519_pk, from->mldsa_ed25519_pk,
	    MLDSA44_ED25519_PK_SZ);
	തിരികെ 0;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
ssh_mldsa44_ed25519_sign(ഘടന sshkey *താക്കോൽ,
    u_char **sigp, size_t *lenp, സ്ഥിരം u_char *data, size_t datalen,
    സ്ഥിരം അക്ഷരം *alg, സ്ഥിരം അക്ഷരം *sk_provider, സ്ഥിരം അക്ഷരം *sk_pin,
    u_int compat)
{
	u_char sig[MLDSA44_ED25519_SIG_SZ];
	ഘടന sshbuf *b = ശൂന്യ;
	പൂർണ്ണസംഖ്യ r = SSH_ERR_INTERNAL_ERROR;

	എങ്കിൽ (lenp != ശൂന്യ)
		*lenp = 0;
	എങ്കിൽ (sigp != ശൂന്യ)
		*sigp = ശൂന്യ;

	എങ്കിൽ (താക്കോൽ == ശൂന്യ ||
	    sshkey_type_plain(താക്കോൽ->type) != താക്കോൽ_MLDSA44_ED25519 ||
	    താക്കോൽ->mldsa_ed25519_sk == ശൂന്യ)
		തിരികെ SSH_ERR_INVALID_ARGUMENT;

	എങ്കിൽ (crypto_sign_mldsa44_ed25519_sign(sig, data, datalen, ശൂന്യ, 0,
	    താക്കോൽ->mldsa_ed25519_sk) != 0) {
		r = SSH_ERR_CRYPTO_ERROR;
		പോകുക out;
	}

	എങ്കിൽ ((b = sshbuf_new()) == ശൂന്യ) {
		r = SSH_ERR_ALLOC_FAIL;
		പോകുക out;
	}
	എങ്കിൽ ((r = sshbuf_put_cstring(b, SSH_MLDSA44_ED25519_ALG_NAME)) != 0 ||
	    (r = sshbuf_put_string(b, sig, വലുപ്പം(sig))) != 0)
		പോകുക out;

	എങ്കിൽ (sigp != ശൂന്യ) {
		എങ്കിൽ ((*sigp = malloc(sshbuf_len(b))) == ശൂന്യ) {
			r = SSH_ERR_ALLOC_FAIL;
			പോകുക out;
		}
		memcpy(*sigp, sshbuf_ptr(b), sshbuf_len(b));
	}
	എങ്കിൽ (lenp != ശൂന്യ)
		*lenp = sshbuf_len(b);
	r = 0;
 out:
	sshbuf_free(b);
	explicit_bzero(sig, വലുപ്പം(sig));
	തിരികെ r;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
ssh_mldsa44_ed25519_verify(സ്ഥിരം ഘടന sshkey *താക്കോൽ,
    സ്ഥിരം u_char *sig, size_t siglen, സ്ഥിരം u_char *data, size_t dlen,
    സ്ഥിരം അക്ഷരം *alg, u_int compat, ഘടന sshkey_sig_details **detailsp)
{
	ഘടന sshbuf *b = ശൂന്യ;
	അക്ഷരം *ktype = ശൂന്യ;
	സ്ഥിരം u_char *sigblob;
	size_t len;
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ (താക്കോൽ == ശൂന്യ ||
	    sshkey_type_plain(താക്കോൽ->type) != താക്കോൽ_MLDSA44_ED25519 ||
	    താക്കോൽ->mldsa_ed25519_pk == ശൂന്യ ||
	    sig == ശൂന്യ || siglen == 0)
		തിരികെ SSH_ERR_INVALID_ARGUMENT;

	എങ്കിൽ ((b = sshbuf_from(sig, siglen)) == ശൂന്യ)
		തിരികെ SSH_ERR_ALLOC_FAIL;
	എങ്കിൽ ((r = sshbuf_get_cstring(b, &ktype, ശൂന്യ)) != 0 ||
	    (r = sshbuf_get_string_direct(b, &sigblob, &len)) != 0)
		പോകുക out;
	എങ്കിൽ (strcmp(SSH_MLDSA44_ED25519_ALG_NAME, ktype) != 0) {
		r = SSH_ERR_താക്കോൽ_TYPE_MISMATCH;
		പോകുക out;
	}
	എങ്കിൽ (sshbuf_len(b) != 0) {
		r = SSH_ERR_UNEXPECTED_TRAILING_DATA;
		പോകുക out;
	}
	എങ്കിൽ (len != MLDSA44_ED25519_SIG_SZ) {
		r = SSH_ERR_INVALID_FORMAT;
		പോകുക out;
	}

	എങ്കിൽ (crypto_sign_mldsa44_ed25519_verify(sigblob, data, dlen, ശൂന്യ, 0,
	    താക്കോൽ->mldsa_ed25519_pk) != 0) {
		r = SSH_ERR_SIGNATURE_INVALID;
		പോകുക out;
	}

	r = 0;
 out:
	sshbuf_free(b);
	സ്വതന്ത്രം(ktype);
	തിരികെ r;
}

സ്ഥിരം ഘടന sshkey_impl_funcs sshkey_mldsa44_ed25519_funcs = {
	/* .size = */		ശൂന്യ,
	/* .alloc = */		ശൂന്യ,
	/* .cleanup = */	ssh_mldsa44_ed25519_cleanup,
	/* .equal = */		ssh_mldsa44_ed25519_equal,
	/* .ssh_serialize_public = */ ssh_mldsa44_ed25519_serialize_public,
	/* .ssh_deserialize_public = */ ssh_mldsa44_ed25519_deserialize_public,
	/* .ssh_serialize_private = */ ssh_mldsa44_ed25519_serialize_private,
	/* .ssh_deserialize_private = */ ssh_mldsa44_ed25519_deserialize_private,
	/* .generate = */	ssh_mldsa44_ed25519_generate,
	/* .copy_public = */	ssh_mldsa44_ed25519_copy_public,
	/* .sign = */		ssh_mldsa44_ed25519_sign,
	/* .verify = */		ssh_mldsa44_ed25519_verify,
};

സ്ഥിരം ഘടന sshkey_impl sshkey_mldsa44_ed25519_impl = {
	/* .name = */		"ssh-mldsa44-ed25519",
	/* .shortname = */	"MLDSA44-ED25519",
	/* .sigalg = */		ശൂന്യ,
	/* .type = */		താക്കോൽ_MLDSA44_ED25519,
	/* .nid = */		0,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	512, /* size of the private key */
	/* .funcs = */		&sshkey_mldsa44_ed25519_funcs,
};

സ്ഥിരം ഘടന sshkey_impl sshkey_mldsa44_ed25519_cert_impl = {
	/* .name = */		"ssh-mldsa44-ed25519-cert",
	/* .shortname = */	"MLDSA44-ED25519-CERT",
	/* .sigalg = */		ശൂന്യ,
	/* .type = */		താക്കോൽ_MLDSA44_ED25519_CERT,
	/* .nid = */		0,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	512, /* size of the private key */
	/* .funcs = */		&sshkey_mldsa44_ed25519_funcs,
};
#endif /* USE_MLDSA */
