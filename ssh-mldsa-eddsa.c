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

#ಅನ್ತರ್ಭಾವ "includes.h"

#ifdef USE_MLDSA

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <stdint.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>

#ಅನ್ತರ್ಭಾವ "crypto_api.h"
#ಅನ್ತರ್ಭಾವ "sshbuf.h"
#ಅನ್ತರ್ಭಾವ "ssherr.h"
#ಅನ್ತರ್ಭಾವ "digest.h"
#define SSHKEY_INTERNAL
#ಅನ್ತರ್ಭಾವ "sshkey.h"
#ಅನ್ತರ್ಭಾವ "log.h"

#define COMPOSITE_PREFIX "CompositeAlgorithmSignatures2025"
#define COMPOSITE_LABEL  "COMPSIG-MLDSA44-Ed25519-SHA512"
#define SSH_MLDSA44_ED25519_ALG_NAME   "ssh-mldsa44-ed25519"

/*
 * raw_* functions implement the draft-ietf-lamps-pq-composite-sigs-18
 * composite signature scheme. These are exposed (i.e. not static) so
 * we can test them separately in unittests/crypto.
 */

ಪೂರ್ಣಾಙ್ಕ
crypto_sign_mldsa44_ed25519_keygen(uint8_t pk[MLDSA44_ED25519_PK_SZ],
    uint8_t sk[MLDSA44_ED25519_SK_SZ])
{
	uint8_t mldsa_seed[MLDSA44_SEEDBYTES];
	uint8_t ed25519_seed[crypto_sign_ed25519_SEEDBYTES];
	ಪೂರ್ಣಾಙ್ಕ r;

	arc4random_buf(mldsa_seed, ಪರಿಮಾಣ(mldsa_seed));
	arc4random_buf(ed25519_seed, ಪರಿಮಾಣ(ed25519_seed));

	r = crypto_sign_mldsa44_ed25519_keygen_seeded(pk, sk, mldsa_seed,
	    ed25519_seed);
	explicit_bzero(mldsa_seed, ಪರಿಮಾಣ(mldsa_seed));
	explicit_bzero(ed25519_seed, ಪರಿಮಾಣ(ed25519_seed));
	ಪ್ರತ್ಯಾಗಮ r;
}

ಪೂರ್ಣಾಙ್ಕ
crypto_sign_mldsa44_ed25519_keygen_seeded(uint8_t pk[MLDSA44_ED25519_PK_SZ],
    uint8_t sk[MLDSA44_ED25519_SK_SZ],
    ಧ್ರುವ uint8_t mldsa_seed[MLDSA44_SEEDBYTES],
    ಧ್ರುವ uint8_t ed25519_seed[crypto_sign_ed25519_SEEDBYTES])
{
	uint8_t ed25519_pk[MLDSA44_SEEDBYTES];
	uint8_t ed25519_sk[crypto_sign_ed25519_SECRETKEYBYTES];
	uint8_t mldsa_sk[MLDSA44_SECRETKEYBYTES];
	ಪೂರ್ಣಾಙ್ಕ ret = -1;

	ಯದಿ (crypto_sign_mldsa44_keypair_seeded(pk, mldsa_sk, mldsa_seed) != 0)
		ಗಚ್ಛ out;
	ಯದಿ (crypto_sign_ed25519_seed_keypair(ed25519_pk, ed25519_sk,
	    ed25519_seed) != 0)
		ಗಚ್ಛ out;

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
	explicit_bzero(mldsa_sk, ಪರಿಮಾಣ(mldsa_sk));
	explicit_bzero(ed25519_sk, ಪರಿಮಾಣ(ed25519_sk));
	ಪ್ರತ್ಯಾಗಮ ret;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
construct_m_ಅವಿಭಾಜ್ಯ(uint8_t **m_primep, size_t *m_ಅವಿಭಾಜ್ಯ_lenp,
    ಧ್ರುವ uint8_t *ಸಂದೇಶ, size_t msglen,
    ಧ್ರುವ uint8_t *ctx, size_t ctxlen)
{
	ಪೂರ್ಣಾಙ್ಕ r;
	uint8_t hash[64];
	ಸಂರಚನಾ sshbuf *m_ಅವಿಭಾಜ್ಯ;

	*m_primep = ರಿಕ್ತ;
	*m_ಅವಿಭಾಜ್ಯ_lenp = 0;

	ಯದಿ (ctxlen > 255)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INVALID_ARGUMENT;
	ಯದಿ ((r = ssh_digest_memory(SSH_DIGEST_SHA512, ಸಂದೇಶ, msglen,
	    hash, ಪರಿಮಾಣ(hash))) != 0)
		ಪ್ರತ್ಯಾಗಮ r;
	ಯದಿ ((m_ಅವಿಭಾಜ್ಯ = sshbuf_new()) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_ALLOC_FAIL;
	ಯದಿ ((r = sshbuf_put(m_ಅವಿಭಾಜ್ಯ, COMPOSITE_PREFIX,
	    ಪರಿಮಾಣ(COMPOSITE_PREFIX) - 1)) != 0 ||
	    (r = sshbuf_put(m_ಅವಿಭಾಜ್ಯ, COMPOSITE_LABEL,
	    ಪರಿಮಾಣ(COMPOSITE_LABEL) - 1)) != 0 ||
	    (r = sshbuf_put_u8(m_ಅವಿಭಾಜ್ಯ, (uint8_t)ctxlen)) != 0 ||
	    (r = sshbuf_put(m_ಅವಿಭಾಜ್ಯ, ctx, ctxlen)) != 0 ||
	    (r = sshbuf_put(m_ಅವಿಭಾಜ್ಯ, hash, ಪರಿಮಾಣ(hash))) != 0) {
		sshbuf_free(m_ಅವಿಭಾಜ್ಯ);
		ಪ್ರತ್ಯಾಗಮ r;
	}
	ಯದಿ ((*m_primep = malloc(sshbuf_len(m_ಅವಿಭಾಜ್ಯ))) == ರಿಕ್ತ) {
		sshbuf_free(m_ಅವಿಭಾಜ್ಯ);
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_ALLOC_FAIL;
	}
	memcpy(*m_primep, sshbuf_ptr(m_ಅವಿಭಾಜ್ಯ), sshbuf_len(m_ಅವಿಭಾಜ್ಯ));
	*m_ಅವಿಭಾಜ್ಯ_lenp = sshbuf_len(m_ಅವಿಭಾಜ್ಯ);
	/* success */
	sshbuf_free(m_ಅವಿಭಾಜ್ಯ);
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಪೂರ್ಣಾಙ್ಕ
crypto_sign_mldsa44_ed25519_sign(uint8_t sig[MLDSA44_ED25519_SIG_SZ],
    ಧ್ರುವ uint8_t *ಸಂದೇಶ, size_t msglen,
    ಧ್ರುವ uint8_t *ctx, size_t ctxlen,
    ಧ್ರುವ uint8_t sk[MLDSA44_ED25519_SK_SZ])
{
	uint8_t *m_ಅವಿಭಾಜ್ಯ = ರಿಕ್ತ;
	size_t m_ಅವಿಭಾಜ್ಯ_len = 0;
	uint8_t mldsa_sk[MLDSA44_SECRETKEYBYTES];
	uint8_t mldsa_pk_dummy[MLDSA44_PUBLICKEYBYTES];
	uint8_t ed25519_pk[crypto_sign_ed25519_PUBLICKEYBYTES];
	uint8_t ed25519_sk[crypto_sign_ed25519_SECRETKEYBYTES];
	uint8_t mldsa_rnd[MLDSA44_SEEDBYTES];
	unsigned long long smlen;
	ಪೂರ್ಣಾಙ್ಕ r = -1;

	ಯದಿ (construct_m_ಅವಿಭಾಜ್ಯ(&m_ಅವಿಭಾಜ್ಯ, &m_ಅವಿಭಾಜ್ಯ_len, ಸಂದೇಶ, msglen,
	    ctx, ctxlen) != 0)
		ಪ್ರತ್ಯಾಗಮ -1;

	/* Expand ML-DSA key from seed */
	ಯದಿ (crypto_sign_mldsa44_keypair_seeded(mldsa_pk_dummy, mldsa_sk, sk) != 0)
		ಗಚ್ಛ out;

	/* Sign with ML-DSA */
	arc4random_buf(mldsa_rnd, ಪರಿಮಾಣ(mldsa_rnd));
	ಯದಿ (crypto_sign_mldsa44_seeded(sig, m_ಅವಿಭಾಜ್ಯ, m_ಅವಿಭಾಜ್ಯ_len,
	    (ಧ್ರುವ uint8_t *)COMPOSITE_LABEL, ಪರಿಮಾಣ(COMPOSITE_LABEL) - 1,
	    mldsa_sk, mldsa_rnd) != 0)
		ಗಚ್ಛ out;

	/* Expand Ed25519 key from seed */
	ಯದಿ (crypto_sign_ed25519_seed_keypair(ed25519_pk, ed25519_sk,
	    sk + MLDSA44_SEEDBYTES) != 0)
		ಗಚ್ಛ out;

	/* Sign with Ed25519 */
	ಯದಿ (crypto_sign_ed25519_detached(sig + MLDSA44_SIGBYTES, &smlen,
	    m_ಅವಿಭಾಜ್ಯ, m_ಅವಿಭಾಜ್ಯ_len, ed25519_sk) != 0 ||
	    smlen != crypto_sign_ed25519_BYTES)
		ಗಚ್ಛ out;

	r = 0;
 out:
	ಮುಕ್ತ(m_ಅವಿಭಾಜ್ಯ);
	explicit_bzero(mldsa_rnd, ಪರಿಮಾಣ(mldsa_rnd));
	explicit_bzero(mldsa_sk, ಪರಿಮಾಣ(mldsa_sk));
	explicit_bzero(ed25519_sk, ಪರಿಮಾಣ(ed25519_sk));
	ಪ್ರತ್ಯಾಗಮ r;
}

ಪೂರ್ಣಾಙ್ಕ
crypto_sign_mldsa44_ed25519_verify(ಧ್ರುವ uint8_t sig[MLDSA44_ED25519_SIG_SZ],
    ಧ್ರುವ uint8_t *ಸಂದೇಶ, size_t msglen,
    ಧ್ರುವ uint8_t *ctx, size_t ctxlen,
    ಧ್ರುವ uint8_t pk[MLDSA44_ED25519_PK_SZ])
{
	uint8_t *m_ಅವಿಭಾಜ್ಯ = ರಿಕ್ತ;
	size_t m_ಅವಿಭಾಜ್ಯ_len = 0;
	ಪೂರ್ಣಾಙ್ಕ r = -1;

	ಯದಿ (construct_m_ಅವಿಭಾಜ್ಯ(&m_ಅವಿಭಾಜ್ಯ, &m_ಅವಿಭಾಜ್ಯ_len, ಸಂದೇಶ, msglen,
	    ctx, ctxlen) != 0)
		ಪ್ರತ್ಯಾಗಮ -1;

	/* Verify ML-DSA */
	ಯದಿ (crypto_sign_mldsa44_verify(sig, m_ಅವಿಭಾಜ್ಯ, m_ಅವಿಭಾಜ್ಯ_len,
	    (ಧ್ರುವ uint8_t *)COMPOSITE_LABEL, ಪರಿಮಾಣ(COMPOSITE_LABEL) - 1,
	    pk) != 0)
		ಗಚ್ಛ out;

	/* Verify Ed25519 */
	ಯದಿ (crypto_sign_ed25519_verify_detached(sig + MLDSA44_SIGBYTES,
	    m_ಅವಿಭಾಜ್ಯ, m_ಅವಿಭಾಜ್ಯ_len, pk + MLDSA44_PUBLICKEYBYTES) != 0)
		ಗಚ್ಛ out;

	r = 0;
 out:
	ಮುಕ್ತ(m_ಅವಿಭಾಜ್ಯ);
	ಪ್ರತ್ಯಾಗಮ r;
}

/* sshkey integration */

ಸ್ಥಿರ ಶೂನ್ಯ
ssh_mldsa44_ed25519_cleanup(ಸಂರಚನಾ sshkey *k)
{
	freezero(k->mldsa_ed25519_pk, MLDSA44_ED25519_PK_SZ);
	freezero(k->mldsa_ed25519_sk, MLDSA44_ED25519_SK_SZ);
	k->mldsa_ed25519_pk = ರಿಕ್ತ;
	k->mldsa_ed25519_sk = ರಿಕ್ತ;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
ssh_mldsa44_ed25519_equal(ಧ್ರುವ ಸಂರಚನಾ sshkey *a, ಧ್ರುವ ಸಂರಚನಾ sshkey *b)
{
	ಯದಿ (a->mldsa_ed25519_pk == ರಿಕ್ತ || b->mldsa_ed25519_pk == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ 0;
	ಯದಿ (memcmp(a->mldsa_ed25519_pk, b->mldsa_ed25519_pk,
	    MLDSA44_ED25519_PK_SZ) != 0)
		ಪ್ರತ್ಯಾಗಮ 0;
	ಪ್ರತ್ಯಾಗಮ 1;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
ssh_mldsa44_ed25519_serialize_public(ಧ್ರುವ ಸಂರಚನಾ sshkey *ಕೀಲಿ, ಸಂರಚನಾ sshbuf *b,
    ಗಣನಾ sshkey_serialize_rep opts)
{
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ (ಕೀಲಿ->mldsa_ed25519_pk == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INVALID_ARGUMENT;
	ಯದಿ ((r = sshbuf_put_string(b, ಕೀಲಿ->mldsa_ed25519_pk,
	    MLDSA44_ED25519_PK_SZ)) != 0)
		ಪ್ರತ್ಯಾಗಮ r;

	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
ssh_mldsa44_ed25519_serialize_private(ಧ್ರುವ ಸಂರಚನಾ sshkey *ಕೀಲಿ, ಸಂರಚನಾ sshbuf *b,
    ಗಣನಾ sshkey_serialize_rep opts)
{
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ (ಕೀಲಿ->mldsa_ed25519_sk == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INVALID_ARGUMENT;
	ಯದಿ (!sshkey_is_cert(ಕೀಲಿ)) {
		ಯದಿ ((r = ssh_mldsa44_ed25519_serialize_public(ಕೀಲಿ,
		    b, opts)) != 0)
			ಪ್ರತ್ಯಾಗಮ r;
	}
	ಯದಿ ((r = sshbuf_put_string(b, ಕೀಲಿ->mldsa_ed25519_sk,
	    MLDSA44_ED25519_SK_SZ)) != 0)
		ಪ್ರತ್ಯಾಗಮ r;

	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
ssh_mldsa44_ed25519_deserialize_public(ಧ್ರುವ ವರ್ಣ *ktype, ಸಂರಚನಾ sshbuf *b,
    ಸಂರಚನಾ sshkey *ಕೀಲಿ)
{
	u_char *pk = ರಿಕ್ತ;
	size_t len = 0;
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ ((r = sshbuf_get_string(b, &pk, &len)) != 0)
		ಪ್ರತ್ಯಾಗಮ r;
	ಯದಿ (len != MLDSA44_ED25519_PK_SZ) {
		freezero(pk, len);
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INVALID_FORMAT;
	}
	ಕೀಲಿ->mldsa_ed25519_pk = pk;
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
ssh_mldsa44_ed25519_deserialize_private(ಧ್ರುವ ವರ್ಣ *ktype, ಸಂರಚನಾ sshbuf *b,
    ಸಂರಚನಾ sshkey *ಕೀಲಿ)
{
	ಪೂರ್ಣಾಙ್ಕ r;
	size_t sklen = 0;
	u_char *sk = ರಿಕ್ತ;

	ಯದಿ (!sshkey_is_cert(ಕೀಲಿ)) {
		ಯದಿ ((r = ssh_mldsa44_ed25519_deserialize_public(ktype,
		    b, ಕೀಲಿ)) != 0)
			ಪ್ರತ್ಯಾಗಮ r;
	}
	ಯದಿ ((r = sshbuf_get_string(b, &sk, &sklen)) != 0)
		ಗಚ್ಛ out;
	ಯದಿ (sklen != MLDSA44_ED25519_SK_SZ) {
		r = SSH_ERR_INVALID_FORMAT;
		ಗಚ್ಛ out;
	}
	ಕೀಲಿ->mldsa_ed25519_sk = sk;
	sk = ರಿಕ್ತ; /* transferred */
	r = 0;
 out:
	freezero(sk, sklen);
	ಪ್ರತ್ಯಾಗಮ r;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
ssh_mldsa44_ed25519_generate(ಸಂರಚನಾ sshkey *k, ಪೂರ್ಣಾಙ್ಕ bits)
{
	ssh_mldsa44_ed25519_cleanup(k);
	ಯದಿ ((k->mldsa_ed25519_pk = malloc(MLDSA44_ED25519_PK_SZ)) == ರಿಕ್ತ ||
	    (k->mldsa_ed25519_sk = malloc(MLDSA44_ED25519_SK_SZ)) == ರಿಕ್ತ) {
		ssh_mldsa44_ed25519_cleanup(k);
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_ALLOC_FAIL;
	}
	ಯದಿ (crypto_sign_mldsa44_ed25519_keygen(k->mldsa_ed25519_pk,
	    k->mldsa_ed25519_sk) != 0) {
		ssh_mldsa44_ed25519_cleanup(k);
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_CRYPTO_ERROR;
	}
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
ssh_mldsa44_ed25519_copy_public(ಧ್ರುವ ಸಂರಚನಾ sshkey *from, ಸಂರಚನಾ sshkey *to)
{
	ಯದಿ (from->mldsa_ed25519_pk == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INVALID_ARGUMENT;
	ಯದಿ ((to->mldsa_ed25519_pk = malloc(MLDSA44_ED25519_PK_SZ)) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_ALLOC_FAIL;
	memcpy(to->mldsa_ed25519_pk, from->mldsa_ed25519_pk,
	    MLDSA44_ED25519_PK_SZ);
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
ssh_mldsa44_ed25519_sign(ಸಂರಚನಾ sshkey *ಕೀಲಿ,
    u_char **sigp, size_t *lenp, ಧ್ರುವ u_char *data, size_t datalen,
    ಧ್ರುವ ವರ್ಣ *alg, ಧ್ರುವ ವರ್ಣ *sk_provider, ಧ್ರುವ ವರ್ಣ *sk_pin,
    u_int compat)
{
	u_char sig[MLDSA44_ED25519_SIG_SZ];
	ಸಂರಚನಾ sshbuf *b = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ r = SSH_ERR_INTERNAL_ERROR;

	ಯದಿ (lenp != ರಿಕ್ತ)
		*lenp = 0;
	ಯದಿ (sigp != ರಿಕ್ತ)
		*sigp = ರಿಕ್ತ;

	ಯದಿ (ಕೀಲಿ == ರಿಕ್ತ ||
	    sshkey_type_plain(ಕೀಲಿ->type) != ಕೀಲಿ_MLDSA44_ED25519 ||
	    ಕೀಲಿ->mldsa_ed25519_sk == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INVALID_ARGUMENT;

	ಯದಿ (crypto_sign_mldsa44_ed25519_sign(sig, data, datalen, ರಿಕ್ತ, 0,
	    ಕೀಲಿ->mldsa_ed25519_sk) != 0) {
		r = SSH_ERR_CRYPTO_ERROR;
		ಗಚ್ಛ out;
	}

	ಯದಿ ((b = sshbuf_new()) == ರಿಕ್ತ) {
		r = SSH_ERR_ALLOC_FAIL;
		ಗಚ್ಛ out;
	}
	ಯದಿ ((r = sshbuf_put_cstring(b, SSH_MLDSA44_ED25519_ALG_NAME)) != 0 ||
	    (r = sshbuf_put_string(b, sig, ಪರಿಮಾಣ(sig))) != 0)
		ಗಚ್ಛ out;

	ಯದಿ (sigp != ರಿಕ್ತ) {
		ಯದಿ ((*sigp = malloc(sshbuf_len(b))) == ರಿಕ್ತ) {
			r = SSH_ERR_ALLOC_FAIL;
			ಗಚ್ಛ out;
		}
		memcpy(*sigp, sshbuf_ptr(b), sshbuf_len(b));
	}
	ಯದಿ (lenp != ರಿಕ್ತ)
		*lenp = sshbuf_len(b);
	r = 0;
 out:
	sshbuf_free(b);
	explicit_bzero(sig, ಪರಿಮಾಣ(sig));
	ಪ್ರತ್ಯಾಗಮ r;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
ssh_mldsa44_ed25519_verify(ಧ್ರುವ ಸಂರಚನಾ sshkey *ಕೀಲಿ,
    ಧ್ರುವ u_char *sig, size_t siglen, ಧ್ರುವ u_char *data, size_t dlen,
    ಧ್ರುವ ವರ್ಣ *alg, u_int compat, ಸಂರಚನಾ sshkey_sig_details **detailsp)
{
	ಸಂರಚನಾ sshbuf *b = ರಿಕ್ತ;
	ವರ್ಣ *ktype = ರಿಕ್ತ;
	ಧ್ರುವ u_char *sigblob;
	size_t len;
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ (ಕೀಲಿ == ರಿಕ್ತ ||
	    sshkey_type_plain(ಕೀಲಿ->type) != ಕೀಲಿ_MLDSA44_ED25519 ||
	    ಕೀಲಿ->mldsa_ed25519_pk == ರಿಕ್ತ ||
	    sig == ರಿಕ್ತ || siglen == 0)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INVALID_ARGUMENT;

	ಯದಿ ((b = sshbuf_from(sig, siglen)) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_ALLOC_FAIL;
	ಯದಿ ((r = sshbuf_get_cstring(b, &ktype, ರಿಕ್ತ)) != 0 ||
	    (r = sshbuf_get_string_direct(b, &sigblob, &len)) != 0)
		ಗಚ್ಛ out;
	ಯದಿ (strcmp(SSH_MLDSA44_ED25519_ALG_NAME, ktype) != 0) {
		r = SSH_ERR_ಕೀಲಿ_TYPE_MISMATCH;
		ಗಚ್ಛ out;
	}
	ಯದಿ (sshbuf_len(b) != 0) {
		r = SSH_ERR_UNEXPECTED_TRAILING_DATA;
		ಗಚ್ಛ out;
	}
	ಯದಿ (len != MLDSA44_ED25519_SIG_SZ) {
		r = SSH_ERR_INVALID_FORMAT;
		ಗಚ್ಛ out;
	}

	ಯದಿ (crypto_sign_mldsa44_ed25519_verify(sigblob, data, dlen, ರಿಕ್ತ, 0,
	    ಕೀಲಿ->mldsa_ed25519_pk) != 0) {
		r = SSH_ERR_SIGNATURE_INVALID;
		ಗಚ್ಛ out;
	}

	r = 0;
 out:
	sshbuf_free(b);
	ಮುಕ್ತ(ktype);
	ಪ್ರತ್ಯಾಗಮ r;
}

ಧ್ರುವ ಸಂರಚನಾ sshkey_impl_funcs sshkey_mldsa44_ed25519_funcs = {
	/* .size = */		ರಿಕ್ತ,
	/* .alloc = */		ರಿಕ್ತ,
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

ಧ್ರುವ ಸಂರಚನಾ sshkey_impl sshkey_mldsa44_ed25519_impl = {
	/* .name = */		"ssh-mldsa44-ed25519",
	/* .shortname = */	"MLDSA44-ED25519",
	/* .sigalg = */		ರಿಕ್ತ,
	/* .type = */		ಕೀಲಿ_MLDSA44_ED25519,
	/* .nid = */		0,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	512, /* size of the private key */
	/* .funcs = */		&sshkey_mldsa44_ed25519_funcs,
};

ಧ್ರುವ ಸಂರಚನಾ sshkey_impl sshkey_mldsa44_ed25519_cert_impl = {
	/* .name = */		"ssh-mldsa44-ed25519-cert",
	/* .shortname = */	"MLDSA44-ED25519-CERT",
	/* .sigalg = */		ರಿಕ್ತ,
	/* .type = */		ಕೀಲಿ_MLDSA44_ED25519_CERT,
	/* .nid = */		0,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	512, /* size of the private key */
	/* .funcs = */		&sshkey_mldsa44_ed25519_funcs,
};
#endif /* USE_MLDSA */
