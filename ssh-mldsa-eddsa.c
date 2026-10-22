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

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ USE_MLDSA

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <stdint.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>

#ಅನ್ತರ್ಭಾವ "crypto_api.h"
#ಅನ್ತರ್ಭಾವ "sshbuf.h"
#ಅನ್ತರ್ಭಾವ "ssherr.h"
#ಅನ್ತರ್ಭಾವ "digest.h"
#ವ್ಯಾಖ್ಯಾನಿಸು SSHKEY_ಆಂತರಿಕ
#ಅನ್ತರ್ಭಾವ "sshkey.h"
#ಅನ್ತರ್ಭಾವ "log.h"

#ವ್ಯಾಖ್ಯಾನಿಸು ಸಂಯುಕ್ತ_ಪೂರ್ವಪ್ರತ್ಯಯ "CompositeAlgorithmSignatures2025"
#ವ್ಯಾಖ್ಯಾನಿಸು ಸಂಯುಕ್ತ_LABEL  "COMPSIG-MLDSA44-Ed25519-SHA512"
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_MLDSA44_ED25519_ALG_NAME   "ssh-mldsa44-ed25519"

/*
 * raw_* functions implement the draft-ietf-lamps-pq-composite-sigs-18
 * composite signature scheme. These are exposed (i.e. not static) so
 * we can test them separately in unittests/crypto.
 */

ಪೂರ್ಣಾಂಕ
crypto_sign_mldsa44_ed25519_keygen(uint8_t pk[MLDSA44_ED25519_PK_SZ],
    uint8_t sk[MLDSA44_ED25519_SK_SZ])
{
	uint8_t mldsa_ಬೀಜ[MLDSA44_SEEDBYTES];
	uint8_t ed25519_ಬೀಜ[crypto_sign_ed25519_SEEDBYTES];
	ಪೂರ್ಣಾಂಕ r;

	arc4random_buf(mldsa_ಬೀಜ, ಗಾತ್ರ(mldsa_ಬೀಜ));
	arc4random_buf(ed25519_ಬೀಜ, ಗಾತ್ರ(ed25519_ಬೀಜ));

	r = crypto_sign_mldsa44_ed25519_keygen_seeded(pk, sk, mldsa_ಬೀಜ,
	    ed25519_ಬೀಜ);
	explicit_bzero(mldsa_ಬೀಜ, ಗಾತ್ರ(mldsa_ಬೀಜ));
	explicit_bzero(ed25519_ಬೀಜ, ಗಾತ್ರ(ed25519_ಬೀಜ));
	ಹಿಂತಿರುಗಿ r;
}

ಪೂರ್ಣಾಂಕ
crypto_sign_mldsa44_ed25519_keygen_seeded(uint8_t pk[MLDSA44_ED25519_PK_SZ],
    uint8_t sk[MLDSA44_ED25519_SK_SZ],
    ಸ್ಥಿರಾಂಕ uint8_t mldsa_ಬೀಜ[MLDSA44_SEEDBYTES],
    ಸ್ಥಿರಾಂಕ uint8_t ed25519_ಬೀಜ[crypto_sign_ed25519_SEEDBYTES])
{
	uint8_t ed25519_pk[MLDSA44_SEEDBYTES];
	uint8_t ed25519_sk[crypto_sign_ed25519_SECRETKEYBYTES];
	uint8_t mldsa_sk[MLDSA44_SECRETKEYBYTES];
	ಪೂರ್ಣಾಂಕ ret = -1;

	ಆದರೆ (crypto_sign_mldsa44_keypair_seeded(pk, mldsa_sk, mldsa_ಬೀಜ) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
	ಆದರೆ (crypto_sign_ed25519_ಬೀಜ_keypair(ed25519_pk, ed25519_sk,
	    ed25519_ಬೀಜ) != 0)
		ಹೋಗು ಹೊರಹೋಗು;

	/* Serialize PK: mldsaPK || ed25519PK */
	ಸ್ಮರಣೆ_ನಕಲು(pk + MLDSA44_PUBLICKEYBYTES, ed25519_pk,
	    crypto_sign_ed25519_SEEDBYTES);

	/* Serialize SK: mldsaSeed || ed25519Seed */
	ಸ್ಮರಣೆ_ನಕಲು(sk, mldsa_ಬೀಜ, MLDSA44_SEEDBYTES);
	ಸ್ಮರಣೆ_ನಕಲು(sk + MLDSA44_SEEDBYTES, ed25519_ಬೀಜ,
	    crypto_sign_ed25519_SEEDBYTES);

	/* success */
	ret = 0;
 ಹೊರಹೋಗು:
	explicit_bzero(mldsa_sk, ಗಾತ್ರ(mldsa_sk));
	explicit_bzero(ed25519_sk, ಗಾತ್ರ(ed25519_sk));
	ಹಿಂತಿರುಗಿ ret;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
construct_m_ಅವಿಭಾಜ್ಯ(uint8_t **m_primep, ಗಾತ್ರ_t *m_ಅವಿಭಾಜ್ಯ_lenp,
    ಸ್ಥಿರಾಂಕ uint8_t *ಸಂದೇಶ, ಗಾತ್ರ_t msglen,
    ಸ್ಥಿರಾಂಕ uint8_t *ctx, ಗಾತ್ರ_t ctxlen)
{
	ಪೂರ್ಣಾಂಕ r;
	uint8_t hash[64];
	ರಚನೆ sshbuf *m_ಅವಿಭಾಜ್ಯ;

	*m_primep = ಖಾಲಿ;
	*m_ಅವಿಭಾಜ್ಯ_lenp = 0;

	ಆದರೆ (ctxlen > 255)
		ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_ವಾದ;
	ಆದರೆ ((r = ssh_digest_ಸ್ಮರಣೆ(SSH_DIGEST_SHA512, ಸಂದೇಶ, msglen,
	    hash, ಗಾತ್ರ(hash))) != 0)
		ಹಿಂತಿರುಗಿ r;
	ಆದರೆ ((m_ಅವಿಭಾಜ್ಯ = sshbuf_new()) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ SSH_ERR_ALLOC_FAIL;
	ಆದರೆ ((r = sshbuf_put(m_ಅವಿಭಾಜ್ಯ, ಸಂಯುಕ್ತ_ಪೂರ್ವಪ್ರತ್ಯಯ,
	    ಗಾತ್ರ(ಸಂಯುಕ್ತ_ಪೂರ್ವಪ್ರತ್ಯಯ) - 1)) != 0 ||
	    (r = sshbuf_put(m_ಅವಿಭಾಜ್ಯ, ಸಂಯುಕ್ತ_LABEL,
	    ಗಾತ್ರ(ಸಂಯುಕ್ತ_LABEL) - 1)) != 0 ||
	    (r = sshbuf_put_u8(m_ಅವಿಭಾಜ್ಯ, (uint8_t)ctxlen)) != 0 ||
	    (r = sshbuf_put(m_ಅವಿಭಾಜ್ಯ, ctx, ctxlen)) != 0 ||
	    (r = sshbuf_put(m_ಅವಿಭಾಜ್ಯ, hash, ಗಾತ್ರ(hash))) != 0) {
		sshbuf_free(m_ಅವಿಭಾಜ್ಯ);
		ಹಿಂತಿರುಗಿ r;
	}
	ಆದರೆ ((*m_primep = ಸ್ಮರಣೆ_ಕೊಡು(sshbuf_len(m_ಅವಿಭಾಜ್ಯ))) == ಖಾಲಿ) {
		sshbuf_free(m_ಅವಿಭಾಜ್ಯ);
		ಹಿಂತಿರುಗಿ SSH_ERR_ALLOC_FAIL;
	}
	ಸ್ಮರಣೆ_ನಕಲು(*m_primep, sshbuf_ptr(m_ಅವಿಭಾಜ್ಯ), sshbuf_len(m_ಅವಿಭಾಜ್ಯ));
	*m_ಅವಿಭಾಜ್ಯ_lenp = sshbuf_len(m_ಅವಿಭಾಜ್ಯ);
	/* success */
	sshbuf_free(m_ಅವಿಭಾಜ್ಯ);
	ಹಿಂತಿರುಗಿ 0;
}

ಪೂರ್ಣಾಂಕ
crypto_sign_mldsa44_ed25519_sign(uint8_t sig[MLDSA44_ED25519_SIG_SZ],
    ಸ್ಥಿರಾಂಕ uint8_t *ಸಂದೇಶ, ಗಾತ್ರ_t msglen,
    ಸ್ಥಿರಾಂಕ uint8_t *ctx, ಗಾತ್ರ_t ctxlen,
    ಸ್ಥಿರಾಂಕ uint8_t sk[MLDSA44_ED25519_SK_SZ])
{
	uint8_t *m_ಅವಿಭಾಜ್ಯ = ಖಾಲಿ;
	ಗಾತ್ರ_t m_ಅವಿಭಾಜ್ಯ_len = 0;
	uint8_t mldsa_sk[MLDSA44_SECRETKEYBYTES];
	uint8_t mldsa_pk_dummy[MLDSA44_PUBLICKEYBYTES];
	uint8_t ed25519_pk[crypto_sign_ed25519_PUBLICKEYBYTES];
	uint8_t ed25519_sk[crypto_sign_ed25519_SECRETKEYBYTES];
	uint8_t mldsa_rnd[MLDSA44_SEEDBYTES];
	ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ ದೀರ್ಘ smlen;
	ಪೂರ್ಣಾಂಕ r = -1;

	ಆದರೆ (construct_m_ಅವಿಭಾಜ್ಯ(&m_ಅವಿಭಾಜ್ಯ, &m_ಅವಿಭಾಜ್ಯ_len, ಸಂದೇಶ, msglen,
	    ctx, ctxlen) != 0)
		ಹಿಂತಿರುಗಿ -1;

	/* Expand ML-DSA key from seed */
	ಆದರೆ (crypto_sign_mldsa44_keypair_seeded(mldsa_pk_dummy, mldsa_sk, sk) != 0)
		ಹೋಗು ಹೊರಹೋಗು;

	/* Sign with ML-DSA */
	arc4random_buf(mldsa_rnd, ಗಾತ್ರ(mldsa_rnd));
	ಆದರೆ (crypto_sign_mldsa44_seeded(sig, m_ಅವಿಭಾಜ್ಯ, m_ಅವಿಭಾಜ್ಯ_len,
	    (ಸ್ಥಿರಾಂಕ uint8_t *)ಸಂಯುಕ್ತ_LABEL, ಗಾತ್ರ(ಸಂಯುಕ್ತ_LABEL) - 1,
	    mldsa_sk, mldsa_rnd) != 0)
		ಹೋಗು ಹೊರಹೋಗು;

	/* Expand Ed25519 key from seed */
	ಆದರೆ (crypto_sign_ed25519_ಬೀಜ_keypair(ed25519_pk, ed25519_sk,
	    sk + MLDSA44_SEEDBYTES) != 0)
		ಹೋಗು ಹೊರಹೋಗು;

	/* Sign with Ed25519 */
	ಆದರೆ (crypto_sign_ed25519_detached(sig + MLDSA44_SIGBYTES, &smlen,
	    m_ಅವಿಭಾಜ್ಯ, m_ಅವಿಭಾಜ್ಯ_len, ed25519_sk) != 0 ||
	    smlen != crypto_sign_ed25519_ಬೈಟುಗಳು)
		ಹೋಗು ಹೊರಹೋಗು;

	r = 0;
 ಹೊರಹೋಗು:
	ಬಿಡುಗಡೆ(m_ಅವಿಭಾಜ್ಯ);
	explicit_bzero(mldsa_rnd, ಗಾತ್ರ(mldsa_rnd));
	explicit_bzero(mldsa_sk, ಗಾತ್ರ(mldsa_sk));
	explicit_bzero(ed25519_sk, ಗಾತ್ರ(ed25519_sk));
	ಹಿಂತಿರುಗಿ r;
}

ಪೂರ್ಣಾಂಕ
crypto_sign_mldsa44_ed25519_verify(ಸ್ಥಿರಾಂಕ uint8_t sig[MLDSA44_ED25519_SIG_SZ],
    ಸ್ಥಿರಾಂಕ uint8_t *ಸಂದೇಶ, ಗಾತ್ರ_t msglen,
    ಸ್ಥಿರಾಂಕ uint8_t *ctx, ಗಾತ್ರ_t ctxlen,
    ಸ್ಥಿರಾಂಕ uint8_t pk[MLDSA44_ED25519_PK_SZ])
{
	uint8_t *m_ಅವಿಭಾಜ್ಯ = ಖಾಲಿ;
	ಗಾತ್ರ_t m_ಅವಿಭಾಜ್ಯ_len = 0;
	ಪೂರ್ಣಾಂಕ r = -1;

	ಆದರೆ (construct_m_ಅವಿಭಾಜ್ಯ(&m_ಅವಿಭಾಜ್ಯ, &m_ಅವಿಭಾಜ್ಯ_len, ಸಂದೇಶ, msglen,
	    ctx, ctxlen) != 0)
		ಹಿಂತಿರುಗಿ -1;

	/* Verify ML-DSA */
	ಆದರೆ (crypto_sign_mldsa44_verify(sig, m_ಅವಿಭಾಜ್ಯ, m_ಅವಿಭಾಜ್ಯ_len,
	    (ಸ್ಥಿರಾಂಕ uint8_t *)ಸಂಯುಕ್ತ_LABEL, ಗಾತ್ರ(ಸಂಯುಕ್ತ_LABEL) - 1,
	    pk) != 0)
		ಹೋಗು ಹೊರಹೋಗು;

	/* Verify Ed25519 */
	ಆದರೆ (crypto_sign_ed25519_verify_detached(sig + MLDSA44_SIGBYTES,
	    m_ಅವಿಭಾಜ್ಯ, m_ಅವಿಭಾಜ್ಯ_len, pk + MLDSA44_PUBLICKEYBYTES) != 0)
		ಹೋಗು ಹೊರಹೋಗು;

	r = 0;
 ಹೊರಹೋಗು:
	ಬಿಡುಗಡೆ(m_ಅವಿಭಾಜ್ಯ);
	ಹಿಂತಿರುಗಿ r;
}

/* sshkey integration */

ಸ್ಥಿರ ಶೂನ್ಯ
ssh_mldsa44_ed25519_cleanup(ರಚನೆ sshkey *k)
{
	freezero(k->mldsa_ed25519_pk, MLDSA44_ED25519_PK_SZ);
	freezero(k->mldsa_ed25519_sk, MLDSA44_ED25519_SK_SZ);
	k->mldsa_ed25519_pk = ಖಾಲಿ;
	k->mldsa_ed25519_sk = ಖಾಲಿ;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ssh_mldsa44_ed25519_equal(ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *a, ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *b)
{
	ಆದರೆ (a->mldsa_ed25519_pk == ಖಾಲಿ || b->mldsa_ed25519_pk == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ 0;
	ಆದರೆ (memcmp(a->mldsa_ed25519_pk, b->mldsa_ed25519_pk,
	    MLDSA44_ED25519_PK_SZ) != 0)
		ಹಿಂತಿರುಗಿ 0;
	ಹಿಂತಿರುಗಿ 1;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ssh_mldsa44_ed25519_serialize_ಬಹಿರಂಗ(ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *ಕೀಲಿ, ರಚನೆ sshbuf *b,
    ಎಣಿಕೆ sshkey_serialize_rep opts)
{
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ (ಕೀಲಿ->mldsa_ed25519_pk == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_ವಾದ;
	ಆದರೆ ((r = sshbuf_put_string(b, ಕೀಲಿ->mldsa_ed25519_pk,
	    MLDSA44_ED25519_PK_SZ)) != 0)
		ಹಿಂತಿರುಗಿ r;

	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ssh_mldsa44_ed25519_serialize_ಖಾಸಗಿ(ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *ಕೀಲಿ, ರಚನೆ sshbuf *b,
    ಎಣಿಕೆ sshkey_serialize_rep opts)
{
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ (ಕೀಲಿ->mldsa_ed25519_sk == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_ವಾದ;
	ಆದರೆ (!sshkey_is_cert(ಕೀಲಿ)) {
		ಆದರೆ ((r = ssh_mldsa44_ed25519_serialize_ಬಹಿರಂಗ(ಕೀಲಿ,
		    b, opts)) != 0)
			ಹಿಂತಿರುಗಿ r;
	}
	ಆದರೆ ((r = sshbuf_put_string(b, ಕೀಲಿ->mldsa_ed25519_sk,
	    MLDSA44_ED25519_SK_SZ)) != 0)
		ಹಿಂತಿರುಗಿ r;

	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ssh_mldsa44_ed25519_deserialize_ಬಹಿರಂಗ(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ktype, ರಚನೆ sshbuf *b,
    ರಚನೆ sshkey *ಕೀಲಿ)
{
	u_char *pk = ಖಾಲಿ;
	ಗಾತ್ರ_t len = 0;
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ ((r = sshbuf_get_string(b, &pk, &len)) != 0)
		ಹಿಂತಿರುಗಿ r;
	ಆದರೆ (len != MLDSA44_ED25519_PK_SZ) {
		freezero(pk, len);
		ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_FORMAT;
	}
	ಕೀಲಿ->mldsa_ed25519_pk = pk;
	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ssh_mldsa44_ed25519_deserialize_ಖಾಸಗಿ(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ktype, ರಚನೆ sshbuf *b,
    ರಚನೆ sshkey *ಕೀಲಿ)
{
	ಪೂರ್ಣಾಂಕ r;
	ಗಾತ್ರ_t sklen = 0;
	u_char *sk = ಖಾಲಿ;

	ಆದರೆ (!sshkey_is_cert(ಕೀಲಿ)) {
		ಆದರೆ ((r = ssh_mldsa44_ed25519_deserialize_ಬಹಿರಂಗ(ktype,
		    b, ಕೀಲಿ)) != 0)
			ಹಿಂತಿರುಗಿ r;
	}
	ಆದರೆ ((r = sshbuf_get_string(b, &sk, &sklen)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
	ಆದರೆ (sklen != MLDSA44_ED25519_SK_SZ) {
		r = SSH_ERR_INVALID_FORMAT;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಕೀಲಿ->mldsa_ed25519_sk = sk;
	sk = ಖಾಲಿ; /* transferred */
	r = 0;
 ಹೊರಹೋಗು:
	freezero(sk, sklen);
	ಹಿಂತಿರುಗಿ r;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ssh_mldsa44_ed25519_generate(ರಚನೆ sshkey *k, ಪೂರ್ಣಾಂಕ ಬಿಟ್ಟುಗಳು)
{
	ssh_mldsa44_ed25519_cleanup(k);
	ಆದರೆ ((k->mldsa_ed25519_pk = ಸ್ಮರಣೆ_ಕೊಡು(MLDSA44_ED25519_PK_SZ)) == ಖಾಲಿ ||
	    (k->mldsa_ed25519_sk = ಸ್ಮರಣೆ_ಕೊಡು(MLDSA44_ED25519_SK_SZ)) == ಖಾಲಿ) {
		ssh_mldsa44_ed25519_cleanup(k);
		ಹಿಂತಿರುಗಿ SSH_ERR_ALLOC_FAIL;
	}
	ಆದರೆ (crypto_sign_mldsa44_ed25519_keygen(k->mldsa_ed25519_pk,
	    k->mldsa_ed25519_sk) != 0) {
		ssh_mldsa44_ed25519_cleanup(k);
		ಹಿಂತಿರುಗಿ SSH_ERR_CRYPTO_ERROR;
	}
	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ssh_mldsa44_ed25519_copy_ಬಹಿರಂಗ(ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *from, ರಚನೆ sshkey *ಗಮ್ಯ)
{
	ಆದರೆ (from->mldsa_ed25519_pk == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_ವಾದ;
	ಆದರೆ ((ಗಮ್ಯ->mldsa_ed25519_pk = ಸ್ಮರಣೆ_ಕೊಡು(MLDSA44_ED25519_PK_SZ)) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ SSH_ERR_ALLOC_FAIL;
	ಸ್ಮರಣೆ_ನಕಲು(ಗಮ್ಯ->mldsa_ed25519_pk, from->mldsa_ed25519_pk,
	    MLDSA44_ED25519_PK_SZ);
	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ssh_mldsa44_ed25519_sign(ರಚನೆ sshkey *ಕೀಲಿ,
    u_char **sigp, ಗಾತ್ರ_t *lenp, ಸ್ಥಿರಾಂಕ u_char *ದತ್ತಾಂಶ, ಗಾತ್ರ_t datalen,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *alg, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *sk_provider, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *sk_pin,
    u_int compat)
{
	u_char sig[MLDSA44_ED25519_SIG_SZ];
	ರಚನೆ sshbuf *b = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ r = SSH_ERR_ಆಂತರಿಕ_ERROR;

	ಆದರೆ (lenp != ಖಾಲಿ)
		*lenp = 0;
	ಆದರೆ (sigp != ಖಾಲಿ)
		*sigp = ಖಾಲಿ;

	ಆದರೆ (ಕೀಲಿ == ಖಾಲಿ ||
	    sshkey_type_plain(ಕೀಲಿ->type) != ಕೀಲಿ_MLDSA44_ED25519 ||
	    ಕೀಲಿ->mldsa_ed25519_sk == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_ವಾದ;

	ಆದರೆ (crypto_sign_mldsa44_ed25519_sign(sig, ದತ್ತಾಂಶ, datalen, ಖಾಲಿ, 0,
	    ಕೀಲಿ->mldsa_ed25519_sk) != 0) {
		r = SSH_ERR_CRYPTO_ERROR;
		ಹೋಗು ಹೊರಹೋಗು;
	}

	ಆದರೆ ((b = sshbuf_new()) == ಖಾಲಿ) {
		r = SSH_ERR_ALLOC_FAIL;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((r = sshbuf_put_cstring(b, SSH_MLDSA44_ED25519_ALG_NAME)) != 0 ||
	    (r = sshbuf_put_string(b, sig, ಗಾತ್ರ(sig))) != 0)
		ಹೋಗು ಹೊರಹೋಗು;

	ಆದರೆ (sigp != ಖಾಲಿ) {
		ಆದರೆ ((*sigp = ಸ್ಮರಣೆ_ಕೊಡು(sshbuf_len(b))) == ಖಾಲಿ) {
			r = SSH_ERR_ALLOC_FAIL;
			ಹೋಗು ಹೊರಹೋಗು;
		}
		ಸ್ಮರಣೆ_ನಕಲು(*sigp, sshbuf_ptr(b), sshbuf_len(b));
	}
	ಆದರೆ (lenp != ಖಾಲಿ)
		*lenp = sshbuf_len(b);
	r = 0;
 ಹೊರಹೋಗು:
	sshbuf_free(b);
	explicit_bzero(sig, ಗಾತ್ರ(sig));
	ಹಿಂತಿರುಗಿ r;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
ssh_mldsa44_ed25519_verify(ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *ಕೀಲಿ,
    ಸ್ಥಿರಾಂಕ u_char *sig, ಗಾತ್ರ_t siglen, ಸ್ಥಿರಾಂಕ u_char *ದತ್ತಾಂಶ, ಗಾತ್ರ_t dlen,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *alg, u_int compat, ರಚನೆ sshkey_sig_details **detailsp)
{
	ರಚನೆ sshbuf *b = ಖಾಲಿ;
	ಅಕ್ಷರ *ktype = ಖಾಲಿ;
	ಸ್ಥಿರಾಂಕ u_char *sigblob;
	ಗಾತ್ರ_t len;
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ (ಕೀಲಿ == ಖಾಲಿ ||
	    sshkey_type_plain(ಕೀಲಿ->type) != ಕೀಲಿ_MLDSA44_ED25519 ||
	    ಕೀಲಿ->mldsa_ed25519_pk == ಖಾಲಿ ||
	    sig == ಖಾಲಿ || siglen == 0)
		ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_ವಾದ;

	ಆದರೆ ((b = sshbuf_from(sig, siglen)) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ SSH_ERR_ALLOC_FAIL;
	ಆದರೆ ((r = sshbuf_get_cstring(b, &ktype, ಖಾಲಿ)) != 0 ||
	    (r = sshbuf_get_string_ನೇರ(b, &sigblob, &len)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
	ಆದರೆ (strcmp(SSH_MLDSA44_ED25519_ALG_NAME, ktype) != 0) {
		r = SSH_ERR_ಕೀಲಿ_TYPE_MISMATCH;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ (sshbuf_len(b) != 0) {
		r = SSH_ERR_UNEXPECTED_TRAILING_ದತ್ತಾಂಶ;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ (len != MLDSA44_ED25519_SIG_SZ) {
		r = SSH_ERR_INVALID_FORMAT;
		ಹೋಗು ಹೊರಹೋಗು;
	}

	ಆದರೆ (crypto_sign_mldsa44_ed25519_verify(sigblob, ದತ್ತಾಂಶ, dlen, ಖಾಲಿ, 0,
	    ಕೀಲಿ->mldsa_ed25519_pk) != 0) {
		r = SSH_ERR_SIGNATURE_INVALID;
		ಹೋಗು ಹೊರಹೋಗು;
	}

	r = 0;
 ಹೊರಹೋಗು:
	sshbuf_free(b);
	ಬಿಡುಗಡೆ(ktype);
	ಹಿಂತಿರುಗಿ r;
}

ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey_impl_funcs sshkey_mldsa44_ed25519_funcs = {
	/* .size = */		ಖಾಲಿ,
	/* .alloc = */		ಖಾಲಿ,
	/* .cleanup = */	ssh_mldsa44_ed25519_cleanup,
	/* .equal = */		ssh_mldsa44_ed25519_equal,
	/* .ssh_serialize_public = */ ssh_mldsa44_ed25519_serialize_ಬಹಿರಂಗ,
	/* .ssh_deserialize_public = */ ssh_mldsa44_ed25519_deserialize_ಬಹಿರಂಗ,
	/* .ssh_serialize_private = */ ssh_mldsa44_ed25519_serialize_ಖಾಸಗಿ,
	/* .ssh_deserialize_private = */ ssh_mldsa44_ed25519_deserialize_ಖಾಸಗಿ,
	/* .generate = */	ssh_mldsa44_ed25519_generate,
	/* .copy_public = */	ssh_mldsa44_ed25519_copy_ಬಹಿರಂಗ,
	/* .sign = */		ssh_mldsa44_ed25519_sign,
	/* .verify = */		ssh_mldsa44_ed25519_verify,
};

ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey_impl sshkey_mldsa44_ed25519_impl = {
	/* .name = */		"ssh-mldsa44-ed25519",
	/* .shortname = */	"MLDSA44-ED25519",
	/* .sigalg = */		ಖಾಲಿ,
	/* .type = */		ಕೀಲಿ_MLDSA44_ED25519,
	/* .nid = */		0,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	512, /* size of the private key */
	/* .funcs = */		&sshkey_mldsa44_ed25519_funcs,
};

ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey_impl sshkey_mldsa44_ed25519_cert_impl = {
	/* .name = */		"ssh-mldsa44-ed25519-cert",
	/* .shortname = */	"MLDSA44-ED25519-CERT",
	/* .sigalg = */		ಖಾಲಿ,
	/* .type = */		ಕೀಲಿ_MLDSA44_ED25519_CERT,
	/* .nid = */		0,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	512, /* size of the private key */
	/* .funcs = */		&sshkey_mldsa44_ed25519_funcs,
};
#ಆದರೆ_ಅಂತ್ಯ /* USE_MLDSA */
