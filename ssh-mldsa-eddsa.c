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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ USE_MLDSA

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdint.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "crypto_api.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshbuf.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssherr.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "digest.h"
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHKEY_ਅੰਦਰੂਨੀ
#ਅਨ੍ਤਰ੍ਭਾਵ "sshkey.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "log.h"

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ਸੰਯੁਕਤ_ਅਗੇਤਰ "CompositeAlgorithmSignatures2025"
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ਸੰਯੁਕਤ_LABEL  "COMPSIG-MLDSA44-Ed25519-SHA512"
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_MLDSA44_ED25519_ALG_NAME   "ssh-mldsa44-ed25519"

/*
 * raw_* functions implement the draft-ietf-lamps-pq-composite-sigs-18
 * composite signature scheme. These are exposed (i.e. not static) so
 * we can test them separately in unittests/crypto.
 */

ਪੂਰਨ
crypto_sign_mldsa44_ed25519_keygen(uint8_t pk[MLDSA44_ED25519_PK_SZ],
    uint8_t sk[MLDSA44_ED25519_SK_SZ])
{
	uint8_t mldsa_ਬੀਜ[MLDSA44_SEEDBYTES];
	uint8_t ed25519_ਬੀਜ[crypto_sign_ed25519_SEEDBYTES];
	ਪੂਰਨ r;

	arc4random_buf(mldsa_ਬੀਜ, ਆਕਾਰ(mldsa_ਬੀਜ));
	arc4random_buf(ed25519_ਬੀਜ, ਆਕਾਰ(ed25519_ਬੀਜ));

	r = crypto_sign_mldsa44_ed25519_keygen_seeded(pk, sk, mldsa_ਬੀਜ,
	    ed25519_ਬੀਜ);
	explicit_bzero(mldsa_ਬੀਜ, ਆਕਾਰ(mldsa_ਬੀਜ));
	explicit_bzero(ed25519_ਬੀਜ, ਆਕਾਰ(ed25519_ਬੀਜ));
	ਵਾਪਸ r;
}

ਪੂਰਨ
crypto_sign_mldsa44_ed25519_keygen_seeded(uint8_t pk[MLDSA44_ED25519_PK_SZ],
    uint8_t sk[MLDSA44_ED25519_SK_SZ],
    ਅਚਲ uint8_t mldsa_ਬੀਜ[MLDSA44_SEEDBYTES],
    ਅਚਲ uint8_t ed25519_ਬੀਜ[crypto_sign_ed25519_SEEDBYTES])
{
	uint8_t ed25519_pk[MLDSA44_SEEDBYTES];
	uint8_t ed25519_sk[crypto_sign_ed25519_SECRETKEYBYTES];
	uint8_t mldsa_sk[MLDSA44_SECRETKEYBYTES];
	ਪੂਰਨ ret = -1;

	ਜੇ (crypto_sign_mldsa44_keypair_seeded(pk, mldsa_sk, mldsa_ਬੀਜ) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	ਜੇ (crypto_sign_ed25519_ਬੀਜ_keypair(ed25519_pk, ed25519_sk,
	    ed25519_ਬੀਜ) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;

	/* Serialize PK: mldsaPK || ed25519PK */
	ਸਮ੍ਰਿਤੀ_ਨਕਲ(pk + MLDSA44_PUBLICKEYBYTES, ed25519_pk,
	    crypto_sign_ed25519_SEEDBYTES);

	/* Serialize SK: mldsaSeed || ed25519Seed */
	ਸਮ੍ਰਿਤੀ_ਨਕਲ(sk, mldsa_ਬੀਜ, MLDSA44_SEEDBYTES);
	ਸਮ੍ਰਿਤੀ_ਨਕਲ(sk + MLDSA44_SEEDBYTES, ed25519_ਬੀਜ,
	    crypto_sign_ed25519_SEEDBYTES);

	/* success */
	ret = 0;
 ਬਾਹਰਲਾ:
	explicit_bzero(mldsa_sk, ਆਕਾਰ(mldsa_sk));
	explicit_bzero(ed25519_sk, ਆਕਾਰ(ed25519_sk));
	ਵਾਪਸ ret;
}

ਸਥਿਰ ਪੂਰਨ
construct_m_ਅਭਾਜ(uint8_t **m_primep, ਮਾਪ_t *m_ਅਭਾਜ_lenp,
    ਅਚਲ uint8_t *ਸੁਨੇਹਾ, ਮਾਪ_t msglen,
    ਅਚਲ uint8_t *ctx, ਮਾਪ_t ctxlen)
{
	ਪੂਰਨ r;
	uint8_t hash[64];
	ਬਣਤਰ sshbuf *m_ਅਭਾਜ;

	*m_primep = ਨਿਰਾ;
	*m_ਅਭਾਜ_lenp = 0;

	ਜੇ (ctxlen > 255)
		ਵਾਪਸ SSH_ERR_INVALID_ਦਲੀਲ;
	ਜੇ ((r = ssh_digest_ਸਮ੍ਰਿਤੀ(SSH_DIGEST_SHA512, ਸੁਨੇਹਾ, msglen,
	    hash, ਆਕਾਰ(hash))) != 0)
		ਵਾਪਸ r;
	ਜੇ ((m_ਅਭਾਜ = sshbuf_new()) == ਨਿਰਾ)
		ਵਾਪਸ SSH_ERR_ALLOC_FAIL;
	ਜੇ ((r = sshbuf_put(m_ਅਭਾਜ, ਸੰਯੁਕਤ_ਅਗੇਤਰ,
	    ਆਕਾਰ(ਸੰਯੁਕਤ_ਅਗੇਤਰ) - 1)) != 0 ||
	    (r = sshbuf_put(m_ਅਭਾਜ, ਸੰਯੁਕਤ_LABEL,
	    ਆਕਾਰ(ਸੰਯੁਕਤ_LABEL) - 1)) != 0 ||
	    (r = sshbuf_put_u8(m_ਅਭਾਜ, (uint8_t)ctxlen)) != 0 ||
	    (r = sshbuf_put(m_ਅਭਾਜ, ctx, ctxlen)) != 0 ||
	    (r = sshbuf_put(m_ਅਭਾਜ, hash, ਆਕਾਰ(hash))) != 0) {
		sshbuf_free(m_ਅਭਾਜ);
		ਵਾਪਸ r;
	}
	ਜੇ ((*m_primep = ਸਮ੍ਰਿਤੀ_ਦਿਓ(sshbuf_len(m_ਅਭਾਜ))) == ਨਿਰਾ) {
		sshbuf_free(m_ਅਭਾਜ);
		ਵਾਪਸ SSH_ERR_ALLOC_FAIL;
	}
	ਸਮ੍ਰਿਤੀ_ਨਕਲ(*m_primep, sshbuf_ptr(m_ਅਭਾਜ), sshbuf_len(m_ਅਭਾਜ));
	*m_ਅਭਾਜ_lenp = sshbuf_len(m_ਅਭਾਜ);
	/* success */
	sshbuf_free(m_ਅਭਾਜ);
	ਵਾਪਸ 0;
}

ਪੂਰਨ
crypto_sign_mldsa44_ed25519_sign(uint8_t sig[MLDSA44_ED25519_SIG_SZ],
    ਅਚਲ uint8_t *ਸੁਨੇਹਾ, ਮਾਪ_t msglen,
    ਅਚਲ uint8_t *ctx, ਮਾਪ_t ctxlen,
    ਅਚਲ uint8_t sk[MLDSA44_ED25519_SK_SZ])
{
	uint8_t *m_ਅਭਾਜ = ਨਿਰਾ;
	ਮਾਪ_t m_ਅਭਾਜ_len = 0;
	uint8_t mldsa_sk[MLDSA44_SECRETKEYBYTES];
	uint8_t mldsa_pk_dummy[MLDSA44_PUBLICKEYBYTES];
	uint8_t ed25519_pk[crypto_sign_ed25519_PUBLICKEYBYTES];
	uint8_t ed25519_sk[crypto_sign_ed25519_SECRETKEYBYTES];
	uint8_t mldsa_rnd[MLDSA44_SEEDBYTES];
	ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਲੰਮਾ smlen;
	ਪੂਰਨ r = -1;

	ਜੇ (construct_m_ਅਭਾਜ(&m_ਅਭਾਜ, &m_ਅਭਾਜ_len, ਸੁਨੇਹਾ, msglen,
	    ctx, ctxlen) != 0)
		ਵਾਪਸ -1;

	/* Expand ML-DSA key from seed */
	ਜੇ (crypto_sign_mldsa44_keypair_seeded(mldsa_pk_dummy, mldsa_sk, sk) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;

	/* Sign with ML-DSA */
	arc4random_buf(mldsa_rnd, ਆਕਾਰ(mldsa_rnd));
	ਜੇ (crypto_sign_mldsa44_seeded(sig, m_ਅਭਾਜ, m_ਅਭਾਜ_len,
	    (ਅਚਲ uint8_t *)ਸੰਯੁਕਤ_LABEL, ਆਕਾਰ(ਸੰਯੁਕਤ_LABEL) - 1,
	    mldsa_sk, mldsa_rnd) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;

	/* Expand Ed25519 key from seed */
	ਜੇ (crypto_sign_ed25519_ਬੀਜ_keypair(ed25519_pk, ed25519_sk,
	    sk + MLDSA44_SEEDBYTES) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;

	/* Sign with Ed25519 */
	ਜੇ (crypto_sign_ed25519_detached(sig + MLDSA44_SIGBYTES, &smlen,
	    m_ਅਭਾਜ, m_ਅਭਾਜ_len, ed25519_sk) != 0 ||
	    smlen != crypto_sign_ed25519_ਬਾਈਟਾਂ)
		ਜਾਓ ਬਾਹਰਲਾ;

	r = 0;
 ਬਾਹਰਲਾ:
	ਮੁਕਤ(m_ਅਭਾਜ);
	explicit_bzero(mldsa_rnd, ਆਕਾਰ(mldsa_rnd));
	explicit_bzero(mldsa_sk, ਆਕਾਰ(mldsa_sk));
	explicit_bzero(ed25519_sk, ਆਕਾਰ(ed25519_sk));
	ਵਾਪਸ r;
}

ਪੂਰਨ
crypto_sign_mldsa44_ed25519_verify(ਅਚਲ uint8_t sig[MLDSA44_ED25519_SIG_SZ],
    ਅਚਲ uint8_t *ਸੁਨੇਹਾ, ਮਾਪ_t msglen,
    ਅਚਲ uint8_t *ctx, ਮਾਪ_t ctxlen,
    ਅਚਲ uint8_t pk[MLDSA44_ED25519_PK_SZ])
{
	uint8_t *m_ਅਭਾਜ = ਨਿਰਾ;
	ਮਾਪ_t m_ਅਭਾਜ_len = 0;
	ਪੂਰਨ r = -1;

	ਜੇ (construct_m_ਅਭਾਜ(&m_ਅਭਾਜ, &m_ਅਭਾਜ_len, ਸੁਨੇਹਾ, msglen,
	    ctx, ctxlen) != 0)
		ਵਾਪਸ -1;

	/* Verify ML-DSA */
	ਜੇ (crypto_sign_mldsa44_verify(sig, m_ਅਭਾਜ, m_ਅਭਾਜ_len,
	    (ਅਚਲ uint8_t *)ਸੰਯੁਕਤ_LABEL, ਆਕਾਰ(ਸੰਯੁਕਤ_LABEL) - 1,
	    pk) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;

	/* Verify Ed25519 */
	ਜੇ (crypto_sign_ed25519_verify_detached(sig + MLDSA44_SIGBYTES,
	    m_ਅਭਾਜ, m_ਅਭਾਜ_len, pk + MLDSA44_PUBLICKEYBYTES) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;

	r = 0;
 ਬਾਹਰਲਾ:
	ਮੁਕਤ(m_ਅਭਾਜ);
	ਵਾਪਸ r;
}

/* sshkey integration */

ਸਥਿਰ ਖਾਲੀ
ssh_mldsa44_ed25519_cleanup(ਬਣਤਰ sshkey *k)
{
	freezero(k->mldsa_ed25519_pk, MLDSA44_ED25519_PK_SZ);
	freezero(k->mldsa_ed25519_sk, MLDSA44_ED25519_SK_SZ);
	k->mldsa_ed25519_pk = ਨਿਰਾ;
	k->mldsa_ed25519_sk = ਨਿਰਾ;
}

ਸਥਿਰ ਪੂਰਨ
ssh_mldsa44_ed25519_equal(ਅਚਲ ਬਣਤਰ sshkey *a, ਅਚਲ ਬਣਤਰ sshkey *b)
{
	ਜੇ (a->mldsa_ed25519_pk == ਨਿਰਾ || b->mldsa_ed25519_pk == ਨਿਰਾ)
		ਵਾਪਸ 0;
	ਜੇ (memcmp(a->mldsa_ed25519_pk, b->mldsa_ed25519_pk,
	    MLDSA44_ED25519_PK_SZ) != 0)
		ਵਾਪਸ 0;
	ਵਾਪਸ 1;
}

ਸਥਿਰ ਪੂਰਨ
ssh_mldsa44_ed25519_serialize_ਜਨਤਕ(ਅਚਲ ਬਣਤਰ sshkey *ਕੁੰਜੀ, ਬਣਤਰ sshbuf *b,
    ਗਿਣਤੀ sshkey_serialize_rep opts)
{
	ਪੂਰਨ r;

	ਜੇ (ਕੁੰਜੀ->mldsa_ed25519_pk == ਨਿਰਾ)
		ਵਾਪਸ SSH_ERR_INVALID_ਦਲੀਲ;
	ਜੇ ((r = sshbuf_put_string(b, ਕੁੰਜੀ->mldsa_ed25519_pk,
	    MLDSA44_ED25519_PK_SZ)) != 0)
		ਵਾਪਸ r;

	ਵਾਪਸ 0;
}

ਸਥਿਰ ਪੂਰਨ
ssh_mldsa44_ed25519_serialize_ਨਿੱਜੀ(ਅਚਲ ਬਣਤਰ sshkey *ਕੁੰਜੀ, ਬਣਤਰ sshbuf *b,
    ਗਿਣਤੀ sshkey_serialize_rep opts)
{
	ਪੂਰਨ r;

	ਜੇ (ਕੁੰਜੀ->mldsa_ed25519_sk == ਨਿਰਾ)
		ਵਾਪਸ SSH_ERR_INVALID_ਦਲੀਲ;
	ਜੇ (!sshkey_is_cert(ਕੁੰਜੀ)) {
		ਜੇ ((r = ssh_mldsa44_ed25519_serialize_ਜਨਤਕ(ਕੁੰਜੀ,
		    b, opts)) != 0)
			ਵਾਪਸ r;
	}
	ਜੇ ((r = sshbuf_put_string(b, ਕੁੰਜੀ->mldsa_ed25519_sk,
	    MLDSA44_ED25519_SK_SZ)) != 0)
		ਵਾਪਸ r;

	ਵਾਪਸ 0;
}

ਸਥਿਰ ਪੂਰਨ
ssh_mldsa44_ed25519_deserialize_ਜਨਤਕ(ਅਚਲ ਅੱਖਰ *ktype, ਬਣਤਰ sshbuf *b,
    ਬਣਤਰ sshkey *ਕੁੰਜੀ)
{
	u_char *pk = ਨਿਰਾ;
	ਮਾਪ_t len = 0;
	ਪੂਰਨ r;

	ਜੇ ((r = sshbuf_get_string(b, &pk, &len)) != 0)
		ਵਾਪਸ r;
	ਜੇ (len != MLDSA44_ED25519_PK_SZ) {
		freezero(pk, len);
		ਵਾਪਸ SSH_ERR_INVALID_FORMAT;
	}
	ਕੁੰਜੀ->mldsa_ed25519_pk = pk;
	ਵਾਪਸ 0;
}

ਸਥਿਰ ਪੂਰਨ
ssh_mldsa44_ed25519_deserialize_ਨਿੱਜੀ(ਅਚਲ ਅੱਖਰ *ktype, ਬਣਤਰ sshbuf *b,
    ਬਣਤਰ sshkey *ਕੁੰਜੀ)
{
	ਪੂਰਨ r;
	ਮਾਪ_t sklen = 0;
	u_char *sk = ਨਿਰਾ;

	ਜੇ (!sshkey_is_cert(ਕੁੰਜੀ)) {
		ਜੇ ((r = ssh_mldsa44_ed25519_deserialize_ਜਨਤਕ(ktype,
		    b, ਕੁੰਜੀ)) != 0)
			ਵਾਪਸ r;
	}
	ਜੇ ((r = sshbuf_get_string(b, &sk, &sklen)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	ਜੇ (sklen != MLDSA44_ED25519_SK_SZ) {
		r = SSH_ERR_INVALID_FORMAT;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਕੁੰਜੀ->mldsa_ed25519_sk = sk;
	sk = ਨਿਰਾ; /* transferred */
	r = 0;
 ਬਾਹਰਲਾ:
	freezero(sk, sklen);
	ਵਾਪਸ r;
}

ਸਥਿਰ ਪੂਰਨ
ssh_mldsa44_ed25519_generate(ਬਣਤਰ sshkey *k, ਪੂਰਨ ਬਿੱਟ)
{
	ssh_mldsa44_ed25519_cleanup(k);
	ਜੇ ((k->mldsa_ed25519_pk = ਸਮ੍ਰਿਤੀ_ਦਿਓ(MLDSA44_ED25519_PK_SZ)) == ਨਿਰਾ ||
	    (k->mldsa_ed25519_sk = ਸਮ੍ਰਿਤੀ_ਦਿਓ(MLDSA44_ED25519_SK_SZ)) == ਨਿਰਾ) {
		ssh_mldsa44_ed25519_cleanup(k);
		ਵਾਪਸ SSH_ERR_ALLOC_FAIL;
	}
	ਜੇ (crypto_sign_mldsa44_ed25519_keygen(k->mldsa_ed25519_pk,
	    k->mldsa_ed25519_sk) != 0) {
		ssh_mldsa44_ed25519_cleanup(k);
		ਵਾਪਸ SSH_ERR_CRYPTO_ERROR;
	}
	ਵਾਪਸ 0;
}

ਸਥਿਰ ਪੂਰਨ
ssh_mldsa44_ed25519_copy_ਜਨਤਕ(ਅਚਲ ਬਣਤਰ sshkey *from, ਬਣਤਰ sshkey *ਮੰਜ਼ਿਲ)
{
	ਜੇ (from->mldsa_ed25519_pk == ਨਿਰਾ)
		ਵਾਪਸ SSH_ERR_INVALID_ਦਲੀਲ;
	ਜੇ ((ਮੰਜ਼ਿਲ->mldsa_ed25519_pk = ਸਮ੍ਰਿਤੀ_ਦਿਓ(MLDSA44_ED25519_PK_SZ)) == ਨਿਰਾ)
		ਵਾਪਸ SSH_ERR_ALLOC_FAIL;
	ਸਮ੍ਰਿਤੀ_ਨਕਲ(ਮੰਜ਼ਿਲ->mldsa_ed25519_pk, from->mldsa_ed25519_pk,
	    MLDSA44_ED25519_PK_SZ);
	ਵਾਪਸ 0;
}

ਸਥਿਰ ਪੂਰਨ
ssh_mldsa44_ed25519_sign(ਬਣਤਰ sshkey *ਕੁੰਜੀ,
    u_char **sigp, ਮਾਪ_t *lenp, ਅਚਲ u_char *ਅੰਕੜੇ, ਮਾਪ_t datalen,
    ਅਚਲ ਅੱਖਰ *alg, ਅਚਲ ਅੱਖਰ *sk_provider, ਅਚਲ ਅੱਖਰ *sk_pin,
    u_int compat)
{
	u_char sig[MLDSA44_ED25519_SIG_SZ];
	ਬਣਤਰ sshbuf *b = ਨਿਰਾ;
	ਪੂਰਨ r = SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;

	ਜੇ (lenp != ਨਿਰਾ)
		*lenp = 0;
	ਜੇ (sigp != ਨਿਰਾ)
		*sigp = ਨਿਰਾ;

	ਜੇ (ਕੁੰਜੀ == ਨਿਰਾ ||
	    sshkey_type_plain(ਕੁੰਜੀ->type) != ਕੁੰਜੀ_MLDSA44_ED25519 ||
	    ਕੁੰਜੀ->mldsa_ed25519_sk == ਨਿਰਾ)
		ਵਾਪਸ SSH_ERR_INVALID_ਦਲੀਲ;

	ਜੇ (crypto_sign_mldsa44_ed25519_sign(sig, ਅੰਕੜੇ, datalen, ਨਿਰਾ, 0,
	    ਕੁੰਜੀ->mldsa_ed25519_sk) != 0) {
		r = SSH_ERR_CRYPTO_ERROR;
		ਜਾਓ ਬਾਹਰਲਾ;
	}

	ਜੇ ((b = sshbuf_new()) == ਨਿਰਾ) {
		r = SSH_ERR_ALLOC_FAIL;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((r = sshbuf_put_cstring(b, SSH_MLDSA44_ED25519_ALG_NAME)) != 0 ||
	    (r = sshbuf_put_string(b, sig, ਆਕਾਰ(sig))) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;

	ਜੇ (sigp != ਨਿਰਾ) {
		ਜੇ ((*sigp = ਸਮ੍ਰਿਤੀ_ਦਿਓ(sshbuf_len(b))) == ਨਿਰਾ) {
			r = SSH_ERR_ALLOC_FAIL;
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		ਸਮ੍ਰਿਤੀ_ਨਕਲ(*sigp, sshbuf_ptr(b), sshbuf_len(b));
	}
	ਜੇ (lenp != ਨਿਰਾ)
		*lenp = sshbuf_len(b);
	r = 0;
 ਬਾਹਰਲਾ:
	sshbuf_free(b);
	explicit_bzero(sig, ਆਕਾਰ(sig));
	ਵਾਪਸ r;
}

ਸਥਿਰ ਪੂਰਨ
ssh_mldsa44_ed25519_verify(ਅਚਲ ਬਣਤਰ sshkey *ਕੁੰਜੀ,
    ਅਚਲ u_char *sig, ਮਾਪ_t siglen, ਅਚਲ u_char *ਅੰਕੜੇ, ਮਾਪ_t dlen,
    ਅਚਲ ਅੱਖਰ *alg, u_int compat, ਬਣਤਰ sshkey_sig_details **detailsp)
{
	ਬਣਤਰ sshbuf *b = ਨਿਰਾ;
	ਅੱਖਰ *ktype = ਨਿਰਾ;
	ਅਚਲ u_char *sigblob;
	ਮਾਪ_t len;
	ਪੂਰਨ r;

	ਜੇ (ਕੁੰਜੀ == ਨਿਰਾ ||
	    sshkey_type_plain(ਕੁੰਜੀ->type) != ਕੁੰਜੀ_MLDSA44_ED25519 ||
	    ਕੁੰਜੀ->mldsa_ed25519_pk == ਨਿਰਾ ||
	    sig == ਨਿਰਾ || siglen == 0)
		ਵਾਪਸ SSH_ERR_INVALID_ਦਲੀਲ;

	ਜੇ ((b = sshbuf_from(sig, siglen)) == ਨਿਰਾ)
		ਵਾਪਸ SSH_ERR_ALLOC_FAIL;
	ਜੇ ((r = sshbuf_get_cstring(b, &ktype, ਨਿਰਾ)) != 0 ||
	    (r = sshbuf_get_string_ਸਿੱਧਾ(b, &sigblob, &len)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	ਜੇ (strcmp(SSH_MLDSA44_ED25519_ALG_NAME, ktype) != 0) {
		r = SSH_ERR_ਕੁੰਜੀ_TYPE_MISMATCH;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ (sshbuf_len(b) != 0) {
		r = SSH_ERR_UNEXPECTED_TRAILING_ਅੰਕੜੇ;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ (len != MLDSA44_ED25519_SIG_SZ) {
		r = SSH_ERR_INVALID_FORMAT;
		ਜਾਓ ਬਾਹਰਲਾ;
	}

	ਜੇ (crypto_sign_mldsa44_ed25519_verify(sigblob, ਅੰਕੜੇ, dlen, ਨਿਰਾ, 0,
	    ਕੁੰਜੀ->mldsa_ed25519_pk) != 0) {
		r = SSH_ERR_SIGNATURE_INVALID;
		ਜਾਓ ਬਾਹਰਲਾ;
	}

	r = 0;
 ਬਾਹਰਲਾ:
	sshbuf_free(b);
	ਮੁਕਤ(ktype);
	ਵਾਪਸ r;
}

ਅਚਲ ਬਣਤਰ sshkey_impl_funcs sshkey_mldsa44_ed25519_funcs = {
	/* .size = */		ਨਿਰਾ,
	/* .alloc = */		ਨਿਰਾ,
	/* .cleanup = */	ssh_mldsa44_ed25519_cleanup,
	/* .equal = */		ssh_mldsa44_ed25519_equal,
	/* .ssh_serialize_public = */ ssh_mldsa44_ed25519_serialize_ਜਨਤਕ,
	/* .ssh_deserialize_public = */ ssh_mldsa44_ed25519_deserialize_ਜਨਤਕ,
	/* .ssh_serialize_private = */ ssh_mldsa44_ed25519_serialize_ਨਿੱਜੀ,
	/* .ssh_deserialize_private = */ ssh_mldsa44_ed25519_deserialize_ਨਿੱਜੀ,
	/* .generate = */	ssh_mldsa44_ed25519_generate,
	/* .copy_public = */	ssh_mldsa44_ed25519_copy_ਜਨਤਕ,
	/* .sign = */		ssh_mldsa44_ed25519_sign,
	/* .verify = */		ssh_mldsa44_ed25519_verify,
};

ਅਚਲ ਬਣਤਰ sshkey_impl sshkey_mldsa44_ed25519_impl = {
	/* .name = */		"ssh-mldsa44-ed25519",
	/* .shortname = */	"MLDSA44-ED25519",
	/* .sigalg = */		ਨਿਰਾ,
	/* .type = */		ਕੁੰਜੀ_MLDSA44_ED25519,
	/* .nid = */		0,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	512, /* size of the private key */
	/* .funcs = */		&sshkey_mldsa44_ed25519_funcs,
};

ਅਚਲ ਬਣਤਰ sshkey_impl sshkey_mldsa44_ed25519_cert_impl = {
	/* .name = */		"ssh-mldsa44-ed25519-cert",
	/* .shortname = */	"MLDSA44-ED25519-CERT",
	/* .sigalg = */		ਨਿਰਾ,
	/* .type = */		ਕੁੰਜੀ_MLDSA44_ED25519_CERT,
	/* .nid = */		0,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	512, /* size of the private key */
	/* .funcs = */		&sshkey_mldsa44_ed25519_funcs,
};
#ਜੇ_ਅੰਤ /* USE_MLDSA */
