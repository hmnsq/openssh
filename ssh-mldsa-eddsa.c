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

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ifdef USE_MLDSA

#ଅନ୍ତର୍ଭାଵ <sys/types.h>
#ଅନ୍ତର୍ଭାଵ <stdint.h>
#ଅନ୍ତର୍ଭାଵ <string.h>
#ଅନ୍ତର୍ଭାଵ <stdlib.h>

#ଅନ୍ତର୍ଭାଵ "crypto_api.h"
#ଅନ୍ତର୍ଭାଵ "sshbuf.h"
#ଅନ୍ତର୍ଭାଵ "ssherr.h"
#ଅନ୍ତର୍ଭାଵ "digest.h"
#define SSHKEY_INTERNAL
#ଅନ୍ତର୍ଭାଵ "sshkey.h"
#ଅନ୍ତର୍ଭାଵ "log.h"

#define COMPOSITE_PREFIX "CompositeAlgorithmSignatures2025"
#define COMPOSITE_LABEL  "COMPSIG-MLDSA44-Ed25519-SHA512"
#define SSH_MLDSA44_ED25519_ALG_NAME   "ssh-mldsa44-ed25519"

/*
 * raw_* functions implement the draft-ietf-lamps-pq-composite-sigs-18
 * composite signature scheme. These are exposed (i.e. not static) so
 * we can test them separately in unittests/crypto.
 */

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
crypto_sign_mldsa44_ed25519_keygen(uint8_t pk[MLDSA44_ED25519_PK_SZ],
    uint8_t sk[MLDSA44_ED25519_SK_SZ])
{
	uint8_t mldsa_seed[MLDSA44_SEEDBYTES];
	uint8_t ed25519_seed[crypto_sign_ed25519_SEEDBYTES];
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	arc4random_buf(mldsa_seed, ଆକାର(mldsa_seed));
	arc4random_buf(ed25519_seed, ଆକାର(ed25519_seed));

	r = crypto_sign_mldsa44_ed25519_keygen_seeded(pk, sk, mldsa_seed,
	    ed25519_seed);
	explicit_bzero(mldsa_seed, ଆକାର(mldsa_seed));
	explicit_bzero(ed25519_seed, ଆକାର(ed25519_seed));
	ଫେରନ୍ତୁ r;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
crypto_sign_mldsa44_ed25519_keygen_seeded(uint8_t pk[MLDSA44_ED25519_PK_SZ],
    uint8_t sk[MLDSA44_ED25519_SK_SZ],
    ଅଚଳ uint8_t mldsa_seed[MLDSA44_SEEDBYTES],
    ଅଚଳ uint8_t ed25519_seed[crypto_sign_ed25519_SEEDBYTES])
{
	uint8_t ed25519_pk[MLDSA44_SEEDBYTES];
	uint8_t ed25519_sk[crypto_sign_ed25519_SECRETKEYBYTES];
	uint8_t mldsa_sk[MLDSA44_SECRETKEYBYTES];
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା ret = -1;

	ଯଦି (crypto_sign_mldsa44_keypair_seeded(pk, mldsa_sk, mldsa_seed) != 0)
		ଯାଅ out;
	ଯଦି (crypto_sign_ed25519_seed_keypair(ed25519_pk, ed25519_sk,
	    ed25519_seed) != 0)
		ଯାଅ out;

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
	explicit_bzero(mldsa_sk, ଆକାର(mldsa_sk));
	explicit_bzero(ed25519_sk, ଆକାର(ed25519_sk));
	ଫେରନ୍ତୁ ret;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
construct_m_ମୌଳିକ(uint8_t **m_primep, size_t *m_ମୌଳିକ_lenp,
    ଅଚଳ uint8_t *ସନ୍ଦେଶ, size_t msglen,
    ଅଚଳ uint8_t *ctx, size_t ctxlen)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;
	uint8_t hash[64];
	ସଂରଚନା sshbuf *m_ମୌଳିକ;

	*m_primep = ଖାଲି;
	*m_ମୌଳିକ_lenp = 0;

	ଯଦି (ctxlen > 255)
		ଫେରନ୍ତୁ SSH_ERR_INVALID_ARGUMENT;
	ଯଦି ((r = ssh_digest_memory(SSH_DIGEST_SHA512, ସନ୍ଦେଶ, msglen,
	    hash, ଆକାର(hash))) != 0)
		ଫେରନ୍ତୁ r;
	ଯଦି ((m_ମୌଳିକ = sshbuf_new()) == ଖାଲି)
		ଫେରନ୍ତୁ SSH_ERR_ALLOC_FAIL;
	ଯଦି ((r = sshbuf_put(m_ମୌଳିକ, COMPOSITE_PREFIX,
	    ଆକାର(COMPOSITE_PREFIX) - 1)) != 0 ||
	    (r = sshbuf_put(m_ମୌଳିକ, COMPOSITE_LABEL,
	    ଆକାର(COMPOSITE_LABEL) - 1)) != 0 ||
	    (r = sshbuf_put_u8(m_ମୌଳିକ, (uint8_t)ctxlen)) != 0 ||
	    (r = sshbuf_put(m_ମୌଳିକ, ctx, ctxlen)) != 0 ||
	    (r = sshbuf_put(m_ମୌଳିକ, hash, ଆକାର(hash))) != 0) {
		sshbuf_free(m_ମୌଳିକ);
		ଫେରନ୍ତୁ r;
	}
	ଯଦି ((*m_primep = malloc(sshbuf_len(m_ମୌଳିକ))) == ଖାଲି) {
		sshbuf_free(m_ମୌଳିକ);
		ଫେରନ୍ତୁ SSH_ERR_ALLOC_FAIL;
	}
	memcpy(*m_primep, sshbuf_ptr(m_ମୌଳିକ), sshbuf_len(m_ମୌଳିକ));
	*m_ମୌଳିକ_lenp = sshbuf_len(m_ମୌଳିକ);
	/* success */
	sshbuf_free(m_ମୌଳିକ);
	ଫେରନ୍ତୁ 0;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
crypto_sign_mldsa44_ed25519_sign(uint8_t sig[MLDSA44_ED25519_SIG_SZ],
    ଅଚଳ uint8_t *ସନ୍ଦେଶ, size_t msglen,
    ଅଚଳ uint8_t *ctx, size_t ctxlen,
    ଅଚଳ uint8_t sk[MLDSA44_ED25519_SK_SZ])
{
	uint8_t *m_ମୌଳିକ = ଖାଲି;
	size_t m_ମୌଳିକ_len = 0;
	uint8_t mldsa_sk[MLDSA44_SECRETKEYBYTES];
	uint8_t mldsa_pk_dummy[MLDSA44_PUBLICKEYBYTES];
	uint8_t ed25519_pk[crypto_sign_ed25519_PUBLICKEYBYTES];
	uint8_t ed25519_sk[crypto_sign_ed25519_SECRETKEYBYTES];
	uint8_t mldsa_rnd[MLDSA44_SEEDBYTES];
	unsigned long long smlen;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r = -1;

	ଯଦି (construct_m_ମୌଳିକ(&m_ମୌଳିକ, &m_ମୌଳିକ_len, ସନ୍ଦେଶ, msglen,
	    ctx, ctxlen) != 0)
		ଫେରନ୍ତୁ -1;

	/* Expand ML-DSA key from seed */
	ଯଦି (crypto_sign_mldsa44_keypair_seeded(mldsa_pk_dummy, mldsa_sk, sk) != 0)
		ଯାଅ out;

	/* Sign with ML-DSA */
	arc4random_buf(mldsa_rnd, ଆକାର(mldsa_rnd));
	ଯଦି (crypto_sign_mldsa44_seeded(sig, m_ମୌଳିକ, m_ମୌଳିକ_len,
	    (ଅଚଳ uint8_t *)COMPOSITE_LABEL, ଆକାର(COMPOSITE_LABEL) - 1,
	    mldsa_sk, mldsa_rnd) != 0)
		ଯାଅ out;

	/* Expand Ed25519 key from seed */
	ଯଦି (crypto_sign_ed25519_seed_keypair(ed25519_pk, ed25519_sk,
	    sk + MLDSA44_SEEDBYTES) != 0)
		ଯାଅ out;

	/* Sign with Ed25519 */
	ଯଦି (crypto_sign_ed25519_detached(sig + MLDSA44_SIGBYTES, &smlen,
	    m_ମୌଳିକ, m_ମୌଳିକ_len, ed25519_sk) != 0 ||
	    smlen != crypto_sign_ed25519_BYTES)
		ଯାଅ out;

	r = 0;
 out:
	ମୁକ୍ତ(m_ମୌଳିକ);
	explicit_bzero(mldsa_rnd, ଆକାର(mldsa_rnd));
	explicit_bzero(mldsa_sk, ଆକାର(mldsa_sk));
	explicit_bzero(ed25519_sk, ଆକାର(ed25519_sk));
	ଫେରନ୍ତୁ r;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
crypto_sign_mldsa44_ed25519_verify(ଅଚଳ uint8_t sig[MLDSA44_ED25519_SIG_SZ],
    ଅଚଳ uint8_t *ସନ୍ଦେଶ, size_t msglen,
    ଅଚଳ uint8_t *ctx, size_t ctxlen,
    ଅଚଳ uint8_t pk[MLDSA44_ED25519_PK_SZ])
{
	uint8_t *m_ମୌଳିକ = ଖାଲି;
	size_t m_ମୌଳିକ_len = 0;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r = -1;

	ଯଦି (construct_m_ମୌଳିକ(&m_ମୌଳିକ, &m_ମୌଳିକ_len, ସନ୍ଦେଶ, msglen,
	    ctx, ctxlen) != 0)
		ଫେରନ୍ତୁ -1;

	/* Verify ML-DSA */
	ଯଦି (crypto_sign_mldsa44_verify(sig, m_ମୌଳିକ, m_ମୌଳିକ_len,
	    (ଅଚଳ uint8_t *)COMPOSITE_LABEL, ଆକାର(COMPOSITE_LABEL) - 1,
	    pk) != 0)
		ଯାଅ out;

	/* Verify Ed25519 */
	ଯଦି (crypto_sign_ed25519_verify_detached(sig + MLDSA44_SIGBYTES,
	    m_ମୌଳିକ, m_ମୌଳିକ_len, pk + MLDSA44_PUBLICKEYBYTES) != 0)
		ଯାଅ out;

	r = 0;
 out:
	ମୁକ୍ତ(m_ମୌଳିକ);
	ଫେରନ୍ତୁ r;
}

/* sshkey integration */

ସ୍ଥିର ଶୂନ୍ୟ
ssh_mldsa44_ed25519_cleanup(ସଂରଚନା sshkey *k)
{
	freezero(k->mldsa_ed25519_pk, MLDSA44_ED25519_PK_SZ);
	freezero(k->mldsa_ed25519_sk, MLDSA44_ED25519_SK_SZ);
	k->mldsa_ed25519_pk = ଖାଲି;
	k->mldsa_ed25519_sk = ଖାଲି;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_mldsa44_ed25519_equal(ଅଚଳ ସଂରଚନା sshkey *a, ଅଚଳ ସଂରଚନା sshkey *b)
{
	ଯଦି (a->mldsa_ed25519_pk == ଖାଲି || b->mldsa_ed25519_pk == ଖାଲି)
		ଫେରନ୍ତୁ 0;
	ଯଦି (memcmp(a->mldsa_ed25519_pk, b->mldsa_ed25519_pk,
	    MLDSA44_ED25519_PK_SZ) != 0)
		ଫେରନ୍ତୁ 0;
	ଫେରନ୍ତୁ 1;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_mldsa44_ed25519_serialize_public(ଅଚଳ ସଂରଚନା sshkey *ଚାବି, ସଂରଚନା sshbuf *b,
    ଗଣନା sshkey_serialize_rep opts)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି (ଚାବି->mldsa_ed25519_pk == ଖାଲି)
		ଫେରନ୍ତୁ SSH_ERR_INVALID_ARGUMENT;
	ଯଦି ((r = sshbuf_put_string(b, ଚାବି->mldsa_ed25519_pk,
	    MLDSA44_ED25519_PK_SZ)) != 0)
		ଫେରନ୍ତୁ r;

	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_mldsa44_ed25519_serialize_private(ଅଚଳ ସଂରଚନା sshkey *ଚାବି, ସଂରଚନା sshbuf *b,
    ଗଣନା sshkey_serialize_rep opts)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି (ଚାବି->mldsa_ed25519_sk == ଖାଲି)
		ଫେରନ୍ତୁ SSH_ERR_INVALID_ARGUMENT;
	ଯଦି (!sshkey_is_cert(ଚାବି)) {
		ଯଦି ((r = ssh_mldsa44_ed25519_serialize_public(ଚାବି,
		    b, opts)) != 0)
			ଫେରନ୍ତୁ r;
	}
	ଯଦି ((r = sshbuf_put_string(b, ଚାବି->mldsa_ed25519_sk,
	    MLDSA44_ED25519_SK_SZ)) != 0)
		ଫେରନ୍ତୁ r;

	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_mldsa44_ed25519_deserialize_public(ଅଚଳ ଅକ୍ଷର *ktype, ସଂରଚନା sshbuf *b,
    ସଂରଚନା sshkey *ଚାବି)
{
	u_char *pk = ଖାଲି;
	size_t len = 0;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି ((r = sshbuf_get_string(b, &pk, &len)) != 0)
		ଫେରନ୍ତୁ r;
	ଯଦି (len != MLDSA44_ED25519_PK_SZ) {
		freezero(pk, len);
		ଫେରନ୍ତୁ SSH_ERR_INVALID_FORMAT;
	}
	ଚାବି->mldsa_ed25519_pk = pk;
	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_mldsa44_ed25519_deserialize_private(ଅଚଳ ଅକ୍ଷର *ktype, ସଂରଚନା sshbuf *b,
    ସଂରଚନା sshkey *ଚାବି)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;
	size_t sklen = 0;
	u_char *sk = ଖାଲି;

	ଯଦି (!sshkey_is_cert(ଚାବି)) {
		ଯଦି ((r = ssh_mldsa44_ed25519_deserialize_public(ktype,
		    b, ଚାବି)) != 0)
			ଫେରନ୍ତୁ r;
	}
	ଯଦି ((r = sshbuf_get_string(b, &sk, &sklen)) != 0)
		ଯାଅ out;
	ଯଦି (sklen != MLDSA44_ED25519_SK_SZ) {
		r = SSH_ERR_INVALID_FORMAT;
		ଯାଅ out;
	}
	ଚାବି->mldsa_ed25519_sk = sk;
	sk = ଖାଲି; /* transferred */
	r = 0;
 out:
	freezero(sk, sklen);
	ଫେରନ୍ତୁ r;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_mldsa44_ed25519_generate(ସଂରଚନା sshkey *k, ପୂର୍ଣ୍ଣସଂଖ୍ୟା bits)
{
	ssh_mldsa44_ed25519_cleanup(k);
	ଯଦି ((k->mldsa_ed25519_pk = malloc(MLDSA44_ED25519_PK_SZ)) == ଖାଲି ||
	    (k->mldsa_ed25519_sk = malloc(MLDSA44_ED25519_SK_SZ)) == ଖାଲି) {
		ssh_mldsa44_ed25519_cleanup(k);
		ଫେରନ୍ତୁ SSH_ERR_ALLOC_FAIL;
	}
	ଯଦି (crypto_sign_mldsa44_ed25519_keygen(k->mldsa_ed25519_pk,
	    k->mldsa_ed25519_sk) != 0) {
		ssh_mldsa44_ed25519_cleanup(k);
		ଫେରନ୍ତୁ SSH_ERR_CRYPTO_ERROR;
	}
	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_mldsa44_ed25519_copy_public(ଅଚଳ ସଂରଚନା sshkey *from, ସଂରଚନା sshkey *to)
{
	ଯଦି (from->mldsa_ed25519_pk == ଖାଲି)
		ଫେରନ୍ତୁ SSH_ERR_INVALID_ARGUMENT;
	ଯଦି ((to->mldsa_ed25519_pk = malloc(MLDSA44_ED25519_PK_SZ)) == ଖାଲି)
		ଫେରନ୍ତୁ SSH_ERR_ALLOC_FAIL;
	memcpy(to->mldsa_ed25519_pk, from->mldsa_ed25519_pk,
	    MLDSA44_ED25519_PK_SZ);
	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_mldsa44_ed25519_sign(ସଂରଚନା sshkey *ଚାବି,
    u_char **sigp, size_t *lenp, ଅଚଳ u_char *data, size_t datalen,
    ଅଚଳ ଅକ୍ଷର *alg, ଅଚଳ ଅକ୍ଷର *sk_provider, ଅଚଳ ଅକ୍ଷର *sk_pin,
    u_int compat)
{
	u_char sig[MLDSA44_ED25519_SIG_SZ];
	ସଂରଚନା sshbuf *b = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r = SSH_ERR_INTERNAL_ERROR;

	ଯଦି (lenp != ଖାଲି)
		*lenp = 0;
	ଯଦି (sigp != ଖାଲି)
		*sigp = ଖାଲି;

	ଯଦି (ଚାବି == ଖାଲି ||
	    sshkey_type_plain(ଚାବି->type) != ଚାବି_MLDSA44_ED25519 ||
	    ଚାବି->mldsa_ed25519_sk == ଖାଲି)
		ଫେରନ୍ତୁ SSH_ERR_INVALID_ARGUMENT;

	ଯଦି (crypto_sign_mldsa44_ed25519_sign(sig, data, datalen, ଖାଲି, 0,
	    ଚାବି->mldsa_ed25519_sk) != 0) {
		r = SSH_ERR_CRYPTO_ERROR;
		ଯାଅ out;
	}

	ଯଦି ((b = sshbuf_new()) == ଖାଲି) {
		r = SSH_ERR_ALLOC_FAIL;
		ଯାଅ out;
	}
	ଯଦି ((r = sshbuf_put_cstring(b, SSH_MLDSA44_ED25519_ALG_NAME)) != 0 ||
	    (r = sshbuf_put_string(b, sig, ଆକାର(sig))) != 0)
		ଯାଅ out;

	ଯଦି (sigp != ଖାଲି) {
		ଯଦି ((*sigp = malloc(sshbuf_len(b))) == ଖାଲି) {
			r = SSH_ERR_ALLOC_FAIL;
			ଯାଅ out;
		}
		memcpy(*sigp, sshbuf_ptr(b), sshbuf_len(b));
	}
	ଯଦି (lenp != ଖାଲି)
		*lenp = sshbuf_len(b);
	r = 0;
 out:
	sshbuf_free(b);
	explicit_bzero(sig, ଆକାର(sig));
	ଫେରନ୍ତୁ r;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_mldsa44_ed25519_verify(ଅଚଳ ସଂରଚନା sshkey *ଚାବି,
    ଅଚଳ u_char *sig, size_t siglen, ଅଚଳ u_char *data, size_t dlen,
    ଅଚଳ ଅକ୍ଷର *alg, u_int compat, ସଂରଚନା sshkey_sig_details **detailsp)
{
	ସଂରଚନା sshbuf *b = ଖାଲି;
	ଅକ୍ଷର *ktype = ଖାଲି;
	ଅଚଳ u_char *sigblob;
	size_t len;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି (ଚାବି == ଖାଲି ||
	    sshkey_type_plain(ଚାବି->type) != ଚାବି_MLDSA44_ED25519 ||
	    ଚାବି->mldsa_ed25519_pk == ଖାଲି ||
	    sig == ଖାଲି || siglen == 0)
		ଫେରନ୍ତୁ SSH_ERR_INVALID_ARGUMENT;

	ଯଦି ((b = sshbuf_from(sig, siglen)) == ଖାଲି)
		ଫେରନ୍ତୁ SSH_ERR_ALLOC_FAIL;
	ଯଦି ((r = sshbuf_get_cstring(b, &ktype, ଖାଲି)) != 0 ||
	    (r = sshbuf_get_string_direct(b, &sigblob, &len)) != 0)
		ଯାଅ out;
	ଯଦି (strcmp(SSH_MLDSA44_ED25519_ALG_NAME, ktype) != 0) {
		r = SSH_ERR_ଚାବି_TYPE_MISMATCH;
		ଯାଅ out;
	}
	ଯଦି (sshbuf_len(b) != 0) {
		r = SSH_ERR_UNEXPECTED_TRAILING_DATA;
		ଯାଅ out;
	}
	ଯଦି (len != MLDSA44_ED25519_SIG_SZ) {
		r = SSH_ERR_INVALID_FORMAT;
		ଯାଅ out;
	}

	ଯଦି (crypto_sign_mldsa44_ed25519_verify(sigblob, data, dlen, ଖାଲି, 0,
	    ଚାବି->mldsa_ed25519_pk) != 0) {
		r = SSH_ERR_SIGNATURE_INVALID;
		ଯାଅ out;
	}

	r = 0;
 out:
	sshbuf_free(b);
	ମୁକ୍ତ(ktype);
	ଫେରନ୍ତୁ r;
}

ଅଚଳ ସଂରଚନା sshkey_impl_funcs sshkey_mldsa44_ed25519_funcs = {
	/* .size = */		ଖାଲି,
	/* .alloc = */		ଖାଲି,
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

ଅଚଳ ସଂରଚନା sshkey_impl sshkey_mldsa44_ed25519_impl = {
	/* .name = */		"ssh-mldsa44-ed25519",
	/* .shortname = */	"MLDSA44-ED25519",
	/* .sigalg = */		ଖାଲି,
	/* .type = */		ଚାବି_MLDSA44_ED25519,
	/* .nid = */		0,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	512, /* size of the private key */
	/* .funcs = */		&sshkey_mldsa44_ed25519_funcs,
};

ଅଚଳ ସଂରଚନା sshkey_impl sshkey_mldsa44_ed25519_cert_impl = {
	/* .name = */		"ssh-mldsa44-ed25519-cert",
	/* .shortname = */	"MLDSA44-ED25519-CERT",
	/* .sigalg = */		ଖାଲି,
	/* .type = */		ଚାବି_MLDSA44_ED25519_CERT,
	/* .nid = */		0,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	512, /* size of the private key */
	/* .funcs = */		&sshkey_mldsa44_ed25519_funcs,
};
#endif /* USE_MLDSA */
