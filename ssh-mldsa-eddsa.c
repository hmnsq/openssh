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

#अन्तर्भाव "includes.h"

#ifdef USE_MLDSA

#अन्तर्भाव <sys/types.h>
#अन्तर्भाव <stdint.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <stdlib.h>

#अन्तर्भाव "crypto_api.h"
#अन्तर्भाव "sshbuf.h"
#अन्तर्भाव "ssherr.h"
#अन्तर्भाव "digest.h"
#define SSHKEY_INTERNAL
#अन्तर्भाव "sshkey.h"
#अन्तर्भाव "log.h"

#define COMPOSITE_PREFIX "CompositeAlgorithmSignatures2025"
#define COMPOSITE_LABEL  "COMPSIG-MLDSA44-Ed25519-SHA512"
#define SSH_MLDSA44_ED25519_ALG_NAME   "ssh-mldsa44-ed25519"

/*
 * raw_* functions implement the draft-ietf-lamps-pq-composite-sigs-18
 * composite signature scheme. These are exposed (i.e. not static) so
 * we can test them separately in unittests/crypto.
 */

पूर्णाङ्क
crypto_sign_mldsa44_ed25519_keygen(uint8_t pk[MLDSA44_ED25519_PK_SZ],
    uint8_t sk[MLDSA44_ED25519_SK_SZ])
{
	uint8_t mldsa_seed[MLDSA44_SEEDBYTES];
	uint8_t ed25519_seed[crypto_sign_ed25519_SEEDBYTES];
	पूर्णाङ्क r;

	arc4random_buf(mldsa_seed, परिमाण(mldsa_seed));
	arc4random_buf(ed25519_seed, परिमाण(ed25519_seed));

	r = crypto_sign_mldsa44_ed25519_keygen_seeded(pk, sk, mldsa_seed,
	    ed25519_seed);
	explicit_bzero(mldsa_seed, परिमाण(mldsa_seed));
	explicit_bzero(ed25519_seed, परिमाण(ed25519_seed));
	पटिनिवत्त r;
}

पूर्णाङ्क
crypto_sign_mldsa44_ed25519_keygen_seeded(uint8_t pk[MLDSA44_ED25519_PK_SZ],
    uint8_t sk[MLDSA44_ED25519_SK_SZ],
    ध्रुव uint8_t mldsa_seed[MLDSA44_SEEDBYTES],
    ध्रुव uint8_t ed25519_seed[crypto_sign_ed25519_SEEDBYTES])
{
	uint8_t ed25519_pk[MLDSA44_SEEDBYTES];
	uint8_t ed25519_sk[crypto_sign_ed25519_SECRETKEYBYTES];
	uint8_t mldsa_sk[MLDSA44_SECRETKEYBYTES];
	पूर्णाङ्क ret = -1;

	सचे (crypto_sign_mldsa44_keypair_seeded(pk, mldsa_sk, mldsa_seed) != 0)
		गच्छ out;
	सचे (crypto_sign_ed25519_seed_keypair(ed25519_pk, ed25519_sk,
	    ed25519_seed) != 0)
		गच्छ out;

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
	explicit_bzero(mldsa_sk, परिमाण(mldsa_sk));
	explicit_bzero(ed25519_sk, परिमाण(ed25519_sk));
	पटिनिवत्त ret;
}

स्थिर पूर्णाङ्क
construct_m_अविभाज्यः(uint8_t **m_primep, size_t *m_अविभाज्यः_lenp,
    ध्रुव uint8_t *सन्देशः, size_t msglen,
    ध्रुव uint8_t *ctx, size_t ctxlen)
{
	पूर्णाङ्क r;
	uint8_t hash[64];
	संरचना sshbuf *m_अविभाज्यः;

	*m_primep = रिक्त;
	*m_अविभाज्यः_lenp = 0;

	सचे (ctxlen > 255)
		पटिनिवत्त SSH_ERR_INVALID_ARGUMENT;
	सचे ((r = ssh_digest_memory(SSH_DIGEST_SHA512, सन्देशः, msglen,
	    hash, परिमाण(hash))) != 0)
		पटिनिवत्त r;
	सचे ((m_अविभाज्यः = sshbuf_new()) == रिक्त)
		पटिनिवत्त SSH_ERR_ALLOC_FAIL;
	सचे ((r = sshbuf_put(m_अविभाज्यः, COMPOSITE_PREFIX,
	    परिमाण(COMPOSITE_PREFIX) - 1)) != 0 ||
	    (r = sshbuf_put(m_अविभाज्यः, COMPOSITE_LABEL,
	    परिमाण(COMPOSITE_LABEL) - 1)) != 0 ||
	    (r = sshbuf_put_u8(m_अविभाज्यः, (uint8_t)ctxlen)) != 0 ||
	    (r = sshbuf_put(m_अविभाज्यः, ctx, ctxlen)) != 0 ||
	    (r = sshbuf_put(m_अविभाज्यः, hash, परिमाण(hash))) != 0) {
		sshbuf_free(m_अविभाज्यः);
		पटिनिवत्त r;
	}
	सचे ((*m_primep = malloc(sshbuf_len(m_अविभाज्यः))) == रिक्त) {
		sshbuf_free(m_अविभाज्यः);
		पटिनिवत्त SSH_ERR_ALLOC_FAIL;
	}
	memcpy(*m_primep, sshbuf_ptr(m_अविभाज्यः), sshbuf_len(m_अविभाज्यः));
	*m_अविभाज्यः_lenp = sshbuf_len(m_अविभाज्यः);
	/* success */
	sshbuf_free(m_अविभाज्यः);
	पटिनिवत्त 0;
}

पूर्णाङ्क
crypto_sign_mldsa44_ed25519_sign(uint8_t sig[MLDSA44_ED25519_SIG_SZ],
    ध्रुव uint8_t *सन्देशः, size_t msglen,
    ध्रुव uint8_t *ctx, size_t ctxlen,
    ध्रुव uint8_t sk[MLDSA44_ED25519_SK_SZ])
{
	uint8_t *m_अविभाज्यः = रिक्त;
	size_t m_अविभाज्यः_len = 0;
	uint8_t mldsa_sk[MLDSA44_SECRETKEYBYTES];
	uint8_t mldsa_pk_dummy[MLDSA44_PUBLICKEYBYTES];
	uint8_t ed25519_pk[crypto_sign_ed25519_PUBLICKEYBYTES];
	uint8_t ed25519_sk[crypto_sign_ed25519_SECRETKEYBYTES];
	uint8_t mldsa_rnd[MLDSA44_SEEDBYTES];
	unsigned long long smlen;
	पूर्णाङ्क r = -1;

	सचे (construct_m_अविभाज्यः(&m_अविभाज्यः, &m_अविभाज्यः_len, सन्देशः, msglen,
	    ctx, ctxlen) != 0)
		पटिनिवत्त -1;

	/* Expand ML-DSA key from seed */
	सचे (crypto_sign_mldsa44_keypair_seeded(mldsa_pk_dummy, mldsa_sk, sk) != 0)
		गच्छ out;

	/* Sign with ML-DSA */
	arc4random_buf(mldsa_rnd, परिमाण(mldsa_rnd));
	सचे (crypto_sign_mldsa44_seeded(sig, m_अविभाज्यः, m_अविभाज्यः_len,
	    (ध्रुव uint8_t *)COMPOSITE_LABEL, परिमाण(COMPOSITE_LABEL) - 1,
	    mldsa_sk, mldsa_rnd) != 0)
		गच्छ out;

	/* Expand Ed25519 key from seed */
	सचे (crypto_sign_ed25519_seed_keypair(ed25519_pk, ed25519_sk,
	    sk + MLDSA44_SEEDBYTES) != 0)
		गच्छ out;

	/* Sign with Ed25519 */
	सचे (crypto_sign_ed25519_detached(sig + MLDSA44_SIGBYTES, &smlen,
	    m_अविभाज्यः, m_अविभाज्यः_len, ed25519_sk) != 0 ||
	    smlen != crypto_sign_ed25519_BYTES)
		गच्छ out;

	r = 0;
 out:
	मुक्त(m_अविभाज्यः);
	explicit_bzero(mldsa_rnd, परिमाण(mldsa_rnd));
	explicit_bzero(mldsa_sk, परिमाण(mldsa_sk));
	explicit_bzero(ed25519_sk, परिमाण(ed25519_sk));
	पटिनिवत्त r;
}

पूर्णाङ्क
crypto_sign_mldsa44_ed25519_verify(ध्रुव uint8_t sig[MLDSA44_ED25519_SIG_SZ],
    ध्रुव uint8_t *सन्देशः, size_t msglen,
    ध्रुव uint8_t *ctx, size_t ctxlen,
    ध्रुव uint8_t pk[MLDSA44_ED25519_PK_SZ])
{
	uint8_t *m_अविभाज्यः = रिक्त;
	size_t m_अविभाज्यः_len = 0;
	पूर्णाङ्क r = -1;

	सचे (construct_m_अविभाज्यः(&m_अविभाज्यः, &m_अविभाज्यः_len, सन्देशः, msglen,
	    ctx, ctxlen) != 0)
		पटिनिवत्त -1;

	/* Verify ML-DSA */
	सचे (crypto_sign_mldsa44_verify(sig, m_अविभाज्यः, m_अविभाज्यः_len,
	    (ध्रुव uint8_t *)COMPOSITE_LABEL, परिमाण(COMPOSITE_LABEL) - 1,
	    pk) != 0)
		गच्छ out;

	/* Verify Ed25519 */
	सचे (crypto_sign_ed25519_verify_detached(sig + MLDSA44_SIGBYTES,
	    m_अविभाज्यः, m_अविभाज्यः_len, pk + MLDSA44_PUBLICKEYBYTES) != 0)
		गच्छ out;

	r = 0;
 out:
	मुक्त(m_अविभाज्यः);
	पटिनिवत्त r;
}

/* sshkey integration */

स्थिर शून्य
ssh_mldsa44_ed25519_cleanup(संरचना sshkey *k)
{
	freezero(k->mldsa_ed25519_pk, MLDSA44_ED25519_PK_SZ);
	freezero(k->mldsa_ed25519_sk, MLDSA44_ED25519_SK_SZ);
	k->mldsa_ed25519_pk = रिक्त;
	k->mldsa_ed25519_sk = रिक्त;
}

स्थिर पूर्णाङ्क
ssh_mldsa44_ed25519_equal(ध्रुव संरचना sshkey *a, ध्रुव संरचना sshkey *b)
{
	सचे (a->mldsa_ed25519_pk == रिक्त || b->mldsa_ed25519_pk == रिक्त)
		पटिनिवत्त 0;
	सचे (memcmp(a->mldsa_ed25519_pk, b->mldsa_ed25519_pk,
	    MLDSA44_ED25519_PK_SZ) != 0)
		पटिनिवत्त 0;
	पटिनिवत्त 1;
}

स्थिर पूर्णाङ्क
ssh_mldsa44_ed25519_serialize_public(ध्रुव संरचना sshkey *कुञ्चिका, संरचना sshbuf *b,
    गणना sshkey_serialize_rep opts)
{
	पूर्णाङ्क r;

	सचे (कुञ्चिका->mldsa_ed25519_pk == रिक्त)
		पटिनिवत्त SSH_ERR_INVALID_ARGUMENT;
	सचे ((r = sshbuf_put_string(b, कुञ्चिका->mldsa_ed25519_pk,
	    MLDSA44_ED25519_PK_SZ)) != 0)
		पटिनिवत्त r;

	पटिनिवत्त 0;
}

स्थिर पूर्णाङ्क
ssh_mldsa44_ed25519_serialize_private(ध्रुव संरचना sshkey *कुञ्चिका, संरचना sshbuf *b,
    गणना sshkey_serialize_rep opts)
{
	पूर्णाङ्क r;

	सचे (कुञ्चिका->mldsa_ed25519_sk == रिक्त)
		पटिनिवत्त SSH_ERR_INVALID_ARGUMENT;
	सचे (!sshkey_is_cert(कुञ्चिका)) {
		सचे ((r = ssh_mldsa44_ed25519_serialize_public(कुञ्चिका,
		    b, opts)) != 0)
			पटिनिवत्त r;
	}
	सचे ((r = sshbuf_put_string(b, कुञ्चिका->mldsa_ed25519_sk,
	    MLDSA44_ED25519_SK_SZ)) != 0)
		पटिनिवत्त r;

	पटिनिवत्त 0;
}

स्थिर पूर्णाङ्क
ssh_mldsa44_ed25519_deserialize_public(ध्रुव वर्ण *ktype, संरचना sshbuf *b,
    संरचना sshkey *कुञ्चिका)
{
	u_char *pk = रिक्त;
	size_t len = 0;
	पूर्णाङ्क r;

	सचे ((r = sshbuf_get_string(b, &pk, &len)) != 0)
		पटिनिवत्त r;
	सचे (len != MLDSA44_ED25519_PK_SZ) {
		freezero(pk, len);
		पटिनिवत्त SSH_ERR_INVALID_FORMAT;
	}
	कुञ्चिका->mldsa_ed25519_pk = pk;
	पटिनिवत्त 0;
}

स्थिर पूर्णाङ्क
ssh_mldsa44_ed25519_deserialize_private(ध्रुव वर्ण *ktype, संरचना sshbuf *b,
    संरचना sshkey *कुञ्चिका)
{
	पूर्णाङ्क r;
	size_t sklen = 0;
	u_char *sk = रिक्त;

	सचे (!sshkey_is_cert(कुञ्चिका)) {
		सचे ((r = ssh_mldsa44_ed25519_deserialize_public(ktype,
		    b, कुञ्चिका)) != 0)
			पटिनिवत्त r;
	}
	सचे ((r = sshbuf_get_string(b, &sk, &sklen)) != 0)
		गच्छ out;
	सचे (sklen != MLDSA44_ED25519_SK_SZ) {
		r = SSH_ERR_INVALID_FORMAT;
		गच्छ out;
	}
	कुञ्चिका->mldsa_ed25519_sk = sk;
	sk = रिक्त; /* transferred */
	r = 0;
 out:
	freezero(sk, sklen);
	पटिनिवत्त r;
}

स्थिर पूर्णाङ्क
ssh_mldsa44_ed25519_generate(संरचना sshkey *k, पूर्णाङ्क bits)
{
	ssh_mldsa44_ed25519_cleanup(k);
	सचे ((k->mldsa_ed25519_pk = malloc(MLDSA44_ED25519_PK_SZ)) == रिक्त ||
	    (k->mldsa_ed25519_sk = malloc(MLDSA44_ED25519_SK_SZ)) == रिक्त) {
		ssh_mldsa44_ed25519_cleanup(k);
		पटिनिवत्त SSH_ERR_ALLOC_FAIL;
	}
	सचे (crypto_sign_mldsa44_ed25519_keygen(k->mldsa_ed25519_pk,
	    k->mldsa_ed25519_sk) != 0) {
		ssh_mldsa44_ed25519_cleanup(k);
		पटिनिवत्त SSH_ERR_CRYPTO_ERROR;
	}
	पटिनिवत्त 0;
}

स्थिर पूर्णाङ्क
ssh_mldsa44_ed25519_copy_public(ध्रुव संरचना sshkey *from, संरचना sshkey *to)
{
	सचे (from->mldsa_ed25519_pk == रिक्त)
		पटिनिवत्त SSH_ERR_INVALID_ARGUMENT;
	सचे ((to->mldsa_ed25519_pk = malloc(MLDSA44_ED25519_PK_SZ)) == रिक्त)
		पटिनिवत्त SSH_ERR_ALLOC_FAIL;
	memcpy(to->mldsa_ed25519_pk, from->mldsa_ed25519_pk,
	    MLDSA44_ED25519_PK_SZ);
	पटिनिवत्त 0;
}

स्थिर पूर्णाङ्क
ssh_mldsa44_ed25519_sign(संरचना sshkey *कुञ्चिका,
    u_char **sigp, size_t *lenp, ध्रुव u_char *data, size_t datalen,
    ध्रुव वर्ण *alg, ध्रुव वर्ण *sk_provider, ध्रुव वर्ण *sk_pin,
    u_int compat)
{
	u_char sig[MLDSA44_ED25519_SIG_SZ];
	संरचना sshbuf *b = रिक्त;
	पूर्णाङ्क r = SSH_ERR_INTERNAL_ERROR;

	सचे (lenp != रिक्त)
		*lenp = 0;
	सचे (sigp != रिक्त)
		*sigp = रिक्त;

	सचे (कुञ्चिका == रिक्त ||
	    sshkey_type_plain(कुञ्चिका->type) != कुञ्चिका_MLDSA44_ED25519 ||
	    कुञ्चिका->mldsa_ed25519_sk == रिक्त)
		पटिनिवत्त SSH_ERR_INVALID_ARGUMENT;

	सचे (crypto_sign_mldsa44_ed25519_sign(sig, data, datalen, रिक्त, 0,
	    कुञ्चिका->mldsa_ed25519_sk) != 0) {
		r = SSH_ERR_CRYPTO_ERROR;
		गच्छ out;
	}

	सचे ((b = sshbuf_new()) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ out;
	}
	सचे ((r = sshbuf_put_cstring(b, SSH_MLDSA44_ED25519_ALG_NAME)) != 0 ||
	    (r = sshbuf_put_string(b, sig, परिमाण(sig))) != 0)
		गच्छ out;

	सचे (sigp != रिक्त) {
		सचे ((*sigp = malloc(sshbuf_len(b))) == रिक्त) {
			r = SSH_ERR_ALLOC_FAIL;
			गच्छ out;
		}
		memcpy(*sigp, sshbuf_ptr(b), sshbuf_len(b));
	}
	सचे (lenp != रिक्त)
		*lenp = sshbuf_len(b);
	r = 0;
 out:
	sshbuf_free(b);
	explicit_bzero(sig, परिमाण(sig));
	पटिनिवत्त r;
}

स्थिर पूर्णाङ्क
ssh_mldsa44_ed25519_verify(ध्रुव संरचना sshkey *कुञ्चिका,
    ध्रुव u_char *sig, size_t siglen, ध्रुव u_char *data, size_t dlen,
    ध्रुव वर्ण *alg, u_int compat, संरचना sshkey_sig_details **detailsp)
{
	संरचना sshbuf *b = रिक्त;
	वर्ण *ktype = रिक्त;
	ध्रुव u_char *sigblob;
	size_t len;
	पूर्णाङ्क r;

	सचे (कुञ्चिका == रिक्त ||
	    sshkey_type_plain(कुञ्चिका->type) != कुञ्चिका_MLDSA44_ED25519 ||
	    कुञ्चिका->mldsa_ed25519_pk == रिक्त ||
	    sig == रिक्त || siglen == 0)
		पटिनिवत्त SSH_ERR_INVALID_ARGUMENT;

	सचे ((b = sshbuf_from(sig, siglen)) == रिक्त)
		पटिनिवत्त SSH_ERR_ALLOC_FAIL;
	सचे ((r = sshbuf_get_cstring(b, &ktype, रिक्त)) != 0 ||
	    (r = sshbuf_get_string_direct(b, &sigblob, &len)) != 0)
		गच्छ out;
	सचे (strcmp(SSH_MLDSA44_ED25519_ALG_NAME, ktype) != 0) {
		r = SSH_ERR_कुञ्चिका_TYPE_MISMATCH;
		गच्छ out;
	}
	सचे (sshbuf_len(b) != 0) {
		r = SSH_ERR_UNEXPECTED_TRAILING_DATA;
		गच्छ out;
	}
	सचे (len != MLDSA44_ED25519_SIG_SZ) {
		r = SSH_ERR_INVALID_FORMAT;
		गच्छ out;
	}

	सचे (crypto_sign_mldsa44_ed25519_verify(sigblob, data, dlen, रिक्त, 0,
	    कुञ्चिका->mldsa_ed25519_pk) != 0) {
		r = SSH_ERR_SIGNATURE_INVALID;
		गच्छ out;
	}

	r = 0;
 out:
	sshbuf_free(b);
	मुक्त(ktype);
	पटिनिवत्त r;
}

ध्रुव संरचना sshkey_impl_funcs sshkey_mldsa44_ed25519_funcs = {
	/* .size = */		रिक्त,
	/* .alloc = */		रिक्त,
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

ध्रुव संरचना sshkey_impl sshkey_mldsa44_ed25519_impl = {
	/* .name = */		"ssh-mldsa44-ed25519",
	/* .shortname = */	"MLDSA44-ED25519",
	/* .sigalg = */		रिक्त,
	/* .type = */		कुञ्चिका_MLDSA44_ED25519,
	/* .nid = */		0,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	512, /* size of the private key */
	/* .funcs = */		&sshkey_mldsa44_ed25519_funcs,
};

ध्रुव संरचना sshkey_impl sshkey_mldsa44_ed25519_cert_impl = {
	/* .name = */		"ssh-mldsa44-ed25519-cert",
	/* .shortname = */	"MLDSA44-ED25519-CERT",
	/* .sigalg = */		रिक्त,
	/* .type = */		कुञ्चिका_MLDSA44_ED25519_CERT,
	/* .nid = */		0,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	512, /* size of the private key */
	/* .funcs = */		&sshkey_mldsa44_ed25519_funcs,
};
#endif /* USE_MLDSA */
