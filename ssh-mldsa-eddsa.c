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

#அந்தர்பாவ "includes.h"

#ifdef USE_MLDSA

#அந்தர்பாவ <sys/types.h>
#அந்தர்பாவ <stdint.h>
#அந்தர்பாவ <string.h>
#அந்தர்பாவ <stdlib.h>

#அந்தர்பாவ "crypto_api.h"
#அந்தர்பாவ "sshbuf.h"
#அந்தர்பாவ "ssherr.h"
#அந்தர்பாவ "digest.h"
#define SSHKEY_INTERNAL
#அந்தர்பாவ "sshkey.h"
#அந்தர்பாவ "log.h"

#define COMPOSITE_PREFIX "CompositeAlgorithmSignatures2025"
#define COMPOSITE_LABEL  "COMPSIG-MLDSA44-Ed25519-SHA512"
#define SSH_MLDSA44_ED25519_ALG_NAME   "ssh-mldsa44-ed25519"

/*
 * raw_* functions implement the draft-ietf-lamps-pq-composite-sigs-18
 * composite signature scheme. These are exposed (i.e. not static) so
 * we can test them separately in unittests/crypto.
 */

முழு
crypto_sign_mldsa44_ed25519_keygen(uint8_t pk[MLDSA44_ED25519_PK_SZ],
    uint8_t sk[MLDSA44_ED25519_SK_SZ])
{
	uint8_t mldsa_seed[MLDSA44_SEEDBYTES];
	uint8_t ed25519_seed[crypto_sign_ed25519_SEEDBYTES];
	முழு r;

	arc4random_buf(mldsa_seed, அளவு(mldsa_seed));
	arc4random_buf(ed25519_seed, அளவு(ed25519_seed));

	r = crypto_sign_mldsa44_ed25519_keygen_seeded(pk, sk, mldsa_seed,
	    ed25519_seed);
	explicit_bzero(mldsa_seed, அளவு(mldsa_seed));
	explicit_bzero(ed25519_seed, அளவு(ed25519_seed));
	திரும்பு r;
}

முழு
crypto_sign_mldsa44_ed25519_keygen_seeded(uint8_t pk[MLDSA44_ED25519_PK_SZ],
    uint8_t sk[MLDSA44_ED25519_SK_SZ],
    மாறிலி uint8_t mldsa_seed[MLDSA44_SEEDBYTES],
    மாறிலி uint8_t ed25519_seed[crypto_sign_ed25519_SEEDBYTES])
{
	uint8_t ed25519_pk[MLDSA44_SEEDBYTES];
	uint8_t ed25519_sk[crypto_sign_ed25519_SECRETKEYBYTES];
	uint8_t mldsa_sk[MLDSA44_SECRETKEYBYTES];
	முழு ret = -1;

	எனில் (crypto_sign_mldsa44_keypair_seeded(pk, mldsa_sk, mldsa_seed) != 0)
		செல் out;
	எனில் (crypto_sign_ed25519_seed_keypair(ed25519_pk, ed25519_sk,
	    ed25519_seed) != 0)
		செல் out;

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
	explicit_bzero(mldsa_sk, அளவு(mldsa_sk));
	explicit_bzero(ed25519_sk, அளவு(ed25519_sk));
	திரும்பு ret;
}

நிலையான முழு
construct_m_பகாஎண்(uint8_t **m_primep, size_t *m_பகாஎண்_lenp,
    மாறிலி uint8_t *செய்தி, size_t msglen,
    மாறிலி uint8_t *ctx, size_t ctxlen)
{
	முழு r;
	uint8_t hash[64];
	கட்டமைப்பு sshbuf *m_பகாஎண்;

	*m_primep = வெற்று;
	*m_பகாஎண்_lenp = 0;

	எனில் (ctxlen > 255)
		திரும்பு SSH_ERR_INVALID_ARGUMENT;
	எனில் ((r = ssh_digest_memory(SSH_DIGEST_SHA512, செய்தி, msglen,
	    hash, அளவு(hash))) != 0)
		திரும்பு r;
	எனில் ((m_பகாஎண் = sshbuf_new()) == வெற்று)
		திரும்பு SSH_ERR_ALLOC_FAIL;
	எனில் ((r = sshbuf_put(m_பகாஎண், COMPOSITE_PREFIX,
	    அளவு(COMPOSITE_PREFIX) - 1)) != 0 ||
	    (r = sshbuf_put(m_பகாஎண், COMPOSITE_LABEL,
	    அளவு(COMPOSITE_LABEL) - 1)) != 0 ||
	    (r = sshbuf_put_u8(m_பகாஎண், (uint8_t)ctxlen)) != 0 ||
	    (r = sshbuf_put(m_பகாஎண், ctx, ctxlen)) != 0 ||
	    (r = sshbuf_put(m_பகாஎண், hash, அளவு(hash))) != 0) {
		sshbuf_free(m_பகாஎண்);
		திரும்பு r;
	}
	எனில் ((*m_primep = malloc(sshbuf_len(m_பகாஎண்))) == வெற்று) {
		sshbuf_free(m_பகாஎண்);
		திரும்பு SSH_ERR_ALLOC_FAIL;
	}
	memcpy(*m_primep, sshbuf_ptr(m_பகாஎண்), sshbuf_len(m_பகாஎண்));
	*m_பகாஎண்_lenp = sshbuf_len(m_பகாஎண்);
	/* success */
	sshbuf_free(m_பகாஎண்);
	திரும்பு 0;
}

முழு
crypto_sign_mldsa44_ed25519_sign(uint8_t sig[MLDSA44_ED25519_SIG_SZ],
    மாறிலி uint8_t *செய்தி, size_t msglen,
    மாறிலி uint8_t *ctx, size_t ctxlen,
    மாறிலி uint8_t sk[MLDSA44_ED25519_SK_SZ])
{
	uint8_t *m_பகாஎண் = வெற்று;
	size_t m_பகாஎண்_len = 0;
	uint8_t mldsa_sk[MLDSA44_SECRETKEYBYTES];
	uint8_t mldsa_pk_dummy[MLDSA44_PUBLICKEYBYTES];
	uint8_t ed25519_pk[crypto_sign_ed25519_PUBLICKEYBYTES];
	uint8_t ed25519_sk[crypto_sign_ed25519_SECRETKEYBYTES];
	uint8_t mldsa_rnd[MLDSA44_SEEDBYTES];
	unsigned long long smlen;
	முழு r = -1;

	எனில் (construct_m_பகாஎண்(&m_பகாஎண், &m_பகாஎண்_len, செய்தி, msglen,
	    ctx, ctxlen) != 0)
		திரும்பு -1;

	/* Expand ML-DSA key from seed */
	எனில் (crypto_sign_mldsa44_keypair_seeded(mldsa_pk_dummy, mldsa_sk, sk) != 0)
		செல் out;

	/* Sign with ML-DSA */
	arc4random_buf(mldsa_rnd, அளவு(mldsa_rnd));
	எனில் (crypto_sign_mldsa44_seeded(sig, m_பகாஎண், m_பகாஎண்_len,
	    (மாறிலி uint8_t *)COMPOSITE_LABEL, அளவு(COMPOSITE_LABEL) - 1,
	    mldsa_sk, mldsa_rnd) != 0)
		செல் out;

	/* Expand Ed25519 key from seed */
	எனில் (crypto_sign_ed25519_seed_keypair(ed25519_pk, ed25519_sk,
	    sk + MLDSA44_SEEDBYTES) != 0)
		செல் out;

	/* Sign with Ed25519 */
	எனில் (crypto_sign_ed25519_detached(sig + MLDSA44_SIGBYTES, &smlen,
	    m_பகாஎண், m_பகாஎண்_len, ed25519_sk) != 0 ||
	    smlen != crypto_sign_ed25519_BYTES)
		செல் out;

	r = 0;
 out:
	விடுவி(m_பகாஎண்);
	explicit_bzero(mldsa_rnd, அளவு(mldsa_rnd));
	explicit_bzero(mldsa_sk, அளவு(mldsa_sk));
	explicit_bzero(ed25519_sk, அளவு(ed25519_sk));
	திரும்பு r;
}

முழு
crypto_sign_mldsa44_ed25519_verify(மாறிலி uint8_t sig[MLDSA44_ED25519_SIG_SZ],
    மாறிலி uint8_t *செய்தி, size_t msglen,
    மாறிலி uint8_t *ctx, size_t ctxlen,
    மாறிலி uint8_t pk[MLDSA44_ED25519_PK_SZ])
{
	uint8_t *m_பகாஎண் = வெற்று;
	size_t m_பகாஎண்_len = 0;
	முழு r = -1;

	எனில் (construct_m_பகாஎண்(&m_பகாஎண், &m_பகாஎண்_len, செய்தி, msglen,
	    ctx, ctxlen) != 0)
		திரும்பு -1;

	/* Verify ML-DSA */
	எனில் (crypto_sign_mldsa44_verify(sig, m_பகாஎண், m_பகாஎண்_len,
	    (மாறிலி uint8_t *)COMPOSITE_LABEL, அளவு(COMPOSITE_LABEL) - 1,
	    pk) != 0)
		செல் out;

	/* Verify Ed25519 */
	எனில் (crypto_sign_ed25519_verify_detached(sig + MLDSA44_SIGBYTES,
	    m_பகாஎண், m_பகாஎண்_len, pk + MLDSA44_PUBLICKEYBYTES) != 0)
		செல் out;

	r = 0;
 out:
	விடுவி(m_பகாஎண்);
	திரும்பு r;
}

/* sshkey integration */

நிலையான வெறுமை
ssh_mldsa44_ed25519_cleanup(கட்டமைப்பு sshkey *k)
{
	freezero(k->mldsa_ed25519_pk, MLDSA44_ED25519_PK_SZ);
	freezero(k->mldsa_ed25519_sk, MLDSA44_ED25519_SK_SZ);
	k->mldsa_ed25519_pk = வெற்று;
	k->mldsa_ed25519_sk = வெற்று;
}

நிலையான முழு
ssh_mldsa44_ed25519_equal(மாறிலி கட்டமைப்பு sshkey *a, மாறிலி கட்டமைப்பு sshkey *b)
{
	எனில் (a->mldsa_ed25519_pk == வெற்று || b->mldsa_ed25519_pk == வெற்று)
		திரும்பு 0;
	எனில் (memcmp(a->mldsa_ed25519_pk, b->mldsa_ed25519_pk,
	    MLDSA44_ED25519_PK_SZ) != 0)
		திரும்பு 0;
	திரும்பு 1;
}

நிலையான முழு
ssh_mldsa44_ed25519_serialize_public(மாறிலி கட்டமைப்பு sshkey *சாவி, கட்டமைப்பு sshbuf *b,
    எண்ணிக்கை sshkey_serialize_rep opts)
{
	முழு r;

	எனில் (சாவி->mldsa_ed25519_pk == வெற்று)
		திரும்பு SSH_ERR_INVALID_ARGUMENT;
	எனில் ((r = sshbuf_put_string(b, சாவி->mldsa_ed25519_pk,
	    MLDSA44_ED25519_PK_SZ)) != 0)
		திரும்பு r;

	திரும்பு 0;
}

நிலையான முழு
ssh_mldsa44_ed25519_serialize_private(மாறிலி கட்டமைப்பு sshkey *சாவி, கட்டமைப்பு sshbuf *b,
    எண்ணிக்கை sshkey_serialize_rep opts)
{
	முழு r;

	எனில் (சாவி->mldsa_ed25519_sk == வெற்று)
		திரும்பு SSH_ERR_INVALID_ARGUMENT;
	எனில் (!sshkey_is_cert(சாவி)) {
		எனில் ((r = ssh_mldsa44_ed25519_serialize_public(சாவி,
		    b, opts)) != 0)
			திரும்பு r;
	}
	எனில் ((r = sshbuf_put_string(b, சாவி->mldsa_ed25519_sk,
	    MLDSA44_ED25519_SK_SZ)) != 0)
		திரும்பு r;

	திரும்பு 0;
}

நிலையான முழு
ssh_mldsa44_ed25519_deserialize_public(மாறிலி எழுத்து *ktype, கட்டமைப்பு sshbuf *b,
    கட்டமைப்பு sshkey *சாவி)
{
	u_char *pk = வெற்று;
	size_t len = 0;
	முழு r;

	எனில் ((r = sshbuf_get_string(b, &pk, &len)) != 0)
		திரும்பு r;
	எனில் (len != MLDSA44_ED25519_PK_SZ) {
		freezero(pk, len);
		திரும்பு SSH_ERR_INVALID_FORMAT;
	}
	சாவி->mldsa_ed25519_pk = pk;
	திரும்பு 0;
}

நிலையான முழு
ssh_mldsa44_ed25519_deserialize_private(மாறிலி எழுத்து *ktype, கட்டமைப்பு sshbuf *b,
    கட்டமைப்பு sshkey *சாவி)
{
	முழு r;
	size_t sklen = 0;
	u_char *sk = வெற்று;

	எனில் (!sshkey_is_cert(சாவி)) {
		எனில் ((r = ssh_mldsa44_ed25519_deserialize_public(ktype,
		    b, சாவி)) != 0)
			திரும்பு r;
	}
	எனில் ((r = sshbuf_get_string(b, &sk, &sklen)) != 0)
		செல் out;
	எனில் (sklen != MLDSA44_ED25519_SK_SZ) {
		r = SSH_ERR_INVALID_FORMAT;
		செல் out;
	}
	சாவி->mldsa_ed25519_sk = sk;
	sk = வெற்று; /* transferred */
	r = 0;
 out:
	freezero(sk, sklen);
	திரும்பு r;
}

நிலையான முழு
ssh_mldsa44_ed25519_generate(கட்டமைப்பு sshkey *k, முழு bits)
{
	ssh_mldsa44_ed25519_cleanup(k);
	எனில் ((k->mldsa_ed25519_pk = malloc(MLDSA44_ED25519_PK_SZ)) == வெற்று ||
	    (k->mldsa_ed25519_sk = malloc(MLDSA44_ED25519_SK_SZ)) == வெற்று) {
		ssh_mldsa44_ed25519_cleanup(k);
		திரும்பு SSH_ERR_ALLOC_FAIL;
	}
	எனில் (crypto_sign_mldsa44_ed25519_keygen(k->mldsa_ed25519_pk,
	    k->mldsa_ed25519_sk) != 0) {
		ssh_mldsa44_ed25519_cleanup(k);
		திரும்பு SSH_ERR_CRYPTO_ERROR;
	}
	திரும்பு 0;
}

நிலையான முழு
ssh_mldsa44_ed25519_copy_public(மாறிலி கட்டமைப்பு sshkey *from, கட்டமைப்பு sshkey *to)
{
	எனில் (from->mldsa_ed25519_pk == வெற்று)
		திரும்பு SSH_ERR_INVALID_ARGUMENT;
	எனில் ((to->mldsa_ed25519_pk = malloc(MLDSA44_ED25519_PK_SZ)) == வெற்று)
		திரும்பு SSH_ERR_ALLOC_FAIL;
	memcpy(to->mldsa_ed25519_pk, from->mldsa_ed25519_pk,
	    MLDSA44_ED25519_PK_SZ);
	திரும்பு 0;
}

நிலையான முழு
ssh_mldsa44_ed25519_sign(கட்டமைப்பு sshkey *சாவி,
    u_char **sigp, size_t *lenp, மாறிலி u_char *data, size_t datalen,
    மாறிலி எழுத்து *alg, மாறிலி எழுத்து *sk_provider, மாறிலி எழுத்து *sk_pin,
    u_int compat)
{
	u_char sig[MLDSA44_ED25519_SIG_SZ];
	கட்டமைப்பு sshbuf *b = வெற்று;
	முழு r = SSH_ERR_INTERNAL_ERROR;

	எனில் (lenp != வெற்று)
		*lenp = 0;
	எனில் (sigp != வெற்று)
		*sigp = வெற்று;

	எனில் (சாவி == வெற்று ||
	    sshkey_type_plain(சாவி->type) != சாவி_MLDSA44_ED25519 ||
	    சாவி->mldsa_ed25519_sk == வெற்று)
		திரும்பு SSH_ERR_INVALID_ARGUMENT;

	எனில் (crypto_sign_mldsa44_ed25519_sign(sig, data, datalen, வெற்று, 0,
	    சாவி->mldsa_ed25519_sk) != 0) {
		r = SSH_ERR_CRYPTO_ERROR;
		செல் out;
	}

	எனில் ((b = sshbuf_new()) == வெற்று) {
		r = SSH_ERR_ALLOC_FAIL;
		செல் out;
	}
	எனில் ((r = sshbuf_put_cstring(b, SSH_MLDSA44_ED25519_ALG_NAME)) != 0 ||
	    (r = sshbuf_put_string(b, sig, அளவு(sig))) != 0)
		செல் out;

	எனில் (sigp != வெற்று) {
		எனில் ((*sigp = malloc(sshbuf_len(b))) == வெற்று) {
			r = SSH_ERR_ALLOC_FAIL;
			செல் out;
		}
		memcpy(*sigp, sshbuf_ptr(b), sshbuf_len(b));
	}
	எனில் (lenp != வெற்று)
		*lenp = sshbuf_len(b);
	r = 0;
 out:
	sshbuf_free(b);
	explicit_bzero(sig, அளவு(sig));
	திரும்பு r;
}

நிலையான முழு
ssh_mldsa44_ed25519_verify(மாறிலி கட்டமைப்பு sshkey *சாவி,
    மாறிலி u_char *sig, size_t siglen, மாறிலி u_char *data, size_t dlen,
    மாறிலி எழுத்து *alg, u_int compat, கட்டமைப்பு sshkey_sig_details **detailsp)
{
	கட்டமைப்பு sshbuf *b = வெற்று;
	எழுத்து *ktype = வெற்று;
	மாறிலி u_char *sigblob;
	size_t len;
	முழு r;

	எனில் (சாவி == வெற்று ||
	    sshkey_type_plain(சாவி->type) != சாவி_MLDSA44_ED25519 ||
	    சாவி->mldsa_ed25519_pk == வெற்று ||
	    sig == வெற்று || siglen == 0)
		திரும்பு SSH_ERR_INVALID_ARGUMENT;

	எனில் ((b = sshbuf_from(sig, siglen)) == வெற்று)
		திரும்பு SSH_ERR_ALLOC_FAIL;
	எனில் ((r = sshbuf_get_cstring(b, &ktype, வெற்று)) != 0 ||
	    (r = sshbuf_get_string_direct(b, &sigblob, &len)) != 0)
		செல் out;
	எனில் (strcmp(SSH_MLDSA44_ED25519_ALG_NAME, ktype) != 0) {
		r = SSH_ERR_சாவி_TYPE_MISMATCH;
		செல் out;
	}
	எனில் (sshbuf_len(b) != 0) {
		r = SSH_ERR_UNEXPECTED_TRAILING_DATA;
		செல் out;
	}
	எனில் (len != MLDSA44_ED25519_SIG_SZ) {
		r = SSH_ERR_INVALID_FORMAT;
		செல் out;
	}

	எனில் (crypto_sign_mldsa44_ed25519_verify(sigblob, data, dlen, வெற்று, 0,
	    சாவி->mldsa_ed25519_pk) != 0) {
		r = SSH_ERR_SIGNATURE_INVALID;
		செல் out;
	}

	r = 0;
 out:
	sshbuf_free(b);
	விடுவி(ktype);
	திரும்பு r;
}

மாறிலி கட்டமைப்பு sshkey_impl_funcs sshkey_mldsa44_ed25519_funcs = {
	/* .size = */		வெற்று,
	/* .alloc = */		வெற்று,
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

மாறிலி கட்டமைப்பு sshkey_impl sshkey_mldsa44_ed25519_impl = {
	/* .name = */		"ssh-mldsa44-ed25519",
	/* .shortname = */	"MLDSA44-ED25519",
	/* .sigalg = */		வெற்று,
	/* .type = */		சாவி_MLDSA44_ED25519,
	/* .nid = */		0,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	512, /* size of the private key */
	/* .funcs = */		&sshkey_mldsa44_ed25519_funcs,
};

மாறிலி கட்டமைப்பு sshkey_impl sshkey_mldsa44_ed25519_cert_impl = {
	/* .name = */		"ssh-mldsa44-ed25519-cert",
	/* .shortname = */	"MLDSA44-ED25519-CERT",
	/* .sigalg = */		வெற்று,
	/* .type = */		சாவி_MLDSA44_ED25519_CERT,
	/* .nid = */		0,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	512, /* size of the private key */
	/* .funcs = */		&sshkey_mldsa44_ed25519_funcs,
};
#endif /* USE_MLDSA */
