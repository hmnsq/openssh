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

#અન્તર્ભાવ "includes.h"

#ifdef USE_MLDSA

#અન્તર્ભાવ <sys/types.h>
#અન્તર્ભાવ <stdint.h>
#અન્તર્ભાવ <string.h>
#અન્તર્ભાવ <stdlib.h>

#અન્તર્ભાવ "crypto_api.h"
#અન્તર્ભાવ "sshbuf.h"
#અન્તર્ભાવ "ssherr.h"
#અન્તર્ભાવ "digest.h"
#define SSHKEY_INTERNAL
#અન્તર્ભાવ "sshkey.h"
#અન્તર્ભાવ "log.h"

#define COMPOSITE_PREFIX "CompositeAlgorithmSignatures2025"
#define COMPOSITE_LABEL  "COMPSIG-MLDSA44-Ed25519-SHA512"
#define SSH_MLDSA44_ED25519_ALG_NAME   "ssh-mldsa44-ed25519"

/*
 * raw_* functions implement the draft-ietf-lamps-pq-composite-sigs-18
 * composite signature scheme. These are exposed (i.e. not static) so
 * we can test them separately in unittests/crypto.
 */

પૂર્ણાંક
crypto_sign_mldsa44_ed25519_keygen(uint8_t pk[MLDSA44_ED25519_PK_SZ],
    uint8_t sk[MLDSA44_ED25519_SK_SZ])
{
	uint8_t mldsa_seed[MLDSA44_SEEDBYTES];
	uint8_t ed25519_seed[crypto_sign_ed25519_SEEDBYTES];
	પૂર્ણાંક r;

	arc4random_buf(mldsa_seed, કદ(mldsa_seed));
	arc4random_buf(ed25519_seed, કદ(ed25519_seed));

	r = crypto_sign_mldsa44_ed25519_keygen_seeded(pk, sk, mldsa_seed,
	    ed25519_seed);
	explicit_bzero(mldsa_seed, કદ(mldsa_seed));
	explicit_bzero(ed25519_seed, કદ(ed25519_seed));
	પાછા r;
}

પૂર્ણાંક
crypto_sign_mldsa44_ed25519_keygen_seeded(uint8_t pk[MLDSA44_ED25519_PK_SZ],
    uint8_t sk[MLDSA44_ED25519_SK_SZ],
    અચલ uint8_t mldsa_seed[MLDSA44_SEEDBYTES],
    અચલ uint8_t ed25519_seed[crypto_sign_ed25519_SEEDBYTES])
{
	uint8_t ed25519_pk[MLDSA44_SEEDBYTES];
	uint8_t ed25519_sk[crypto_sign_ed25519_SECRETKEYBYTES];
	uint8_t mldsa_sk[MLDSA44_SECRETKEYBYTES];
	પૂર્ણાંક ret = -1;

	જો (crypto_sign_mldsa44_keypair_seeded(pk, mldsa_sk, mldsa_seed) != 0)
		જાઓ out;
	જો (crypto_sign_ed25519_seed_keypair(ed25519_pk, ed25519_sk,
	    ed25519_seed) != 0)
		જાઓ out;

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
	explicit_bzero(mldsa_sk, કદ(mldsa_sk));
	explicit_bzero(ed25519_sk, કદ(ed25519_sk));
	પાછા ret;
}

સ્થિર પૂર્ણાંક
construct_m_અવિભાજ્ય(uint8_t **m_primep, size_t *m_અવિભાજ્ય_lenp,
    અચલ uint8_t *સંદેશ, size_t msglen,
    અચલ uint8_t *ctx, size_t ctxlen)
{
	પૂર્ણાંક r;
	uint8_t hash[64];
	સંરચના sshbuf *m_અવિભાજ્ય;

	*m_primep = ખાલી;
	*m_અવિભાજ્ય_lenp = 0;

	જો (ctxlen > 255)
		પાછા SSH_ERR_INVALID_ARGUMENT;
	જો ((r = ssh_digest_memory(SSH_DIGEST_SHA512, સંદેશ, msglen,
	    hash, કદ(hash))) != 0)
		પાછા r;
	જો ((m_અવિભાજ્ય = sshbuf_new()) == ખાલી)
		પાછા SSH_ERR_ALLOC_FAIL;
	જો ((r = sshbuf_put(m_અવિભાજ્ય, COMPOSITE_PREFIX,
	    કદ(COMPOSITE_PREFIX) - 1)) != 0 ||
	    (r = sshbuf_put(m_અવિભાજ્ય, COMPOSITE_LABEL,
	    કદ(COMPOSITE_LABEL) - 1)) != 0 ||
	    (r = sshbuf_put_u8(m_અવિભાજ્ય, (uint8_t)ctxlen)) != 0 ||
	    (r = sshbuf_put(m_અવિભાજ્ય, ctx, ctxlen)) != 0 ||
	    (r = sshbuf_put(m_અવિભાજ્ય, hash, કદ(hash))) != 0) {
		sshbuf_free(m_અવિભાજ્ય);
		પાછા r;
	}
	જો ((*m_primep = malloc(sshbuf_len(m_અવિભાજ્ય))) == ખાલી) {
		sshbuf_free(m_અવિભાજ્ય);
		પાછા SSH_ERR_ALLOC_FAIL;
	}
	memcpy(*m_primep, sshbuf_ptr(m_અવિભાજ્ય), sshbuf_len(m_અવિભાજ્ય));
	*m_અવિભાજ્ય_lenp = sshbuf_len(m_અવિભાજ્ય);
	/* success */
	sshbuf_free(m_અવિભાજ્ય);
	પાછા 0;
}

પૂર્ણાંક
crypto_sign_mldsa44_ed25519_sign(uint8_t sig[MLDSA44_ED25519_SIG_SZ],
    અચલ uint8_t *સંદેશ, size_t msglen,
    અચલ uint8_t *ctx, size_t ctxlen,
    અચલ uint8_t sk[MLDSA44_ED25519_SK_SZ])
{
	uint8_t *m_અવિભાજ્ય = ખાલી;
	size_t m_અવિભાજ્ય_len = 0;
	uint8_t mldsa_sk[MLDSA44_SECRETKEYBYTES];
	uint8_t mldsa_pk_dummy[MLDSA44_PUBLICKEYBYTES];
	uint8_t ed25519_pk[crypto_sign_ed25519_PUBLICKEYBYTES];
	uint8_t ed25519_sk[crypto_sign_ed25519_SECRETKEYBYTES];
	uint8_t mldsa_rnd[MLDSA44_SEEDBYTES];
	unsigned long long smlen;
	પૂર્ણાંક r = -1;

	જો (construct_m_અવિભાજ્ય(&m_અવિભાજ્ય, &m_અવિભાજ્ય_len, સંદેશ, msglen,
	    ctx, ctxlen) != 0)
		પાછા -1;

	/* Expand ML-DSA key from seed */
	જો (crypto_sign_mldsa44_keypair_seeded(mldsa_pk_dummy, mldsa_sk, sk) != 0)
		જાઓ out;

	/* Sign with ML-DSA */
	arc4random_buf(mldsa_rnd, કદ(mldsa_rnd));
	જો (crypto_sign_mldsa44_seeded(sig, m_અવિભાજ્ય, m_અવિભાજ્ય_len,
	    (અચલ uint8_t *)COMPOSITE_LABEL, કદ(COMPOSITE_LABEL) - 1,
	    mldsa_sk, mldsa_rnd) != 0)
		જાઓ out;

	/* Expand Ed25519 key from seed */
	જો (crypto_sign_ed25519_seed_keypair(ed25519_pk, ed25519_sk,
	    sk + MLDSA44_SEEDBYTES) != 0)
		જાઓ out;

	/* Sign with Ed25519 */
	જો (crypto_sign_ed25519_detached(sig + MLDSA44_SIGBYTES, &smlen,
	    m_અવિભાજ્ય, m_અવિભાજ્ય_len, ed25519_sk) != 0 ||
	    smlen != crypto_sign_ed25519_BYTES)
		જાઓ out;

	r = 0;
 out:
	મુક્ત(m_અવિભાજ્ય);
	explicit_bzero(mldsa_rnd, કદ(mldsa_rnd));
	explicit_bzero(mldsa_sk, કદ(mldsa_sk));
	explicit_bzero(ed25519_sk, કદ(ed25519_sk));
	પાછા r;
}

પૂર્ણાંક
crypto_sign_mldsa44_ed25519_verify(અચલ uint8_t sig[MLDSA44_ED25519_SIG_SZ],
    અચલ uint8_t *સંદેશ, size_t msglen,
    અચલ uint8_t *ctx, size_t ctxlen,
    અચલ uint8_t pk[MLDSA44_ED25519_PK_SZ])
{
	uint8_t *m_અવિભાજ્ય = ખાલી;
	size_t m_અવિભાજ્ય_len = 0;
	પૂર્ણાંક r = -1;

	જો (construct_m_અવિભાજ્ય(&m_અવિભાજ્ય, &m_અવિભાજ્ય_len, સંદેશ, msglen,
	    ctx, ctxlen) != 0)
		પાછા -1;

	/* Verify ML-DSA */
	જો (crypto_sign_mldsa44_verify(sig, m_અવિભાજ્ય, m_અવિભાજ્ય_len,
	    (અચલ uint8_t *)COMPOSITE_LABEL, કદ(COMPOSITE_LABEL) - 1,
	    pk) != 0)
		જાઓ out;

	/* Verify Ed25519 */
	જો (crypto_sign_ed25519_verify_detached(sig + MLDSA44_SIGBYTES,
	    m_અવિભાજ્ય, m_અવિભાજ્ય_len, pk + MLDSA44_PUBLICKEYBYTES) != 0)
		જાઓ out;

	r = 0;
 out:
	મુક્ત(m_અવિભાજ્ય);
	પાછા r;
}

/* sshkey integration */

સ્થિર શૂન્ય
ssh_mldsa44_ed25519_cleanup(સંરચના sshkey *k)
{
	freezero(k->mldsa_ed25519_pk, MLDSA44_ED25519_PK_SZ);
	freezero(k->mldsa_ed25519_sk, MLDSA44_ED25519_SK_SZ);
	k->mldsa_ed25519_pk = ખાલી;
	k->mldsa_ed25519_sk = ખાલી;
}

સ્થિર પૂર્ણાંક
ssh_mldsa44_ed25519_equal(અચલ સંરચના sshkey *a, અચલ સંરચના sshkey *b)
{
	જો (a->mldsa_ed25519_pk == ખાલી || b->mldsa_ed25519_pk == ખાલી)
		પાછા 0;
	જો (memcmp(a->mldsa_ed25519_pk, b->mldsa_ed25519_pk,
	    MLDSA44_ED25519_PK_SZ) != 0)
		પાછા 0;
	પાછા 1;
}

સ્થિર પૂર્ણાંક
ssh_mldsa44_ed25519_serialize_public(અચલ સંરચના sshkey *ચાવી, સંરચના sshbuf *b,
    ગણના sshkey_serialize_rep opts)
{
	પૂર્ણાંક r;

	જો (ચાવી->mldsa_ed25519_pk == ખાલી)
		પાછા SSH_ERR_INVALID_ARGUMENT;
	જો ((r = sshbuf_put_string(b, ચાવી->mldsa_ed25519_pk,
	    MLDSA44_ED25519_PK_SZ)) != 0)
		પાછા r;

	પાછા 0;
}

સ્થિર પૂર્ણાંક
ssh_mldsa44_ed25519_serialize_private(અચલ સંરચના sshkey *ચાવી, સંરચના sshbuf *b,
    ગણના sshkey_serialize_rep opts)
{
	પૂર્ણાંક r;

	જો (ચાવી->mldsa_ed25519_sk == ખાલી)
		પાછા SSH_ERR_INVALID_ARGUMENT;
	જો (!sshkey_is_cert(ચાવી)) {
		જો ((r = ssh_mldsa44_ed25519_serialize_public(ચાવી,
		    b, opts)) != 0)
			પાછા r;
	}
	જો ((r = sshbuf_put_string(b, ચાવી->mldsa_ed25519_sk,
	    MLDSA44_ED25519_SK_SZ)) != 0)
		પાછા r;

	પાછા 0;
}

સ્થિર પૂર્ણાંક
ssh_mldsa44_ed25519_deserialize_public(અચલ અક્ષર *ktype, સંરચના sshbuf *b,
    સંરચના sshkey *ચાવી)
{
	u_char *pk = ખાલી;
	size_t len = 0;
	પૂર્ણાંક r;

	જો ((r = sshbuf_get_string(b, &pk, &len)) != 0)
		પાછા r;
	જો (len != MLDSA44_ED25519_PK_SZ) {
		freezero(pk, len);
		પાછા SSH_ERR_INVALID_FORMAT;
	}
	ચાવી->mldsa_ed25519_pk = pk;
	પાછા 0;
}

સ્થિર પૂર્ણાંક
ssh_mldsa44_ed25519_deserialize_private(અચલ અક્ષર *ktype, સંરચના sshbuf *b,
    સંરચના sshkey *ચાવી)
{
	પૂર્ણાંક r;
	size_t sklen = 0;
	u_char *sk = ખાલી;

	જો (!sshkey_is_cert(ચાવી)) {
		જો ((r = ssh_mldsa44_ed25519_deserialize_public(ktype,
		    b, ચાવી)) != 0)
			પાછા r;
	}
	જો ((r = sshbuf_get_string(b, &sk, &sklen)) != 0)
		જાઓ out;
	જો (sklen != MLDSA44_ED25519_SK_SZ) {
		r = SSH_ERR_INVALID_FORMAT;
		જાઓ out;
	}
	ચાવી->mldsa_ed25519_sk = sk;
	sk = ખાલી; /* transferred */
	r = 0;
 out:
	freezero(sk, sklen);
	પાછા r;
}

સ્થિર પૂર્ણાંક
ssh_mldsa44_ed25519_generate(સંરચના sshkey *k, પૂર્ણાંક bits)
{
	ssh_mldsa44_ed25519_cleanup(k);
	જો ((k->mldsa_ed25519_pk = malloc(MLDSA44_ED25519_PK_SZ)) == ખાલી ||
	    (k->mldsa_ed25519_sk = malloc(MLDSA44_ED25519_SK_SZ)) == ખાલી) {
		ssh_mldsa44_ed25519_cleanup(k);
		પાછા SSH_ERR_ALLOC_FAIL;
	}
	જો (crypto_sign_mldsa44_ed25519_keygen(k->mldsa_ed25519_pk,
	    k->mldsa_ed25519_sk) != 0) {
		ssh_mldsa44_ed25519_cleanup(k);
		પાછા SSH_ERR_CRYPTO_ERROR;
	}
	પાછા 0;
}

સ્થિર પૂર્ણાંક
ssh_mldsa44_ed25519_copy_public(અચલ સંરચના sshkey *from, સંરચના sshkey *to)
{
	જો (from->mldsa_ed25519_pk == ખાલી)
		પાછા SSH_ERR_INVALID_ARGUMENT;
	જો ((to->mldsa_ed25519_pk = malloc(MLDSA44_ED25519_PK_SZ)) == ખાલી)
		પાછા SSH_ERR_ALLOC_FAIL;
	memcpy(to->mldsa_ed25519_pk, from->mldsa_ed25519_pk,
	    MLDSA44_ED25519_PK_SZ);
	પાછા 0;
}

સ્થિર પૂર્ણાંક
ssh_mldsa44_ed25519_sign(સંરચના sshkey *ચાવી,
    u_char **sigp, size_t *lenp, અચલ u_char *data, size_t datalen,
    અચલ અક્ષર *alg, અચલ અક્ષર *sk_provider, અચલ અક્ષર *sk_pin,
    u_int compat)
{
	u_char sig[MLDSA44_ED25519_SIG_SZ];
	સંરચના sshbuf *b = ખાલી;
	પૂર્ણાંક r = SSH_ERR_INTERNAL_ERROR;

	જો (lenp != ખાલી)
		*lenp = 0;
	જો (sigp != ખાલી)
		*sigp = ખાલી;

	જો (ચાવી == ખાલી ||
	    sshkey_type_plain(ચાવી->type) != ચાવી_MLDSA44_ED25519 ||
	    ચાવી->mldsa_ed25519_sk == ખાલી)
		પાછા SSH_ERR_INVALID_ARGUMENT;

	જો (crypto_sign_mldsa44_ed25519_sign(sig, data, datalen, ખાલી, 0,
	    ચાવી->mldsa_ed25519_sk) != 0) {
		r = SSH_ERR_CRYPTO_ERROR;
		જાઓ out;
	}

	જો ((b = sshbuf_new()) == ખાલી) {
		r = SSH_ERR_ALLOC_FAIL;
		જાઓ out;
	}
	જો ((r = sshbuf_put_cstring(b, SSH_MLDSA44_ED25519_ALG_NAME)) != 0 ||
	    (r = sshbuf_put_string(b, sig, કદ(sig))) != 0)
		જાઓ out;

	જો (sigp != ખાલી) {
		જો ((*sigp = malloc(sshbuf_len(b))) == ખાલી) {
			r = SSH_ERR_ALLOC_FAIL;
			જાઓ out;
		}
		memcpy(*sigp, sshbuf_ptr(b), sshbuf_len(b));
	}
	જો (lenp != ખાલી)
		*lenp = sshbuf_len(b);
	r = 0;
 out:
	sshbuf_free(b);
	explicit_bzero(sig, કદ(sig));
	પાછા r;
}

સ્થિર પૂર્ણાંક
ssh_mldsa44_ed25519_verify(અચલ સંરચના sshkey *ચાવી,
    અચલ u_char *sig, size_t siglen, અચલ u_char *data, size_t dlen,
    અચલ અક્ષર *alg, u_int compat, સંરચના sshkey_sig_details **detailsp)
{
	સંરચના sshbuf *b = ખાલી;
	અક્ષર *ktype = ખાલી;
	અચલ u_char *sigblob;
	size_t len;
	પૂર્ણાંક r;

	જો (ચાવી == ખાલી ||
	    sshkey_type_plain(ચાવી->type) != ચાવી_MLDSA44_ED25519 ||
	    ચાવી->mldsa_ed25519_pk == ખાલી ||
	    sig == ખાલી || siglen == 0)
		પાછા SSH_ERR_INVALID_ARGUMENT;

	જો ((b = sshbuf_from(sig, siglen)) == ખાલી)
		પાછા SSH_ERR_ALLOC_FAIL;
	જો ((r = sshbuf_get_cstring(b, &ktype, ખાલી)) != 0 ||
	    (r = sshbuf_get_string_direct(b, &sigblob, &len)) != 0)
		જાઓ out;
	જો (strcmp(SSH_MLDSA44_ED25519_ALG_NAME, ktype) != 0) {
		r = SSH_ERR_ચાવી_TYPE_MISMATCH;
		જાઓ out;
	}
	જો (sshbuf_len(b) != 0) {
		r = SSH_ERR_UNEXPECTED_TRAILING_DATA;
		જાઓ out;
	}
	જો (len != MLDSA44_ED25519_SIG_SZ) {
		r = SSH_ERR_INVALID_FORMAT;
		જાઓ out;
	}

	જો (crypto_sign_mldsa44_ed25519_verify(sigblob, data, dlen, ખાલી, 0,
	    ચાવી->mldsa_ed25519_pk) != 0) {
		r = SSH_ERR_SIGNATURE_INVALID;
		જાઓ out;
	}

	r = 0;
 out:
	sshbuf_free(b);
	મુક્ત(ktype);
	પાછા r;
}

અચલ સંરચના sshkey_impl_funcs sshkey_mldsa44_ed25519_funcs = {
	/* .size = */		ખાલી,
	/* .alloc = */		ખાલી,
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

અચલ સંરચના sshkey_impl sshkey_mldsa44_ed25519_impl = {
	/* .name = */		"ssh-mldsa44-ed25519",
	/* .shortname = */	"MLDSA44-ED25519",
	/* .sigalg = */		ખાલી,
	/* .type = */		ચાવી_MLDSA44_ED25519,
	/* .nid = */		0,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	512, /* size of the private key */
	/* .funcs = */		&sshkey_mldsa44_ed25519_funcs,
};

અચલ સંરચના sshkey_impl sshkey_mldsa44_ed25519_cert_impl = {
	/* .name = */		"ssh-mldsa44-ed25519-cert",
	/* .shortname = */	"MLDSA44-ED25519-CERT",
	/* .sigalg = */		ખાલી,
	/* .type = */		ચાવી_MLDSA44_ED25519_CERT,
	/* .nid = */		0,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	512, /* size of the private key */
	/* .funcs = */		&sshkey_mldsa44_ed25519_funcs,
};
#endif /* USE_MLDSA */
