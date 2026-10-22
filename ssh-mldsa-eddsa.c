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

#অন্তর্ভাব "includes.h"

#ifdef USE_MLDSA

#অন্তর্ভাব <sys/types.h>
#অন্তর্ভাব <stdint.h>
#অন্তর্ভাব <string.h>
#অন্তর্ভাব <stdlib.h>

#অন্তর্ভাব "crypto_api.h"
#অন্তর্ভাব "sshbuf.h"
#অন্তর্ভাব "ssherr.h"
#অন্তর্ভাব "digest.h"
#define SSHKEY_INTERNAL
#অন্তর্ভাব "sshkey.h"
#অন্তর্ভাব "log.h"

#define COMPOSITE_PREFIX "CompositeAlgorithmSignatures2025"
#define COMPOSITE_LABEL  "COMPSIG-MLDSA44-Ed25519-SHA512"
#define SSH_MLDSA44_ED25519_ALG_NAME   "ssh-mldsa44-ed25519"

/*
 * raw_* functions implement the draft-ietf-lamps-pq-composite-sigs-18
 * composite signature scheme. These are exposed (i.e. not static) so
 * we can test them separately in unittests/crypto.
 */

পূর্ণাঙ্ক
crypto_sign_mldsa44_ed25519_keygen(uint8_t pk[MLDSA44_ED25519_PK_SZ],
    uint8_t sk[MLDSA44_ED25519_SK_SZ])
{
	uint8_t mldsa_seed[MLDSA44_SEEDBYTES];
	uint8_t ed25519_seed[crypto_sign_ed25519_SEEDBYTES];
	পূর্ণাঙ্ক r;

	arc4random_buf(mldsa_seed, পরিমাণ(mldsa_seed));
	arc4random_buf(ed25519_seed, পরিমাণ(ed25519_seed));

	r = crypto_sign_mldsa44_ed25519_keygen_seeded(pk, sk, mldsa_seed,
	    ed25519_seed);
	explicit_bzero(mldsa_seed, পরিমাণ(mldsa_seed));
	explicit_bzero(ed25519_seed, পরিমাণ(ed25519_seed));
	প্রত্যাগম r;
}

পূর্ণাঙ্ক
crypto_sign_mldsa44_ed25519_keygen_seeded(uint8_t pk[MLDSA44_ED25519_PK_SZ],
    uint8_t sk[MLDSA44_ED25519_SK_SZ],
    ধ্রুব uint8_t mldsa_seed[MLDSA44_SEEDBYTES],
    ধ্রুব uint8_t ed25519_seed[crypto_sign_ed25519_SEEDBYTES])
{
	uint8_t ed25519_pk[MLDSA44_SEEDBYTES];
	uint8_t ed25519_sk[crypto_sign_ed25519_SECRETKEYBYTES];
	uint8_t mldsa_sk[MLDSA44_SECRETKEYBYTES];
	পূর্ণাঙ্ক ret = -1;

	যদি (crypto_sign_mldsa44_keypair_seeded(pk, mldsa_sk, mldsa_seed) != 0)
		গচ্ছ out;
	যদি (crypto_sign_ed25519_seed_keypair(ed25519_pk, ed25519_sk,
	    ed25519_seed) != 0)
		গচ্ছ out;

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
	explicit_bzero(mldsa_sk, পরিমাণ(mldsa_sk));
	explicit_bzero(ed25519_sk, পরিমাণ(ed25519_sk));
	প্রত্যাগম ret;
}

স্থির পূর্ণাঙ্ক
construct_m_মৌলিক(uint8_t **m_primep, size_t *m_মৌলিক_lenp,
    ধ্রুব uint8_t *বার্তা, size_t msglen,
    ধ্রুব uint8_t *ctx, size_t ctxlen)
{
	পূর্ণাঙ্ক r;
	uint8_t hash[64];
	সংরচনা sshbuf *m_মৌলিক;

	*m_primep = রিক্ত;
	*m_মৌলিক_lenp = 0;

	যদি (ctxlen > 255)
		প্রত্যাগম SSH_ERR_INVALID_ARGUMENT;
	যদি ((r = ssh_digest_memory(SSH_DIGEST_SHA512, বার্তা, msglen,
	    hash, পরিমাণ(hash))) != 0)
		প্রত্যাগম r;
	যদি ((m_মৌলিক = sshbuf_new()) == রিক্ত)
		প্রত্যাগম SSH_ERR_ALLOC_FAIL;
	যদি ((r = sshbuf_put(m_মৌলিক, COMPOSITE_PREFIX,
	    পরিমাণ(COMPOSITE_PREFIX) - 1)) != 0 ||
	    (r = sshbuf_put(m_মৌলিক, COMPOSITE_LABEL,
	    পরিমাণ(COMPOSITE_LABEL) - 1)) != 0 ||
	    (r = sshbuf_put_u8(m_মৌলিক, (uint8_t)ctxlen)) != 0 ||
	    (r = sshbuf_put(m_মৌলিক, ctx, ctxlen)) != 0 ||
	    (r = sshbuf_put(m_মৌলিক, hash, পরিমাণ(hash))) != 0) {
		sshbuf_free(m_মৌলিক);
		প্রত্যাগম r;
	}
	যদি ((*m_primep = malloc(sshbuf_len(m_মৌলিক))) == রিক্ত) {
		sshbuf_free(m_মৌলিক);
		প্রত্যাগম SSH_ERR_ALLOC_FAIL;
	}
	memcpy(*m_primep, sshbuf_ptr(m_মৌলিক), sshbuf_len(m_মৌলিক));
	*m_মৌলিক_lenp = sshbuf_len(m_মৌলিক);
	/* success */
	sshbuf_free(m_মৌলিক);
	প্রত্যাগম 0;
}

পূর্ণাঙ্ক
crypto_sign_mldsa44_ed25519_sign(uint8_t sig[MLDSA44_ED25519_SIG_SZ],
    ধ্রুব uint8_t *বার্তা, size_t msglen,
    ধ্রুব uint8_t *ctx, size_t ctxlen,
    ধ্রুব uint8_t sk[MLDSA44_ED25519_SK_SZ])
{
	uint8_t *m_মৌলিক = রিক্ত;
	size_t m_মৌলিক_len = 0;
	uint8_t mldsa_sk[MLDSA44_SECRETKEYBYTES];
	uint8_t mldsa_pk_dummy[MLDSA44_PUBLICKEYBYTES];
	uint8_t ed25519_pk[crypto_sign_ed25519_PUBLICKEYBYTES];
	uint8_t ed25519_sk[crypto_sign_ed25519_SECRETKEYBYTES];
	uint8_t mldsa_rnd[MLDSA44_SEEDBYTES];
	unsigned long long smlen;
	পূর্ণাঙ্ক r = -1;

	যদি (construct_m_মৌলিক(&m_মৌলিক, &m_মৌলিক_len, বার্তা, msglen,
	    ctx, ctxlen) != 0)
		প্রত্যাগম -1;

	/* Expand ML-DSA key from seed */
	যদি (crypto_sign_mldsa44_keypair_seeded(mldsa_pk_dummy, mldsa_sk, sk) != 0)
		গচ্ছ out;

	/* Sign with ML-DSA */
	arc4random_buf(mldsa_rnd, পরিমাণ(mldsa_rnd));
	যদি (crypto_sign_mldsa44_seeded(sig, m_মৌলিক, m_মৌলিক_len,
	    (ধ্রুব uint8_t *)COMPOSITE_LABEL, পরিমাণ(COMPOSITE_LABEL) - 1,
	    mldsa_sk, mldsa_rnd) != 0)
		গচ্ছ out;

	/* Expand Ed25519 key from seed */
	যদি (crypto_sign_ed25519_seed_keypair(ed25519_pk, ed25519_sk,
	    sk + MLDSA44_SEEDBYTES) != 0)
		গচ্ছ out;

	/* Sign with Ed25519 */
	যদি (crypto_sign_ed25519_detached(sig + MLDSA44_SIGBYTES, &smlen,
	    m_মৌলিক, m_মৌলিক_len, ed25519_sk) != 0 ||
	    smlen != crypto_sign_ed25519_BYTES)
		গচ্ছ out;

	r = 0;
 out:
	মুক্ত(m_মৌলিক);
	explicit_bzero(mldsa_rnd, পরিমাণ(mldsa_rnd));
	explicit_bzero(mldsa_sk, পরিমাণ(mldsa_sk));
	explicit_bzero(ed25519_sk, পরিমাণ(ed25519_sk));
	প্রত্যাগম r;
}

পূর্ণাঙ্ক
crypto_sign_mldsa44_ed25519_verify(ধ্রুব uint8_t sig[MLDSA44_ED25519_SIG_SZ],
    ধ্রুব uint8_t *বার্তা, size_t msglen,
    ধ্রুব uint8_t *ctx, size_t ctxlen,
    ধ্রুব uint8_t pk[MLDSA44_ED25519_PK_SZ])
{
	uint8_t *m_মৌলিক = রিক্ত;
	size_t m_মৌলিক_len = 0;
	পূর্ণাঙ্ক r = -1;

	যদি (construct_m_মৌলিক(&m_মৌলিক, &m_মৌলিক_len, বার্তা, msglen,
	    ctx, ctxlen) != 0)
		প্রত্যাগম -1;

	/* Verify ML-DSA */
	যদি (crypto_sign_mldsa44_verify(sig, m_মৌলিক, m_মৌলিক_len,
	    (ধ্রুব uint8_t *)COMPOSITE_LABEL, পরিমাণ(COMPOSITE_LABEL) - 1,
	    pk) != 0)
		গচ্ছ out;

	/* Verify Ed25519 */
	যদি (crypto_sign_ed25519_verify_detached(sig + MLDSA44_SIGBYTES,
	    m_মৌলিক, m_মৌলিক_len, pk + MLDSA44_PUBLICKEYBYTES) != 0)
		গচ্ছ out;

	r = 0;
 out:
	মুক্ত(m_মৌলিক);
	প্রত্যাগম r;
}

/* sshkey integration */

স্থির শূন্য
ssh_mldsa44_ed25519_cleanup(সংরচনা sshkey *k)
{
	freezero(k->mldsa_ed25519_pk, MLDSA44_ED25519_PK_SZ);
	freezero(k->mldsa_ed25519_sk, MLDSA44_ED25519_SK_SZ);
	k->mldsa_ed25519_pk = রিক্ত;
	k->mldsa_ed25519_sk = রিক্ত;
}

স্থির পূর্ণাঙ্ক
ssh_mldsa44_ed25519_equal(ধ্রুব সংরচনা sshkey *a, ধ্রুব সংরচনা sshkey *b)
{
	যদি (a->mldsa_ed25519_pk == রিক্ত || b->mldsa_ed25519_pk == রিক্ত)
		প্রত্যাগম 0;
	যদি (memcmp(a->mldsa_ed25519_pk, b->mldsa_ed25519_pk,
	    MLDSA44_ED25519_PK_SZ) != 0)
		প্রত্যাগম 0;
	প্রত্যাগম 1;
}

স্থির পূর্ণাঙ্ক
ssh_mldsa44_ed25519_serialize_public(ধ্রুব সংরচনা sshkey *চাবি, সংরচনা sshbuf *b,
    গণনা sshkey_serialize_rep opts)
{
	পূর্ণাঙ্ক r;

	যদি (চাবি->mldsa_ed25519_pk == রিক্ত)
		প্রত্যাগম SSH_ERR_INVALID_ARGUMENT;
	যদি ((r = sshbuf_put_string(b, চাবি->mldsa_ed25519_pk,
	    MLDSA44_ED25519_PK_SZ)) != 0)
		প্রত্যাগম r;

	প্রত্যাগম 0;
}

স্থির পূর্ণাঙ্ক
ssh_mldsa44_ed25519_serialize_private(ধ্রুব সংরচনা sshkey *চাবি, সংরচনা sshbuf *b,
    গণনা sshkey_serialize_rep opts)
{
	পূর্ণাঙ্ক r;

	যদি (চাবি->mldsa_ed25519_sk == রিক্ত)
		প্রত্যাগম SSH_ERR_INVALID_ARGUMENT;
	যদি (!sshkey_is_cert(চাবি)) {
		যদি ((r = ssh_mldsa44_ed25519_serialize_public(চাবি,
		    b, opts)) != 0)
			প্রত্যাগম r;
	}
	যদি ((r = sshbuf_put_string(b, চাবি->mldsa_ed25519_sk,
	    MLDSA44_ED25519_SK_SZ)) != 0)
		প্রত্যাগম r;

	প্রত্যাগম 0;
}

স্থির পূর্ণাঙ্ক
ssh_mldsa44_ed25519_deserialize_public(ধ্রুব বর্ণ *ktype, সংরচনা sshbuf *b,
    সংরচনা sshkey *চাবি)
{
	u_char *pk = রিক্ত;
	size_t len = 0;
	পূর্ণাঙ্ক r;

	যদি ((r = sshbuf_get_string(b, &pk, &len)) != 0)
		প্রত্যাগম r;
	যদি (len != MLDSA44_ED25519_PK_SZ) {
		freezero(pk, len);
		প্রত্যাগম SSH_ERR_INVALID_FORMAT;
	}
	চাবি->mldsa_ed25519_pk = pk;
	প্রত্যাগম 0;
}

স্থির পূর্ণাঙ্ক
ssh_mldsa44_ed25519_deserialize_private(ধ্রুব বর্ণ *ktype, সংরচনা sshbuf *b,
    সংরচনা sshkey *চাবি)
{
	পূর্ণাঙ্ক r;
	size_t sklen = 0;
	u_char *sk = রিক্ত;

	যদি (!sshkey_is_cert(চাবি)) {
		যদি ((r = ssh_mldsa44_ed25519_deserialize_public(ktype,
		    b, চাবি)) != 0)
			প্রত্যাগম r;
	}
	যদি ((r = sshbuf_get_string(b, &sk, &sklen)) != 0)
		গচ্ছ out;
	যদি (sklen != MLDSA44_ED25519_SK_SZ) {
		r = SSH_ERR_INVALID_FORMAT;
		গচ্ছ out;
	}
	চাবি->mldsa_ed25519_sk = sk;
	sk = রিক্ত; /* transferred */
	r = 0;
 out:
	freezero(sk, sklen);
	প্রত্যাগম r;
}

স্থির পূর্ণাঙ্ক
ssh_mldsa44_ed25519_generate(সংরচনা sshkey *k, পূর্ণাঙ্ক bits)
{
	ssh_mldsa44_ed25519_cleanup(k);
	যদি ((k->mldsa_ed25519_pk = malloc(MLDSA44_ED25519_PK_SZ)) == রিক্ত ||
	    (k->mldsa_ed25519_sk = malloc(MLDSA44_ED25519_SK_SZ)) == রিক্ত) {
		ssh_mldsa44_ed25519_cleanup(k);
		প্রত্যাগম SSH_ERR_ALLOC_FAIL;
	}
	যদি (crypto_sign_mldsa44_ed25519_keygen(k->mldsa_ed25519_pk,
	    k->mldsa_ed25519_sk) != 0) {
		ssh_mldsa44_ed25519_cleanup(k);
		প্রত্যাগম SSH_ERR_CRYPTO_ERROR;
	}
	প্রত্যাগম 0;
}

স্থির পূর্ণাঙ্ক
ssh_mldsa44_ed25519_copy_public(ধ্রুব সংরচনা sshkey *from, সংরচনা sshkey *to)
{
	যদি (from->mldsa_ed25519_pk == রিক্ত)
		প্রত্যাগম SSH_ERR_INVALID_ARGUMENT;
	যদি ((to->mldsa_ed25519_pk = malloc(MLDSA44_ED25519_PK_SZ)) == রিক্ত)
		প্রত্যাগম SSH_ERR_ALLOC_FAIL;
	memcpy(to->mldsa_ed25519_pk, from->mldsa_ed25519_pk,
	    MLDSA44_ED25519_PK_SZ);
	প্রত্যাগম 0;
}

স্থির পূর্ণাঙ্ক
ssh_mldsa44_ed25519_sign(সংরচনা sshkey *চাবি,
    u_char **sigp, size_t *lenp, ধ্রুব u_char *data, size_t datalen,
    ধ্রুব বর্ণ *alg, ধ্রুব বর্ণ *sk_provider, ধ্রুব বর্ণ *sk_pin,
    u_int compat)
{
	u_char sig[MLDSA44_ED25519_SIG_SZ];
	সংরচনা sshbuf *b = রিক্ত;
	পূর্ণাঙ্ক r = SSH_ERR_INTERNAL_ERROR;

	যদি (lenp != রিক্ত)
		*lenp = 0;
	যদি (sigp != রিক্ত)
		*sigp = রিক্ত;

	যদি (চাবি == রিক্ত ||
	    sshkey_type_plain(চাবি->type) != চাবি_MLDSA44_ED25519 ||
	    চাবি->mldsa_ed25519_sk == রিক্ত)
		প্রত্যাগম SSH_ERR_INVALID_ARGUMENT;

	যদি (crypto_sign_mldsa44_ed25519_sign(sig, data, datalen, রিক্ত, 0,
	    চাবি->mldsa_ed25519_sk) != 0) {
		r = SSH_ERR_CRYPTO_ERROR;
		গচ্ছ out;
	}

	যদি ((b = sshbuf_new()) == রিক্ত) {
		r = SSH_ERR_ALLOC_FAIL;
		গচ্ছ out;
	}
	যদি ((r = sshbuf_put_cstring(b, SSH_MLDSA44_ED25519_ALG_NAME)) != 0 ||
	    (r = sshbuf_put_string(b, sig, পরিমাণ(sig))) != 0)
		গচ্ছ out;

	যদি (sigp != রিক্ত) {
		যদি ((*sigp = malloc(sshbuf_len(b))) == রিক্ত) {
			r = SSH_ERR_ALLOC_FAIL;
			গচ্ছ out;
		}
		memcpy(*sigp, sshbuf_ptr(b), sshbuf_len(b));
	}
	যদি (lenp != রিক্ত)
		*lenp = sshbuf_len(b);
	r = 0;
 out:
	sshbuf_free(b);
	explicit_bzero(sig, পরিমাণ(sig));
	প্রত্যাগম r;
}

স্থির পূর্ণাঙ্ক
ssh_mldsa44_ed25519_verify(ধ্রুব সংরচনা sshkey *চাবি,
    ধ্রুব u_char *sig, size_t siglen, ধ্রুব u_char *data, size_t dlen,
    ধ্রুব বর্ণ *alg, u_int compat, সংরচনা sshkey_sig_details **detailsp)
{
	সংরচনা sshbuf *b = রিক্ত;
	বর্ণ *ktype = রিক্ত;
	ধ্রুব u_char *sigblob;
	size_t len;
	পূর্ণাঙ্ক r;

	যদি (চাবি == রিক্ত ||
	    sshkey_type_plain(চাবি->type) != চাবি_MLDSA44_ED25519 ||
	    চাবি->mldsa_ed25519_pk == রিক্ত ||
	    sig == রিক্ত || siglen == 0)
		প্রত্যাগম SSH_ERR_INVALID_ARGUMENT;

	যদি ((b = sshbuf_from(sig, siglen)) == রিক্ত)
		প্রত্যাগম SSH_ERR_ALLOC_FAIL;
	যদি ((r = sshbuf_get_cstring(b, &ktype, রিক্ত)) != 0 ||
	    (r = sshbuf_get_string_direct(b, &sigblob, &len)) != 0)
		গচ্ছ out;
	যদি (strcmp(SSH_MLDSA44_ED25519_ALG_NAME, ktype) != 0) {
		r = SSH_ERR_চাবি_TYPE_MISMATCH;
		গচ্ছ out;
	}
	যদি (sshbuf_len(b) != 0) {
		r = SSH_ERR_UNEXPECTED_TRAILING_DATA;
		গচ্ছ out;
	}
	যদি (len != MLDSA44_ED25519_SIG_SZ) {
		r = SSH_ERR_INVALID_FORMAT;
		গচ্ছ out;
	}

	যদি (crypto_sign_mldsa44_ed25519_verify(sigblob, data, dlen, রিক্ত, 0,
	    চাবি->mldsa_ed25519_pk) != 0) {
		r = SSH_ERR_SIGNATURE_INVALID;
		গচ্ছ out;
	}

	r = 0;
 out:
	sshbuf_free(b);
	মুক্ত(ktype);
	প্রত্যাগম r;
}

ধ্রুব সংরচনা sshkey_impl_funcs sshkey_mldsa44_ed25519_funcs = {
	/* .size = */		রিক্ত,
	/* .alloc = */		রিক্ত,
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

ধ্রুব সংরচনা sshkey_impl sshkey_mldsa44_ed25519_impl = {
	/* .name = */		"ssh-mldsa44-ed25519",
	/* .shortname = */	"MLDSA44-ED25519",
	/* .sigalg = */		রিক্ত,
	/* .type = */		চাবি_MLDSA44_ED25519,
	/* .nid = */		0,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	512, /* size of the private key */
	/* .funcs = */		&sshkey_mldsa44_ed25519_funcs,
};

ধ্রুব সংরচনা sshkey_impl sshkey_mldsa44_ed25519_cert_impl = {
	/* .name = */		"ssh-mldsa44-ed25519-cert",
	/* .shortname = */	"MLDSA44-ED25519-CERT",
	/* .sigalg = */		রিক্ত,
	/* .type = */		চাবি_MLDSA44_ED25519_CERT,
	/* .nid = */		0,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	512, /* size of the private key */
	/* .funcs = */		&sshkey_mldsa44_ed25519_funcs,
};
#endif /* USE_MLDSA */
