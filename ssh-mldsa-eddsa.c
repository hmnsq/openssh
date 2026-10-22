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

পূর্ণসংখ্যা
crypto_sign_mldsa44_ed25519_keygen(uint8_t pk[MLDSA44_ED25519_PK_SZ],
    uint8_t sk[MLDSA44_ED25519_SK_SZ])
{
	uint8_t mldsa_seed[MLDSA44_SEEDBYTES];
	uint8_t ed25519_seed[crypto_sign_ed25519_SEEDBYTES];
	পূর্ণসংখ্যা r;

	arc4random_buf(mldsa_seed, আকার(mldsa_seed));
	arc4random_buf(ed25519_seed, আকার(ed25519_seed));

	r = crypto_sign_mldsa44_ed25519_keygen_seeded(pk, sk, mldsa_seed,
	    ed25519_seed);
	explicit_bzero(mldsa_seed, আকার(mldsa_seed));
	explicit_bzero(ed25519_seed, আকার(ed25519_seed));
	ফেরত r;
}

পূর্ণসংখ্যা
crypto_sign_mldsa44_ed25519_keygen_seeded(uint8_t pk[MLDSA44_ED25519_PK_SZ],
    uint8_t sk[MLDSA44_ED25519_SK_SZ],
    ধ্রুবক uint8_t mldsa_seed[MLDSA44_SEEDBYTES],
    ধ্রুবক uint8_t ed25519_seed[crypto_sign_ed25519_SEEDBYTES])
{
	uint8_t ed25519_pk[MLDSA44_SEEDBYTES];
	uint8_t ed25519_sk[crypto_sign_ed25519_SECRETKEYBYTES];
	uint8_t mldsa_sk[MLDSA44_SECRETKEYBYTES];
	পূর্ণসংখ্যা ret = -1;

	যদি (crypto_sign_mldsa44_keypair_seeded(pk, mldsa_sk, mldsa_seed) != 0)
		যাও out;
	যদি (crypto_sign_ed25519_seed_keypair(ed25519_pk, ed25519_sk,
	    ed25519_seed) != 0)
		যাও out;

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
	explicit_bzero(mldsa_sk, আকার(mldsa_sk));
	explicit_bzero(ed25519_sk, আকার(ed25519_sk));
	ফেরত ret;
}

স্থির পূর্ণসংখ্যা
construct_m_মৌলিক(uint8_t **m_primep, আকার_t *m_মৌলিক_lenp,
    ধ্রুবক uint8_t *বার্তা, আকার_t msglen,
    ধ্রুবক uint8_t *ctx, আকার_t ctxlen)
{
	পূর্ণসংখ্যা r;
	uint8_t hash[64];
	কাঠামো sshbuf *m_মৌলিক;

	*m_primep = ফাঁকা;
	*m_মৌলিক_lenp = 0;

	যদি (ctxlen > 255)
		ফেরত SSH_ERR_INVALID_ARGUMENT;
	যদি ((r = ssh_digest_memory(SSH_DIGEST_SHA512, বার্তা, msglen,
	    hash, আকার(hash))) != 0)
		ফেরত r;
	যদি ((m_মৌলিক = sshbuf_new()) == ফাঁকা)
		ফেরত SSH_ERR_ALLOC_FAIL;
	যদি ((r = sshbuf_put(m_মৌলিক, COMPOSITE_PREFIX,
	    আকার(COMPOSITE_PREFIX) - 1)) != 0 ||
	    (r = sshbuf_put(m_মৌলিক, COMPOSITE_LABEL,
	    আকার(COMPOSITE_LABEL) - 1)) != 0 ||
	    (r = sshbuf_put_u8(m_মৌলিক, (uint8_t)ctxlen)) != 0 ||
	    (r = sshbuf_put(m_মৌলিক, ctx, ctxlen)) != 0 ||
	    (r = sshbuf_put(m_মৌলিক, hash, আকার(hash))) != 0) {
		sshbuf_free(m_মৌলিক);
		ফেরত r;
	}
	যদি ((*m_primep = malloc(sshbuf_len(m_মৌলিক))) == ফাঁকা) {
		sshbuf_free(m_মৌলিক);
		ফেরত SSH_ERR_ALLOC_FAIL;
	}
	memcpy(*m_primep, sshbuf_ptr(m_মৌলিক), sshbuf_len(m_মৌলিক));
	*m_মৌলিক_lenp = sshbuf_len(m_মৌলিক);
	/* success */
	sshbuf_free(m_মৌলিক);
	ফেরত 0;
}

পূর্ণসংখ্যা
crypto_sign_mldsa44_ed25519_sign(uint8_t sig[MLDSA44_ED25519_SIG_SZ],
    ধ্রুবক uint8_t *বার্তা, আকার_t msglen,
    ধ্রুবক uint8_t *ctx, আকার_t ctxlen,
    ধ্রুবক uint8_t sk[MLDSA44_ED25519_SK_SZ])
{
	uint8_t *m_মৌলিক = ফাঁকা;
	আকার_t m_মৌলিক_len = 0;
	uint8_t mldsa_sk[MLDSA44_SECRETKEYBYTES];
	uint8_t mldsa_pk_dummy[MLDSA44_PUBLICKEYBYTES];
	uint8_t ed25519_pk[crypto_sign_ed25519_PUBLICKEYBYTES];
	uint8_t ed25519_sk[crypto_sign_ed25519_SECRETKEYBYTES];
	uint8_t mldsa_rnd[MLDSA44_SEEDBYTES];
	unsigned long long smlen;
	পূর্ণসংখ্যা r = -1;

	যদি (construct_m_মৌলিক(&m_মৌলিক, &m_মৌলিক_len, বার্তা, msglen,
	    ctx, ctxlen) != 0)
		ফেরত -1;

	/* Expand ML-DSA key from seed */
	যদি (crypto_sign_mldsa44_keypair_seeded(mldsa_pk_dummy, mldsa_sk, sk) != 0)
		যাও out;

	/* Sign with ML-DSA */
	arc4random_buf(mldsa_rnd, আকার(mldsa_rnd));
	যদি (crypto_sign_mldsa44_seeded(sig, m_মৌলিক, m_মৌলিক_len,
	    (ধ্রুবক uint8_t *)COMPOSITE_LABEL, আকার(COMPOSITE_LABEL) - 1,
	    mldsa_sk, mldsa_rnd) != 0)
		যাও out;

	/* Expand Ed25519 key from seed */
	যদি (crypto_sign_ed25519_seed_keypair(ed25519_pk, ed25519_sk,
	    sk + MLDSA44_SEEDBYTES) != 0)
		যাও out;

	/* Sign with Ed25519 */
	যদি (crypto_sign_ed25519_detached(sig + MLDSA44_SIGBYTES, &smlen,
	    m_মৌলিক, m_মৌলিক_len, ed25519_sk) != 0 ||
	    smlen != crypto_sign_ed25519_BYTES)
		যাও out;

	r = 0;
 out:
	মুক্ত(m_মৌলিক);
	explicit_bzero(mldsa_rnd, আকার(mldsa_rnd));
	explicit_bzero(mldsa_sk, আকার(mldsa_sk));
	explicit_bzero(ed25519_sk, আকার(ed25519_sk));
	ফেরত r;
}

পূর্ণসংখ্যা
crypto_sign_mldsa44_ed25519_verify(ধ্রুবক uint8_t sig[MLDSA44_ED25519_SIG_SZ],
    ধ্রুবক uint8_t *বার্তা, আকার_t msglen,
    ধ্রুবক uint8_t *ctx, আকার_t ctxlen,
    ধ্রুবক uint8_t pk[MLDSA44_ED25519_PK_SZ])
{
	uint8_t *m_মৌলিক = ফাঁকা;
	আকার_t m_মৌলিক_len = 0;
	পূর্ণসংখ্যা r = -1;

	যদি (construct_m_মৌলিক(&m_মৌলিক, &m_মৌলিক_len, বার্তা, msglen,
	    ctx, ctxlen) != 0)
		ফেরত -1;

	/* Verify ML-DSA */
	যদি (crypto_sign_mldsa44_verify(sig, m_মৌলিক, m_মৌলিক_len,
	    (ধ্রুবক uint8_t *)COMPOSITE_LABEL, আকার(COMPOSITE_LABEL) - 1,
	    pk) != 0)
		যাও out;

	/* Verify Ed25519 */
	যদি (crypto_sign_ed25519_verify_detached(sig + MLDSA44_SIGBYTES,
	    m_মৌলিক, m_মৌলিক_len, pk + MLDSA44_PUBLICKEYBYTES) != 0)
		যাও out;

	r = 0;
 out:
	মুক্ত(m_মৌলিক);
	ফেরত r;
}

/* sshkey integration */

স্থির শূন্য
ssh_mldsa44_ed25519_cleanup(কাঠামো sshkey *k)
{
	freezero(k->mldsa_ed25519_pk, MLDSA44_ED25519_PK_SZ);
	freezero(k->mldsa_ed25519_sk, MLDSA44_ED25519_SK_SZ);
	k->mldsa_ed25519_pk = ফাঁকা;
	k->mldsa_ed25519_sk = ফাঁকা;
}

স্থির পূর্ণসংখ্যা
ssh_mldsa44_ed25519_equal(ধ্রুবক কাঠামো sshkey *a, ধ্রুবক কাঠামো sshkey *b)
{
	যদি (a->mldsa_ed25519_pk == ফাঁকা || b->mldsa_ed25519_pk == ফাঁকা)
		ফেরত 0;
	যদি (memcmp(a->mldsa_ed25519_pk, b->mldsa_ed25519_pk,
	    MLDSA44_ED25519_PK_SZ) != 0)
		ফেরত 0;
	ফেরত 1;
}

স্থির পূর্ণসংখ্যা
ssh_mldsa44_ed25519_serialize_public(ধ্রুবক কাঠামো sshkey *চাবি, কাঠামো sshbuf *b,
    গণনা sshkey_serialize_rep opts)
{
	পূর্ণসংখ্যা r;

	যদি (চাবি->mldsa_ed25519_pk == ফাঁকা)
		ফেরত SSH_ERR_INVALID_ARGUMENT;
	যদি ((r = sshbuf_put_string(b, চাবি->mldsa_ed25519_pk,
	    MLDSA44_ED25519_PK_SZ)) != 0)
		ফেরত r;

	ফেরত 0;
}

স্থির পূর্ণসংখ্যা
ssh_mldsa44_ed25519_serialize_private(ধ্রুবক কাঠামো sshkey *চাবি, কাঠামো sshbuf *b,
    গণনা sshkey_serialize_rep opts)
{
	পূর্ণসংখ্যা r;

	যদি (চাবি->mldsa_ed25519_sk == ফাঁকা)
		ফেরত SSH_ERR_INVALID_ARGUMENT;
	যদি (!sshkey_is_cert(চাবি)) {
		যদি ((r = ssh_mldsa44_ed25519_serialize_public(চাবি,
		    b, opts)) != 0)
			ফেরত r;
	}
	যদি ((r = sshbuf_put_string(b, চাবি->mldsa_ed25519_sk,
	    MLDSA44_ED25519_SK_SZ)) != 0)
		ফেরত r;

	ফেরত 0;
}

স্থির পূর্ণসংখ্যা
ssh_mldsa44_ed25519_deserialize_public(ধ্রুবক অক্ষর *ktype, কাঠামো sshbuf *b,
    কাঠামো sshkey *চাবি)
{
	u_char *pk = ফাঁকা;
	আকার_t len = 0;
	পূর্ণসংখ্যা r;

	যদি ((r = sshbuf_get_string(b, &pk, &len)) != 0)
		ফেরত r;
	যদি (len != MLDSA44_ED25519_PK_SZ) {
		freezero(pk, len);
		ফেরত SSH_ERR_INVALID_FORMAT;
	}
	চাবি->mldsa_ed25519_pk = pk;
	ফেরত 0;
}

স্থির পূর্ণসংখ্যা
ssh_mldsa44_ed25519_deserialize_private(ধ্রুবক অক্ষর *ktype, কাঠামো sshbuf *b,
    কাঠামো sshkey *চাবি)
{
	পূর্ণসংখ্যা r;
	আকার_t sklen = 0;
	u_char *sk = ফাঁকা;

	যদি (!sshkey_is_cert(চাবি)) {
		যদি ((r = ssh_mldsa44_ed25519_deserialize_public(ktype,
		    b, চাবি)) != 0)
			ফেরত r;
	}
	যদি ((r = sshbuf_get_string(b, &sk, &sklen)) != 0)
		যাও out;
	যদি (sklen != MLDSA44_ED25519_SK_SZ) {
		r = SSH_ERR_INVALID_FORMAT;
		যাও out;
	}
	চাবি->mldsa_ed25519_sk = sk;
	sk = ফাঁকা; /* transferred */
	r = 0;
 out:
	freezero(sk, sklen);
	ফেরত r;
}

স্থির পূর্ণসংখ্যা
ssh_mldsa44_ed25519_generate(কাঠামো sshkey *k, পূর্ণসংখ্যা bits)
{
	ssh_mldsa44_ed25519_cleanup(k);
	যদি ((k->mldsa_ed25519_pk = malloc(MLDSA44_ED25519_PK_SZ)) == ফাঁকা ||
	    (k->mldsa_ed25519_sk = malloc(MLDSA44_ED25519_SK_SZ)) == ফাঁকা) {
		ssh_mldsa44_ed25519_cleanup(k);
		ফেরত SSH_ERR_ALLOC_FAIL;
	}
	যদি (crypto_sign_mldsa44_ed25519_keygen(k->mldsa_ed25519_pk,
	    k->mldsa_ed25519_sk) != 0) {
		ssh_mldsa44_ed25519_cleanup(k);
		ফেরত SSH_ERR_CRYPTO_ERROR;
	}
	ফেরত 0;
}

স্থির পূর্ণসংখ্যা
ssh_mldsa44_ed25519_copy_public(ধ্রুবক কাঠামো sshkey *from, কাঠামো sshkey *to)
{
	যদি (from->mldsa_ed25519_pk == ফাঁকা)
		ফেরত SSH_ERR_INVALID_ARGUMENT;
	যদি ((to->mldsa_ed25519_pk = malloc(MLDSA44_ED25519_PK_SZ)) == ফাঁকা)
		ফেরত SSH_ERR_ALLOC_FAIL;
	memcpy(to->mldsa_ed25519_pk, from->mldsa_ed25519_pk,
	    MLDSA44_ED25519_PK_SZ);
	ফেরত 0;
}

স্থির পূর্ণসংখ্যা
ssh_mldsa44_ed25519_sign(কাঠামো sshkey *চাবি,
    u_char **sigp, আকার_t *lenp, ধ্রুবক u_char *তথ্য, আকার_t datalen,
    ধ্রুবক অক্ষর *alg, ধ্রুবক অক্ষর *sk_provider, ধ্রুবক অক্ষর *sk_pin,
    u_int compat)
{
	u_char sig[MLDSA44_ED25519_SIG_SZ];
	কাঠামো sshbuf *b = ফাঁকা;
	পূর্ণসংখ্যা r = SSH_ERR_INTERNAL_ERROR;

	যদি (lenp != ফাঁকা)
		*lenp = 0;
	যদি (sigp != ফাঁকা)
		*sigp = ফাঁকা;

	যদি (চাবি == ফাঁকা ||
	    sshkey_type_plain(চাবি->type) != চাবি_MLDSA44_ED25519 ||
	    চাবি->mldsa_ed25519_sk == ফাঁকা)
		ফেরত SSH_ERR_INVALID_ARGUMENT;

	যদি (crypto_sign_mldsa44_ed25519_sign(sig, তথ্য, datalen, ফাঁকা, 0,
	    চাবি->mldsa_ed25519_sk) != 0) {
		r = SSH_ERR_CRYPTO_ERROR;
		যাও out;
	}

	যদি ((b = sshbuf_new()) == ফাঁকা) {
		r = SSH_ERR_ALLOC_FAIL;
		যাও out;
	}
	যদি ((r = sshbuf_put_cstring(b, SSH_MLDSA44_ED25519_ALG_NAME)) != 0 ||
	    (r = sshbuf_put_string(b, sig, আকার(sig))) != 0)
		যাও out;

	যদি (sigp != ফাঁকা) {
		যদি ((*sigp = malloc(sshbuf_len(b))) == ফাঁকা) {
			r = SSH_ERR_ALLOC_FAIL;
			যাও out;
		}
		memcpy(*sigp, sshbuf_ptr(b), sshbuf_len(b));
	}
	যদি (lenp != ফাঁকা)
		*lenp = sshbuf_len(b);
	r = 0;
 out:
	sshbuf_free(b);
	explicit_bzero(sig, আকার(sig));
	ফেরত r;
}

স্থির পূর্ণসংখ্যা
ssh_mldsa44_ed25519_verify(ধ্রুবক কাঠামো sshkey *চাবি,
    ধ্রুবক u_char *sig, আকার_t siglen, ধ্রুবক u_char *তথ্য, আকার_t dlen,
    ধ্রুবক অক্ষর *alg, u_int compat, কাঠামো sshkey_sig_details **detailsp)
{
	কাঠামো sshbuf *b = ফাঁকা;
	অক্ষর *ktype = ফাঁকা;
	ধ্রুবক u_char *sigblob;
	আকার_t len;
	পূর্ণসংখ্যা r;

	যদি (চাবি == ফাঁকা ||
	    sshkey_type_plain(চাবি->type) != চাবি_MLDSA44_ED25519 ||
	    চাবি->mldsa_ed25519_pk == ফাঁকা ||
	    sig == ফাঁকা || siglen == 0)
		ফেরত SSH_ERR_INVALID_ARGUMENT;

	যদি ((b = sshbuf_from(sig, siglen)) == ফাঁকা)
		ফেরত SSH_ERR_ALLOC_FAIL;
	যদি ((r = sshbuf_get_cstring(b, &ktype, ফাঁকা)) != 0 ||
	    (r = sshbuf_get_string_direct(b, &sigblob, &len)) != 0)
		যাও out;
	যদি (strcmp(SSH_MLDSA44_ED25519_ALG_NAME, ktype) != 0) {
		r = SSH_ERR_চাবি_TYPE_MISMATCH;
		যাও out;
	}
	যদি (sshbuf_len(b) != 0) {
		r = SSH_ERR_UNEXPECTED_TRAILING_তথ্য;
		যাও out;
	}
	যদি (len != MLDSA44_ED25519_SIG_SZ) {
		r = SSH_ERR_INVALID_FORMAT;
		যাও out;
	}

	যদি (crypto_sign_mldsa44_ed25519_verify(sigblob, তথ্য, dlen, ফাঁকা, 0,
	    চাবি->mldsa_ed25519_pk) != 0) {
		r = SSH_ERR_SIGNATURE_INVALID;
		যাও out;
	}

	r = 0;
 out:
	sshbuf_free(b);
	মুক্ত(ktype);
	ফেরত r;
}

ধ্রুবক কাঠামো sshkey_impl_funcs sshkey_mldsa44_ed25519_funcs = {
	/* .size = */		ফাঁকা,
	/* .alloc = */		ফাঁকা,
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

ধ্রুবক কাঠামো sshkey_impl sshkey_mldsa44_ed25519_impl = {
	/* .name = */		"ssh-mldsa44-ed25519",
	/* .shortname = */	"MLDSA44-ED25519",
	/* .sigalg = */		ফাঁকা,
	/* .type = */		চাবি_MLDSA44_ED25519,
	/* .nid = */		0,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	512, /* size of the private key */
	/* .funcs = */		&sshkey_mldsa44_ed25519_funcs,
};

ধ্রুবক কাঠামো sshkey_impl sshkey_mldsa44_ed25519_cert_impl = {
	/* .name = */		"ssh-mldsa44-ed25519-cert",
	/* .shortname = */	"MLDSA44-ED25519-CERT",
	/* .sigalg = */		ফাঁকা,
	/* .type = */		চাবি_MLDSA44_ED25519_CERT,
	/* .nid = */		0,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	512, /* size of the private key */
	/* .funcs = */		&sshkey_mldsa44_ed25519_funcs,
};
#endif /* USE_MLDSA */
