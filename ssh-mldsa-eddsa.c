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

#شامل "includes.h"

#ifdef USE_MLDSA

#شامل <sys/types.h>
#شامل <stdint.h>
#شامل <string.h>
#شامل <stdlib.h>

#شامل "crypto_api.h"
#شامل "sshbuf.h"
#شامل "ssherr.h"
#شامل "digest.h"
#define SSHKEY_INTERNAL
#شامل "sshkey.h"
#شامل "log.h"

#define COMPOSITE_PREFIX "CompositeAlgorithmSignatures2025"
#define COMPOSITE_LABEL  "COMPSIG-MLDSA44-Ed25519-SHA512"
#define SSH_MLDSA44_ED25519_ALG_NAME   "ssh-mldsa44-ed25519"

/*
 * raw_* functions implement the draft-ietf-lamps-pq-composite-sigs-18
 * composite signature scheme. These are exposed (i.e. not static) so
 * we can test them separately in unittests/crypto.
 */

صحیح
crypto_sign_mldsa44_ed25519_keygen(uint8_t pk[MLDSA44_ED25519_PK_SZ],
    uint8_t sk[MLDSA44_ED25519_SK_SZ])
{
	uint8_t mldsa_seed[MLDSA44_SEEDBYTES];
	uint8_t ed25519_seed[crypto_sign_ed25519_SEEDBYTES];
	صحیح r;

	arc4random_buf(mldsa_seed, اندازه(mldsa_seed));
	arc4random_buf(ed25519_seed, اندازه(ed25519_seed));

	r = crypto_sign_mldsa44_ed25519_keygen_seeded(pk, sk, mldsa_seed,
	    ed25519_seed);
	explicit_bzero(mldsa_seed, اندازه(mldsa_seed));
	explicit_bzero(ed25519_seed, اندازه(ed25519_seed));
	بازگشت r;
}

صحیح
crypto_sign_mldsa44_ed25519_keygen_seeded(uint8_t pk[MLDSA44_ED25519_PK_SZ],
    uint8_t sk[MLDSA44_ED25519_SK_SZ],
    ثابت uint8_t mldsa_seed[MLDSA44_SEEDBYTES],
    ثابت uint8_t ed25519_seed[crypto_sign_ed25519_SEEDBYTES])
{
	uint8_t ed25519_pk[MLDSA44_SEEDBYTES];
	uint8_t ed25519_sk[crypto_sign_ed25519_SECRETKEYBYTES];
	uint8_t mldsa_sk[MLDSA44_SECRETKEYBYTES];
	صحیح ret = -1;

	اگر (crypto_sign_mldsa44_keypair_seeded(pk, mldsa_sk, mldsa_seed) != 0)
		برو out;
	اگر (crypto_sign_ed25519_seed_keypair(ed25519_pk, ed25519_sk,
	    ed25519_seed) != 0)
		برو out;

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
	explicit_bzero(mldsa_sk, اندازه(mldsa_sk));
	explicit_bzero(ed25519_sk, اندازه(ed25519_sk));
	بازگشت ret;
}

ایستا صحیح
construct_m_اول(uint8_t **m_primep, size_t *m_اول_lenp,
    ثابت uint8_t *پیام, size_t msglen,
    ثابت uint8_t *ctx, size_t ctxlen)
{
	صحیح r;
	uint8_t hash[64];
	ساختار sshbuf *m_اول;

	*m_primep = پوچ;
	*m_اول_lenp = 0;

	اگر (ctxlen > 255)
		بازگشت SSH_ERR_INVALID_ARGUMENT;
	اگر ((r = ssh_digest_memory(SSH_DIGEST_SHA512, پیام, msglen,
	    hash, اندازه(hash))) != 0)
		بازگشت r;
	اگر ((m_اول = sshbuf_new()) == پوچ)
		بازگشت SSH_ERR_ALLOC_FAIL;
	اگر ((r = sshbuf_put(m_اول, COMPOSITE_PREFIX,
	    اندازه(COMPOSITE_PREFIX) - 1)) != 0 ||
	    (r = sshbuf_put(m_اول, COMPOSITE_LABEL,
	    اندازه(COMPOSITE_LABEL) - 1)) != 0 ||
	    (r = sshbuf_put_u8(m_اول, (uint8_t)ctxlen)) != 0 ||
	    (r = sshbuf_put(m_اول, ctx, ctxlen)) != 0 ||
	    (r = sshbuf_put(m_اول, hash, اندازه(hash))) != 0) {
		sshbuf_free(m_اول);
		بازگشت r;
	}
	اگر ((*m_primep = malloc(sshbuf_len(m_اول))) == پوچ) {
		sshbuf_free(m_اول);
		بازگشت SSH_ERR_ALLOC_FAIL;
	}
	memcpy(*m_primep, sshbuf_ptr(m_اول), sshbuf_len(m_اول));
	*m_اول_lenp = sshbuf_len(m_اول);
	/* success */
	sshbuf_free(m_اول);
	بازگشت 0;
}

صحیح
crypto_sign_mldsa44_ed25519_sign(uint8_t sig[MLDSA44_ED25519_SIG_SZ],
    ثابت uint8_t *پیام, size_t msglen,
    ثابت uint8_t *ctx, size_t ctxlen,
    ثابت uint8_t sk[MLDSA44_ED25519_SK_SZ])
{
	uint8_t *m_اول = پوچ;
	size_t m_اول_len = 0;
	uint8_t mldsa_sk[MLDSA44_SECRETKEYBYTES];
	uint8_t mldsa_pk_dummy[MLDSA44_PUBLICKEYBYTES];
	uint8_t ed25519_pk[crypto_sign_ed25519_PUBLICKEYBYTES];
	uint8_t ed25519_sk[crypto_sign_ed25519_SECRETKEYBYTES];
	uint8_t mldsa_rnd[MLDSA44_SEEDBYTES];
	unsigned long long smlen;
	صحیح r = -1;

	اگر (construct_m_اول(&m_اول, &m_اول_len, پیام, msglen,
	    ctx, ctxlen) != 0)
		بازگشت -1;

	/* Expand ML-DSA key from seed */
	اگر (crypto_sign_mldsa44_keypair_seeded(mldsa_pk_dummy, mldsa_sk, sk) != 0)
		برو out;

	/* Sign with ML-DSA */
	arc4random_buf(mldsa_rnd, اندازه(mldsa_rnd));
	اگر (crypto_sign_mldsa44_seeded(sig, m_اول, m_اول_len,
	    (ثابت uint8_t *)COMPOSITE_LABEL, اندازه(COMPOSITE_LABEL) - 1,
	    mldsa_sk, mldsa_rnd) != 0)
		برو out;

	/* Expand Ed25519 key from seed */
	اگر (crypto_sign_ed25519_seed_keypair(ed25519_pk, ed25519_sk,
	    sk + MLDSA44_SEEDBYTES) != 0)
		برو out;

	/* Sign with Ed25519 */
	اگر (crypto_sign_ed25519_detached(sig + MLDSA44_SIGBYTES, &smlen,
	    m_اول, m_اول_len, ed25519_sk) != 0 ||
	    smlen != crypto_sign_ed25519_BYTES)
		برو out;

	r = 0;
 out:
	آزاد(m_اول);
	explicit_bzero(mldsa_rnd, اندازه(mldsa_rnd));
	explicit_bzero(mldsa_sk, اندازه(mldsa_sk));
	explicit_bzero(ed25519_sk, اندازه(ed25519_sk));
	بازگشت r;
}

صحیح
crypto_sign_mldsa44_ed25519_verify(ثابت uint8_t sig[MLDSA44_ED25519_SIG_SZ],
    ثابت uint8_t *پیام, size_t msglen,
    ثابت uint8_t *ctx, size_t ctxlen,
    ثابت uint8_t pk[MLDSA44_ED25519_PK_SZ])
{
	uint8_t *m_اول = پوچ;
	size_t m_اول_len = 0;
	صحیح r = -1;

	اگر (construct_m_اول(&m_اول, &m_اول_len, پیام, msglen,
	    ctx, ctxlen) != 0)
		بازگشت -1;

	/* Verify ML-DSA */
	اگر (crypto_sign_mldsa44_verify(sig, m_اول, m_اول_len,
	    (ثابت uint8_t *)COMPOSITE_LABEL, اندازه(COMPOSITE_LABEL) - 1,
	    pk) != 0)
		برو out;

	/* Verify Ed25519 */
	اگر (crypto_sign_ed25519_verify_detached(sig + MLDSA44_SIGBYTES,
	    m_اول, m_اول_len, pk + MLDSA44_PUBLICKEYBYTES) != 0)
		برو out;

	r = 0;
 out:
	آزاد(m_اول);
	بازگشت r;
}

/* sshkey integration */

ایستا تهی
ssh_mldsa44_ed25519_cleanup(ساختار sshkey *k)
{
	freezero(k->mldsa_ed25519_pk, MLDSA44_ED25519_PK_SZ);
	freezero(k->mldsa_ed25519_sk, MLDSA44_ED25519_SK_SZ);
	k->mldsa_ed25519_pk = پوچ;
	k->mldsa_ed25519_sk = پوچ;
}

ایستا صحیح
ssh_mldsa44_ed25519_equal(ثابت ساختار sshkey *a, ثابت ساختار sshkey *b)
{
	اگر (a->mldsa_ed25519_pk == پوچ || b->mldsa_ed25519_pk == پوچ)
		بازگشت 0;
	اگر (memcmp(a->mldsa_ed25519_pk, b->mldsa_ed25519_pk,
	    MLDSA44_ED25519_PK_SZ) != 0)
		بازگشت 0;
	بازگشت 1;
}

ایستا صحیح
ssh_mldsa44_ed25519_serialize_public(ثابت ساختار sshkey *کلید, ساختار sshbuf *b,
    شمارش sshkey_serialize_rep opts)
{
	صحیح r;

	اگر (کلید->mldsa_ed25519_pk == پوچ)
		بازگشت SSH_ERR_INVALID_ARGUMENT;
	اگر ((r = sshbuf_put_string(b, کلید->mldsa_ed25519_pk,
	    MLDSA44_ED25519_PK_SZ)) != 0)
		بازگشت r;

	بازگشت 0;
}

ایستا صحیح
ssh_mldsa44_ed25519_serialize_private(ثابت ساختار sshkey *کلید, ساختار sshbuf *b,
    شمارش sshkey_serialize_rep opts)
{
	صحیح r;

	اگر (کلید->mldsa_ed25519_sk == پوچ)
		بازگشت SSH_ERR_INVALID_ARGUMENT;
	اگر (!sshkey_is_cert(کلید)) {
		اگر ((r = ssh_mldsa44_ed25519_serialize_public(کلید,
		    b, opts)) != 0)
			بازگشت r;
	}
	اگر ((r = sshbuf_put_string(b, کلید->mldsa_ed25519_sk,
	    MLDSA44_ED25519_SK_SZ)) != 0)
		بازگشت r;

	بازگشت 0;
}

ایستا صحیح
ssh_mldsa44_ed25519_deserialize_public(ثابت نویسه *ktype, ساختار sshbuf *b,
    ساختار sshkey *کلید)
{
	u_char *pk = پوچ;
	size_t len = 0;
	صحیح r;

	اگر ((r = sshbuf_get_string(b, &pk, &len)) != 0)
		بازگشت r;
	اگر (len != MLDSA44_ED25519_PK_SZ) {
		freezero(pk, len);
		بازگشت SSH_ERR_INVALID_FORMAT;
	}
	کلید->mldsa_ed25519_pk = pk;
	بازگشت 0;
}

ایستا صحیح
ssh_mldsa44_ed25519_deserialize_private(ثابت نویسه *ktype, ساختار sshbuf *b,
    ساختار sshkey *کلید)
{
	صحیح r;
	size_t sklen = 0;
	u_char *sk = پوچ;

	اگر (!sshkey_is_cert(کلید)) {
		اگر ((r = ssh_mldsa44_ed25519_deserialize_public(ktype,
		    b, کلید)) != 0)
			بازگشت r;
	}
	اگر ((r = sshbuf_get_string(b, &sk, &sklen)) != 0)
		برو out;
	اگر (sklen != MLDSA44_ED25519_SK_SZ) {
		r = SSH_ERR_INVALID_FORMAT;
		برو out;
	}
	کلید->mldsa_ed25519_sk = sk;
	sk = پوچ; /* transferred */
	r = 0;
 out:
	freezero(sk, sklen);
	بازگشت r;
}

ایستا صحیح
ssh_mldsa44_ed25519_generate(ساختار sshkey *k, صحیح bits)
{
	ssh_mldsa44_ed25519_cleanup(k);
	اگر ((k->mldsa_ed25519_pk = malloc(MLDSA44_ED25519_PK_SZ)) == پوچ ||
	    (k->mldsa_ed25519_sk = malloc(MLDSA44_ED25519_SK_SZ)) == پوچ) {
		ssh_mldsa44_ed25519_cleanup(k);
		بازگشت SSH_ERR_ALLOC_FAIL;
	}
	اگر (crypto_sign_mldsa44_ed25519_keygen(k->mldsa_ed25519_pk,
	    k->mldsa_ed25519_sk) != 0) {
		ssh_mldsa44_ed25519_cleanup(k);
		بازگشت SSH_ERR_CRYPTO_ERROR;
	}
	بازگشت 0;
}

ایستا صحیح
ssh_mldsa44_ed25519_copy_public(ثابت ساختار sshkey *from, ساختار sshkey *to)
{
	اگر (from->mldsa_ed25519_pk == پوچ)
		بازگشت SSH_ERR_INVALID_ARGUMENT;
	اگر ((to->mldsa_ed25519_pk = malloc(MLDSA44_ED25519_PK_SZ)) == پوچ)
		بازگشت SSH_ERR_ALLOC_FAIL;
	memcpy(to->mldsa_ed25519_pk, from->mldsa_ed25519_pk,
	    MLDSA44_ED25519_PK_SZ);
	بازگشت 0;
}

ایستا صحیح
ssh_mldsa44_ed25519_sign(ساختار sshkey *کلید,
    u_char **sigp, size_t *lenp, ثابت u_char *data, size_t datalen,
    ثابت نویسه *alg, ثابت نویسه *sk_provider, ثابت نویسه *sk_pin,
    u_int compat)
{
	u_char sig[MLDSA44_ED25519_SIG_SZ];
	ساختار sshbuf *b = پوچ;
	صحیح r = SSH_ERR_INTERNAL_ERROR;

	اگر (lenp != پوچ)
		*lenp = 0;
	اگر (sigp != پوچ)
		*sigp = پوچ;

	اگر (کلید == پوچ ||
	    sshkey_type_plain(کلید->type) != کلید_MLDSA44_ED25519 ||
	    کلید->mldsa_ed25519_sk == پوچ)
		بازگشت SSH_ERR_INVALID_ARGUMENT;

	اگر (crypto_sign_mldsa44_ed25519_sign(sig, data, datalen, پوچ, 0,
	    کلید->mldsa_ed25519_sk) != 0) {
		r = SSH_ERR_CRYPTO_ERROR;
		برو out;
	}

	اگر ((b = sshbuf_new()) == پوچ) {
		r = SSH_ERR_ALLOC_FAIL;
		برو out;
	}
	اگر ((r = sshbuf_put_cstring(b, SSH_MLDSA44_ED25519_ALG_NAME)) != 0 ||
	    (r = sshbuf_put_string(b, sig, اندازه(sig))) != 0)
		برو out;

	اگر (sigp != پوچ) {
		اگر ((*sigp = malloc(sshbuf_len(b))) == پوچ) {
			r = SSH_ERR_ALLOC_FAIL;
			برو out;
		}
		memcpy(*sigp, sshbuf_ptr(b), sshbuf_len(b));
	}
	اگر (lenp != پوچ)
		*lenp = sshbuf_len(b);
	r = 0;
 out:
	sshbuf_free(b);
	explicit_bzero(sig, اندازه(sig));
	بازگشت r;
}

ایستا صحیح
ssh_mldsa44_ed25519_verify(ثابت ساختار sshkey *کلید,
    ثابت u_char *sig, size_t siglen, ثابت u_char *data, size_t dlen,
    ثابت نویسه *alg, u_int compat, ساختار sshkey_sig_details **detailsp)
{
	ساختار sshbuf *b = پوچ;
	نویسه *ktype = پوچ;
	ثابت u_char *sigblob;
	size_t len;
	صحیح r;

	اگر (کلید == پوچ ||
	    sshkey_type_plain(کلید->type) != کلید_MLDSA44_ED25519 ||
	    کلید->mldsa_ed25519_pk == پوچ ||
	    sig == پوچ || siglen == 0)
		بازگشت SSH_ERR_INVALID_ARGUMENT;

	اگر ((b = sshbuf_from(sig, siglen)) == پوچ)
		بازگشت SSH_ERR_ALLOC_FAIL;
	اگر ((r = sshbuf_get_cstring(b, &ktype, پوچ)) != 0 ||
	    (r = sshbuf_get_string_direct(b, &sigblob, &len)) != 0)
		برو out;
	اگر (strcmp(SSH_MLDSA44_ED25519_ALG_NAME, ktype) != 0) {
		r = SSH_ERR_کلید_TYPE_MISMATCH;
		برو out;
	}
	اگر (sshbuf_len(b) != 0) {
		r = SSH_ERR_UNEXPECTED_TRAILING_DATA;
		برو out;
	}
	اگر (len != MLDSA44_ED25519_SIG_SZ) {
		r = SSH_ERR_INVALID_FORMAT;
		برو out;
	}

	اگر (crypto_sign_mldsa44_ed25519_verify(sigblob, data, dlen, پوچ, 0,
	    کلید->mldsa_ed25519_pk) != 0) {
		r = SSH_ERR_SIGNATURE_INVALID;
		برو out;
	}

	r = 0;
 out:
	sshbuf_free(b);
	آزاد(ktype);
	بازگشت r;
}

ثابت ساختار sshkey_impl_funcs sshkey_mldsa44_ed25519_funcs = {
	/* .size = */		پوچ,
	/* .alloc = */		پوچ,
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

ثابت ساختار sshkey_impl sshkey_mldsa44_ed25519_impl = {
	/* .name = */		"ssh-mldsa44-ed25519",
	/* .shortname = */	"MLDSA44-ED25519",
	/* .sigalg = */		پوچ,
	/* .type = */		کلید_MLDSA44_ED25519,
	/* .nid = */		0,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	512, /* size of the private key */
	/* .funcs = */		&sshkey_mldsa44_ed25519_funcs,
};

ثابت ساختار sshkey_impl sshkey_mldsa44_ed25519_cert_impl = {
	/* .name = */		"ssh-mldsa44-ed25519-cert",
	/* .shortname = */	"MLDSA44-ED25519-CERT",
	/* .sigalg = */		پوچ,
	/* .type = */		کلید_MLDSA44_ED25519_CERT,
	/* .nid = */		0,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	512, /* size of the private key */
	/* .funcs = */		&sshkey_mldsa44_ed25519_funcs,
};
#endif /* USE_MLDSA */
