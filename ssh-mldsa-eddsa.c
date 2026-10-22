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

#ضمن "includes.h"

#ifdef USE_MLDSA

#ضمن <sys/types.h>
#ضمن <stdint.h>
#ضمن <string.h>
#ضمن <stdlib.h>

#ضمن "crypto_api.h"
#ضمن "sshbuf.h"
#ضمن "ssherr.h"
#ضمن "digest.h"
#define SSHKEY_INTERNAL
#ضمن "sshkey.h"
#ضمن "log.h"

#define COMPOSITE_PREFIX "CompositeAlgorithmSignatures2025"
#define COMPOSITE_LABEL  "COMPSIG-MLDSA44-Ed25519-SHA512"
#define SSH_MLDSA44_ED25519_ALG_NAME   "ssh-mldsa44-ed25519"

/*
 * raw_* functions implement the draft-ietf-lamps-pq-composite-sigs-18
 * composite signature scheme. These are exposed (i.e. not static) so
 * we can test them separately in unittests/crypto.
 */

صحيح
crypto_sign_mldsa44_ed25519_keygen(uint8_t pk[MLDSA44_ED25519_PK_SZ],
    uint8_t sk[MLDSA44_ED25519_SK_SZ])
{
	uint8_t mldsa_seed[MLDSA44_SEEDBYTES];
	uint8_t ed25519_seed[crypto_sign_ed25519_SEEDBYTES];
	صحيح r;

	arc4random_buf(mldsa_seed, حجم(mldsa_seed));
	arc4random_buf(ed25519_seed, حجم(ed25519_seed));

	r = crypto_sign_mldsa44_ed25519_keygen_seeded(pk, sk, mldsa_seed,
	    ed25519_seed);
	explicit_bzero(mldsa_seed, حجم(mldsa_seed));
	explicit_bzero(ed25519_seed, حجم(ed25519_seed));
	أرجع r;
}

صحيح
crypto_sign_mldsa44_ed25519_keygen_seeded(uint8_t pk[MLDSA44_ED25519_PK_SZ],
    uint8_t sk[MLDSA44_ED25519_SK_SZ],
    ثابت uint8_t mldsa_seed[MLDSA44_SEEDBYTES],
    ثابت uint8_t ed25519_seed[crypto_sign_ed25519_SEEDBYTES])
{
	uint8_t ed25519_pk[MLDSA44_SEEDBYTES];
	uint8_t ed25519_sk[crypto_sign_ed25519_SECRETKEYBYTES];
	uint8_t mldsa_sk[MLDSA44_SECRETKEYBYTES];
	صحيح ret = -1;

	إذا (crypto_sign_mldsa44_keypair_seeded(pk, mldsa_sk, mldsa_seed) != 0)
		اذهب out;
	إذا (crypto_sign_ed25519_seed_keypair(ed25519_pk, ed25519_sk,
	    ed25519_seed) != 0)
		اذهب out;

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
	explicit_bzero(mldsa_sk, حجم(mldsa_sk));
	explicit_bzero(ed25519_sk, حجم(ed25519_sk));
	أرجع ret;
}

ساكن صحيح
construct_m_أولي(uint8_t **m_primep, size_t *m_أولي_lenp,
    ثابت uint8_t *رسالة, size_t msglen,
    ثابت uint8_t *ctx, size_t ctxlen)
{
	صحيح r;
	uint8_t hash[64];
	بنية sshbuf *m_أولي;

	*m_primep = عدم;
	*m_أولي_lenp = 0;

	إذا (ctxlen > 255)
		أرجع SSH_ERR_INVALID_ARGUMENT;
	إذا ((r = ssh_digest_memory(SSH_DIGEST_SHA512, رسالة, msglen,
	    hash, حجم(hash))) != 0)
		أرجع r;
	إذا ((m_أولي = sshbuf_new()) == عدم)
		أرجع SSH_ERR_ALLOC_FAIL;
	إذا ((r = sshbuf_put(m_أولي, COMPOSITE_PREFIX,
	    حجم(COMPOSITE_PREFIX) - 1)) != 0 ||
	    (r = sshbuf_put(m_أولي, COMPOSITE_LABEL,
	    حجم(COMPOSITE_LABEL) - 1)) != 0 ||
	    (r = sshbuf_put_u8(m_أولي, (uint8_t)ctxlen)) != 0 ||
	    (r = sshbuf_put(m_أولي, ctx, ctxlen)) != 0 ||
	    (r = sshbuf_put(m_أولي, hash, حجم(hash))) != 0) {
		sshbuf_free(m_أولي);
		أرجع r;
	}
	إذا ((*m_primep = malloc(sshbuf_len(m_أولي))) == عدم) {
		sshbuf_free(m_أولي);
		أرجع SSH_ERR_ALLOC_FAIL;
	}
	memcpy(*m_primep, sshbuf_ptr(m_أولي), sshbuf_len(m_أولي));
	*m_أولي_lenp = sshbuf_len(m_أولي);
	/* success */
	sshbuf_free(m_أولي);
	أرجع 0;
}

صحيح
crypto_sign_mldsa44_ed25519_sign(uint8_t sig[MLDSA44_ED25519_SIG_SZ],
    ثابت uint8_t *رسالة, size_t msglen,
    ثابت uint8_t *ctx, size_t ctxlen,
    ثابت uint8_t sk[MLDSA44_ED25519_SK_SZ])
{
	uint8_t *m_أولي = عدم;
	size_t m_أولي_len = 0;
	uint8_t mldsa_sk[MLDSA44_SECRETKEYBYTES];
	uint8_t mldsa_pk_dummy[MLDSA44_PUBLICKEYBYTES];
	uint8_t ed25519_pk[crypto_sign_ed25519_PUBLICKEYBYTES];
	uint8_t ed25519_sk[crypto_sign_ed25519_SECRETKEYBYTES];
	uint8_t mldsa_rnd[MLDSA44_SEEDBYTES];
	unsigned long long smlen;
	صحيح r = -1;

	إذا (construct_m_أولي(&m_أولي, &m_أولي_len, رسالة, msglen,
	    ctx, ctxlen) != 0)
		أرجع -1;

	/* Expand ML-DSA key from seed */
	إذا (crypto_sign_mldsa44_keypair_seeded(mldsa_pk_dummy, mldsa_sk, sk) != 0)
		اذهب out;

	/* Sign with ML-DSA */
	arc4random_buf(mldsa_rnd, حجم(mldsa_rnd));
	إذا (crypto_sign_mldsa44_seeded(sig, m_أولي, m_أولي_len,
	    (ثابت uint8_t *)COMPOSITE_LABEL, حجم(COMPOSITE_LABEL) - 1,
	    mldsa_sk, mldsa_rnd) != 0)
		اذهب out;

	/* Expand Ed25519 key from seed */
	إذا (crypto_sign_ed25519_seed_keypair(ed25519_pk, ed25519_sk,
	    sk + MLDSA44_SEEDBYTES) != 0)
		اذهب out;

	/* Sign with Ed25519 */
	إذا (crypto_sign_ed25519_detached(sig + MLDSA44_SIGBYTES, &smlen,
	    m_أولي, m_أولي_len, ed25519_sk) != 0 ||
	    smlen != crypto_sign_ed25519_BYTES)
		اذهب out;

	r = 0;
 out:
	حرر(m_أولي);
	explicit_bzero(mldsa_rnd, حجم(mldsa_rnd));
	explicit_bzero(mldsa_sk, حجم(mldsa_sk));
	explicit_bzero(ed25519_sk, حجم(ed25519_sk));
	أرجع r;
}

صحيح
crypto_sign_mldsa44_ed25519_verify(ثابت uint8_t sig[MLDSA44_ED25519_SIG_SZ],
    ثابت uint8_t *رسالة, size_t msglen,
    ثابت uint8_t *ctx, size_t ctxlen,
    ثابت uint8_t pk[MLDSA44_ED25519_PK_SZ])
{
	uint8_t *m_أولي = عدم;
	size_t m_أولي_len = 0;
	صحيح r = -1;

	إذا (construct_m_أولي(&m_أولي, &m_أولي_len, رسالة, msglen,
	    ctx, ctxlen) != 0)
		أرجع -1;

	/* Verify ML-DSA */
	إذا (crypto_sign_mldsa44_verify(sig, m_أولي, m_أولي_len,
	    (ثابت uint8_t *)COMPOSITE_LABEL, حجم(COMPOSITE_LABEL) - 1,
	    pk) != 0)
		اذهب out;

	/* Verify Ed25519 */
	إذا (crypto_sign_ed25519_verify_detached(sig + MLDSA44_SIGBYTES,
	    m_أولي, m_أولي_len, pk + MLDSA44_PUBLICKEYBYTES) != 0)
		اذهب out;

	r = 0;
 out:
	حرر(m_أولي);
	أرجع r;
}

/* sshkey integration */

ساكن فراغ
ssh_mldsa44_ed25519_cleanup(بنية sshkey *k)
{
	freezero(k->mldsa_ed25519_pk, MLDSA44_ED25519_PK_SZ);
	freezero(k->mldsa_ed25519_sk, MLDSA44_ED25519_SK_SZ);
	k->mldsa_ed25519_pk = عدم;
	k->mldsa_ed25519_sk = عدم;
}

ساكن صحيح
ssh_mldsa44_ed25519_equal(ثابت بنية sshkey *a, ثابت بنية sshkey *b)
{
	إذا (a->mldsa_ed25519_pk == عدم || b->mldsa_ed25519_pk == عدم)
		أرجع 0;
	إذا (memcmp(a->mldsa_ed25519_pk, b->mldsa_ed25519_pk,
	    MLDSA44_ED25519_PK_SZ) != 0)
		أرجع 0;
	أرجع 1;
}

ساكن صحيح
ssh_mldsa44_ed25519_serialize_public(ثابت بنية sshkey *مفتاح, بنية sshbuf *b,
    تعداد sshkey_serialize_rep opts)
{
	صحيح r;

	إذا (مفتاح->mldsa_ed25519_pk == عدم)
		أرجع SSH_ERR_INVALID_ARGUMENT;
	إذا ((r = sshbuf_put_string(b, مفتاح->mldsa_ed25519_pk,
	    MLDSA44_ED25519_PK_SZ)) != 0)
		أرجع r;

	أرجع 0;
}

ساكن صحيح
ssh_mldsa44_ed25519_serialize_private(ثابت بنية sshkey *مفتاح, بنية sshbuf *b,
    تعداد sshkey_serialize_rep opts)
{
	صحيح r;

	إذا (مفتاح->mldsa_ed25519_sk == عدم)
		أرجع SSH_ERR_INVALID_ARGUMENT;
	إذا (!sshkey_is_cert(مفتاح)) {
		إذا ((r = ssh_mldsa44_ed25519_serialize_public(مفتاح,
		    b, opts)) != 0)
			أرجع r;
	}
	إذا ((r = sshbuf_put_string(b, مفتاح->mldsa_ed25519_sk,
	    MLDSA44_ED25519_SK_SZ)) != 0)
		أرجع r;

	أرجع 0;
}

ساكن صحيح
ssh_mldsa44_ed25519_deserialize_public(ثابت حرف *ktype, بنية sshbuf *b,
    بنية sshkey *مفتاح)
{
	u_char *pk = عدم;
	size_t len = 0;
	صحيح r;

	إذا ((r = sshbuf_get_string(b, &pk, &len)) != 0)
		أرجع r;
	إذا (len != MLDSA44_ED25519_PK_SZ) {
		freezero(pk, len);
		أرجع SSH_ERR_INVALID_FORMAT;
	}
	مفتاح->mldsa_ed25519_pk = pk;
	أرجع 0;
}

ساكن صحيح
ssh_mldsa44_ed25519_deserialize_private(ثابت حرف *ktype, بنية sshbuf *b,
    بنية sshkey *مفتاح)
{
	صحيح r;
	size_t sklen = 0;
	u_char *sk = عدم;

	إذا (!sshkey_is_cert(مفتاح)) {
		إذا ((r = ssh_mldsa44_ed25519_deserialize_public(ktype,
		    b, مفتاح)) != 0)
			أرجع r;
	}
	إذا ((r = sshbuf_get_string(b, &sk, &sklen)) != 0)
		اذهب out;
	إذا (sklen != MLDSA44_ED25519_SK_SZ) {
		r = SSH_ERR_INVALID_FORMAT;
		اذهب out;
	}
	مفتاح->mldsa_ed25519_sk = sk;
	sk = عدم; /* transferred */
	r = 0;
 out:
	freezero(sk, sklen);
	أرجع r;
}

ساكن صحيح
ssh_mldsa44_ed25519_generate(بنية sshkey *k, صحيح bits)
{
	ssh_mldsa44_ed25519_cleanup(k);
	إذا ((k->mldsa_ed25519_pk = malloc(MLDSA44_ED25519_PK_SZ)) == عدم ||
	    (k->mldsa_ed25519_sk = malloc(MLDSA44_ED25519_SK_SZ)) == عدم) {
		ssh_mldsa44_ed25519_cleanup(k);
		أرجع SSH_ERR_ALLOC_FAIL;
	}
	إذا (crypto_sign_mldsa44_ed25519_keygen(k->mldsa_ed25519_pk,
	    k->mldsa_ed25519_sk) != 0) {
		ssh_mldsa44_ed25519_cleanup(k);
		أرجع SSH_ERR_CRYPTO_ERROR;
	}
	أرجع 0;
}

ساكن صحيح
ssh_mldsa44_ed25519_copy_public(ثابت بنية sshkey *from, بنية sshkey *to)
{
	إذا (from->mldsa_ed25519_pk == عدم)
		أرجع SSH_ERR_INVALID_ARGUMENT;
	إذا ((to->mldsa_ed25519_pk = malloc(MLDSA44_ED25519_PK_SZ)) == عدم)
		أرجع SSH_ERR_ALLOC_FAIL;
	memcpy(to->mldsa_ed25519_pk, from->mldsa_ed25519_pk,
	    MLDSA44_ED25519_PK_SZ);
	أرجع 0;
}

ساكن صحيح
ssh_mldsa44_ed25519_sign(بنية sshkey *مفتاح,
    u_char **sigp, size_t *lenp, ثابت u_char *data, size_t datalen,
    ثابت حرف *alg, ثابت حرف *sk_provider, ثابت حرف *sk_pin,
    u_int compat)
{
	u_char sig[MLDSA44_ED25519_SIG_SZ];
	بنية sshbuf *b = عدم;
	صحيح r = SSH_ERR_INTERNAL_ERROR;

	إذا (lenp != عدم)
		*lenp = 0;
	إذا (sigp != عدم)
		*sigp = عدم;

	إذا (مفتاح == عدم ||
	    sshkey_type_plain(مفتاح->type) != مفتاح_MLDSA44_ED25519 ||
	    مفتاح->mldsa_ed25519_sk == عدم)
		أرجع SSH_ERR_INVALID_ARGUMENT;

	إذا (crypto_sign_mldsa44_ed25519_sign(sig, data, datalen, عدم, 0,
	    مفتاح->mldsa_ed25519_sk) != 0) {
		r = SSH_ERR_CRYPTO_ERROR;
		اذهب out;
	}

	إذا ((b = sshbuf_new()) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب out;
	}
	إذا ((r = sshbuf_put_cstring(b, SSH_MLDSA44_ED25519_ALG_NAME)) != 0 ||
	    (r = sshbuf_put_string(b, sig, حجم(sig))) != 0)
		اذهب out;

	إذا (sigp != عدم) {
		إذا ((*sigp = malloc(sshbuf_len(b))) == عدم) {
			r = SSH_ERR_ALLOC_FAIL;
			اذهب out;
		}
		memcpy(*sigp, sshbuf_ptr(b), sshbuf_len(b));
	}
	إذا (lenp != عدم)
		*lenp = sshbuf_len(b);
	r = 0;
 out:
	sshbuf_free(b);
	explicit_bzero(sig, حجم(sig));
	أرجع r;
}

ساكن صحيح
ssh_mldsa44_ed25519_verify(ثابت بنية sshkey *مفتاح,
    ثابت u_char *sig, size_t siglen, ثابت u_char *data, size_t dlen,
    ثابت حرف *alg, u_int compat, بنية sshkey_sig_details **detailsp)
{
	بنية sshbuf *b = عدم;
	حرف *ktype = عدم;
	ثابت u_char *sigblob;
	size_t len;
	صحيح r;

	إذا (مفتاح == عدم ||
	    sshkey_type_plain(مفتاح->type) != مفتاح_MLDSA44_ED25519 ||
	    مفتاح->mldsa_ed25519_pk == عدم ||
	    sig == عدم || siglen == 0)
		أرجع SSH_ERR_INVALID_ARGUMENT;

	إذا ((b = sshbuf_from(sig, siglen)) == عدم)
		أرجع SSH_ERR_ALLOC_FAIL;
	إذا ((r = sshbuf_get_cstring(b, &ktype, عدم)) != 0 ||
	    (r = sshbuf_get_string_direct(b, &sigblob, &len)) != 0)
		اذهب out;
	إذا (strcmp(SSH_MLDSA44_ED25519_ALG_NAME, ktype) != 0) {
		r = SSH_ERR_مفتاح_TYPE_MISMATCH;
		اذهب out;
	}
	إذا (sshbuf_len(b) != 0) {
		r = SSH_ERR_UNEXPECTED_TRAILING_DATA;
		اذهب out;
	}
	إذا (len != MLDSA44_ED25519_SIG_SZ) {
		r = SSH_ERR_INVALID_FORMAT;
		اذهب out;
	}

	إذا (crypto_sign_mldsa44_ed25519_verify(sigblob, data, dlen, عدم, 0,
	    مفتاح->mldsa_ed25519_pk) != 0) {
		r = SSH_ERR_SIGNATURE_INVALID;
		اذهب out;
	}

	r = 0;
 out:
	sshbuf_free(b);
	حرر(ktype);
	أرجع r;
}

ثابت بنية sshkey_impl_funcs sshkey_mldsa44_ed25519_funcs = {
	/* .size = */		عدم,
	/* .alloc = */		عدم,
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

ثابت بنية sshkey_impl sshkey_mldsa44_ed25519_impl = {
	/* .name = */		"ssh-mldsa44-ed25519",
	/* .shortname = */	"MLDSA44-ED25519",
	/* .sigalg = */		عدم,
	/* .type = */		مفتاح_MLDSA44_ED25519,
	/* .nid = */		0,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	512, /* size of the private key */
	/* .funcs = */		&sshkey_mldsa44_ed25519_funcs,
};

ثابت بنية sshkey_impl sshkey_mldsa44_ed25519_cert_impl = {
	/* .name = */		"ssh-mldsa44-ed25519-cert",
	/* .shortname = */	"MLDSA44-ED25519-CERT",
	/* .sigalg = */		عدم,
	/* .type = */		مفتاح_MLDSA44_ED25519_CERT,
	/* .nid = */		0,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	512, /* size of the private key */
	/* .funcs = */		&sshkey_mldsa44_ed25519_funcs,
};
#endif /* USE_MLDSA */
