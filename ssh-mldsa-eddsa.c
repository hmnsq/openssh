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
	फर्काऊ r;
}

पूर्णाङ्क
crypto_sign_mldsa44_ed25519_keygen_seeded(uint8_t pk[MLDSA44_ED25519_PK_SZ],
    uint8_t sk[MLDSA44_ED25519_SK_SZ],
    अचर uint8_t mldsa_seed[MLDSA44_SEEDBYTES],
    अचर uint8_t ed25519_seed[crypto_sign_ed25519_SEEDBYTES])
{
	uint8_t ed25519_pk[MLDSA44_SEEDBYTES];
	uint8_t ed25519_sk[crypto_sign_ed25519_SECRETKEYBYTES];
	uint8_t mldsa_sk[MLDSA44_SECRETKEYBYTES];
	पूर्णाङ्क ret = -1;

	यदि (crypto_sign_mldsa44_keypair_seeded(pk, mldsa_sk, mldsa_seed) != 0)
		गच्छ out;
	यदि (crypto_sign_ed25519_seed_keypair(ed25519_pk, ed25519_sk,
	    ed25519_seed) != 0)
		गच्छ out;

	/* Serialize PK: mldsaPK || ed25519PK */
	स_नकल(pk + MLDSA44_PUBLICKEYBYTES, ed25519_pk,
	    crypto_sign_ed25519_SEEDBYTES);

	/* Serialize SK: mldsaSeed || ed25519Seed */
	स_नकल(sk, mldsa_seed, MLDSA44_SEEDBYTES);
	स_नकल(sk + MLDSA44_SEEDBYTES, ed25519_seed,
	    crypto_sign_ed25519_SEEDBYTES);

	/* success */
	ret = 0;
 out:
	explicit_bzero(mldsa_sk, परिमाण(mldsa_sk));
	explicit_bzero(ed25519_sk, परिमाण(ed25519_sk));
	फर्काऊ ret;
}

स्थिर पूर्णाङ्क
construct_m_अविभाज्य(uint8_t **m_primep, माप_प्रकार *m_अविभाज्य_lenp,
    अचर uint8_t *सन्देश, माप_प्रकार msglen,
    अचर uint8_t *ctx, माप_प्रकार ctxlen)
{
	पूर्णाङ्क r;
	uint8_t hash[64];
	संरचना sshbuf *m_अविभाज्य;

	*m_primep = रिक्त;
	*m_अविभाज्य_lenp = 0;

	यदि (ctxlen > 255)
		फर्काऊ SSH_ERR_INVALID_ARGUMENT;
	यदि ((r = ssh_digest_memory(SSH_DIGEST_SHA512, सन्देश, msglen,
	    hash, परिमाण(hash))) != 0)
		फर्काऊ r;
	यदि ((m_अविभाज्य = sshbuf_new()) == रिक्त)
		फर्काऊ SSH_ERR_ALLOC_FAIL;
	यदि ((r = sshbuf_put(m_अविभाज्य, COMPOSITE_PREFIX,
	    परिमाण(COMPOSITE_PREFIX) - 1)) != 0 ||
	    (r = sshbuf_put(m_अविभाज्य, COMPOSITE_LABEL,
	    परिमाण(COMPOSITE_LABEL) - 1)) != 0 ||
	    (r = sshbuf_put_u8(m_अविभाज्य, (uint8_t)ctxlen)) != 0 ||
	    (r = sshbuf_put(m_अविभाज्य, ctx, ctxlen)) != 0 ||
	    (r = sshbuf_put(m_अविभाज्य, hash, परिमाण(hash))) != 0) {
		sshbuf_free(m_अविभाज्य);
		फर्काऊ r;
	}
	यदि ((*m_primep = दो_स्मृति(sshbuf_len(m_अविभाज्य))) == रिक्त) {
		sshbuf_free(m_अविभाज्य);
		फर्काऊ SSH_ERR_ALLOC_FAIL;
	}
	स_नकल(*m_primep, sshbuf_ptr(m_अविभाज्य), sshbuf_len(m_अविभाज्य));
	*m_अविभाज्य_lenp = sshbuf_len(m_अविभाज्य);
	/* success */
	sshbuf_free(m_अविभाज्य);
	फर्काऊ 0;
}

पूर्णाङ्क
crypto_sign_mldsa44_ed25519_sign(uint8_t sig[MLDSA44_ED25519_SIG_SZ],
    अचर uint8_t *सन्देश, माप_प्रकार msglen,
    अचर uint8_t *ctx, माप_प्रकार ctxlen,
    अचर uint8_t sk[MLDSA44_ED25519_SK_SZ])
{
	uint8_t *m_अविभाज्य = रिक्त;
	माप_प्रकार m_अविभाज्य_len = 0;
	uint8_t mldsa_sk[MLDSA44_SECRETKEYBYTES];
	uint8_t mldsa_pk_dummy[MLDSA44_PUBLICKEYBYTES];
	uint8_t ed25519_pk[crypto_sign_ed25519_PUBLICKEYBYTES];
	uint8_t ed25519_sk[crypto_sign_ed25519_SECRETKEYBYTES];
	uint8_t mldsa_rnd[MLDSA44_SEEDBYTES];
	अचिन्हित दीर्घ दीर्घ smlen;
	पूर्णाङ्क r = -1;

	यदि (construct_m_अविभाज्य(&m_अविभाज्य, &m_अविभाज्य_len, सन्देश, msglen,
	    ctx, ctxlen) != 0)
		फर्काऊ -1;

	/* Expand ML-DSA key from seed */
	यदि (crypto_sign_mldsa44_keypair_seeded(mldsa_pk_dummy, mldsa_sk, sk) != 0)
		गच्छ out;

	/* Sign with ML-DSA */
	arc4random_buf(mldsa_rnd, परिमाण(mldsa_rnd));
	यदि (crypto_sign_mldsa44_seeded(sig, m_अविभाज्य, m_अविभाज्य_len,
	    (अचर uint8_t *)COMPOSITE_LABEL, परिमाण(COMPOSITE_LABEL) - 1,
	    mldsa_sk, mldsa_rnd) != 0)
		गच्छ out;

	/* Expand Ed25519 key from seed */
	यदि (crypto_sign_ed25519_seed_keypair(ed25519_pk, ed25519_sk,
	    sk + MLDSA44_SEEDBYTES) != 0)
		गच्छ out;

	/* Sign with Ed25519 */
	यदि (crypto_sign_ed25519_detached(sig + MLDSA44_SIGBYTES, &smlen,
	    m_अविभाज्य, m_अविभाज्य_len, ed25519_sk) != 0 ||
	    smlen != crypto_sign_ed25519_BYTES)
		गच्छ out;

	r = 0;
 out:
	मुक्त(m_अविभाज्य);
	explicit_bzero(mldsa_rnd, परिमाण(mldsa_rnd));
	explicit_bzero(mldsa_sk, परिमाण(mldsa_sk));
	explicit_bzero(ed25519_sk, परिमाण(ed25519_sk));
	फर्काऊ r;
}

पूर्णाङ्क
crypto_sign_mldsa44_ed25519_verify(अचर uint8_t sig[MLDSA44_ED25519_SIG_SZ],
    अचर uint8_t *सन्देश, माप_प्रकार msglen,
    अचर uint8_t *ctx, माप_प्रकार ctxlen,
    अचर uint8_t pk[MLDSA44_ED25519_PK_SZ])
{
	uint8_t *m_अविभाज्य = रिक्त;
	माप_प्रकार m_अविभाज्य_len = 0;
	पूर्णाङ्क r = -1;

	यदि (construct_m_अविभाज्य(&m_अविभाज्य, &m_अविभाज्य_len, सन्देश, msglen,
	    ctx, ctxlen) != 0)
		फर्काऊ -1;

	/* Verify ML-DSA */
	यदि (crypto_sign_mldsa44_verify(sig, m_अविभाज्य, m_अविभाज्य_len,
	    (अचर uint8_t *)COMPOSITE_LABEL, परिमाण(COMPOSITE_LABEL) - 1,
	    pk) != 0)
		गच्छ out;

	/* Verify Ed25519 */
	यदि (crypto_sign_ed25519_verify_detached(sig + MLDSA44_SIGBYTES,
	    m_अविभाज्य, m_अविभाज्य_len, pk + MLDSA44_PUBLICKEYBYTES) != 0)
		गच्छ out;

	r = 0;
 out:
	मुक्त(m_अविभाज्य);
	फर्काऊ r;
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
ssh_mldsa44_ed25519_equal(अचर संरचना sshkey *a, अचर संरचना sshkey *b)
{
	यदि (a->mldsa_ed25519_pk == रिक्त || b->mldsa_ed25519_pk == रिक्त)
		फर्काऊ 0;
	यदि (स_भेद(a->mldsa_ed25519_pk, b->mldsa_ed25519_pk,
	    MLDSA44_ED25519_PK_SZ) != 0)
		फर्काऊ 0;
	फर्काऊ 1;
}

स्थिर पूर्णाङ्क
ssh_mldsa44_ed25519_serialize_public(अचर संरचना sshkey *साँचो, संरचना sshbuf *b,
    गणना sshkey_serialize_rep opts)
{
	पूर्णाङ्क r;

	यदि (साँचो->mldsa_ed25519_pk == रिक्त)
		फर्काऊ SSH_ERR_INVALID_ARGUMENT;
	यदि ((r = sshbuf_put_string(b, साँचो->mldsa_ed25519_pk,
	    MLDSA44_ED25519_PK_SZ)) != 0)
		फर्काऊ r;

	फर्काऊ 0;
}

स्थिर पूर्णाङ्क
ssh_mldsa44_ed25519_serialize_private(अचर संरचना sshkey *साँचो, संरचना sshbuf *b,
    गणना sshkey_serialize_rep opts)
{
	पूर्णाङ्क r;

	यदि (साँचो->mldsa_ed25519_sk == रिक्त)
		फर्काऊ SSH_ERR_INVALID_ARGUMENT;
	यदि (!sshkey_is_cert(साँचो)) {
		यदि ((r = ssh_mldsa44_ed25519_serialize_public(साँचो,
		    b, opts)) != 0)
			फर्काऊ r;
	}
	यदि ((r = sshbuf_put_string(b, साँचो->mldsa_ed25519_sk,
	    MLDSA44_ED25519_SK_SZ)) != 0)
		फर्काऊ r;

	फर्काऊ 0;
}

स्थिर पूर्णाङ्क
ssh_mldsa44_ed25519_deserialize_public(अचर वर्ण *ktype, संरचना sshbuf *b,
    संरचना sshkey *साँचो)
{
	u_char *pk = रिक्त;
	माप_प्रकार len = 0;
	पूर्णाङ्क r;

	यदि ((r = sshbuf_get_string(b, &pk, &len)) != 0)
		फर्काऊ r;
	यदि (len != MLDSA44_ED25519_PK_SZ) {
		freezero(pk, len);
		फर्काऊ SSH_ERR_INVALID_FORMAT;
	}
	साँचो->mldsa_ed25519_pk = pk;
	फर्काऊ 0;
}

स्थिर पूर्णाङ्क
ssh_mldsa44_ed25519_deserialize_private(अचर वर्ण *ktype, संरचना sshbuf *b,
    संरचना sshkey *साँचो)
{
	पूर्णाङ्क r;
	माप_प्रकार sklen = 0;
	u_char *sk = रिक्त;

	यदि (!sshkey_is_cert(साँचो)) {
		यदि ((r = ssh_mldsa44_ed25519_deserialize_public(ktype,
		    b, साँचो)) != 0)
			फर्काऊ r;
	}
	यदि ((r = sshbuf_get_string(b, &sk, &sklen)) != 0)
		गच्छ out;
	यदि (sklen != MLDSA44_ED25519_SK_SZ) {
		r = SSH_ERR_INVALID_FORMAT;
		गच्छ out;
	}
	साँचो->mldsa_ed25519_sk = sk;
	sk = रिक्त; /* transferred */
	r = 0;
 out:
	freezero(sk, sklen);
	फर्काऊ r;
}

स्थिर पूर्णाङ्क
ssh_mldsa44_ed25519_generate(संरचना sshkey *k, पूर्णाङ्क bits)
{
	ssh_mldsa44_ed25519_cleanup(k);
	यदि ((k->mldsa_ed25519_pk = दो_स्मृति(MLDSA44_ED25519_PK_SZ)) == रिक्त ||
	    (k->mldsa_ed25519_sk = दो_स्मृति(MLDSA44_ED25519_SK_SZ)) == रिक्त) {
		ssh_mldsa44_ed25519_cleanup(k);
		फर्काऊ SSH_ERR_ALLOC_FAIL;
	}
	यदि (crypto_sign_mldsa44_ed25519_keygen(k->mldsa_ed25519_pk,
	    k->mldsa_ed25519_sk) != 0) {
		ssh_mldsa44_ed25519_cleanup(k);
		फर्काऊ SSH_ERR_CRYPTO_ERROR;
	}
	फर्काऊ 0;
}

स्थिर पूर्णाङ्क
ssh_mldsa44_ed25519_copy_public(अचर संरचना sshkey *from, संरचना sshkey *to)
{
	यदि (from->mldsa_ed25519_pk == रिक्त)
		फर्काऊ SSH_ERR_INVALID_ARGUMENT;
	यदि ((to->mldsa_ed25519_pk = दो_स्मृति(MLDSA44_ED25519_PK_SZ)) == रिक्त)
		फर्काऊ SSH_ERR_ALLOC_FAIL;
	स_नकल(to->mldsa_ed25519_pk, from->mldsa_ed25519_pk,
	    MLDSA44_ED25519_PK_SZ);
	फर्काऊ 0;
}

स्थिर पूर्णाङ्क
ssh_mldsa44_ed25519_sign(संरचना sshkey *साँचो,
    u_char **sigp, माप_प्रकार *lenp, अचर u_char *data, माप_प्रकार datalen,
    अचर वर्ण *alg, अचर वर्ण *sk_provider, अचर वर्ण *sk_pin,
    u_int compat)
{
	u_char sig[MLDSA44_ED25519_SIG_SZ];
	संरचना sshbuf *b = रिक्त;
	पूर्णाङ्क r = SSH_ERR_INTERNAL_ERROR;

	यदि (lenp != रिक्त)
		*lenp = 0;
	यदि (sigp != रिक्त)
		*sigp = रिक्त;

	यदि (साँचो == रिक्त ||
	    sshkey_type_plain(साँचो->type) != साँचो_MLDSA44_ED25519 ||
	    साँचो->mldsa_ed25519_sk == रिक्त)
		फर्काऊ SSH_ERR_INVALID_ARGUMENT;

	यदि (crypto_sign_mldsa44_ed25519_sign(sig, data, datalen, रिक्त, 0,
	    साँचो->mldsa_ed25519_sk) != 0) {
		r = SSH_ERR_CRYPTO_ERROR;
		गच्छ out;
	}

	यदि ((b = sshbuf_new()) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ out;
	}
	यदि ((r = sshbuf_put_cstring(b, SSH_MLDSA44_ED25519_ALG_NAME)) != 0 ||
	    (r = sshbuf_put_string(b, sig, परिमाण(sig))) != 0)
		गच्छ out;

	यदि (sigp != रिक्त) {
		यदि ((*sigp = दो_स्मृति(sshbuf_len(b))) == रिक्त) {
			r = SSH_ERR_ALLOC_FAIL;
			गच्छ out;
		}
		स_नकल(*sigp, sshbuf_ptr(b), sshbuf_len(b));
	}
	यदि (lenp != रिक्त)
		*lenp = sshbuf_len(b);
	r = 0;
 out:
	sshbuf_free(b);
	explicit_bzero(sig, परिमाण(sig));
	फर्काऊ r;
}

स्थिर पूर्णाङ्क
ssh_mldsa44_ed25519_verify(अचर संरचना sshkey *साँचो,
    अचर u_char *sig, माप_प्रकार siglen, अचर u_char *data, माप_प्रकार dlen,
    अचर वर्ण *alg, u_int compat, संरचना sshkey_sig_details **detailsp)
{
	संरचना sshbuf *b = रिक्त;
	वर्ण *ktype = रिक्त;
	अचर u_char *sigblob;
	माप_प्रकार len;
	पूर्णाङ्क r;

	यदि (साँचो == रिक्त ||
	    sshkey_type_plain(साँचो->type) != साँचो_MLDSA44_ED25519 ||
	    साँचो->mldsa_ed25519_pk == रिक्त ||
	    sig == रिक्त || siglen == 0)
		फर्काऊ SSH_ERR_INVALID_ARGUMENT;

	यदि ((b = sshbuf_from(sig, siglen)) == रिक्त)
		फर्काऊ SSH_ERR_ALLOC_FAIL;
	यदि ((r = sshbuf_get_cstring(b, &ktype, रिक्त)) != 0 ||
	    (r = sshbuf_get_string_direct(b, &sigblob, &len)) != 0)
		गच्छ out;
	यदि (म_भेद(SSH_MLDSA44_ED25519_ALG_NAME, ktype) != 0) {
		r = SSH_ERR_साँचो_TYPE_MISMATCH;
		गच्छ out;
	}
	यदि (sshbuf_len(b) != 0) {
		r = SSH_ERR_UNEXPECTED_TRAILING_DATA;
		गच्छ out;
	}
	यदि (len != MLDSA44_ED25519_SIG_SZ) {
		r = SSH_ERR_INVALID_FORMAT;
		गच्छ out;
	}

	यदि (crypto_sign_mldsa44_ed25519_verify(sigblob, data, dlen, रिक्त, 0,
	    साँचो->mldsa_ed25519_pk) != 0) {
		r = SSH_ERR_SIGNATURE_INVALID;
		गच्छ out;
	}

	r = 0;
 out:
	sshbuf_free(b);
	मुक्त(ktype);
	फर्काऊ r;
}

अचर संरचना sshkey_impl_funcs sshkey_mldsa44_ed25519_funcs = {
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

अचर संरचना sshkey_impl sshkey_mldsa44_ed25519_impl = {
	/* .name = */		"ssh-mldsa44-ed25519",
	/* .shortname = */	"MLDSA44-ED25519",
	/* .sigalg = */		रिक्त,
	/* .type = */		साँचो_MLDSA44_ED25519,
	/* .nid = */		0,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	512, /* size of the private key */
	/* .funcs = */		&sshkey_mldsa44_ed25519_funcs,
};

अचर संरचना sshkey_impl sshkey_mldsa44_ed25519_cert_impl = {
	/* .name = */		"ssh-mldsa44-ed25519-cert",
	/* .shortname = */	"MLDSA44-ED25519-CERT",
	/* .sigalg = */		रिक्त,
	/* .type = */		साँचो_MLDSA44_ED25519_CERT,
	/* .nid = */		0,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	512, /* size of the private key */
	/* .funcs = */		&sshkey_mldsa44_ed25519_funcs,
};
#endif /* USE_MLDSA */
