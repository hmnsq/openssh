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

पूर्णांक
crypto_sign_mldsa44_ed25519_keygen(uint8_t pk[MLDSA44_ED25519_PK_SZ],
    uint8_t sk[MLDSA44_ED25519_SK_SZ])
{
	uint8_t mldsa_seed[MLDSA44_SEEDBYTES];
	uint8_t ed25519_seed[crypto_sign_ed25519_SEEDBYTES];
	पूर्णांक r;

	arc4random_buf(mldsa_seed, आकार(mldsa_seed));
	arc4random_buf(ed25519_seed, आकार(ed25519_seed));

	r = crypto_sign_mldsa44_ed25519_keygen_seeded(pk, sk, mldsa_seed,
	    ed25519_seed);
	explicit_bzero(mldsa_seed, आकार(mldsa_seed));
	explicit_bzero(ed25519_seed, आकार(ed25519_seed));
	परत r;
}

पूर्णांक
crypto_sign_mldsa44_ed25519_keygen_seeded(uint8_t pk[MLDSA44_ED25519_PK_SZ],
    uint8_t sk[MLDSA44_ED25519_SK_SZ],
    स्थिरांक uint8_t mldsa_seed[MLDSA44_SEEDBYTES],
    स्थिरांक uint8_t ed25519_seed[crypto_sign_ed25519_SEEDBYTES])
{
	uint8_t ed25519_pk[MLDSA44_SEEDBYTES];
	uint8_t ed25519_sk[crypto_sign_ed25519_SECRETKEYBYTES];
	uint8_t mldsa_sk[MLDSA44_SECRETKEYBYTES];
	पूर्णांक ret = -1;

	जर (crypto_sign_mldsa44_keypair_seeded(pk, mldsa_sk, mldsa_seed) != 0)
		जा out;
	जर (crypto_sign_ed25519_seed_keypair(ed25519_pk, ed25519_sk,
	    ed25519_seed) != 0)
		जा out;

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
	explicit_bzero(mldsa_sk, आकार(mldsa_sk));
	explicit_bzero(ed25519_sk, आकार(ed25519_sk));
	परत ret;
}

स्थिर पूर्णांक
construct_m_मूळसंख्या(uint8_t **m_primep, माप_प्रकार *m_मूळसंख्या_lenp,
    स्थिरांक uint8_t *संदेश, माप_प्रकार msglen,
    स्थिरांक uint8_t *ctx, माप_प्रकार ctxlen)
{
	पूर्णांक r;
	uint8_t hash[64];
	संरचना sshbuf *m_मूळसंख्या;

	*m_primep = रिक्त;
	*m_मूळसंख्या_lenp = 0;

	जर (ctxlen > 255)
		परत SSH_ERR_INVALID_ARGUMENT;
	जर ((r = ssh_digest_memory(SSH_DIGEST_SHA512, संदेश, msglen,
	    hash, आकार(hash))) != 0)
		परत r;
	जर ((m_मूळसंख्या = sshbuf_new()) == रिक्त)
		परत SSH_ERR_ALLOC_FAIL;
	जर ((r = sshbuf_put(m_मूळसंख्या, COMPOSITE_PREFIX,
	    आकार(COMPOSITE_PREFIX) - 1)) != 0 ||
	    (r = sshbuf_put(m_मूळसंख्या, COMPOSITE_LABEL,
	    आकार(COMPOSITE_LABEL) - 1)) != 0 ||
	    (r = sshbuf_put_u8(m_मूळसंख्या, (uint8_t)ctxlen)) != 0 ||
	    (r = sshbuf_put(m_मूळसंख्या, ctx, ctxlen)) != 0 ||
	    (r = sshbuf_put(m_मूळसंख्या, hash, आकार(hash))) != 0) {
		sshbuf_free(m_मूळसंख्या);
		परत r;
	}
	जर ((*m_primep = दो_स्मृति(sshbuf_len(m_मूळसंख्या))) == रिक्त) {
		sshbuf_free(m_मूळसंख्या);
		परत SSH_ERR_ALLOC_FAIL;
	}
	स_नकल(*m_primep, sshbuf_ptr(m_मूळसंख्या), sshbuf_len(m_मूळसंख्या));
	*m_मूळसंख्या_lenp = sshbuf_len(m_मूळसंख्या);
	/* success */
	sshbuf_free(m_मूळसंख्या);
	परत 0;
}

पूर्णांक
crypto_sign_mldsa44_ed25519_sign(uint8_t sig[MLDSA44_ED25519_SIG_SZ],
    स्थिरांक uint8_t *संदेश, माप_प्रकार msglen,
    स्थिरांक uint8_t *ctx, माप_प्रकार ctxlen,
    स्थिरांक uint8_t sk[MLDSA44_ED25519_SK_SZ])
{
	uint8_t *m_मूळसंख्या = रिक्त;
	माप_प्रकार m_मूळसंख्या_len = 0;
	uint8_t mldsa_sk[MLDSA44_SECRETKEYBYTES];
	uint8_t mldsa_pk_dummy[MLDSA44_PUBLICKEYBYTES];
	uint8_t ed25519_pk[crypto_sign_ed25519_PUBLICKEYBYTES];
	uint8_t ed25519_sk[crypto_sign_ed25519_SECRETKEYBYTES];
	uint8_t mldsa_rnd[MLDSA44_SEEDBYTES];
	अचिन्हित दीर्घ दीर्घ smlen;
	पूर्णांक r = -1;

	जर (construct_m_मूळसंख्या(&m_मूळसंख्या, &m_मूळसंख्या_len, संदेश, msglen,
	    ctx, ctxlen) != 0)
		परत -1;

	/* Expand ML-DSA key from seed */
	जर (crypto_sign_mldsa44_keypair_seeded(mldsa_pk_dummy, mldsa_sk, sk) != 0)
		जा out;

	/* Sign with ML-DSA */
	arc4random_buf(mldsa_rnd, आकार(mldsa_rnd));
	जर (crypto_sign_mldsa44_seeded(sig, m_मूळसंख्या, m_मूळसंख्या_len,
	    (स्थिरांक uint8_t *)COMPOSITE_LABEL, आकार(COMPOSITE_LABEL) - 1,
	    mldsa_sk, mldsa_rnd) != 0)
		जा out;

	/* Expand Ed25519 key from seed */
	जर (crypto_sign_ed25519_seed_keypair(ed25519_pk, ed25519_sk,
	    sk + MLDSA44_SEEDBYTES) != 0)
		जा out;

	/* Sign with Ed25519 */
	जर (crypto_sign_ed25519_detached(sig + MLDSA44_SIGBYTES, &smlen,
	    m_मूळसंख्या, m_मूळसंख्या_len, ed25519_sk) != 0 ||
	    smlen != crypto_sign_ed25519_BYTES)
		जा out;

	r = 0;
 out:
	मुक्त(m_मूळसंख्या);
	explicit_bzero(mldsa_rnd, आकार(mldsa_rnd));
	explicit_bzero(mldsa_sk, आकार(mldsa_sk));
	explicit_bzero(ed25519_sk, आकार(ed25519_sk));
	परत r;
}

पूर्णांक
crypto_sign_mldsa44_ed25519_verify(स्थिरांक uint8_t sig[MLDSA44_ED25519_SIG_SZ],
    स्थिरांक uint8_t *संदेश, माप_प्रकार msglen,
    स्थिरांक uint8_t *ctx, माप_प्रकार ctxlen,
    स्थिरांक uint8_t pk[MLDSA44_ED25519_PK_SZ])
{
	uint8_t *m_मूळसंख्या = रिक्त;
	माप_प्रकार m_मूळसंख्या_len = 0;
	पूर्णांक r = -1;

	जर (construct_m_मूळसंख्या(&m_मूळसंख्या, &m_मूळसंख्या_len, संदेश, msglen,
	    ctx, ctxlen) != 0)
		परत -1;

	/* Verify ML-DSA */
	जर (crypto_sign_mldsa44_verify(sig, m_मूळसंख्या, m_मूळसंख्या_len,
	    (स्थिरांक uint8_t *)COMPOSITE_LABEL, आकार(COMPOSITE_LABEL) - 1,
	    pk) != 0)
		जा out;

	/* Verify Ed25519 */
	जर (crypto_sign_ed25519_verify_detached(sig + MLDSA44_SIGBYTES,
	    m_मूळसंख्या, m_मूळसंख्या_len, pk + MLDSA44_PUBLICKEYBYTES) != 0)
		जा out;

	r = 0;
 out:
	मुक्त(m_मूळसंख्या);
	परत r;
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

स्थिर पूर्णांक
ssh_mldsa44_ed25519_equal(स्थिरांक संरचना sshkey *a, स्थिरांक संरचना sshkey *b)
{
	जर (a->mldsa_ed25519_pk == रिक्त || b->mldsa_ed25519_pk == रिक्त)
		परत 0;
	जर (स_भेद(a->mldsa_ed25519_pk, b->mldsa_ed25519_pk,
	    MLDSA44_ED25519_PK_SZ) != 0)
		परत 0;
	परत 1;
}

स्थिर पूर्णांक
ssh_mldsa44_ed25519_serialize_public(स्थिरांक संरचना sshkey *किल्ली, संरचना sshbuf *b,
    गणना sshkey_serialize_rep opts)
{
	पूर्णांक r;

	जर (किल्ली->mldsa_ed25519_pk == रिक्त)
		परत SSH_ERR_INVALID_ARGUMENT;
	जर ((r = sshbuf_put_string(b, किल्ली->mldsa_ed25519_pk,
	    MLDSA44_ED25519_PK_SZ)) != 0)
		परत r;

	परत 0;
}

स्थिर पूर्णांक
ssh_mldsa44_ed25519_serialize_private(स्थिरांक संरचना sshkey *किल्ली, संरचना sshbuf *b,
    गणना sshkey_serialize_rep opts)
{
	पूर्णांक r;

	जर (किल्ली->mldsa_ed25519_sk == रिक्त)
		परत SSH_ERR_INVALID_ARGUMENT;
	जर (!sshkey_is_cert(किल्ली)) {
		जर ((r = ssh_mldsa44_ed25519_serialize_public(किल्ली,
		    b, opts)) != 0)
			परत r;
	}
	जर ((r = sshbuf_put_string(b, किल्ली->mldsa_ed25519_sk,
	    MLDSA44_ED25519_SK_SZ)) != 0)
		परत r;

	परत 0;
}

स्थिर पूर्णांक
ssh_mldsa44_ed25519_deserialize_public(स्थिरांक अक्षर *ktype, संरचना sshbuf *b,
    संरचना sshkey *किल्ली)
{
	u_char *pk = रिक्त;
	माप_प्रकार len = 0;
	पूर्णांक r;

	जर ((r = sshbuf_get_string(b, &pk, &len)) != 0)
		परत r;
	जर (len != MLDSA44_ED25519_PK_SZ) {
		freezero(pk, len);
		परत SSH_ERR_INVALID_FORMAT;
	}
	किल्ली->mldsa_ed25519_pk = pk;
	परत 0;
}

स्थिर पूर्णांक
ssh_mldsa44_ed25519_deserialize_private(स्थिरांक अक्षर *ktype, संरचना sshbuf *b,
    संरचना sshkey *किल्ली)
{
	पूर्णांक r;
	माप_प्रकार sklen = 0;
	u_char *sk = रिक्त;

	जर (!sshkey_is_cert(किल्ली)) {
		जर ((r = ssh_mldsa44_ed25519_deserialize_public(ktype,
		    b, किल्ली)) != 0)
			परत r;
	}
	जर ((r = sshbuf_get_string(b, &sk, &sklen)) != 0)
		जा out;
	जर (sklen != MLDSA44_ED25519_SK_SZ) {
		r = SSH_ERR_INVALID_FORMAT;
		जा out;
	}
	किल्ली->mldsa_ed25519_sk = sk;
	sk = रिक्त; /* transferred */
	r = 0;
 out:
	freezero(sk, sklen);
	परत r;
}

स्थिर पूर्णांक
ssh_mldsa44_ed25519_generate(संरचना sshkey *k, पूर्णांक bits)
{
	ssh_mldsa44_ed25519_cleanup(k);
	जर ((k->mldsa_ed25519_pk = दो_स्मृति(MLDSA44_ED25519_PK_SZ)) == रिक्त ||
	    (k->mldsa_ed25519_sk = दो_स्मृति(MLDSA44_ED25519_SK_SZ)) == रिक्त) {
		ssh_mldsa44_ed25519_cleanup(k);
		परत SSH_ERR_ALLOC_FAIL;
	}
	जर (crypto_sign_mldsa44_ed25519_keygen(k->mldsa_ed25519_pk,
	    k->mldsa_ed25519_sk) != 0) {
		ssh_mldsa44_ed25519_cleanup(k);
		परत SSH_ERR_CRYPTO_ERROR;
	}
	परत 0;
}

स्थिर पूर्णांक
ssh_mldsa44_ed25519_copy_public(स्थिरांक संरचना sshkey *from, संरचना sshkey *to)
{
	जर (from->mldsa_ed25519_pk == रिक्त)
		परत SSH_ERR_INVALID_ARGUMENT;
	जर ((to->mldsa_ed25519_pk = दो_स्मृति(MLDSA44_ED25519_PK_SZ)) == रिक्त)
		परत SSH_ERR_ALLOC_FAIL;
	स_नकल(to->mldsa_ed25519_pk, from->mldsa_ed25519_pk,
	    MLDSA44_ED25519_PK_SZ);
	परत 0;
}

स्थिर पूर्णांक
ssh_mldsa44_ed25519_sign(संरचना sshkey *किल्ली,
    u_char **sigp, माप_प्रकार *lenp, स्थिरांक u_char *data, माप_प्रकार datalen,
    स्थिरांक अक्षर *alg, स्थिरांक अक्षर *sk_provider, स्थिरांक अक्षर *sk_pin,
    u_int compat)
{
	u_char sig[MLDSA44_ED25519_SIG_SZ];
	संरचना sshbuf *b = रिक्त;
	पूर्णांक r = SSH_ERR_INTERNAL_ERROR;

	जर (lenp != रिक्त)
		*lenp = 0;
	जर (sigp != रिक्त)
		*sigp = रिक्त;

	जर (किल्ली == रिक्त ||
	    sshkey_type_plain(किल्ली->type) != किल्ली_MLDSA44_ED25519 ||
	    किल्ली->mldsa_ed25519_sk == रिक्त)
		परत SSH_ERR_INVALID_ARGUMENT;

	जर (crypto_sign_mldsa44_ed25519_sign(sig, data, datalen, रिक्त, 0,
	    किल्ली->mldsa_ed25519_sk) != 0) {
		r = SSH_ERR_CRYPTO_ERROR;
		जा out;
	}

	जर ((b = sshbuf_new()) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		जा out;
	}
	जर ((r = sshbuf_put_cstring(b, SSH_MLDSA44_ED25519_ALG_NAME)) != 0 ||
	    (r = sshbuf_put_string(b, sig, आकार(sig))) != 0)
		जा out;

	जर (sigp != रिक्त) {
		जर ((*sigp = दो_स्मृति(sshbuf_len(b))) == रिक्त) {
			r = SSH_ERR_ALLOC_FAIL;
			जा out;
		}
		स_नकल(*sigp, sshbuf_ptr(b), sshbuf_len(b));
	}
	जर (lenp != रिक्त)
		*lenp = sshbuf_len(b);
	r = 0;
 out:
	sshbuf_free(b);
	explicit_bzero(sig, आकार(sig));
	परत r;
}

स्थिर पूर्णांक
ssh_mldsa44_ed25519_verify(स्थिरांक संरचना sshkey *किल्ली,
    स्थिरांक u_char *sig, माप_प्रकार siglen, स्थिरांक u_char *data, माप_प्रकार dlen,
    स्थिरांक अक्षर *alg, u_int compat, संरचना sshkey_sig_details **detailsp)
{
	संरचना sshbuf *b = रिक्त;
	अक्षर *ktype = रिक्त;
	स्थिरांक u_char *sigblob;
	माप_प्रकार len;
	पूर्णांक r;

	जर (किल्ली == रिक्त ||
	    sshkey_type_plain(किल्ली->type) != किल्ली_MLDSA44_ED25519 ||
	    किल्ली->mldsa_ed25519_pk == रिक्त ||
	    sig == रिक्त || siglen == 0)
		परत SSH_ERR_INVALID_ARGUMENT;

	जर ((b = sshbuf_from(sig, siglen)) == रिक्त)
		परत SSH_ERR_ALLOC_FAIL;
	जर ((r = sshbuf_get_cstring(b, &ktype, रिक्त)) != 0 ||
	    (r = sshbuf_get_string_direct(b, &sigblob, &len)) != 0)
		जा out;
	जर (म_भेद(SSH_MLDSA44_ED25519_ALG_NAME, ktype) != 0) {
		r = SSH_ERR_किल्ली_TYPE_MISMATCH;
		जा out;
	}
	जर (sshbuf_len(b) != 0) {
		r = SSH_ERR_UNEXPECTED_TRAILING_DATA;
		जा out;
	}
	जर (len != MLDSA44_ED25519_SIG_SZ) {
		r = SSH_ERR_INVALID_FORMAT;
		जा out;
	}

	जर (crypto_sign_mldsa44_ed25519_verify(sigblob, data, dlen, रिक्त, 0,
	    किल्ली->mldsa_ed25519_pk) != 0) {
		r = SSH_ERR_SIGNATURE_INVALID;
		जा out;
	}

	r = 0;
 out:
	sshbuf_free(b);
	मुक्त(ktype);
	परत r;
}

स्थिरांक संरचना sshkey_impl_funcs sshkey_mldsa44_ed25519_funcs = {
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

स्थिरांक संरचना sshkey_impl sshkey_mldsa44_ed25519_impl = {
	/* .name = */		"ssh-mldsa44-ed25519",
	/* .shortname = */	"MLDSA44-ED25519",
	/* .sigalg = */		रिक्त,
	/* .type = */		किल्ली_MLDSA44_ED25519,
	/* .nid = */		0,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	512, /* size of the private key */
	/* .funcs = */		&sshkey_mldsa44_ed25519_funcs,
};

स्थिरांक संरचना sshkey_impl sshkey_mldsa44_ed25519_cert_impl = {
	/* .name = */		"ssh-mldsa44-ed25519-cert",
	/* .shortname = */	"MLDSA44-ED25519-CERT",
	/* .sigalg = */		रिक्त,
	/* .type = */		किल्ली_MLDSA44_ED25519_CERT,
	/* .nid = */		0,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	512, /* size of the private key */
	/* .funcs = */		&sshkey_mldsa44_ed25519_funcs,
};
#endif /* USE_MLDSA */
