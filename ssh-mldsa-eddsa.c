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

#समावेश "includes.h"

#अगर_घोषित USE_MLDSA

#समावेश <sys/types.h>
#समावेश <stdint.h>
#समावेश <string.h>
#समावेश <stdlib.h>

#समावेश "crypto_api.h"
#समावेश "sshbuf.h"
#समावेश "ssherr.h"
#समावेश "digest.h"
#घोषणा SSHKEY_INTERNAL
#समावेश "sshkey.h"
#समावेश "log.h"

#घोषणा COMPOSITE_PREFIX "CompositeAlgorithmSignatures2025"
#घोषणा COMPOSITE_LABEL  "COMPSIG-MLDSA44-Ed25519-SHA512"
#घोषणा SSH_MLDSA44_ED25519_ALG_NAME   "ssh-mldsa44-ed25519"

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

	arc4random_buf(mldsa_seed, माप(mldsa_seed));
	arc4random_buf(ed25519_seed, माप(ed25519_seed));

	r = crypto_sign_mldsa44_ed25519_keygen_seeded(pk, sk, mldsa_seed,
	    ed25519_seed);
	explicit_bzero(mldsa_seed, माप(mldsa_seed));
	explicit_bzero(ed25519_seed, माप(ed25519_seed));
	वापस r;
}

पूर्णांक
crypto_sign_mldsa44_ed25519_keygen_seeded(uint8_t pk[MLDSA44_ED25519_PK_SZ],
    uint8_t sk[MLDSA44_ED25519_SK_SZ],
    स्थिर uint8_t mldsa_seed[MLDSA44_SEEDBYTES],
    स्थिर uint8_t ed25519_seed[crypto_sign_ed25519_SEEDBYTES])
{
	uint8_t ed25519_pk[MLDSA44_SEEDBYTES];
	uint8_t ed25519_sk[crypto_sign_ed25519_SECRETKEYBYTES];
	uint8_t mldsa_sk[MLDSA44_SECRETKEYBYTES];
	पूर्णांक ret = -1;

	अगर (crypto_sign_mldsa44_keypair_seeded(pk, mldsa_sk, mldsa_seed) != 0)
		जाओ out;
	अगर (crypto_sign_ed25519_seed_keypair(ed25519_pk, ed25519_sk,
	    ed25519_seed) != 0)
		जाओ out;

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
	explicit_bzero(mldsa_sk, माप(mldsa_sk));
	explicit_bzero(ed25519_sk, माप(ed25519_sk));
	वापस ret;
}

अटल पूर्णांक
construct_m_अभाज्य(uint8_t **m_primep, माप_प्रकार *m_अभाज्य_lenp,
    स्थिर uint8_t *संदेश, माप_प्रकार msglen,
    स्थिर uint8_t *ctx, माप_प्रकार ctxlen)
{
	पूर्णांक r;
	uint8_t hash[64];
	काष्ठा sshbuf *m_अभाज्य;

	*m_primep = शून्य;
	*m_अभाज्य_lenp = 0;

	अगर (ctxlen > 255)
		वापस SSH_ERR_INVALID_ARGUMENT;
	अगर ((r = ssh_digest_memory(SSH_DIGEST_SHA512, संदेश, msglen,
	    hash, माप(hash))) != 0)
		वापस r;
	अगर ((m_अभाज्य = sshbuf_new()) == शून्य)
		वापस SSH_ERR_ALLOC_FAIL;
	अगर ((r = sshbuf_put(m_अभाज्य, COMPOSITE_PREFIX,
	    माप(COMPOSITE_PREFIX) - 1)) != 0 ||
	    (r = sshbuf_put(m_अभाज्य, COMPOSITE_LABEL,
	    माप(COMPOSITE_LABEL) - 1)) != 0 ||
	    (r = sshbuf_put_u8(m_अभाज्य, (uint8_t)ctxlen)) != 0 ||
	    (r = sshbuf_put(m_अभाज्य, ctx, ctxlen)) != 0 ||
	    (r = sshbuf_put(m_अभाज्य, hash, माप(hash))) != 0) {
		sshbuf_free(m_अभाज्य);
		वापस r;
	}
	अगर ((*m_primep = दो_स्मृति(sshbuf_len(m_अभाज्य))) == शून्य) {
		sshbuf_free(m_अभाज्य);
		वापस SSH_ERR_ALLOC_FAIL;
	}
	स_नकल(*m_primep, sshbuf_ptr(m_अभाज्य), sshbuf_len(m_अभाज्य));
	*m_अभाज्य_lenp = sshbuf_len(m_अभाज्य);
	/* success */
	sshbuf_free(m_अभाज्य);
	वापस 0;
}

पूर्णांक
crypto_sign_mldsa44_ed25519_sign(uint8_t sig[MLDSA44_ED25519_SIG_SZ],
    स्थिर uint8_t *संदेश, माप_प्रकार msglen,
    स्थिर uint8_t *ctx, माप_प्रकार ctxlen,
    स्थिर uint8_t sk[MLDSA44_ED25519_SK_SZ])
{
	uint8_t *m_अभाज्य = शून्य;
	माप_प्रकार m_अभाज्य_len = 0;
	uint8_t mldsa_sk[MLDSA44_SECRETKEYBYTES];
	uint8_t mldsa_pk_dummy[MLDSA44_PUBLICKEYBYTES];
	uint8_t ed25519_pk[crypto_sign_ed25519_PUBLICKEYBYTES];
	uint8_t ed25519_sk[crypto_sign_ed25519_SECRETKEYBYTES];
	uint8_t mldsa_rnd[MLDSA44_SEEDBYTES];
	अचिन्हित दीर्घ दीर्घ smlen;
	पूर्णांक r = -1;

	अगर (construct_m_अभाज्य(&m_अभाज्य, &m_अभाज्य_len, संदेश, msglen,
	    ctx, ctxlen) != 0)
		वापस -1;

	/* Expand ML-DSA key from seed */
	अगर (crypto_sign_mldsa44_keypair_seeded(mldsa_pk_dummy, mldsa_sk, sk) != 0)
		जाओ out;

	/* Sign with ML-DSA */
	arc4random_buf(mldsa_rnd, माप(mldsa_rnd));
	अगर (crypto_sign_mldsa44_seeded(sig, m_अभाज्य, m_अभाज्य_len,
	    (स्थिर uint8_t *)COMPOSITE_LABEL, माप(COMPOSITE_LABEL) - 1,
	    mldsa_sk, mldsa_rnd) != 0)
		जाओ out;

	/* Expand Ed25519 key from seed */
	अगर (crypto_sign_ed25519_seed_keypair(ed25519_pk, ed25519_sk,
	    sk + MLDSA44_SEEDBYTES) != 0)
		जाओ out;

	/* Sign with Ed25519 */
	अगर (crypto_sign_ed25519_detached(sig + MLDSA44_SIGBYTES, &smlen,
	    m_अभाज्य, m_अभाज्य_len, ed25519_sk) != 0 ||
	    smlen != crypto_sign_ed25519_BYTES)
		जाओ out;

	r = 0;
 out:
	मुक्त(m_अभाज्य);
	explicit_bzero(mldsa_rnd, माप(mldsa_rnd));
	explicit_bzero(mldsa_sk, माप(mldsa_sk));
	explicit_bzero(ed25519_sk, माप(ed25519_sk));
	वापस r;
}

पूर्णांक
crypto_sign_mldsa44_ed25519_verify(स्थिर uint8_t sig[MLDSA44_ED25519_SIG_SZ],
    स्थिर uint8_t *संदेश, माप_प्रकार msglen,
    स्थिर uint8_t *ctx, माप_प्रकार ctxlen,
    स्थिर uint8_t pk[MLDSA44_ED25519_PK_SZ])
{
	uint8_t *m_अभाज्य = शून्य;
	माप_प्रकार m_अभाज्य_len = 0;
	पूर्णांक r = -1;

	अगर (construct_m_अभाज्य(&m_अभाज्य, &m_अभाज्य_len, संदेश, msglen,
	    ctx, ctxlen) != 0)
		वापस -1;

	/* Verify ML-DSA */
	अगर (crypto_sign_mldsa44_verify(sig, m_अभाज्य, m_अभाज्य_len,
	    (स्थिर uint8_t *)COMPOSITE_LABEL, माप(COMPOSITE_LABEL) - 1,
	    pk) != 0)
		जाओ out;

	/* Verify Ed25519 */
	अगर (crypto_sign_ed25519_verify_detached(sig + MLDSA44_SIGBYTES,
	    m_अभाज्य, m_अभाज्य_len, pk + MLDSA44_PUBLICKEYBYTES) != 0)
		जाओ out;

	r = 0;
 out:
	मुक्त(m_अभाज्य);
	वापस r;
}

/* sshkey integration */

अटल व्योम
ssh_mldsa44_ed25519_cleanup(काष्ठा sshkey *k)
{
	freezero(k->mldsa_ed25519_pk, MLDSA44_ED25519_PK_SZ);
	freezero(k->mldsa_ed25519_sk, MLDSA44_ED25519_SK_SZ);
	k->mldsa_ed25519_pk = शून्य;
	k->mldsa_ed25519_sk = शून्य;
}

अटल पूर्णांक
ssh_mldsa44_ed25519_equal(स्थिर काष्ठा sshkey *a, स्थिर काष्ठा sshkey *b)
{
	अगर (a->mldsa_ed25519_pk == शून्य || b->mldsa_ed25519_pk == शून्य)
		वापस 0;
	अगर (स_भेद(a->mldsa_ed25519_pk, b->mldsa_ed25519_pk,
	    MLDSA44_ED25519_PK_SZ) != 0)
		वापस 0;
	वापस 1;
}

अटल पूर्णांक
ssh_mldsa44_ed25519_serialize_public(स्थिर काष्ठा sshkey *कुंजी, काष्ठा sshbuf *b,
    क्रमागत sshkey_serialize_rep opts)
{
	पूर्णांक r;

	अगर (कुंजी->mldsa_ed25519_pk == शून्य)
		वापस SSH_ERR_INVALID_ARGUMENT;
	अगर ((r = sshbuf_put_string(b, कुंजी->mldsa_ed25519_pk,
	    MLDSA44_ED25519_PK_SZ)) != 0)
		वापस r;

	वापस 0;
}

अटल पूर्णांक
ssh_mldsa44_ed25519_serialize_private(स्थिर काष्ठा sshkey *कुंजी, काष्ठा sshbuf *b,
    क्रमागत sshkey_serialize_rep opts)
{
	पूर्णांक r;

	अगर (कुंजी->mldsa_ed25519_sk == शून्य)
		वापस SSH_ERR_INVALID_ARGUMENT;
	अगर (!sshkey_is_cert(कुंजी)) {
		अगर ((r = ssh_mldsa44_ed25519_serialize_public(कुंजी,
		    b, opts)) != 0)
			वापस r;
	}
	अगर ((r = sshbuf_put_string(b, कुंजी->mldsa_ed25519_sk,
	    MLDSA44_ED25519_SK_SZ)) != 0)
		वापस r;

	वापस 0;
}

अटल पूर्णांक
ssh_mldsa44_ed25519_deserialize_public(स्थिर अक्षर *ktype, काष्ठा sshbuf *b,
    काष्ठा sshkey *कुंजी)
{
	u_char *pk = शून्य;
	माप_प्रकार len = 0;
	पूर्णांक r;

	अगर ((r = sshbuf_get_string(b, &pk, &len)) != 0)
		वापस r;
	अगर (len != MLDSA44_ED25519_PK_SZ) {
		freezero(pk, len);
		वापस SSH_ERR_INVALID_FORMAT;
	}
	कुंजी->mldsa_ed25519_pk = pk;
	वापस 0;
}

अटल पूर्णांक
ssh_mldsa44_ed25519_deserialize_private(स्थिर अक्षर *ktype, काष्ठा sshbuf *b,
    काष्ठा sshkey *कुंजी)
{
	पूर्णांक r;
	माप_प्रकार sklen = 0;
	u_char *sk = शून्य;

	अगर (!sshkey_is_cert(कुंजी)) {
		अगर ((r = ssh_mldsa44_ed25519_deserialize_public(ktype,
		    b, कुंजी)) != 0)
			वापस r;
	}
	अगर ((r = sshbuf_get_string(b, &sk, &sklen)) != 0)
		जाओ out;
	अगर (sklen != MLDSA44_ED25519_SK_SZ) {
		r = SSH_ERR_INVALID_FORMAT;
		जाओ out;
	}
	कुंजी->mldsa_ed25519_sk = sk;
	sk = शून्य; /* transferred */
	r = 0;
 out:
	freezero(sk, sklen);
	वापस r;
}

अटल पूर्णांक
ssh_mldsa44_ed25519_generate(काष्ठा sshkey *k, पूर्णांक bits)
{
	ssh_mldsa44_ed25519_cleanup(k);
	अगर ((k->mldsa_ed25519_pk = दो_स्मृति(MLDSA44_ED25519_PK_SZ)) == शून्य ||
	    (k->mldsa_ed25519_sk = दो_स्मृति(MLDSA44_ED25519_SK_SZ)) == शून्य) {
		ssh_mldsa44_ed25519_cleanup(k);
		वापस SSH_ERR_ALLOC_FAIL;
	}
	अगर (crypto_sign_mldsa44_ed25519_keygen(k->mldsa_ed25519_pk,
	    k->mldsa_ed25519_sk) != 0) {
		ssh_mldsa44_ed25519_cleanup(k);
		वापस SSH_ERR_CRYPTO_ERROR;
	}
	वापस 0;
}

अटल पूर्णांक
ssh_mldsa44_ed25519_copy_public(स्थिर काष्ठा sshkey *from, काष्ठा sshkey *to)
{
	अगर (from->mldsa_ed25519_pk == शून्य)
		वापस SSH_ERR_INVALID_ARGUMENT;
	अगर ((to->mldsa_ed25519_pk = दो_स्मृति(MLDSA44_ED25519_PK_SZ)) == शून्य)
		वापस SSH_ERR_ALLOC_FAIL;
	स_नकल(to->mldsa_ed25519_pk, from->mldsa_ed25519_pk,
	    MLDSA44_ED25519_PK_SZ);
	वापस 0;
}

अटल पूर्णांक
ssh_mldsa44_ed25519_sign(काष्ठा sshkey *कुंजी,
    u_char **sigp, माप_प्रकार *lenp, स्थिर u_char *तथ्य, माप_प्रकार datalen,
    स्थिर अक्षर *alg, स्थिर अक्षर *sk_provider, स्थिर अक्षर *sk_pin,
    u_int compat)
{
	u_char sig[MLDSA44_ED25519_SIG_SZ];
	काष्ठा sshbuf *b = शून्य;
	पूर्णांक r = SSH_ERR_INTERNAL_ERROR;

	अगर (lenp != शून्य)
		*lenp = 0;
	अगर (sigp != शून्य)
		*sigp = शून्य;

	अगर (कुंजी == शून्य ||
	    sshkey_type_plain(कुंजी->type) != कुंजी_MLDSA44_ED25519 ||
	    कुंजी->mldsa_ed25519_sk == शून्य)
		वापस SSH_ERR_INVALID_ARGUMENT;

	अगर (crypto_sign_mldsa44_ed25519_sign(sig, तथ्य, datalen, शून्य, 0,
	    कुंजी->mldsa_ed25519_sk) != 0) {
		r = SSH_ERR_CRYPTO_ERROR;
		जाओ out;
	}

	अगर ((b = sshbuf_new()) == शून्य) {
		r = SSH_ERR_ALLOC_FAIL;
		जाओ out;
	}
	अगर ((r = sshbuf_put_cstring(b, SSH_MLDSA44_ED25519_ALG_NAME)) != 0 ||
	    (r = sshbuf_put_string(b, sig, माप(sig))) != 0)
		जाओ out;

	अगर (sigp != शून्य) {
		अगर ((*sigp = दो_स्मृति(sshbuf_len(b))) == शून्य) {
			r = SSH_ERR_ALLOC_FAIL;
			जाओ out;
		}
		स_नकल(*sigp, sshbuf_ptr(b), sshbuf_len(b));
	}
	अगर (lenp != शून्य)
		*lenp = sshbuf_len(b);
	r = 0;
 out:
	sshbuf_free(b);
	explicit_bzero(sig, माप(sig));
	वापस r;
}

अटल पूर्णांक
ssh_mldsa44_ed25519_verify(स्थिर काष्ठा sshkey *कुंजी,
    स्थिर u_char *sig, माप_प्रकार siglen, स्थिर u_char *तथ्य, माप_प्रकार dlen,
    स्थिर अक्षर *alg, u_int compat, काष्ठा sshkey_sig_details **detailsp)
{
	काष्ठा sshbuf *b = शून्य;
	अक्षर *ktype = शून्य;
	स्थिर u_char *sigblob;
	माप_प्रकार len;
	पूर्णांक r;

	अगर (कुंजी == शून्य ||
	    sshkey_type_plain(कुंजी->type) != कुंजी_MLDSA44_ED25519 ||
	    कुंजी->mldsa_ed25519_pk == शून्य ||
	    sig == शून्य || siglen == 0)
		वापस SSH_ERR_INVALID_ARGUMENT;

	अगर ((b = sshbuf_from(sig, siglen)) == शून्य)
		वापस SSH_ERR_ALLOC_FAIL;
	अगर ((r = sshbuf_get_cstring(b, &ktype, शून्य)) != 0 ||
	    (r = sshbuf_get_string_direct(b, &sigblob, &len)) != 0)
		जाओ out;
	अगर (म_भेद(SSH_MLDSA44_ED25519_ALG_NAME, ktype) != 0) {
		r = SSH_ERR_कुंजी_TYPE_MISMATCH;
		जाओ out;
	}
	अगर (sshbuf_len(b) != 0) {
		r = SSH_ERR_UNEXPECTED_TRAILING_तथ्य;
		जाओ out;
	}
	अगर (len != MLDSA44_ED25519_SIG_SZ) {
		r = SSH_ERR_INVALID_FORMAT;
		जाओ out;
	}

	अगर (crypto_sign_mldsa44_ed25519_verify(sigblob, तथ्य, dlen, शून्य, 0,
	    कुंजी->mldsa_ed25519_pk) != 0) {
		r = SSH_ERR_SIGNATURE_INVALID;
		जाओ out;
	}

	r = 0;
 out:
	sshbuf_free(b);
	मुक्त(ktype);
	वापस r;
}

स्थिर काष्ठा sshkey_impl_funcs sshkey_mldsa44_ed25519_funcs = {
	/* .size = */		शून्य,
	/* .alloc = */		शून्य,
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

स्थिर काष्ठा sshkey_impl sshkey_mldsa44_ed25519_impl = {
	/* .name = */		"ssh-mldsa44-ed25519",
	/* .shortname = */	"MLDSA44-ED25519",
	/* .sigalg = */		शून्य,
	/* .type = */		कुंजी_MLDSA44_ED25519,
	/* .nid = */		0,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	512, /* size of the private key */
	/* .funcs = */		&sshkey_mldsa44_ed25519_funcs,
};

स्थिर काष्ठा sshkey_impl sshkey_mldsa44_ed25519_cert_impl = {
	/* .name = */		"ssh-mldsa44-ed25519-cert",
	/* .shortname = */	"MLDSA44-ED25519-CERT",
	/* .sigalg = */		शून्य,
	/* .type = */		कुंजी_MLDSA44_ED25519_CERT,
	/* .nid = */		0,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	512, /* size of the private key */
	/* .funcs = */		&sshkey_mldsa44_ed25519_funcs,
};
#पूर्ण_अगर /* USE_MLDSA */
