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

#అన్తర్భావ "includes.h"

#నిర్వచితమైతే USE_MLDSA

#అన్తర్భావ <sys/types.h>
#అన్తర్భావ <stdint.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <stdlib.h>

#అన్తర్భావ "crypto_api.h"
#అన్తర్భావ "sshbuf.h"
#అన్తర్భావ "ssherr.h"
#అన్తర్భావ "digest.h"
#నిర్వచించు SSHKEY_అంతర్గత
#అన్తర్భావ "sshkey.h"
#అన్తర్భావ "log.h"

#నిర్వచించు సంయుక్త_ఉపసర్గ "CompositeAlgorithmSignatures2025"
#నిర్వచించు సంయుక్త_LABEL  "COMPSIG-MLDSA44-Ed25519-SHA512"
#నిర్వచించు SSH_MLDSA44_ED25519_ALG_NAME   "ssh-mldsa44-ed25519"

/*
 * raw_* functions implement the draft-ietf-lamps-pq-composite-sigs-18
 * composite signature scheme. These are exposed (i.e. not static) so
 * we can test them separately in unittests/crypto.
 */

పూర్ణాంకం
crypto_sign_mldsa44_ed25519_keygen(uint8_t pk[MLDSA44_ED25519_PK_SZ],
    uint8_t sk[MLDSA44_ED25519_SK_SZ])
{
	uint8_t mldsa_విత్తనం[MLDSA44_SEEDBYTES];
	uint8_t ed25519_విత్తనం[crypto_sign_ed25519_SEEDBYTES];
	పూర్ణాంకం r;

	arc4random_buf(mldsa_విత్తనం, పరిమాణం(mldsa_విత్తనం));
	arc4random_buf(ed25519_విత్తనం, పరిమాణం(ed25519_విత్తనం));

	r = crypto_sign_mldsa44_ed25519_keygen_seeded(pk, sk, mldsa_విత్తనం,
	    ed25519_విత్తనం);
	explicit_bzero(mldsa_విత్తనం, పరిమాణం(mldsa_విత్తనం));
	explicit_bzero(ed25519_విత్తనం, పరిమాణం(ed25519_విత్తనం));
	తిరిగి r;
}

పూర్ణాంకం
crypto_sign_mldsa44_ed25519_keygen_seeded(uint8_t pk[MLDSA44_ED25519_PK_SZ],
    uint8_t sk[MLDSA44_ED25519_SK_SZ],
    స్థిరరాశి uint8_t mldsa_విత్తనం[MLDSA44_SEEDBYTES],
    స్థిరరాశి uint8_t ed25519_విత్తనం[crypto_sign_ed25519_SEEDBYTES])
{
	uint8_t ed25519_pk[MLDSA44_SEEDBYTES];
	uint8_t ed25519_sk[crypto_sign_ed25519_SECRETKEYBYTES];
	uint8_t mldsa_sk[MLDSA44_SECRETKEYBYTES];
	పూర్ణాంకం ret = -1;

	ఒకవేళ (crypto_sign_mldsa44_keypair_seeded(pk, mldsa_sk, mldsa_విత్తనం) != 0)
		వెళ్ళు బహిర్గతం;
	ఒకవేళ (crypto_sign_ed25519_విత్తనం_keypair(ed25519_pk, ed25519_sk,
	    ed25519_విత్తనం) != 0)
		వెళ్ళు బహిర్గతం;

	/* Serialize PK: mldsaPK || ed25519PK */
	జ్ఞాపకం_నకలు(pk + MLDSA44_PUBLICKEYBYTES, ed25519_pk,
	    crypto_sign_ed25519_SEEDBYTES);

	/* Serialize SK: mldsaSeed || ed25519Seed */
	జ్ఞాపకం_నకలు(sk, mldsa_విత్తనం, MLDSA44_SEEDBYTES);
	జ్ఞాపకం_నకలు(sk + MLDSA44_SEEDBYTES, ed25519_విత్తనం,
	    crypto_sign_ed25519_SEEDBYTES);

	/* success */
	ret = 0;
 బహిర్గతం:
	explicit_bzero(mldsa_sk, పరిమాణం(mldsa_sk));
	explicit_bzero(ed25519_sk, పరిమాణం(ed25519_sk));
	తిరిగి ret;
}

స్థిర పూర్ణాంకం
construct_m_ప్రధానసంఖ్య(uint8_t **m_primep, కొలత_t *m_ప్రధానసంఖ్య_lenp,
    స్థిరరాశి uint8_t *సందేశం, కొలత_t msglen,
    స్థిరరాశి uint8_t *ctx, కొలత_t ctxlen)
{
	పూర్ణాంకం r;
	uint8_t hash[64];
	నిర్మాణం sshbuf *m_ప్రధానసంఖ్య;

	*m_primep = ఖాళీ;
	*m_ప్రధానసంఖ్య_lenp = 0;

	ఒకవేళ (ctxlen > 255)
		తిరిగి SSH_ERR_INVALID_వాదం;
	ఒకవేళ ((r = ssh_digest_జ్ఞాపకం(SSH_DIGEST_SHA512, సందేశం, msglen,
	    hash, పరిమాణం(hash))) != 0)
		తిరిగి r;
	ఒకవేళ ((m_ప్రధానసంఖ్య = sshbuf_new()) == ఖాళీ)
		తిరిగి SSH_ERR_ALLOC_FAIL;
	ఒకవేళ ((r = sshbuf_put(m_ప్రధానసంఖ్య, సంయుక్త_ఉపసర్గ,
	    పరిమాణం(సంయుక్త_ఉపసర్గ) - 1)) != 0 ||
	    (r = sshbuf_put(m_ప్రధానసంఖ్య, సంయుక్త_LABEL,
	    పరిమాణం(సంయుక్త_LABEL) - 1)) != 0 ||
	    (r = sshbuf_put_u8(m_ప్రధానసంఖ్య, (uint8_t)ctxlen)) != 0 ||
	    (r = sshbuf_put(m_ప్రధానసంఖ్య, ctx, ctxlen)) != 0 ||
	    (r = sshbuf_put(m_ప్రధానసంఖ్య, hash, పరిమాణం(hash))) != 0) {
		sshbuf_free(m_ప్రధానసంఖ్య);
		తిరిగి r;
	}
	ఒకవేళ ((*m_primep = జ్ఞాపకం_ఇవ్వు(sshbuf_len(m_ప్రధానసంఖ్య))) == ఖాళీ) {
		sshbuf_free(m_ప్రధానసంఖ్య);
		తిరిగి SSH_ERR_ALLOC_FAIL;
	}
	జ్ఞాపకం_నకలు(*m_primep, sshbuf_ptr(m_ప్రధానసంఖ్య), sshbuf_len(m_ప్రధానసంఖ్య));
	*m_ప్రధానసంఖ్య_lenp = sshbuf_len(m_ప్రధానసంఖ్య);
	/* success */
	sshbuf_free(m_ప్రధానసంఖ్య);
	తిరిగి 0;
}

పూర్ణాంకం
crypto_sign_mldsa44_ed25519_sign(uint8_t sig[MLDSA44_ED25519_SIG_SZ],
    స్థిరరాశి uint8_t *సందేశం, కొలత_t msglen,
    స్థిరరాశి uint8_t *ctx, కొలత_t ctxlen,
    స్థిరరాశి uint8_t sk[MLDSA44_ED25519_SK_SZ])
{
	uint8_t *m_ప్రధానసంఖ్య = ఖాళీ;
	కొలత_t m_ప్రధానసంఖ్య_len = 0;
	uint8_t mldsa_sk[MLDSA44_SECRETKEYBYTES];
	uint8_t mldsa_pk_dummy[MLDSA44_PUBLICKEYBYTES];
	uint8_t ed25519_pk[crypto_sign_ed25519_PUBLICKEYBYTES];
	uint8_t ed25519_sk[crypto_sign_ed25519_SECRETKEYBYTES];
	uint8_t mldsa_rnd[MLDSA44_SEEDBYTES];
	గుర్తులేని దీర్ఘ దీర్ఘ smlen;
	పూర్ణాంకం r = -1;

	ఒకవేళ (construct_m_ప్రధానసంఖ్య(&m_ప్రధానసంఖ్య, &m_ప్రధానసంఖ్య_len, సందేశం, msglen,
	    ctx, ctxlen) != 0)
		తిరిగి -1;

	/* Expand ML-DSA key from seed */
	ఒకవేళ (crypto_sign_mldsa44_keypair_seeded(mldsa_pk_dummy, mldsa_sk, sk) != 0)
		వెళ్ళు బహిర్గతం;

	/* Sign with ML-DSA */
	arc4random_buf(mldsa_rnd, పరిమాణం(mldsa_rnd));
	ఒకవేళ (crypto_sign_mldsa44_seeded(sig, m_ప్రధానసంఖ్య, m_ప్రధానసంఖ్య_len,
	    (స్థిరరాశి uint8_t *)సంయుక్త_LABEL, పరిమాణం(సంయుక్త_LABEL) - 1,
	    mldsa_sk, mldsa_rnd) != 0)
		వెళ్ళు బహిర్గతం;

	/* Expand Ed25519 key from seed */
	ఒకవేళ (crypto_sign_ed25519_విత్తనం_keypair(ed25519_pk, ed25519_sk,
	    sk + MLDSA44_SEEDBYTES) != 0)
		వెళ్ళు బహిర్గతం;

	/* Sign with Ed25519 */
	ఒకవేళ (crypto_sign_ed25519_detached(sig + MLDSA44_SIGBYTES, &smlen,
	    m_ప్రధానసంఖ్య, m_ప్రధానసంఖ్య_len, ed25519_sk) != 0 ||
	    smlen != crypto_sign_ed25519_బైట్లు)
		వెళ్ళు బహిర్గతం;

	r = 0;
 బహిర్గతం:
	విడుదల(m_ప్రధానసంఖ్య);
	explicit_bzero(mldsa_rnd, పరిమాణం(mldsa_rnd));
	explicit_bzero(mldsa_sk, పరిమాణం(mldsa_sk));
	explicit_bzero(ed25519_sk, పరిమాణం(ed25519_sk));
	తిరిగి r;
}

పూర్ణాంకం
crypto_sign_mldsa44_ed25519_verify(స్థిరరాశి uint8_t sig[MLDSA44_ED25519_SIG_SZ],
    స్థిరరాశి uint8_t *సందేశం, కొలత_t msglen,
    స్థిరరాశి uint8_t *ctx, కొలత_t ctxlen,
    స్థిరరాశి uint8_t pk[MLDSA44_ED25519_PK_SZ])
{
	uint8_t *m_ప్రధానసంఖ్య = ఖాళీ;
	కొలత_t m_ప్రధానసంఖ్య_len = 0;
	పూర్ణాంకం r = -1;

	ఒకవేళ (construct_m_ప్రధానసంఖ్య(&m_ప్రధానసంఖ్య, &m_ప్రధానసంఖ్య_len, సందేశం, msglen,
	    ctx, ctxlen) != 0)
		తిరిగి -1;

	/* Verify ML-DSA */
	ఒకవేళ (crypto_sign_mldsa44_verify(sig, m_ప్రధానసంఖ్య, m_ప్రధానసంఖ్య_len,
	    (స్థిరరాశి uint8_t *)సంయుక్త_LABEL, పరిమాణం(సంయుక్త_LABEL) - 1,
	    pk) != 0)
		వెళ్ళు బహిర్గతం;

	/* Verify Ed25519 */
	ఒకవేళ (crypto_sign_ed25519_verify_detached(sig + MLDSA44_SIGBYTES,
	    m_ప్రధానసంఖ్య, m_ప్రధానసంఖ్య_len, pk + MLDSA44_PUBLICKEYBYTES) != 0)
		వెళ్ళు బహిర్గతం;

	r = 0;
 బహిర్గతం:
	విడుదల(m_ప్రధానసంఖ్య);
	తిరిగి r;
}

/* sshkey integration */

స్థిర శూన్య
ssh_mldsa44_ed25519_cleanup(నిర్మాణం sshkey *k)
{
	freezero(k->mldsa_ed25519_pk, MLDSA44_ED25519_PK_SZ);
	freezero(k->mldsa_ed25519_sk, MLDSA44_ED25519_SK_SZ);
	k->mldsa_ed25519_pk = ఖాళీ;
	k->mldsa_ed25519_sk = ఖాళీ;
}

స్థిర పూర్ణాంకం
ssh_mldsa44_ed25519_equal(స్థిరరాశి నిర్మాణం sshkey *a, స్థిరరాశి నిర్మాణం sshkey *b)
{
	ఒకవేళ (a->mldsa_ed25519_pk == ఖాళీ || b->mldsa_ed25519_pk == ఖాళీ)
		తిరిగి 0;
	ఒకవేళ (memcmp(a->mldsa_ed25519_pk, b->mldsa_ed25519_pk,
	    MLDSA44_ED25519_PK_SZ) != 0)
		తిరిగి 0;
	తిరిగి 1;
}

స్థిర పూర్ణాంకం
ssh_mldsa44_ed25519_serialize_ప్రజా(స్థిరరాశి నిర్మాణం sshkey *కీలకం, నిర్మాణం sshbuf *b,
    గణన sshkey_serialize_rep opts)
{
	పూర్ణాంకం r;

	ఒకవేళ (కీలకం->mldsa_ed25519_pk == ఖాళీ)
		తిరిగి SSH_ERR_INVALID_వాదం;
	ఒకవేళ ((r = sshbuf_put_string(b, కీలకం->mldsa_ed25519_pk,
	    MLDSA44_ED25519_PK_SZ)) != 0)
		తిరిగి r;

	తిరిగి 0;
}

స్థిర పూర్ణాంకం
ssh_mldsa44_ed25519_serialize_వ్యక్తిగత(స్థిరరాశి నిర్మాణం sshkey *కీలకం, నిర్మాణం sshbuf *b,
    గణన sshkey_serialize_rep opts)
{
	పూర్ణాంకం r;

	ఒకవేళ (కీలకం->mldsa_ed25519_sk == ఖాళీ)
		తిరిగి SSH_ERR_INVALID_వాదం;
	ఒకవేళ (!sshkey_is_cert(కీలకం)) {
		ఒకవేళ ((r = ssh_mldsa44_ed25519_serialize_ప్రజా(కీలకం,
		    b, opts)) != 0)
			తిరిగి r;
	}
	ఒకవేళ ((r = sshbuf_put_string(b, కీలకం->mldsa_ed25519_sk,
	    MLDSA44_ED25519_SK_SZ)) != 0)
		తిరిగి r;

	తిరిగి 0;
}

స్థిర పూర్ణాంకం
ssh_mldsa44_ed25519_deserialize_ప్రజా(స్థిరరాశి అక్షరం *ktype, నిర్మాణం sshbuf *b,
    నిర్మాణం sshkey *కీలకం)
{
	u_char *pk = ఖాళీ;
	కొలత_t len = 0;
	పూర్ణాంకం r;

	ఒకవేళ ((r = sshbuf_get_string(b, &pk, &len)) != 0)
		తిరిగి r;
	ఒకవేళ (len != MLDSA44_ED25519_PK_SZ) {
		freezero(pk, len);
		తిరిగి SSH_ERR_INVALID_FORMAT;
	}
	కీలకం->mldsa_ed25519_pk = pk;
	తిరిగి 0;
}

స్థిర పూర్ణాంకం
ssh_mldsa44_ed25519_deserialize_వ్యక్తిగత(స్థిరరాశి అక్షరం *ktype, నిర్మాణం sshbuf *b,
    నిర్మాణం sshkey *కీలకం)
{
	పూర్ణాంకం r;
	కొలత_t sklen = 0;
	u_char *sk = ఖాళీ;

	ఒకవేళ (!sshkey_is_cert(కీలకం)) {
		ఒకవేళ ((r = ssh_mldsa44_ed25519_deserialize_ప్రజా(ktype,
		    b, కీలకం)) != 0)
			తిరిగి r;
	}
	ఒకవేళ ((r = sshbuf_get_string(b, &sk, &sklen)) != 0)
		వెళ్ళు బహిర్గతం;
	ఒకవేళ (sklen != MLDSA44_ED25519_SK_SZ) {
		r = SSH_ERR_INVALID_FORMAT;
		వెళ్ళు బహిర్గతం;
	}
	కీలకం->mldsa_ed25519_sk = sk;
	sk = ఖాళీ; /* transferred */
	r = 0;
 బహిర్గతం:
	freezero(sk, sklen);
	తిరిగి r;
}

స్థిర పూర్ణాంకం
ssh_mldsa44_ed25519_generate(నిర్మాణం sshkey *k, పూర్ణాంకం బిట్లు)
{
	ssh_mldsa44_ed25519_cleanup(k);
	ఒకవేళ ((k->mldsa_ed25519_pk = జ్ఞాపకం_ఇవ్వు(MLDSA44_ED25519_PK_SZ)) == ఖాళీ ||
	    (k->mldsa_ed25519_sk = జ్ఞాపకం_ఇవ్వు(MLDSA44_ED25519_SK_SZ)) == ఖాళీ) {
		ssh_mldsa44_ed25519_cleanup(k);
		తిరిగి SSH_ERR_ALLOC_FAIL;
	}
	ఒకవేళ (crypto_sign_mldsa44_ed25519_keygen(k->mldsa_ed25519_pk,
	    k->mldsa_ed25519_sk) != 0) {
		ssh_mldsa44_ed25519_cleanup(k);
		తిరిగి SSH_ERR_CRYPTO_ERROR;
	}
	తిరిగి 0;
}

స్థిర పూర్ణాంకం
ssh_mldsa44_ed25519_copy_ప్రజా(స్థిరరాశి నిర్మాణం sshkey *from, నిర్మాణం sshkey *గమ్యం)
{
	ఒకవేళ (from->mldsa_ed25519_pk == ఖాళీ)
		తిరిగి SSH_ERR_INVALID_వాదం;
	ఒకవేళ ((గమ్యం->mldsa_ed25519_pk = జ్ఞాపకం_ఇవ్వు(MLDSA44_ED25519_PK_SZ)) == ఖాళీ)
		తిరిగి SSH_ERR_ALLOC_FAIL;
	జ్ఞాపకం_నకలు(గమ్యం->mldsa_ed25519_pk, from->mldsa_ed25519_pk,
	    MLDSA44_ED25519_PK_SZ);
	తిరిగి 0;
}

స్థిర పూర్ణాంకం
ssh_mldsa44_ed25519_sign(నిర్మాణం sshkey *కీలకం,
    u_char **sigp, కొలత_t *lenp, స్థిరరాశి u_char *దత్తాంశం, కొలత_t datalen,
    స్థిరరాశి అక్షరం *alg, స్థిరరాశి అక్షరం *sk_provider, స్థిరరాశి అక్షరం *sk_pin,
    u_int compat)
{
	u_char sig[MLDSA44_ED25519_SIG_SZ];
	నిర్మాణం sshbuf *b = ఖాళీ;
	పూర్ణాంకం r = SSH_ERR_అంతర్గత_ERROR;

	ఒకవేళ (lenp != ఖాళీ)
		*lenp = 0;
	ఒకవేళ (sigp != ఖాళీ)
		*sigp = ఖాళీ;

	ఒకవేళ (కీలకం == ఖాళీ ||
	    sshkey_type_plain(కీలకం->type) != కీలకం_MLDSA44_ED25519 ||
	    కీలకం->mldsa_ed25519_sk == ఖాళీ)
		తిరిగి SSH_ERR_INVALID_వాదం;

	ఒకవేళ (crypto_sign_mldsa44_ed25519_sign(sig, దత్తాంశం, datalen, ఖాళీ, 0,
	    కీలకం->mldsa_ed25519_sk) != 0) {
		r = SSH_ERR_CRYPTO_ERROR;
		వెళ్ళు బహిర్గతం;
	}

	ఒకవేళ ((b = sshbuf_new()) == ఖాళీ) {
		r = SSH_ERR_ALLOC_FAIL;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((r = sshbuf_put_cstring(b, SSH_MLDSA44_ED25519_ALG_NAME)) != 0 ||
	    (r = sshbuf_put_string(b, sig, పరిమాణం(sig))) != 0)
		వెళ్ళు బహిర్గతం;

	ఒకవేళ (sigp != ఖాళీ) {
		ఒకవేళ ((*sigp = జ్ఞాపకం_ఇవ్వు(sshbuf_len(b))) == ఖాళీ) {
			r = SSH_ERR_ALLOC_FAIL;
			వెళ్ళు బహిర్గతం;
		}
		జ్ఞాపకం_నకలు(*sigp, sshbuf_ptr(b), sshbuf_len(b));
	}
	ఒకవేళ (lenp != ఖాళీ)
		*lenp = sshbuf_len(b);
	r = 0;
 బహిర్గతం:
	sshbuf_free(b);
	explicit_bzero(sig, పరిమాణం(sig));
	తిరిగి r;
}

స్థిర పూర్ణాంకం
ssh_mldsa44_ed25519_verify(స్థిరరాశి నిర్మాణం sshkey *కీలకం,
    స్థిరరాశి u_char *sig, కొలత_t siglen, స్థిరరాశి u_char *దత్తాంశం, కొలత_t dlen,
    స్థిరరాశి అక్షరం *alg, u_int compat, నిర్మాణం sshkey_sig_details **detailsp)
{
	నిర్మాణం sshbuf *b = ఖాళీ;
	అక్షరం *ktype = ఖాళీ;
	స్థిరరాశి u_char *sigblob;
	కొలత_t len;
	పూర్ణాంకం r;

	ఒకవేళ (కీలకం == ఖాళీ ||
	    sshkey_type_plain(కీలకం->type) != కీలకం_MLDSA44_ED25519 ||
	    కీలకం->mldsa_ed25519_pk == ఖాళీ ||
	    sig == ఖాళీ || siglen == 0)
		తిరిగి SSH_ERR_INVALID_వాదం;

	ఒకవేళ ((b = sshbuf_from(sig, siglen)) == ఖాళీ)
		తిరిగి SSH_ERR_ALLOC_FAIL;
	ఒకవేళ ((r = sshbuf_get_cstring(b, &ktype, ఖాళీ)) != 0 ||
	    (r = sshbuf_get_string_ప్రత్యక్ష(b, &sigblob, &len)) != 0)
		వెళ్ళు బహిర్గతం;
	ఒకవేళ (strcmp(SSH_MLDSA44_ED25519_ALG_NAME, ktype) != 0) {
		r = SSH_ERR_కీలకం_TYPE_MISMATCH;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ (sshbuf_len(b) != 0) {
		r = SSH_ERR_UNEXPECTED_TRAILING_దత్తాంశం;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ (len != MLDSA44_ED25519_SIG_SZ) {
		r = SSH_ERR_INVALID_FORMAT;
		వెళ్ళు బహిర్గతం;
	}

	ఒకవేళ (crypto_sign_mldsa44_ed25519_verify(sigblob, దత్తాంశం, dlen, ఖాళీ, 0,
	    కీలకం->mldsa_ed25519_pk) != 0) {
		r = SSH_ERR_SIGNATURE_INVALID;
		వెళ్ళు బహిర్గతం;
	}

	r = 0;
 బహిర్గతం:
	sshbuf_free(b);
	విడుదల(ktype);
	తిరిగి r;
}

స్థిరరాశి నిర్మాణం sshkey_impl_funcs sshkey_mldsa44_ed25519_funcs = {
	/* .size = */		ఖాళీ,
	/* .alloc = */		ఖాళీ,
	/* .cleanup = */	ssh_mldsa44_ed25519_cleanup,
	/* .equal = */		ssh_mldsa44_ed25519_equal,
	/* .ssh_serialize_public = */ ssh_mldsa44_ed25519_serialize_ప్రజా,
	/* .ssh_deserialize_public = */ ssh_mldsa44_ed25519_deserialize_ప్రజా,
	/* .ssh_serialize_private = */ ssh_mldsa44_ed25519_serialize_వ్యక్తిగత,
	/* .ssh_deserialize_private = */ ssh_mldsa44_ed25519_deserialize_వ్యక్తిగత,
	/* .generate = */	ssh_mldsa44_ed25519_generate,
	/* .copy_public = */	ssh_mldsa44_ed25519_copy_ప్రజా,
	/* .sign = */		ssh_mldsa44_ed25519_sign,
	/* .verify = */		ssh_mldsa44_ed25519_verify,
};

స్థిరరాశి నిర్మాణం sshkey_impl sshkey_mldsa44_ed25519_impl = {
	/* .name = */		"ssh-mldsa44-ed25519",
	/* .shortname = */	"MLDSA44-ED25519",
	/* .sigalg = */		ఖాళీ,
	/* .type = */		కీలకం_MLDSA44_ED25519,
	/* .nid = */		0,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	512, /* size of the private key */
	/* .funcs = */		&sshkey_mldsa44_ed25519_funcs,
};

స్థిరరాశి నిర్మాణం sshkey_impl sshkey_mldsa44_ed25519_cert_impl = {
	/* .name = */		"ssh-mldsa44-ed25519-cert",
	/* .shortname = */	"MLDSA44-ED25519-CERT",
	/* .sigalg = */		ఖాళీ,
	/* .type = */		కీలకం_MLDSA44_ED25519_CERT,
	/* .nid = */		0,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	512, /* size of the private key */
	/* .funcs = */		&sshkey_mldsa44_ed25519_funcs,
};
#అయితే_ముగింపు /* USE_MLDSA */
