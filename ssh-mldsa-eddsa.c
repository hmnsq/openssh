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

#اگر_تعریف_شدہ USE_MLDSA

#شامل <sys/types.h>
#شامل <stdint.h>
#شامل <string.h>
#شامل <stdlib.h>

#شامل "crypto_api.h"
#شامل "sshbuf.h"
#شامل "ssherr.h"
#شامل "digest.h"
#تعریف_کرو SSHKEY_اندرونی
#شامل "sshkey.h"
#شامل "log.h"

#تعریف_کرو مرکب_سابقہ "CompositeAlgorithmSignatures2025"
#تعریف_کرو مرکب_LABEL  "COMPSIG-MLDSA44-Ed25519-SHA512"
#تعریف_کرو SSH_MLDSA44_ED25519_ALG_NAME   "ssh-mldsa44-ed25519"

/*
 * raw_* functions implement the draft-ietf-lamps-pq-composite-sigs-18
 * composite signature scheme. These are exposed (i.e. not static) so
 * we can test them separately in unittests/crypto.
 */

صحیح
crypto_sign_mldsa44_ed25519_keygen(uint8_t pk[MLDSA44_ED25519_PK_SZ],
    uint8_t sk[MLDSA44_ED25519_SK_SZ])
{
	uint8_t mldsa_بیج[MLDSA44_SEEDBYTES];
	uint8_t ed25519_بیج[crypto_sign_ed25519_SEEDBYTES];
	صحیح r;

	arc4random_buf(mldsa_بیج, حجم(mldsa_بیج));
	arc4random_buf(ed25519_بیج, حجم(ed25519_بیج));

	r = crypto_sign_mldsa44_ed25519_keygen_seeded(pk, sk, mldsa_بیج,
	    ed25519_بیج);
	explicit_bzero(mldsa_بیج, حجم(mldsa_بیج));
	explicit_bzero(ed25519_بیج, حجم(ed25519_بیج));
	واپس r;
}

صحیح
crypto_sign_mldsa44_ed25519_keygen_seeded(uint8_t pk[MLDSA44_ED25519_PK_SZ],
    uint8_t sk[MLDSA44_ED25519_SK_SZ],
    ثابت uint8_t mldsa_بیج[MLDSA44_SEEDBYTES],
    ثابت uint8_t ed25519_بیج[crypto_sign_ed25519_SEEDBYTES])
{
	uint8_t ed25519_pk[MLDSA44_SEEDBYTES];
	uint8_t ed25519_sk[crypto_sign_ed25519_SECRETKEYBYTES];
	uint8_t mldsa_sk[MLDSA44_SECRETKEYBYTES];
	صحیح ret = -1;

	اگر (crypto_sign_mldsa44_keypair_seeded(pk, mldsa_sk, mldsa_بیج) != 0)
		جاؤ برآمد;
	اگر (crypto_sign_ed25519_بیج_keypair(ed25519_pk, ed25519_sk,
	    ed25519_بیج) != 0)
		جاؤ برآمد;

	/* Serialize PK: mldsaPK || ed25519PK */
	حافظہ_نقل(pk + MLDSA44_PUBLICKEYBYTES, ed25519_pk,
	    crypto_sign_ed25519_SEEDBYTES);

	/* Serialize SK: mldsaSeed || ed25519Seed */
	حافظہ_نقل(sk, mldsa_بیج, MLDSA44_SEEDBYTES);
	حافظہ_نقل(sk + MLDSA44_SEEDBYTES, ed25519_بیج,
	    crypto_sign_ed25519_SEEDBYTES);

	/* success */
	ret = 0;
 برآمد:
	explicit_bzero(mldsa_sk, حجم(mldsa_sk));
	explicit_bzero(ed25519_sk, حجم(ed25519_sk));
	واپس ret;
}

ساکن صحیح
construct_m_مفرد(uint8_t **m_primep, سائز_t *m_مفرد_lenp,
    ثابت uint8_t *پیغام, سائز_t msglen,
    ثابت uint8_t *ctx, سائز_t ctxlen)
{
	صحیح r;
	uint8_t hash[64];
	ساخت sshbuf *m_مفرد;

	*m_primep = تہی;
	*m_مفرد_lenp = 0;

	اگر (ctxlen > 255)
		واپس SSH_ERR_INVALID_دلیل;
	اگر ((r = ssh_digest_حافظہ(SSH_DIGEST_SHA512, پیغام, msglen,
	    hash, حجم(hash))) != 0)
		واپس r;
	اگر ((m_مفرد = sshbuf_new()) == تہی)
		واپس SSH_ERR_ALLOC_FAIL;
	اگر ((r = sshbuf_put(m_مفرد, مرکب_سابقہ,
	    حجم(مرکب_سابقہ) - 1)) != 0 ||
	    (r = sshbuf_put(m_مفرد, مرکب_LABEL,
	    حجم(مرکب_LABEL) - 1)) != 0 ||
	    (r = sshbuf_put_u8(m_مفرد, (uint8_t)ctxlen)) != 0 ||
	    (r = sshbuf_put(m_مفرد, ctx, ctxlen)) != 0 ||
	    (r = sshbuf_put(m_مفرد, hash, حجم(hash))) != 0) {
		sshbuf_free(m_مفرد);
		واپس r;
	}
	اگر ((*m_primep = حافظہ_دو(sshbuf_len(m_مفرد))) == تہی) {
		sshbuf_free(m_مفرد);
		واپس SSH_ERR_ALLOC_FAIL;
	}
	حافظہ_نقل(*m_primep, sshbuf_ptr(m_مفرد), sshbuf_len(m_مفرد));
	*m_مفرد_lenp = sshbuf_len(m_مفرد);
	/* success */
	sshbuf_free(m_مفرد);
	واپس 0;
}

صحیح
crypto_sign_mldsa44_ed25519_sign(uint8_t sig[MLDSA44_ED25519_SIG_SZ],
    ثابت uint8_t *پیغام, سائز_t msglen,
    ثابت uint8_t *ctx, سائز_t ctxlen,
    ثابت uint8_t sk[MLDSA44_ED25519_SK_SZ])
{
	uint8_t *m_مفرد = تہی;
	سائز_t m_مفرد_len = 0;
	uint8_t mldsa_sk[MLDSA44_SECRETKEYBYTES];
	uint8_t mldsa_pk_dummy[MLDSA44_PUBLICKEYBYTES];
	uint8_t ed25519_pk[crypto_sign_ed25519_PUBLICKEYBYTES];
	uint8_t ed25519_sk[crypto_sign_ed25519_SECRETKEYBYTES];
	uint8_t mldsa_rnd[MLDSA44_SEEDBYTES];
	غیرعلامتی طویل طویل smlen;
	صحیح r = -1;

	اگر (construct_m_مفرد(&m_مفرد, &m_مفرد_len, پیغام, msglen,
	    ctx, ctxlen) != 0)
		واپس -1;

	/* Expand ML-DSA key from seed */
	اگر (crypto_sign_mldsa44_keypair_seeded(mldsa_pk_dummy, mldsa_sk, sk) != 0)
		جاؤ برآمد;

	/* Sign with ML-DSA */
	arc4random_buf(mldsa_rnd, حجم(mldsa_rnd));
	اگر (crypto_sign_mldsa44_seeded(sig, m_مفرد, m_مفرد_len,
	    (ثابت uint8_t *)مرکب_LABEL, حجم(مرکب_LABEL) - 1,
	    mldsa_sk, mldsa_rnd) != 0)
		جاؤ برآمد;

	/* Expand Ed25519 key from seed */
	اگر (crypto_sign_ed25519_بیج_keypair(ed25519_pk, ed25519_sk,
	    sk + MLDSA44_SEEDBYTES) != 0)
		جاؤ برآمد;

	/* Sign with Ed25519 */
	اگر (crypto_sign_ed25519_detached(sig + MLDSA44_SIGBYTES, &smlen,
	    m_مفرد, m_مفرد_len, ed25519_sk) != 0 ||
	    smlen != crypto_sign_ed25519_بائٹیں)
		جاؤ برآمد;

	r = 0;
 برآمد:
	آزاد(m_مفرد);
	explicit_bzero(mldsa_rnd, حجم(mldsa_rnd));
	explicit_bzero(mldsa_sk, حجم(mldsa_sk));
	explicit_bzero(ed25519_sk, حجم(ed25519_sk));
	واپس r;
}

صحیح
crypto_sign_mldsa44_ed25519_verify(ثابت uint8_t sig[MLDSA44_ED25519_SIG_SZ],
    ثابت uint8_t *پیغام, سائز_t msglen,
    ثابت uint8_t *ctx, سائز_t ctxlen,
    ثابت uint8_t pk[MLDSA44_ED25519_PK_SZ])
{
	uint8_t *m_مفرد = تہی;
	سائز_t m_مفرد_len = 0;
	صحیح r = -1;

	اگر (construct_m_مفرد(&m_مفرد, &m_مفرد_len, پیغام, msglen,
	    ctx, ctxlen) != 0)
		واپس -1;

	/* Verify ML-DSA */
	اگر (crypto_sign_mldsa44_verify(sig, m_مفرد, m_مفرد_len,
	    (ثابت uint8_t *)مرکب_LABEL, حجم(مرکب_LABEL) - 1,
	    pk) != 0)
		جاؤ برآمد;

	/* Verify Ed25519 */
	اگر (crypto_sign_ed25519_verify_detached(sig + MLDSA44_SIGBYTES,
	    m_مفرد, m_مفرد_len, pk + MLDSA44_PUBLICKEYBYTES) != 0)
		جاؤ برآمد;

	r = 0;
 برآمد:
	آزاد(m_مفرد);
	واپس r;
}

/* sshkey integration */

ساکن خالی
ssh_mldsa44_ed25519_cleanup(ساخت sshkey *k)
{
	freezero(k->mldsa_ed25519_pk, MLDSA44_ED25519_PK_SZ);
	freezero(k->mldsa_ed25519_sk, MLDSA44_ED25519_SK_SZ);
	k->mldsa_ed25519_pk = تہی;
	k->mldsa_ed25519_sk = تہی;
}

ساکن صحیح
ssh_mldsa44_ed25519_equal(ثابت ساخت sshkey *a, ثابت ساخت sshkey *b)
{
	اگر (a->mldsa_ed25519_pk == تہی || b->mldsa_ed25519_pk == تہی)
		واپس 0;
	اگر (memcmp(a->mldsa_ed25519_pk, b->mldsa_ed25519_pk,
	    MLDSA44_ED25519_PK_SZ) != 0)
		واپس 0;
	واپس 1;
}

ساکن صحیح
ssh_mldsa44_ed25519_serialize_عوامی(ثابت ساخت sshkey *کلید, ساخت sshbuf *b,
    شمار sshkey_serialize_rep opts)
{
	صحیح r;

	اگر (کلید->mldsa_ed25519_pk == تہی)
		واپس SSH_ERR_INVALID_دلیل;
	اگر ((r = sshbuf_put_string(b, کلید->mldsa_ed25519_pk,
	    MLDSA44_ED25519_PK_SZ)) != 0)
		واپس r;

	واپس 0;
}

ساکن صحیح
ssh_mldsa44_ed25519_serialize_نجی(ثابت ساخت sshkey *کلید, ساخت sshbuf *b,
    شمار sshkey_serialize_rep opts)
{
	صحیح r;

	اگر (کلید->mldsa_ed25519_sk == تہی)
		واپس SSH_ERR_INVALID_دلیل;
	اگر (!sshkey_is_cert(کلید)) {
		اگر ((r = ssh_mldsa44_ed25519_serialize_عوامی(کلید,
		    b, opts)) != 0)
			واپس r;
	}
	اگر ((r = sshbuf_put_string(b, کلید->mldsa_ed25519_sk,
	    MLDSA44_ED25519_SK_SZ)) != 0)
		واپس r;

	واپس 0;
}

ساکن صحیح
ssh_mldsa44_ed25519_deserialize_عوامی(ثابت حرف *ktype, ساخت sshbuf *b,
    ساخت sshkey *کلید)
{
	u_char *pk = تہی;
	سائز_t len = 0;
	صحیح r;

	اگر ((r = sshbuf_get_string(b, &pk, &len)) != 0)
		واپس r;
	اگر (len != MLDSA44_ED25519_PK_SZ) {
		freezero(pk, len);
		واپس SSH_ERR_INVALID_FORMAT;
	}
	کلید->mldsa_ed25519_pk = pk;
	واپس 0;
}

ساکن صحیح
ssh_mldsa44_ed25519_deserialize_نجی(ثابت حرف *ktype, ساخت sshbuf *b,
    ساخت sshkey *کلید)
{
	صحیح r;
	سائز_t sklen = 0;
	u_char *sk = تہی;

	اگر (!sshkey_is_cert(کلید)) {
		اگر ((r = ssh_mldsa44_ed25519_deserialize_عوامی(ktype,
		    b, کلید)) != 0)
			واپس r;
	}
	اگر ((r = sshbuf_get_string(b, &sk, &sklen)) != 0)
		جاؤ برآمد;
	اگر (sklen != MLDSA44_ED25519_SK_SZ) {
		r = SSH_ERR_INVALID_FORMAT;
		جاؤ برآمد;
	}
	کلید->mldsa_ed25519_sk = sk;
	sk = تہی; /* transferred */
	r = 0;
 برآمد:
	freezero(sk, sklen);
	واپس r;
}

ساکن صحیح
ssh_mldsa44_ed25519_generate(ساخت sshkey *k, صحیح بٹ)
{
	ssh_mldsa44_ed25519_cleanup(k);
	اگر ((k->mldsa_ed25519_pk = حافظہ_دو(MLDSA44_ED25519_PK_SZ)) == تہی ||
	    (k->mldsa_ed25519_sk = حافظہ_دو(MLDSA44_ED25519_SK_SZ)) == تہی) {
		ssh_mldsa44_ed25519_cleanup(k);
		واپس SSH_ERR_ALLOC_FAIL;
	}
	اگر (crypto_sign_mldsa44_ed25519_keygen(k->mldsa_ed25519_pk,
	    k->mldsa_ed25519_sk) != 0) {
		ssh_mldsa44_ed25519_cleanup(k);
		واپس SSH_ERR_CRYPTO_ERROR;
	}
	واپس 0;
}

ساکن صحیح
ssh_mldsa44_ed25519_copy_عوامی(ثابت ساخت sshkey *from, ساخت sshkey *مقصد)
{
	اگر (from->mldsa_ed25519_pk == تہی)
		واپس SSH_ERR_INVALID_دلیل;
	اگر ((مقصد->mldsa_ed25519_pk = حافظہ_دو(MLDSA44_ED25519_PK_SZ)) == تہی)
		واپس SSH_ERR_ALLOC_FAIL;
	حافظہ_نقل(مقصد->mldsa_ed25519_pk, from->mldsa_ed25519_pk,
	    MLDSA44_ED25519_PK_SZ);
	واپس 0;
}

ساکن صحیح
ssh_mldsa44_ed25519_sign(ساخت sshkey *کلید,
    u_char **sigp, سائز_t *lenp, ثابت u_char *ڈیٹا, سائز_t datalen,
    ثابت حرف *alg, ثابت حرف *sk_provider, ثابت حرف *sk_pin,
    u_int compat)
{
	u_char sig[MLDSA44_ED25519_SIG_SZ];
	ساخت sshbuf *b = تہی;
	صحیح r = SSH_ERR_اندرونی_ERROR;

	اگر (lenp != تہی)
		*lenp = 0;
	اگر (sigp != تہی)
		*sigp = تہی;

	اگر (کلید == تہی ||
	    sshkey_type_plain(کلید->type) != کلید_MLDSA44_ED25519 ||
	    کلید->mldsa_ed25519_sk == تہی)
		واپس SSH_ERR_INVALID_دلیل;

	اگر (crypto_sign_mldsa44_ed25519_sign(sig, ڈیٹا, datalen, تہی, 0,
	    کلید->mldsa_ed25519_sk) != 0) {
		r = SSH_ERR_CRYPTO_ERROR;
		جاؤ برآمد;
	}

	اگر ((b = sshbuf_new()) == تہی) {
		r = SSH_ERR_ALLOC_FAIL;
		جاؤ برآمد;
	}
	اگر ((r = sshbuf_put_cstring(b, SSH_MLDSA44_ED25519_ALG_NAME)) != 0 ||
	    (r = sshbuf_put_string(b, sig, حجم(sig))) != 0)
		جاؤ برآمد;

	اگر (sigp != تہی) {
		اگر ((*sigp = حافظہ_دو(sshbuf_len(b))) == تہی) {
			r = SSH_ERR_ALLOC_FAIL;
			جاؤ برآمد;
		}
		حافظہ_نقل(*sigp, sshbuf_ptr(b), sshbuf_len(b));
	}
	اگر (lenp != تہی)
		*lenp = sshbuf_len(b);
	r = 0;
 برآمد:
	sshbuf_free(b);
	explicit_bzero(sig, حجم(sig));
	واپس r;
}

ساکن صحیح
ssh_mldsa44_ed25519_verify(ثابت ساخت sshkey *کلید,
    ثابت u_char *sig, سائز_t siglen, ثابت u_char *ڈیٹا, سائز_t dlen,
    ثابت حرف *alg, u_int compat, ساخت sshkey_sig_details **detailsp)
{
	ساخت sshbuf *b = تہی;
	حرف *ktype = تہی;
	ثابت u_char *sigblob;
	سائز_t len;
	صحیح r;

	اگر (کلید == تہی ||
	    sshkey_type_plain(کلید->type) != کلید_MLDSA44_ED25519 ||
	    کلید->mldsa_ed25519_pk == تہی ||
	    sig == تہی || siglen == 0)
		واپس SSH_ERR_INVALID_دلیل;

	اگر ((b = sshbuf_from(sig, siglen)) == تہی)
		واپس SSH_ERR_ALLOC_FAIL;
	اگر ((r = sshbuf_get_cstring(b, &ktype, تہی)) != 0 ||
	    (r = sshbuf_get_string_براہ_راست(b, &sigblob, &len)) != 0)
		جاؤ برآمد;
	اگر (strcmp(SSH_MLDSA44_ED25519_ALG_NAME, ktype) != 0) {
		r = SSH_ERR_کلید_TYPE_MISMATCH;
		جاؤ برآمد;
	}
	اگر (sshbuf_len(b) != 0) {
		r = SSH_ERR_UNEXPECTED_TRAILING_ڈیٹا;
		جاؤ برآمد;
	}
	اگر (len != MLDSA44_ED25519_SIG_SZ) {
		r = SSH_ERR_INVALID_FORMAT;
		جاؤ برآمد;
	}

	اگر (crypto_sign_mldsa44_ed25519_verify(sigblob, ڈیٹا, dlen, تہی, 0,
	    کلید->mldsa_ed25519_pk) != 0) {
		r = SSH_ERR_SIGNATURE_INVALID;
		جاؤ برآمد;
	}

	r = 0;
 برآمد:
	sshbuf_free(b);
	آزاد(ktype);
	واپس r;
}

ثابت ساخت sshkey_impl_funcs sshkey_mldsa44_ed25519_funcs = {
	/* .size = */		تہی,
	/* .alloc = */		تہی,
	/* .cleanup = */	ssh_mldsa44_ed25519_cleanup,
	/* .equal = */		ssh_mldsa44_ed25519_equal,
	/* .ssh_serialize_public = */ ssh_mldsa44_ed25519_serialize_عوامی,
	/* .ssh_deserialize_public = */ ssh_mldsa44_ed25519_deserialize_عوامی,
	/* .ssh_serialize_private = */ ssh_mldsa44_ed25519_serialize_نجی,
	/* .ssh_deserialize_private = */ ssh_mldsa44_ed25519_deserialize_نجی,
	/* .generate = */	ssh_mldsa44_ed25519_generate,
	/* .copy_public = */	ssh_mldsa44_ed25519_copy_عوامی,
	/* .sign = */		ssh_mldsa44_ed25519_sign,
	/* .verify = */		ssh_mldsa44_ed25519_verify,
};

ثابت ساخت sshkey_impl sshkey_mldsa44_ed25519_impl = {
	/* .name = */		"ssh-mldsa44-ed25519",
	/* .shortname = */	"MLDSA44-ED25519",
	/* .sigalg = */		تہی,
	/* .type = */		کلید_MLDSA44_ED25519,
	/* .nid = */		0,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	512, /* size of the private key */
	/* .funcs = */		&sshkey_mldsa44_ed25519_funcs,
};

ثابت ساخت sshkey_impl sshkey_mldsa44_ed25519_cert_impl = {
	/* .name = */		"ssh-mldsa44-ed25519-cert",
	/* .shortname = */	"MLDSA44-ED25519-CERT",
	/* .sigalg = */		تہی,
	/* .type = */		کلید_MLDSA44_ED25519_CERT,
	/* .nid = */		0,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	512, /* size of the private key */
	/* .funcs = */		&sshkey_mldsa44_ed25519_funcs,
};
#اگر_ختم /* USE_MLDSA */
