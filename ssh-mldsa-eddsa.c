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

#که_تعریف_شوی USE_MLDSA

#ضمن <sys/types.h>
#ضمن <stdint.h>
#ضمن <string.h>
#ضمن <stdlib.h>

#ضمن "crypto_api.h"
#ضمن "sshbuf.h"
#ضمن "ssherr.h"
#ضمن "digest.h"
#تعریف_کړه SSHKEY_دننی
#ضمن "sshkey.h"
#ضمن "log.h"

#تعریف_کړه مرکب_مختاړی "CompositeAlgorithmSignatures2025"
#تعریف_کړه مرکب_LABEL  "COMPSIG-MLDSA44-Ed25519-SHA512"
#تعریف_کړه SSH_MLDSA44_ED25519_ALG_NAME   "ssh-mldsa44-ed25519"

/*
 * raw_* functions implement the draft-ietf-lamps-pq-composite-sigs-18
 * composite signature scheme. These are exposed (i.e. not static) so
 * we can test them separately in unittests/crypto.
 */

صحيح
crypto_sign_mldsa44_ed25519_keygen(uint8_t pk[MLDSA44_ED25519_PK_SZ],
    uint8_t sk[MLDSA44_ED25519_SK_SZ])
{
	uint8_t mldsa_تخم[MLDSA44_SEEDBYTES];
	uint8_t ed25519_تخم[crypto_sign_ed25519_SEEDBYTES];
	صحيح r;

	arc4random_buf(mldsa_تخم, حجم(mldsa_تخم));
	arc4random_buf(ed25519_تخم, حجم(ed25519_تخم));

	r = crypto_sign_mldsa44_ed25519_keygen_seeded(pk, sk, mldsa_تخم,
	    ed25519_تخم);
	explicit_bzero(mldsa_تخم, حجم(mldsa_تخم));
	explicit_bzero(ed25519_تخم, حجم(ed25519_تخم));
	أرجع r;
}

صحيح
crypto_sign_mldsa44_ed25519_keygen_seeded(uint8_t pk[MLDSA44_ED25519_PK_SZ],
    uint8_t sk[MLDSA44_ED25519_SK_SZ],
    ثابت uint8_t mldsa_تخم[MLDSA44_SEEDBYTES],
    ثابت uint8_t ed25519_تخم[crypto_sign_ed25519_SEEDBYTES])
{
	uint8_t ed25519_pk[MLDSA44_SEEDBYTES];
	uint8_t ed25519_sk[crypto_sign_ed25519_SECRETKEYBYTES];
	uint8_t mldsa_sk[MLDSA44_SECRETKEYBYTES];
	صحيح ret = -1;

	إذا (crypto_sign_mldsa44_keypair_seeded(pk, mldsa_sk, mldsa_تخم) != 0)
		اذهب بهر;
	إذا (crypto_sign_ed25519_تخم_keypair(ed25519_pk, ed25519_sk,
	    ed25519_تخم) != 0)
		اذهب بهر;

	/* Serialize PK: mldsaPK || ed25519PK */
	حافظه_نقل(pk + MLDSA44_PUBLICKEYBYTES, ed25519_pk,
	    crypto_sign_ed25519_SEEDBYTES);

	/* Serialize SK: mldsaSeed || ed25519Seed */
	حافظه_نقل(sk, mldsa_تخم, MLDSA44_SEEDBYTES);
	حافظه_نقل(sk + MLDSA44_SEEDBYTES, ed25519_تخم,
	    crypto_sign_ed25519_SEEDBYTES);

	/* success */
	ret = 0;
 بهر:
	explicit_bzero(mldsa_sk, حجم(mldsa_sk));
	explicit_bzero(ed25519_sk, حجم(ed25519_sk));
	أرجع ret;
}

ساكن صحيح
construct_m_اولي(uint8_t **m_primep, اندازه_t *m_اولي_lenp,
    ثابت uint8_t *پیغام, اندازه_t msglen,
    ثابت uint8_t *ctx, اندازه_t ctxlen)
{
	صحيح r;
	uint8_t hash[64];
	بنية sshbuf *m_اولي;

	*m_primep = عدم;
	*m_اولي_lenp = 0;

	إذا (ctxlen > 255)
		أرجع SSH_ERR_INVALID_دلیل;
	إذا ((r = ssh_digest_حافظه(SSH_DIGEST_SHA512, پیغام, msglen,
	    hash, حجم(hash))) != 0)
		أرجع r;
	إذا ((m_اولي = sshbuf_new()) == عدم)
		أرجع SSH_ERR_ALLOC_FAIL;
	إذا ((r = sshbuf_put(m_اولي, مرکب_مختاړی,
	    حجم(مرکب_مختاړی) - 1)) != 0 ||
	    (r = sshbuf_put(m_اولي, مرکب_LABEL,
	    حجم(مرکب_LABEL) - 1)) != 0 ||
	    (r = sshbuf_put_u8(m_اولي, (uint8_t)ctxlen)) != 0 ||
	    (r = sshbuf_put(m_اولي, ctx, ctxlen)) != 0 ||
	    (r = sshbuf_put(m_اولي, hash, حجم(hash))) != 0) {
		sshbuf_free(m_اولي);
		أرجع r;
	}
	إذا ((*m_primep = حافظه_ورکړه(sshbuf_len(m_اولي))) == عدم) {
		sshbuf_free(m_اولي);
		أرجع SSH_ERR_ALLOC_FAIL;
	}
	حافظه_نقل(*m_primep, sshbuf_ptr(m_اولي), sshbuf_len(m_اولي));
	*m_اولي_lenp = sshbuf_len(m_اولي);
	/* success */
	sshbuf_free(m_اولي);
	أرجع 0;
}

صحيح
crypto_sign_mldsa44_ed25519_sign(uint8_t sig[MLDSA44_ED25519_SIG_SZ],
    ثابت uint8_t *پیغام, اندازه_t msglen,
    ثابت uint8_t *ctx, اندازه_t ctxlen,
    ثابت uint8_t sk[MLDSA44_ED25519_SK_SZ])
{
	uint8_t *m_اولي = عدم;
	اندازه_t m_اولي_len = 0;
	uint8_t mldsa_sk[MLDSA44_SECRETKEYBYTES];
	uint8_t mldsa_pk_dummy[MLDSA44_PUBLICKEYBYTES];
	uint8_t ed25519_pk[crypto_sign_ed25519_PUBLICKEYBYTES];
	uint8_t ed25519_sk[crypto_sign_ed25519_SECRETKEYBYTES];
	uint8_t mldsa_rnd[MLDSA44_SEEDBYTES];
	بینښه اوږد اوږد smlen;
	صحيح r = -1;

	إذا (construct_m_اولي(&m_اولي, &m_اولي_len, پیغام, msglen,
	    ctx, ctxlen) != 0)
		أرجع -1;

	/* Expand ML-DSA key from seed */
	إذا (crypto_sign_mldsa44_keypair_seeded(mldsa_pk_dummy, mldsa_sk, sk) != 0)
		اذهب بهر;

	/* Sign with ML-DSA */
	arc4random_buf(mldsa_rnd, حجم(mldsa_rnd));
	إذا (crypto_sign_mldsa44_seeded(sig, m_اولي, m_اولي_len,
	    (ثابت uint8_t *)مرکب_LABEL, حجم(مرکب_LABEL) - 1,
	    mldsa_sk, mldsa_rnd) != 0)
		اذهب بهر;

	/* Expand Ed25519 key from seed */
	إذا (crypto_sign_ed25519_تخم_keypair(ed25519_pk, ed25519_sk,
	    sk + MLDSA44_SEEDBYTES) != 0)
		اذهب بهر;

	/* Sign with Ed25519 */
	إذا (crypto_sign_ed25519_detached(sig + MLDSA44_SIGBYTES, &smlen,
	    m_اولي, m_اولي_len, ed25519_sk) != 0 ||
	    smlen != crypto_sign_ed25519_بایټونه)
		اذهب بهر;

	r = 0;
 بهر:
	حرر(m_اولي);
	explicit_bzero(mldsa_rnd, حجم(mldsa_rnd));
	explicit_bzero(mldsa_sk, حجم(mldsa_sk));
	explicit_bzero(ed25519_sk, حجم(ed25519_sk));
	أرجع r;
}

صحيح
crypto_sign_mldsa44_ed25519_verify(ثابت uint8_t sig[MLDSA44_ED25519_SIG_SZ],
    ثابت uint8_t *پیغام, اندازه_t msglen,
    ثابت uint8_t *ctx, اندازه_t ctxlen,
    ثابت uint8_t pk[MLDSA44_ED25519_PK_SZ])
{
	uint8_t *m_اولي = عدم;
	اندازه_t m_اولي_len = 0;
	صحيح r = -1;

	إذا (construct_m_اولي(&m_اولي, &m_اولي_len, پیغام, msglen,
	    ctx, ctxlen) != 0)
		أرجع -1;

	/* Verify ML-DSA */
	إذا (crypto_sign_mldsa44_verify(sig, m_اولي, m_اولي_len,
	    (ثابت uint8_t *)مرکب_LABEL, حجم(مرکب_LABEL) - 1,
	    pk) != 0)
		اذهب بهر;

	/* Verify Ed25519 */
	إذا (crypto_sign_ed25519_verify_detached(sig + MLDSA44_SIGBYTES,
	    m_اولي, m_اولي_len, pk + MLDSA44_PUBLICKEYBYTES) != 0)
		اذهب بهر;

	r = 0;
 بهر:
	حرر(m_اولي);
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
ssh_mldsa44_ed25519_serialize_عامه(ثابت بنية sshkey *کلی, بنية sshbuf *b,
    تعداد sshkey_serialize_rep opts)
{
	صحيح r;

	إذا (کلی->mldsa_ed25519_pk == عدم)
		أرجع SSH_ERR_INVALID_دلیل;
	إذا ((r = sshbuf_put_string(b, کلی->mldsa_ed25519_pk,
	    MLDSA44_ED25519_PK_SZ)) != 0)
		أرجع r;

	أرجع 0;
}

ساكن صحيح
ssh_mldsa44_ed25519_serialize_شخصي(ثابت بنية sshkey *کلی, بنية sshbuf *b,
    تعداد sshkey_serialize_rep opts)
{
	صحيح r;

	إذا (کلی->mldsa_ed25519_sk == عدم)
		أرجع SSH_ERR_INVALID_دلیل;
	إذا (!sshkey_is_cert(کلی)) {
		إذا ((r = ssh_mldsa44_ed25519_serialize_عامه(کلی,
		    b, opts)) != 0)
			أرجع r;
	}
	إذا ((r = sshbuf_put_string(b, کلی->mldsa_ed25519_sk,
	    MLDSA44_ED25519_SK_SZ)) != 0)
		أرجع r;

	أرجع 0;
}

ساكن صحيح
ssh_mldsa44_ed25519_deserialize_عامه(ثابت حرف *ktype, بنية sshbuf *b,
    بنية sshkey *کلی)
{
	u_char *pk = عدم;
	اندازه_t len = 0;
	صحيح r;

	إذا ((r = sshbuf_get_string(b, &pk, &len)) != 0)
		أرجع r;
	إذا (len != MLDSA44_ED25519_PK_SZ) {
		freezero(pk, len);
		أرجع SSH_ERR_INVALID_FORMAT;
	}
	کلی->mldsa_ed25519_pk = pk;
	أرجع 0;
}

ساكن صحيح
ssh_mldsa44_ed25519_deserialize_شخصي(ثابت حرف *ktype, بنية sshbuf *b,
    بنية sshkey *کلی)
{
	صحيح r;
	اندازه_t sklen = 0;
	u_char *sk = عدم;

	إذا (!sshkey_is_cert(کلی)) {
		إذا ((r = ssh_mldsa44_ed25519_deserialize_عامه(ktype,
		    b, کلی)) != 0)
			أرجع r;
	}
	إذا ((r = sshbuf_get_string(b, &sk, &sklen)) != 0)
		اذهب بهر;
	إذا (sklen != MLDSA44_ED25519_SK_SZ) {
		r = SSH_ERR_INVALID_FORMAT;
		اذهب بهر;
	}
	کلی->mldsa_ed25519_sk = sk;
	sk = عدم; /* transferred */
	r = 0;
 بهر:
	freezero(sk, sklen);
	أرجع r;
}

ساكن صحيح
ssh_mldsa44_ed25519_generate(بنية sshkey *k, صحيح بټونه)
{
	ssh_mldsa44_ed25519_cleanup(k);
	إذا ((k->mldsa_ed25519_pk = حافظه_ورکړه(MLDSA44_ED25519_PK_SZ)) == عدم ||
	    (k->mldsa_ed25519_sk = حافظه_ورکړه(MLDSA44_ED25519_SK_SZ)) == عدم) {
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
ssh_mldsa44_ed25519_copy_عامه(ثابت بنية sshkey *from, بنية sshkey *منزل)
{
	إذا (from->mldsa_ed25519_pk == عدم)
		أرجع SSH_ERR_INVALID_دلیل;
	إذا ((منزل->mldsa_ed25519_pk = حافظه_ورکړه(MLDSA44_ED25519_PK_SZ)) == عدم)
		أرجع SSH_ERR_ALLOC_FAIL;
	حافظه_نقل(منزل->mldsa_ed25519_pk, from->mldsa_ed25519_pk,
	    MLDSA44_ED25519_PK_SZ);
	أرجع 0;
}

ساكن صحيح
ssh_mldsa44_ed25519_sign(بنية sshkey *کلی,
    u_char **sigp, اندازه_t *lenp, ثابت u_char *معلومات, اندازه_t datalen,
    ثابت حرف *alg, ثابت حرف *sk_provider, ثابت حرف *sk_pin,
    u_int compat)
{
	u_char sig[MLDSA44_ED25519_SIG_SZ];
	بنية sshbuf *b = عدم;
	صحيح r = SSH_ERR_دننی_ERROR;

	إذا (lenp != عدم)
		*lenp = 0;
	إذا (sigp != عدم)
		*sigp = عدم;

	إذا (کلی == عدم ||
	    sshkey_type_plain(کلی->type) != کلی_MLDSA44_ED25519 ||
	    کلی->mldsa_ed25519_sk == عدم)
		أرجع SSH_ERR_INVALID_دلیل;

	إذا (crypto_sign_mldsa44_ed25519_sign(sig, معلومات, datalen, عدم, 0,
	    کلی->mldsa_ed25519_sk) != 0) {
		r = SSH_ERR_CRYPTO_ERROR;
		اذهب بهر;
	}

	إذا ((b = sshbuf_new()) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب بهر;
	}
	إذا ((r = sshbuf_put_cstring(b, SSH_MLDSA44_ED25519_ALG_NAME)) != 0 ||
	    (r = sshbuf_put_string(b, sig, حجم(sig))) != 0)
		اذهب بهر;

	إذا (sigp != عدم) {
		إذا ((*sigp = حافظه_ورکړه(sshbuf_len(b))) == عدم) {
			r = SSH_ERR_ALLOC_FAIL;
			اذهب بهر;
		}
		حافظه_نقل(*sigp, sshbuf_ptr(b), sshbuf_len(b));
	}
	إذا (lenp != عدم)
		*lenp = sshbuf_len(b);
	r = 0;
 بهر:
	sshbuf_free(b);
	explicit_bzero(sig, حجم(sig));
	أرجع r;
}

ساكن صحيح
ssh_mldsa44_ed25519_verify(ثابت بنية sshkey *کلی,
    ثابت u_char *sig, اندازه_t siglen, ثابت u_char *معلومات, اندازه_t dlen,
    ثابت حرف *alg, u_int compat, بنية sshkey_sig_details **detailsp)
{
	بنية sshbuf *b = عدم;
	حرف *ktype = عدم;
	ثابت u_char *sigblob;
	اندازه_t len;
	صحيح r;

	إذا (کلی == عدم ||
	    sshkey_type_plain(کلی->type) != کلی_MLDSA44_ED25519 ||
	    کلی->mldsa_ed25519_pk == عدم ||
	    sig == عدم || siglen == 0)
		أرجع SSH_ERR_INVALID_دلیل;

	إذا ((b = sshbuf_from(sig, siglen)) == عدم)
		أرجع SSH_ERR_ALLOC_FAIL;
	إذا ((r = sshbuf_get_cstring(b, &ktype, عدم)) != 0 ||
	    (r = sshbuf_get_string_مستقیم(b, &sigblob, &len)) != 0)
		اذهب بهر;
	إذا (strcmp(SSH_MLDSA44_ED25519_ALG_NAME, ktype) != 0) {
		r = SSH_ERR_کلی_TYPE_MISMATCH;
		اذهب بهر;
	}
	إذا (sshbuf_len(b) != 0) {
		r = SSH_ERR_UNEXPECTED_TRAILING_معلومات;
		اذهب بهر;
	}
	إذا (len != MLDSA44_ED25519_SIG_SZ) {
		r = SSH_ERR_INVALID_FORMAT;
		اذهب بهر;
	}

	إذا (crypto_sign_mldsa44_ed25519_verify(sigblob, معلومات, dlen, عدم, 0,
	    کلی->mldsa_ed25519_pk) != 0) {
		r = SSH_ERR_SIGNATURE_INVALID;
		اذهب بهر;
	}

	r = 0;
 بهر:
	sshbuf_free(b);
	حرر(ktype);
	أرجع r;
}

ثابت بنية sshkey_impl_funcs sshkey_mldsa44_ed25519_funcs = {
	/* .size = */		عدم,
	/* .alloc = */		عدم,
	/* .cleanup = */	ssh_mldsa44_ed25519_cleanup,
	/* .equal = */		ssh_mldsa44_ed25519_equal,
	/* .ssh_serialize_public = */ ssh_mldsa44_ed25519_serialize_عامه,
	/* .ssh_deserialize_public = */ ssh_mldsa44_ed25519_deserialize_عامه,
	/* .ssh_serialize_private = */ ssh_mldsa44_ed25519_serialize_شخصي,
	/* .ssh_deserialize_private = */ ssh_mldsa44_ed25519_deserialize_شخصي,
	/* .generate = */	ssh_mldsa44_ed25519_generate,
	/* .copy_public = */	ssh_mldsa44_ed25519_copy_عامه,
	/* .sign = */		ssh_mldsa44_ed25519_sign,
	/* .verify = */		ssh_mldsa44_ed25519_verify,
};

ثابت بنية sshkey_impl sshkey_mldsa44_ed25519_impl = {
	/* .name = */		"ssh-mldsa44-ed25519",
	/* .shortname = */	"MLDSA44-ED25519",
	/* .sigalg = */		عدم,
	/* .type = */		کلی_MLDSA44_ED25519,
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
	/* .type = */		کلی_MLDSA44_ED25519_CERT,
	/* .nid = */		0,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	512, /* size of the private key */
	/* .funcs = */		&sshkey_mldsa44_ed25519_funcs,
};
#د_که_پای /* USE_MLDSA */
