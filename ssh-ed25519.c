/* $OpenBSD: ssh-ed25519.c,v 1.24 2026/09/16 00:43:00 djm Exp $ */
/*
 * Copyright (c) 2013 Markus Friedl <markus@openbsd.org>
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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <limits.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "crypto_api.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdarg.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "log.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshbuf.h"
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHKEY_ਅੰਦਰੂਨੀ
#ਅਨ੍ਤਰ੍ਭਾਵ "sshkey.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssherr.h"

ਸਥਿਰ ਖਾਲੀ
ssh_ed25519_cleanup(ਬਣਤਰ sshkey *k)
{
	freezero(k->ed25519_pk, ED25519_PK_SZ);
	freezero(k->ed25519_sk, ED25519_SK_SZ);
	k->ed25519_pk = ਨਿਰਾ;
	k->ed25519_sk = ਨਿਰਾ;
}

ਸਥਿਰ ਪੂਰਨ
ssh_ed25519_equal(ਅਚਲ ਬਣਤਰ sshkey *a, ਅਚਲ ਬਣਤਰ sshkey *b)
{
	ਜੇ (a->ed25519_pk == ਨਿਰਾ || b->ed25519_pk == ਨਿਰਾ)
		ਵਾਪਸ 0;
	ਜੇ (memcmp(a->ed25519_pk, b->ed25519_pk, ED25519_PK_SZ) != 0)
		ਵਾਪਸ 0;
	ਵਾਪਸ 1;
}

ਸਥਿਰ ਪੂਰਨ
ssh_ed25519_serialize_ਜਨਤਕ(ਅਚਲ ਬਣਤਰ sshkey *ਕੁੰਜੀ, ਬਣਤਰ sshbuf *b,
    ਗਿਣਤੀ sshkey_serialize_rep opts)
{
	ਪੂਰਨ r;

	ਜੇ (ਕੁੰਜੀ->ed25519_pk == ਨਿਰਾ)
		ਵਾਪਸ SSH_ERR_INVALID_ਦਲੀਲ;
	ਜੇ ((r = sshbuf_put_string(b, ਕੁੰਜੀ->ed25519_pk, ED25519_PK_SZ)) != 0)
		ਵਾਪਸ r;

	ਵਾਪਸ 0;
}

ਸਥਿਰ ਪੂਰਨ
ssh_ed25519_serialize_ਨਿੱਜੀ(ਅਚਲ ਬਣਤਰ sshkey *ਕੁੰਜੀ, ਬਣਤਰ sshbuf *b,
    ਗਿਣਤੀ sshkey_serialize_rep opts)
{
	ਪੂਰਨ r;

	ਜੇ ((r = sshbuf_put_string(b, ਕੁੰਜੀ->ed25519_pk, ED25519_PK_SZ)) != 0 ||
	    (r = sshbuf_put_string(b, ਕੁੰਜੀ->ed25519_sk, ED25519_SK_SZ)) != 0)
		ਵਾਪਸ r;

	ਵਾਪਸ 0;
}

ਸਥਿਰ ਪੂਰਨ
ssh_ed25519_generate(ਬਣਤਰ sshkey *k, ਪੂਰਨ ਬਿੱਟ)
{
	ਜੇ ((k->ed25519_pk = ਸਮ੍ਰਿਤੀ_ਦਿਓ(ED25519_PK_SZ)) == ਨਿਰਾ ||
	    (k->ed25519_sk = ਸਮ੍ਰਿਤੀ_ਦਿਓ(ED25519_SK_SZ)) == ਨਿਰਾ)
		ਵਾਪਸ SSH_ERR_ALLOC_FAIL;
	ਜੇ (crypto_sign_ed25519_keypair(k->ed25519_pk, k->ed25519_sk) != 0)
		ਵਾਪਸ SSH_ERR_CRYPTO_ERROR;
	ਵਾਪਸ 0;
}

ਸਥਿਰ ਪੂਰਨ
ssh_ed25519_copy_ਜਨਤਕ(ਅਚਲ ਬਣਤਰ sshkey *from, ਬਣਤਰ sshkey *ਮੰਜ਼ਿਲ)
{
	ਜੇ (from->ed25519_pk == ਨਿਰਾ)
		ਵਾਪਸ 0; /* XXX SSH_ERR_INTERNAL_ERROR ? */
	ਜੇ ((ਮੰਜ਼ਿਲ->ed25519_pk = ਸਮ੍ਰਿਤੀ_ਦਿਓ(ED25519_PK_SZ)) == ਨਿਰਾ)
		ਵਾਪਸ SSH_ERR_ALLOC_FAIL;
	ਸਮ੍ਰਿਤੀ_ਨਕਲ(ਮੰਜ਼ਿਲ->ed25519_pk, from->ed25519_pk, ED25519_PK_SZ);
	ਵਾਪਸ 0;
}

ਸਥਿਰ ਪੂਰਨ
ssh_ed25519_deserialize_ਜਨਤਕ(ਅਚਲ ਅੱਖਰ *ktype, ਬਣਤਰ sshbuf *b,
    ਬਣਤਰ sshkey *ਕੁੰਜੀ)
{
	u_char *pk = ਨਿਰਾ;
	ਮਾਪ_t len = 0;
	ਪੂਰਨ r;

	ਜੇ ((r = sshbuf_get_string(b, &pk, &len)) != 0)
		ਵਾਪਸ r;
	ਜੇ (len != ED25519_PK_SZ) {
		freezero(pk, len);
		ਵਾਪਸ SSH_ERR_INVALID_FORMAT;
	}
	ਕੁੰਜੀ->ed25519_pk = pk;
	ਵਾਪਸ 0;
}

ਸਥਿਰ ਪੂਰਨ
ssh_ed25519_deserialize_ਨਿੱਜੀ(ਅਚਲ ਅੱਖਰ *ktype, ਬਣਤਰ sshbuf *b,
    ਬਣਤਰ sshkey *ਕੁੰਜੀ)
{
	ਪੂਰਨ r;
	ਮਾਪ_t sklen = 0;
	u_char *ed25519_sk = ਨਿਰਾ;

	ਜੇ ((r = ssh_ed25519_deserialize_ਜਨਤਕ(ਨਿਰਾ, b, ਕੁੰਜੀ)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	ਜੇ ((r = sshbuf_get_string(b, &ed25519_sk, &sklen)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	ਜੇ (sklen != ED25519_SK_SZ) {
		r = SSH_ERR_INVALID_FORMAT;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਕੁੰਜੀ->ed25519_sk = ed25519_sk;
	ed25519_sk = ਨਿਰਾ; /* transferred */
	/* success */
	r = 0;
 ਬਾਹਰਲਾ:
	freezero(ed25519_sk, sklen);
	ਵਾਪਸ r;
}

ਸਥਿਰ ਪੂਰਨ
ssh_ed25519_sign(ਬਣਤਰ sshkey *ਕੁੰਜੀ,
    u_char **sigp, ਮਾਪ_t *lenp,
    ਅਚਲ u_char *ਅੰਕੜੇ, ਮਾਪ_t datalen,
    ਅਚਲ ਅੱਖਰ *alg, ਅਚਲ ਅੱਖਰ *sk_provider, ਅਚਲ ਅੱਖਰ *sk_pin, u_int compat)
{
	u_char sig[crypto_sign_ed25519_ਬਾਈਟਾਂ];
	ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ ਲੰਮਾ siglen = 0;
	ਪੂਰਨ r, ret;

	ਜੇ (lenp != ਨਿਰਾ)
		*lenp = 0;
	ਜੇ (sigp != ਨਿਰਾ)
		*sigp = ਨਿਰਾ;

	ਜੇ (ਕੁੰਜੀ == ਨਿਰਾ ||
	    sshkey_type_plain(ਕੁੰਜੀ->type) != ਕੁੰਜੀ_ED25519 ||
	    ਕੁੰਜੀ->ed25519_sk == ਨਿਰਾ)
		ਵਾਪਸ SSH_ERR_INVALID_ਦਲੀਲ;

	ਜੇ ((ret = crypto_sign_ed25519_detached(sig, &siglen, ਅੰਕੜੇ, datalen,
	    ਕੁੰਜੀ->ed25519_sk)) != 0 || siglen != ਆਕਾਰ(sig)) {
		r = SSH_ERR_INVALID_ਦਲੀਲ; /* XXX better error? */
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((r = ssh_ed25519_encode_store_sig(sig, siglen,
	    sigp, lenp)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;

	/* success */
	r = 0;
 ਬਾਹਰਲਾ:
	explicit_bzero(sig, ਆਕਾਰ(sig));
	ਵਾਪਸ r;
}

ਪੂਰਨ
ssh_ed25519_encode_store_sig(ਅਚਲ u_char *sig, ਮਾਪ_t slen,
    u_char **sigp, ਮਾਪ_t *lenp)
{
	ਬਣਤਰ sshbuf *b = ਨਿਰਾ;
	ਪੂਰਨ r = -1;
	ਮਾਪ_t len;

	ਜੇ (lenp != ਨਿਰਾ)
		*lenp = 0;
	ਜੇ (sigp != ਨਿਰਾ)
		*sigp = ਨਿਰਾ;

	ਜੇ (slen != crypto_sign_ed25519_ਬਾਈਟਾਂ)
		ਵਾਪਸ SSH_ERR_INVALID_ਦਲੀਲ;

	/* encode signature */
	ਜੇ ((b = sshbuf_new()) == ਨਿਰਾ) {
		r = SSH_ERR_ALLOC_FAIL;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((r = sshbuf_put_cstring(b, "ssh-ed25519")) != 0 ||
	    (r = sshbuf_put_string(b, sig, slen)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	len = sshbuf_len(b);
	ਜੇ (sigp != ਨਿਰਾ) {
		ਜੇ ((*sigp = ਸਮ੍ਰਿਤੀ_ਦਿਓ(len)) == ਨਿਰਾ) {
			r = SSH_ERR_ALLOC_FAIL;
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		ਸਮ੍ਰਿਤੀ_ਨਕਲ(*sigp, sshbuf_ptr(b), len);
	}
	ਜੇ (lenp != ਨਿਰਾ)
		*lenp = len;
	/* success */
	r = 0;
 ਬਾਹਰਲਾ:
	sshbuf_free(b);
	ਵਾਪਸ r;
}

ਸਥਿਰ ਪੂਰਨ
ssh_ed25519_verify(ਅਚਲ ਬਣਤਰ sshkey *ਕੁੰਜੀ,
    ਅਚਲ u_char *sig, ਮਾਪ_t siglen,
    ਅਚਲ u_char *ਅੰਕੜੇ, ਮਾਪ_t dlen, ਅਚਲ ਅੱਖਰ *alg, u_int compat,
    ਬਣਤਰ sshkey_sig_details **detailsp)
{
	ਬਣਤਰ sshbuf *b = ਨਿਰਾ;
	ਅੱਖਰ *ktype = ਨਿਰਾ;
	ਅਚਲ u_char *sigblob;
	ਮਾਪ_t len;
	ਪੂਰਨ r, ret;

	ਜੇ (ਕੁੰਜੀ == ਨਿਰਾ ||
	    sshkey_type_plain(ਕੁੰਜੀ->type) != ਕੁੰਜੀ_ED25519 ||
	    ਕੁੰਜੀ->ed25519_pk == ਨਿਰਾ ||
	    sig == ਨਿਰਾ || siglen == 0)
		ਵਾਪਸ SSH_ERR_INVALID_ਦਲੀਲ;

	ਜੇ ((b = sshbuf_from(sig, siglen)) == ਨਿਰਾ)
		ਵਾਪਸ SSH_ERR_ALLOC_FAIL;
	ਜੇ ((r = sshbuf_get_cstring(b, &ktype, ਨਿਰਾ)) != 0 ||
	    (r = sshbuf_get_string_ਸਿੱਧਾ(b, &sigblob, &len)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	ਜੇ (strcmp("ssh-ed25519", ktype) != 0) {
		r = SSH_ERR_ਕੁੰਜੀ_TYPE_MISMATCH;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ (sshbuf_len(b) != 0) {
		r = SSH_ERR_UNEXPECTED_TRAILING_ਅੰਕੜੇ;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ (len != crypto_sign_ed25519_ਬਾਈਟਾਂ) {
		r = SSH_ERR_INVALID_FORMAT;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((ret = crypto_sign_ed25519_verify_detached(sigblob, ਅੰਕੜੇ, dlen,
	    ਕੁੰਜੀ->ed25519_pk)) != 0) {
		debug2_f("crypto_sign_ed25519_verify_detached failed: %d", ret);
	}
	ਜੇ (ret != 0) {
		r = SSH_ERR_SIGNATURE_INVALID;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	/* success */
	r = 0;
 ਬਾਹਰਲਾ:
	sshbuf_free(b);
	ਮੁਕਤ(ktype);
	ਵਾਪਸ r;
}

/* NB. not static; used by ED25519-SK */
ਅਚਲ ਬਣਤਰ sshkey_impl_funcs sshkey_ed25519_funcs = {
	/* .size = */		ਨਿਰਾ,
	/* .alloc = */		ਨਿਰਾ,
	/* .cleanup = */	ssh_ed25519_cleanup,
	/* .equal = */		ssh_ed25519_equal,
	/* .ssh_serialize_public = */ ssh_ed25519_serialize_ਜਨਤਕ,
	/* .ssh_deserialize_public = */ ssh_ed25519_deserialize_ਜਨਤਕ,
	/* .ssh_serialize_private = */ ssh_ed25519_serialize_ਨਿੱਜੀ,
	/* .ssh_deserialize_private = */ ssh_ed25519_deserialize_ਨਿੱਜੀ,
	/* .generate = */	ssh_ed25519_generate,
	/* .copy_public = */	ssh_ed25519_copy_ਜਨਤਕ,
	/* .sign = */		ssh_ed25519_sign,
	/* .verify = */		ssh_ed25519_verify,
};

ਅਚਲ ਬਣਤਰ sshkey_impl sshkey_ed25519_impl = {
	/* .name = */		"ssh-ed25519",
	/* .shortname = */	"ED25519",
	/* .sigalg = */		ਨਿਰਾ,
	/* .type = */		ਕੁੰਜੀ_ED25519,
	/* .nid = */		0,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	256,
	/* .funcs = */		&sshkey_ed25519_funcs,
};

ਅਚਲ ਬਣਤਰ sshkey_impl sshkey_ed25519_cert_impl = {
	/* .name = */		"ssh-ed25519-cert-v01@openssh.com",
	/* .shortname = */	"ED25519-CERT",
	/* .sigalg = */		ਨਿਰਾ,
	/* .type = */		ਕੁੰਜੀ_ED25519_CERT,
	/* .nid = */		0,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	256,
	/* .funcs = */		&sshkey_ed25519_funcs,
};
