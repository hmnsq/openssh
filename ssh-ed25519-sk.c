/* $OpenBSD: ssh-ed25519-sk.c,v 1.17 2026/09/16 00:43:00 djm Exp $ */
/*
 * Copyright (c) 2019 Markus Friedl.  All rights reserved.
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

/* #define DEBUG_SK 1 */

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHKEY_ਅੰਦਰੂਨੀ
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "crypto_api.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdarg.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "log.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshbuf.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshkey.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssherr.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "digest.h"

/* Reuse some ED25519 internals */
ਬਾਹਰੀ ਬਣਤਰ sshkey_impl_funcs sshkey_ed25519_funcs;

ਸਥਿਰ ਖਾਲੀ
ssh_ed25519_sk_cleanup(ਬਣਤਰ sshkey *k)
{
	sshkey_sk_cleanup(k);
	sshkey_ed25519_funcs.cleanup(k);
}

ਸਥਿਰ ਪੂਰਨ
ssh_ed25519_sk_equal(ਅਚਲ ਬਣਤਰ sshkey *a, ਅਚਲ ਬਣਤਰ sshkey *b)
{
	ਜੇ (!sshkey_sk_fields_equal(a, b))
		ਵਾਪਸ 0;
	ਜੇ (!sshkey_ed25519_funcs.equal(a, b))
		ਵਾਪਸ 0;
	ਵਾਪਸ 1;
}

ਸਥਿਰ ਪੂਰਨ
ssh_ed25519_sk_serialize_ਜਨਤਕ(ਅਚਲ ਬਣਤਰ sshkey *ਕੁੰਜੀ, ਬਣਤਰ sshbuf *b,
    ਗਿਣਤੀ sshkey_serialize_rep opts)
{
	ਪੂਰਨ r;

	ਜੇ ((r = sshkey_ed25519_funcs.serialize_ਜਨਤਕ(ਕੁੰਜੀ, b, opts)) != 0)
		ਵਾਪਸ r;
	ਜੇ ((r = sshkey_serialize_sk(ਕੁੰਜੀ, b)) != 0)
		ਵਾਪਸ r;

	ਵਾਪਸ 0;
}

ਸਥਿਰ ਪੂਰਨ
ssh_ed25519_sk_serialize_ਨਿੱਜੀ(ਅਚਲ ਬਣਤਰ sshkey *ਕੁੰਜੀ, ਬਣਤਰ sshbuf *b,
    ਗਿਣਤੀ sshkey_serialize_rep opts)
{
	ਪੂਰਨ r;

	ਜੇ ((r = sshkey_ed25519_funcs.serialize_ਜਨਤਕ(ਕੁੰਜੀ, b, opts)) != 0)
		ਵਾਪਸ r;
	ਜੇ ((r = sshkey_serialize_ਨਿੱਜੀ_sk(ਕੁੰਜੀ, b)) != 0)
		ਵਾਪਸ r;

	ਵਾਪਸ 0;
}

ਸਥਿਰ ਪੂਰਨ
ssh_ed25519_sk_copy_ਜਨਤਕ(ਅਚਲ ਬਣਤਰ sshkey *from, ਬਣਤਰ sshkey *ਮੰਜ਼ਿਲ)
{
	ਪੂਰਨ r;

	ਜੇ ((r = sshkey_ed25519_funcs.copy_ਜਨਤਕ(from, ਮੰਜ਼ਿਲ)) != 0)
		ਵਾਪਸ r;
	ਜੇ ((r = sshkey_copy_ਜਨਤਕ_sk(from, ਮੰਜ਼ਿਲ)) != 0)
		ਵਾਪਸ r;
	ਵਾਪਸ 0;
}

ਸਥਿਰ ਪੂਰਨ
ssh_ed25519_sk_deserialize_ਜਨਤਕ(ਅਚਲ ਅੱਖਰ *ktype, ਬਣਤਰ sshbuf *b,
    ਬਣਤਰ sshkey *ਕੁੰਜੀ)
{
	ਪੂਰਨ r;

	ਜੇ ((r = sshkey_ed25519_funcs.deserialize_ਜਨਤਕ(ktype, b, ਕੁੰਜੀ)) != 0)
		ਵਾਪਸ r;
	ਜੇ ((r = sshkey_deserialize_sk(b, ਕੁੰਜੀ)) != 0)
		ਵਾਪਸ r;
	ਵਾਪਸ 0;
}

ਸਥਿਰ ਪੂਰਨ
ssh_ed25519_sk_deserialize_ਨਿੱਜੀ(ਅਚਲ ਅੱਖਰ *ktype, ਬਣਤਰ sshbuf *b,
    ਬਣਤਰ sshkey *ਕੁੰਜੀ)
{
	ਪੂਰਨ r;

	ਜੇ ((r = sshkey_ed25519_funcs.deserialize_ਜਨਤਕ(ktype, b, ਕੁੰਜੀ)) != 0)
		ਵਾਪਸ r;
	ਜੇ ((r = sshkey_ਨਿੱਜੀ_deserialize_sk(b, ਕੁੰਜੀ)) != 0)
		ਵਾਪਸ r;
	ਵਾਪਸ 0;
}

ਸਥਿਰ ਪੂਰਨ
ssh_ed25519_sk_verify(ਅਚਲ ਬਣਤਰ sshkey *ਕੁੰਜੀ,
    ਅਚਲ u_char *sig, ਮਾਪ_t siglen,
    ਅਚਲ u_char *ਅੰਕੜੇ, ਮਾਪ_t dlen, ਅਚਲ ਅੱਖਰ *alg, u_int compat,
    ਬਣਤਰ sshkey_sig_details **detailsp)
{
	ਬਣਤਰ sshbuf *b = ਨਿਰਾ;
	ਬਣਤਰ sshbuf *encoded = ਨਿਰਾ;
	ਅੱਖਰ *ktype = ਨਿਰਾ;
	ਅਚਲ u_char *sigblob;
	u_char apphash[32];
	u_char msghash[32];
	u_char sig_flags;
	u_int sig_counter;
	ਮਾਪ_t len;
	ਪੂਰਨ r = SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;
	ਪੂਰਨ ret;
	ਬਣਤਰ sshkey_sig_details *details = ਨਿਰਾ;

	ਜੇ (detailsp != ਨਿਰਾ)
		*detailsp = ਨਿਰਾ;

	ਜੇ (ਕੁੰਜੀ == ਨਿਰਾ ||
	    sshkey_type_plain(ਕੁੰਜੀ->type) != ਕੁੰਜੀ_ED25519_SK ||
	    ਕੁੰਜੀ->ed25519_pk == ਨਿਰਾ ||
	    sig == ਨਿਰਾ || siglen == 0)
		ਵਾਪਸ SSH_ERR_INVALID_ਦਲੀਲ;

	ਜੇ ((b = sshbuf_from(sig, siglen)) == ਨਿਰਾ)
		ਵਾਪਸ SSH_ERR_ALLOC_FAIL;
	ਜੇ (sshbuf_get_cstring(b, &ktype, ਨਿਰਾ) != 0 ||
	    sshbuf_get_string_ਸਿੱਧਾ(b, &sigblob, &len) != 0 ||
	    sshbuf_get_u8(b, &sig_flags) != 0 ||
	    sshbuf_get_u32(b, &sig_counter) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ DEBUG_SK
	fprintf(stderr, "%s: data:\n", __func__);
	/* sshbuf_dump_data(data, datalen, stderr); */
	fprintf(stderr, "%s: sigblob:\n", __func__);
	sshbuf_dump_ਅੰਕੜੇ(sigblob, len, stderr);
	fprintf(stderr, "%s: sig_flags = 0x%02x, sig_counter = %u\n",
	    __func__, sig_flags, sig_counter);
#ਜੇ_ਅੰਤ
	ਜੇ (strcmp(sshkey_ssh_name_plain(ਕੁੰਜੀ), ktype) != 0) {
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
	ਜੇ (ssh_digest_ਸਮ੍ਰਿਤੀ(SSH_DIGEST_SHA256, ਕੁੰਜੀ->sk_application,
	    ਲੜੀ_ਲੰਬਾਈ(ਕੁੰਜੀ->sk_application), apphash, ਆਕਾਰ(apphash)) != 0 ||
	    ssh_digest_ਸਮ੍ਰਿਤੀ(SSH_DIGEST_SHA256, ਅੰਕੜੇ, dlen,
	    msghash, ਆਕਾਰ(msghash)) != 0) {
		r = SSH_ERR_INVALID_ਦਲੀਲ;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ DEBUG_SK
	fprintf(stderr, "%s: hashed application:\n", __func__);
	sshbuf_dump_ਅੰਕੜੇ(apphash, ਆਕਾਰ(apphash), stderr);
	fprintf(stderr, "%s: hashed message:\n", __func__);
	sshbuf_dump_ਅੰਕੜੇ(msghash, ਆਕਾਰ(msghash), stderr);
#ਜੇ_ਅੰਤ
	ਜੇ ((details = ਸਿਫਰ_ਸਮ੍ਰਿਤੀ_ਦਿਓ(1, ਆਕਾਰ(*details))) == ਨਿਰਾ) {
		r = SSH_ERR_ALLOC_FAIL;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	details->sk_counter = sig_counter;
	details->sk_flags = sig_flags;
	ਜੇ ((encoded = sshbuf_new()) == ਨਿਰਾ) {
		r = SSH_ERR_ALLOC_FAIL;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ (sshbuf_put(encoded, apphash, ਆਕਾਰ(apphash)) != 0 ||
	    sshbuf_put_u8(encoded, sig_flags) != 0 ||
	    sshbuf_put_u32(encoded, sig_counter) != 0 ||
	    sshbuf_put(encoded, msghash, ਆਕਾਰ(msghash)) != 0) {
		r = SSH_ERR_ALLOC_FAIL;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ DEBUG_SK
	fprintf(stderr, "%s: signed buf:\n", __func__);
	sshbuf_dump(encoded, stderr);
#ਜੇ_ਅੰਤ
	ਜੇ ((ret = crypto_sign_ed25519_verify_detached(sigblob,
	    sshbuf_ptr(encoded), sshbuf_len(encoded),
	    ਕੁੰਜੀ->ed25519_pk)) != 0) {
		debug2_f("crypto_sign_ed25519_verify_detached failed: %d", ret);
	}
	ਜੇ (ret != 0) {
		r = SSH_ERR_SIGNATURE_INVALID;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	/* success */
	r = 0;
	ਜੇ (detailsp != ਨਿਰਾ) {
		*detailsp = details;
		details = ਨਿਰਾ;
	}
 ਬਾਹਰਲਾ:
	sshkey_sig_details_free(details);
	sshbuf_free(b);
	sshbuf_free(encoded);
	ਮੁਕਤ(ktype);
	ਵਾਪਸ r;
}

ਸਥਿਰ ਅਚਲ ਬਣਤਰ sshkey_impl_funcs sshkey_ed25519_sk_funcs = {
	/* .size = */		ਨਿਰਾ,
	/* .alloc = */		ਨਿਰਾ,
	/* .cleanup = */	ssh_ed25519_sk_cleanup,
	/* .equal = */		ssh_ed25519_sk_equal,
	/* .ssh_serialize_public = */ ssh_ed25519_sk_serialize_ਜਨਤਕ,
	/* .ssh_deserialize_public = */ ssh_ed25519_sk_deserialize_ਜਨਤਕ,
	/* .ssh_serialize_private = */ ssh_ed25519_sk_serialize_ਨਿੱਜੀ,
	/* .ssh_deserialize_private = */ ssh_ed25519_sk_deserialize_ਨਿੱਜੀ,
	/* .generate = */	ਨਿਰਾ,
	/* .copy_public = */	ssh_ed25519_sk_copy_ਜਨਤਕ,
	/* .sign = */		ਨਿਰਾ,
	/* .verify = */		ssh_ed25519_sk_verify,
};

ਅਚਲ ਬਣਤਰ sshkey_impl sshkey_ed25519_sk_impl = {
	/* .name = */		"sk-ssh-ed25519@openssh.com",
	/* .shortname = */	"ED25519-SK",
	/* .sigalg = */		ਨਿਰਾ,
	/* .type = */		ਕੁੰਜੀ_ED25519_SK,
	/* .nid = */		0,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	256,
	/* .funcs = */		&sshkey_ed25519_sk_funcs,
};

ਅਚਲ ਬਣਤਰ sshkey_impl sshkey_ed25519_sk_cert_impl = {
	/* .name = */		"sk-ssh-ed25519-cert-v01@openssh.com",
	/* .shortname = */	"ED25519-SK-CERT",
	/* .sigalg = */		ਨਿਰਾ,
	/* .type = */		ਕੁੰਜੀ_ED25519_SK_CERT,
	/* .nid = */		0,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	256,
	/* .funcs = */		&sshkey_ed25519_sk_funcs,
};
