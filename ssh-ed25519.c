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

#അന്തര്ഭാവ "includes.h"

#അന്തര്ഭാവ <sys/types.h>
#അന്തര്ഭാവ <limits.h>

#അന്തര്ഭാവ "crypto_api.h"

#അന്തര്ഭാവ <string.h>
#അന്തര്ഭാവ <stdarg.h>

#അന്തര്ഭാവ "log.h"
#അന്തര്ഭാവ "sshbuf.h"
#define SSHKEY_INTERNAL
#അന്തര്ഭാവ "sshkey.h"
#അന്തര്ഭാവ "ssherr.h"

സ്ഥിതം ശൂന്യം
ssh_ed25519_cleanup(ഘടന sshkey *k)
{
	freezero(k->ed25519_pk, ED25519_PK_SZ);
	freezero(k->ed25519_sk, ED25519_SK_SZ);
	k->ed25519_pk = ശൂന്യ;
	k->ed25519_sk = ശൂന്യ;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
ssh_ed25519_equal(സ്ഥിരം ഘടന sshkey *a, സ്ഥിരം ഘടന sshkey *b)
{
	എങ്കിൽ (a->ed25519_pk == ശൂന്യ || b->ed25519_pk == ശൂന്യ)
		തിരികെ 0;
	എങ്കിൽ (memcmp(a->ed25519_pk, b->ed25519_pk, ED25519_PK_SZ) != 0)
		തിരികെ 0;
	തിരികെ 1;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
ssh_ed25519_serialize_public(സ്ഥിരം ഘടന sshkey *താക്കോൽ, ഘടന sshbuf *b,
    എണ്ണൽ sshkey_serialize_rep opts)
{
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ (താക്കോൽ->ed25519_pk == ശൂന്യ)
		തിരികെ SSH_ERR_INVALID_ARGUMENT;
	എങ്കിൽ ((r = sshbuf_put_string(b, താക്കോൽ->ed25519_pk, ED25519_PK_SZ)) != 0)
		തിരികെ r;

	തിരികെ 0;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
ssh_ed25519_serialize_private(സ്ഥിരം ഘടന sshkey *താക്കോൽ, ഘടന sshbuf *b,
    എണ്ണൽ sshkey_serialize_rep opts)
{
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ ((r = sshbuf_put_string(b, താക്കോൽ->ed25519_pk, ED25519_PK_SZ)) != 0 ||
	    (r = sshbuf_put_string(b, താക്കോൽ->ed25519_sk, ED25519_SK_SZ)) != 0)
		തിരികെ r;

	തിരികെ 0;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
ssh_ed25519_generate(ഘടന sshkey *k, പൂർണ്ണസംഖ്യ bits)
{
	എങ്കിൽ ((k->ed25519_pk = malloc(ED25519_PK_SZ)) == ശൂന്യ ||
	    (k->ed25519_sk = malloc(ED25519_SK_SZ)) == ശൂന്യ)
		തിരികെ SSH_ERR_ALLOC_FAIL;
	എങ്കിൽ (crypto_sign_ed25519_keypair(k->ed25519_pk, k->ed25519_sk) != 0)
		തിരികെ SSH_ERR_CRYPTO_ERROR;
	തിരികെ 0;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
ssh_ed25519_copy_public(സ്ഥിരം ഘടന sshkey *from, ഘടന sshkey *to)
{
	എങ്കിൽ (from->ed25519_pk == ശൂന്യ)
		തിരികെ 0; /* XXX SSH_ERR_INTERNAL_ERROR ? */
	എങ്കിൽ ((to->ed25519_pk = malloc(ED25519_PK_SZ)) == ശൂന്യ)
		തിരികെ SSH_ERR_ALLOC_FAIL;
	memcpy(to->ed25519_pk, from->ed25519_pk, ED25519_PK_SZ);
	തിരികെ 0;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
ssh_ed25519_deserialize_public(സ്ഥിരം അക്ഷരം *ktype, ഘടന sshbuf *b,
    ഘടന sshkey *താക്കോൽ)
{
	u_char *pk = ശൂന്യ;
	size_t len = 0;
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ ((r = sshbuf_get_string(b, &pk, &len)) != 0)
		തിരികെ r;
	എങ്കിൽ (len != ED25519_PK_SZ) {
		freezero(pk, len);
		തിരികെ SSH_ERR_INVALID_FORMAT;
	}
	താക്കോൽ->ed25519_pk = pk;
	തിരികെ 0;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
ssh_ed25519_deserialize_private(സ്ഥിരം അക്ഷരം *ktype, ഘടന sshbuf *b,
    ഘടന sshkey *താക്കോൽ)
{
	പൂർണ്ണസംഖ്യ r;
	size_t sklen = 0;
	u_char *ed25519_sk = ശൂന്യ;

	എങ്കിൽ ((r = ssh_ed25519_deserialize_public(ശൂന്യ, b, താക്കോൽ)) != 0)
		പോകുക out;
	എങ്കിൽ ((r = sshbuf_get_string(b, &ed25519_sk, &sklen)) != 0)
		പോകുക out;
	എങ്കിൽ (sklen != ED25519_SK_SZ) {
		r = SSH_ERR_INVALID_FORMAT;
		പോകുക out;
	}
	താക്കോൽ->ed25519_sk = ed25519_sk;
	ed25519_sk = ശൂന്യ; /* transferred */
	/* success */
	r = 0;
 out:
	freezero(ed25519_sk, sklen);
	തിരികെ r;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
ssh_ed25519_sign(ഘടന sshkey *താക്കോൽ,
    u_char **sigp, size_t *lenp,
    സ്ഥിരം u_char *data, size_t datalen,
    സ്ഥിരം അക്ഷരം *alg, സ്ഥിരം അക്ഷരം *sk_provider, സ്ഥിരം അക്ഷരം *sk_pin, u_int compat)
{
	u_char sig[crypto_sign_ed25519_BYTES];
	unsigned long long siglen = 0;
	പൂർണ്ണസംഖ്യ r, ret;

	എങ്കിൽ (lenp != ശൂന്യ)
		*lenp = 0;
	എങ്കിൽ (sigp != ശൂന്യ)
		*sigp = ശൂന്യ;

	എങ്കിൽ (താക്കോൽ == ശൂന്യ ||
	    sshkey_type_plain(താക്കോൽ->type) != താക്കോൽ_ED25519 ||
	    താക്കോൽ->ed25519_sk == ശൂന്യ)
		തിരികെ SSH_ERR_INVALID_ARGUMENT;

	എങ്കിൽ ((ret = crypto_sign_ed25519_detached(sig, &siglen, data, datalen,
	    താക്കോൽ->ed25519_sk)) != 0 || siglen != വലുപ്പം(sig)) {
		r = SSH_ERR_INVALID_ARGUMENT; /* XXX better error? */
		പോകുക out;
	}
	എങ്കിൽ ((r = ssh_ed25519_encode_store_sig(sig, siglen,
	    sigp, lenp)) != 0)
		പോകുക out;

	/* success */
	r = 0;
 out:
	explicit_bzero(sig, വലുപ്പം(sig));
	തിരികെ r;
}

പൂർണ്ണസംഖ്യ
ssh_ed25519_encode_store_sig(സ്ഥിരം u_char *sig, size_t slen,
    u_char **sigp, size_t *lenp)
{
	ഘടന sshbuf *b = ശൂന്യ;
	പൂർണ്ണസംഖ്യ r = -1;
	size_t len;

	എങ്കിൽ (lenp != ശൂന്യ)
		*lenp = 0;
	എങ്കിൽ (sigp != ശൂന്യ)
		*sigp = ശൂന്യ;

	എങ്കിൽ (slen != crypto_sign_ed25519_BYTES)
		തിരികെ SSH_ERR_INVALID_ARGUMENT;

	/* encode signature */
	എങ്കിൽ ((b = sshbuf_new()) == ശൂന്യ) {
		r = SSH_ERR_ALLOC_FAIL;
		പോകുക out;
	}
	എങ്കിൽ ((r = sshbuf_put_cstring(b, "ssh-ed25519")) != 0 ||
	    (r = sshbuf_put_string(b, sig, slen)) != 0)
		പോകുക out;
	len = sshbuf_len(b);
	എങ്കിൽ (sigp != ശൂന്യ) {
		എങ്കിൽ ((*sigp = malloc(len)) == ശൂന്യ) {
			r = SSH_ERR_ALLOC_FAIL;
			പോകുക out;
		}
		memcpy(*sigp, sshbuf_ptr(b), len);
	}
	എങ്കിൽ (lenp != ശൂന്യ)
		*lenp = len;
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	തിരികെ r;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
ssh_ed25519_verify(സ്ഥിരം ഘടന sshkey *താക്കോൽ,
    സ്ഥിരം u_char *sig, size_t siglen,
    സ്ഥിരം u_char *data, size_t dlen, സ്ഥിരം അക്ഷരം *alg, u_int compat,
    ഘടന sshkey_sig_details **detailsp)
{
	ഘടന sshbuf *b = ശൂന്യ;
	അക്ഷരം *ktype = ശൂന്യ;
	സ്ഥിരം u_char *sigblob;
	size_t len;
	പൂർണ്ണസംഖ്യ r, ret;

	എങ്കിൽ (താക്കോൽ == ശൂന്യ ||
	    sshkey_type_plain(താക്കോൽ->type) != താക്കോൽ_ED25519 ||
	    താക്കോൽ->ed25519_pk == ശൂന്യ ||
	    sig == ശൂന്യ || siglen == 0)
		തിരികെ SSH_ERR_INVALID_ARGUMENT;

	എങ്കിൽ ((b = sshbuf_from(sig, siglen)) == ശൂന്യ)
		തിരികെ SSH_ERR_ALLOC_FAIL;
	എങ്കിൽ ((r = sshbuf_get_cstring(b, &ktype, ശൂന്യ)) != 0 ||
	    (r = sshbuf_get_string_direct(b, &sigblob, &len)) != 0)
		പോകുക out;
	എങ്കിൽ (strcmp("ssh-ed25519", ktype) != 0) {
		r = SSH_ERR_താക്കോൽ_TYPE_MISMATCH;
		പോകുക out;
	}
	എങ്കിൽ (sshbuf_len(b) != 0) {
		r = SSH_ERR_UNEXPECTED_TRAILING_DATA;
		പോകുക out;
	}
	എങ്കിൽ (len != crypto_sign_ed25519_BYTES) {
		r = SSH_ERR_INVALID_FORMAT;
		പോകുക out;
	}
	എങ്കിൽ ((ret = crypto_sign_ed25519_verify_detached(sigblob, data, dlen,
	    താക്കോൽ->ed25519_pk)) != 0) {
		debug2_f("crypto_sign_ed25519_verify_detached failed: %d", ret);
	}
	എങ്കിൽ (ret != 0) {
		r = SSH_ERR_SIGNATURE_INVALID;
		പോകുക out;
	}
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	സ്വതന്ത്രം(ktype);
	തിരികെ r;
}

/* NB. not static; used by ED25519-SK */
സ്ഥിരം ഘടന sshkey_impl_funcs sshkey_ed25519_funcs = {
	/* .size = */		ശൂന്യ,
	/* .alloc = */		ശൂന്യ,
	/* .cleanup = */	ssh_ed25519_cleanup,
	/* .equal = */		ssh_ed25519_equal,
	/* .ssh_serialize_public = */ ssh_ed25519_serialize_public,
	/* .ssh_deserialize_public = */ ssh_ed25519_deserialize_public,
	/* .ssh_serialize_private = */ ssh_ed25519_serialize_private,
	/* .ssh_deserialize_private = */ ssh_ed25519_deserialize_private,
	/* .generate = */	ssh_ed25519_generate,
	/* .copy_public = */	ssh_ed25519_copy_public,
	/* .sign = */		ssh_ed25519_sign,
	/* .verify = */		ssh_ed25519_verify,
};

സ്ഥിരം ഘടന sshkey_impl sshkey_ed25519_impl = {
	/* .name = */		"ssh-ed25519",
	/* .shortname = */	"ED25519",
	/* .sigalg = */		ശൂന്യ,
	/* .type = */		താക്കോൽ_ED25519,
	/* .nid = */		0,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	256,
	/* .funcs = */		&sshkey_ed25519_funcs,
};

സ്ഥിരം ഘടന sshkey_impl sshkey_ed25519_cert_impl = {
	/* .name = */		"ssh-ed25519-cert-v01@openssh.com",
	/* .shortname = */	"ED25519-CERT",
	/* .sigalg = */		ശൂന്യ,
	/* .type = */		താക്കോൽ_ED25519_CERT,
	/* .nid = */		0,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	256,
	/* .funcs = */		&sshkey_ed25519_funcs,
};
