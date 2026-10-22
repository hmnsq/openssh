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

#അന്തര്ഭാവ "includes.h"

#define SSHKEY_INTERNAL
#അന്തര്ഭാവ <sys/types.h>

#അന്തര്ഭാവ "crypto_api.h"

#അന്തര്ഭാവ <string.h>
#അന്തര്ഭാവ <stdarg.h>

#അന്തര്ഭാവ "log.h"
#അന്തര്ഭാവ "sshbuf.h"
#അന്തര്ഭാവ "sshkey.h"
#അന്തര്ഭാവ "ssherr.h"
#അന്തര്ഭാവ "digest.h"

/* Reuse some ED25519 internals */
ബാഹ്യ ഘടന sshkey_impl_funcs sshkey_ed25519_funcs;

സ്ഥിതം ശൂന്യം
ssh_ed25519_sk_cleanup(ഘടന sshkey *k)
{
	sshkey_sk_cleanup(k);
	sshkey_ed25519_funcs.cleanup(k);
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
ssh_ed25519_sk_equal(സ്ഥിരം ഘടന sshkey *a, സ്ഥിരം ഘടന sshkey *b)
{
	എങ്കിൽ (!sshkey_sk_fields_equal(a, b))
		തിരികെ 0;
	എങ്കിൽ (!sshkey_ed25519_funcs.equal(a, b))
		തിരികെ 0;
	തിരികെ 1;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
ssh_ed25519_sk_serialize_public(സ്ഥിരം ഘടന sshkey *താക്കോൽ, ഘടന sshbuf *b,
    എണ്ണൽ sshkey_serialize_rep opts)
{
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ ((r = sshkey_ed25519_funcs.serialize_public(താക്കോൽ, b, opts)) != 0)
		തിരികെ r;
	എങ്കിൽ ((r = sshkey_serialize_sk(താക്കോൽ, b)) != 0)
		തിരികെ r;

	തിരികെ 0;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
ssh_ed25519_sk_serialize_private(സ്ഥിരം ഘടന sshkey *താക്കോൽ, ഘടന sshbuf *b,
    എണ്ണൽ sshkey_serialize_rep opts)
{
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ ((r = sshkey_ed25519_funcs.serialize_public(താക്കോൽ, b, opts)) != 0)
		തിരികെ r;
	എങ്കിൽ ((r = sshkey_serialize_private_sk(താക്കോൽ, b)) != 0)
		തിരികെ r;

	തിരികെ 0;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
ssh_ed25519_sk_copy_public(സ്ഥിരം ഘടന sshkey *from, ഘടന sshkey *to)
{
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ ((r = sshkey_ed25519_funcs.copy_public(from, to)) != 0)
		തിരികെ r;
	എങ്കിൽ ((r = sshkey_copy_public_sk(from, to)) != 0)
		തിരികെ r;
	തിരികെ 0;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
ssh_ed25519_sk_deserialize_public(സ്ഥിരം അക്ഷരം *ktype, ഘടന sshbuf *b,
    ഘടന sshkey *താക്കോൽ)
{
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ ((r = sshkey_ed25519_funcs.deserialize_public(ktype, b, താക്കോൽ)) != 0)
		തിരികെ r;
	എങ്കിൽ ((r = sshkey_deserialize_sk(b, താക്കോൽ)) != 0)
		തിരികെ r;
	തിരികെ 0;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
ssh_ed25519_sk_deserialize_private(സ്ഥിരം അക്ഷരം *ktype, ഘടന sshbuf *b,
    ഘടന sshkey *താക്കോൽ)
{
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ ((r = sshkey_ed25519_funcs.deserialize_public(ktype, b, താക്കോൽ)) != 0)
		തിരികെ r;
	എങ്കിൽ ((r = sshkey_private_deserialize_sk(b, താക്കോൽ)) != 0)
		തിരികെ r;
	തിരികെ 0;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
ssh_ed25519_sk_verify(സ്ഥിരം ഘടന sshkey *താക്കോൽ,
    സ്ഥിരം u_char *sig, size_t siglen,
    സ്ഥിരം u_char *data, size_t dlen, സ്ഥിരം അക്ഷരം *alg, u_int compat,
    ഘടന sshkey_sig_details **detailsp)
{
	ഘടന sshbuf *b = ശൂന്യ;
	ഘടന sshbuf *encoded = ശൂന്യ;
	അക്ഷരം *ktype = ശൂന്യ;
	സ്ഥിരം u_char *sigblob;
	u_char apphash[32];
	u_char msghash[32];
	u_char sig_flags;
	u_int sig_counter;
	size_t len;
	പൂർണ്ണസംഖ്യ r = SSH_ERR_INTERNAL_ERROR;
	പൂർണ്ണസംഖ്യ ret;
	ഘടന sshkey_sig_details *details = ശൂന്യ;

	എങ്കിൽ (detailsp != ശൂന്യ)
		*detailsp = ശൂന്യ;

	എങ്കിൽ (താക്കോൽ == ശൂന്യ ||
	    sshkey_type_plain(താക്കോൽ->type) != താക്കോൽ_ED25519_SK ||
	    താക്കോൽ->ed25519_pk == ശൂന്യ ||
	    sig == ശൂന്യ || siglen == 0)
		തിരികെ SSH_ERR_INVALID_ARGUMENT;

	എങ്കിൽ ((b = sshbuf_from(sig, siglen)) == ശൂന്യ)
		തിരികെ SSH_ERR_ALLOC_FAIL;
	എങ്കിൽ (sshbuf_get_cstring(b, &ktype, ശൂന്യ) != 0 ||
	    sshbuf_get_string_direct(b, &sigblob, &len) != 0 ||
	    sshbuf_get_u8(b, &sig_flags) != 0 ||
	    sshbuf_get_u32(b, &sig_counter) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		പോകുക out;
	}
#ifdef DEBUG_SK
	fprintf(stderr, "%s: data:\n", __func__);
	/* sshbuf_dump_data(data, datalen, stderr); */
	fprintf(stderr, "%s: sigblob:\n", __func__);
	sshbuf_dump_data(sigblob, len, stderr);
	fprintf(stderr, "%s: sig_flags = 0x%02x, sig_counter = %u\n",
	    __func__, sig_flags, sig_counter);
#endif
	എങ്കിൽ (strcmp(sshkey_ssh_name_plain(താക്കോൽ), ktype) != 0) {
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
	എങ്കിൽ (ssh_digest_memory(SSH_DIGEST_SHA256, താക്കോൽ->sk_application,
	    strlen(താക്കോൽ->sk_application), apphash, വലുപ്പം(apphash)) != 0 ||
	    ssh_digest_memory(SSH_DIGEST_SHA256, data, dlen,
	    msghash, വലുപ്പം(msghash)) != 0) {
		r = SSH_ERR_INVALID_ARGUMENT;
		പോകുക out;
	}
#ifdef DEBUG_SK
	fprintf(stderr, "%s: hashed application:\n", __func__);
	sshbuf_dump_data(apphash, വലുപ്പം(apphash), stderr);
	fprintf(stderr, "%s: hashed message:\n", __func__);
	sshbuf_dump_data(msghash, വലുപ്പം(msghash), stderr);
#endif
	എങ്കിൽ ((details = calloc(1, വലുപ്പം(*details))) == ശൂന്യ) {
		r = SSH_ERR_ALLOC_FAIL;
		പോകുക out;
	}
	details->sk_counter = sig_counter;
	details->sk_flags = sig_flags;
	എങ്കിൽ ((encoded = sshbuf_new()) == ശൂന്യ) {
		r = SSH_ERR_ALLOC_FAIL;
		പോകുക out;
	}
	എങ്കിൽ (sshbuf_put(encoded, apphash, വലുപ്പം(apphash)) != 0 ||
	    sshbuf_put_u8(encoded, sig_flags) != 0 ||
	    sshbuf_put_u32(encoded, sig_counter) != 0 ||
	    sshbuf_put(encoded, msghash, വലുപ്പം(msghash)) != 0) {
		r = SSH_ERR_ALLOC_FAIL;
		പോകുക out;
	}
#ifdef DEBUG_SK
	fprintf(stderr, "%s: signed buf:\n", __func__);
	sshbuf_dump(encoded, stderr);
#endif
	എങ്കിൽ ((ret = crypto_sign_ed25519_verify_detached(sigblob,
	    sshbuf_ptr(encoded), sshbuf_len(encoded),
	    താക്കോൽ->ed25519_pk)) != 0) {
		debug2_f("crypto_sign_ed25519_verify_detached failed: %d", ret);
	}
	എങ്കിൽ (ret != 0) {
		r = SSH_ERR_SIGNATURE_INVALID;
		പോകുക out;
	}
	/* success */
	r = 0;
	എങ്കിൽ (detailsp != ശൂന്യ) {
		*detailsp = details;
		details = ശൂന്യ;
	}
 out:
	sshkey_sig_details_free(details);
	sshbuf_free(b);
	sshbuf_free(encoded);
	സ്വതന്ത്രം(ktype);
	തിരികെ r;
}

സ്ഥിതം സ്ഥിരം ഘടന sshkey_impl_funcs sshkey_ed25519_sk_funcs = {
	/* .size = */		ശൂന്യ,
	/* .alloc = */		ശൂന്യ,
	/* .cleanup = */	ssh_ed25519_sk_cleanup,
	/* .equal = */		ssh_ed25519_sk_equal,
	/* .ssh_serialize_public = */ ssh_ed25519_sk_serialize_public,
	/* .ssh_deserialize_public = */ ssh_ed25519_sk_deserialize_public,
	/* .ssh_serialize_private = */ ssh_ed25519_sk_serialize_private,
	/* .ssh_deserialize_private = */ ssh_ed25519_sk_deserialize_private,
	/* .generate = */	ശൂന്യ,
	/* .copy_public = */	ssh_ed25519_sk_copy_public,
	/* .sign = */		ശൂന്യ,
	/* .verify = */		ssh_ed25519_sk_verify,
};

സ്ഥിരം ഘടന sshkey_impl sshkey_ed25519_sk_impl = {
	/* .name = */		"sk-ssh-ed25519@openssh.com",
	/* .shortname = */	"ED25519-SK",
	/* .sigalg = */		ശൂന്യ,
	/* .type = */		താക്കോൽ_ED25519_SK,
	/* .nid = */		0,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	256,
	/* .funcs = */		&sshkey_ed25519_sk_funcs,
};

സ്ഥിരം ഘടന sshkey_impl sshkey_ed25519_sk_cert_impl = {
	/* .name = */		"sk-ssh-ed25519-cert-v01@openssh.com",
	/* .shortname = */	"ED25519-SK-CERT",
	/* .sigalg = */		ശൂന്യ,
	/* .type = */		താക്കോൽ_ED25519_SK_CERT,
	/* .nid = */		0,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	256,
	/* .funcs = */		&sshkey_ed25519_sk_funcs,
};
