/* $OpenBSD: sshsig.c,v 1.41 2025/12/22 01:49:03 djm Exp $ */
/*
 * Copyright (c) 2019 Google LLC
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

#അന്തര്ഭാവ <stdio.h>
#അന്തര്ഭാവ <stdlib.h>
#അന്തര്ഭാവ <stdarg.h>
#അന്തര്ഭാവ <errno.h>
#അന്തര്ഭാവ <string.h>
#അന്തര്ഭാവ <unistd.h>

#അന്തര്ഭാവ "authfd.h"
#അന്തര്ഭാവ "authfile.h"
#അന്തര്ഭാവ "log.h"
#അന്തര്ഭാവ "misc.h"
#അന്തര്ഭാവ "sshbuf.h"
#അന്തര്ഭാവ "sshsig.h"
#അന്തര്ഭാവ "ssherr.h"
#അന്തര്ഭാവ "sshkey.h"
#അന്തര്ഭാവ "match.h"
#അന്തര്ഭാവ "digest.h"

#define SIG_VERSION		0x01
#define MAGIC_PREAMBLE		"SSHSIG"
#define MAGIC_PREAMBLE_LEN	(വലുപ്പം(MAGIC_PREAMBLE) - 1)
#define BEGIN_SIGNATURE		"-----BEGIN SSH SIGNATURE-----"
#define END_SIGNATURE		"-----END SSH SIGNATURE-----"
#define RSA_SIGN_ALG		"rsa-sha2-512"
#define RSA_SIGN_ALLOWED	"rsa-sha2-512,rsa-sha2-256"
#define HASHALG_DEFAULT		"sha512"
#define HASHALG_ALLOWED		"sha256,sha512"

പൂർണ്ണസംഖ്യ
sshsig_armor(സ്ഥിരം ഘടന sshbuf *blob, ഘടന sshbuf **out)
{
	ഘടന sshbuf *buf = ശൂന്യ;
	പൂർണ്ണസംഖ്യ r = SSH_ERR_INTERNAL_ERROR;

	*out = ശൂന്യ;

	എങ്കിൽ ((buf = sshbuf_new()) == ശൂന്യ) {
		error_f("sshbuf_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		പോകുക out;
	}

	എങ്കിൽ ((r = sshbuf_putf(buf, "%s\n", BEGIN_SIGNATURE)) != 0) {
		error_fr(r, "sshbuf_putf");
		പോകുക out;
	}

	എങ്കിൽ ((r = sshbuf_dtob64(blob, buf, 1)) != 0) {
		error_fr(r, "base64 encode signature");
		പോകുക out;
	}

	എങ്കിൽ ((r = sshbuf_put(buf, END_SIGNATURE,
	    വലുപ്പം(END_SIGNATURE)-1)) != 0 ||
	    (r = sshbuf_put_u8(buf, '\n')) != 0) {
		error_fr(r, "sshbuf_put");
		പോകുക out;
	}
	/* success */
	*out = buf;
	buf = ശൂന്യ; /* transferred */
	r = 0;
 out:
	sshbuf_free(buf);
	തിരികെ r;
}

പൂർണ്ണസംഖ്യ
sshsig_dearmor(ഘടന sshbuf *sig, ഘടന sshbuf **out)
{
	പൂർണ്ണസംഖ്യ r;
	size_t eoffset = 0;
	ഘടന sshbuf *buf = ശൂന്യ;
	ഘടന sshbuf *sbuf = ശൂന്യ;
	അക്ഷരം *b64 = ശൂന്യ;

	എങ്കിൽ ((sbuf = sshbuf_fromb(sig)) == ശൂന്യ) {
		error_f("sshbuf_fromb failed");
		തിരികെ SSH_ERR_ALLOC_FAIL;
	}

	/* Expect and consume preamble + lf/crlf */
	എങ്കിൽ ((r = sshbuf_cmp(sbuf, 0,
	    BEGIN_SIGNATURE, വലുപ്പം(BEGIN_SIGNATURE)-1)) != 0) {
		error("Couldn't parse signature: missing header");
		പോകുക done;
	}
	എങ്കിൽ ((r = sshbuf_consume(sbuf, വലുപ്പം(BEGIN_SIGNATURE)-1)) != 0) {
		error_fr(r, "consume");
		പോകുക done;
	}
	എങ്കിൽ ((r = sshbuf_cmp(sbuf, 0, "\r\n", 2)) == 0)
		eoffset = 2;
	അല്ലെങ്കിൽ എങ്കിൽ ((r = sshbuf_cmp(sbuf, 0, "\n", 1)) == 0)
		eoffset = 1;
	അല്ലെങ്കിൽ {
		r = SSH_ERR_INVALID_FORMAT;
		error_f("no header eol");
		പോകുക done;
	}
	എങ്കിൽ ((r = sshbuf_consume(sbuf, eoffset)) != 0) {
		error_fr(r, "consume eol");
		പോകുക done;
	}
	/* Find and consume lf + suffix (any prior cr would be ignored) */
	എങ്കിൽ ((r = sshbuf_find(sbuf, 0, "\n" END_SIGNATURE,
	    വലുപ്പം(END_SIGNATURE), &eoffset)) != 0) {
		error("Couldn't parse signature: missing footer");
		പോകുക done;
	}
	എങ്കിൽ ((r = sshbuf_consume_end(sbuf, sshbuf_len(sbuf)-eoffset)) != 0) {
		error_fr(r, "consume");
		പോകുക done;
	}

	എങ്കിൽ ((b64 = sshbuf_dup_string(sbuf)) == ശൂന്യ) {
		error_f("sshbuf_dup_string failed");
		r = SSH_ERR_ALLOC_FAIL;
		പോകുക done;
	}

	എങ്കിൽ ((buf = sshbuf_new()) == ശൂന്യ) {
		error_f("sshbuf_new() failed");
		r = SSH_ERR_ALLOC_FAIL;
		പോകുക done;
	}

	എങ്കിൽ ((r = sshbuf_b64tod(buf, b64)) != 0) {
		error_fr(r, "decode base64");
		പോകുക done;
	}

	/* success */
	*out = buf;
	r = 0;
	buf = ശൂന്യ; /* transferred */
done:
	sshbuf_free(buf);
	sshbuf_free(sbuf);
	സ്വതന്ത്രം(b64);
	തിരികെ r;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
sshsig_wrap_sign(ഘടന sshkey *താക്കോൽ, സ്ഥിരം അക്ഷരം *hashalg,
    സ്ഥിരം അക്ഷരം *sk_provider, സ്ഥിരം അക്ഷരം *sk_pin, സ്ഥിരം ഘടന sshbuf *h_message,
    സ്ഥിരം അക്ഷരം *sig_namespace, ഘടന sshbuf **out,
    sshsig_signer *signer, ശൂന്യം *signer_ctx)
{
	പൂർണ്ണസംഖ്യ r;
	size_t slen = 0;
	u_char *sig = ശൂന്യ;
	ഘടന sshbuf *blob = ശൂന്യ;
	ഘടന sshbuf *tosign = ശൂന്യ;
	സ്ഥിരം അക്ഷരം *sign_alg = ശൂന്യ;

	എങ്കിൽ ((tosign = sshbuf_new()) == ശൂന്യ ||
	    (blob = sshbuf_new()) == ശൂന്യ) {
		error_f("sshbuf_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		പോകുക done;
	}

	എങ്കിൽ ((r = sshbuf_put(tosign, MAGIC_PREAMBLE, MAGIC_PREAMBLE_LEN)) != 0 ||
	    (r = sshbuf_put_cstring(tosign, sig_namespace)) != 0 ||
	    (r = sshbuf_put_string(tosign, ശൂന്യ, 0)) != 0 || /* reserved */
	    (r = sshbuf_put_cstring(tosign, hashalg)) != 0 ||
	    (r = sshbuf_put_stringb(tosign, h_message)) != 0) {
		error_fr(r, "assemble message to sign");
		പോകുക done;
	}

	/* If using RSA keys then default to a good signature algorithm */
	എങ്കിൽ (sshkey_type_plain(താക്കോൽ->type) == താക്കോൽ_RSA) {
		sign_alg = RSA_SIGN_ALG;
		എങ്കിൽ (strcmp(hashalg, "sha256") == 0)
			sign_alg = "rsa-sha2-256";
		അല്ലെങ്കിൽ എങ്കിൽ (strcmp(hashalg, "sha512") == 0)
			sign_alg = "rsa-sha2-512";
	}

	എങ്കിൽ (signer != ശൂന്യ) {
		എങ്കിൽ ((r = signer(താക്കോൽ, &sig, &slen,
		    sshbuf_ptr(tosign), sshbuf_len(tosign),
		    sign_alg, sk_provider, sk_pin, 0, signer_ctx)) != 0) {
			error_r(r, "Couldn't sign message (signer)");
			പോകുക done;
		}
	} അല്ലെങ്കിൽ {
		എങ്കിൽ ((r = sshkey_sign(താക്കോൽ, &sig, &slen,
		    sshbuf_ptr(tosign), sshbuf_len(tosign),
		    sign_alg, sk_provider, sk_pin, 0)) != 0) {
			error_r(r, "Couldn't sign message");
			പോകുക done;
		}
	}

	എങ്കിൽ ((r = sshbuf_put(blob, MAGIC_PREAMBLE, MAGIC_PREAMBLE_LEN)) != 0 ||
	    (r = sshbuf_put_u32(blob, SIG_VERSION)) != 0 ||
	    (r = sshkey_puts(താക്കോൽ, blob)) != 0 ||
	    (r = sshbuf_put_cstring(blob, sig_namespace)) != 0 ||
	    (r = sshbuf_put_string(blob, ശൂന്യ, 0)) != 0 || /* reserved */
	    (r = sshbuf_put_cstring(blob, hashalg)) != 0 ||
	    (r = sshbuf_put_string(blob, sig, slen)) != 0) {
		error_fr(r, "assemble signature object");
		പോകുക done;
	}

	എങ്കിൽ (out != ശൂന്യ) {
		*out = blob;
		blob = ശൂന്യ;
	}
	r = 0;
done:
	സ്വതന്ത്രം(sig);
	sshbuf_free(blob);
	sshbuf_free(tosign);
	തിരികെ r;
}

/* Check preamble and version. */
സ്ഥിതം പൂർണ്ണസംഖ്യ
sshsig_parse_preamble(ഘടന sshbuf *buf)
{
	പൂർണ്ണസംഖ്യ r = SSH_ERR_INTERNAL_ERROR;
	uint32_t sversion;

	എങ്കിൽ ((r = sshbuf_cmp(buf, 0, MAGIC_PREAMBLE, MAGIC_PREAMBLE_LEN)) != 0 ||
	    (r = sshbuf_consume(buf, (വലുപ്പം(MAGIC_PREAMBLE)-1))) != 0 ||
	    (r = sshbuf_get_u32(buf, &sversion)) != 0) {
		error("Couldn't verify signature: invalid format");
		തിരികെ r;
	}

	എങ്കിൽ (sversion > SIG_VERSION) {
		error("Signature version %lu is larger than supported "
		    "version %u", (unsigned long)sversion, SIG_VERSION);
		തിരികെ SSH_ERR_INVALID_FORMAT;
	}
	തിരികെ 0;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
sshsig_check_hashalg(സ്ഥിരം അക്ഷരം *hashalg)
{
	എങ്കിൽ (hashalg == ശൂന്യ ||
	    match_pattern_list(hashalg, HASHALG_ALLOWED, 0) == 1)
		തിരികെ 0;
	error_f("unsupported hash algorithm \"%.100s\"", hashalg);
	തിരികെ SSH_ERR_SIGN_ALG_UNSUPPORTED;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
sshsig_peek_hashalg(ഘടന sshbuf *signature, അക്ഷരം **hashalgp)
{
	ഘടന sshbuf *buf = ശൂന്യ;
	അക്ഷരം *hashalg = ശൂന്യ;
	പൂർണ്ണസംഖ്യ r = SSH_ERR_INTERNAL_ERROR;

	എങ്കിൽ (hashalgp != ശൂന്യ)
		*hashalgp = ശൂന്യ;
	എങ്കിൽ ((buf = sshbuf_fromb(signature)) == ശൂന്യ)
		തിരികെ SSH_ERR_ALLOC_FAIL;
	എങ്കിൽ ((r = sshsig_parse_preamble(buf)) != 0)
		പോകുക done;
	എങ്കിൽ ((r = sshbuf_get_string_direct(buf, ശൂന്യ, ശൂന്യ)) != 0 ||
	    (r = sshbuf_get_string_direct(buf, ശൂന്യ, ശൂന്യ)) != 0 ||
	    (r = sshbuf_get_string(buf, ശൂന്യ, ശൂന്യ)) != 0 ||
	    (r = sshbuf_get_cstring(buf, &hashalg, ശൂന്യ)) != 0 ||
	    (r = sshbuf_get_string_direct(buf, ശൂന്യ, ശൂന്യ)) != 0) {
		error_fr(r, "parse signature object");
		പോകുക done;
	}

	/* success */
	r = 0;
	*hashalgp = hashalg;
	hashalg = ശൂന്യ;
 done:
	സ്വതന്ത്രം(hashalg);
	sshbuf_free(buf);
	തിരികെ r;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
sshsig_wrap_verify(ഘടന sshbuf *signature, സ്ഥിരം അക്ഷരം *hashalg,
    സ്ഥിരം ഘടന sshbuf *h_message, സ്ഥിരം അക്ഷരം *expect_namespace,
    ഘടന sshkey **sign_keyp, ഘടന sshkey_sig_details **sig_details)
{
	പൂർണ്ണസംഖ്യ r = SSH_ERR_INTERNAL_ERROR;
	ഘടന sshbuf *buf = ശൂന്യ, *toverify = ശൂന്യ;
	ഘടന sshkey *താക്കോൽ = ശൂന്യ;
	സ്ഥിരം u_char *sig;
	അക്ഷരം *got_namespace = ശൂന്യ, *sigtype = ശൂന്യ, *sig_hashalg = ശൂന്യ;
	size_t siglen;

	debug_f("verify message length %zu", sshbuf_len(h_message));
	എങ്കിൽ (sig_details != ശൂന്യ)
		*sig_details = ശൂന്യ;
	എങ്കിൽ (sign_keyp != ശൂന്യ)
		*sign_keyp = ശൂന്യ;

	എങ്കിൽ ((toverify = sshbuf_new()) == ശൂന്യ) {
		error_f("sshbuf_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		പോകുക done;
	}
	എങ്കിൽ ((r = sshbuf_put(toverify, MAGIC_PREAMBLE,
	    MAGIC_PREAMBLE_LEN)) != 0 ||
	    (r = sshbuf_put_cstring(toverify, expect_namespace)) != 0 ||
	    (r = sshbuf_put_string(toverify, ശൂന്യ, 0)) != 0 || /* reserved */
	    (r = sshbuf_put_cstring(toverify, hashalg)) != 0 ||
	    (r = sshbuf_put_stringb(toverify, h_message)) != 0) {
		error_fr(r, "assemble message to verify");
		പോകുക done;
	}

	എങ്കിൽ ((r = sshsig_parse_preamble(signature)) != 0)
		പോകുക done;

	എങ്കിൽ ((r = sshkey_froms(signature, &താക്കോൽ)) != 0 ||
	    (r = sshbuf_get_cstring(signature, &got_namespace, ശൂന്യ)) != 0 ||
	    (r = sshbuf_get_string(signature, ശൂന്യ, ശൂന്യ)) != 0 ||
	    (r = sshbuf_get_cstring(signature, &sig_hashalg, ശൂന്യ)) != 0 ||
	    (r = sshbuf_get_string_direct(signature, &sig, &siglen)) != 0) {
		error_fr(r, "parse signature object");
		പോകുക done;
	}

	എങ്കിൽ (sshbuf_len(signature) != 0) {
		error("Signature contains trailing data");
		r = SSH_ERR_INVALID_FORMAT;
		പോകുക done;
	}

	എങ്കിൽ (strcmp(expect_namespace, got_namespace) != 0) {
		error("Couldn't verify signature: namespace does not match");
		debug_f("expected namespace \"%s\" received \"%s\"",
		    expect_namespace, got_namespace);
		r = SSH_ERR_SIGNATURE_INVALID;
		പോകുക done;
	}
	എങ്കിൽ (strcmp(hashalg, sig_hashalg) != 0) {
		error("Couldn't verify signature: hash algorithm mismatch");
		debug_f("expected algorithm \"%s\" received \"%s\"",
		    hashalg, sig_hashalg);
		r = SSH_ERR_SIGNATURE_INVALID;
		പോകുക done;
	}
	/* Ensure that RSA keys use an acceptable signature algorithm */
	എങ്കിൽ (sshkey_type_plain(താക്കോൽ->type) == താക്കോൽ_RSA) {
		എങ്കിൽ ((r = sshkey_get_sigtype(sig, siglen, &sigtype)) != 0) {
			error_r(r, "Couldn't verify signature: unable to get "
			    "signature type");
			പോകുക done;
		}
		എങ്കിൽ (match_pattern_list(sigtype, RSA_SIGN_ALLOWED, 0) != 1) {
			error("Couldn't verify signature: unsupported RSA "
			    "signature algorithm %s", sigtype);
			r = SSH_ERR_SIGN_ALG_UNSUPPORTED;
			പോകുക done;
		}
	}
	എങ്കിൽ ((r = sshkey_verify(താക്കോൽ, sig, siglen, sshbuf_ptr(toverify),
	    sshbuf_len(toverify), ശൂന്യ, 0, sig_details)) != 0) {
		error_r(r, "Signature verification failed");
		പോകുക done;
	}

	/* success */
	r = 0;
	എങ്കിൽ (sign_keyp != ശൂന്യ) {
		*sign_keyp = താക്കോൽ;
		താക്കോൽ = ശൂന്യ; /* transferred */
	}
done:
	സ്വതന്ത്രം(got_namespace);
	സ്വതന്ത്രം(sigtype);
	സ്വതന്ത്രം(sig_hashalg);
	sshbuf_free(buf);
	sshbuf_free(toverify);
	sshkey_free(താക്കോൽ);
	തിരികെ r;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
hash_buffer(സ്ഥിരം ഘടന sshbuf *m, സ്ഥിരം അക്ഷരം *hashalg, ഘടന sshbuf **bp)
{
	അക്ഷരം *hex, hash[SSH_DIGEST_MAX_LENGTH];
	പൂർണ്ണസംഖ്യ alg, r = SSH_ERR_INTERNAL_ERROR;
	ഘടന sshbuf *b = ശൂന്യ;

	*bp = ശൂന്യ;
	memset(hash, 0, വലുപ്പം(hash));

	എങ്കിൽ ((r = sshsig_check_hashalg(hashalg)) != 0)
		തിരികെ r;
	എങ്കിൽ ((alg = ssh_digest_alg_by_name(hashalg)) == -1) {
		error_f("can't look up hash algorithm %s", hashalg);
		തിരികെ SSH_ERR_INTERNAL_ERROR;
	}
	എങ്കിൽ ((r = ssh_digest_buffer(alg, m, hash, വലുപ്പം(hash))) != 0) {
		error_fr(r, "ssh_digest_buffer");
		തിരികെ r;
	}
	എങ്കിൽ ((hex = tohex(hash, ssh_digest_bytes(alg))) != ശൂന്യ) {
		debug3_f("final hash: %s", hex);
		freezero(hex, strlen(hex));
	}
	എങ്കിൽ ((b = sshbuf_new()) == ശൂന്യ) {
		r = SSH_ERR_ALLOC_FAIL;
		പോകുക out;
	}
	എങ്കിൽ ((r = sshbuf_put(b, hash, ssh_digest_bytes(alg))) != 0) {
		error_fr(r, "sshbuf_put");
		പോകുക out;
	}
	*bp = b;
	b = ശൂന്യ; /* transferred */
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	explicit_bzero(hash, വലുപ്പം(hash));
	തിരികെ r;
}

പൂർണ്ണസംഖ്യ
sshsig_signb(ഘടന sshkey *താക്കോൽ, സ്ഥിരം അക്ഷരം *hashalg,
    സ്ഥിരം അക്ഷരം *sk_provider, സ്ഥിരം അക്ഷരം *sk_pin,
    സ്ഥിരം ഘടന sshbuf *message, സ്ഥിരം അക്ഷരം *sig_namespace,
    ഘടന sshbuf **out, sshsig_signer *signer, ശൂന്യം *signer_ctx)
{
	ഘടന sshbuf *b = ശൂന്യ;
	പൂർണ്ണസംഖ്യ r = SSH_ERR_INTERNAL_ERROR;

	എങ്കിൽ (hashalg == ശൂന്യ)
		hashalg = HASHALG_DEFAULT;
	എങ്കിൽ (out != ശൂന്യ)
		*out = ശൂന്യ;
	എങ്കിൽ ((r = hash_buffer(message, hashalg, &b)) != 0) {
		error_fr(r, "hash buffer");
		പോകുക out;
	}
	എങ്കിൽ ((r = sshsig_wrap_sign(താക്കോൽ, hashalg, sk_provider, sk_pin, b,
	    sig_namespace, out, signer, signer_ctx)) != 0)
		പോകുക out;
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	തിരികെ r;
}

പൂർണ്ണസംഖ്യ
sshsig_verifyb(ഘടന sshbuf *signature, സ്ഥിരം ഘടന sshbuf *message,
    സ്ഥിരം അക്ഷരം *expect_namespace, ഘടന sshkey **sign_keyp,
    ഘടന sshkey_sig_details **sig_details)
{
	ഘടന sshbuf *b = ശൂന്യ;
	പൂർണ്ണസംഖ്യ r = SSH_ERR_INTERNAL_ERROR;
	അക്ഷരം *hashalg = ശൂന്യ;

	എങ്കിൽ (sig_details != ശൂന്യ)
		*sig_details = ശൂന്യ;
	എങ്കിൽ (sign_keyp != ശൂന്യ)
		*sign_keyp = ശൂന്യ;
	എങ്കിൽ ((r = sshsig_peek_hashalg(signature, &hashalg)) != 0)
		തിരികെ r;
	debug_f("signature made with hash \"%s\"", hashalg);
	എങ്കിൽ ((r = hash_buffer(message, hashalg, &b)) != 0) {
		error_fr(r, "hash buffer");
		പോകുക out;
	}
	എങ്കിൽ ((r = sshsig_wrap_verify(signature, hashalg, b, expect_namespace,
	    sign_keyp, sig_details)) != 0)
		പോകുക out;
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	സ്വതന്ത്രം(hashalg);
	തിരികെ r;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
hash_file(പൂർണ്ണസംഖ്യ fd, സ്ഥിരം അക്ഷരം *hashalg, ഘടന sshbuf **bp)
{
	അക്ഷരം *hex, rbuf[8192], hash[SSH_DIGEST_MAX_LENGTH];
	ssize_t n, total = 0;
	ഘടന ssh_digest_ctx *ctx = ശൂന്യ;
	പൂർണ്ണസംഖ്യ alg, oerrno, r = SSH_ERR_INTERNAL_ERROR;
	ഘടന sshbuf *b = ശൂന്യ;

	*bp = ശൂന്യ;
	memset(hash, 0, വലുപ്പം(hash));

	എങ്കിൽ ((r = sshsig_check_hashalg(hashalg)) != 0)
		തിരികെ r;
	എങ്കിൽ ((alg = ssh_digest_alg_by_name(hashalg)) == -1) {
		error_f("can't look up hash algorithm %s", hashalg);
		തിരികെ SSH_ERR_INTERNAL_ERROR;
	}
	എങ്കിൽ ((ctx = ssh_digest_start(alg)) == ശൂന്യ) {
		error_f("ssh_digest_start failed");
		തിരികെ SSH_ERR_INTERNAL_ERROR;
	}
	വേണ്ടി (;;) {
		എങ്കിൽ ((n = പഠ(fd, rbuf, വലുപ്പം(rbuf))) == -1) {
			എങ്കിൽ (errno == EINTR || errno == EAGAIN)
				തുടരുക;
			oerrno = errno;
			error_f("read: %s", strerror(errno));
			errno = oerrno;
			r = SSH_ERR_SYSTEM_ERROR;
			പോകുക out;
		} അല്ലെങ്കിൽ എങ്കിൽ (n == 0) {
			debug2_f("hashed %zu bytes", total);
			നിർത്തുക; /* EOF */
		}
		total += (size_t)n;
		എങ്കിൽ ((r = ssh_digest_update(ctx, rbuf, (size_t)n)) != 0) {
			error_fr(r, "ssh_digest_update");
			പോകുക out;
		}
	}
	എങ്കിൽ ((r = ssh_digest_final(ctx, hash, വലുപ്പം(hash))) != 0) {
		error_fr(r, "ssh_digest_final");
		പോകുക out;
	}
	എങ്കിൽ ((hex = tohex(hash, ssh_digest_bytes(alg))) != ശൂന്യ) {
		debug3_f("final hash: %s", hex);
		freezero(hex, strlen(hex));
	}
	എങ്കിൽ ((b = sshbuf_new()) == ശൂന്യ) {
		r = SSH_ERR_ALLOC_FAIL;
		പോകുക out;
	}
	എങ്കിൽ ((r = sshbuf_put(b, hash, ssh_digest_bytes(alg))) != 0) {
		error_fr(r, "sshbuf_put");
		പോകുക out;
	}
	*bp = b;
	b = ശൂന്യ; /* transferred */
	/* success */
	r = 0;
 out:
	oerrno = errno;
	sshbuf_free(b);
	ssh_digest_free(ctx);
	explicit_bzero(hash, വലുപ്പം(hash));
	errno = oerrno;
	തിരികെ r;
}

പൂർണ്ണസംഖ്യ
sshsig_sign_fd(ഘടന sshkey *താക്കോൽ, സ്ഥിരം അക്ഷരം *hashalg,
    സ്ഥിരം അക്ഷരം *sk_provider, സ്ഥിരം അക്ഷരം *sk_pin,
    പൂർണ്ണസംഖ്യ fd, സ്ഥിരം അക്ഷരം *sig_namespace, ഘടന sshbuf **out,
    sshsig_signer *signer, ശൂന്യം *signer_ctx)
{
	ഘടന sshbuf *b = ശൂന്യ;
	പൂർണ്ണസംഖ്യ r = SSH_ERR_INTERNAL_ERROR;

	എങ്കിൽ (hashalg == ശൂന്യ)
		hashalg = HASHALG_DEFAULT;
	എങ്കിൽ (out != ശൂന്യ)
		*out = ശൂന്യ;
	എങ്കിൽ ((r = hash_file(fd, hashalg, &b)) != 0) {
		error_fr(r, "hash_file");
		തിരികെ r;
	}
	എങ്കിൽ ((r = sshsig_wrap_sign(താക്കോൽ, hashalg, sk_provider, sk_pin, b,
	    sig_namespace, out, signer, signer_ctx)) != 0)
		പോകുക out;
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	തിരികെ r;
}

പൂർണ്ണസംഖ്യ
sshsig_verify_fd(ഘടന sshbuf *signature, പൂർണ്ണസംഖ്യ fd,
    സ്ഥിരം അക്ഷരം *expect_namespace, ഘടന sshkey **sign_keyp,
    ഘടന sshkey_sig_details **sig_details)
{
	ഘടന sshbuf *b = ശൂന്യ;
	പൂർണ്ണസംഖ്യ r = SSH_ERR_INTERNAL_ERROR;
	അക്ഷരം *hashalg = ശൂന്യ;

	എങ്കിൽ (sig_details != ശൂന്യ)
		*sig_details = ശൂന്യ;
	എങ്കിൽ (sign_keyp != ശൂന്യ)
		*sign_keyp = ശൂന്യ;
	എങ്കിൽ ((r = sshsig_peek_hashalg(signature, &hashalg)) != 0)
		തിരികെ r;
	debug_f("signature made with hash \"%s\"", hashalg);
	എങ്കിൽ ((r = hash_file(fd, hashalg, &b)) != 0) {
		error_fr(r, "hash_file");
		പോകുക out;
	}
	എങ്കിൽ ((r = sshsig_wrap_verify(signature, hashalg, b, expect_namespace,
	    sign_keyp, sig_details)) != 0)
		പോകുക out;
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	സ്വതന്ത്രം(hashalg);
	തിരികെ r;
}

ഘടന sshsigopt {
	പൂർണ്ണസംഖ്യ ca;
	അക്ഷരം *namespaces;
	uint64_t valid_after, valid_before;
};

ഘടന sshsigopt *
sshsigopt_parse(സ്ഥിരം അക്ഷരം *opts, സ്ഥിരം അക്ഷരം *path, u_long linenum,
    സ്ഥിരം അക്ഷരം **errstrp)
{
	ഘടന sshsigopt *ret;
	പൂർണ്ണസംഖ്യ r;
	അക്ഷരം *opt;
	സ്ഥിരം അക്ഷരം *errstr = ശൂന്യ;

	എങ്കിൽ ((ret = calloc(1, വലുപ്പം(*ret))) == ശൂന്യ)
		തിരികെ ശൂന്യ;
	എങ്കിൽ (opts == ശൂന്യ || *opts == '\0')
		തിരികെ ret; /* Empty options yields empty options :) */

	ആകുമ്പോൾ (*opts && *opts != ' ' && *opts != '\t') {
		/* flag options */
		എങ്കിൽ ((r = opt_flag("cert-authority", 0, &opts)) != -1) {
			ret->ca = 1;
		} അല്ലെങ്കിൽ എങ്കിൽ (opt_match(&opts, "namespaces")) {
			എങ്കിൽ (ret->namespaces != ശൂന്യ) {
				errstr = "multiple \"namespaces\" clauses";
				പോകുക fail;
			}
			ret->namespaces = opt_dequote(&opts, &errstr);
			എങ്കിൽ (ret->namespaces == ശൂന്യ)
				പോകുക fail;
		} അല്ലെങ്കിൽ എങ്കിൽ (opt_match(&opts, "valid-after")) {
			എങ്കിൽ (ret->valid_after != 0) {
				errstr = "multiple \"valid-after\" clauses";
				പോകുക fail;
			}
			എങ്കിൽ ((opt = opt_dequote(&opts, &errstr)) == ശൂന്യ)
				പോകുക fail;
			എങ്കിൽ (parse_absolute_time(opt, &ret->valid_after) != 0 ||
			    ret->valid_after == 0) {
				സ്വതന്ത്രം(opt);
				errstr = "invalid \"valid-after\" time";
				പോകുക fail;
			}
			സ്വതന്ത്രം(opt);
		} അല്ലെങ്കിൽ എങ്കിൽ (opt_match(&opts, "valid-before")) {
			എങ്കിൽ (ret->valid_before != 0) {
				errstr = "multiple \"valid-before\" clauses";
				പോകുക fail;
			}
			എങ്കിൽ ((opt = opt_dequote(&opts, &errstr)) == ശൂന്യ)
				പോകുക fail;
			എങ്കിൽ (parse_absolute_time(opt, &ret->valid_before) != 0 ||
			    ret->valid_before == 0) {
				സ്വതന്ത്രം(opt);
				errstr = "invalid \"valid-before\" time";
				പോകുക fail;
			}
			സ്വതന്ത്രം(opt);
		}
		/*
		 * Skip the comma, and move to the next option
		 * (or break out if there are no more).
		 */
		എങ്കിൽ (*opts == '\0' || *opts == ' ' || *opts == '\t')
			നിർത്തുക;		/* End of options. */
		/* Anything other than a comma is an unknown option */
		എങ്കിൽ (*opts != ',') {
			errstr = "unknown key option";
			പോകുക fail;
		}
		opts++;
		എങ്കിൽ (*opts == '\0') {
			errstr = "unexpected end-of-options";
			പോകുക fail;
		}
	}
	/* final consistency check */
	എങ്കിൽ (ret->valid_after != 0 && ret->valid_before != 0 &&
	    ret->valid_before <= ret->valid_after) {
		errstr = "\"valid-before\" time is before \"valid-after\"";
		പോകുക fail;
	}
	/* success */
	തിരികെ ret;
 fail:
	എങ്കിൽ (errstrp != ശൂന്യ)
		*errstrp = errstr;
	sshsigopt_free(ret);
	തിരികെ ശൂന്യ;
}

ശൂന്യം
sshsigopt_free(ഘടന sshsigopt *opts)
{
	എങ്കിൽ (opts == ശൂന്യ)
		തിരികെ;
	സ്വതന്ത്രം(opts->namespaces);
	സ്വതന്ത്രം(opts);
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
parse_principals_താക്കോൽ_and_options(സ്ഥിരം അക്ഷരം *path, u_long linenum, അക്ഷരം *വരി,
    സ്ഥിരം അക്ഷരം *required_principal, അക്ഷരം **principalsp, ഘടന sshkey **keyp,
    ഘടന sshsigopt **sigoptsp)
{
	അക്ഷരം *opts = ശൂന്യ, *tmp, *cp, *principals = ശൂന്യ;
	സ്ഥിരം അക്ഷരം *reason = ശൂന്യ;
	ഘടന sshsigopt *sigopts = ശൂന്യ;
	ഘടന sshkey *താക്കോൽ = ശൂന്യ;
	പൂർണ്ണസംഖ്യ r = SSH_ERR_INTERNAL_ERROR;

	എങ്കിൽ (principalsp != ശൂന്യ)
		*principalsp = ശൂന്യ;
	എങ്കിൽ (sigoptsp != ശൂന്യ)
		*sigoptsp = ശൂന്യ;
	എങ്കിൽ (keyp != ശൂന്യ)
		*keyp = ശൂന്യ;

	cp = വരി;
	cp = cp + strspn(cp, " \t\n\r"); /* skip leading whitespace */
	എങ്കിൽ (*cp == '#' || *cp == '\0')
		തിരികെ SSH_ERR_താക്കോൽ_NOT_FOUND; /* blank or all-comment line */

	/* format: identity[,identity...] [option[,option...]] key */
	എങ്കിൽ ((tmp = strdelimw(&cp)) == ശൂന്യ || cp == ശൂന്യ) {
		error("%s:%lu: invalid line", path, linenum);
		r = SSH_ERR_INVALID_FORMAT;
		പോകുക out;
	}
	എങ്കിൽ ((principals = strdup(tmp)) == ശൂന്യ) {
		error_f("strdup failed");
		r = SSH_ERR_ALLOC_FAIL;
		പോകുക out;
	}
	/*
	 * Bail out early if we're looking for a particular principal and this
	 * line does not list it.
	 */
	എങ്കിൽ (required_principal != ശൂന്യ) {
		എങ്കിൽ (match_pattern_list(required_principal,
		    principals, 0) != 1) {
			/* principal didn't match */
			r = SSH_ERR_താക്കോൽ_NOT_FOUND;
			പോകുക out;
		}
		debug_f("%s:%lu: matched principal \"%s\"",
		    path, linenum, required_principal);
	}

	എങ്കിൽ ((താക്കോൽ = sshkey_new(താക്കോൽ_UNSPEC)) == ശൂന്യ) {
		error_f("sshkey_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		പോകുക out;
	}
	എങ്കിൽ (sshkey_read(താക്കോൽ, &cp) != 0) {
		/* no key? Check for options */
		opts = cp;
		എങ്കിൽ (sshkey_advance_past_options(&cp) != 0) {
			error("%s:%lu: invalid options", path, linenum);
			r = SSH_ERR_INVALID_FORMAT;
			പോകുക out;
		}
		എങ്കിൽ (cp == ശൂന്യ || *cp == '\0') {
			error("%s:%lu: missing key", path, linenum);
			r = SSH_ERR_INVALID_FORMAT;
			പോകുക out;
		}
		*cp++ = '\0';
		skip_space(&cp);
		എങ്കിൽ (sshkey_read(താക്കോൽ, &cp) != 0) {
			error("%s:%lu: invalid key", path, linenum);
			r = SSH_ERR_INVALID_FORMAT;
			പോകുക out;
		}
	}
	debug3("%s:%lu: options %s", path, linenum, opts == ശൂന്യ ? "" : opts);
	എങ്കിൽ ((sigopts = sshsigopt_parse(opts, path, linenum, &reason)) == ശൂന്യ) {
		error("%s:%lu: bad options: %s", path, linenum, reason);
		r = SSH_ERR_INVALID_FORMAT;
		പോകുക out;
	}
	/* success */
	എങ്കിൽ (principalsp != ശൂന്യ) {
		*principalsp = principals;
		principals = ശൂന്യ; /* transferred */
	}
	എങ്കിൽ (sigoptsp != ശൂന്യ) {
		*sigoptsp = sigopts;
		sigopts = ശൂന്യ; /* transferred */
	}
	എങ്കിൽ (keyp != ശൂന്യ) {
		*keyp = താക്കോൽ;
		താക്കോൽ = ശൂന്യ; /* transferred */
	}
	r = 0;
 out:
	സ്വതന്ത്രം(principals);
	sshsigopt_free(sigopts);
	sshkey_free(താക്കോൽ);
	തിരികെ r;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
cert_filter_principals(സ്ഥിരം അക്ഷരം *path, u_long linenum,
    അക്ഷരം **principalsp, സ്ഥിരം ഘടന sshkey *cert, uint64_t verify_time)
{
	അക്ഷരം *cp, *oprincipals, *principals;
	സ്ഥിരം അക്ഷരം *reason;
	ഘടന sshbuf *nprincipals;
	പൂർണ്ണസംഖ്യ r = SSH_ERR_INTERNAL_ERROR, success = 0;
	u_int i;

	oprincipals = principals = *principalsp;
	*principalsp = ശൂന്യ;

	എങ്കിൽ ((nprincipals = sshbuf_new()) == ശൂന്യ) {
		r = SSH_ERR_ALLOC_FAIL;
		പോകുക out;
	}

	ആകുമ്പോൾ ((cp = strsep(&principals, ",")) != ശൂന്യ && *cp != '\0') {
		/* Check certificate validity */
		എങ്കിൽ ((r = sshkey_cert_check_authority(cert, 0, 0, verify_time,
		    ശൂന്യ, &reason)) != 0) {
			debug("%s:%lu: principal \"%s\" not authorized: %s",
			    path, linenum, cp, reason);
			തുടരുക;
		}
		/* Return all matching principal names from the cert */
		വേണ്ടി (i = 0; i < cert->cert->nprincipals; i++) {
			എങ്കിൽ (match_pattern(cert->cert->principals[i], cp)) {
				എങ്കിൽ ((r = sshbuf_putf(nprincipals, "%s%s",
					sshbuf_len(nprincipals) != 0 ? "," : "",
						cert->cert->principals[i])) != 0) {
					error_f("buffer error");
					പോകുക out;
				}
			}
		}
	}
	എങ്കിൽ (sshbuf_len(nprincipals) == 0) {
		error("%s:%lu: no valid principals found", path, linenum);
		r = SSH_ERR_താക്കോൽ_CERT_INVALID;
		പോകുക out;
	}
	എങ്കിൽ ((principals = sshbuf_dup_string(nprincipals)) == ശൂന്യ) {
		error_f("buffer error");
		r = SSH_ERR_ALLOC_FAIL;
		പോകുക out;
	}
	/* success */
	success = 1;
	*principalsp = principals;
 out:
	sshbuf_free(nprincipals);
	സ്വതന്ത്രം(oprincipals);
	തിരികെ success ? 0 : r;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
check_allowed_താക്കോലുകൾ_വരി(സ്ഥിരം അക്ഷരം *path, u_long linenum, അക്ഷരം *വരി,
    സ്ഥിരം ഘടന sshkey *sign_താക്കോൽ, സ്ഥിരം അക്ഷരം *principal,
    സ്ഥിരം അക്ഷരം *sig_namespace, uint64_t verify_time, അക്ഷരം **principalsp)
{
	ഘടന sshkey *found_താക്കോൽ = ശൂന്യ;
	അക്ഷരം *principals = ശൂന്യ;
	പൂർണ്ണസംഖ്യ r, success = 0;
	സ്ഥിരം അക്ഷരം *reason = ശൂന്യ;
	ഘടന sshsigopt *sigopts = ശൂന്യ;
	അക്ഷരം tvalid[64], tverify[64];

	എങ്കിൽ (principalsp != ശൂന്യ)
		*principalsp = ശൂന്യ;

	/* Parse the line */
	എങ്കിൽ ((r = parse_principals_താക്കോൽ_and_options(path, linenum, വരി,
	    principal, &principals, &found_താക്കോൽ, &sigopts)) != 0) {
		/* error already logged */
		പോകുക done;
	}

	എങ്കിൽ (!sigopts->ca && sshkey_equal(found_താക്കോൽ, sign_താക്കോൽ)) {
		/* Exact match of key */
		debug("%s:%lu: matched key", path, linenum);
	} അല്ലെങ്കിൽ എങ്കിൽ (sigopts->ca && sshkey_is_cert(sign_താക്കോൽ) &&
	    sshkey_equal_public(sign_താക്കോൽ->cert->signature_താക്കോൽ, found_താക്കോൽ)) {
		എങ്കിൽ (principal) {
			/* Match certificate CA key with specified principal */
			എങ്കിൽ ((r = sshkey_cert_check_authority(sign_താക്കോൽ, 0, 0,
			    verify_time, principal, &reason)) != 0) {
				error("%s:%lu: certificate not authorized: %s",
				    path, linenum, reason);
				പോകുക done;
			}
			debug("%s:%lu: matched certificate CA key",
			    path, linenum);
		} അല്ലെങ്കിൽ {
			/* No principal specified - find all matching ones */
			എങ്കിൽ ((r = cert_filter_principals(path, linenum,
			    &principals, sign_താക്കോൽ, verify_time)) != 0) {
				/* error already displayed */
				debug_r(r, "%s:%lu: cert_filter_principals",
				    path, linenum);
				പോകുക done;
			}
			debug("%s:%lu: matched certificate CA key",
			    path, linenum);
		}
	} അല്ലെങ്കിൽ {
		/* Didn't match key */
		പോകുക done;
	}

	/* Check whether options preclude the use of this key */
	എങ്കിൽ (sigopts->namespaces != ശൂന്യ && sig_namespace != ശൂന്യ &&
	    match_pattern_list(sig_namespace, sigopts->namespaces, 0) != 1) {
		error("%s:%lu: key is not permitted for use in signature "
		    "namespace \"%s\"", path, linenum, sig_namespace);
		പോകുക done;
	}

	/* check key time validity */
	format_absolute_time((uint64_t)verify_time, tverify, വലുപ്പം(tverify));
	എങ്കിൽ (sigopts->valid_after != 0 &&
	    (uint64_t)verify_time < sigopts->valid_after) {
		format_absolute_time(sigopts->valid_after,
		    tvalid, വലുപ്പം(tvalid));
		error("%s:%lu: key is not yet valid: "
		    "verify time %s < valid-after %s", path, linenum,
		    tverify, tvalid);
		പോകുക done;
	}
	എങ്കിൽ (sigopts->valid_before != 0 &&
	    (uint64_t)verify_time > sigopts->valid_before) {
		format_absolute_time(sigopts->valid_before,
		    tvalid, വലുപ്പം(tvalid));
		error("%s:%lu: key has expired: "
		    "verify time %s > valid-before %s", path, linenum,
		    tverify, tvalid);
		പോകുക done;
	}
	success = 1;

 done:
	എങ്കിൽ (success && principalsp != ശൂന്യ) {
		*principalsp = principals;
		principals = ശൂന്യ; /* transferred */
	}
	സ്വതന്ത്രം(principals);
	sshkey_free(found_താക്കോൽ);
	sshsigopt_free(sigopts);
	തിരികെ success ? 0 : SSH_ERR_താക്കോൽ_NOT_FOUND;
}

പൂർണ്ണസംഖ്യ
sshsig_check_allowed_താക്കോലുകൾ(സ്ഥിരം അക്ഷരം *path, സ്ഥിരം ഘടന sshkey *sign_താക്കോൽ,
    സ്ഥിരം അക്ഷരം *principal, സ്ഥിരം അക്ഷരം *sig_namespace, uint64_t verify_time)
{
	FILE *f = ശൂന്യ;
	അക്ഷരം *വരി = ശൂന്യ;
	size_t linesize = 0;
	u_long linenum = 0;
	പൂർണ്ണസംഖ്യ r = SSH_ERR_താക്കോൽ_NOT_FOUND, oerrno;

	/* Check key and principal against file */
	എങ്കിൽ ((f = fopen(path, "r")) == ശൂന്യ) {
		oerrno = errno;
		error("Unable to open allowed keys file \"%s\": %s",
		    path, strerror(errno));
		errno = oerrno;
		തിരികെ SSH_ERR_SYSTEM_ERROR;
	}

	ആകുമ്പോൾ (getline(&വരി, &linesize, f) != -1) {
		linenum++;
		r = check_allowed_താക്കോലുകൾ_വരി(path, linenum, വരി, sign_താക്കോൽ,
		    principal, sig_namespace, verify_time, ശൂന്യ);
		സ്വതന്ത്രം(വരി);
		വരി = ശൂന്യ;
		linesize = 0;
		എങ്കിൽ (r == SSH_ERR_താക്കോൽ_NOT_FOUND)
			തുടരുക;
		അല്ലെങ്കിൽ എങ്കിൽ (r == 0) {
			/* success */
			fclose(f);
			തിരികെ 0;
		} അല്ലെങ്കിൽ
			നിർത്തുക;
	}
	/* Either we hit an error parsing or we simply didn't find the key */
	fclose(f);
	സ്വതന്ത്രം(വരി);
	തിരികെ r;
}

പൂർണ്ണസംഖ്യ
sshsig_find_principals(സ്ഥിരം അക്ഷരം *path, സ്ഥിരം ഘടന sshkey *sign_താക്കോൽ,
    uint64_t verify_time, അക്ഷരം **principals)
{
	FILE *f = ശൂന്യ;
	അക്ഷരം *വരി = ശൂന്യ;
	size_t linesize = 0;
	u_long linenum = 0;
	പൂർണ്ണസംഖ്യ r = SSH_ERR_താക്കോൽ_NOT_FOUND, oerrno;

	എങ്കിൽ ((f = fopen(path, "r")) == ശൂന്യ) {
		oerrno = errno;
		error("Unable to open allowed keys file \"%s\": %s",
		    path, strerror(errno));
		errno = oerrno;
		തിരികെ SSH_ERR_SYSTEM_ERROR;
	}

	ആകുമ്പോൾ (getline(&വരി, &linesize, f) != -1) {
		linenum++;
		r = check_allowed_താക്കോലുകൾ_വരി(path, linenum, വരി,
		    sign_താക്കോൽ, ശൂന്യ, ശൂന്യ, verify_time, principals);
		സ്വതന്ത്രം(വരി);
		വരി = ശൂന്യ;
		linesize = 0;
		എങ്കിൽ (r == SSH_ERR_താക്കോൽ_NOT_FOUND)
			തുടരുക;
		അല്ലെങ്കിൽ എങ്കിൽ (r == 0) {
			/* success */
			fclose(f);
			തിരികെ 0;
		} അല്ലെങ്കിൽ
			നിർത്തുക;
	}
	സ്വതന്ത്രം(വരി);
	/* Either we hit an error parsing or we simply didn't find the key */
	എങ്കിൽ (ferror(f) != 0) {
		oerrno = errno;
		fclose(f);
		error("Unable to read allowed keys file \"%s\": %s",
		    path, strerror(errno));
		errno = oerrno;
		തിരികെ SSH_ERR_SYSTEM_ERROR;
	}
	fclose(f);
	തിരികെ r;
}

പൂർണ്ണസംഖ്യ
sshsig_match_principals(സ്ഥിരം അക്ഷരം *path, സ്ഥിരം അക്ഷരം *principal,
    അക്ഷരം ***principalsp, size_t *nprincipalsp)
{
	FILE *f = ശൂന്യ;
	അക്ഷരം *found, *വരി = ശൂന്യ, **principals = ശൂന്യ, **tmp;
	size_t i, nprincipals = 0, linesize = 0;
	u_long linenum = 0;
	പൂർണ്ണസംഖ്യ oerrno = 0, r, ret = 0;

	എങ്കിൽ (principalsp != ശൂന്യ)
		*principalsp = ശൂന്യ;
	എങ്കിൽ (nprincipalsp != ശൂന്യ)
		*nprincipalsp = 0;

	/* Check key and principal against file */
	എങ്കിൽ ((f = fopen(path, "r")) == ശൂന്യ) {
		oerrno = errno;
		error("Unable to open allowed keys file \"%s\": %s",
		    path, strerror(errno));
		errno = oerrno;
		തിരികെ SSH_ERR_SYSTEM_ERROR;
	}

	ആകുമ്പോൾ (getline(&വരി, &linesize, f) != -1) {
		linenum++;
		/* Parse the line */
		എങ്കിൽ ((r = parse_principals_താക്കോൽ_and_options(path, linenum, വരി,
		    principal, &found, ശൂന്യ, ശൂന്യ)) != 0) {
			എങ്കിൽ (r == SSH_ERR_താക്കോൽ_NOT_FOUND)
				തുടരുക;
			ret = r;
			oerrno = errno;
			നിർത്തുക; /* unexpected error */
		}
		എങ്കിൽ ((tmp = recallocarray(principals, nprincipals,
		    nprincipals + 1, വലുപ്പം(*principals))) == ശൂന്യ) {
			ret = SSH_ERR_ALLOC_FAIL;
			സ്വതന്ത്രം(found);
			നിർത്തുക;
		}
		principals = tmp;
		principals[nprincipals++] = found; /* transferred */
		സ്വതന്ത്രം(വരി);
		വരി = ശൂന്യ;
		linesize = 0;
	}
	fclose(f);
	സ്വതന്ത്രം(വരി);

	എങ്കിൽ (ret == 0) {
		എങ്കിൽ (nprincipals == 0)
			ret = SSH_ERR_താക്കോൽ_NOT_FOUND;
		എങ്കിൽ (nprincipalsp != ശൂന്യ)
			*nprincipalsp = nprincipals;
		എങ്കിൽ (principalsp != ശൂന്യ) {
			*principalsp = principals;
			principals = ശൂന്യ; /* transferred */
			nprincipals = 0;
		}
	}

	വേണ്ടി (i = 0; i < nprincipals; i++)
		സ്വതന്ത്രം(principals[i]);
	സ്വതന്ത്രം(principals);

	errno = oerrno;
	തിരികെ ret;
}

പൂർണ്ണസംഖ്യ
sshsig_get_pubkey(ഘടന sshbuf *signature, ഘടന sshkey **pubkey)
{
	ഘടന sshkey *pk = ശൂന്യ;
	പൂർണ്ണസംഖ്യ r = SSH_ERR_SIGNATURE_INVALID;

	എങ്കിൽ (pubkey == ശൂന്യ)
		തിരികെ SSH_ERR_INTERNAL_ERROR;
	എങ്കിൽ ((r = sshsig_parse_preamble(signature)) != 0)
		തിരികെ r;
	എങ്കിൽ ((r = sshkey_froms(signature, &pk)) != 0)
		തിരികെ r;

	*pubkey = pk;
	pk = ശൂന്യ;
	തിരികെ 0;
}
