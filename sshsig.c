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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdarg.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <errno.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <unistd.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "authfd.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "authfile.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "log.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "misc.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshbuf.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshsig.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssherr.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshkey.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "match.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "digest.h"

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SIG_ਸੰਸਕਰਣ		0x01
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ MAGIC_PREAMBLE		"SSHSIG"
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ MAGIC_PREAMBLE_LEN	(ਆਕਾਰ(MAGIC_PREAMBLE) - 1)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ BEGIN_SIGNATURE		"-----BEGIN SSH SIGNATURE-----"
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ ਸਿਰਾ_SIGNATURE		"-----END SSH SIGNATURE-----"
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ RSA_SIGN_ALG		"rsa-sha2-512"
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ RSA_SIGN_ALLOWED	"rsa-sha2-512,rsa-sha2-256"
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ HASHALG_DEFAULT		"sha512"
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ HASHALG_ALLOWED		"sha256,sha512"

ਪੂਰਨ
sshsig_armor(ਅਚਲ ਬਣਤਰ sshbuf *blob, ਬਣਤਰ sshbuf **ਬਾਹਰਲਾ)
{
	ਬਣਤਰ sshbuf *buf = ਨਿਰਾ;
	ਪੂਰਨ r = SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;

	*ਬਾਹਰਲਾ = ਨਿਰਾ;

	ਜੇ ((buf = sshbuf_new()) == ਨਿਰਾ) {
		error_f("sshbuf_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		ਜਾਓ ਬਾਹਰਲਾ;
	}

	ਜੇ ((r = sshbuf_putf(buf, "%s\n", BEGIN_SIGNATURE)) != 0) {
		error_fr(r, "sshbuf_putf");
		ਜਾਓ ਬਾਹਰਲਾ;
	}

	ਜੇ ((r = sshbuf_dtob64(blob, buf, 1)) != 0) {
		error_fr(r, "base64 encode signature");
		ਜਾਓ ਬਾਹਰਲਾ;
	}

	ਜੇ ((r = sshbuf_put(buf, ਸਿਰਾ_SIGNATURE,
	    ਆਕਾਰ(ਸਿਰਾ_SIGNATURE)-1)) != 0 ||
	    (r = sshbuf_put_u8(buf, '\n')) != 0) {
		error_fr(r, "sshbuf_put");
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	/* success */
	*ਬਾਹਰਲਾ = buf;
	buf = ਨਿਰਾ; /* transferred */
	r = 0;
 ਬਾਹਰਲਾ:
	sshbuf_free(buf);
	ਵਾਪਸ r;
}

ਪੂਰਨ
sshsig_dearmor(ਬਣਤਰ sshbuf *sig, ਬਣਤਰ sshbuf **ਬਾਹਰਲਾ)
{
	ਪੂਰਨ r;
	ਮਾਪ_t eoffset = 0;
	ਬਣਤਰ sshbuf *buf = ਨਿਰਾ;
	ਬਣਤਰ sshbuf *sbuf = ਨਿਰਾ;
	ਅੱਖਰ *b64 = ਨਿਰਾ;

	ਜੇ ((sbuf = sshbuf_fromb(sig)) == ਨਿਰਾ) {
		error_f("sshbuf_fromb failed");
		ਵਾਪਸ SSH_ERR_ALLOC_FAIL;
	}

	/* Expect and consume preamble + lf/crlf */
	ਜੇ ((r = sshbuf_cmp(sbuf, 0,
	    BEGIN_SIGNATURE, ਆਕਾਰ(BEGIN_SIGNATURE)-1)) != 0) {
		error("Couldn't parse signature: missing header");
		ਜਾਓ ਪੂਰਾ;
	}
	ਜੇ ((r = sshbuf_consume(sbuf, ਆਕਾਰ(BEGIN_SIGNATURE)-1)) != 0) {
		error_fr(r, "consume");
		ਜਾਓ ਪੂਰਾ;
	}
	ਜੇ ((r = sshbuf_cmp(sbuf, 0, "\r\n", 2)) == 0)
		eoffset = 2;
	ਨਹੀਂਤਾਂ ਜੇ ((r = sshbuf_cmp(sbuf, 0, "\n", 1)) == 0)
		eoffset = 1;
	ਨਹੀਂਤਾਂ {
		r = SSH_ERR_INVALID_FORMAT;
		error_f("no header eol");
		ਜਾਓ ਪੂਰਾ;
	}
	ਜੇ ((r = sshbuf_consume(sbuf, eoffset)) != 0) {
		error_fr(r, "consume eol");
		ਜਾਓ ਪੂਰਾ;
	}
	/* Find and consume lf + suffix (any prior cr would be ignored) */
	ਜੇ ((r = sshbuf_ਲੱਭੋ(sbuf, 0, "\n" ਸਿਰਾ_SIGNATURE,
	    ਆਕਾਰ(ਸਿਰਾ_SIGNATURE), &eoffset)) != 0) {
		error("Couldn't parse signature: missing footer");
		ਜਾਓ ਪੂਰਾ;
	}
	ਜੇ ((r = sshbuf_consume_ਸਿਰਾ(sbuf, sshbuf_len(sbuf)-eoffset)) != 0) {
		error_fr(r, "consume");
		ਜਾਓ ਪੂਰਾ;
	}

	ਜੇ ((b64 = sshbuf_dup_string(sbuf)) == ਨਿਰਾ) {
		error_f("sshbuf_dup_string failed");
		r = SSH_ERR_ALLOC_FAIL;
		ਜਾਓ ਪੂਰਾ;
	}

	ਜੇ ((buf = sshbuf_new()) == ਨਿਰਾ) {
		error_f("sshbuf_new() failed");
		r = SSH_ERR_ALLOC_FAIL;
		ਜਾਓ ਪੂਰਾ;
	}

	ਜੇ ((r = sshbuf_b64tod(buf, b64)) != 0) {
		error_fr(r, "decode base64");
		ਜਾਓ ਪੂਰਾ;
	}

	/* success */
	*ਬਾਹਰਲਾ = buf;
	r = 0;
	buf = ਨਿਰਾ; /* transferred */
ਪੂਰਾ:
	sshbuf_free(buf);
	sshbuf_free(sbuf);
	ਮੁਕਤ(b64);
	ਵਾਪਸ r;
}

ਸਥਿਰ ਪੂਰਨ
sshsig_wrap_sign(ਬਣਤਰ sshkey *ਕੁੰਜੀ, ਅਚਲ ਅੱਖਰ *hashalg,
    ਅਚਲ ਅੱਖਰ *sk_provider, ਅਚਲ ਅੱਖਰ *sk_pin, ਅਚਲ ਬਣਤਰ sshbuf *h_ਸੁਨੇਹਾ,
    ਅਚਲ ਅੱਖਰ *sig_namespace, ਬਣਤਰ sshbuf **ਬਾਹਰਲਾ,
    sshsig_signer *signer, ਖਾਲੀ *signer_ctx)
{
	ਪੂਰਨ r;
	ਮਾਪ_t slen = 0;
	u_char *sig = ਨਿਰਾ;
	ਬਣਤਰ sshbuf *blob = ਨਿਰਾ;
	ਬਣਤਰ sshbuf *tosign = ਨਿਰਾ;
	ਅਚਲ ਅੱਖਰ *sign_alg = ਨਿਰਾ;

	ਜੇ ((tosign = sshbuf_new()) == ਨਿਰਾ ||
	    (blob = sshbuf_new()) == ਨਿਰਾ) {
		error_f("sshbuf_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		ਜਾਓ ਪੂਰਾ;
	}

	ਜੇ ((r = sshbuf_put(tosign, MAGIC_PREAMBLE, MAGIC_PREAMBLE_LEN)) != 0 ||
	    (r = sshbuf_put_cstring(tosign, sig_namespace)) != 0 ||
	    (r = sshbuf_put_string(tosign, ਨਿਰਾ, 0)) != 0 || /* reserved */
	    (r = sshbuf_put_cstring(tosign, hashalg)) != 0 ||
	    (r = sshbuf_put_stringb(tosign, h_ਸੁਨੇਹਾ)) != 0) {
		error_fr(r, "assemble message to sign");
		ਜਾਓ ਪੂਰਾ;
	}

	/* If using RSA keys then default to a good signature algorithm */
	ਜੇ (sshkey_type_plain(ਕੁੰਜੀ->type) == ਕੁੰਜੀ_RSA) {
		sign_alg = RSA_SIGN_ALG;
		ਜੇ (strcmp(hashalg, "sha256") == 0)
			sign_alg = "rsa-sha2-256";
		ਨਹੀਂਤਾਂ ਜੇ (strcmp(hashalg, "sha512") == 0)
			sign_alg = "rsa-sha2-512";
	}

	ਜੇ (signer != ਨਿਰਾ) {
		ਜੇ ((r = signer(ਕੁੰਜੀ, &sig, &slen,
		    sshbuf_ptr(tosign), sshbuf_len(tosign),
		    sign_alg, sk_provider, sk_pin, 0, signer_ctx)) != 0) {
			error_r(r, "Couldn't sign message (signer)");
			ਜਾਓ ਪੂਰਾ;
		}
	} ਨਹੀਂਤਾਂ {
		ਜੇ ((r = sshkey_sign(ਕੁੰਜੀ, &sig, &slen,
		    sshbuf_ptr(tosign), sshbuf_len(tosign),
		    sign_alg, sk_provider, sk_pin, 0)) != 0) {
			error_r(r, "Couldn't sign message");
			ਜਾਓ ਪੂਰਾ;
		}
	}

	ਜੇ ((r = sshbuf_put(blob, MAGIC_PREAMBLE, MAGIC_PREAMBLE_LEN)) != 0 ||
	    (r = sshbuf_put_u32(blob, SIG_ਸੰਸਕਰਣ)) != 0 ||
	    (r = sshkey_puts(ਕੁੰਜੀ, blob)) != 0 ||
	    (r = sshbuf_put_cstring(blob, sig_namespace)) != 0 ||
	    (r = sshbuf_put_string(blob, ਨਿਰਾ, 0)) != 0 || /* reserved */
	    (r = sshbuf_put_cstring(blob, hashalg)) != 0 ||
	    (r = sshbuf_put_string(blob, sig, slen)) != 0) {
		error_fr(r, "assemble signature object");
		ਜਾਓ ਪੂਰਾ;
	}

	ਜੇ (ਬਾਹਰਲਾ != ਨਿਰਾ) {
		*ਬਾਹਰਲਾ = blob;
		blob = ਨਿਰਾ;
	}
	r = 0;
ਪੂਰਾ:
	ਮੁਕਤ(sig);
	sshbuf_free(blob);
	sshbuf_free(tosign);
	ਵਾਪਸ r;
}

/* Check preamble and version. */
ਸਥਿਰ ਪੂਰਨ
sshsig_parse_preamble(ਬਣਤਰ sshbuf *buf)
{
	ਪੂਰਨ r = SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;
	uint32_t sversion;

	ਜੇ ((r = sshbuf_cmp(buf, 0, MAGIC_PREAMBLE, MAGIC_PREAMBLE_LEN)) != 0 ||
	    (r = sshbuf_consume(buf, (ਆਕਾਰ(MAGIC_PREAMBLE)-1))) != 0 ||
	    (r = sshbuf_get_u32(buf, &sversion)) != 0) {
		error("Couldn't verify signature: invalid format");
		ਵਾਪਸ r;
	}

	ਜੇ (sversion > SIG_ਸੰਸਕਰਣ) {
		error("Signature version %lu is larger than supported "
		    "version %u", (ਬਿਨਾਨਿਸ਼ਾਨੀ ਲੰਮਾ)sversion, SIG_ਸੰਸਕਰਣ);
		ਵਾਪਸ SSH_ERR_INVALID_FORMAT;
	}
	ਵਾਪਸ 0;
}

ਸਥਿਰ ਪੂਰਨ
sshsig_check_hashalg(ਅਚਲ ਅੱਖਰ *hashalg)
{
	ਜੇ (hashalg == ਨਿਰਾ ||
	    ਮੇਲ_ਨਮੂਨਾ_list(hashalg, HASHALG_ALLOWED, 0) == 1)
		ਵਾਪਸ 0;
	error_f("unsupported hash algorithm \"%.100s\"", hashalg);
	ਵਾਪਸ SSH_ERR_SIGN_ALG_UNSUPPORTED;
}

ਸਥਿਰ ਪੂਰਨ
sshsig_peek_hashalg(ਬਣਤਰ sshbuf *signature, ਅੱਖਰ **hashalgp)
{
	ਬਣਤਰ sshbuf *buf = ਨਿਰਾ;
	ਅੱਖਰ *hashalg = ਨਿਰਾ;
	ਪੂਰਨ r = SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;

	ਜੇ (hashalgp != ਨਿਰਾ)
		*hashalgp = ਨਿਰਾ;
	ਜੇ ((buf = sshbuf_fromb(signature)) == ਨਿਰਾ)
		ਵਾਪਸ SSH_ERR_ALLOC_FAIL;
	ਜੇ ((r = sshsig_parse_preamble(buf)) != 0)
		ਜਾਓ ਪੂਰਾ;
	ਜੇ ((r = sshbuf_get_string_ਸਿੱਧਾ(buf, ਨਿਰਾ, ਨਿਰਾ)) != 0 ||
	    (r = sshbuf_get_string_ਸਿੱਧਾ(buf, ਨਿਰਾ, ਨਿਰਾ)) != 0 ||
	    (r = sshbuf_get_string(buf, ਨਿਰਾ, ਨਿਰਾ)) != 0 ||
	    (r = sshbuf_get_cstring(buf, &hashalg, ਨਿਰਾ)) != 0 ||
	    (r = sshbuf_get_string_ਸਿੱਧਾ(buf, ਨਿਰਾ, ਨਿਰਾ)) != 0) {
		error_fr(r, "parse signature object");
		ਜਾਓ ਪੂਰਾ;
	}

	/* success */
	r = 0;
	*hashalgp = hashalg;
	hashalg = ਨਿਰਾ;
 ਪੂਰਾ:
	ਮੁਕਤ(hashalg);
	sshbuf_free(buf);
	ਵਾਪਸ r;
}

ਸਥਿਰ ਪੂਰਨ
sshsig_wrap_verify(ਬਣਤਰ sshbuf *signature, ਅਚਲ ਅੱਖਰ *hashalg,
    ਅਚਲ ਬਣਤਰ sshbuf *h_ਸੁਨੇਹਾ, ਅਚਲ ਅੱਖਰ *expect_namespace,
    ਬਣਤਰ sshkey **sign_keyp, ਬਣਤਰ sshkey_sig_details **sig_details)
{
	ਪੂਰਨ r = SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;
	ਬਣਤਰ sshbuf *buf = ਨਿਰਾ, *toverify = ਨਿਰਾ;
	ਬਣਤਰ sshkey *ਕੁੰਜੀ = ਨਿਰਾ;
	ਅਚਲ u_char *sig;
	ਅੱਖਰ *got_namespace = ਨਿਰਾ, *sigtype = ਨਿਰਾ, *sig_hashalg = ਨਿਰਾ;
	ਮਾਪ_t siglen;

	debug_f("verify message length %zu", sshbuf_len(h_ਸੁਨੇਹਾ));
	ਜੇ (sig_details != ਨਿਰਾ)
		*sig_details = ਨਿਰਾ;
	ਜੇ (sign_keyp != ਨਿਰਾ)
		*sign_keyp = ਨਿਰਾ;

	ਜੇ ((toverify = sshbuf_new()) == ਨਿਰਾ) {
		error_f("sshbuf_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		ਜਾਓ ਪੂਰਾ;
	}
	ਜੇ ((r = sshbuf_put(toverify, MAGIC_PREAMBLE,
	    MAGIC_PREAMBLE_LEN)) != 0 ||
	    (r = sshbuf_put_cstring(toverify, expect_namespace)) != 0 ||
	    (r = sshbuf_put_string(toverify, ਨਿਰਾ, 0)) != 0 || /* reserved */
	    (r = sshbuf_put_cstring(toverify, hashalg)) != 0 ||
	    (r = sshbuf_put_stringb(toverify, h_ਸੁਨੇਹਾ)) != 0) {
		error_fr(r, "assemble message to verify");
		ਜਾਓ ਪੂਰਾ;
	}

	ਜੇ ((r = sshsig_parse_preamble(signature)) != 0)
		ਜਾਓ ਪੂਰਾ;

	ਜੇ ((r = sshkey_froms(signature, &ਕੁੰਜੀ)) != 0 ||
	    (r = sshbuf_get_cstring(signature, &got_namespace, ਨਿਰਾ)) != 0 ||
	    (r = sshbuf_get_string(signature, ਨਿਰਾ, ਨਿਰਾ)) != 0 ||
	    (r = sshbuf_get_cstring(signature, &sig_hashalg, ਨਿਰਾ)) != 0 ||
	    (r = sshbuf_get_string_ਸਿੱਧਾ(signature, &sig, &siglen)) != 0) {
		error_fr(r, "parse signature object");
		ਜਾਓ ਪੂਰਾ;
	}

	ਜੇ (sshbuf_len(signature) != 0) {
		error("Signature contains trailing data");
		r = SSH_ERR_INVALID_FORMAT;
		ਜਾਓ ਪੂਰਾ;
	}

	ਜੇ (strcmp(expect_namespace, got_namespace) != 0) {
		error("Couldn't verify signature: namespace does not match");
		debug_f("expected namespace \"%s\" received \"%s\"",
		    expect_namespace, got_namespace);
		r = SSH_ERR_SIGNATURE_INVALID;
		ਜਾਓ ਪੂਰਾ;
	}
	ਜੇ (strcmp(hashalg, sig_hashalg) != 0) {
		error("Couldn't verify signature: hash algorithm mismatch");
		debug_f("expected algorithm \"%s\" received \"%s\"",
		    hashalg, sig_hashalg);
		r = SSH_ERR_SIGNATURE_INVALID;
		ਜਾਓ ਪੂਰਾ;
	}
	/* Ensure that RSA keys use an acceptable signature algorithm */
	ਜੇ (sshkey_type_plain(ਕੁੰਜੀ->type) == ਕੁੰਜੀ_RSA) {
		ਜੇ ((r = sshkey_get_sigtype(sig, siglen, &sigtype)) != 0) {
			error_r(r, "Couldn't verify signature: unable to get "
			    "signature type");
			ਜਾਓ ਪੂਰਾ;
		}
		ਜੇ (ਮੇਲ_ਨਮੂਨਾ_list(sigtype, RSA_SIGN_ALLOWED, 0) != 1) {
			error("Couldn't verify signature: unsupported RSA "
			    "signature algorithm %s", sigtype);
			r = SSH_ERR_SIGN_ALG_UNSUPPORTED;
			ਜਾਓ ਪੂਰਾ;
		}
	}
	ਜੇ ((r = sshkey_verify(ਕੁੰਜੀ, sig, siglen, sshbuf_ptr(toverify),
	    sshbuf_len(toverify), ਨਿਰਾ, 0, sig_details)) != 0) {
		error_r(r, "Signature verification failed");
		ਜਾਓ ਪੂਰਾ;
	}

	/* success */
	r = 0;
	ਜੇ (sign_keyp != ਨਿਰਾ) {
		*sign_keyp = ਕੁੰਜੀ;
		ਕੁੰਜੀ = ਨਿਰਾ; /* transferred */
	}
ਪੂਰਾ:
	ਮੁਕਤ(got_namespace);
	ਮੁਕਤ(sigtype);
	ਮੁਕਤ(sig_hashalg);
	sshbuf_free(buf);
	sshbuf_free(toverify);
	sshkey_free(ਕੁੰਜੀ);
	ਵਾਪਸ r;
}

ਸਥਿਰ ਪੂਰਨ
hash_ਬਫਰ(ਅਚਲ ਬਣਤਰ sshbuf *m, ਅਚਲ ਅੱਖਰ *hashalg, ਬਣਤਰ sshbuf **bp)
{
	ਅੱਖਰ *hex, hash[SSH_DIGEST_MAX_ਲੰਮਾਈ];
	ਪੂਰਨ alg, r = SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;
	ਬਣਤਰ sshbuf *b = ਨਿਰਾ;

	*bp = ਨਿਰਾ;
	memset(hash, 0, ਆਕਾਰ(hash));

	ਜੇ ((r = sshsig_check_hashalg(hashalg)) != 0)
		ਵਾਪਸ r;
	ਜੇ ((alg = ssh_digest_alg_by_name(hashalg)) == -1) {
		error_f("can't look up hash algorithm %s", hashalg);
		ਵਾਪਸ SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;
	}
	ਜੇ ((r = ssh_digest_ਬਫਰ(alg, m, hash, ਆਕਾਰ(hash))) != 0) {
		error_fr(r, "ssh_digest_buffer");
		ਵਾਪਸ r;
	}
	ਜੇ ((hex = tohex(hash, ssh_digest_ਬਾਈਟਾਂ(alg))) != ਨਿਰਾ) {
		debug3_f("final hash: %s", hex);
		freezero(hex, ਲੜੀ_ਲੰਬਾਈ(hex));
	}
	ਜੇ ((b = sshbuf_new()) == ਨਿਰਾ) {
		r = SSH_ERR_ALLOC_FAIL;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((r = sshbuf_put(b, hash, ssh_digest_ਬਾਈਟਾਂ(alg))) != 0) {
		error_fr(r, "sshbuf_put");
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	*bp = b;
	b = ਨਿਰਾ; /* transferred */
	/* success */
	r = 0;
 ਬਾਹਰਲਾ:
	sshbuf_free(b);
	explicit_bzero(hash, ਆਕਾਰ(hash));
	ਵਾਪਸ r;
}

ਪੂਰਨ
sshsig_signb(ਬਣਤਰ sshkey *ਕੁੰਜੀ, ਅਚਲ ਅੱਖਰ *hashalg,
    ਅਚਲ ਅੱਖਰ *sk_provider, ਅਚਲ ਅੱਖਰ *sk_pin,
    ਅਚਲ ਬਣਤਰ sshbuf *ਸੁਨੇਹਾ_2, ਅਚਲ ਅੱਖਰ *sig_namespace,
    ਬਣਤਰ sshbuf **ਬਾਹਰਲਾ, sshsig_signer *signer, ਖਾਲੀ *signer_ctx)
{
	ਬਣਤਰ sshbuf *b = ਨਿਰਾ;
	ਪੂਰਨ r = SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;

	ਜੇ (hashalg == ਨਿਰਾ)
		hashalg = HASHALG_DEFAULT;
	ਜੇ (ਬਾਹਰਲਾ != ਨਿਰਾ)
		*ਬਾਹਰਲਾ = ਨਿਰਾ;
	ਜੇ ((r = hash_ਬਫਰ(ਸੁਨੇਹਾ_2, hashalg, &b)) != 0) {
		error_fr(r, "hash buffer");
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((r = sshsig_wrap_sign(ਕੁੰਜੀ, hashalg, sk_provider, sk_pin, b,
	    sig_namespace, ਬਾਹਰਲਾ, signer, signer_ctx)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	/* success */
	r = 0;
 ਬਾਹਰਲਾ:
	sshbuf_free(b);
	ਵਾਪਸ r;
}

ਪੂਰਨ
sshsig_verifyb(ਬਣਤਰ sshbuf *signature, ਅਚਲ ਬਣਤਰ sshbuf *ਸੁਨੇਹਾ_2,
    ਅਚਲ ਅੱਖਰ *expect_namespace, ਬਣਤਰ sshkey **sign_keyp,
    ਬਣਤਰ sshkey_sig_details **sig_details)
{
	ਬਣਤਰ sshbuf *b = ਨਿਰਾ;
	ਪੂਰਨ r = SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;
	ਅੱਖਰ *hashalg = ਨਿਰਾ;

	ਜੇ (sig_details != ਨਿਰਾ)
		*sig_details = ਨਿਰਾ;
	ਜੇ (sign_keyp != ਨਿਰਾ)
		*sign_keyp = ਨਿਰਾ;
	ਜੇ ((r = sshsig_peek_hashalg(signature, &hashalg)) != 0)
		ਵਾਪਸ r;
	debug_f("signature made with hash \"%s\"", hashalg);
	ਜੇ ((r = hash_ਬਫਰ(ਸੁਨੇਹਾ_2, hashalg, &b)) != 0) {
		error_fr(r, "hash buffer");
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((r = sshsig_wrap_verify(signature, hashalg, b, expect_namespace,
	    sign_keyp, sig_details)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	/* success */
	r = 0;
 ਬਾਹਰਲਾ:
	sshbuf_free(b);
	ਮੁਕਤ(hashalg);
	ਵਾਪਸ r;
}

ਸਥਿਰ ਪੂਰਨ
hash_file(ਪੂਰਨ fd, ਅਚਲ ਅੱਖਰ *hashalg, ਬਣਤਰ sshbuf **bp)
{
	ਅੱਖਰ *hex, rbuf[8192], hash[SSH_DIGEST_MAX_ਲੰਮਾਈ];
	ssize_t n, ਕੁੱਲ = 0;
	ਬਣਤਰ ssh_digest_ctx *ctx = ਨਿਰਾ;
	ਪੂਰਨ alg, oerrno, r = SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;
	ਬਣਤਰ sshbuf *b = ਨਿਰਾ;

	*bp = ਨਿਰਾ;
	memset(hash, 0, ਆਕਾਰ(hash));

	ਜੇ ((r = sshsig_check_hashalg(hashalg)) != 0)
		ਵਾਪਸ r;
	ਜੇ ((alg = ssh_digest_alg_by_name(hashalg)) == -1) {
		error_f("can't look up hash algorithm %s", hashalg);
		ਵਾਪਸ SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;
	}
	ਜੇ ((ctx = ssh_digest_ਸ਼ੁਰੂ(alg)) == ਨਿਰਾ) {
		error_f("ssh_digest_start failed");
		ਵਾਪਸ SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;
	}
	ਲਈ (;;) {
		ਜੇ ((n = ਪਠ(fd, rbuf, ਆਕਾਰ(rbuf))) == -1) {
			ਜੇ (errno == EINTR || errno == EAGAIN)
				ਜਾਰੀ;
			oerrno = errno;
			error_f("read: %s", strerror(errno));
			errno = oerrno;
			r = SSH_ERR_SYSTEM_ERROR;
			ਜਾਓ ਬਾਹਰਲਾ;
		} ਨਹੀਂਤਾਂ ਜੇ (n == 0) {
			debug2_f("hashed %zu bytes", ਕੁੱਲ);
			ਰੋਕੋ; /* EOF */
		}
		ਕੁੱਲ += (ਮਾਪ_t)n;
		ਜੇ ((r = ssh_digest_update(ctx, rbuf, (ਮਾਪ_t)n)) != 0) {
			error_fr(r, "ssh_digest_update");
			ਜਾਓ ਬਾਹਰਲਾ;
		}
	}
	ਜੇ ((r = ssh_digest_final(ctx, hash, ਆਕਾਰ(hash))) != 0) {
		error_fr(r, "ssh_digest_final");
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((hex = tohex(hash, ssh_digest_ਬਾਈਟਾਂ(alg))) != ਨਿਰਾ) {
		debug3_f("final hash: %s", hex);
		freezero(hex, ਲੜੀ_ਲੰਬਾਈ(hex));
	}
	ਜੇ ((b = sshbuf_new()) == ਨਿਰਾ) {
		r = SSH_ERR_ALLOC_FAIL;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((r = sshbuf_put(b, hash, ssh_digest_ਬਾਈਟਾਂ(alg))) != 0) {
		error_fr(r, "sshbuf_put");
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	*bp = b;
	b = ਨਿਰਾ; /* transferred */
	/* success */
	r = 0;
 ਬਾਹਰਲਾ:
	oerrno = errno;
	sshbuf_free(b);
	ssh_digest_free(ctx);
	explicit_bzero(hash, ਆਕਾਰ(hash));
	errno = oerrno;
	ਵਾਪਸ r;
}

ਪੂਰਨ
sshsig_sign_fd(ਬਣਤਰ sshkey *ਕੁੰਜੀ, ਅਚਲ ਅੱਖਰ *hashalg,
    ਅਚਲ ਅੱਖਰ *sk_provider, ਅਚਲ ਅੱਖਰ *sk_pin,
    ਪੂਰਨ fd, ਅਚਲ ਅੱਖਰ *sig_namespace, ਬਣਤਰ sshbuf **ਬਾਹਰਲਾ,
    sshsig_signer *signer, ਖਾਲੀ *signer_ctx)
{
	ਬਣਤਰ sshbuf *b = ਨਿਰਾ;
	ਪੂਰਨ r = SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;

	ਜੇ (hashalg == ਨਿਰਾ)
		hashalg = HASHALG_DEFAULT;
	ਜੇ (ਬਾਹਰਲਾ != ਨਿਰਾ)
		*ਬਾਹਰਲਾ = ਨਿਰਾ;
	ਜੇ ((r = hash_file(fd, hashalg, &b)) != 0) {
		error_fr(r, "hash_file");
		ਵਾਪਸ r;
	}
	ਜੇ ((r = sshsig_wrap_sign(ਕੁੰਜੀ, hashalg, sk_provider, sk_pin, b,
	    sig_namespace, ਬਾਹਰਲਾ, signer, signer_ctx)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	/* success */
	r = 0;
 ਬਾਹਰਲਾ:
	sshbuf_free(b);
	ਵਾਪਸ r;
}

ਪੂਰਨ
sshsig_verify_fd(ਬਣਤਰ sshbuf *signature, ਪੂਰਨ fd,
    ਅਚਲ ਅੱਖਰ *expect_namespace, ਬਣਤਰ sshkey **sign_keyp,
    ਬਣਤਰ sshkey_sig_details **sig_details)
{
	ਬਣਤਰ sshbuf *b = ਨਿਰਾ;
	ਪੂਰਨ r = SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;
	ਅੱਖਰ *hashalg = ਨਿਰਾ;

	ਜੇ (sig_details != ਨਿਰਾ)
		*sig_details = ਨਿਰਾ;
	ਜੇ (sign_keyp != ਨਿਰਾ)
		*sign_keyp = ਨਿਰਾ;
	ਜੇ ((r = sshsig_peek_hashalg(signature, &hashalg)) != 0)
		ਵਾਪਸ r;
	debug_f("signature made with hash \"%s\"", hashalg);
	ਜੇ ((r = hash_file(fd, hashalg, &b)) != 0) {
		error_fr(r, "hash_file");
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((r = sshsig_wrap_verify(signature, hashalg, b, expect_namespace,
	    sign_keyp, sig_details)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	/* success */
	r = 0;
 ਬਾਹਰਲਾ:
	sshbuf_free(b);
	ਮੁਕਤ(hashalg);
	ਵਾਪਸ r;
}

ਬਣਤਰ sshsigopt {
	ਪੂਰਨ ca;
	ਅੱਖਰ *namespaces;
	uint64_t valid_after, valid_before;
};

ਬਣਤਰ sshsigopt *
sshsigopt_parse(ਅਚਲ ਅੱਖਰ *opts, ਅਚਲ ਅੱਖਰ *ਰਸਤਾ, u_long linenum,
    ਅਚਲ ਅੱਖਰ **errstrp)
{
	ਬਣਤਰ sshsigopt *ret;
	ਪੂਰਨ r;
	ਅੱਖਰ *opt;
	ਅਚਲ ਅੱਖਰ *errstr = ਨਿਰਾ;

	ਜੇ ((ret = ਸਿਫਰ_ਸਮ੍ਰਿਤੀ_ਦਿਓ(1, ਆਕਾਰ(*ret))) == ਨਿਰਾ)
		ਵਾਪਸ ਨਿਰਾ;
	ਜੇ (opts == ਨਿਰਾ || *opts == '\0')
		ਵਾਪਸ ret; /* Empty options yields empty options :) */

	ਜਦੋਂ (*opts && *opts != ' ' && *opts != '\t') {
		/* flag options */
		ਜੇ ((r = opt_flag("cert-authority", 0, &opts)) != -1) {
			ret->ca = 1;
		} ਨਹੀਂਤਾਂ ਜੇ (opt_ਮੇਲ(&opts, "namespaces")) {
			ਜੇ (ret->namespaces != ਨਿਰਾ) {
				errstr = "multiple \"namespaces\" clauses";
				ਜਾਓ fail;
			}
			ret->namespaces = opt_dequote(&opts, &errstr);
			ਜੇ (ret->namespaces == ਨਿਰਾ)
				ਜਾਓ fail;
		} ਨਹੀਂਤਾਂ ਜੇ (opt_ਮੇਲ(&opts, "valid-after")) {
			ਜੇ (ret->valid_after != 0) {
				errstr = "multiple \"valid-after\" clauses";
				ਜਾਓ fail;
			}
			ਜੇ ((opt = opt_dequote(&opts, &errstr)) == ਨਿਰਾ)
				ਜਾਓ fail;
			ਜੇ (parse_absolute_ਸਮਾਂ(opt, &ret->valid_after) != 0 ||
			    ret->valid_after == 0) {
				ਮੁਕਤ(opt);
				errstr = "invalid \"valid-after\" time";
				ਜਾਓ fail;
			}
			ਮੁਕਤ(opt);
		} ਨਹੀਂਤਾਂ ਜੇ (opt_ਮੇਲ(&opts, "valid-before")) {
			ਜੇ (ret->valid_before != 0) {
				errstr = "multiple \"valid-before\" clauses";
				ਜਾਓ fail;
			}
			ਜੇ ((opt = opt_dequote(&opts, &errstr)) == ਨਿਰਾ)
				ਜਾਓ fail;
			ਜੇ (parse_absolute_ਸਮਾਂ(opt, &ret->valid_before) != 0 ||
			    ret->valid_before == 0) {
				ਮੁਕਤ(opt);
				errstr = "invalid \"valid-before\" time";
				ਜਾਓ fail;
			}
			ਮੁਕਤ(opt);
		}
		/*
		 * Skip the comma, and move to the next option
		 * (or break out if there are no more).
		 */
		ਜੇ (*opts == '\0' || *opts == ' ' || *opts == '\t')
			ਰੋਕੋ;		/* End of options. */
		/* Anything other than a comma is an unknown option */
		ਜੇ (*opts != ',') {
			errstr = "unknown key option";
			ਜਾਓ fail;
		}
		opts++;
		ਜੇ (*opts == '\0') {
			errstr = "unexpected end-of-options";
			ਜਾਓ fail;
		}
	}
	/* final consistency check */
	ਜੇ (ret->valid_after != 0 && ret->valid_before != 0 &&
	    ret->valid_before <= ret->valid_after) {
		errstr = "\"valid-before\" time is before \"valid-after\"";
		ਜਾਓ fail;
	}
	/* success */
	ਵਾਪਸ ret;
 fail:
	ਜੇ (errstrp != ਨਿਰਾ)
		*errstrp = errstr;
	sshsigopt_free(ret);
	ਵਾਪਸ ਨਿਰਾ;
}

ਖਾਲੀ
sshsigopt_free(ਬਣਤਰ sshsigopt *opts)
{
	ਜੇ (opts == ਨਿਰਾ)
		ਵਾਪਸ;
	ਮੁਕਤ(opts->namespaces);
	ਮੁਕਤ(opts);
}

ਸਥਿਰ ਪੂਰਨ
parse_principals_ਕੁੰਜੀ_and_options(ਅਚਲ ਅੱਖਰ *ਰਸਤਾ, u_long linenum, ਅੱਖਰ *ਸਤਰ,
    ਅਚਲ ਅੱਖਰ *required_principal, ਅੱਖਰ **principalsp, ਬਣਤਰ sshkey **keyp,
    ਬਣਤਰ sshsigopt **sigoptsp)
{
	ਅੱਖਰ *opts = ਨਿਰਾ, *tmp, *cp, *principals = ਨਿਰਾ;
	ਅਚਲ ਅੱਖਰ *reason = ਨਿਰਾ;
	ਬਣਤਰ sshsigopt *sigopts = ਨਿਰਾ;
	ਬਣਤਰ sshkey *ਕੁੰਜੀ = ਨਿਰਾ;
	ਪੂਰਨ r = SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;

	ਜੇ (principalsp != ਨਿਰਾ)
		*principalsp = ਨਿਰਾ;
	ਜੇ (sigoptsp != ਨਿਰਾ)
		*sigoptsp = ਨਿਰਾ;
	ਜੇ (keyp != ਨਿਰਾ)
		*keyp = ਨਿਰਾ;

	cp = ਸਤਰ;
	cp = cp + strspn(cp, " \t\n\r"); /* skip leading whitespace */
	ਜੇ (*cp == '#' || *cp == '\0')
		ਵਾਪਸ SSH_ERR_ਕੁੰਜੀ_NOT_ਮਿਲਿਆ; /* blank or all-comment line */

	/* format: identity[,identity...] [option[,option...]] key */
	ਜੇ ((tmp = strdelimw(&cp)) == ਨਿਰਾ || cp == ਨਿਰਾ) {
		error("%s:%lu: invalid line", ਰਸਤਾ, linenum);
		r = SSH_ERR_INVALID_FORMAT;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((principals = strdup(tmp)) == ਨਿਰਾ) {
		error_f("strdup failed");
		r = SSH_ERR_ALLOC_FAIL;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	/*
	 * Bail out early if we're looking for a particular principal and this
	 * line does not list it.
	 */
	ਜੇ (required_principal != ਨਿਰਾ) {
		ਜੇ (ਮੇਲ_ਨਮੂਨਾ_list(required_principal,
		    principals, 0) != 1) {
			/* principal didn't match */
			r = SSH_ERR_ਕੁੰਜੀ_NOT_ਮਿਲਿਆ;
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		debug_f("%s:%lu: matched principal \"%s\"",
		    ਰਸਤਾ, linenum, required_principal);
	}

	ਜੇ ((ਕੁੰਜੀ = sshkey_new(ਕੁੰਜੀ_UNSPEC)) == ਨਿਰਾ) {
		error_f("sshkey_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ (sshkey_read(ਕੁੰਜੀ, &cp) != 0) {
		/* no key? Check for options */
		opts = cp;
		ਜੇ (sshkey_advance_past_options(&cp) != 0) {
			error("%s:%lu: invalid options", ਰਸਤਾ, linenum);
			r = SSH_ERR_INVALID_FORMAT;
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		ਜੇ (cp == ਨਿਰਾ || *cp == '\0') {
			error("%s:%lu: missing key", ਰਸਤਾ, linenum);
			r = SSH_ERR_INVALID_FORMAT;
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		*cp++ = '\0';
		skip_space(&cp);
		ਜੇ (sshkey_read(ਕੁੰਜੀ, &cp) != 0) {
			error("%s:%lu: invalid key", ਰਸਤਾ, linenum);
			r = SSH_ERR_INVALID_FORMAT;
			ਜਾਓ ਬਾਹਰਲਾ;
		}
	}
	debug3("%s:%lu: options %s", ਰਸਤਾ, linenum, opts == ਨਿਰਾ ? "" : opts);
	ਜੇ ((sigopts = sshsigopt_parse(opts, ਰਸਤਾ, linenum, &reason)) == ਨਿਰਾ) {
		error("%s:%lu: bad options: %s", ਰਸਤਾ, linenum, reason);
		r = SSH_ERR_INVALID_FORMAT;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	/* success */
	ਜੇ (principalsp != ਨਿਰਾ) {
		*principalsp = principals;
		principals = ਨਿਰਾ; /* transferred */
	}
	ਜੇ (sigoptsp != ਨਿਰਾ) {
		*sigoptsp = sigopts;
		sigopts = ਨਿਰਾ; /* transferred */
	}
	ਜੇ (keyp != ਨਿਰਾ) {
		*keyp = ਕੁੰਜੀ;
		ਕੁੰਜੀ = ਨਿਰਾ; /* transferred */
	}
	r = 0;
 ਬਾਹਰਲਾ:
	ਮੁਕਤ(principals);
	sshsigopt_free(sigopts);
	sshkey_free(ਕੁੰਜੀ);
	ਵਾਪਸ r;
}

ਸਥਿਰ ਪੂਰਨ
cert_filter_principals(ਅਚਲ ਅੱਖਰ *ਰਸਤਾ, u_long linenum,
    ਅੱਖਰ **principalsp, ਅਚਲ ਬਣਤਰ sshkey *cert, uint64_t verify_ਸਮਾਂ)
{
	ਅੱਖਰ *cp, *oprincipals, *principals;
	ਅਚਲ ਅੱਖਰ *reason;
	ਬਣਤਰ sshbuf *nprincipals;
	ਪੂਰਨ r = SSH_ERR_ਅੰਦਰੂਨੀ_ERROR, success = 0;
	u_int i;

	oprincipals = principals = *principalsp;
	*principalsp = ਨਿਰਾ;

	ਜੇ ((nprincipals = sshbuf_new()) == ਨਿਰਾ) {
		r = SSH_ERR_ALLOC_FAIL;
		ਜਾਓ ਬਾਹਰਲਾ;
	}

	ਜਦੋਂ ((cp = strsep(&principals, ",")) != ਨਿਰਾ && *cp != '\0') {
		/* Check certificate validity */
		ਜੇ ((r = sshkey_cert_check_authority(cert, 0, 0, verify_ਸਮਾਂ,
		    ਨਿਰਾ, &reason)) != 0) {
			debug("%s:%lu: principal \"%s\" not authorized: %s",
			    ਰਸਤਾ, linenum, cp, reason);
			ਜਾਰੀ;
		}
		/* Return all matching principal names from the cert */
		ਲਈ (i = 0; i < cert->cert->nprincipals; i++) {
			ਜੇ (ਮੇਲ_ਨਮੂਨਾ(cert->cert->principals[i], cp)) {
				ਜੇ ((r = sshbuf_putf(nprincipals, "%s%s",
					sshbuf_len(nprincipals) != 0 ? "," : "",
						cert->cert->principals[i])) != 0) {
					error_f("buffer error");
					ਜਾਓ ਬਾਹਰਲਾ;
				}
			}
		}
	}
	ਜੇ (sshbuf_len(nprincipals) == 0) {
		error("%s:%lu: no valid principals found", ਰਸਤਾ, linenum);
		r = SSH_ERR_ਕੁੰਜੀ_CERT_INVALID;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((principals = sshbuf_dup_string(nprincipals)) == ਨਿਰਾ) {
		error_f("buffer error");
		r = SSH_ERR_ALLOC_FAIL;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	/* success */
	success = 1;
	*principalsp = principals;
 ਬਾਹਰਲਾ:
	sshbuf_free(nprincipals);
	ਮੁਕਤ(oprincipals);
	ਵਾਪਸ success ? 0 : r;
}

ਸਥਿਰ ਪੂਰਨ
check_allowed_ਕੁੰਜੀਆਂ_ਸਤਰ(ਅਚਲ ਅੱਖਰ *ਰਸਤਾ, u_long linenum, ਅੱਖਰ *ਸਤਰ,
    ਅਚਲ ਬਣਤਰ sshkey *sign_ਕੁੰਜੀ, ਅਚਲ ਅੱਖਰ *principal,
    ਅਚਲ ਅੱਖਰ *sig_namespace, uint64_t verify_ਸਮਾਂ, ਅੱਖਰ **principalsp)
{
	ਬਣਤਰ sshkey *ਮਿਲਿਆ_ਕੁੰਜੀ = ਨਿਰਾ;
	ਅੱਖਰ *principals = ਨਿਰਾ;
	ਪੂਰਨ r, success = 0;
	ਅਚਲ ਅੱਖਰ *reason = ਨਿਰਾ;
	ਬਣਤਰ sshsigopt *sigopts = ਨਿਰਾ;
	ਅੱਖਰ tvalid[64], tverify[64];

	ਜੇ (principalsp != ਨਿਰਾ)
		*principalsp = ਨਿਰਾ;

	/* Parse the line */
	ਜੇ ((r = parse_principals_ਕੁੰਜੀ_and_options(ਰਸਤਾ, linenum, ਸਤਰ,
	    principal, &principals, &ਮਿਲਿਆ_ਕੁੰਜੀ, &sigopts)) != 0) {
		/* error already logged */
		ਜਾਓ ਪੂਰਾ;
	}

	ਜੇ (!sigopts->ca && sshkey_equal(ਮਿਲਿਆ_ਕੁੰਜੀ, sign_ਕੁੰਜੀ)) {
		/* Exact match of key */
		debug("%s:%lu: matched key", ਰਸਤਾ, linenum);
	} ਨਹੀਂਤਾਂ ਜੇ (sigopts->ca && sshkey_is_cert(sign_ਕੁੰਜੀ) &&
	    sshkey_equal_ਜਨਤਕ(sign_ਕੁੰਜੀ->cert->signature_ਕੁੰਜੀ, ਮਿਲਿਆ_ਕੁੰਜੀ)) {
		ਜੇ (principal) {
			/* Match certificate CA key with specified principal */
			ਜੇ ((r = sshkey_cert_check_authority(sign_ਕੁੰਜੀ, 0, 0,
			    verify_ਸਮਾਂ, principal, &reason)) != 0) {
				error("%s:%lu: certificate not authorized: %s",
				    ਰਸਤਾ, linenum, reason);
				ਜਾਓ ਪੂਰਾ;
			}
			debug("%s:%lu: matched certificate CA key",
			    ਰਸਤਾ, linenum);
		} ਨਹੀਂਤਾਂ {
			/* No principal specified - find all matching ones */
			ਜੇ ((r = cert_filter_principals(ਰਸਤਾ, linenum,
			    &principals, sign_ਕੁੰਜੀ, verify_ਸਮਾਂ)) != 0) {
				/* error already displayed */
				debug_r(r, "%s:%lu: cert_filter_principals",
				    ਰਸਤਾ, linenum);
				ਜਾਓ ਪੂਰਾ;
			}
			debug("%s:%lu: matched certificate CA key",
			    ਰਸਤਾ, linenum);
		}
	} ਨਹੀਂਤਾਂ {
		/* Didn't match key */
		ਜਾਓ ਪੂਰਾ;
	}

	/* Check whether options preclude the use of this key */
	ਜੇ (sigopts->namespaces != ਨਿਰਾ && sig_namespace != ਨਿਰਾ &&
	    ਮੇਲ_ਨਮੂਨਾ_list(sig_namespace, sigopts->namespaces, 0) != 1) {
		error("%s:%lu: key is not permitted for use in signature "
		    "namespace \"%s\"", ਰਸਤਾ, linenum, sig_namespace);
		ਜਾਓ ਪੂਰਾ;
	}

	/* check key time validity */
	format_absolute_ਸਮਾਂ((uint64_t)verify_ਸਮਾਂ, tverify, ਆਕਾਰ(tverify));
	ਜੇ (sigopts->valid_after != 0 &&
	    (uint64_t)verify_ਸਮਾਂ < sigopts->valid_after) {
		format_absolute_ਸਮਾਂ(sigopts->valid_after,
		    tvalid, ਆਕਾਰ(tvalid));
		error("%s:%lu: key is not yet valid: "
		    "verify time %s < valid-after %s", ਰਸਤਾ, linenum,
		    tverify, tvalid);
		ਜਾਓ ਪੂਰਾ;
	}
	ਜੇ (sigopts->valid_before != 0 &&
	    (uint64_t)verify_ਸਮਾਂ > sigopts->valid_before) {
		format_absolute_ਸਮਾਂ(sigopts->valid_before,
		    tvalid, ਆਕਾਰ(tvalid));
		error("%s:%lu: key has expired: "
		    "verify time %s > valid-before %s", ਰਸਤਾ, linenum,
		    tverify, tvalid);
		ਜਾਓ ਪੂਰਾ;
	}
	success = 1;

 ਪੂਰਾ:
	ਜੇ (success && principalsp != ਨਿਰਾ) {
		*principalsp = principals;
		principals = ਨਿਰਾ; /* transferred */
	}
	ਮੁਕਤ(principals);
	sshkey_free(ਮਿਲਿਆ_ਕੁੰਜੀ);
	sshsigopt_free(sigopts);
	ਵਾਪਸ success ? 0 : SSH_ERR_ਕੁੰਜੀ_NOT_ਮਿਲਿਆ;
}

ਪੂਰਨ
sshsig_check_allowed_ਕੁੰਜੀਆਂ(ਅਚਲ ਅੱਖਰ *ਰਸਤਾ, ਅਚਲ ਬਣਤਰ sshkey *sign_ਕੁੰਜੀ,
    ਅਚਲ ਅੱਖਰ *principal, ਅਚਲ ਅੱਖਰ *sig_namespace, uint64_t verify_ਸਮਾਂ)
{
	FILE *f = ਨਿਰਾ;
	ਅੱਖਰ *ਸਤਰ = ਨਿਰਾ;
	ਮਾਪ_t linesize = 0;
	u_long linenum = 0;
	ਪੂਰਨ r = SSH_ERR_ਕੁੰਜੀ_NOT_ਮਿਲਿਆ, oerrno;

	/* Check key and principal against file */
	ਜੇ ((f = fopen(ਰਸਤਾ, "r")) == ਨਿਰਾ) {
		oerrno = errno;
		error("Unable to open allowed keys file \"%s\": %s",
		    ਰਸਤਾ, strerror(errno));
		errno = oerrno;
		ਵਾਪਸ SSH_ERR_SYSTEM_ERROR;
	}

	ਜਦੋਂ (getline(&ਸਤਰ, &linesize, f) != -1) {
		linenum++;
		r = check_allowed_ਕੁੰਜੀਆਂ_ਸਤਰ(ਰਸਤਾ, linenum, ਸਤਰ, sign_ਕੁੰਜੀ,
		    principal, sig_namespace, verify_ਸਮਾਂ, ਨਿਰਾ);
		ਮੁਕਤ(ਸਤਰ);
		ਸਤਰ = ਨਿਰਾ;
		linesize = 0;
		ਜੇ (r == SSH_ERR_ਕੁੰਜੀ_NOT_ਮਿਲਿਆ)
			ਜਾਰੀ;
		ਨਹੀਂਤਾਂ ਜੇ (r == 0) {
			/* success */
			fclose(f);
			ਵਾਪਸ 0;
		} ਨਹੀਂਤਾਂ
			ਰੋਕੋ;
	}
	/* Either we hit an error parsing or we simply didn't find the key */
	fclose(f);
	ਮੁਕਤ(ਸਤਰ);
	ਵਾਪਸ r;
}

ਪੂਰਨ
sshsig_ਲੱਭੋ_principals(ਅਚਲ ਅੱਖਰ *ਰਸਤਾ, ਅਚਲ ਬਣਤਰ sshkey *sign_ਕੁੰਜੀ,
    uint64_t verify_ਸਮਾਂ, ਅੱਖਰ **principals)
{
	FILE *f = ਨਿਰਾ;
	ਅੱਖਰ *ਸਤਰ = ਨਿਰਾ;
	ਮਾਪ_t linesize = 0;
	u_long linenum = 0;
	ਪੂਰਨ r = SSH_ERR_ਕੁੰਜੀ_NOT_ਮਿਲਿਆ, oerrno;

	ਜੇ ((f = fopen(ਰਸਤਾ, "r")) == ਨਿਰਾ) {
		oerrno = errno;
		error("Unable to open allowed keys file \"%s\": %s",
		    ਰਸਤਾ, strerror(errno));
		errno = oerrno;
		ਵਾਪਸ SSH_ERR_SYSTEM_ERROR;
	}

	ਜਦੋਂ (getline(&ਸਤਰ, &linesize, f) != -1) {
		linenum++;
		r = check_allowed_ਕੁੰਜੀਆਂ_ਸਤਰ(ਰਸਤਾ, linenum, ਸਤਰ,
		    sign_ਕੁੰਜੀ, ਨਿਰਾ, ਨਿਰਾ, verify_ਸਮਾਂ, principals);
		ਮੁਕਤ(ਸਤਰ);
		ਸਤਰ = ਨਿਰਾ;
		linesize = 0;
		ਜੇ (r == SSH_ERR_ਕੁੰਜੀ_NOT_ਮਿਲਿਆ)
			ਜਾਰੀ;
		ਨਹੀਂਤਾਂ ਜੇ (r == 0) {
			/* success */
			fclose(f);
			ਵਾਪਸ 0;
		} ਨਹੀਂਤਾਂ
			ਰੋਕੋ;
	}
	ਮੁਕਤ(ਸਤਰ);
	/* Either we hit an error parsing or we simply didn't find the key */
	ਜੇ (ferror(f) != 0) {
		oerrno = errno;
		fclose(f);
		error("Unable to read allowed keys file \"%s\": %s",
		    ਰਸਤਾ, strerror(errno));
		errno = oerrno;
		ਵਾਪਸ SSH_ERR_SYSTEM_ERROR;
	}
	fclose(f);
	ਵਾਪਸ r;
}

ਪੂਰਨ
sshsig_ਮੇਲ_principals(ਅਚਲ ਅੱਖਰ *ਰਸਤਾ, ਅਚਲ ਅੱਖਰ *principal,
    ਅੱਖਰ ***principalsp, ਮਾਪ_t *nprincipalsp)
{
	FILE *f = ਨਿਰਾ;
	ਅੱਖਰ *ਮਿਲਿਆ, *ਸਤਰ = ਨਿਰਾ, **principals = ਨਿਰਾ, **tmp;
	ਮਾਪ_t i, nprincipals = 0, linesize = 0;
	u_long linenum = 0;
	ਪੂਰਨ oerrno = 0, r, ret = 0;

	ਜੇ (principalsp != ਨਿਰਾ)
		*principalsp = ਨਿਰਾ;
	ਜੇ (nprincipalsp != ਨਿਰਾ)
		*nprincipalsp = 0;

	/* Check key and principal against file */
	ਜੇ ((f = fopen(ਰਸਤਾ, "r")) == ਨਿਰਾ) {
		oerrno = errno;
		error("Unable to open allowed keys file \"%s\": %s",
		    ਰਸਤਾ, strerror(errno));
		errno = oerrno;
		ਵਾਪਸ SSH_ERR_SYSTEM_ERROR;
	}

	ਜਦੋਂ (getline(&ਸਤਰ, &linesize, f) != -1) {
		linenum++;
		/* Parse the line */
		ਜੇ ((r = parse_principals_ਕੁੰਜੀ_and_options(ਰਸਤਾ, linenum, ਸਤਰ,
		    principal, &ਮਿਲਿਆ, ਨਿਰਾ, ਨਿਰਾ)) != 0) {
			ਜੇ (r == SSH_ERR_ਕੁੰਜੀ_NOT_ਮਿਲਿਆ)
				ਜਾਰੀ;
			ret = r;
			oerrno = errno;
			ਰੋਕੋ; /* unexpected error */
		}
		ਜੇ ((tmp = recallocarray(principals, nprincipals,
		    nprincipals + 1, ਆਕਾਰ(*principals))) == ਨਿਰਾ) {
			ret = SSH_ERR_ALLOC_FAIL;
			ਮੁਕਤ(ਮਿਲਿਆ);
			ਰੋਕੋ;
		}
		principals = tmp;
		principals[nprincipals++] = ਮਿਲਿਆ; /* transferred */
		ਮੁਕਤ(ਸਤਰ);
		ਸਤਰ = ਨਿਰਾ;
		linesize = 0;
	}
	fclose(f);
	ਮੁਕਤ(ਸਤਰ);

	ਜੇ (ret == 0) {
		ਜੇ (nprincipals == 0)
			ret = SSH_ERR_ਕੁੰਜੀ_NOT_ਮਿਲਿਆ;
		ਜੇ (nprincipalsp != ਨਿਰਾ)
			*nprincipalsp = nprincipals;
		ਜੇ (principalsp != ਨਿਰਾ) {
			*principalsp = principals;
			principals = ਨਿਰਾ; /* transferred */
			nprincipals = 0;
		}
	}

	ਲਈ (i = 0; i < nprincipals; i++)
		ਮੁਕਤ(principals[i]);
	ਮੁਕਤ(principals);

	errno = oerrno;
	ਵਾਪਸ ret;
}

ਪੂਰਨ
sshsig_get_pubkey(ਬਣਤਰ sshbuf *signature, ਬਣਤਰ sshkey **pubkey)
{
	ਬਣਤਰ sshkey *pk = ਨਿਰਾ;
	ਪੂਰਨ r = SSH_ERR_SIGNATURE_INVALID;

	ਜੇ (pubkey == ਨਿਰਾ)
		ਵਾਪਸ SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;
	ਜੇ ((r = sshsig_parse_preamble(signature)) != 0)
		ਵਾਪਸ r;
	ਜੇ ((r = sshkey_froms(signature, &pk)) != 0)
		ਵਾਪਸ r;

	*pubkey = pk;
	pk = ਨਿਰਾ;
	ਵਾਪਸ 0;
}
