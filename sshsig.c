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

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <stdarg.h>
#ಅನ್ತರ್ಭಾವ <errno.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <unistd.h>

#ಅನ್ತರ್ಭಾವ "authfd.h"
#ಅನ್ತರ್ಭಾವ "authfile.h"
#ಅನ್ತರ್ಭಾವ "log.h"
#ಅನ್ತರ್ಭಾವ "misc.h"
#ಅನ್ತರ್ಭಾವ "sshbuf.h"
#ಅನ್ತರ್ಭಾವ "sshsig.h"
#ಅನ್ತರ್ಭಾವ "ssherr.h"
#ಅನ್ತರ್ಭಾವ "sshkey.h"
#ಅನ್ತರ್ಭಾವ "match.h"
#ಅನ್ತರ್ಭಾವ "digest.h"

#ವ್ಯಾಖ್ಯಾನಿಸು SIG_ಆವೃತ್ತಿ		0x01
#ವ್ಯಾಖ್ಯಾನಿಸು MAGIC_PREAMBLE		"SSHSIG"
#ವ್ಯಾಖ್ಯಾನಿಸು MAGIC_PREAMBLE_LEN	(ಗಾತ್ರ(MAGIC_PREAMBLE) - 1)
#ವ್ಯಾಖ್ಯಾನಿಸು BEGIN_SIGNATURE		"-----BEGIN SSH SIGNATURE-----"
#ವ್ಯಾಖ್ಯಾನಿಸು ಕೊನೆ_SIGNATURE		"-----END SSH SIGNATURE-----"
#ವ್ಯಾಖ್ಯಾನಿಸು RSA_SIGN_ALG		"rsa-sha2-512"
#ವ್ಯಾಖ್ಯಾನಿಸು RSA_SIGN_ALLOWED	"rsa-sha2-512,rsa-sha2-256"
#ವ್ಯಾಖ್ಯಾನಿಸು HASHALG_DEFAULT		"sha512"
#ವ್ಯಾಖ್ಯಾನಿಸು HASHALG_ALLOWED		"sha256,sha512"

ಪೂರ್ಣಾಂಕ
sshsig_armor(ಸ್ಥಿರಾಂಕ ರಚನೆ sshbuf *blob, ರಚನೆ sshbuf **ಹೊರಹೋಗು)
{
	ರಚನೆ sshbuf *buf = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ r = SSH_ERR_ಆಂತರಿಕ_ERROR;

	*ಹೊರಹೋಗು = ಖಾಲಿ;

	ಆದರೆ ((buf = sshbuf_new()) == ಖಾಲಿ) {
		error_f("sshbuf_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		ಹೋಗು ಹೊರಹೋಗು;
	}

	ಆದರೆ ((r = sshbuf_putf(buf, "%s\n", BEGIN_SIGNATURE)) != 0) {
		error_fr(r, "sshbuf_putf");
		ಹೋಗು ಹೊರಹೋಗು;
	}

	ಆದರೆ ((r = sshbuf_dtob64(blob, buf, 1)) != 0) {
		error_fr(r, "base64 encode signature");
		ಹೋಗು ಹೊರಹೋಗು;
	}

	ಆದರೆ ((r = sshbuf_put(buf, ಕೊನೆ_SIGNATURE,
	    ಗಾತ್ರ(ಕೊನೆ_SIGNATURE)-1)) != 0 ||
	    (r = sshbuf_put_u8(buf, '\n')) != 0) {
		error_fr(r, "sshbuf_put");
		ಹೋಗು ಹೊರಹೋಗು;
	}
	/* success */
	*ಹೊರಹೋಗು = buf;
	buf = ಖಾಲಿ; /* transferred */
	r = 0;
 ಹೊರಹೋಗು:
	sshbuf_free(buf);
	ಹಿಂತಿರುಗಿ r;
}

ಪೂರ್ಣಾಂಕ
sshsig_dearmor(ರಚನೆ sshbuf *sig, ರಚನೆ sshbuf **ಹೊರಹೋಗು)
{
	ಪೂರ್ಣಾಂಕ r;
	ಗಾತ್ರ_t eoffset = 0;
	ರಚನೆ sshbuf *buf = ಖಾಲಿ;
	ರಚನೆ sshbuf *sbuf = ಖಾಲಿ;
	ಅಕ್ಷರ *b64 = ಖಾಲಿ;

	ಆದರೆ ((sbuf = sshbuf_fromb(sig)) == ಖಾಲಿ) {
		error_f("sshbuf_fromb failed");
		ಹಿಂತಿರುಗಿ SSH_ERR_ALLOC_FAIL;
	}

	/* Expect and consume preamble + lf/crlf */
	ಆದರೆ ((r = sshbuf_cmp(sbuf, 0,
	    BEGIN_SIGNATURE, ಗಾತ್ರ(BEGIN_SIGNATURE)-1)) != 0) {
		error("Couldn't parse signature: missing header");
		ಹೋಗು ಮುಗಿದ;
	}
	ಆದರೆ ((r = sshbuf_consume(sbuf, ಗಾತ್ರ(BEGIN_SIGNATURE)-1)) != 0) {
		error_fr(r, "consume");
		ಹೋಗು ಮುಗಿದ;
	}
	ಆದರೆ ((r = sshbuf_cmp(sbuf, 0, "\r\n", 2)) == 0)
		eoffset = 2;
	ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ ((r = sshbuf_cmp(sbuf, 0, "\n", 1)) == 0)
		eoffset = 1;
	ಇಲ್ಲದಿದ್ದರೆ {
		r = SSH_ERR_INVALID_FORMAT;
		error_f("no header eol");
		ಹೋಗು ಮುಗಿದ;
	}
	ಆದರೆ ((r = sshbuf_consume(sbuf, eoffset)) != 0) {
		error_fr(r, "consume eol");
		ಹೋಗು ಮುಗಿದ;
	}
	/* Find and consume lf + suffix (any prior cr would be ignored) */
	ಆದರೆ ((r = sshbuf_ಕಂಡುಹಿಡಿ(sbuf, 0, "\n" ಕೊನೆ_SIGNATURE,
	    ಗಾತ್ರ(ಕೊನೆ_SIGNATURE), &eoffset)) != 0) {
		error("Couldn't parse signature: missing footer");
		ಹೋಗು ಮುಗಿದ;
	}
	ಆದರೆ ((r = sshbuf_consume_ಕೊನೆ(sbuf, sshbuf_len(sbuf)-eoffset)) != 0) {
		error_fr(r, "consume");
		ಹೋಗು ಮುಗಿದ;
	}

	ಆದರೆ ((b64 = sshbuf_dup_string(sbuf)) == ಖಾಲಿ) {
		error_f("sshbuf_dup_string failed");
		r = SSH_ERR_ALLOC_FAIL;
		ಹೋಗು ಮುಗಿದ;
	}

	ಆದರೆ ((buf = sshbuf_new()) == ಖಾಲಿ) {
		error_f("sshbuf_new() failed");
		r = SSH_ERR_ALLOC_FAIL;
		ಹೋಗು ಮುಗಿದ;
	}

	ಆದರೆ ((r = sshbuf_b64tod(buf, b64)) != 0) {
		error_fr(r, "decode base64");
		ಹೋಗು ಮುಗಿದ;
	}

	/* success */
	*ಹೊರಹೋಗು = buf;
	r = 0;
	buf = ಖಾಲಿ; /* transferred */
ಮುಗಿದ:
	sshbuf_free(buf);
	sshbuf_free(sbuf);
	ಬಿಡುಗಡೆ(b64);
	ಹಿಂತಿರುಗಿ r;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
sshsig_wrap_sign(ರಚನೆ sshkey *ಕೀಲಿ, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *hashalg,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *sk_provider, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *sk_pin, ಸ್ಥಿರಾಂಕ ರಚನೆ sshbuf *h_ಸಂದೇಶ,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *sig_namespace, ರಚನೆ sshbuf **ಹೊರಹೋಗು,
    sshsig_signer *signer, ಶೂನ್ಯ *signer_ctx)
{
	ಪೂರ್ಣಾಂಕ r;
	ಗಾತ್ರ_t slen = 0;
	u_char *sig = ಖಾಲಿ;
	ರಚನೆ sshbuf *blob = ಖಾಲಿ;
	ರಚನೆ sshbuf *tosign = ಖಾಲಿ;
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *sign_alg = ಖಾಲಿ;

	ಆದರೆ ((tosign = sshbuf_new()) == ಖಾಲಿ ||
	    (blob = sshbuf_new()) == ಖಾಲಿ) {
		error_f("sshbuf_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		ಹೋಗು ಮುಗಿದ;
	}

	ಆದರೆ ((r = sshbuf_put(tosign, MAGIC_PREAMBLE, MAGIC_PREAMBLE_LEN)) != 0 ||
	    (r = sshbuf_put_cstring(tosign, sig_namespace)) != 0 ||
	    (r = sshbuf_put_string(tosign, ಖಾಲಿ, 0)) != 0 || /* reserved */
	    (r = sshbuf_put_cstring(tosign, hashalg)) != 0 ||
	    (r = sshbuf_put_stringb(tosign, h_ಸಂದೇಶ)) != 0) {
		error_fr(r, "assemble message to sign");
		ಹೋಗು ಮುಗಿದ;
	}

	/* If using RSA keys then default to a good signature algorithm */
	ಆದರೆ (sshkey_type_plain(ಕೀಲಿ->type) == ಕೀಲಿ_RSA) {
		sign_alg = RSA_SIGN_ALG;
		ಆದರೆ (strcmp(hashalg, "sha256") == 0)
			sign_alg = "rsa-sha2-256";
		ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strcmp(hashalg, "sha512") == 0)
			sign_alg = "rsa-sha2-512";
	}

	ಆದರೆ (signer != ಖಾಲಿ) {
		ಆದರೆ ((r = signer(ಕೀಲಿ, &sig, &slen,
		    sshbuf_ptr(tosign), sshbuf_len(tosign),
		    sign_alg, sk_provider, sk_pin, 0, signer_ctx)) != 0) {
			error_r(r, "Couldn't sign message (signer)");
			ಹೋಗು ಮುಗಿದ;
		}
	} ಇಲ್ಲದಿದ್ದರೆ {
		ಆದರೆ ((r = sshkey_sign(ಕೀಲಿ, &sig, &slen,
		    sshbuf_ptr(tosign), sshbuf_len(tosign),
		    sign_alg, sk_provider, sk_pin, 0)) != 0) {
			error_r(r, "Couldn't sign message");
			ಹೋಗು ಮುಗಿದ;
		}
	}

	ಆದರೆ ((r = sshbuf_put(blob, MAGIC_PREAMBLE, MAGIC_PREAMBLE_LEN)) != 0 ||
	    (r = sshbuf_put_u32(blob, SIG_ಆವೃತ್ತಿ)) != 0 ||
	    (r = sshkey_puts(ಕೀಲಿ, blob)) != 0 ||
	    (r = sshbuf_put_cstring(blob, sig_namespace)) != 0 ||
	    (r = sshbuf_put_string(blob, ಖಾಲಿ, 0)) != 0 || /* reserved */
	    (r = sshbuf_put_cstring(blob, hashalg)) != 0 ||
	    (r = sshbuf_put_string(blob, sig, slen)) != 0) {
		error_fr(r, "assemble signature object");
		ಹೋಗು ಮುಗಿದ;
	}

	ಆದರೆ (ಹೊರಹೋಗು != ಖಾಲಿ) {
		*ಹೊರಹೋಗು = blob;
		blob = ಖಾಲಿ;
	}
	r = 0;
ಮುಗಿದ:
	ಬಿಡುಗಡೆ(sig);
	sshbuf_free(blob);
	sshbuf_free(tosign);
	ಹಿಂತಿರುಗಿ r;
}

/* Check preamble and version. */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
sshsig_parse_preamble(ರಚನೆ sshbuf *buf)
{
	ಪೂರ್ಣಾಂಕ r = SSH_ERR_ಆಂತರಿಕ_ERROR;
	uint32_t sversion;

	ಆದರೆ ((r = sshbuf_cmp(buf, 0, MAGIC_PREAMBLE, MAGIC_PREAMBLE_LEN)) != 0 ||
	    (r = sshbuf_consume(buf, (ಗಾತ್ರ(MAGIC_PREAMBLE)-1))) != 0 ||
	    (r = sshbuf_get_u32(buf, &sversion)) != 0) {
		error("Couldn't verify signature: invalid format");
		ಹಿಂತಿರುಗಿ r;
	}

	ಆದರೆ (sversion > SIG_ಆವೃತ್ತಿ) {
		error("Signature version %lu is larger than supported "
		    "version %u", (ಚಿಹ್ನೆರಹಿತ ದೀರ್ಘ)sversion, SIG_ಆವೃತ್ತಿ);
		ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_FORMAT;
	}
	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
sshsig_check_hashalg(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *hashalg)
{
	ಆದರೆ (hashalg == ಖಾಲಿ ||
	    ಹೊಂದಿಕೆ_ನಮೂನೆ_list(hashalg, HASHALG_ALLOWED, 0) == 1)
		ಹಿಂತಿರುಗಿ 0;
	error_f("unsupported hash algorithm \"%.100s\"", hashalg);
	ಹಿಂತಿರುಗಿ SSH_ERR_SIGN_ALG_UNSUPPORTED;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
sshsig_peek_hashalg(ರಚನೆ sshbuf *signature, ಅಕ್ಷರ **hashalgp)
{
	ರಚನೆ sshbuf *buf = ಖಾಲಿ;
	ಅಕ್ಷರ *hashalg = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ r = SSH_ERR_ಆಂತರಿಕ_ERROR;

	ಆದರೆ (hashalgp != ಖಾಲಿ)
		*hashalgp = ಖಾಲಿ;
	ಆದರೆ ((buf = sshbuf_fromb(signature)) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ SSH_ERR_ALLOC_FAIL;
	ಆದರೆ ((r = sshsig_parse_preamble(buf)) != 0)
		ಹೋಗು ಮುಗಿದ;
	ಆದರೆ ((r = sshbuf_get_string_ನೇರ(buf, ಖಾಲಿ, ಖಾಲಿ)) != 0 ||
	    (r = sshbuf_get_string_ನೇರ(buf, ಖಾಲಿ, ಖಾಲಿ)) != 0 ||
	    (r = sshbuf_get_string(buf, ಖಾಲಿ, ಖಾಲಿ)) != 0 ||
	    (r = sshbuf_get_cstring(buf, &hashalg, ಖಾಲಿ)) != 0 ||
	    (r = sshbuf_get_string_ನೇರ(buf, ಖಾಲಿ, ಖಾಲಿ)) != 0) {
		error_fr(r, "parse signature object");
		ಹೋಗು ಮುಗಿದ;
	}

	/* success */
	r = 0;
	*hashalgp = hashalg;
	hashalg = ಖಾಲಿ;
 ಮುಗಿದ:
	ಬಿಡುಗಡೆ(hashalg);
	sshbuf_free(buf);
	ಹಿಂತಿರುಗಿ r;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
sshsig_wrap_verify(ರಚನೆ sshbuf *signature, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *hashalg,
    ಸ್ಥಿರಾಂಕ ರಚನೆ sshbuf *h_ಸಂದೇಶ, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *expect_namespace,
    ರಚನೆ sshkey **sign_keyp, ರಚನೆ sshkey_sig_details **sig_details)
{
	ಪೂರ್ಣಾಂಕ r = SSH_ERR_ಆಂತರಿಕ_ERROR;
	ರಚನೆ sshbuf *buf = ಖಾಲಿ, *toverify = ಖಾಲಿ;
	ರಚನೆ sshkey *ಕೀಲಿ = ಖಾಲಿ;
	ಸ್ಥಿರಾಂಕ u_char *sig;
	ಅಕ್ಷರ *got_namespace = ಖಾಲಿ, *sigtype = ಖಾಲಿ, *sig_hashalg = ಖಾಲಿ;
	ಗಾತ್ರ_t siglen;

	debug_f("verify message length %zu", sshbuf_len(h_ಸಂದೇಶ));
	ಆದರೆ (sig_details != ಖಾಲಿ)
		*sig_details = ಖಾಲಿ;
	ಆದರೆ (sign_keyp != ಖಾಲಿ)
		*sign_keyp = ಖಾಲಿ;

	ಆದರೆ ((toverify = sshbuf_new()) == ಖಾಲಿ) {
		error_f("sshbuf_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		ಹೋಗು ಮುಗಿದ;
	}
	ಆದರೆ ((r = sshbuf_put(toverify, MAGIC_PREAMBLE,
	    MAGIC_PREAMBLE_LEN)) != 0 ||
	    (r = sshbuf_put_cstring(toverify, expect_namespace)) != 0 ||
	    (r = sshbuf_put_string(toverify, ಖಾಲಿ, 0)) != 0 || /* reserved */
	    (r = sshbuf_put_cstring(toverify, hashalg)) != 0 ||
	    (r = sshbuf_put_stringb(toverify, h_ಸಂದೇಶ)) != 0) {
		error_fr(r, "assemble message to verify");
		ಹೋಗು ಮುಗಿದ;
	}

	ಆದರೆ ((r = sshsig_parse_preamble(signature)) != 0)
		ಹೋಗು ಮುಗಿದ;

	ಆದರೆ ((r = sshkey_froms(signature, &ಕೀಲಿ)) != 0 ||
	    (r = sshbuf_get_cstring(signature, &got_namespace, ಖಾಲಿ)) != 0 ||
	    (r = sshbuf_get_string(signature, ಖಾಲಿ, ಖಾಲಿ)) != 0 ||
	    (r = sshbuf_get_cstring(signature, &sig_hashalg, ಖಾಲಿ)) != 0 ||
	    (r = sshbuf_get_string_ನೇರ(signature, &sig, &siglen)) != 0) {
		error_fr(r, "parse signature object");
		ಹೋಗು ಮುಗಿದ;
	}

	ಆದರೆ (sshbuf_len(signature) != 0) {
		error("Signature contains trailing data");
		r = SSH_ERR_INVALID_FORMAT;
		ಹೋಗು ಮುಗಿದ;
	}

	ಆದರೆ (strcmp(expect_namespace, got_namespace) != 0) {
		error("Couldn't verify signature: namespace does not match");
		debug_f("expected namespace \"%s\" received \"%s\"",
		    expect_namespace, got_namespace);
		r = SSH_ERR_SIGNATURE_INVALID;
		ಹೋಗು ಮುಗಿದ;
	}
	ಆದರೆ (strcmp(hashalg, sig_hashalg) != 0) {
		error("Couldn't verify signature: hash algorithm mismatch");
		debug_f("expected algorithm \"%s\" received \"%s\"",
		    hashalg, sig_hashalg);
		r = SSH_ERR_SIGNATURE_INVALID;
		ಹೋಗು ಮುಗಿದ;
	}
	/* Ensure that RSA keys use an acceptable signature algorithm */
	ಆದರೆ (sshkey_type_plain(ಕೀಲಿ->type) == ಕೀಲಿ_RSA) {
		ಆದರೆ ((r = sshkey_get_sigtype(sig, siglen, &sigtype)) != 0) {
			error_r(r, "Couldn't verify signature: unable to get "
			    "signature type");
			ಹೋಗು ಮುಗಿದ;
		}
		ಆದರೆ (ಹೊಂದಿಕೆ_ನಮೂನೆ_list(sigtype, RSA_SIGN_ALLOWED, 0) != 1) {
			error("Couldn't verify signature: unsupported RSA "
			    "signature algorithm %s", sigtype);
			r = SSH_ERR_SIGN_ALG_UNSUPPORTED;
			ಹೋಗು ಮುಗಿದ;
		}
	}
	ಆದರೆ ((r = sshkey_verify(ಕೀಲಿ, sig, siglen, sshbuf_ptr(toverify),
	    sshbuf_len(toverify), ಖಾಲಿ, 0, sig_details)) != 0) {
		error_r(r, "Signature verification failed");
		ಹೋಗು ಮುಗಿದ;
	}

	/* success */
	r = 0;
	ಆದರೆ (sign_keyp != ಖಾಲಿ) {
		*sign_keyp = ಕೀಲಿ;
		ಕೀಲಿ = ಖಾಲಿ; /* transferred */
	}
ಮುಗಿದ:
	ಬಿಡುಗಡೆ(got_namespace);
	ಬಿಡುಗಡೆ(sigtype);
	ಬಿಡುಗಡೆ(sig_hashalg);
	sshbuf_free(buf);
	sshbuf_free(toverify);
	sshkey_free(ಕೀಲಿ);
	ಹಿಂತಿರುಗಿ r;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
hash_ಬಫರ್(ಸ್ಥಿರಾಂಕ ರಚನೆ sshbuf *m, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *hashalg, ರಚನೆ sshbuf **bp)
{
	ಅಕ್ಷರ *hex, hash[SSH_DIGEST_MAX_ಉದ್ದಳತೆ];
	ಪೂರ್ಣಾಂಕ alg, r = SSH_ERR_ಆಂತರಿಕ_ERROR;
	ರಚನೆ sshbuf *b = ಖಾಲಿ;

	*bp = ಖಾಲಿ;
	memset(hash, 0, ಗಾತ್ರ(hash));

	ಆದರೆ ((r = sshsig_check_hashalg(hashalg)) != 0)
		ಹಿಂತಿರುಗಿ r;
	ಆದರೆ ((alg = ssh_digest_alg_by_name(hashalg)) == -1) {
		error_f("can't look up hash algorithm %s", hashalg);
		ಹಿಂತಿರುಗಿ SSH_ERR_ಆಂತರಿಕ_ERROR;
	}
	ಆದರೆ ((r = ssh_digest_ಬಫರ್(alg, m, hash, ಗಾತ್ರ(hash))) != 0) {
		error_fr(r, "ssh_digest_buffer");
		ಹಿಂತಿರುಗಿ r;
	}
	ಆದರೆ ((hex = tohex(hash, ssh_digest_ಬೈಟುಗಳು(alg))) != ಖಾಲಿ) {
		debug3_f("final hash: %s", hex);
		freezero(hex, ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(hex));
	}
	ಆದರೆ ((b = sshbuf_new()) == ಖಾಲಿ) {
		r = SSH_ERR_ALLOC_FAIL;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((r = sshbuf_put(b, hash, ssh_digest_ಬೈಟುಗಳು(alg))) != 0) {
		error_fr(r, "sshbuf_put");
		ಹೋಗು ಹೊರಹೋಗು;
	}
	*bp = b;
	b = ಖಾಲಿ; /* transferred */
	/* success */
	r = 0;
 ಹೊರಹೋಗು:
	sshbuf_free(b);
	explicit_bzero(hash, ಗಾತ್ರ(hash));
	ಹಿಂತಿರುಗಿ r;
}

ಪೂರ್ಣಾಂಕ
sshsig_signb(ರಚನೆ sshkey *ಕೀಲಿ, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *hashalg,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *sk_provider, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *sk_pin,
    ಸ್ಥಿರಾಂಕ ರಚನೆ sshbuf *ಸಂದೇಶ_2, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *sig_namespace,
    ರಚನೆ sshbuf **ಹೊರಹೋಗು, sshsig_signer *signer, ಶೂನ್ಯ *signer_ctx)
{
	ರಚನೆ sshbuf *b = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ r = SSH_ERR_ಆಂತರಿಕ_ERROR;

	ಆದರೆ (hashalg == ಖಾಲಿ)
		hashalg = HASHALG_DEFAULT;
	ಆದರೆ (ಹೊರಹೋಗು != ಖಾಲಿ)
		*ಹೊರಹೋಗು = ಖಾಲಿ;
	ಆದರೆ ((r = hash_ಬಫರ್(ಸಂದೇಶ_2, hashalg, &b)) != 0) {
		error_fr(r, "hash buffer");
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((r = sshsig_wrap_sign(ಕೀಲಿ, hashalg, sk_provider, sk_pin, b,
	    sig_namespace, ಹೊರಹೋಗು, signer, signer_ctx)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
	/* success */
	r = 0;
 ಹೊರಹೋಗು:
	sshbuf_free(b);
	ಹಿಂತಿರುಗಿ r;
}

ಪೂರ್ಣಾಂಕ
sshsig_verifyb(ರಚನೆ sshbuf *signature, ಸ್ಥಿರಾಂಕ ರಚನೆ sshbuf *ಸಂದೇಶ_2,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *expect_namespace, ರಚನೆ sshkey **sign_keyp,
    ರಚನೆ sshkey_sig_details **sig_details)
{
	ರಚನೆ sshbuf *b = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ r = SSH_ERR_ಆಂತರಿಕ_ERROR;
	ಅಕ್ಷರ *hashalg = ಖಾಲಿ;

	ಆದರೆ (sig_details != ಖಾಲಿ)
		*sig_details = ಖಾಲಿ;
	ಆದರೆ (sign_keyp != ಖಾಲಿ)
		*sign_keyp = ಖಾಲಿ;
	ಆದರೆ ((r = sshsig_peek_hashalg(signature, &hashalg)) != 0)
		ಹಿಂತಿರುಗಿ r;
	debug_f("signature made with hash \"%s\"", hashalg);
	ಆದರೆ ((r = hash_ಬಫರ್(ಸಂದೇಶ_2, hashalg, &b)) != 0) {
		error_fr(r, "hash buffer");
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((r = sshsig_wrap_verify(signature, hashalg, b, expect_namespace,
	    sign_keyp, sig_details)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
	/* success */
	r = 0;
 ಹೊರಹೋಗು:
	sshbuf_free(b);
	ಬಿಡುಗಡೆ(hashalg);
	ಹಿಂತಿರುಗಿ r;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
hash_file(ಪೂರ್ಣಾಂಕ fd, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *hashalg, ರಚನೆ sshbuf **bp)
{
	ಅಕ್ಷರ *hex, rbuf[8192], hash[SSH_DIGEST_MAX_ಉದ್ದಳತೆ];
	ssize_t n, ಒಟ್ಟು = 0;
	ರಚನೆ ssh_digest_ctx *ctx = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ alg, oerrno, r = SSH_ERR_ಆಂತರಿಕ_ERROR;
	ರಚನೆ sshbuf *b = ಖಾಲಿ;

	*bp = ಖಾಲಿ;
	memset(hash, 0, ಗಾತ್ರ(hash));

	ಆದರೆ ((r = sshsig_check_hashalg(hashalg)) != 0)
		ಹಿಂತಿರುಗಿ r;
	ಆದರೆ ((alg = ssh_digest_alg_by_name(hashalg)) == -1) {
		error_f("can't look up hash algorithm %s", hashalg);
		ಹಿಂತಿರುಗಿ SSH_ERR_ಆಂತರಿಕ_ERROR;
	}
	ಆದರೆ ((ctx = ssh_digest_ಆರಂಭ(alg)) == ಖಾಲಿ) {
		error_f("ssh_digest_start failed");
		ಹಿಂತಿರುಗಿ SSH_ERR_ಆಂತರಿಕ_ERROR;
	}
	ಗಾಗಿ (;;) {
		ಆದರೆ ((n = ಪಠ(fd, rbuf, ಗಾತ್ರ(rbuf))) == -1) {
			ಆದರೆ (errno == EINTR || errno == EAGAIN)
				ಮುಂದುವರಿ;
			oerrno = errno;
			error_f("read: %s", strerror(errno));
			errno = oerrno;
			r = SSH_ERR_SYSTEM_ERROR;
			ಹೋಗು ಹೊರಹೋಗು;
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (n == 0) {
			debug2_f("hashed %zu bytes", ಒಟ್ಟು);
			ನಿಲ್ಲಿಸು; /* EOF */
		}
		ಒಟ್ಟು += (ಗಾತ್ರ_t)n;
		ಆದರೆ ((r = ssh_digest_update(ctx, rbuf, (ಗಾತ್ರ_t)n)) != 0) {
			error_fr(r, "ssh_digest_update");
			ಹೋಗು ಹೊರಹೋಗು;
		}
	}
	ಆದರೆ ((r = ssh_digest_final(ctx, hash, ಗಾತ್ರ(hash))) != 0) {
		error_fr(r, "ssh_digest_final");
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((hex = tohex(hash, ssh_digest_ಬೈಟುಗಳು(alg))) != ಖಾಲಿ) {
		debug3_f("final hash: %s", hex);
		freezero(hex, ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(hex));
	}
	ಆದರೆ ((b = sshbuf_new()) == ಖಾಲಿ) {
		r = SSH_ERR_ALLOC_FAIL;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((r = sshbuf_put(b, hash, ssh_digest_ಬೈಟುಗಳು(alg))) != 0) {
		error_fr(r, "sshbuf_put");
		ಹೋಗು ಹೊರಹೋಗು;
	}
	*bp = b;
	b = ಖಾಲಿ; /* transferred */
	/* success */
	r = 0;
 ಹೊರಹೋಗು:
	oerrno = errno;
	sshbuf_free(b);
	ssh_digest_free(ctx);
	explicit_bzero(hash, ಗಾತ್ರ(hash));
	errno = oerrno;
	ಹಿಂತಿರುಗಿ r;
}

ಪೂರ್ಣಾಂಕ
sshsig_sign_fd(ರಚನೆ sshkey *ಕೀಲಿ, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *hashalg,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *sk_provider, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *sk_pin,
    ಪೂರ್ಣಾಂಕ fd, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *sig_namespace, ರಚನೆ sshbuf **ಹೊರಹೋಗು,
    sshsig_signer *signer, ಶೂನ್ಯ *signer_ctx)
{
	ರಚನೆ sshbuf *b = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ r = SSH_ERR_ಆಂತರಿಕ_ERROR;

	ಆದರೆ (hashalg == ಖಾಲಿ)
		hashalg = HASHALG_DEFAULT;
	ಆದರೆ (ಹೊರಹೋಗು != ಖಾಲಿ)
		*ಹೊರಹೋಗು = ಖಾಲಿ;
	ಆದರೆ ((r = hash_file(fd, hashalg, &b)) != 0) {
		error_fr(r, "hash_file");
		ಹಿಂತಿರುಗಿ r;
	}
	ಆದರೆ ((r = sshsig_wrap_sign(ಕೀಲಿ, hashalg, sk_provider, sk_pin, b,
	    sig_namespace, ಹೊರಹೋಗು, signer, signer_ctx)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
	/* success */
	r = 0;
 ಹೊರಹೋಗು:
	sshbuf_free(b);
	ಹಿಂತಿರುಗಿ r;
}

ಪೂರ್ಣಾಂಕ
sshsig_verify_fd(ರಚನೆ sshbuf *signature, ಪೂರ್ಣಾಂಕ fd,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *expect_namespace, ರಚನೆ sshkey **sign_keyp,
    ರಚನೆ sshkey_sig_details **sig_details)
{
	ರಚನೆ sshbuf *b = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ r = SSH_ERR_ಆಂತರಿಕ_ERROR;
	ಅಕ್ಷರ *hashalg = ಖಾಲಿ;

	ಆದರೆ (sig_details != ಖಾಲಿ)
		*sig_details = ಖಾಲಿ;
	ಆದರೆ (sign_keyp != ಖಾಲಿ)
		*sign_keyp = ಖಾಲಿ;
	ಆದರೆ ((r = sshsig_peek_hashalg(signature, &hashalg)) != 0)
		ಹಿಂತಿರುಗಿ r;
	debug_f("signature made with hash \"%s\"", hashalg);
	ಆದರೆ ((r = hash_file(fd, hashalg, &b)) != 0) {
		error_fr(r, "hash_file");
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((r = sshsig_wrap_verify(signature, hashalg, b, expect_namespace,
	    sign_keyp, sig_details)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
	/* success */
	r = 0;
 ಹೊರಹೋಗು:
	sshbuf_free(b);
	ಬಿಡುಗಡೆ(hashalg);
	ಹಿಂತಿರುಗಿ r;
}

ರಚನೆ sshsigopt {
	ಪೂರ್ಣಾಂಕ ca;
	ಅಕ್ಷರ *namespaces;
	uint64_t valid_after, valid_before;
};

ರಚನೆ sshsigopt *
sshsigopt_parse(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *opts, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಮಾರ್ಗ, u_long linenum,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ **errstrp)
{
	ರಚನೆ sshsigopt *ret;
	ಪೂರ್ಣಾಂಕ r;
	ಅಕ್ಷರ *opt;
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *errstr = ಖಾಲಿ;

	ಆದರೆ ((ret = ಸೊನ್ನೆ_ಸ್ಮರಣೆ_ಕೊಡು(1, ಗಾತ್ರ(*ret))) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;
	ಆದರೆ (opts == ಖಾಲಿ || *opts == '\0')
		ಹಿಂತಿರುಗಿ ret; /* Empty options yields empty options :) */

	ಆಗ (*opts && *opts != ' ' && *opts != '\t') {
		/* flag options */
		ಆದರೆ ((r = opt_flag("cert-authority", 0, &opts)) != -1) {
			ret->ca = 1;
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (opt_ಹೊಂದಿಕೆ(&opts, "namespaces")) {
			ಆದರೆ (ret->namespaces != ಖಾಲಿ) {
				errstr = "multiple \"namespaces\" clauses";
				ಹೋಗು fail;
			}
			ret->namespaces = opt_dequote(&opts, &errstr);
			ಆದರೆ (ret->namespaces == ಖಾಲಿ)
				ಹೋಗು fail;
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (opt_ಹೊಂದಿಕೆ(&opts, "valid-after")) {
			ಆದರೆ (ret->valid_after != 0) {
				errstr = "multiple \"valid-after\" clauses";
				ಹೋಗು fail;
			}
			ಆದರೆ ((opt = opt_dequote(&opts, &errstr)) == ಖಾಲಿ)
				ಹೋಗು fail;
			ಆದರೆ (parse_absolute_ಸಮಯ(opt, &ret->valid_after) != 0 ||
			    ret->valid_after == 0) {
				ಬಿಡುಗಡೆ(opt);
				errstr = "invalid \"valid-after\" time";
				ಹೋಗು fail;
			}
			ಬಿಡುಗಡೆ(opt);
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (opt_ಹೊಂದಿಕೆ(&opts, "valid-before")) {
			ಆದರೆ (ret->valid_before != 0) {
				errstr = "multiple \"valid-before\" clauses";
				ಹೋಗು fail;
			}
			ಆದರೆ ((opt = opt_dequote(&opts, &errstr)) == ಖಾಲಿ)
				ಹೋಗು fail;
			ಆದರೆ (parse_absolute_ಸಮಯ(opt, &ret->valid_before) != 0 ||
			    ret->valid_before == 0) {
				ಬಿಡುಗಡೆ(opt);
				errstr = "invalid \"valid-before\" time";
				ಹೋಗು fail;
			}
			ಬಿಡುಗಡೆ(opt);
		}
		/*
		 * Skip the comma, and move to the next option
		 * (or break out if there are no more).
		 */
		ಆದರೆ (*opts == '\0' || *opts == ' ' || *opts == '\t')
			ನಿಲ್ಲಿಸು;		/* End of options. */
		/* Anything other than a comma is an unknown option */
		ಆದರೆ (*opts != ',') {
			errstr = "unknown key option";
			ಹೋಗು fail;
		}
		opts++;
		ಆದರೆ (*opts == '\0') {
			errstr = "unexpected end-of-options";
			ಹೋಗು fail;
		}
	}
	/* final consistency check */
	ಆದರೆ (ret->valid_after != 0 && ret->valid_before != 0 &&
	    ret->valid_before <= ret->valid_after) {
		errstr = "\"valid-before\" time is before \"valid-after\"";
		ಹೋಗು fail;
	}
	/* success */
	ಹಿಂತಿರುಗಿ ret;
 fail:
	ಆದರೆ (errstrp != ಖಾಲಿ)
		*errstrp = errstr;
	sshsigopt_free(ret);
	ಹಿಂತಿರುಗಿ ಖಾಲಿ;
}

ಶೂನ್ಯ
sshsigopt_free(ರಚನೆ sshsigopt *opts)
{
	ಆದರೆ (opts == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ;
	ಬಿಡುಗಡೆ(opts->namespaces);
	ಬಿಡುಗಡೆ(opts);
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
parse_principals_ಕೀಲಿ_and_options(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಮಾರ್ಗ, u_long linenum, ಅಕ್ಷರ *ಸಾಲು,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *required_principal, ಅಕ್ಷರ **principalsp, ರಚನೆ sshkey **keyp,
    ರಚನೆ sshsigopt **sigoptsp)
{
	ಅಕ್ಷರ *opts = ಖಾಲಿ, *tmp, *cp, *principals = ಖಾಲಿ;
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *reason = ಖಾಲಿ;
	ರಚನೆ sshsigopt *sigopts = ಖಾಲಿ;
	ರಚನೆ sshkey *ಕೀಲಿ = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ r = SSH_ERR_ಆಂತರಿಕ_ERROR;

	ಆದರೆ (principalsp != ಖಾಲಿ)
		*principalsp = ಖಾಲಿ;
	ಆದರೆ (sigoptsp != ಖಾಲಿ)
		*sigoptsp = ಖಾಲಿ;
	ಆದರೆ (keyp != ಖಾಲಿ)
		*keyp = ಖಾಲಿ;

	cp = ಸಾಲು;
	cp = cp + strspn(cp, " \t\n\r"); /* skip leading whitespace */
	ಆದರೆ (*cp == '#' || *cp == '\0')
		ಹಿಂತಿರುಗಿ SSH_ERR_ಕೀಲಿ_NOT_ಸಿಕ್ಕಿತು; /* blank or all-comment line */

	/* format: identity[,identity...] [option[,option...]] key */
	ಆದರೆ ((tmp = strdelimw(&cp)) == ಖಾಲಿ || cp == ಖಾಲಿ) {
		error("%s:%lu: invalid line", ಮಾರ್ಗ, linenum);
		r = SSH_ERR_INVALID_FORMAT;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((principals = strdup(tmp)) == ಖಾಲಿ) {
		error_f("strdup failed");
		r = SSH_ERR_ALLOC_FAIL;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	/*
	 * Bail out early if we're looking for a particular principal and this
	 * line does not list it.
	 */
	ಆದರೆ (required_principal != ಖಾಲಿ) {
		ಆದರೆ (ಹೊಂದಿಕೆ_ನಮೂನೆ_list(required_principal,
		    principals, 0) != 1) {
			/* principal didn't match */
			r = SSH_ERR_ಕೀಲಿ_NOT_ಸಿಕ್ಕಿತು;
			ಹೋಗು ಹೊರಹೋಗು;
		}
		debug_f("%s:%lu: matched principal \"%s\"",
		    ಮಾರ್ಗ, linenum, required_principal);
	}

	ಆದರೆ ((ಕೀಲಿ = sshkey_new(ಕೀಲಿ_UNSPEC)) == ಖಾಲಿ) {
		error_f("sshkey_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ (sshkey_read(ಕೀಲಿ, &cp) != 0) {
		/* no key? Check for options */
		opts = cp;
		ಆದರೆ (sshkey_advance_past_options(&cp) != 0) {
			error("%s:%lu: invalid options", ಮಾರ್ಗ, linenum);
			r = SSH_ERR_INVALID_FORMAT;
			ಹೋಗು ಹೊರಹೋಗು;
		}
		ಆದರೆ (cp == ಖಾಲಿ || *cp == '\0') {
			error("%s:%lu: missing key", ಮಾರ್ಗ, linenum);
			r = SSH_ERR_INVALID_FORMAT;
			ಹೋಗು ಹೊರಹೋಗು;
		}
		*cp++ = '\0';
		skip_space(&cp);
		ಆದರೆ (sshkey_read(ಕೀಲಿ, &cp) != 0) {
			error("%s:%lu: invalid key", ಮಾರ್ಗ, linenum);
			r = SSH_ERR_INVALID_FORMAT;
			ಹೋಗು ಹೊರಹೋಗು;
		}
	}
	debug3("%s:%lu: options %s", ಮಾರ್ಗ, linenum, opts == ಖಾಲಿ ? "" : opts);
	ಆದರೆ ((sigopts = sshsigopt_parse(opts, ಮಾರ್ಗ, linenum, &reason)) == ಖಾಲಿ) {
		error("%s:%lu: bad options: %s", ಮಾರ್ಗ, linenum, reason);
		r = SSH_ERR_INVALID_FORMAT;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	/* success */
	ಆದರೆ (principalsp != ಖಾಲಿ) {
		*principalsp = principals;
		principals = ಖಾಲಿ; /* transferred */
	}
	ಆದರೆ (sigoptsp != ಖಾಲಿ) {
		*sigoptsp = sigopts;
		sigopts = ಖಾಲಿ; /* transferred */
	}
	ಆದರೆ (keyp != ಖಾಲಿ) {
		*keyp = ಕೀಲಿ;
		ಕೀಲಿ = ಖಾಲಿ; /* transferred */
	}
	r = 0;
 ಹೊರಹೋಗು:
	ಬಿಡುಗಡೆ(principals);
	sshsigopt_free(sigopts);
	sshkey_free(ಕೀಲಿ);
	ಹಿಂತಿರುಗಿ r;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
cert_filter_principals(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಮಾರ್ಗ, u_long linenum,
    ಅಕ್ಷರ **principalsp, ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *cert, uint64_t verify_ಸಮಯ)
{
	ಅಕ್ಷರ *cp, *oprincipals, *principals;
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *reason;
	ರಚನೆ sshbuf *nprincipals;
	ಪೂರ್ಣಾಂಕ r = SSH_ERR_ಆಂತರಿಕ_ERROR, success = 0;
	u_int i;

	oprincipals = principals = *principalsp;
	*principalsp = ಖಾಲಿ;

	ಆದರೆ ((nprincipals = sshbuf_new()) == ಖಾಲಿ) {
		r = SSH_ERR_ALLOC_FAIL;
		ಹೋಗು ಹೊರಹೋಗು;
	}

	ಆಗ ((cp = strsep(&principals, ",")) != ಖಾಲಿ && *cp != '\0') {
		/* Check certificate validity */
		ಆದರೆ ((r = sshkey_cert_check_authority(cert, 0, 0, verify_ಸಮಯ,
		    ಖಾಲಿ, &reason)) != 0) {
			debug("%s:%lu: principal \"%s\" not authorized: %s",
			    ಮಾರ್ಗ, linenum, cp, reason);
			ಮುಂದುವರಿ;
		}
		/* Return all matching principal names from the cert */
		ಗಾಗಿ (i = 0; i < cert->cert->nprincipals; i++) {
			ಆದರೆ (ಹೊಂದಿಕೆ_ನಮೂನೆ(cert->cert->principals[i], cp)) {
				ಆದರೆ ((r = sshbuf_putf(nprincipals, "%s%s",
					sshbuf_len(nprincipals) != 0 ? "," : "",
						cert->cert->principals[i])) != 0) {
					error_f("buffer error");
					ಹೋಗು ಹೊರಹೋಗು;
				}
			}
		}
	}
	ಆದರೆ (sshbuf_len(nprincipals) == 0) {
		error("%s:%lu: no valid principals found", ಮಾರ್ಗ, linenum);
		r = SSH_ERR_ಕೀಲಿ_CERT_INVALID;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((principals = sshbuf_dup_string(nprincipals)) == ಖಾಲಿ) {
		error_f("buffer error");
		r = SSH_ERR_ALLOC_FAIL;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	/* success */
	success = 1;
	*principalsp = principals;
 ಹೊರಹೋಗು:
	sshbuf_free(nprincipals);
	ಬಿಡುಗಡೆ(oprincipals);
	ಹಿಂತಿರುಗಿ success ? 0 : r;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
check_allowed_ಕೀಲಿಗಳು_ಸಾಲು(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಮಾರ್ಗ, u_long linenum, ಅಕ್ಷರ *ಸಾಲು,
    ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *sign_ಕೀಲಿ, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *principal,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *sig_namespace, uint64_t verify_ಸಮಯ, ಅಕ್ಷರ **principalsp)
{
	ರಚನೆ sshkey *ಸಿಕ್ಕಿತು_ಕೀಲಿ = ಖಾಲಿ;
	ಅಕ್ಷರ *principals = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ r, success = 0;
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *reason = ಖಾಲಿ;
	ರಚನೆ sshsigopt *sigopts = ಖಾಲಿ;
	ಅಕ್ಷರ tvalid[64], tverify[64];

	ಆದರೆ (principalsp != ಖಾಲಿ)
		*principalsp = ಖಾಲಿ;

	/* Parse the line */
	ಆದರೆ ((r = parse_principals_ಕೀಲಿ_and_options(ಮಾರ್ಗ, linenum, ಸಾಲು,
	    principal, &principals, &ಸಿಕ್ಕಿತು_ಕೀಲಿ, &sigopts)) != 0) {
		/* error already logged */
		ಹೋಗು ಮುಗಿದ;
	}

	ಆದರೆ (!sigopts->ca && sshkey_equal(ಸಿಕ್ಕಿತು_ಕೀಲಿ, sign_ಕೀಲಿ)) {
		/* Exact match of key */
		debug("%s:%lu: matched key", ಮಾರ್ಗ, linenum);
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (sigopts->ca && sshkey_is_cert(sign_ಕೀಲಿ) &&
	    sshkey_equal_ಬಹಿರಂಗ(sign_ಕೀಲಿ->cert->signature_ಕೀಲಿ, ಸಿಕ್ಕಿತು_ಕೀಲಿ)) {
		ಆದರೆ (principal) {
			/* Match certificate CA key with specified principal */
			ಆದರೆ ((r = sshkey_cert_check_authority(sign_ಕೀಲಿ, 0, 0,
			    verify_ಸಮಯ, principal, &reason)) != 0) {
				error("%s:%lu: certificate not authorized: %s",
				    ಮಾರ್ಗ, linenum, reason);
				ಹೋಗು ಮುಗಿದ;
			}
			debug("%s:%lu: matched certificate CA key",
			    ಮಾರ್ಗ, linenum);
		} ಇಲ್ಲದಿದ್ದರೆ {
			/* No principal specified - find all matching ones */
			ಆದರೆ ((r = cert_filter_principals(ಮಾರ್ಗ, linenum,
			    &principals, sign_ಕೀಲಿ, verify_ಸಮಯ)) != 0) {
				/* error already displayed */
				debug_r(r, "%s:%lu: cert_filter_principals",
				    ಮಾರ್ಗ, linenum);
				ಹೋಗು ಮುಗಿದ;
			}
			debug("%s:%lu: matched certificate CA key",
			    ಮಾರ್ಗ, linenum);
		}
	} ಇಲ್ಲದಿದ್ದರೆ {
		/* Didn't match key */
		ಹೋಗು ಮುಗಿದ;
	}

	/* Check whether options preclude the use of this key */
	ಆದರೆ (sigopts->namespaces != ಖಾಲಿ && sig_namespace != ಖಾಲಿ &&
	    ಹೊಂದಿಕೆ_ನಮೂನೆ_list(sig_namespace, sigopts->namespaces, 0) != 1) {
		error("%s:%lu: key is not permitted for use in signature "
		    "namespace \"%s\"", ಮಾರ್ಗ, linenum, sig_namespace);
		ಹೋಗು ಮುಗಿದ;
	}

	/* check key time validity */
	format_absolute_ಸಮಯ((uint64_t)verify_ಸಮಯ, tverify, ಗಾತ್ರ(tverify));
	ಆದರೆ (sigopts->valid_after != 0 &&
	    (uint64_t)verify_ಸಮಯ < sigopts->valid_after) {
		format_absolute_ಸಮಯ(sigopts->valid_after,
		    tvalid, ಗಾತ್ರ(tvalid));
		error("%s:%lu: key is not yet valid: "
		    "verify time %s < valid-after %s", ಮಾರ್ಗ, linenum,
		    tverify, tvalid);
		ಹೋಗು ಮುಗಿದ;
	}
	ಆದರೆ (sigopts->valid_before != 0 &&
	    (uint64_t)verify_ಸಮಯ > sigopts->valid_before) {
		format_absolute_ಸಮಯ(sigopts->valid_before,
		    tvalid, ಗಾತ್ರ(tvalid));
		error("%s:%lu: key has expired: "
		    "verify time %s > valid-before %s", ಮಾರ್ಗ, linenum,
		    tverify, tvalid);
		ಹೋಗು ಮುಗಿದ;
	}
	success = 1;

 ಮುಗಿದ:
	ಆದರೆ (success && principalsp != ಖಾಲಿ) {
		*principalsp = principals;
		principals = ಖಾಲಿ; /* transferred */
	}
	ಬಿಡುಗಡೆ(principals);
	sshkey_free(ಸಿಕ್ಕಿತು_ಕೀಲಿ);
	sshsigopt_free(sigopts);
	ಹಿಂತಿರುಗಿ success ? 0 : SSH_ERR_ಕೀಲಿ_NOT_ಸಿಕ್ಕಿತು;
}

ಪೂರ್ಣಾಂಕ
sshsig_check_allowed_ಕೀಲಿಗಳು(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಮಾರ್ಗ, ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *sign_ಕೀಲಿ,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *principal, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *sig_namespace, uint64_t verify_ಸಮಯ)
{
	FILE *f = ಖಾಲಿ;
	ಅಕ್ಷರ *ಸಾಲು = ಖಾಲಿ;
	ಗಾತ್ರ_t linesize = 0;
	u_long linenum = 0;
	ಪೂರ್ಣಾಂಕ r = SSH_ERR_ಕೀಲಿ_NOT_ಸಿಕ್ಕಿತು, oerrno;

	/* Check key and principal against file */
	ಆದರೆ ((f = fopen(ಮಾರ್ಗ, "r")) == ಖಾಲಿ) {
		oerrno = errno;
		error("Unable to open allowed keys file \"%s\": %s",
		    ಮಾರ್ಗ, strerror(errno));
		errno = oerrno;
		ಹಿಂತಿರುಗಿ SSH_ERR_SYSTEM_ERROR;
	}

	ಆಗ (getline(&ಸಾಲು, &linesize, f) != -1) {
		linenum++;
		r = check_allowed_ಕೀಲಿಗಳು_ಸಾಲು(ಮಾರ್ಗ, linenum, ಸಾಲು, sign_ಕೀಲಿ,
		    principal, sig_namespace, verify_ಸಮಯ, ಖಾಲಿ);
		ಬಿಡುಗಡೆ(ಸಾಲು);
		ಸಾಲು = ಖಾಲಿ;
		linesize = 0;
		ಆದರೆ (r == SSH_ERR_ಕೀಲಿ_NOT_ಸಿಕ್ಕಿತು)
			ಮುಂದುವರಿ;
		ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (r == 0) {
			/* success */
			fclose(f);
			ಹಿಂತಿರುಗಿ 0;
		} ಇಲ್ಲದಿದ್ದರೆ
			ನಿಲ್ಲಿಸು;
	}
	/* Either we hit an error parsing or we simply didn't find the key */
	fclose(f);
	ಬಿಡುಗಡೆ(ಸಾಲು);
	ಹಿಂತಿರುಗಿ r;
}

ಪೂರ್ಣಾಂಕ
sshsig_ಕಂಡುಹಿಡಿ_principals(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಮಾರ್ಗ, ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *sign_ಕೀಲಿ,
    uint64_t verify_ಸಮಯ, ಅಕ್ಷರ **principals)
{
	FILE *f = ಖಾಲಿ;
	ಅಕ್ಷರ *ಸಾಲು = ಖಾಲಿ;
	ಗಾತ್ರ_t linesize = 0;
	u_long linenum = 0;
	ಪೂರ್ಣಾಂಕ r = SSH_ERR_ಕೀಲಿ_NOT_ಸಿಕ್ಕಿತು, oerrno;

	ಆದರೆ ((f = fopen(ಮಾರ್ಗ, "r")) == ಖಾಲಿ) {
		oerrno = errno;
		error("Unable to open allowed keys file \"%s\": %s",
		    ಮಾರ್ಗ, strerror(errno));
		errno = oerrno;
		ಹಿಂತಿರುಗಿ SSH_ERR_SYSTEM_ERROR;
	}

	ಆಗ (getline(&ಸಾಲು, &linesize, f) != -1) {
		linenum++;
		r = check_allowed_ಕೀಲಿಗಳು_ಸಾಲು(ಮಾರ್ಗ, linenum, ಸಾಲು,
		    sign_ಕೀಲಿ, ಖಾಲಿ, ಖಾಲಿ, verify_ಸಮಯ, principals);
		ಬಿಡುಗಡೆ(ಸಾಲು);
		ಸಾಲು = ಖಾಲಿ;
		linesize = 0;
		ಆದರೆ (r == SSH_ERR_ಕೀಲಿ_NOT_ಸಿಕ್ಕಿತು)
			ಮುಂದುವರಿ;
		ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (r == 0) {
			/* success */
			fclose(f);
			ಹಿಂತಿರುಗಿ 0;
		} ಇಲ್ಲದಿದ್ದರೆ
			ನಿಲ್ಲಿಸು;
	}
	ಬಿಡುಗಡೆ(ಸಾಲು);
	/* Either we hit an error parsing or we simply didn't find the key */
	ಆದರೆ (ferror(f) != 0) {
		oerrno = errno;
		fclose(f);
		error("Unable to read allowed keys file \"%s\": %s",
		    ಮಾರ್ಗ, strerror(errno));
		errno = oerrno;
		ಹಿಂತಿರುಗಿ SSH_ERR_SYSTEM_ERROR;
	}
	fclose(f);
	ಹಿಂತಿರುಗಿ r;
}

ಪೂರ್ಣಾಂಕ
sshsig_ಹೊಂದಿಕೆ_principals(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಮಾರ್ಗ, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *principal,
    ಅಕ್ಷರ ***principalsp, ಗಾತ್ರ_t *nprincipalsp)
{
	FILE *f = ಖಾಲಿ;
	ಅಕ್ಷರ *ಸಿಕ್ಕಿತು, *ಸಾಲು = ಖಾಲಿ, **principals = ಖಾಲಿ, **tmp;
	ಗಾತ್ರ_t i, nprincipals = 0, linesize = 0;
	u_long linenum = 0;
	ಪೂರ್ಣಾಂಕ oerrno = 0, r, ret = 0;

	ಆದರೆ (principalsp != ಖಾಲಿ)
		*principalsp = ಖಾಲಿ;
	ಆದರೆ (nprincipalsp != ಖಾಲಿ)
		*nprincipalsp = 0;

	/* Check key and principal against file */
	ಆದರೆ ((f = fopen(ಮಾರ್ಗ, "r")) == ಖಾಲಿ) {
		oerrno = errno;
		error("Unable to open allowed keys file \"%s\": %s",
		    ಮಾರ್ಗ, strerror(errno));
		errno = oerrno;
		ಹಿಂತಿರುಗಿ SSH_ERR_SYSTEM_ERROR;
	}

	ಆಗ (getline(&ಸಾಲು, &linesize, f) != -1) {
		linenum++;
		/* Parse the line */
		ಆದರೆ ((r = parse_principals_ಕೀಲಿ_and_options(ಮಾರ್ಗ, linenum, ಸಾಲು,
		    principal, &ಸಿಕ್ಕಿತು, ಖಾಲಿ, ಖಾಲಿ)) != 0) {
			ಆದರೆ (r == SSH_ERR_ಕೀಲಿ_NOT_ಸಿಕ್ಕಿತು)
				ಮುಂದುವರಿ;
			ret = r;
			oerrno = errno;
			ನಿಲ್ಲಿಸು; /* unexpected error */
		}
		ಆದರೆ ((tmp = recallocarray(principals, nprincipals,
		    nprincipals + 1, ಗಾತ್ರ(*principals))) == ಖಾಲಿ) {
			ret = SSH_ERR_ALLOC_FAIL;
			ಬಿಡುಗಡೆ(ಸಿಕ್ಕಿತು);
			ನಿಲ್ಲಿಸು;
		}
		principals = tmp;
		principals[nprincipals++] = ಸಿಕ್ಕಿತು; /* transferred */
		ಬಿಡುಗಡೆ(ಸಾಲು);
		ಸಾಲು = ಖಾಲಿ;
		linesize = 0;
	}
	fclose(f);
	ಬಿಡುಗಡೆ(ಸಾಲು);

	ಆದರೆ (ret == 0) {
		ಆದರೆ (nprincipals == 0)
			ret = SSH_ERR_ಕೀಲಿ_NOT_ಸಿಕ್ಕಿತು;
		ಆದರೆ (nprincipalsp != ಖಾಲಿ)
			*nprincipalsp = nprincipals;
		ಆದರೆ (principalsp != ಖಾಲಿ) {
			*principalsp = principals;
			principals = ಖಾಲಿ; /* transferred */
			nprincipals = 0;
		}
	}

	ಗಾಗಿ (i = 0; i < nprincipals; i++)
		ಬಿಡುಗಡೆ(principals[i]);
	ಬಿಡುಗಡೆ(principals);

	errno = oerrno;
	ಹಿಂತಿರುಗಿ ret;
}

ಪೂರ್ಣಾಂಕ
sshsig_get_pubkey(ರಚನೆ sshbuf *signature, ರಚನೆ sshkey **pubkey)
{
	ರಚನೆ sshkey *pk = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ r = SSH_ERR_SIGNATURE_INVALID;

	ಆದರೆ (pubkey == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ SSH_ERR_ಆಂತರಿಕ_ERROR;
	ಆದರೆ ((r = sshsig_parse_preamble(signature)) != 0)
		ಹಿಂತಿರುಗಿ r;
	ಆದರೆ ((r = sshkey_froms(signature, &pk)) != 0)
		ಹಿಂತಿರುಗಿ r;

	*pubkey = pk;
	pk = ಖಾಲಿ;
	ಹಿಂತಿರುಗಿ 0;
}
