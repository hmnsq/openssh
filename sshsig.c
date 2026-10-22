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

#define SIG_VERSION		0x01
#define MAGIC_PREAMBLE		"SSHSIG"
#define MAGIC_PREAMBLE_LEN	(ಪರಿಮಾಣ(MAGIC_PREAMBLE) - 1)
#define BEGIN_SIGNATURE		"-----BEGIN SSH SIGNATURE-----"
#define END_SIGNATURE		"-----END SSH SIGNATURE-----"
#define RSA_SIGN_ALG		"rsa-sha2-512"
#define RSA_SIGN_ALLOWED	"rsa-sha2-512,rsa-sha2-256"
#define HASHALG_DEFAULT		"sha512"
#define HASHALG_ALLOWED		"sha256,sha512"

ಪೂರ್ಣಾಙ್ಕ
sshsig_armor(ಧ್ರುವ ಸಂರಚನಾ sshbuf *blob, ಸಂರಚನಾ sshbuf **out)
{
	ಸಂರಚನಾ sshbuf *buf = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ r = SSH_ERR_INTERNAL_ERROR;

	*out = ರಿಕ್ತ;

	ಯದಿ ((buf = sshbuf_new()) == ರಿಕ್ತ) {
		error_f("sshbuf_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		ಗಚ್ಛ out;
	}

	ಯದಿ ((r = sshbuf_putf(buf, "%s\n", BEGIN_SIGNATURE)) != 0) {
		error_fr(r, "sshbuf_putf");
		ಗಚ್ಛ out;
	}

	ಯದಿ ((r = sshbuf_dtob64(blob, buf, 1)) != 0) {
		error_fr(r, "base64 encode signature");
		ಗಚ್ಛ out;
	}

	ಯದಿ ((r = sshbuf_put(buf, END_SIGNATURE,
	    ಪರಿಮಾಣ(END_SIGNATURE)-1)) != 0 ||
	    (r = sshbuf_put_u8(buf, '\n')) != 0) {
		error_fr(r, "sshbuf_put");
		ಗಚ್ಛ out;
	}
	/* success */
	*out = buf;
	buf = ರಿಕ್ತ; /* transferred */
	r = 0;
 out:
	sshbuf_free(buf);
	ಪ್ರತ್ಯಾಗಮ r;
}

ಪೂರ್ಣಾಙ್ಕ
sshsig_dearmor(ಸಂರಚನಾ sshbuf *sig, ಸಂರಚನಾ sshbuf **out)
{
	ಪೂರ್ಣಾಙ್ಕ r;
	size_t eoffset = 0;
	ಸಂರಚನಾ sshbuf *buf = ರಿಕ್ತ;
	ಸಂರಚನಾ sshbuf *sbuf = ರಿಕ್ತ;
	ವರ್ಣ *b64 = ರಿಕ್ತ;

	ಯದಿ ((sbuf = sshbuf_fromb(sig)) == ರಿಕ್ತ) {
		error_f("sshbuf_fromb failed");
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_ALLOC_FAIL;
	}

	/* Expect and consume preamble + lf/crlf */
	ಯದಿ ((r = sshbuf_cmp(sbuf, 0,
	    BEGIN_SIGNATURE, ಪರಿಮಾಣ(BEGIN_SIGNATURE)-1)) != 0) {
		error("Couldn't parse signature: missing header");
		ಗಚ್ಛ done;
	}
	ಯದಿ ((r = sshbuf_consume(sbuf, ಪರಿಮಾಣ(BEGIN_SIGNATURE)-1)) != 0) {
		error_fr(r, "consume");
		ಗಚ್ಛ done;
	}
	ಯದಿ ((r = sshbuf_cmp(sbuf, 0, "\r\n", 2)) == 0)
		eoffset = 2;
	ಅನ್ಯಥಾ ಯದಿ ((r = sshbuf_cmp(sbuf, 0, "\n", 1)) == 0)
		eoffset = 1;
	ಅನ್ಯಥಾ {
		r = SSH_ERR_INVALID_FORMAT;
		error_f("no header eol");
		ಗಚ್ಛ done;
	}
	ಯದಿ ((r = sshbuf_consume(sbuf, eoffset)) != 0) {
		error_fr(r, "consume eol");
		ಗಚ್ಛ done;
	}
	/* Find and consume lf + suffix (any prior cr would be ignored) */
	ಯದಿ ((r = sshbuf_find(sbuf, 0, "\n" END_SIGNATURE,
	    ಪರಿಮಾಣ(END_SIGNATURE), &eoffset)) != 0) {
		error("Couldn't parse signature: missing footer");
		ಗಚ್ಛ done;
	}
	ಯದಿ ((r = sshbuf_consume_end(sbuf, sshbuf_len(sbuf)-eoffset)) != 0) {
		error_fr(r, "consume");
		ಗಚ್ಛ done;
	}

	ಯದಿ ((b64 = sshbuf_dup_string(sbuf)) == ರಿಕ್ತ) {
		error_f("sshbuf_dup_string failed");
		r = SSH_ERR_ALLOC_FAIL;
		ಗಚ್ಛ done;
	}

	ಯದಿ ((buf = sshbuf_new()) == ರಿಕ್ತ) {
		error_f("sshbuf_new() failed");
		r = SSH_ERR_ALLOC_FAIL;
		ಗಚ್ಛ done;
	}

	ಯದಿ ((r = sshbuf_b64tod(buf, b64)) != 0) {
		error_fr(r, "decode base64");
		ಗಚ್ಛ done;
	}

	/* success */
	*out = buf;
	r = 0;
	buf = ರಿಕ್ತ; /* transferred */
done:
	sshbuf_free(buf);
	sshbuf_free(sbuf);
	ಮುಕ್ತ(b64);
	ಪ್ರತ್ಯಾಗಮ r;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
sshsig_wrap_sign(ಸಂರಚನಾ sshkey *ಕೀಲಿ, ಧ್ರುವ ವರ್ಣ *hashalg,
    ಧ್ರುವ ವರ್ಣ *sk_provider, ಧ್ರುವ ವರ್ಣ *sk_pin, ಧ್ರುವ ಸಂರಚನಾ sshbuf *h_message,
    ಧ್ರುವ ವರ್ಣ *sig_namespace, ಸಂರಚನಾ sshbuf **out,
    sshsig_signer *signer, ಶೂನ್ಯ *signer_ctx)
{
	ಪೂರ್ಣಾಙ್ಕ r;
	size_t slen = 0;
	u_char *sig = ರಿಕ್ತ;
	ಸಂರಚನಾ sshbuf *blob = ರಿಕ್ತ;
	ಸಂರಚನಾ sshbuf *tosign = ರಿಕ್ತ;
	ಧ್ರುವ ವರ್ಣ *sign_alg = ರಿಕ್ತ;

	ಯದಿ ((tosign = sshbuf_new()) == ರಿಕ್ತ ||
	    (blob = sshbuf_new()) == ರಿಕ್ತ) {
		error_f("sshbuf_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		ಗಚ್ಛ done;
	}

	ಯದಿ ((r = sshbuf_put(tosign, MAGIC_PREAMBLE, MAGIC_PREAMBLE_LEN)) != 0 ||
	    (r = sshbuf_put_cstring(tosign, sig_namespace)) != 0 ||
	    (r = sshbuf_put_string(tosign, ರಿಕ್ತ, 0)) != 0 || /* reserved */
	    (r = sshbuf_put_cstring(tosign, hashalg)) != 0 ||
	    (r = sshbuf_put_stringb(tosign, h_message)) != 0) {
		error_fr(r, "assemble message to sign");
		ಗಚ್ಛ done;
	}

	/* If using RSA keys then default to a good signature algorithm */
	ಯದಿ (sshkey_type_plain(ಕೀಲಿ->type) == ಕೀಲಿ_RSA) {
		sign_alg = RSA_SIGN_ALG;
		ಯದಿ (strcmp(hashalg, "sha256") == 0)
			sign_alg = "rsa-sha2-256";
		ಅನ್ಯಥಾ ಯದಿ (strcmp(hashalg, "sha512") == 0)
			sign_alg = "rsa-sha2-512";
	}

	ಯದಿ (signer != ರಿಕ್ತ) {
		ಯದಿ ((r = signer(ಕೀಲಿ, &sig, &slen,
		    sshbuf_ptr(tosign), sshbuf_len(tosign),
		    sign_alg, sk_provider, sk_pin, 0, signer_ctx)) != 0) {
			error_r(r, "Couldn't sign message (signer)");
			ಗಚ್ಛ done;
		}
	} ಅನ್ಯಥಾ {
		ಯದಿ ((r = sshkey_sign(ಕೀಲಿ, &sig, &slen,
		    sshbuf_ptr(tosign), sshbuf_len(tosign),
		    sign_alg, sk_provider, sk_pin, 0)) != 0) {
			error_r(r, "Couldn't sign message");
			ಗಚ್ಛ done;
		}
	}

	ಯದಿ ((r = sshbuf_put(blob, MAGIC_PREAMBLE, MAGIC_PREAMBLE_LEN)) != 0 ||
	    (r = sshbuf_put_u32(blob, SIG_VERSION)) != 0 ||
	    (r = sshkey_puts(ಕೀಲಿ, blob)) != 0 ||
	    (r = sshbuf_put_cstring(blob, sig_namespace)) != 0 ||
	    (r = sshbuf_put_string(blob, ರಿಕ್ತ, 0)) != 0 || /* reserved */
	    (r = sshbuf_put_cstring(blob, hashalg)) != 0 ||
	    (r = sshbuf_put_string(blob, sig, slen)) != 0) {
		error_fr(r, "assemble signature object");
		ಗಚ್ಛ done;
	}

	ಯದಿ (out != ರಿಕ್ತ) {
		*out = blob;
		blob = ರಿಕ್ತ;
	}
	r = 0;
done:
	ಮುಕ್ತ(sig);
	sshbuf_free(blob);
	sshbuf_free(tosign);
	ಪ್ರತ್ಯಾಗಮ r;
}

/* Check preamble and version. */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
sshsig_parse_preamble(ಸಂರಚನಾ sshbuf *buf)
{
	ಪೂರ್ಣಾಙ್ಕ r = SSH_ERR_INTERNAL_ERROR;
	uint32_t sversion;

	ಯದಿ ((r = sshbuf_cmp(buf, 0, MAGIC_PREAMBLE, MAGIC_PREAMBLE_LEN)) != 0 ||
	    (r = sshbuf_consume(buf, (ಪರಿಮಾಣ(MAGIC_PREAMBLE)-1))) != 0 ||
	    (r = sshbuf_get_u32(buf, &sversion)) != 0) {
		error("Couldn't verify signature: invalid format");
		ಪ್ರತ್ಯಾಗಮ r;
	}

	ಯದಿ (sversion > SIG_VERSION) {
		error("Signature version %lu is larger than supported "
		    "version %u", (unsigned long)sversion, SIG_VERSION);
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INVALID_FORMAT;
	}
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
sshsig_check_hashalg(ಧ್ರುವ ವರ್ಣ *hashalg)
{
	ಯದಿ (hashalg == ರಿಕ್ತ ||
	    match_pattern_list(hashalg, HASHALG_ALLOWED, 0) == 1)
		ಪ್ರತ್ಯಾಗಮ 0;
	error_f("unsupported hash algorithm \"%.100s\"", hashalg);
	ಪ್ರತ್ಯಾಗಮ SSH_ERR_SIGN_ALG_UNSUPPORTED;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
sshsig_peek_hashalg(ಸಂರಚನಾ sshbuf *signature, ವರ್ಣ **hashalgp)
{
	ಸಂರಚನಾ sshbuf *buf = ರಿಕ್ತ;
	ವರ್ಣ *hashalg = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ r = SSH_ERR_INTERNAL_ERROR;

	ಯದಿ (hashalgp != ರಿಕ್ತ)
		*hashalgp = ರಿಕ್ತ;
	ಯದಿ ((buf = sshbuf_fromb(signature)) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_ALLOC_FAIL;
	ಯದಿ ((r = sshsig_parse_preamble(buf)) != 0)
		ಗಚ್ಛ done;
	ಯದಿ ((r = sshbuf_get_string_direct(buf, ರಿಕ್ತ, ರಿಕ್ತ)) != 0 ||
	    (r = sshbuf_get_string_direct(buf, ರಿಕ್ತ, ರಿಕ್ತ)) != 0 ||
	    (r = sshbuf_get_string(buf, ರಿಕ್ತ, ರಿಕ್ತ)) != 0 ||
	    (r = sshbuf_get_cstring(buf, &hashalg, ರಿಕ್ತ)) != 0 ||
	    (r = sshbuf_get_string_direct(buf, ರಿಕ್ತ, ರಿಕ್ತ)) != 0) {
		error_fr(r, "parse signature object");
		ಗಚ್ಛ done;
	}

	/* success */
	r = 0;
	*hashalgp = hashalg;
	hashalg = ರಿಕ್ತ;
 done:
	ಮುಕ್ತ(hashalg);
	sshbuf_free(buf);
	ಪ್ರತ್ಯಾಗಮ r;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
sshsig_wrap_verify(ಸಂರಚನಾ sshbuf *signature, ಧ್ರುವ ವರ್ಣ *hashalg,
    ಧ್ರುವ ಸಂರಚನಾ sshbuf *h_message, ಧ್ರುವ ವರ್ಣ *expect_namespace,
    ಸಂರಚನಾ sshkey **sign_keyp, ಸಂರಚನಾ sshkey_sig_details **sig_details)
{
	ಪೂರ್ಣಾಙ್ಕ r = SSH_ERR_INTERNAL_ERROR;
	ಸಂರಚನಾ sshbuf *buf = ರಿಕ್ತ, *toverify = ರಿಕ್ತ;
	ಸಂರಚನಾ sshkey *ಕೀಲಿ = ರಿಕ್ತ;
	ಧ್ರುವ u_char *sig;
	ವರ್ಣ *got_namespace = ರಿಕ್ತ, *sigtype = ರಿಕ್ತ, *sig_hashalg = ರಿಕ್ತ;
	size_t siglen;

	debug_f("verify message length %zu", sshbuf_len(h_message));
	ಯದಿ (sig_details != ರಿಕ್ತ)
		*sig_details = ರಿಕ್ತ;
	ಯದಿ (sign_keyp != ರಿಕ್ತ)
		*sign_keyp = ರಿಕ್ತ;

	ಯದಿ ((toverify = sshbuf_new()) == ರಿಕ್ತ) {
		error_f("sshbuf_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		ಗಚ್ಛ done;
	}
	ಯದಿ ((r = sshbuf_put(toverify, MAGIC_PREAMBLE,
	    MAGIC_PREAMBLE_LEN)) != 0 ||
	    (r = sshbuf_put_cstring(toverify, expect_namespace)) != 0 ||
	    (r = sshbuf_put_string(toverify, ರಿಕ್ತ, 0)) != 0 || /* reserved */
	    (r = sshbuf_put_cstring(toverify, hashalg)) != 0 ||
	    (r = sshbuf_put_stringb(toverify, h_message)) != 0) {
		error_fr(r, "assemble message to verify");
		ಗಚ್ಛ done;
	}

	ಯದಿ ((r = sshsig_parse_preamble(signature)) != 0)
		ಗಚ್ಛ done;

	ಯದಿ ((r = sshkey_froms(signature, &ಕೀಲಿ)) != 0 ||
	    (r = sshbuf_get_cstring(signature, &got_namespace, ರಿಕ್ತ)) != 0 ||
	    (r = sshbuf_get_string(signature, ರಿಕ್ತ, ರಿಕ್ತ)) != 0 ||
	    (r = sshbuf_get_cstring(signature, &sig_hashalg, ರಿಕ್ತ)) != 0 ||
	    (r = sshbuf_get_string_direct(signature, &sig, &siglen)) != 0) {
		error_fr(r, "parse signature object");
		ಗಚ್ಛ done;
	}

	ಯದಿ (sshbuf_len(signature) != 0) {
		error("Signature contains trailing data");
		r = SSH_ERR_INVALID_FORMAT;
		ಗಚ್ಛ done;
	}

	ಯದಿ (strcmp(expect_namespace, got_namespace) != 0) {
		error("Couldn't verify signature: namespace does not match");
		debug_f("expected namespace \"%s\" received \"%s\"",
		    expect_namespace, got_namespace);
		r = SSH_ERR_SIGNATURE_INVALID;
		ಗಚ್ಛ done;
	}
	ಯದಿ (strcmp(hashalg, sig_hashalg) != 0) {
		error("Couldn't verify signature: hash algorithm mismatch");
		debug_f("expected algorithm \"%s\" received \"%s\"",
		    hashalg, sig_hashalg);
		r = SSH_ERR_SIGNATURE_INVALID;
		ಗಚ್ಛ done;
	}
	/* Ensure that RSA keys use an acceptable signature algorithm */
	ಯದಿ (sshkey_type_plain(ಕೀಲಿ->type) == ಕೀಲಿ_RSA) {
		ಯದಿ ((r = sshkey_get_sigtype(sig, siglen, &sigtype)) != 0) {
			error_r(r, "Couldn't verify signature: unable to get "
			    "signature type");
			ಗಚ್ಛ done;
		}
		ಯದಿ (match_pattern_list(sigtype, RSA_SIGN_ALLOWED, 0) != 1) {
			error("Couldn't verify signature: unsupported RSA "
			    "signature algorithm %s", sigtype);
			r = SSH_ERR_SIGN_ALG_UNSUPPORTED;
			ಗಚ್ಛ done;
		}
	}
	ಯದಿ ((r = sshkey_verify(ಕೀಲಿ, sig, siglen, sshbuf_ptr(toverify),
	    sshbuf_len(toverify), ರಿಕ್ತ, 0, sig_details)) != 0) {
		error_r(r, "Signature verification failed");
		ಗಚ್ಛ done;
	}

	/* success */
	r = 0;
	ಯದಿ (sign_keyp != ರಿಕ್ತ) {
		*sign_keyp = ಕೀಲಿ;
		ಕೀಲಿ = ರಿಕ್ತ; /* transferred */
	}
done:
	ಮುಕ್ತ(got_namespace);
	ಮುಕ್ತ(sigtype);
	ಮುಕ್ತ(sig_hashalg);
	sshbuf_free(buf);
	sshbuf_free(toverify);
	sshkey_free(ಕೀಲಿ);
	ಪ್ರತ್ಯಾಗಮ r;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
hash_buffer(ಧ್ರುವ ಸಂರಚನಾ sshbuf *m, ಧ್ರುವ ವರ್ಣ *hashalg, ಸಂರಚನಾ sshbuf **bp)
{
	ವರ್ಣ *hex, hash[SSH_DIGEST_MAX_LENGTH];
	ಪೂರ್ಣಾಙ್ಕ alg, r = SSH_ERR_INTERNAL_ERROR;
	ಸಂರಚನಾ sshbuf *b = ರಿಕ್ತ;

	*bp = ರಿಕ್ತ;
	memset(hash, 0, ಪರಿಮಾಣ(hash));

	ಯದಿ ((r = sshsig_check_hashalg(hashalg)) != 0)
		ಪ್ರತ್ಯಾಗಮ r;
	ಯದಿ ((alg = ssh_digest_alg_by_name(hashalg)) == -1) {
		error_f("can't look up hash algorithm %s", hashalg);
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INTERNAL_ERROR;
	}
	ಯದಿ ((r = ssh_digest_buffer(alg, m, hash, ಪರಿಮಾಣ(hash))) != 0) {
		error_fr(r, "ssh_digest_buffer");
		ಪ್ರತ್ಯಾಗಮ r;
	}
	ಯದಿ ((hex = tohex(hash, ssh_digest_bytes(alg))) != ರಿಕ್ತ) {
		debug3_f("final hash: %s", hex);
		freezero(hex, strlen(hex));
	}
	ಯದಿ ((b = sshbuf_new()) == ರಿಕ್ತ) {
		r = SSH_ERR_ALLOC_FAIL;
		ಗಚ್ಛ out;
	}
	ಯದಿ ((r = sshbuf_put(b, hash, ssh_digest_bytes(alg))) != 0) {
		error_fr(r, "sshbuf_put");
		ಗಚ್ಛ out;
	}
	*bp = b;
	b = ರಿಕ್ತ; /* transferred */
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	explicit_bzero(hash, ಪರಿಮಾಣ(hash));
	ಪ್ರತ್ಯಾಗಮ r;
}

ಪೂರ್ಣಾಙ್ಕ
sshsig_signb(ಸಂರಚನಾ sshkey *ಕೀಲಿ, ಧ್ರುವ ವರ್ಣ *hashalg,
    ಧ್ರುವ ವರ್ಣ *sk_provider, ಧ್ರುವ ವರ್ಣ *sk_pin,
    ಧ್ರುವ ಸಂರಚನಾ sshbuf *message, ಧ್ರುವ ವರ್ಣ *sig_namespace,
    ಸಂರಚನಾ sshbuf **out, sshsig_signer *signer, ಶೂನ್ಯ *signer_ctx)
{
	ಸಂರಚನಾ sshbuf *b = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ r = SSH_ERR_INTERNAL_ERROR;

	ಯದಿ (hashalg == ರಿಕ್ತ)
		hashalg = HASHALG_DEFAULT;
	ಯದಿ (out != ರಿಕ್ತ)
		*out = ರಿಕ್ತ;
	ಯದಿ ((r = hash_buffer(message, hashalg, &b)) != 0) {
		error_fr(r, "hash buffer");
		ಗಚ್ಛ out;
	}
	ಯದಿ ((r = sshsig_wrap_sign(ಕೀಲಿ, hashalg, sk_provider, sk_pin, b,
	    sig_namespace, out, signer, signer_ctx)) != 0)
		ಗಚ್ಛ out;
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	ಪ್ರತ್ಯಾಗಮ r;
}

ಪೂರ್ಣಾಙ್ಕ
sshsig_verifyb(ಸಂರಚನಾ sshbuf *signature, ಧ್ರುವ ಸಂರಚನಾ sshbuf *message,
    ಧ್ರುವ ವರ್ಣ *expect_namespace, ಸಂರಚನಾ sshkey **sign_keyp,
    ಸಂರಚನಾ sshkey_sig_details **sig_details)
{
	ಸಂರಚನಾ sshbuf *b = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ r = SSH_ERR_INTERNAL_ERROR;
	ವರ್ಣ *hashalg = ರಿಕ್ತ;

	ಯದಿ (sig_details != ರಿಕ್ತ)
		*sig_details = ರಿಕ್ತ;
	ಯದಿ (sign_keyp != ರಿಕ್ತ)
		*sign_keyp = ರಿಕ್ತ;
	ಯದಿ ((r = sshsig_peek_hashalg(signature, &hashalg)) != 0)
		ಪ್ರತ್ಯಾಗಮ r;
	debug_f("signature made with hash \"%s\"", hashalg);
	ಯದಿ ((r = hash_buffer(message, hashalg, &b)) != 0) {
		error_fr(r, "hash buffer");
		ಗಚ್ಛ out;
	}
	ಯದಿ ((r = sshsig_wrap_verify(signature, hashalg, b, expect_namespace,
	    sign_keyp, sig_details)) != 0)
		ಗಚ್ಛ out;
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	ಮುಕ್ತ(hashalg);
	ಪ್ರತ್ಯಾಗಮ r;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
hash_file(ಪೂರ್ಣಾಙ್ಕ fd, ಧ್ರುವ ವರ್ಣ *hashalg, ಸಂರಚನಾ sshbuf **bp)
{
	ವರ್ಣ *hex, rbuf[8192], hash[SSH_DIGEST_MAX_LENGTH];
	ssize_t n, total = 0;
	ಸಂರಚನಾ ssh_digest_ctx *ctx = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ alg, oerrno, r = SSH_ERR_INTERNAL_ERROR;
	ಸಂರಚನಾ sshbuf *b = ರಿಕ್ತ;

	*bp = ರಿಕ್ತ;
	memset(hash, 0, ಪರಿಮಾಣ(hash));

	ಯದಿ ((r = sshsig_check_hashalg(hashalg)) != 0)
		ಪ್ರತ್ಯಾಗಮ r;
	ಯದಿ ((alg = ssh_digest_alg_by_name(hashalg)) == -1) {
		error_f("can't look up hash algorithm %s", hashalg);
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INTERNAL_ERROR;
	}
	ಯದಿ ((ctx = ssh_digest_start(alg)) == ರಿಕ್ತ) {
		error_f("ssh_digest_start failed");
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INTERNAL_ERROR;
	}
	ಪ್ರತಿ (;;) {
		ಯದಿ ((n = ಪಠ(fd, rbuf, ಪರಿಮಾಣ(rbuf))) == -1) {
			ಯದಿ (errno == EINTR || errno == EAGAIN)
				ಅನುವರ್ತ;
			oerrno = errno;
			error_f("read: %s", strerror(errno));
			errno = oerrno;
			r = SSH_ERR_SYSTEM_ERROR;
			ಗಚ್ಛ out;
		} ಅನ್ಯಥಾ ಯದಿ (n == 0) {
			debug2_f("hashed %zu bytes", total);
			ಭಙ್ಗ; /* EOF */
		}
		total += (size_t)n;
		ಯದಿ ((r = ssh_digest_update(ctx, rbuf, (size_t)n)) != 0) {
			error_fr(r, "ssh_digest_update");
			ಗಚ್ಛ out;
		}
	}
	ಯದಿ ((r = ssh_digest_final(ctx, hash, ಪರಿಮಾಣ(hash))) != 0) {
		error_fr(r, "ssh_digest_final");
		ಗಚ್ಛ out;
	}
	ಯದಿ ((hex = tohex(hash, ssh_digest_bytes(alg))) != ರಿಕ್ತ) {
		debug3_f("final hash: %s", hex);
		freezero(hex, strlen(hex));
	}
	ಯದಿ ((b = sshbuf_new()) == ರಿಕ್ತ) {
		r = SSH_ERR_ALLOC_FAIL;
		ಗಚ್ಛ out;
	}
	ಯದಿ ((r = sshbuf_put(b, hash, ssh_digest_bytes(alg))) != 0) {
		error_fr(r, "sshbuf_put");
		ಗಚ್ಛ out;
	}
	*bp = b;
	b = ರಿಕ್ತ; /* transferred */
	/* success */
	r = 0;
 out:
	oerrno = errno;
	sshbuf_free(b);
	ssh_digest_free(ctx);
	explicit_bzero(hash, ಪರಿಮಾಣ(hash));
	errno = oerrno;
	ಪ್ರತ್ಯಾಗಮ r;
}

ಪೂರ್ಣಾಙ್ಕ
sshsig_sign_fd(ಸಂರಚನಾ sshkey *ಕೀಲಿ, ಧ್ರುವ ವರ್ಣ *hashalg,
    ಧ್ರುವ ವರ್ಣ *sk_provider, ಧ್ರುವ ವರ್ಣ *sk_pin,
    ಪೂರ್ಣಾಙ್ಕ fd, ಧ್ರುವ ವರ್ಣ *sig_namespace, ಸಂರಚನಾ sshbuf **out,
    sshsig_signer *signer, ಶೂನ್ಯ *signer_ctx)
{
	ಸಂರಚನಾ sshbuf *b = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ r = SSH_ERR_INTERNAL_ERROR;

	ಯದಿ (hashalg == ರಿಕ್ತ)
		hashalg = HASHALG_DEFAULT;
	ಯದಿ (out != ರಿಕ್ತ)
		*out = ರಿಕ್ತ;
	ಯದಿ ((r = hash_file(fd, hashalg, &b)) != 0) {
		error_fr(r, "hash_file");
		ಪ್ರತ್ಯಾಗಮ r;
	}
	ಯದಿ ((r = sshsig_wrap_sign(ಕೀಲಿ, hashalg, sk_provider, sk_pin, b,
	    sig_namespace, out, signer, signer_ctx)) != 0)
		ಗಚ್ಛ out;
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	ಪ್ರತ್ಯಾಗಮ r;
}

ಪೂರ್ಣಾಙ್ಕ
sshsig_verify_fd(ಸಂರಚನಾ sshbuf *signature, ಪೂರ್ಣಾಙ್ಕ fd,
    ಧ್ರುವ ವರ್ಣ *expect_namespace, ಸಂರಚನಾ sshkey **sign_keyp,
    ಸಂರಚನಾ sshkey_sig_details **sig_details)
{
	ಸಂರಚನಾ sshbuf *b = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ r = SSH_ERR_INTERNAL_ERROR;
	ವರ್ಣ *hashalg = ರಿಕ್ತ;

	ಯದಿ (sig_details != ರಿಕ್ತ)
		*sig_details = ರಿಕ್ತ;
	ಯದಿ (sign_keyp != ರಿಕ್ತ)
		*sign_keyp = ರಿಕ್ತ;
	ಯದಿ ((r = sshsig_peek_hashalg(signature, &hashalg)) != 0)
		ಪ್ರತ್ಯಾಗಮ r;
	debug_f("signature made with hash \"%s\"", hashalg);
	ಯದಿ ((r = hash_file(fd, hashalg, &b)) != 0) {
		error_fr(r, "hash_file");
		ಗಚ್ಛ out;
	}
	ಯದಿ ((r = sshsig_wrap_verify(signature, hashalg, b, expect_namespace,
	    sign_keyp, sig_details)) != 0)
		ಗಚ್ಛ out;
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	ಮುಕ್ತ(hashalg);
	ಪ್ರತ್ಯಾಗಮ r;
}

ಸಂರಚನಾ sshsigopt {
	ಪೂರ್ಣಾಙ್ಕ ca;
	ವರ್ಣ *namespaces;
	uint64_t valid_after, valid_before;
};

ಸಂರಚನಾ sshsigopt *
sshsigopt_parse(ಧ್ರುವ ವರ್ಣ *opts, ಧ್ರುವ ವರ್ಣ *path, u_long linenum,
    ಧ್ರುವ ವರ್ಣ **errstrp)
{
	ಸಂರಚನಾ sshsigopt *ret;
	ಪೂರ್ಣಾಙ್ಕ r;
	ವರ್ಣ *opt;
	ಧ್ರುವ ವರ್ಣ *errstr = ರಿಕ್ತ;

	ಯದಿ ((ret = calloc(1, ಪರಿಮಾಣ(*ret))) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
	ಯದಿ (opts == ರಿಕ್ತ || *opts == '\0')
		ಪ್ರತ್ಯಾಗಮ ret; /* Empty options yields empty options :) */

	ಯಾವತ್ (*opts && *opts != ' ' && *opts != '\t') {
		/* flag options */
		ಯದಿ ((r = opt_flag("cert-authority", 0, &opts)) != -1) {
			ret->ca = 1;
		} ಅನ್ಯಥಾ ಯದಿ (opt_match(&opts, "namespaces")) {
			ಯದಿ (ret->namespaces != ರಿಕ್ತ) {
				errstr = "multiple \"namespaces\" clauses";
				ಗಚ್ಛ fail;
			}
			ret->namespaces = opt_dequote(&opts, &errstr);
			ಯದಿ (ret->namespaces == ರಿಕ್ತ)
				ಗಚ್ಛ fail;
		} ಅನ್ಯಥಾ ಯದಿ (opt_match(&opts, "valid-after")) {
			ಯದಿ (ret->valid_after != 0) {
				errstr = "multiple \"valid-after\" clauses";
				ಗಚ್ಛ fail;
			}
			ಯದಿ ((opt = opt_dequote(&opts, &errstr)) == ರಿಕ್ತ)
				ಗಚ್ಛ fail;
			ಯದಿ (parse_absolute_time(opt, &ret->valid_after) != 0 ||
			    ret->valid_after == 0) {
				ಮುಕ್ತ(opt);
				errstr = "invalid \"valid-after\" time";
				ಗಚ್ಛ fail;
			}
			ಮುಕ್ತ(opt);
		} ಅನ್ಯಥಾ ಯದಿ (opt_match(&opts, "valid-before")) {
			ಯದಿ (ret->valid_before != 0) {
				errstr = "multiple \"valid-before\" clauses";
				ಗಚ್ಛ fail;
			}
			ಯದಿ ((opt = opt_dequote(&opts, &errstr)) == ರಿಕ್ತ)
				ಗಚ್ಛ fail;
			ಯದಿ (parse_absolute_time(opt, &ret->valid_before) != 0 ||
			    ret->valid_before == 0) {
				ಮುಕ್ತ(opt);
				errstr = "invalid \"valid-before\" time";
				ಗಚ್ಛ fail;
			}
			ಮುಕ್ತ(opt);
		}
		/*
		 * Skip the comma, and move to the next option
		 * (or break out if there are no more).
		 */
		ಯದಿ (*opts == '\0' || *opts == ' ' || *opts == '\t')
			ಭಙ್ಗ;		/* End of options. */
		/* Anything other than a comma is an unknown option */
		ಯದಿ (*opts != ',') {
			errstr = "unknown key option";
			ಗಚ್ಛ fail;
		}
		opts++;
		ಯದಿ (*opts == '\0') {
			errstr = "unexpected end-of-options";
			ಗಚ್ಛ fail;
		}
	}
	/* final consistency check */
	ಯದಿ (ret->valid_after != 0 && ret->valid_before != 0 &&
	    ret->valid_before <= ret->valid_after) {
		errstr = "\"valid-before\" time is before \"valid-after\"";
		ಗಚ್ಛ fail;
	}
	/* success */
	ಪ್ರತ್ಯಾಗಮ ret;
 fail:
	ಯದಿ (errstrp != ರಿಕ್ತ)
		*errstrp = errstr;
	sshsigopt_free(ret);
	ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
}

ಶೂನ್ಯ
sshsigopt_free(ಸಂರಚನಾ sshsigopt *opts)
{
	ಯದಿ (opts == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ;
	ಮುಕ್ತ(opts->namespaces);
	ಮುಕ್ತ(opts);
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
parse_principals_ಕೀಲಿ_and_options(ಧ್ರುವ ವರ್ಣ *path, u_long linenum, ವರ್ಣ *ಸಾಲು,
    ಧ್ರುವ ವರ್ಣ *required_principal, ವರ್ಣ **principalsp, ಸಂರಚನಾ sshkey **keyp,
    ಸಂರಚನಾ sshsigopt **sigoptsp)
{
	ವರ್ಣ *opts = ರಿಕ್ತ, *tmp, *cp, *principals = ರಿಕ್ತ;
	ಧ್ರುವ ವರ್ಣ *reason = ರಿಕ್ತ;
	ಸಂರಚನಾ sshsigopt *sigopts = ರಿಕ್ತ;
	ಸಂರಚನಾ sshkey *ಕೀಲಿ = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ r = SSH_ERR_INTERNAL_ERROR;

	ಯದಿ (principalsp != ರಿಕ್ತ)
		*principalsp = ರಿಕ್ತ;
	ಯದಿ (sigoptsp != ರಿಕ್ತ)
		*sigoptsp = ರಿಕ್ತ;
	ಯದಿ (keyp != ರಿಕ್ತ)
		*keyp = ರಿಕ್ತ;

	cp = ಸಾಲು;
	cp = cp + strspn(cp, " \t\n\r"); /* skip leading whitespace */
	ಯದಿ (*cp == '#' || *cp == '\0')
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_ಕೀಲಿ_NOT_FOUND; /* blank or all-comment line */

	/* format: identity[,identity...] [option[,option...]] key */
	ಯದಿ ((tmp = strdelimw(&cp)) == ರಿಕ್ತ || cp == ರಿಕ್ತ) {
		error("%s:%lu: invalid line", path, linenum);
		r = SSH_ERR_INVALID_FORMAT;
		ಗಚ್ಛ out;
	}
	ಯದಿ ((principals = strdup(tmp)) == ರಿಕ್ತ) {
		error_f("strdup failed");
		r = SSH_ERR_ALLOC_FAIL;
		ಗಚ್ಛ out;
	}
	/*
	 * Bail out early if we're looking for a particular principal and this
	 * line does not list it.
	 */
	ಯದಿ (required_principal != ರಿಕ್ತ) {
		ಯದಿ (match_pattern_list(required_principal,
		    principals, 0) != 1) {
			/* principal didn't match */
			r = SSH_ERR_ಕೀಲಿ_NOT_FOUND;
			ಗಚ್ಛ out;
		}
		debug_f("%s:%lu: matched principal \"%s\"",
		    path, linenum, required_principal);
	}

	ಯದಿ ((ಕೀಲಿ = sshkey_new(ಕೀಲಿ_UNSPEC)) == ರಿಕ್ತ) {
		error_f("sshkey_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		ಗಚ್ಛ out;
	}
	ಯದಿ (sshkey_read(ಕೀಲಿ, &cp) != 0) {
		/* no key? Check for options */
		opts = cp;
		ಯದಿ (sshkey_advance_past_options(&cp) != 0) {
			error("%s:%lu: invalid options", path, linenum);
			r = SSH_ERR_INVALID_FORMAT;
			ಗಚ್ಛ out;
		}
		ಯದಿ (cp == ರಿಕ್ತ || *cp == '\0') {
			error("%s:%lu: missing key", path, linenum);
			r = SSH_ERR_INVALID_FORMAT;
			ಗಚ್ಛ out;
		}
		*cp++ = '\0';
		skip_space(&cp);
		ಯದಿ (sshkey_read(ಕೀಲಿ, &cp) != 0) {
			error("%s:%lu: invalid key", path, linenum);
			r = SSH_ERR_INVALID_FORMAT;
			ಗಚ್ಛ out;
		}
	}
	debug3("%s:%lu: options %s", path, linenum, opts == ರಿಕ್ತ ? "" : opts);
	ಯದಿ ((sigopts = sshsigopt_parse(opts, path, linenum, &reason)) == ರಿಕ್ತ) {
		error("%s:%lu: bad options: %s", path, linenum, reason);
		r = SSH_ERR_INVALID_FORMAT;
		ಗಚ್ಛ out;
	}
	/* success */
	ಯದಿ (principalsp != ರಿಕ್ತ) {
		*principalsp = principals;
		principals = ರಿಕ್ತ; /* transferred */
	}
	ಯದಿ (sigoptsp != ರಿಕ್ತ) {
		*sigoptsp = sigopts;
		sigopts = ರಿಕ್ತ; /* transferred */
	}
	ಯದಿ (keyp != ರಿಕ್ತ) {
		*keyp = ಕೀಲಿ;
		ಕೀಲಿ = ರಿಕ್ತ; /* transferred */
	}
	r = 0;
 out:
	ಮುಕ್ತ(principals);
	sshsigopt_free(sigopts);
	sshkey_free(ಕೀಲಿ);
	ಪ್ರತ್ಯಾಗಮ r;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
cert_filter_principals(ಧ್ರುವ ವರ್ಣ *path, u_long linenum,
    ವರ್ಣ **principalsp, ಧ್ರುವ ಸಂರಚನಾ sshkey *cert, uint64_t verify_time)
{
	ವರ್ಣ *cp, *oprincipals, *principals;
	ಧ್ರುವ ವರ್ಣ *reason;
	ಸಂರಚನಾ sshbuf *nprincipals;
	ಪೂರ್ಣಾಙ್ಕ r = SSH_ERR_INTERNAL_ERROR, success = 0;
	u_int i;

	oprincipals = principals = *principalsp;
	*principalsp = ರಿಕ್ತ;

	ಯದಿ ((nprincipals = sshbuf_new()) == ರಿಕ್ತ) {
		r = SSH_ERR_ALLOC_FAIL;
		ಗಚ್ಛ out;
	}

	ಯಾವತ್ ((cp = strsep(&principals, ",")) != ರಿಕ್ತ && *cp != '\0') {
		/* Check certificate validity */
		ಯದಿ ((r = sshkey_cert_check_authority(cert, 0, 0, verify_time,
		    ರಿಕ್ತ, &reason)) != 0) {
			debug("%s:%lu: principal \"%s\" not authorized: %s",
			    path, linenum, cp, reason);
			ಅನುವರ್ತ;
		}
		/* Return all matching principal names from the cert */
		ಪ್ರತಿ (i = 0; i < cert->cert->nprincipals; i++) {
			ಯದಿ (match_pattern(cert->cert->principals[i], cp)) {
				ಯದಿ ((r = sshbuf_putf(nprincipals, "%s%s",
					sshbuf_len(nprincipals) != 0 ? "," : "",
						cert->cert->principals[i])) != 0) {
					error_f("buffer error");
					ಗಚ್ಛ out;
				}
			}
		}
	}
	ಯದಿ (sshbuf_len(nprincipals) == 0) {
		error("%s:%lu: no valid principals found", path, linenum);
		r = SSH_ERR_ಕೀಲಿ_CERT_INVALID;
		ಗಚ್ಛ out;
	}
	ಯದಿ ((principals = sshbuf_dup_string(nprincipals)) == ರಿಕ್ತ) {
		error_f("buffer error");
		r = SSH_ERR_ALLOC_FAIL;
		ಗಚ್ಛ out;
	}
	/* success */
	success = 1;
	*principalsp = principals;
 out:
	sshbuf_free(nprincipals);
	ಮುಕ್ತ(oprincipals);
	ಪ್ರತ್ಯಾಗಮ success ? 0 : r;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
check_allowed_ಕೀಲಿಗಳು_ಸಾಲು(ಧ್ರುವ ವರ್ಣ *path, u_long linenum, ವರ್ಣ *ಸಾಲು,
    ಧ್ರುವ ಸಂರಚನಾ sshkey *sign_ಕೀಲಿ, ಧ್ರುವ ವರ್ಣ *principal,
    ಧ್ರುವ ವರ್ಣ *sig_namespace, uint64_t verify_time, ವರ್ಣ **principalsp)
{
	ಸಂರಚನಾ sshkey *found_ಕೀಲಿ = ರಿಕ್ತ;
	ವರ್ಣ *principals = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ r, success = 0;
	ಧ್ರುವ ವರ್ಣ *reason = ರಿಕ್ತ;
	ಸಂರಚನಾ sshsigopt *sigopts = ರಿಕ್ತ;
	ವರ್ಣ tvalid[64], tverify[64];

	ಯದಿ (principalsp != ರಿಕ್ತ)
		*principalsp = ರಿಕ್ತ;

	/* Parse the line */
	ಯದಿ ((r = parse_principals_ಕೀಲಿ_and_options(path, linenum, ಸಾಲು,
	    principal, &principals, &found_ಕೀಲಿ, &sigopts)) != 0) {
		/* error already logged */
		ಗಚ್ಛ done;
	}

	ಯದಿ (!sigopts->ca && sshkey_equal(found_ಕೀಲಿ, sign_ಕೀಲಿ)) {
		/* Exact match of key */
		debug("%s:%lu: matched key", path, linenum);
	} ಅನ್ಯಥಾ ಯದಿ (sigopts->ca && sshkey_is_cert(sign_ಕೀಲಿ) &&
	    sshkey_equal_public(sign_ಕೀಲಿ->cert->signature_ಕೀಲಿ, found_ಕೀಲಿ)) {
		ಯದಿ (principal) {
			/* Match certificate CA key with specified principal */
			ಯದಿ ((r = sshkey_cert_check_authority(sign_ಕೀಲಿ, 0, 0,
			    verify_time, principal, &reason)) != 0) {
				error("%s:%lu: certificate not authorized: %s",
				    path, linenum, reason);
				ಗಚ್ಛ done;
			}
			debug("%s:%lu: matched certificate CA key",
			    path, linenum);
		} ಅನ್ಯಥಾ {
			/* No principal specified - find all matching ones */
			ಯದಿ ((r = cert_filter_principals(path, linenum,
			    &principals, sign_ಕೀಲಿ, verify_time)) != 0) {
				/* error already displayed */
				debug_r(r, "%s:%lu: cert_filter_principals",
				    path, linenum);
				ಗಚ್ಛ done;
			}
			debug("%s:%lu: matched certificate CA key",
			    path, linenum);
		}
	} ಅನ್ಯಥಾ {
		/* Didn't match key */
		ಗಚ್ಛ done;
	}

	/* Check whether options preclude the use of this key */
	ಯದಿ (sigopts->namespaces != ರಿಕ್ತ && sig_namespace != ರಿಕ್ತ &&
	    match_pattern_list(sig_namespace, sigopts->namespaces, 0) != 1) {
		error("%s:%lu: key is not permitted for use in signature "
		    "namespace \"%s\"", path, linenum, sig_namespace);
		ಗಚ್ಛ done;
	}

	/* check key time validity */
	format_absolute_time((uint64_t)verify_time, tverify, ಪರಿಮಾಣ(tverify));
	ಯದಿ (sigopts->valid_after != 0 &&
	    (uint64_t)verify_time < sigopts->valid_after) {
		format_absolute_time(sigopts->valid_after,
		    tvalid, ಪರಿಮಾಣ(tvalid));
		error("%s:%lu: key is not yet valid: "
		    "verify time %s < valid-after %s", path, linenum,
		    tverify, tvalid);
		ಗಚ್ಛ done;
	}
	ಯದಿ (sigopts->valid_before != 0 &&
	    (uint64_t)verify_time > sigopts->valid_before) {
		format_absolute_time(sigopts->valid_before,
		    tvalid, ಪರಿಮಾಣ(tvalid));
		error("%s:%lu: key has expired: "
		    "verify time %s > valid-before %s", path, linenum,
		    tverify, tvalid);
		ಗಚ್ಛ done;
	}
	success = 1;

 done:
	ಯದಿ (success && principalsp != ರಿಕ್ತ) {
		*principalsp = principals;
		principals = ರಿಕ್ತ; /* transferred */
	}
	ಮುಕ್ತ(principals);
	sshkey_free(found_ಕೀಲಿ);
	sshsigopt_free(sigopts);
	ಪ್ರತ್ಯಾಗಮ success ? 0 : SSH_ERR_ಕೀಲಿ_NOT_FOUND;
}

ಪೂರ್ಣಾಙ್ಕ
sshsig_check_allowed_ಕೀಲಿಗಳು(ಧ್ರುವ ವರ್ಣ *path, ಧ್ರುವ ಸಂರಚನಾ sshkey *sign_ಕೀಲಿ,
    ಧ್ರುವ ವರ್ಣ *principal, ಧ್ರುವ ವರ್ಣ *sig_namespace, uint64_t verify_time)
{
	FILE *f = ರಿಕ್ತ;
	ವರ್ಣ *ಸಾಲು = ರಿಕ್ತ;
	size_t linesize = 0;
	u_long linenum = 0;
	ಪೂರ್ಣಾಙ್ಕ r = SSH_ERR_ಕೀಲಿ_NOT_FOUND, oerrno;

	/* Check key and principal against file */
	ಯದಿ ((f = fopen(path, "r")) == ರಿಕ್ತ) {
		oerrno = errno;
		error("Unable to open allowed keys file \"%s\": %s",
		    path, strerror(errno));
		errno = oerrno;
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_SYSTEM_ERROR;
	}

	ಯಾವತ್ (getline(&ಸಾಲು, &linesize, f) != -1) {
		linenum++;
		r = check_allowed_ಕೀಲಿಗಳು_ಸಾಲು(path, linenum, ಸಾಲು, sign_ಕೀಲಿ,
		    principal, sig_namespace, verify_time, ರಿಕ್ತ);
		ಮುಕ್ತ(ಸಾಲು);
		ಸಾಲು = ರಿಕ್ತ;
		linesize = 0;
		ಯದಿ (r == SSH_ERR_ಕೀಲಿ_NOT_FOUND)
			ಅನುವರ್ತ;
		ಅನ್ಯಥಾ ಯದಿ (r == 0) {
			/* success */
			fclose(f);
			ಪ್ರತ್ಯಾಗಮ 0;
		} ಅನ್ಯಥಾ
			ಭಙ್ಗ;
	}
	/* Either we hit an error parsing or we simply didn't find the key */
	fclose(f);
	ಮುಕ್ತ(ಸಾಲು);
	ಪ್ರತ್ಯಾಗಮ r;
}

ಪೂರ್ಣಾಙ್ಕ
sshsig_find_principals(ಧ್ರುವ ವರ್ಣ *path, ಧ್ರುವ ಸಂರಚನಾ sshkey *sign_ಕೀಲಿ,
    uint64_t verify_time, ವರ್ಣ **principals)
{
	FILE *f = ರಿಕ್ತ;
	ವರ್ಣ *ಸಾಲು = ರಿಕ್ತ;
	size_t linesize = 0;
	u_long linenum = 0;
	ಪೂರ್ಣಾಙ್ಕ r = SSH_ERR_ಕೀಲಿ_NOT_FOUND, oerrno;

	ಯದಿ ((f = fopen(path, "r")) == ರಿಕ್ತ) {
		oerrno = errno;
		error("Unable to open allowed keys file \"%s\": %s",
		    path, strerror(errno));
		errno = oerrno;
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_SYSTEM_ERROR;
	}

	ಯಾವತ್ (getline(&ಸಾಲು, &linesize, f) != -1) {
		linenum++;
		r = check_allowed_ಕೀಲಿಗಳು_ಸಾಲು(path, linenum, ಸಾಲು,
		    sign_ಕೀಲಿ, ರಿಕ್ತ, ರಿಕ್ತ, verify_time, principals);
		ಮುಕ್ತ(ಸಾಲು);
		ಸಾಲು = ರಿಕ್ತ;
		linesize = 0;
		ಯದಿ (r == SSH_ERR_ಕೀಲಿ_NOT_FOUND)
			ಅನುವರ್ತ;
		ಅನ್ಯಥಾ ಯದಿ (r == 0) {
			/* success */
			fclose(f);
			ಪ್ರತ್ಯಾಗಮ 0;
		} ಅನ್ಯಥಾ
			ಭಙ್ಗ;
	}
	ಮುಕ್ತ(ಸಾಲು);
	/* Either we hit an error parsing or we simply didn't find the key */
	ಯದಿ (ferror(f) != 0) {
		oerrno = errno;
		fclose(f);
		error("Unable to read allowed keys file \"%s\": %s",
		    path, strerror(errno));
		errno = oerrno;
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_SYSTEM_ERROR;
	}
	fclose(f);
	ಪ್ರತ್ಯಾಗಮ r;
}

ಪೂರ್ಣಾಙ್ಕ
sshsig_match_principals(ಧ್ರುವ ವರ್ಣ *path, ಧ್ರುವ ವರ್ಣ *principal,
    ವರ್ಣ ***principalsp, size_t *nprincipalsp)
{
	FILE *f = ರಿಕ್ತ;
	ವರ್ಣ *found, *ಸಾಲು = ರಿಕ್ತ, **principals = ರಿಕ್ತ, **tmp;
	size_t i, nprincipals = 0, linesize = 0;
	u_long linenum = 0;
	ಪೂರ್ಣಾಙ್ಕ oerrno = 0, r, ret = 0;

	ಯದಿ (principalsp != ರಿಕ್ತ)
		*principalsp = ರಿಕ್ತ;
	ಯದಿ (nprincipalsp != ರಿಕ್ತ)
		*nprincipalsp = 0;

	/* Check key and principal against file */
	ಯದಿ ((f = fopen(path, "r")) == ರಿಕ್ತ) {
		oerrno = errno;
		error("Unable to open allowed keys file \"%s\": %s",
		    path, strerror(errno));
		errno = oerrno;
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_SYSTEM_ERROR;
	}

	ಯಾವತ್ (getline(&ಸಾಲು, &linesize, f) != -1) {
		linenum++;
		/* Parse the line */
		ಯದಿ ((r = parse_principals_ಕೀಲಿ_and_options(path, linenum, ಸಾಲು,
		    principal, &found, ರಿಕ್ತ, ರಿಕ್ತ)) != 0) {
			ಯದಿ (r == SSH_ERR_ಕೀಲಿ_NOT_FOUND)
				ಅನುವರ್ತ;
			ret = r;
			oerrno = errno;
			ಭಙ್ಗ; /* unexpected error */
		}
		ಯದಿ ((tmp = recallocarray(principals, nprincipals,
		    nprincipals + 1, ಪರಿಮಾಣ(*principals))) == ರಿಕ್ತ) {
			ret = SSH_ERR_ALLOC_FAIL;
			ಮುಕ್ತ(found);
			ಭಙ್ಗ;
		}
		principals = tmp;
		principals[nprincipals++] = found; /* transferred */
		ಮುಕ್ತ(ಸಾಲು);
		ಸಾಲು = ರಿಕ್ತ;
		linesize = 0;
	}
	fclose(f);
	ಮುಕ್ತ(ಸಾಲು);

	ಯದಿ (ret == 0) {
		ಯದಿ (nprincipals == 0)
			ret = SSH_ERR_ಕೀಲಿ_NOT_FOUND;
		ಯದಿ (nprincipalsp != ರಿಕ್ತ)
			*nprincipalsp = nprincipals;
		ಯದಿ (principalsp != ರಿಕ್ತ) {
			*principalsp = principals;
			principals = ರಿಕ್ತ; /* transferred */
			nprincipals = 0;
		}
	}

	ಪ್ರತಿ (i = 0; i < nprincipals; i++)
		ಮುಕ್ತ(principals[i]);
	ಮುಕ್ತ(principals);

	errno = oerrno;
	ಪ್ರತ್ಯಾಗಮ ret;
}

ಪೂರ್ಣಾಙ್ಕ
sshsig_get_pubkey(ಸಂರಚನಾ sshbuf *signature, ಸಂರಚನಾ sshkey **pubkey)
{
	ಸಂರಚನಾ sshkey *pk = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ r = SSH_ERR_SIGNATURE_INVALID;

	ಯದಿ (pubkey == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INTERNAL_ERROR;
	ಯದಿ ((r = sshsig_parse_preamble(signature)) != 0)
		ಪ್ರತ್ಯಾಗಮ r;
	ಯದಿ ((r = sshkey_froms(signature, &pk)) != 0)
		ಪ್ರತ್ಯಾಗಮ r;

	*pubkey = pk;
	pk = ರಿಕ್ತ;
	ಪ್ರತ್ಯಾಗಮ 0;
}
