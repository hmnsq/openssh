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

#অন্তর্ভাব "includes.h"

#অন্তর্ভাব <stdio.h>
#অন্তর্ভাব <stdlib.h>
#অন্তর্ভাব <stdarg.h>
#অন্তর্ভাব <errno.h>
#অন্তর্ভাব <string.h>
#অন্তর্ভাব <unistd.h>

#অন্তর্ভাব "authfd.h"
#অন্তর্ভাব "authfile.h"
#অন্তর্ভাব "log.h"
#অন্তর্ভাব "misc.h"
#অন্তর্ভাব "sshbuf.h"
#অন্তর্ভাব "sshsig.h"
#অন্তর্ভাব "ssherr.h"
#অন্তর্ভাব "sshkey.h"
#অন্তর্ভাব "match.h"
#অন্তর্ভাব "digest.h"

#define SIG_VERSION		0x01
#define MAGIC_PREAMBLE		"SSHSIG"
#define MAGIC_PREAMBLE_LEN	(পরিমাণ(MAGIC_PREAMBLE) - 1)
#define BEGIN_SIGNATURE		"-----BEGIN SSH SIGNATURE-----"
#define END_SIGNATURE		"-----END SSH SIGNATURE-----"
#define RSA_SIGN_ALG		"rsa-sha2-512"
#define RSA_SIGN_ALLOWED	"rsa-sha2-512,rsa-sha2-256"
#define HASHALG_DEFAULT		"sha512"
#define HASHALG_ALLOWED		"sha256,sha512"

পূর্ণাঙ্ক
sshsig_armor(ধ্রুব সংরচনা sshbuf *blob, সংরচনা sshbuf **out)
{
	সংরচনা sshbuf *buf = রিক্ত;
	পূর্ণাঙ্ক r = SSH_ERR_INTERNAL_ERROR;

	*out = রিক্ত;

	যদি ((buf = sshbuf_new()) == রিক্ত) {
		error_f("sshbuf_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		গচ্ছ out;
	}

	যদি ((r = sshbuf_putf(buf, "%s\n", BEGIN_SIGNATURE)) != 0) {
		error_fr(r, "sshbuf_putf");
		গচ্ছ out;
	}

	যদি ((r = sshbuf_dtob64(blob, buf, 1)) != 0) {
		error_fr(r, "base64 encode signature");
		গচ্ছ out;
	}

	যদি ((r = sshbuf_put(buf, END_SIGNATURE,
	    পরিমাণ(END_SIGNATURE)-1)) != 0 ||
	    (r = sshbuf_put_u8(buf, '\n')) != 0) {
		error_fr(r, "sshbuf_put");
		গচ্ছ out;
	}
	/* success */
	*out = buf;
	buf = রিক্ত; /* transferred */
	r = 0;
 out:
	sshbuf_free(buf);
	প্রত্যাগম r;
}

পূর্ণাঙ্ক
sshsig_dearmor(সংরচনা sshbuf *sig, সংরচনা sshbuf **out)
{
	পূর্ণাঙ্ক r;
	size_t eoffset = 0;
	সংরচনা sshbuf *buf = রিক্ত;
	সংরচনা sshbuf *sbuf = রিক্ত;
	বর্ণ *b64 = রিক্ত;

	যদি ((sbuf = sshbuf_fromb(sig)) == রিক্ত) {
		error_f("sshbuf_fromb failed");
		প্রত্যাগম SSH_ERR_ALLOC_FAIL;
	}

	/* Expect and consume preamble + lf/crlf */
	যদি ((r = sshbuf_cmp(sbuf, 0,
	    BEGIN_SIGNATURE, পরিমাণ(BEGIN_SIGNATURE)-1)) != 0) {
		error("Couldn't parse signature: missing header");
		গচ্ছ done;
	}
	যদি ((r = sshbuf_consume(sbuf, পরিমাণ(BEGIN_SIGNATURE)-1)) != 0) {
		error_fr(r, "consume");
		গচ্ছ done;
	}
	যদি ((r = sshbuf_cmp(sbuf, 0, "\r\n", 2)) == 0)
		eoffset = 2;
	অন্যথা যদি ((r = sshbuf_cmp(sbuf, 0, "\n", 1)) == 0)
		eoffset = 1;
	অন্যথা {
		r = SSH_ERR_INVALID_FORMAT;
		error_f("no header eol");
		গচ্ছ done;
	}
	যদি ((r = sshbuf_consume(sbuf, eoffset)) != 0) {
		error_fr(r, "consume eol");
		গচ্ছ done;
	}
	/* Find and consume lf + suffix (any prior cr would be ignored) */
	যদি ((r = sshbuf_find(sbuf, 0, "\n" END_SIGNATURE,
	    পরিমাণ(END_SIGNATURE), &eoffset)) != 0) {
		error("Couldn't parse signature: missing footer");
		গচ্ছ done;
	}
	যদি ((r = sshbuf_consume_end(sbuf, sshbuf_len(sbuf)-eoffset)) != 0) {
		error_fr(r, "consume");
		গচ্ছ done;
	}

	যদি ((b64 = sshbuf_dup_string(sbuf)) == রিক্ত) {
		error_f("sshbuf_dup_string failed");
		r = SSH_ERR_ALLOC_FAIL;
		গচ্ছ done;
	}

	যদি ((buf = sshbuf_new()) == রিক্ত) {
		error_f("sshbuf_new() failed");
		r = SSH_ERR_ALLOC_FAIL;
		গচ্ছ done;
	}

	যদি ((r = sshbuf_b64tod(buf, b64)) != 0) {
		error_fr(r, "decode base64");
		গচ্ছ done;
	}

	/* success */
	*out = buf;
	r = 0;
	buf = রিক্ত; /* transferred */
done:
	sshbuf_free(buf);
	sshbuf_free(sbuf);
	মুক্ত(b64);
	প্রত্যাগম r;
}

স্থির পূর্ণাঙ্ক
sshsig_wrap_sign(সংরচনা sshkey *চাবি, ধ্রুব বর্ণ *hashalg,
    ধ্রুব বর্ণ *sk_provider, ধ্রুব বর্ণ *sk_pin, ধ্রুব সংরচনা sshbuf *h_message,
    ধ্রুব বর্ণ *sig_namespace, সংরচনা sshbuf **out,
    sshsig_signer *signer, শূন্য *signer_ctx)
{
	পূর্ণাঙ্ক r;
	size_t slen = 0;
	u_char *sig = রিক্ত;
	সংরচনা sshbuf *blob = রিক্ত;
	সংরচনা sshbuf *tosign = রিক্ত;
	ধ্রুব বর্ণ *sign_alg = রিক্ত;

	যদি ((tosign = sshbuf_new()) == রিক্ত ||
	    (blob = sshbuf_new()) == রিক্ত) {
		error_f("sshbuf_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		গচ্ছ done;
	}

	যদি ((r = sshbuf_put(tosign, MAGIC_PREAMBLE, MAGIC_PREAMBLE_LEN)) != 0 ||
	    (r = sshbuf_put_cstring(tosign, sig_namespace)) != 0 ||
	    (r = sshbuf_put_string(tosign, রিক্ত, 0)) != 0 || /* reserved */
	    (r = sshbuf_put_cstring(tosign, hashalg)) != 0 ||
	    (r = sshbuf_put_stringb(tosign, h_message)) != 0) {
		error_fr(r, "assemble message to sign");
		গচ্ছ done;
	}

	/* If using RSA keys then default to a good signature algorithm */
	যদি (sshkey_type_plain(চাবি->type) == চাবি_RSA) {
		sign_alg = RSA_SIGN_ALG;
		যদি (strcmp(hashalg, "sha256") == 0)
			sign_alg = "rsa-sha2-256";
		অন্যথা যদি (strcmp(hashalg, "sha512") == 0)
			sign_alg = "rsa-sha2-512";
	}

	যদি (signer != রিক্ত) {
		যদি ((r = signer(চাবি, &sig, &slen,
		    sshbuf_ptr(tosign), sshbuf_len(tosign),
		    sign_alg, sk_provider, sk_pin, 0, signer_ctx)) != 0) {
			error_r(r, "Couldn't sign message (signer)");
			গচ্ছ done;
		}
	} অন্যথা {
		যদি ((r = sshkey_sign(চাবি, &sig, &slen,
		    sshbuf_ptr(tosign), sshbuf_len(tosign),
		    sign_alg, sk_provider, sk_pin, 0)) != 0) {
			error_r(r, "Couldn't sign message");
			গচ্ছ done;
		}
	}

	যদি ((r = sshbuf_put(blob, MAGIC_PREAMBLE, MAGIC_PREAMBLE_LEN)) != 0 ||
	    (r = sshbuf_put_u32(blob, SIG_VERSION)) != 0 ||
	    (r = sshkey_puts(চাবি, blob)) != 0 ||
	    (r = sshbuf_put_cstring(blob, sig_namespace)) != 0 ||
	    (r = sshbuf_put_string(blob, রিক্ত, 0)) != 0 || /* reserved */
	    (r = sshbuf_put_cstring(blob, hashalg)) != 0 ||
	    (r = sshbuf_put_string(blob, sig, slen)) != 0) {
		error_fr(r, "assemble signature object");
		গচ্ছ done;
	}

	যদি (out != রিক্ত) {
		*out = blob;
		blob = রিক্ত;
	}
	r = 0;
done:
	মুক্ত(sig);
	sshbuf_free(blob);
	sshbuf_free(tosign);
	প্রত্যাগম r;
}

/* Check preamble and version. */
স্থির পূর্ণাঙ্ক
sshsig_parse_preamble(সংরচনা sshbuf *buf)
{
	পূর্ণাঙ্ক r = SSH_ERR_INTERNAL_ERROR;
	uint32_t sversion;

	যদি ((r = sshbuf_cmp(buf, 0, MAGIC_PREAMBLE, MAGIC_PREAMBLE_LEN)) != 0 ||
	    (r = sshbuf_consume(buf, (পরিমাণ(MAGIC_PREAMBLE)-1))) != 0 ||
	    (r = sshbuf_get_u32(buf, &sversion)) != 0) {
		error("Couldn't verify signature: invalid format");
		প্রত্যাগম r;
	}

	যদি (sversion > SIG_VERSION) {
		error("Signature version %lu is larger than supported "
		    "version %u", (unsigned long)sversion, SIG_VERSION);
		প্রত্যাগম SSH_ERR_INVALID_FORMAT;
	}
	প্রত্যাগম 0;
}

স্থির পূর্ণাঙ্ক
sshsig_check_hashalg(ধ্রুব বর্ণ *hashalg)
{
	যদি (hashalg == রিক্ত ||
	    match_pattern_list(hashalg, HASHALG_ALLOWED, 0) == 1)
		প্রত্যাগম 0;
	error_f("unsupported hash algorithm \"%.100s\"", hashalg);
	প্রত্যাগম SSH_ERR_SIGN_ALG_UNSUPPORTED;
}

স্থির পূর্ণাঙ্ক
sshsig_peek_hashalg(সংরচনা sshbuf *signature, বর্ণ **hashalgp)
{
	সংরচনা sshbuf *buf = রিক্ত;
	বর্ণ *hashalg = রিক্ত;
	পূর্ণাঙ্ক r = SSH_ERR_INTERNAL_ERROR;

	যদি (hashalgp != রিক্ত)
		*hashalgp = রিক্ত;
	যদি ((buf = sshbuf_fromb(signature)) == রিক্ত)
		প্রত্যাগম SSH_ERR_ALLOC_FAIL;
	যদি ((r = sshsig_parse_preamble(buf)) != 0)
		গচ্ছ done;
	যদি ((r = sshbuf_get_string_direct(buf, রিক্ত, রিক্ত)) != 0 ||
	    (r = sshbuf_get_string_direct(buf, রিক্ত, রিক্ত)) != 0 ||
	    (r = sshbuf_get_string(buf, রিক্ত, রিক্ত)) != 0 ||
	    (r = sshbuf_get_cstring(buf, &hashalg, রিক্ত)) != 0 ||
	    (r = sshbuf_get_string_direct(buf, রিক্ত, রিক্ত)) != 0) {
		error_fr(r, "parse signature object");
		গচ্ছ done;
	}

	/* success */
	r = 0;
	*hashalgp = hashalg;
	hashalg = রিক্ত;
 done:
	মুক্ত(hashalg);
	sshbuf_free(buf);
	প্রত্যাগম r;
}

স্থির পূর্ণাঙ্ক
sshsig_wrap_verify(সংরচনা sshbuf *signature, ধ্রুব বর্ণ *hashalg,
    ধ্রুব সংরচনা sshbuf *h_message, ধ্রুব বর্ণ *expect_namespace,
    সংরচনা sshkey **sign_keyp, সংরচনা sshkey_sig_details **sig_details)
{
	পূর্ণাঙ্ক r = SSH_ERR_INTERNAL_ERROR;
	সংরচনা sshbuf *buf = রিক্ত, *toverify = রিক্ত;
	সংরচনা sshkey *চাবি = রিক্ত;
	ধ্রুব u_char *sig;
	বর্ণ *got_namespace = রিক্ত, *sigtype = রিক্ত, *sig_hashalg = রিক্ত;
	size_t siglen;

	debug_f("verify message length %zu", sshbuf_len(h_message));
	যদি (sig_details != রিক্ত)
		*sig_details = রিক্ত;
	যদি (sign_keyp != রিক্ত)
		*sign_keyp = রিক্ত;

	যদি ((toverify = sshbuf_new()) == রিক্ত) {
		error_f("sshbuf_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		গচ্ছ done;
	}
	যদি ((r = sshbuf_put(toverify, MAGIC_PREAMBLE,
	    MAGIC_PREAMBLE_LEN)) != 0 ||
	    (r = sshbuf_put_cstring(toverify, expect_namespace)) != 0 ||
	    (r = sshbuf_put_string(toverify, রিক্ত, 0)) != 0 || /* reserved */
	    (r = sshbuf_put_cstring(toverify, hashalg)) != 0 ||
	    (r = sshbuf_put_stringb(toverify, h_message)) != 0) {
		error_fr(r, "assemble message to verify");
		গচ্ছ done;
	}

	যদি ((r = sshsig_parse_preamble(signature)) != 0)
		গচ্ছ done;

	যদি ((r = sshkey_froms(signature, &চাবি)) != 0 ||
	    (r = sshbuf_get_cstring(signature, &got_namespace, রিক্ত)) != 0 ||
	    (r = sshbuf_get_string(signature, রিক্ত, রিক্ত)) != 0 ||
	    (r = sshbuf_get_cstring(signature, &sig_hashalg, রিক্ত)) != 0 ||
	    (r = sshbuf_get_string_direct(signature, &sig, &siglen)) != 0) {
		error_fr(r, "parse signature object");
		গচ্ছ done;
	}

	যদি (sshbuf_len(signature) != 0) {
		error("Signature contains trailing data");
		r = SSH_ERR_INVALID_FORMAT;
		গচ্ছ done;
	}

	যদি (strcmp(expect_namespace, got_namespace) != 0) {
		error("Couldn't verify signature: namespace does not match");
		debug_f("expected namespace \"%s\" received \"%s\"",
		    expect_namespace, got_namespace);
		r = SSH_ERR_SIGNATURE_INVALID;
		গচ্ছ done;
	}
	যদি (strcmp(hashalg, sig_hashalg) != 0) {
		error("Couldn't verify signature: hash algorithm mismatch");
		debug_f("expected algorithm \"%s\" received \"%s\"",
		    hashalg, sig_hashalg);
		r = SSH_ERR_SIGNATURE_INVALID;
		গচ্ছ done;
	}
	/* Ensure that RSA keys use an acceptable signature algorithm */
	যদি (sshkey_type_plain(চাবি->type) == চাবি_RSA) {
		যদি ((r = sshkey_get_sigtype(sig, siglen, &sigtype)) != 0) {
			error_r(r, "Couldn't verify signature: unable to get "
			    "signature type");
			গচ্ছ done;
		}
		যদি (match_pattern_list(sigtype, RSA_SIGN_ALLOWED, 0) != 1) {
			error("Couldn't verify signature: unsupported RSA "
			    "signature algorithm %s", sigtype);
			r = SSH_ERR_SIGN_ALG_UNSUPPORTED;
			গচ্ছ done;
		}
	}
	যদি ((r = sshkey_verify(চাবি, sig, siglen, sshbuf_ptr(toverify),
	    sshbuf_len(toverify), রিক্ত, 0, sig_details)) != 0) {
		error_r(r, "Signature verification failed");
		গচ্ছ done;
	}

	/* success */
	r = 0;
	যদি (sign_keyp != রিক্ত) {
		*sign_keyp = চাবি;
		চাবি = রিক্ত; /* transferred */
	}
done:
	মুক্ত(got_namespace);
	মুক্ত(sigtype);
	মুক্ত(sig_hashalg);
	sshbuf_free(buf);
	sshbuf_free(toverify);
	sshkey_free(চাবি);
	প্রত্যাগম r;
}

স্থির পূর্ণাঙ্ক
hash_buffer(ধ্রুব সংরচনা sshbuf *m, ধ্রুব বর্ণ *hashalg, সংরচনা sshbuf **bp)
{
	বর্ণ *hex, hash[SSH_DIGEST_MAX_LENGTH];
	পূর্ণাঙ্ক alg, r = SSH_ERR_INTERNAL_ERROR;
	সংরচনা sshbuf *b = রিক্ত;

	*bp = রিক্ত;
	memset(hash, 0, পরিমাণ(hash));

	যদি ((r = sshsig_check_hashalg(hashalg)) != 0)
		প্রত্যাগম r;
	যদি ((alg = ssh_digest_alg_by_name(hashalg)) == -1) {
		error_f("can't look up hash algorithm %s", hashalg);
		প্রত্যাগম SSH_ERR_INTERNAL_ERROR;
	}
	যদি ((r = ssh_digest_buffer(alg, m, hash, পরিমাণ(hash))) != 0) {
		error_fr(r, "ssh_digest_buffer");
		প্রত্যাগম r;
	}
	যদি ((hex = tohex(hash, ssh_digest_bytes(alg))) != রিক্ত) {
		debug3_f("final hash: %s", hex);
		freezero(hex, strlen(hex));
	}
	যদি ((b = sshbuf_new()) == রিক্ত) {
		r = SSH_ERR_ALLOC_FAIL;
		গচ্ছ out;
	}
	যদি ((r = sshbuf_put(b, hash, ssh_digest_bytes(alg))) != 0) {
		error_fr(r, "sshbuf_put");
		গচ্ছ out;
	}
	*bp = b;
	b = রিক্ত; /* transferred */
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	explicit_bzero(hash, পরিমাণ(hash));
	প্রত্যাগম r;
}

পূর্ণাঙ্ক
sshsig_signb(সংরচনা sshkey *চাবি, ধ্রুব বর্ণ *hashalg,
    ধ্রুব বর্ণ *sk_provider, ধ্রুব বর্ণ *sk_pin,
    ধ্রুব সংরচনা sshbuf *message, ধ্রুব বর্ণ *sig_namespace,
    সংরচনা sshbuf **out, sshsig_signer *signer, শূন্য *signer_ctx)
{
	সংরচনা sshbuf *b = রিক্ত;
	পূর্ণাঙ্ক r = SSH_ERR_INTERNAL_ERROR;

	যদি (hashalg == রিক্ত)
		hashalg = HASHALG_DEFAULT;
	যদি (out != রিক্ত)
		*out = রিক্ত;
	যদি ((r = hash_buffer(message, hashalg, &b)) != 0) {
		error_fr(r, "hash buffer");
		গচ্ছ out;
	}
	যদি ((r = sshsig_wrap_sign(চাবি, hashalg, sk_provider, sk_pin, b,
	    sig_namespace, out, signer, signer_ctx)) != 0)
		গচ্ছ out;
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	প্রত্যাগম r;
}

পূর্ণাঙ্ক
sshsig_verifyb(সংরচনা sshbuf *signature, ধ্রুব সংরচনা sshbuf *message,
    ধ্রুব বর্ণ *expect_namespace, সংরচনা sshkey **sign_keyp,
    সংরচনা sshkey_sig_details **sig_details)
{
	সংরচনা sshbuf *b = রিক্ত;
	পূর্ণাঙ্ক r = SSH_ERR_INTERNAL_ERROR;
	বর্ণ *hashalg = রিক্ত;

	যদি (sig_details != রিক্ত)
		*sig_details = রিক্ত;
	যদি (sign_keyp != রিক্ত)
		*sign_keyp = রিক্ত;
	যদি ((r = sshsig_peek_hashalg(signature, &hashalg)) != 0)
		প্রত্যাগম r;
	debug_f("signature made with hash \"%s\"", hashalg);
	যদি ((r = hash_buffer(message, hashalg, &b)) != 0) {
		error_fr(r, "hash buffer");
		গচ্ছ out;
	}
	যদি ((r = sshsig_wrap_verify(signature, hashalg, b, expect_namespace,
	    sign_keyp, sig_details)) != 0)
		গচ্ছ out;
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	মুক্ত(hashalg);
	প্রত্যাগম r;
}

স্থির পূর্ণাঙ্ক
hash_file(পূর্ণাঙ্ক fd, ধ্রুব বর্ণ *hashalg, সংরচনা sshbuf **bp)
{
	বর্ণ *hex, rbuf[8192], hash[SSH_DIGEST_MAX_LENGTH];
	ssize_t n, total = 0;
	সংরচনা ssh_digest_ctx *ctx = রিক্ত;
	পূর্ণাঙ্ক alg, oerrno, r = SSH_ERR_INTERNAL_ERROR;
	সংরচনা sshbuf *b = রিক্ত;

	*bp = রিক্ত;
	memset(hash, 0, পরিমাণ(hash));

	যদি ((r = sshsig_check_hashalg(hashalg)) != 0)
		প্রত্যাগম r;
	যদি ((alg = ssh_digest_alg_by_name(hashalg)) == -1) {
		error_f("can't look up hash algorithm %s", hashalg);
		প্রত্যাগম SSH_ERR_INTERNAL_ERROR;
	}
	যদি ((ctx = ssh_digest_start(alg)) == রিক্ত) {
		error_f("ssh_digest_start failed");
		প্রত্যাগম SSH_ERR_INTERNAL_ERROR;
	}
	প্রতি (;;) {
		যদি ((n = পঠ(fd, rbuf, পরিমাণ(rbuf))) == -1) {
			যদি (errno == EINTR || errno == EAGAIN)
				অনুবর্ত;
			oerrno = errno;
			error_f("read: %s", strerror(errno));
			errno = oerrno;
			r = SSH_ERR_SYSTEM_ERROR;
			গচ্ছ out;
		} অন্যথা যদি (n == 0) {
			debug2_f("hashed %zu bytes", total);
			ভঙ্গ; /* EOF */
		}
		total += (size_t)n;
		যদি ((r = ssh_digest_update(ctx, rbuf, (size_t)n)) != 0) {
			error_fr(r, "ssh_digest_update");
			গচ্ছ out;
		}
	}
	যদি ((r = ssh_digest_final(ctx, hash, পরিমাণ(hash))) != 0) {
		error_fr(r, "ssh_digest_final");
		গচ্ছ out;
	}
	যদি ((hex = tohex(hash, ssh_digest_bytes(alg))) != রিক্ত) {
		debug3_f("final hash: %s", hex);
		freezero(hex, strlen(hex));
	}
	যদি ((b = sshbuf_new()) == রিক্ত) {
		r = SSH_ERR_ALLOC_FAIL;
		গচ্ছ out;
	}
	যদি ((r = sshbuf_put(b, hash, ssh_digest_bytes(alg))) != 0) {
		error_fr(r, "sshbuf_put");
		গচ্ছ out;
	}
	*bp = b;
	b = রিক্ত; /* transferred */
	/* success */
	r = 0;
 out:
	oerrno = errno;
	sshbuf_free(b);
	ssh_digest_free(ctx);
	explicit_bzero(hash, পরিমাণ(hash));
	errno = oerrno;
	প্রত্যাগম r;
}

পূর্ণাঙ্ক
sshsig_sign_fd(সংরচনা sshkey *চাবি, ধ্রুব বর্ণ *hashalg,
    ধ্রুব বর্ণ *sk_provider, ধ্রুব বর্ণ *sk_pin,
    পূর্ণাঙ্ক fd, ধ্রুব বর্ণ *sig_namespace, সংরচনা sshbuf **out,
    sshsig_signer *signer, শূন্য *signer_ctx)
{
	সংরচনা sshbuf *b = রিক্ত;
	পূর্ণাঙ্ক r = SSH_ERR_INTERNAL_ERROR;

	যদি (hashalg == রিক্ত)
		hashalg = HASHALG_DEFAULT;
	যদি (out != রিক্ত)
		*out = রিক্ত;
	যদি ((r = hash_file(fd, hashalg, &b)) != 0) {
		error_fr(r, "hash_file");
		প্রত্যাগম r;
	}
	যদি ((r = sshsig_wrap_sign(চাবি, hashalg, sk_provider, sk_pin, b,
	    sig_namespace, out, signer, signer_ctx)) != 0)
		গচ্ছ out;
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	প্রত্যাগম r;
}

পূর্ণাঙ্ক
sshsig_verify_fd(সংরচনা sshbuf *signature, পূর্ণাঙ্ক fd,
    ধ্রুব বর্ণ *expect_namespace, সংরচনা sshkey **sign_keyp,
    সংরচনা sshkey_sig_details **sig_details)
{
	সংরচনা sshbuf *b = রিক্ত;
	পূর্ণাঙ্ক r = SSH_ERR_INTERNAL_ERROR;
	বর্ণ *hashalg = রিক্ত;

	যদি (sig_details != রিক্ত)
		*sig_details = রিক্ত;
	যদি (sign_keyp != রিক্ত)
		*sign_keyp = রিক্ত;
	যদি ((r = sshsig_peek_hashalg(signature, &hashalg)) != 0)
		প্রত্যাগম r;
	debug_f("signature made with hash \"%s\"", hashalg);
	যদি ((r = hash_file(fd, hashalg, &b)) != 0) {
		error_fr(r, "hash_file");
		গচ্ছ out;
	}
	যদি ((r = sshsig_wrap_verify(signature, hashalg, b, expect_namespace,
	    sign_keyp, sig_details)) != 0)
		গচ্ছ out;
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	মুক্ত(hashalg);
	প্রত্যাগম r;
}

সংরচনা sshsigopt {
	পূর্ণাঙ্ক ca;
	বর্ণ *namespaces;
	uint64_t valid_after, valid_before;
};

সংরচনা sshsigopt *
sshsigopt_parse(ধ্রুব বর্ণ *opts, ধ্রুব বর্ণ *path, u_long linenum,
    ধ্রুব বর্ণ **errstrp)
{
	সংরচনা sshsigopt *ret;
	পূর্ণাঙ্ক r;
	বর্ণ *opt;
	ধ্রুব বর্ণ *errstr = রিক্ত;

	যদি ((ret = calloc(1, পরিমাণ(*ret))) == রিক্ত)
		প্রত্যাগম রিক্ত;
	যদি (opts == রিক্ত || *opts == '\0')
		প্রত্যাগম ret; /* Empty options yields empty options :) */

	যাবত্ (*opts && *opts != ' ' && *opts != '\t') {
		/* flag options */
		যদি ((r = opt_flag("cert-authority", 0, &opts)) != -1) {
			ret->ca = 1;
		} অন্যথা যদি (opt_match(&opts, "namespaces")) {
			যদি (ret->namespaces != রিক্ত) {
				errstr = "multiple \"namespaces\" clauses";
				গচ্ছ fail;
			}
			ret->namespaces = opt_dequote(&opts, &errstr);
			যদি (ret->namespaces == রিক্ত)
				গচ্ছ fail;
		} অন্যথা যদি (opt_match(&opts, "valid-after")) {
			যদি (ret->valid_after != 0) {
				errstr = "multiple \"valid-after\" clauses";
				গচ্ছ fail;
			}
			যদি ((opt = opt_dequote(&opts, &errstr)) == রিক্ত)
				গচ্ছ fail;
			যদি (parse_absolute_time(opt, &ret->valid_after) != 0 ||
			    ret->valid_after == 0) {
				মুক্ত(opt);
				errstr = "invalid \"valid-after\" time";
				গচ্ছ fail;
			}
			মুক্ত(opt);
		} অন্যথা যদি (opt_match(&opts, "valid-before")) {
			যদি (ret->valid_before != 0) {
				errstr = "multiple \"valid-before\" clauses";
				গচ্ছ fail;
			}
			যদি ((opt = opt_dequote(&opts, &errstr)) == রিক্ত)
				গচ্ছ fail;
			যদি (parse_absolute_time(opt, &ret->valid_before) != 0 ||
			    ret->valid_before == 0) {
				মুক্ত(opt);
				errstr = "invalid \"valid-before\" time";
				গচ্ছ fail;
			}
			মুক্ত(opt);
		}
		/*
		 * Skip the comma, and move to the next option
		 * (or break out if there are no more).
		 */
		যদি (*opts == '\0' || *opts == ' ' || *opts == '\t')
			ভঙ্গ;		/* End of options. */
		/* Anything other than a comma is an unknown option */
		যদি (*opts != ',') {
			errstr = "unknown key option";
			গচ্ছ fail;
		}
		opts++;
		যদি (*opts == '\0') {
			errstr = "unexpected end-of-options";
			গচ্ছ fail;
		}
	}
	/* final consistency check */
	যদি (ret->valid_after != 0 && ret->valid_before != 0 &&
	    ret->valid_before <= ret->valid_after) {
		errstr = "\"valid-before\" time is before \"valid-after\"";
		গচ্ছ fail;
	}
	/* success */
	প্রত্যাগম ret;
 fail:
	যদি (errstrp != রিক্ত)
		*errstrp = errstr;
	sshsigopt_free(ret);
	প্রত্যাগম রিক্ত;
}

শূন্য
sshsigopt_free(সংরচনা sshsigopt *opts)
{
	যদি (opts == রিক্ত)
		প্রত্যাগম;
	মুক্ত(opts->namespaces);
	মুক্ত(opts);
}

স্থির পূর্ণাঙ্ক
parse_principals_চাবি_and_options(ধ্রুব বর্ণ *path, u_long linenum, বর্ণ *সারি,
    ধ্রুব বর্ণ *required_principal, বর্ণ **principalsp, সংরচনা sshkey **keyp,
    সংরচনা sshsigopt **sigoptsp)
{
	বর্ণ *opts = রিক্ত, *tmp, *cp, *principals = রিক্ত;
	ধ্রুব বর্ণ *reason = রিক্ত;
	সংরচনা sshsigopt *sigopts = রিক্ত;
	সংরচনা sshkey *চাবি = রিক্ত;
	পূর্ণাঙ্ক r = SSH_ERR_INTERNAL_ERROR;

	যদি (principalsp != রিক্ত)
		*principalsp = রিক্ত;
	যদি (sigoptsp != রিক্ত)
		*sigoptsp = রিক্ত;
	যদি (keyp != রিক্ত)
		*keyp = রিক্ত;

	cp = সারি;
	cp = cp + strspn(cp, " \t\n\r"); /* skip leading whitespace */
	যদি (*cp == '#' || *cp == '\0')
		প্রত্যাগম SSH_ERR_চাবি_NOT_FOUND; /* blank or all-comment line */

	/* format: identity[,identity...] [option[,option...]] key */
	যদি ((tmp = strdelimw(&cp)) == রিক্ত || cp == রিক্ত) {
		error("%s:%lu: invalid line", path, linenum);
		r = SSH_ERR_INVALID_FORMAT;
		গচ্ছ out;
	}
	যদি ((principals = strdup(tmp)) == রিক্ত) {
		error_f("strdup failed");
		r = SSH_ERR_ALLOC_FAIL;
		গচ্ছ out;
	}
	/*
	 * Bail out early if we're looking for a particular principal and this
	 * line does not list it.
	 */
	যদি (required_principal != রিক্ত) {
		যদি (match_pattern_list(required_principal,
		    principals, 0) != 1) {
			/* principal didn't match */
			r = SSH_ERR_চাবি_NOT_FOUND;
			গচ্ছ out;
		}
		debug_f("%s:%lu: matched principal \"%s\"",
		    path, linenum, required_principal);
	}

	যদি ((চাবি = sshkey_new(চাবি_UNSPEC)) == রিক্ত) {
		error_f("sshkey_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		গচ্ছ out;
	}
	যদি (sshkey_read(চাবি, &cp) != 0) {
		/* no key? Check for options */
		opts = cp;
		যদি (sshkey_advance_past_options(&cp) != 0) {
			error("%s:%lu: invalid options", path, linenum);
			r = SSH_ERR_INVALID_FORMAT;
			গচ্ছ out;
		}
		যদি (cp == রিক্ত || *cp == '\0') {
			error("%s:%lu: missing key", path, linenum);
			r = SSH_ERR_INVALID_FORMAT;
			গচ্ছ out;
		}
		*cp++ = '\0';
		skip_space(&cp);
		যদি (sshkey_read(চাবি, &cp) != 0) {
			error("%s:%lu: invalid key", path, linenum);
			r = SSH_ERR_INVALID_FORMAT;
			গচ্ছ out;
		}
	}
	debug3("%s:%lu: options %s", path, linenum, opts == রিক্ত ? "" : opts);
	যদি ((sigopts = sshsigopt_parse(opts, path, linenum, &reason)) == রিক্ত) {
		error("%s:%lu: bad options: %s", path, linenum, reason);
		r = SSH_ERR_INVALID_FORMAT;
		গচ্ছ out;
	}
	/* success */
	যদি (principalsp != রিক্ত) {
		*principalsp = principals;
		principals = রিক্ত; /* transferred */
	}
	যদি (sigoptsp != রিক্ত) {
		*sigoptsp = sigopts;
		sigopts = রিক্ত; /* transferred */
	}
	যদি (keyp != রিক্ত) {
		*keyp = চাবি;
		চাবি = রিক্ত; /* transferred */
	}
	r = 0;
 out:
	মুক্ত(principals);
	sshsigopt_free(sigopts);
	sshkey_free(চাবি);
	প্রত্যাগম r;
}

স্থির পূর্ণাঙ্ক
cert_filter_principals(ধ্রুব বর্ণ *path, u_long linenum,
    বর্ণ **principalsp, ধ্রুব সংরচনা sshkey *cert, uint64_t verify_time)
{
	বর্ণ *cp, *oprincipals, *principals;
	ধ্রুব বর্ণ *reason;
	সংরচনা sshbuf *nprincipals;
	পূর্ণাঙ্ক r = SSH_ERR_INTERNAL_ERROR, success = 0;
	u_int i;

	oprincipals = principals = *principalsp;
	*principalsp = রিক্ত;

	যদি ((nprincipals = sshbuf_new()) == রিক্ত) {
		r = SSH_ERR_ALLOC_FAIL;
		গচ্ছ out;
	}

	যাবত্ ((cp = strsep(&principals, ",")) != রিক্ত && *cp != '\0') {
		/* Check certificate validity */
		যদি ((r = sshkey_cert_check_authority(cert, 0, 0, verify_time,
		    রিক্ত, &reason)) != 0) {
			debug("%s:%lu: principal \"%s\" not authorized: %s",
			    path, linenum, cp, reason);
			অনুবর্ত;
		}
		/* Return all matching principal names from the cert */
		প্রতি (i = 0; i < cert->cert->nprincipals; i++) {
			যদি (match_pattern(cert->cert->principals[i], cp)) {
				যদি ((r = sshbuf_putf(nprincipals, "%s%s",
					sshbuf_len(nprincipals) != 0 ? "," : "",
						cert->cert->principals[i])) != 0) {
					error_f("buffer error");
					গচ্ছ out;
				}
			}
		}
	}
	যদি (sshbuf_len(nprincipals) == 0) {
		error("%s:%lu: no valid principals found", path, linenum);
		r = SSH_ERR_চাবি_CERT_INVALID;
		গচ্ছ out;
	}
	যদি ((principals = sshbuf_dup_string(nprincipals)) == রিক্ত) {
		error_f("buffer error");
		r = SSH_ERR_ALLOC_FAIL;
		গচ্ছ out;
	}
	/* success */
	success = 1;
	*principalsp = principals;
 out:
	sshbuf_free(nprincipals);
	মুক্ত(oprincipals);
	প্রত্যাগম success ? 0 : r;
}

স্থির পূর্ণাঙ্ক
check_allowed_চাবিগুলি_সারি(ধ্রুব বর্ণ *path, u_long linenum, বর্ণ *সারি,
    ধ্রুব সংরচনা sshkey *sign_চাবি, ধ্রুব বর্ণ *principal,
    ধ্রুব বর্ণ *sig_namespace, uint64_t verify_time, বর্ণ **principalsp)
{
	সংরচনা sshkey *found_চাবি = রিক্ত;
	বর্ণ *principals = রিক্ত;
	পূর্ণাঙ্ক r, success = 0;
	ধ্রুব বর্ণ *reason = রিক্ত;
	সংরচনা sshsigopt *sigopts = রিক্ত;
	বর্ণ tvalid[64], tverify[64];

	যদি (principalsp != রিক্ত)
		*principalsp = রিক্ত;

	/* Parse the line */
	যদি ((r = parse_principals_চাবি_and_options(path, linenum, সারি,
	    principal, &principals, &found_চাবি, &sigopts)) != 0) {
		/* error already logged */
		গচ্ছ done;
	}

	যদি (!sigopts->ca && sshkey_equal(found_চাবি, sign_চাবি)) {
		/* Exact match of key */
		debug("%s:%lu: matched key", path, linenum);
	} অন্যথা যদি (sigopts->ca && sshkey_is_cert(sign_চাবি) &&
	    sshkey_equal_public(sign_চাবি->cert->signature_চাবি, found_চাবি)) {
		যদি (principal) {
			/* Match certificate CA key with specified principal */
			যদি ((r = sshkey_cert_check_authority(sign_চাবি, 0, 0,
			    verify_time, principal, &reason)) != 0) {
				error("%s:%lu: certificate not authorized: %s",
				    path, linenum, reason);
				গচ্ছ done;
			}
			debug("%s:%lu: matched certificate CA key",
			    path, linenum);
		} অন্যথা {
			/* No principal specified - find all matching ones */
			যদি ((r = cert_filter_principals(path, linenum,
			    &principals, sign_চাবি, verify_time)) != 0) {
				/* error already displayed */
				debug_r(r, "%s:%lu: cert_filter_principals",
				    path, linenum);
				গচ্ছ done;
			}
			debug("%s:%lu: matched certificate CA key",
			    path, linenum);
		}
	} অন্যথা {
		/* Didn't match key */
		গচ্ছ done;
	}

	/* Check whether options preclude the use of this key */
	যদি (sigopts->namespaces != রিক্ত && sig_namespace != রিক্ত &&
	    match_pattern_list(sig_namespace, sigopts->namespaces, 0) != 1) {
		error("%s:%lu: key is not permitted for use in signature "
		    "namespace \"%s\"", path, linenum, sig_namespace);
		গচ্ছ done;
	}

	/* check key time validity */
	format_absolute_time((uint64_t)verify_time, tverify, পরিমাণ(tverify));
	যদি (sigopts->valid_after != 0 &&
	    (uint64_t)verify_time < sigopts->valid_after) {
		format_absolute_time(sigopts->valid_after,
		    tvalid, পরিমাণ(tvalid));
		error("%s:%lu: key is not yet valid: "
		    "verify time %s < valid-after %s", path, linenum,
		    tverify, tvalid);
		গচ্ছ done;
	}
	যদি (sigopts->valid_before != 0 &&
	    (uint64_t)verify_time > sigopts->valid_before) {
		format_absolute_time(sigopts->valid_before,
		    tvalid, পরিমাণ(tvalid));
		error("%s:%lu: key has expired: "
		    "verify time %s > valid-before %s", path, linenum,
		    tverify, tvalid);
		গচ্ছ done;
	}
	success = 1;

 done:
	যদি (success && principalsp != রিক্ত) {
		*principalsp = principals;
		principals = রিক্ত; /* transferred */
	}
	মুক্ত(principals);
	sshkey_free(found_চাবি);
	sshsigopt_free(sigopts);
	প্রত্যাগম success ? 0 : SSH_ERR_চাবি_NOT_FOUND;
}

পূর্ণাঙ্ক
sshsig_check_allowed_চাবিগুলি(ধ্রুব বর্ণ *path, ধ্রুব সংরচনা sshkey *sign_চাবি,
    ধ্রুব বর্ণ *principal, ধ্রুব বর্ণ *sig_namespace, uint64_t verify_time)
{
	FILE *f = রিক্ত;
	বর্ণ *সারি = রিক্ত;
	size_t linesize = 0;
	u_long linenum = 0;
	পূর্ণাঙ্ক r = SSH_ERR_চাবি_NOT_FOUND, oerrno;

	/* Check key and principal against file */
	যদি ((f = fopen(path, "r")) == রিক্ত) {
		oerrno = errno;
		error("Unable to open allowed keys file \"%s\": %s",
		    path, strerror(errno));
		errno = oerrno;
		প্রত্যাগম SSH_ERR_SYSTEM_ERROR;
	}

	যাবত্ (getline(&সারি, &linesize, f) != -1) {
		linenum++;
		r = check_allowed_চাবিগুলি_সারি(path, linenum, সারি, sign_চাবি,
		    principal, sig_namespace, verify_time, রিক্ত);
		মুক্ত(সারি);
		সারি = রিক্ত;
		linesize = 0;
		যদি (r == SSH_ERR_চাবি_NOT_FOUND)
			অনুবর্ত;
		অন্যথা যদি (r == 0) {
			/* success */
			fclose(f);
			প্রত্যাগম 0;
		} অন্যথা
			ভঙ্গ;
	}
	/* Either we hit an error parsing or we simply didn't find the key */
	fclose(f);
	মুক্ত(সারি);
	প্রত্যাগম r;
}

পূর্ণাঙ্ক
sshsig_find_principals(ধ্রুব বর্ণ *path, ধ্রুব সংরচনা sshkey *sign_চাবি,
    uint64_t verify_time, বর্ণ **principals)
{
	FILE *f = রিক্ত;
	বর্ণ *সারি = রিক্ত;
	size_t linesize = 0;
	u_long linenum = 0;
	পূর্ণাঙ্ক r = SSH_ERR_চাবি_NOT_FOUND, oerrno;

	যদি ((f = fopen(path, "r")) == রিক্ত) {
		oerrno = errno;
		error("Unable to open allowed keys file \"%s\": %s",
		    path, strerror(errno));
		errno = oerrno;
		প্রত্যাগম SSH_ERR_SYSTEM_ERROR;
	}

	যাবত্ (getline(&সারি, &linesize, f) != -1) {
		linenum++;
		r = check_allowed_চাবিগুলি_সারি(path, linenum, সারি,
		    sign_চাবি, রিক্ত, রিক্ত, verify_time, principals);
		মুক্ত(সারি);
		সারি = রিক্ত;
		linesize = 0;
		যদি (r == SSH_ERR_চাবি_NOT_FOUND)
			অনুবর্ত;
		অন্যথা যদি (r == 0) {
			/* success */
			fclose(f);
			প্রত্যাগম 0;
		} অন্যথা
			ভঙ্গ;
	}
	মুক্ত(সারি);
	/* Either we hit an error parsing or we simply didn't find the key */
	যদি (ferror(f) != 0) {
		oerrno = errno;
		fclose(f);
		error("Unable to read allowed keys file \"%s\": %s",
		    path, strerror(errno));
		errno = oerrno;
		প্রত্যাগম SSH_ERR_SYSTEM_ERROR;
	}
	fclose(f);
	প্রত্যাগম r;
}

পূর্ণাঙ্ক
sshsig_match_principals(ধ্রুব বর্ণ *path, ধ্রুব বর্ণ *principal,
    বর্ণ ***principalsp, size_t *nprincipalsp)
{
	FILE *f = রিক্ত;
	বর্ণ *found, *সারি = রিক্ত, **principals = রিক্ত, **tmp;
	size_t i, nprincipals = 0, linesize = 0;
	u_long linenum = 0;
	পূর্ণাঙ্ক oerrno = 0, r, ret = 0;

	যদি (principalsp != রিক্ত)
		*principalsp = রিক্ত;
	যদি (nprincipalsp != রিক্ত)
		*nprincipalsp = 0;

	/* Check key and principal against file */
	যদি ((f = fopen(path, "r")) == রিক্ত) {
		oerrno = errno;
		error("Unable to open allowed keys file \"%s\": %s",
		    path, strerror(errno));
		errno = oerrno;
		প্রত্যাগম SSH_ERR_SYSTEM_ERROR;
	}

	যাবত্ (getline(&সারি, &linesize, f) != -1) {
		linenum++;
		/* Parse the line */
		যদি ((r = parse_principals_চাবি_and_options(path, linenum, সারি,
		    principal, &found, রিক্ত, রিক্ত)) != 0) {
			যদি (r == SSH_ERR_চাবি_NOT_FOUND)
				অনুবর্ত;
			ret = r;
			oerrno = errno;
			ভঙ্গ; /* unexpected error */
		}
		যদি ((tmp = recallocarray(principals, nprincipals,
		    nprincipals + 1, পরিমাণ(*principals))) == রিক্ত) {
			ret = SSH_ERR_ALLOC_FAIL;
			মুক্ত(found);
			ভঙ্গ;
		}
		principals = tmp;
		principals[nprincipals++] = found; /* transferred */
		মুক্ত(সারি);
		সারি = রিক্ত;
		linesize = 0;
	}
	fclose(f);
	মুক্ত(সারি);

	যদি (ret == 0) {
		যদি (nprincipals == 0)
			ret = SSH_ERR_চাবি_NOT_FOUND;
		যদি (nprincipalsp != রিক্ত)
			*nprincipalsp = nprincipals;
		যদি (principalsp != রিক্ত) {
			*principalsp = principals;
			principals = রিক্ত; /* transferred */
			nprincipals = 0;
		}
	}

	প্রতি (i = 0; i < nprincipals; i++)
		মুক্ত(principals[i]);
	মুক্ত(principals);

	errno = oerrno;
	প্রত্যাগম ret;
}

পূর্ণাঙ্ক
sshsig_get_pubkey(সংরচনা sshbuf *signature, সংরচনা sshkey **pubkey)
{
	সংরচনা sshkey *pk = রিক্ত;
	পূর্ণাঙ্ক r = SSH_ERR_SIGNATURE_INVALID;

	যদি (pubkey == রিক্ত)
		প্রত্যাগম SSH_ERR_INTERNAL_ERROR;
	যদি ((r = sshsig_parse_preamble(signature)) != 0)
		প্রত্যাগম r;
	যদি ((r = sshkey_froms(signature, &pk)) != 0)
		প্রত্যাগম r;

	*pubkey = pk;
	pk = রিক্ত;
	প্রত্যাগম 0;
}
