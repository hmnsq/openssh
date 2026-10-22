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

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ଅନ୍ତର୍ଭାଵ <stdio.h>
#ଅନ୍ତର୍ଭାଵ <stdlib.h>
#ଅନ୍ତର୍ଭାଵ <stdarg.h>
#ଅନ୍ତର୍ଭାଵ <errno.h>
#ଅନ୍ତର୍ଭାଵ <string.h>
#ଅନ୍ତର୍ଭାଵ <unistd.h>

#ଅନ୍ତର୍ଭାଵ "authfd.h"
#ଅନ୍ତର୍ଭାଵ "authfile.h"
#ଅନ୍ତର୍ଭାଵ "log.h"
#ଅନ୍ତର୍ଭାଵ "misc.h"
#ଅନ୍ତର୍ଭାଵ "sshbuf.h"
#ଅନ୍ତର୍ଭାଵ "sshsig.h"
#ଅନ୍ତର୍ଭାଵ "ssherr.h"
#ଅନ୍ତର୍ଭାଵ "sshkey.h"
#ଅନ୍ତର୍ଭାଵ "match.h"
#ଅନ୍ତର୍ଭାଵ "digest.h"

#define SIG_VERSION		0x01
#define MAGIC_PREAMBLE		"SSHSIG"
#define MAGIC_PREAMBLE_LEN	(ଆକାର(MAGIC_PREAMBLE) - 1)
#define BEGIN_SIGNATURE		"-----BEGIN SSH SIGNATURE-----"
#define END_SIGNATURE		"-----END SSH SIGNATURE-----"
#define RSA_SIGN_ALG		"rsa-sha2-512"
#define RSA_SIGN_ALLOWED	"rsa-sha2-512,rsa-sha2-256"
#define HASHALG_DEFAULT		"sha512"
#define HASHALG_ALLOWED		"sha256,sha512"

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshsig_armor(ଅଚଳ ସଂରଚନା sshbuf *blob, ସଂରଚନା sshbuf **out)
{
	ସଂରଚନା sshbuf *buf = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r = SSH_ERR_INTERNAL_ERROR;

	*out = ଖାଲି;

	ଯଦି ((buf = sshbuf_new()) == ଖାଲି) {
		error_f("sshbuf_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		ଯାଅ out;
	}

	ଯଦି ((r = sshbuf_putf(buf, "%s\n", BEGIN_SIGNATURE)) != 0) {
		error_fr(r, "sshbuf_putf");
		ଯାଅ out;
	}

	ଯଦି ((r = sshbuf_dtob64(blob, buf, 1)) != 0) {
		error_fr(r, "base64 encode signature");
		ଯାଅ out;
	}

	ଯଦି ((r = sshbuf_put(buf, END_SIGNATURE,
	    ଆକାର(END_SIGNATURE)-1)) != 0 ||
	    (r = sshbuf_put_u8(buf, '\n')) != 0) {
		error_fr(r, "sshbuf_put");
		ଯାଅ out;
	}
	/* success */
	*out = buf;
	buf = ଖାଲି; /* transferred */
	r = 0;
 out:
	sshbuf_free(buf);
	ଫେରନ୍ତୁ r;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshsig_dearmor(ସଂରଚନା sshbuf *sig, ସଂରଚନା sshbuf **out)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;
	size_t eoffset = 0;
	ସଂରଚନା sshbuf *buf = ଖାଲି;
	ସଂରଚନା sshbuf *sbuf = ଖାଲି;
	ଅକ୍ଷର *b64 = ଖାଲି;

	ଯଦି ((sbuf = sshbuf_fromb(sig)) == ଖାଲି) {
		error_f("sshbuf_fromb failed");
		ଫେରନ୍ତୁ SSH_ERR_ALLOC_FAIL;
	}

	/* Expect and consume preamble + lf/crlf */
	ଯଦି ((r = sshbuf_cmp(sbuf, 0,
	    BEGIN_SIGNATURE, ଆକାର(BEGIN_SIGNATURE)-1)) != 0) {
		error("Couldn't parse signature: missing header");
		ଯାଅ done;
	}
	ଯଦି ((r = sshbuf_consume(sbuf, ଆକାର(BEGIN_SIGNATURE)-1)) != 0) {
		error_fr(r, "consume");
		ଯାଅ done;
	}
	ଯଦି ((r = sshbuf_cmp(sbuf, 0, "\r\n", 2)) == 0)
		eoffset = 2;
	ଅନ୍ୟଥା ଯଦି ((r = sshbuf_cmp(sbuf, 0, "\n", 1)) == 0)
		eoffset = 1;
	ଅନ୍ୟଥା {
		r = SSH_ERR_INVALID_FORMAT;
		error_f("no header eol");
		ଯାଅ done;
	}
	ଯଦି ((r = sshbuf_consume(sbuf, eoffset)) != 0) {
		error_fr(r, "consume eol");
		ଯାଅ done;
	}
	/* Find and consume lf + suffix (any prior cr would be ignored) */
	ଯଦି ((r = sshbuf_find(sbuf, 0, "\n" END_SIGNATURE,
	    ଆକାର(END_SIGNATURE), &eoffset)) != 0) {
		error("Couldn't parse signature: missing footer");
		ଯାଅ done;
	}
	ଯଦି ((r = sshbuf_consume_end(sbuf, sshbuf_len(sbuf)-eoffset)) != 0) {
		error_fr(r, "consume");
		ଯାଅ done;
	}

	ଯଦି ((b64 = sshbuf_dup_string(sbuf)) == ଖାଲି) {
		error_f("sshbuf_dup_string failed");
		r = SSH_ERR_ALLOC_FAIL;
		ଯାଅ done;
	}

	ଯଦି ((buf = sshbuf_new()) == ଖାଲି) {
		error_f("sshbuf_new() failed");
		r = SSH_ERR_ALLOC_FAIL;
		ଯାଅ done;
	}

	ଯଦି ((r = sshbuf_b64tod(buf, b64)) != 0) {
		error_fr(r, "decode base64");
		ଯାଅ done;
	}

	/* success */
	*out = buf;
	r = 0;
	buf = ଖାଲି; /* transferred */
done:
	sshbuf_free(buf);
	sshbuf_free(sbuf);
	ମୁକ୍ତ(b64);
	ଫେରନ୍ତୁ r;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshsig_wrap_sign(ସଂରଚନା sshkey *ଚାବି, ଅଚଳ ଅକ୍ଷର *hashalg,
    ଅଚଳ ଅକ୍ଷର *sk_provider, ଅଚଳ ଅକ୍ଷର *sk_pin, ଅଚଳ ସଂରଚନା sshbuf *h_message,
    ଅଚଳ ଅକ୍ଷର *sig_namespace, ସଂରଚନା sshbuf **out,
    sshsig_signer *signer, ଶୂନ୍ୟ *signer_ctx)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;
	size_t slen = 0;
	u_char *sig = ଖାଲି;
	ସଂରଚନା sshbuf *blob = ଖାଲି;
	ସଂରଚନା sshbuf *tosign = ଖାଲି;
	ଅଚଳ ଅକ୍ଷର *sign_alg = ଖାଲି;

	ଯଦି ((tosign = sshbuf_new()) == ଖାଲି ||
	    (blob = sshbuf_new()) == ଖାଲି) {
		error_f("sshbuf_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		ଯାଅ done;
	}

	ଯଦି ((r = sshbuf_put(tosign, MAGIC_PREAMBLE, MAGIC_PREAMBLE_LEN)) != 0 ||
	    (r = sshbuf_put_cstring(tosign, sig_namespace)) != 0 ||
	    (r = sshbuf_put_string(tosign, ଖାଲି, 0)) != 0 || /* reserved */
	    (r = sshbuf_put_cstring(tosign, hashalg)) != 0 ||
	    (r = sshbuf_put_stringb(tosign, h_message)) != 0) {
		error_fr(r, "assemble message to sign");
		ଯାଅ done;
	}

	/* If using RSA keys then default to a good signature algorithm */
	ଯଦି (sshkey_type_plain(ଚାବି->type) == ଚାବି_RSA) {
		sign_alg = RSA_SIGN_ALG;
		ଯଦି (strcmp(hashalg, "sha256") == 0)
			sign_alg = "rsa-sha2-256";
		ଅନ୍ୟଥା ଯଦି (strcmp(hashalg, "sha512") == 0)
			sign_alg = "rsa-sha2-512";
	}

	ଯଦି (signer != ଖାଲି) {
		ଯଦି ((r = signer(ଚାବି, &sig, &slen,
		    sshbuf_ptr(tosign), sshbuf_len(tosign),
		    sign_alg, sk_provider, sk_pin, 0, signer_ctx)) != 0) {
			error_r(r, "Couldn't sign message (signer)");
			ଯାଅ done;
		}
	} ଅନ୍ୟଥା {
		ଯଦି ((r = sshkey_sign(ଚାବି, &sig, &slen,
		    sshbuf_ptr(tosign), sshbuf_len(tosign),
		    sign_alg, sk_provider, sk_pin, 0)) != 0) {
			error_r(r, "Couldn't sign message");
			ଯାଅ done;
		}
	}

	ଯଦି ((r = sshbuf_put(blob, MAGIC_PREAMBLE, MAGIC_PREAMBLE_LEN)) != 0 ||
	    (r = sshbuf_put_u32(blob, SIG_VERSION)) != 0 ||
	    (r = sshkey_puts(ଚାବି, blob)) != 0 ||
	    (r = sshbuf_put_cstring(blob, sig_namespace)) != 0 ||
	    (r = sshbuf_put_string(blob, ଖାଲି, 0)) != 0 || /* reserved */
	    (r = sshbuf_put_cstring(blob, hashalg)) != 0 ||
	    (r = sshbuf_put_string(blob, sig, slen)) != 0) {
		error_fr(r, "assemble signature object");
		ଯାଅ done;
	}

	ଯଦି (out != ଖାଲି) {
		*out = blob;
		blob = ଖାଲି;
	}
	r = 0;
done:
	ମୁକ୍ତ(sig);
	sshbuf_free(blob);
	sshbuf_free(tosign);
	ଫେରନ୍ତୁ r;
}

/* Check preamble and version. */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshsig_parse_preamble(ସଂରଚନା sshbuf *buf)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r = SSH_ERR_INTERNAL_ERROR;
	uint32_t sversion;

	ଯଦି ((r = sshbuf_cmp(buf, 0, MAGIC_PREAMBLE, MAGIC_PREAMBLE_LEN)) != 0 ||
	    (r = sshbuf_consume(buf, (ଆକାର(MAGIC_PREAMBLE)-1))) != 0 ||
	    (r = sshbuf_get_u32(buf, &sversion)) != 0) {
		error("Couldn't verify signature: invalid format");
		ଫେରନ୍ତୁ r;
	}

	ଯଦି (sversion > SIG_VERSION) {
		error("Signature version %lu is larger than supported "
		    "version %u", (unsigned long)sversion, SIG_VERSION);
		ଫେରନ୍ତୁ SSH_ERR_INVALID_FORMAT;
	}
	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshsig_check_hashalg(ଅଚଳ ଅକ୍ଷର *hashalg)
{
	ଯଦି (hashalg == ଖାଲି ||
	    match_pattern_list(hashalg, HASHALG_ALLOWED, 0) == 1)
		ଫେରନ୍ତୁ 0;
	error_f("unsupported hash algorithm \"%.100s\"", hashalg);
	ଫେରନ୍ତୁ SSH_ERR_SIGN_ALG_UNSUPPORTED;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshsig_peek_hashalg(ସଂରଚନା sshbuf *signature, ଅକ୍ଷର **hashalgp)
{
	ସଂରଚନା sshbuf *buf = ଖାଲି;
	ଅକ୍ଷର *hashalg = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r = SSH_ERR_INTERNAL_ERROR;

	ଯଦି (hashalgp != ଖାଲି)
		*hashalgp = ଖାଲି;
	ଯଦି ((buf = sshbuf_fromb(signature)) == ଖାଲି)
		ଫେରନ୍ତୁ SSH_ERR_ALLOC_FAIL;
	ଯଦି ((r = sshsig_parse_preamble(buf)) != 0)
		ଯାଅ done;
	ଯଦି ((r = sshbuf_get_string_direct(buf, ଖାଲି, ଖାଲି)) != 0 ||
	    (r = sshbuf_get_string_direct(buf, ଖାଲି, ଖାଲି)) != 0 ||
	    (r = sshbuf_get_string(buf, ଖାଲି, ଖାଲି)) != 0 ||
	    (r = sshbuf_get_cstring(buf, &hashalg, ଖାଲି)) != 0 ||
	    (r = sshbuf_get_string_direct(buf, ଖାଲି, ଖାଲି)) != 0) {
		error_fr(r, "parse signature object");
		ଯାଅ done;
	}

	/* success */
	r = 0;
	*hashalgp = hashalg;
	hashalg = ଖାଲି;
 done:
	ମୁକ୍ତ(hashalg);
	sshbuf_free(buf);
	ଫେରନ୍ତୁ r;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshsig_wrap_verify(ସଂରଚନା sshbuf *signature, ଅଚଳ ଅକ୍ଷର *hashalg,
    ଅଚଳ ସଂରଚନା sshbuf *h_message, ଅଚଳ ଅକ୍ଷର *expect_namespace,
    ସଂରଚନା sshkey **sign_keyp, ସଂରଚନା sshkey_sig_details **sig_details)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r = SSH_ERR_INTERNAL_ERROR;
	ସଂରଚନା sshbuf *buf = ଖାଲି, *toverify = ଖାଲି;
	ସଂରଚନା sshkey *ଚାବି = ଖାଲି;
	ଅଚଳ u_char *sig;
	ଅକ୍ଷର *got_namespace = ଖାଲି, *sigtype = ଖାଲି, *sig_hashalg = ଖାଲି;
	size_t siglen;

	debug_f("verify message length %zu", sshbuf_len(h_message));
	ଯଦି (sig_details != ଖାଲି)
		*sig_details = ଖାଲି;
	ଯଦି (sign_keyp != ଖାଲି)
		*sign_keyp = ଖାଲି;

	ଯଦି ((toverify = sshbuf_new()) == ଖାଲି) {
		error_f("sshbuf_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		ଯାଅ done;
	}
	ଯଦି ((r = sshbuf_put(toverify, MAGIC_PREAMBLE,
	    MAGIC_PREAMBLE_LEN)) != 0 ||
	    (r = sshbuf_put_cstring(toverify, expect_namespace)) != 0 ||
	    (r = sshbuf_put_string(toverify, ଖାଲି, 0)) != 0 || /* reserved */
	    (r = sshbuf_put_cstring(toverify, hashalg)) != 0 ||
	    (r = sshbuf_put_stringb(toverify, h_message)) != 0) {
		error_fr(r, "assemble message to verify");
		ଯାଅ done;
	}

	ଯଦି ((r = sshsig_parse_preamble(signature)) != 0)
		ଯାଅ done;

	ଯଦି ((r = sshkey_froms(signature, &ଚାବି)) != 0 ||
	    (r = sshbuf_get_cstring(signature, &got_namespace, ଖାଲି)) != 0 ||
	    (r = sshbuf_get_string(signature, ଖାଲି, ଖାଲି)) != 0 ||
	    (r = sshbuf_get_cstring(signature, &sig_hashalg, ଖାଲି)) != 0 ||
	    (r = sshbuf_get_string_direct(signature, &sig, &siglen)) != 0) {
		error_fr(r, "parse signature object");
		ଯାଅ done;
	}

	ଯଦି (sshbuf_len(signature) != 0) {
		error("Signature contains trailing data");
		r = SSH_ERR_INVALID_FORMAT;
		ଯାଅ done;
	}

	ଯଦି (strcmp(expect_namespace, got_namespace) != 0) {
		error("Couldn't verify signature: namespace does not match");
		debug_f("expected namespace \"%s\" received \"%s\"",
		    expect_namespace, got_namespace);
		r = SSH_ERR_SIGNATURE_INVALID;
		ଯାଅ done;
	}
	ଯଦି (strcmp(hashalg, sig_hashalg) != 0) {
		error("Couldn't verify signature: hash algorithm mismatch");
		debug_f("expected algorithm \"%s\" received \"%s\"",
		    hashalg, sig_hashalg);
		r = SSH_ERR_SIGNATURE_INVALID;
		ଯାଅ done;
	}
	/* Ensure that RSA keys use an acceptable signature algorithm */
	ଯଦି (sshkey_type_plain(ଚାବି->type) == ଚାବି_RSA) {
		ଯଦି ((r = sshkey_get_sigtype(sig, siglen, &sigtype)) != 0) {
			error_r(r, "Couldn't verify signature: unable to get "
			    "signature type");
			ଯାଅ done;
		}
		ଯଦି (match_pattern_list(sigtype, RSA_SIGN_ALLOWED, 0) != 1) {
			error("Couldn't verify signature: unsupported RSA "
			    "signature algorithm %s", sigtype);
			r = SSH_ERR_SIGN_ALG_UNSUPPORTED;
			ଯାଅ done;
		}
	}
	ଯଦି ((r = sshkey_verify(ଚାବି, sig, siglen, sshbuf_ptr(toverify),
	    sshbuf_len(toverify), ଖାଲି, 0, sig_details)) != 0) {
		error_r(r, "Signature verification failed");
		ଯାଅ done;
	}

	/* success */
	r = 0;
	ଯଦି (sign_keyp != ଖାଲି) {
		*sign_keyp = ଚାବି;
		ଚାବି = ଖାଲି; /* transferred */
	}
done:
	ମୁକ୍ତ(got_namespace);
	ମୁକ୍ତ(sigtype);
	ମୁକ୍ତ(sig_hashalg);
	sshbuf_free(buf);
	sshbuf_free(toverify);
	sshkey_free(ଚାବି);
	ଫେରନ୍ତୁ r;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
hash_buffer(ଅଚଳ ସଂରଚନା sshbuf *m, ଅଚଳ ଅକ୍ଷର *hashalg, ସଂରଚନା sshbuf **bp)
{
	ଅକ୍ଷର *hex, hash[SSH_DIGEST_MAX_LENGTH];
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା alg, r = SSH_ERR_INTERNAL_ERROR;
	ସଂରଚନା sshbuf *b = ଖାଲି;

	*bp = ଖାଲି;
	memset(hash, 0, ଆକାର(hash));

	ଯଦି ((r = sshsig_check_hashalg(hashalg)) != 0)
		ଫେରନ୍ତୁ r;
	ଯଦି ((alg = ssh_digest_alg_by_name(hashalg)) == -1) {
		error_f("can't look up hash algorithm %s", hashalg);
		ଫେରନ୍ତୁ SSH_ERR_INTERNAL_ERROR;
	}
	ଯଦି ((r = ssh_digest_buffer(alg, m, hash, ଆକାର(hash))) != 0) {
		error_fr(r, "ssh_digest_buffer");
		ଫେରନ୍ତୁ r;
	}
	ଯଦି ((hex = tohex(hash, ssh_digest_bytes(alg))) != ଖାଲି) {
		debug3_f("final hash: %s", hex);
		freezero(hex, strlen(hex));
	}
	ଯଦି ((b = sshbuf_new()) == ଖାଲି) {
		r = SSH_ERR_ALLOC_FAIL;
		ଯାଅ out;
	}
	ଯଦି ((r = sshbuf_put(b, hash, ssh_digest_bytes(alg))) != 0) {
		error_fr(r, "sshbuf_put");
		ଯାଅ out;
	}
	*bp = b;
	b = ଖାଲି; /* transferred */
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	explicit_bzero(hash, ଆକାର(hash));
	ଫେରନ୍ତୁ r;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshsig_signb(ସଂରଚନା sshkey *ଚାବି, ଅଚଳ ଅକ୍ଷର *hashalg,
    ଅଚଳ ଅକ୍ଷର *sk_provider, ଅଚଳ ଅକ୍ଷର *sk_pin,
    ଅଚଳ ସଂରଚନା sshbuf *message, ଅଚଳ ଅକ୍ଷର *sig_namespace,
    ସଂରଚନା sshbuf **out, sshsig_signer *signer, ଶୂନ୍ୟ *signer_ctx)
{
	ସଂରଚନା sshbuf *b = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r = SSH_ERR_INTERNAL_ERROR;

	ଯଦି (hashalg == ଖାଲି)
		hashalg = HASHALG_DEFAULT;
	ଯଦି (out != ଖାଲି)
		*out = ଖାଲି;
	ଯଦି ((r = hash_buffer(message, hashalg, &b)) != 0) {
		error_fr(r, "hash buffer");
		ଯାଅ out;
	}
	ଯଦି ((r = sshsig_wrap_sign(ଚାବି, hashalg, sk_provider, sk_pin, b,
	    sig_namespace, out, signer, signer_ctx)) != 0)
		ଯାଅ out;
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	ଫେରନ୍ତୁ r;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshsig_verifyb(ସଂରଚନା sshbuf *signature, ଅଚଳ ସଂରଚନା sshbuf *message,
    ଅଚଳ ଅକ୍ଷର *expect_namespace, ସଂରଚନା sshkey **sign_keyp,
    ସଂରଚନା sshkey_sig_details **sig_details)
{
	ସଂରଚନା sshbuf *b = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r = SSH_ERR_INTERNAL_ERROR;
	ଅକ୍ଷର *hashalg = ଖାଲି;

	ଯଦି (sig_details != ଖାଲି)
		*sig_details = ଖାଲି;
	ଯଦି (sign_keyp != ଖାଲି)
		*sign_keyp = ଖାଲି;
	ଯଦି ((r = sshsig_peek_hashalg(signature, &hashalg)) != 0)
		ଫେରନ୍ତୁ r;
	debug_f("signature made with hash \"%s\"", hashalg);
	ଯଦି ((r = hash_buffer(message, hashalg, &b)) != 0) {
		error_fr(r, "hash buffer");
		ଯାଅ out;
	}
	ଯଦି ((r = sshsig_wrap_verify(signature, hashalg, b, expect_namespace,
	    sign_keyp, sig_details)) != 0)
		ଯାଅ out;
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	ମୁକ୍ତ(hashalg);
	ଫେରନ୍ତୁ r;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
hash_file(ପୂର୍ଣ୍ଣସଂଖ୍ୟା fd, ଅଚଳ ଅକ୍ଷର *hashalg, ସଂରଚନା sshbuf **bp)
{
	ଅକ୍ଷର *hex, rbuf[8192], hash[SSH_DIGEST_MAX_LENGTH];
	ssize_t n, total = 0;
	ସଂରଚନା ssh_digest_ctx *ctx = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା alg, oerrno, r = SSH_ERR_INTERNAL_ERROR;
	ସଂରଚନା sshbuf *b = ଖାଲି;

	*bp = ଖାଲି;
	memset(hash, 0, ଆକାର(hash));

	ଯଦି ((r = sshsig_check_hashalg(hashalg)) != 0)
		ଫେରନ୍ତୁ r;
	ଯଦି ((alg = ssh_digest_alg_by_name(hashalg)) == -1) {
		error_f("can't look up hash algorithm %s", hashalg);
		ଫେରନ୍ତୁ SSH_ERR_INTERNAL_ERROR;
	}
	ଯଦି ((ctx = ssh_digest_start(alg)) == ଖାଲି) {
		error_f("ssh_digest_start failed");
		ଫେରନ୍ତୁ SSH_ERR_INTERNAL_ERROR;
	}
	ପାଇଁ (;;) {
		ଯଦି ((n = ପଠ(fd, rbuf, ଆକାର(rbuf))) == -1) {
			ଯଦି (errno == EINTR || errno == EAGAIN)
				ଜାରି;
			oerrno = errno;
			error_f("read: %s", strerror(errno));
			errno = oerrno;
			r = SSH_ERR_SYSTEM_ERROR;
			ଯାଅ out;
		} ଅନ୍ୟଥା ଯଦି (n == 0) {
			debug2_f("hashed %zu bytes", total);
			ଭାଙ୍ଗ; /* EOF */
		}
		total += (size_t)n;
		ଯଦି ((r = ssh_digest_update(ctx, rbuf, (size_t)n)) != 0) {
			error_fr(r, "ssh_digest_update");
			ଯାଅ out;
		}
	}
	ଯଦି ((r = ssh_digest_final(ctx, hash, ଆକାର(hash))) != 0) {
		error_fr(r, "ssh_digest_final");
		ଯାଅ out;
	}
	ଯଦି ((hex = tohex(hash, ssh_digest_bytes(alg))) != ଖାଲି) {
		debug3_f("final hash: %s", hex);
		freezero(hex, strlen(hex));
	}
	ଯଦି ((b = sshbuf_new()) == ଖାଲି) {
		r = SSH_ERR_ALLOC_FAIL;
		ଯାଅ out;
	}
	ଯଦି ((r = sshbuf_put(b, hash, ssh_digest_bytes(alg))) != 0) {
		error_fr(r, "sshbuf_put");
		ଯାଅ out;
	}
	*bp = b;
	b = ଖାଲି; /* transferred */
	/* success */
	r = 0;
 out:
	oerrno = errno;
	sshbuf_free(b);
	ssh_digest_free(ctx);
	explicit_bzero(hash, ଆକାର(hash));
	errno = oerrno;
	ଫେରନ୍ତୁ r;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshsig_sign_fd(ସଂରଚନା sshkey *ଚାବି, ଅଚଳ ଅକ୍ଷର *hashalg,
    ଅଚଳ ଅକ୍ଷର *sk_provider, ଅଚଳ ଅକ୍ଷର *sk_pin,
    ପୂର୍ଣ୍ଣସଂଖ୍ୟା fd, ଅଚଳ ଅକ୍ଷର *sig_namespace, ସଂରଚନା sshbuf **out,
    sshsig_signer *signer, ଶୂନ୍ୟ *signer_ctx)
{
	ସଂରଚନା sshbuf *b = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r = SSH_ERR_INTERNAL_ERROR;

	ଯଦି (hashalg == ଖାଲି)
		hashalg = HASHALG_DEFAULT;
	ଯଦି (out != ଖାଲି)
		*out = ଖାଲି;
	ଯଦି ((r = hash_file(fd, hashalg, &b)) != 0) {
		error_fr(r, "hash_file");
		ଫେରନ୍ତୁ r;
	}
	ଯଦି ((r = sshsig_wrap_sign(ଚାବି, hashalg, sk_provider, sk_pin, b,
	    sig_namespace, out, signer, signer_ctx)) != 0)
		ଯାଅ out;
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	ଫେରନ୍ତୁ r;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshsig_verify_fd(ସଂରଚନା sshbuf *signature, ପୂର୍ଣ୍ଣସଂଖ୍ୟା fd,
    ଅଚଳ ଅକ୍ଷର *expect_namespace, ସଂରଚନା sshkey **sign_keyp,
    ସଂରଚନା sshkey_sig_details **sig_details)
{
	ସଂରଚନା sshbuf *b = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r = SSH_ERR_INTERNAL_ERROR;
	ଅକ୍ଷର *hashalg = ଖାଲି;

	ଯଦି (sig_details != ଖାଲି)
		*sig_details = ଖାଲି;
	ଯଦି (sign_keyp != ଖାଲି)
		*sign_keyp = ଖାଲି;
	ଯଦି ((r = sshsig_peek_hashalg(signature, &hashalg)) != 0)
		ଫେରନ୍ତୁ r;
	debug_f("signature made with hash \"%s\"", hashalg);
	ଯଦି ((r = hash_file(fd, hashalg, &b)) != 0) {
		error_fr(r, "hash_file");
		ଯାଅ out;
	}
	ଯଦି ((r = sshsig_wrap_verify(signature, hashalg, b, expect_namespace,
	    sign_keyp, sig_details)) != 0)
		ଯାଅ out;
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	ମୁକ୍ତ(hashalg);
	ଫେରନ୍ତୁ r;
}

ସଂରଚନା sshsigopt {
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା ca;
	ଅକ୍ଷର *namespaces;
	uint64_t valid_after, valid_before;
};

ସଂରଚନା sshsigopt *
sshsigopt_parse(ଅଚଳ ଅକ୍ଷର *opts, ଅଚଳ ଅକ୍ଷର *path, u_long linenum,
    ଅଚଳ ଅକ୍ଷର **errstrp)
{
	ସଂରଚନା sshsigopt *ret;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;
	ଅକ୍ଷର *opt;
	ଅଚଳ ଅକ୍ଷର *errstr = ଖାଲି;

	ଯଦି ((ret = calloc(1, ଆକାର(*ret))) == ଖାଲି)
		ଫେରନ୍ତୁ ଖାଲି;
	ଯଦି (opts == ଖାଲି || *opts == '\0')
		ଫେରନ୍ତୁ ret; /* Empty options yields empty options :) */

	ଯେତେବେଳେ (*opts && *opts != ' ' && *opts != '\t') {
		/* flag options */
		ଯଦି ((r = opt_flag("cert-authority", 0, &opts)) != -1) {
			ret->ca = 1;
		} ଅନ୍ୟଥା ଯଦି (opt_match(&opts, "namespaces")) {
			ଯଦି (ret->namespaces != ଖାଲି) {
				errstr = "multiple \"namespaces\" clauses";
				ଯାଅ fail;
			}
			ret->namespaces = opt_dequote(&opts, &errstr);
			ଯଦି (ret->namespaces == ଖାଲି)
				ଯାଅ fail;
		} ଅନ୍ୟଥା ଯଦି (opt_match(&opts, "valid-after")) {
			ଯଦି (ret->valid_after != 0) {
				errstr = "multiple \"valid-after\" clauses";
				ଯାଅ fail;
			}
			ଯଦି ((opt = opt_dequote(&opts, &errstr)) == ଖାଲି)
				ଯାଅ fail;
			ଯଦି (parse_absolute_time(opt, &ret->valid_after) != 0 ||
			    ret->valid_after == 0) {
				ମୁକ୍ତ(opt);
				errstr = "invalid \"valid-after\" time";
				ଯାଅ fail;
			}
			ମୁକ୍ତ(opt);
		} ଅନ୍ୟଥା ଯଦି (opt_match(&opts, "valid-before")) {
			ଯଦି (ret->valid_before != 0) {
				errstr = "multiple \"valid-before\" clauses";
				ଯାଅ fail;
			}
			ଯଦି ((opt = opt_dequote(&opts, &errstr)) == ଖାଲି)
				ଯାଅ fail;
			ଯଦି (parse_absolute_time(opt, &ret->valid_before) != 0 ||
			    ret->valid_before == 0) {
				ମୁକ୍ତ(opt);
				errstr = "invalid \"valid-before\" time";
				ଯାଅ fail;
			}
			ମୁକ୍ତ(opt);
		}
		/*
		 * Skip the comma, and move to the next option
		 * (or break out if there are no more).
		 */
		ଯଦି (*opts == '\0' || *opts == ' ' || *opts == '\t')
			ଭାଙ୍ଗ;		/* End of options. */
		/* Anything other than a comma is an unknown option */
		ଯଦି (*opts != ',') {
			errstr = "unknown key option";
			ଯାଅ fail;
		}
		opts++;
		ଯଦି (*opts == '\0') {
			errstr = "unexpected end-of-options";
			ଯାଅ fail;
		}
	}
	/* final consistency check */
	ଯଦି (ret->valid_after != 0 && ret->valid_before != 0 &&
	    ret->valid_before <= ret->valid_after) {
		errstr = "\"valid-before\" time is before \"valid-after\"";
		ଯାଅ fail;
	}
	/* success */
	ଫେରନ୍ତୁ ret;
 fail:
	ଯଦି (errstrp != ଖାଲି)
		*errstrp = errstr;
	sshsigopt_free(ret);
	ଫେରନ୍ତୁ ଖାଲି;
}

ଶୂନ୍ୟ
sshsigopt_free(ସଂରଚନା sshsigopt *opts)
{
	ଯଦି (opts == ଖାଲି)
		ଫେରନ୍ତୁ;
	ମୁକ୍ତ(opts->namespaces);
	ମୁକ୍ତ(opts);
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
parse_principals_ଚାବି_and_options(ଅଚଳ ଅକ୍ଷର *path, u_long linenum, ଅକ୍ଷର *ଧାଡ଼ି,
    ଅଚଳ ଅକ୍ଷର *required_principal, ଅକ୍ଷର **principalsp, ସଂରଚନା sshkey **keyp,
    ସଂରଚନା sshsigopt **sigoptsp)
{
	ଅକ୍ଷର *opts = ଖାଲି, *tmp, *cp, *principals = ଖାଲି;
	ଅଚଳ ଅକ୍ଷର *reason = ଖାଲି;
	ସଂରଚନା sshsigopt *sigopts = ଖାଲି;
	ସଂରଚନା sshkey *ଚାବି = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r = SSH_ERR_INTERNAL_ERROR;

	ଯଦି (principalsp != ଖାଲି)
		*principalsp = ଖାଲି;
	ଯଦି (sigoptsp != ଖାଲି)
		*sigoptsp = ଖାଲି;
	ଯଦି (keyp != ଖାଲି)
		*keyp = ଖାଲି;

	cp = ଧାଡ଼ି;
	cp = cp + strspn(cp, " \t\n\r"); /* skip leading whitespace */
	ଯଦି (*cp == '#' || *cp == '\0')
		ଫେରନ୍ତୁ SSH_ERR_ଚାବି_NOT_FOUND; /* blank or all-comment line */

	/* format: identity[,identity...] [option[,option...]] key */
	ଯଦି ((tmp = strdelimw(&cp)) == ଖାଲି || cp == ଖାଲି) {
		error("%s:%lu: invalid line", path, linenum);
		r = SSH_ERR_INVALID_FORMAT;
		ଯାଅ out;
	}
	ଯଦି ((principals = strdup(tmp)) == ଖାଲି) {
		error_f("strdup failed");
		r = SSH_ERR_ALLOC_FAIL;
		ଯାଅ out;
	}
	/*
	 * Bail out early if we're looking for a particular principal and this
	 * line does not list it.
	 */
	ଯଦି (required_principal != ଖାଲି) {
		ଯଦି (match_pattern_list(required_principal,
		    principals, 0) != 1) {
			/* principal didn't match */
			r = SSH_ERR_ଚାବି_NOT_FOUND;
			ଯାଅ out;
		}
		debug_f("%s:%lu: matched principal \"%s\"",
		    path, linenum, required_principal);
	}

	ଯଦି ((ଚାବି = sshkey_new(ଚାବି_UNSPEC)) == ଖାଲି) {
		error_f("sshkey_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		ଯାଅ out;
	}
	ଯଦି (sshkey_read(ଚାବି, &cp) != 0) {
		/* no key? Check for options */
		opts = cp;
		ଯଦି (sshkey_advance_past_options(&cp) != 0) {
			error("%s:%lu: invalid options", path, linenum);
			r = SSH_ERR_INVALID_FORMAT;
			ଯାଅ out;
		}
		ଯଦି (cp == ଖାଲି || *cp == '\0') {
			error("%s:%lu: missing key", path, linenum);
			r = SSH_ERR_INVALID_FORMAT;
			ଯାଅ out;
		}
		*cp++ = '\0';
		skip_space(&cp);
		ଯଦି (sshkey_read(ଚାବି, &cp) != 0) {
			error("%s:%lu: invalid key", path, linenum);
			r = SSH_ERR_INVALID_FORMAT;
			ଯାଅ out;
		}
	}
	debug3("%s:%lu: options %s", path, linenum, opts == ଖାଲି ? "" : opts);
	ଯଦି ((sigopts = sshsigopt_parse(opts, path, linenum, &reason)) == ଖାଲି) {
		error("%s:%lu: bad options: %s", path, linenum, reason);
		r = SSH_ERR_INVALID_FORMAT;
		ଯାଅ out;
	}
	/* success */
	ଯଦି (principalsp != ଖାଲି) {
		*principalsp = principals;
		principals = ଖାଲି; /* transferred */
	}
	ଯଦି (sigoptsp != ଖାଲି) {
		*sigoptsp = sigopts;
		sigopts = ଖାଲି; /* transferred */
	}
	ଯଦି (keyp != ଖାଲି) {
		*keyp = ଚାବି;
		ଚାବି = ଖାଲି; /* transferred */
	}
	r = 0;
 out:
	ମୁକ୍ତ(principals);
	sshsigopt_free(sigopts);
	sshkey_free(ଚାବି);
	ଫେରନ୍ତୁ r;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
cert_filter_principals(ଅଚଳ ଅକ୍ଷର *path, u_long linenum,
    ଅକ୍ଷର **principalsp, ଅଚଳ ସଂରଚନା sshkey *cert, uint64_t verify_time)
{
	ଅକ୍ଷର *cp, *oprincipals, *principals;
	ଅଚଳ ଅକ୍ଷର *reason;
	ସଂରଚନା sshbuf *nprincipals;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r = SSH_ERR_INTERNAL_ERROR, success = 0;
	u_int i;

	oprincipals = principals = *principalsp;
	*principalsp = ଖାଲି;

	ଯଦି ((nprincipals = sshbuf_new()) == ଖାଲି) {
		r = SSH_ERR_ALLOC_FAIL;
		ଯାଅ out;
	}

	ଯେତେବେଳେ ((cp = strsep(&principals, ",")) != ଖାଲି && *cp != '\0') {
		/* Check certificate validity */
		ଯଦି ((r = sshkey_cert_check_authority(cert, 0, 0, verify_time,
		    ଖାଲି, &reason)) != 0) {
			debug("%s:%lu: principal \"%s\" not authorized: %s",
			    path, linenum, cp, reason);
			ଜାରି;
		}
		/* Return all matching principal names from the cert */
		ପାଇଁ (i = 0; i < cert->cert->nprincipals; i++) {
			ଯଦି (match_pattern(cert->cert->principals[i], cp)) {
				ଯଦି ((r = sshbuf_putf(nprincipals, "%s%s",
					sshbuf_len(nprincipals) != 0 ? "," : "",
						cert->cert->principals[i])) != 0) {
					error_f("buffer error");
					ଯାଅ out;
				}
			}
		}
	}
	ଯଦି (sshbuf_len(nprincipals) == 0) {
		error("%s:%lu: no valid principals found", path, linenum);
		r = SSH_ERR_ଚାବି_CERT_INVALID;
		ଯାଅ out;
	}
	ଯଦି ((principals = sshbuf_dup_string(nprincipals)) == ଖାଲି) {
		error_f("buffer error");
		r = SSH_ERR_ALLOC_FAIL;
		ଯାଅ out;
	}
	/* success */
	success = 1;
	*principalsp = principals;
 out:
	sshbuf_free(nprincipals);
	ମୁକ୍ତ(oprincipals);
	ଫେରନ୍ତୁ success ? 0 : r;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
check_allowed_ଚାବିଗୁଡ଼ିକ_ଧାଡ଼ି(ଅଚଳ ଅକ୍ଷର *path, u_long linenum, ଅକ୍ଷର *ଧାଡ଼ି,
    ଅଚଳ ସଂରଚନା sshkey *sign_ଚାବି, ଅଚଳ ଅକ୍ଷର *principal,
    ଅଚଳ ଅକ୍ଷର *sig_namespace, uint64_t verify_time, ଅକ୍ଷର **principalsp)
{
	ସଂରଚନା sshkey *found_ଚାବି = ଖାଲି;
	ଅକ୍ଷର *principals = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, success = 0;
	ଅଚଳ ଅକ୍ଷର *reason = ଖାଲି;
	ସଂରଚନା sshsigopt *sigopts = ଖାଲି;
	ଅକ୍ଷର tvalid[64], tverify[64];

	ଯଦି (principalsp != ଖାଲି)
		*principalsp = ଖାଲି;

	/* Parse the line */
	ଯଦି ((r = parse_principals_ଚାବି_and_options(path, linenum, ଧାଡ଼ି,
	    principal, &principals, &found_ଚାବି, &sigopts)) != 0) {
		/* error already logged */
		ଯାଅ done;
	}

	ଯଦି (!sigopts->ca && sshkey_equal(found_ଚାବି, sign_ଚାବି)) {
		/* Exact match of key */
		debug("%s:%lu: matched key", path, linenum);
	} ଅନ୍ୟଥା ଯଦି (sigopts->ca && sshkey_is_cert(sign_ଚାବି) &&
	    sshkey_equal_public(sign_ଚାବି->cert->signature_ଚାବି, found_ଚାବି)) {
		ଯଦି (principal) {
			/* Match certificate CA key with specified principal */
			ଯଦି ((r = sshkey_cert_check_authority(sign_ଚାବି, 0, 0,
			    verify_time, principal, &reason)) != 0) {
				error("%s:%lu: certificate not authorized: %s",
				    path, linenum, reason);
				ଯାଅ done;
			}
			debug("%s:%lu: matched certificate CA key",
			    path, linenum);
		} ଅନ୍ୟଥା {
			/* No principal specified - find all matching ones */
			ଯଦି ((r = cert_filter_principals(path, linenum,
			    &principals, sign_ଚାବି, verify_time)) != 0) {
				/* error already displayed */
				debug_r(r, "%s:%lu: cert_filter_principals",
				    path, linenum);
				ଯାଅ done;
			}
			debug("%s:%lu: matched certificate CA key",
			    path, linenum);
		}
	} ଅନ୍ୟଥା {
		/* Didn't match key */
		ଯାଅ done;
	}

	/* Check whether options preclude the use of this key */
	ଯଦି (sigopts->namespaces != ଖାଲି && sig_namespace != ଖାଲି &&
	    match_pattern_list(sig_namespace, sigopts->namespaces, 0) != 1) {
		error("%s:%lu: key is not permitted for use in signature "
		    "namespace \"%s\"", path, linenum, sig_namespace);
		ଯାଅ done;
	}

	/* check key time validity */
	format_absolute_time((uint64_t)verify_time, tverify, ଆକାର(tverify));
	ଯଦି (sigopts->valid_after != 0 &&
	    (uint64_t)verify_time < sigopts->valid_after) {
		format_absolute_time(sigopts->valid_after,
		    tvalid, ଆକାର(tvalid));
		error("%s:%lu: key is not yet valid: "
		    "verify time %s < valid-after %s", path, linenum,
		    tverify, tvalid);
		ଯାଅ done;
	}
	ଯଦି (sigopts->valid_before != 0 &&
	    (uint64_t)verify_time > sigopts->valid_before) {
		format_absolute_time(sigopts->valid_before,
		    tvalid, ଆକାର(tvalid));
		error("%s:%lu: key has expired: "
		    "verify time %s > valid-before %s", path, linenum,
		    tverify, tvalid);
		ଯାଅ done;
	}
	success = 1;

 done:
	ଯଦି (success && principalsp != ଖାଲି) {
		*principalsp = principals;
		principals = ଖାଲି; /* transferred */
	}
	ମୁକ୍ତ(principals);
	sshkey_free(found_ଚାବି);
	sshsigopt_free(sigopts);
	ଫେରନ୍ତୁ success ? 0 : SSH_ERR_ଚାବି_NOT_FOUND;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshsig_check_allowed_ଚାବିଗୁଡ଼ିକ(ଅଚଳ ଅକ୍ଷର *path, ଅଚଳ ସଂରଚନା sshkey *sign_ଚାବି,
    ଅଚଳ ଅକ୍ଷର *principal, ଅଚଳ ଅକ୍ଷର *sig_namespace, uint64_t verify_time)
{
	FILE *f = ଖାଲି;
	ଅକ୍ଷର *ଧାଡ଼ି = ଖାଲି;
	size_t linesize = 0;
	u_long linenum = 0;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r = SSH_ERR_ଚାବି_NOT_FOUND, oerrno;

	/* Check key and principal against file */
	ଯଦି ((f = fopen(path, "r")) == ଖାଲି) {
		oerrno = errno;
		error("Unable to open allowed keys file \"%s\": %s",
		    path, strerror(errno));
		errno = oerrno;
		ଫେରନ୍ତୁ SSH_ERR_SYSTEM_ERROR;
	}

	ଯେତେବେଳେ (getline(&ଧାଡ଼ି, &linesize, f) != -1) {
		linenum++;
		r = check_allowed_ଚାବିଗୁଡ଼ିକ_ଧାଡ଼ି(path, linenum, ଧାଡ଼ି, sign_ଚାବି,
		    principal, sig_namespace, verify_time, ଖାଲି);
		ମୁକ୍ତ(ଧାଡ଼ି);
		ଧାଡ଼ି = ଖାଲି;
		linesize = 0;
		ଯଦି (r == SSH_ERR_ଚାବି_NOT_FOUND)
			ଜାରି;
		ଅନ୍ୟଥା ଯଦି (r == 0) {
			/* success */
			fclose(f);
			ଫେରନ୍ତୁ 0;
		} ଅନ୍ୟଥା
			ଭାଙ୍ଗ;
	}
	/* Either we hit an error parsing or we simply didn't find the key */
	fclose(f);
	ମୁକ୍ତ(ଧାଡ଼ି);
	ଫେରନ୍ତୁ r;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshsig_find_principals(ଅଚଳ ଅକ୍ଷର *path, ଅଚଳ ସଂରଚନା sshkey *sign_ଚାବି,
    uint64_t verify_time, ଅକ୍ଷର **principals)
{
	FILE *f = ଖାଲି;
	ଅକ୍ଷର *ଧାଡ଼ି = ଖାଲି;
	size_t linesize = 0;
	u_long linenum = 0;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r = SSH_ERR_ଚାବି_NOT_FOUND, oerrno;

	ଯଦି ((f = fopen(path, "r")) == ଖାଲି) {
		oerrno = errno;
		error("Unable to open allowed keys file \"%s\": %s",
		    path, strerror(errno));
		errno = oerrno;
		ଫେରନ୍ତୁ SSH_ERR_SYSTEM_ERROR;
	}

	ଯେତେବେଳେ (getline(&ଧାଡ଼ି, &linesize, f) != -1) {
		linenum++;
		r = check_allowed_ଚାବିଗୁଡ଼ିକ_ଧାଡ଼ି(path, linenum, ଧାଡ଼ି,
		    sign_ଚାବି, ଖାଲି, ଖାଲି, verify_time, principals);
		ମୁକ୍ତ(ଧାଡ଼ି);
		ଧାଡ଼ି = ଖାଲି;
		linesize = 0;
		ଯଦି (r == SSH_ERR_ଚାବି_NOT_FOUND)
			ଜାରି;
		ଅନ୍ୟଥା ଯଦି (r == 0) {
			/* success */
			fclose(f);
			ଫେରନ୍ତୁ 0;
		} ଅନ୍ୟଥା
			ଭାଙ୍ଗ;
	}
	ମୁକ୍ତ(ଧାଡ଼ି);
	/* Either we hit an error parsing or we simply didn't find the key */
	ଯଦି (ferror(f) != 0) {
		oerrno = errno;
		fclose(f);
		error("Unable to read allowed keys file \"%s\": %s",
		    path, strerror(errno));
		errno = oerrno;
		ଫେରନ୍ତୁ SSH_ERR_SYSTEM_ERROR;
	}
	fclose(f);
	ଫେରନ୍ତୁ r;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshsig_match_principals(ଅଚଳ ଅକ୍ଷର *path, ଅଚଳ ଅକ୍ଷର *principal,
    ଅକ୍ଷର ***principalsp, size_t *nprincipalsp)
{
	FILE *f = ଖାଲି;
	ଅକ୍ଷର *found, *ଧାଡ଼ି = ଖାଲି, **principals = ଖାଲି, **tmp;
	size_t i, nprincipals = 0, linesize = 0;
	u_long linenum = 0;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା oerrno = 0, r, ret = 0;

	ଯଦି (principalsp != ଖାଲି)
		*principalsp = ଖାଲି;
	ଯଦି (nprincipalsp != ଖାଲି)
		*nprincipalsp = 0;

	/* Check key and principal against file */
	ଯଦି ((f = fopen(path, "r")) == ଖାଲି) {
		oerrno = errno;
		error("Unable to open allowed keys file \"%s\": %s",
		    path, strerror(errno));
		errno = oerrno;
		ଫେରନ୍ତୁ SSH_ERR_SYSTEM_ERROR;
	}

	ଯେତେବେଳେ (getline(&ଧାଡ଼ି, &linesize, f) != -1) {
		linenum++;
		/* Parse the line */
		ଯଦି ((r = parse_principals_ଚାବି_and_options(path, linenum, ଧାଡ଼ି,
		    principal, &found, ଖାଲି, ଖାଲି)) != 0) {
			ଯଦି (r == SSH_ERR_ଚାବି_NOT_FOUND)
				ଜାରି;
			ret = r;
			oerrno = errno;
			ଭାଙ୍ଗ; /* unexpected error */
		}
		ଯଦି ((tmp = recallocarray(principals, nprincipals,
		    nprincipals + 1, ଆକାର(*principals))) == ଖାଲି) {
			ret = SSH_ERR_ALLOC_FAIL;
			ମୁକ୍ତ(found);
			ଭାଙ୍ଗ;
		}
		principals = tmp;
		principals[nprincipals++] = found; /* transferred */
		ମୁକ୍ତ(ଧାଡ଼ି);
		ଧାଡ଼ି = ଖାଲି;
		linesize = 0;
	}
	fclose(f);
	ମୁକ୍ତ(ଧାଡ଼ି);

	ଯଦି (ret == 0) {
		ଯଦି (nprincipals == 0)
			ret = SSH_ERR_ଚାବି_NOT_FOUND;
		ଯଦି (nprincipalsp != ଖାଲି)
			*nprincipalsp = nprincipals;
		ଯଦି (principalsp != ଖାଲି) {
			*principalsp = principals;
			principals = ଖାଲି; /* transferred */
			nprincipals = 0;
		}
	}

	ପାଇଁ (i = 0; i < nprincipals; i++)
		ମୁକ୍ତ(principals[i]);
	ମୁକ୍ତ(principals);

	errno = oerrno;
	ଫେରନ୍ତୁ ret;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshsig_get_pubkey(ସଂରଚନା sshbuf *signature, ସଂରଚନା sshkey **pubkey)
{
	ସଂରଚନା sshkey *pk = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r = SSH_ERR_SIGNATURE_INVALID;

	ଯଦି (pubkey == ଖାଲି)
		ଫେରନ୍ତୁ SSH_ERR_INTERNAL_ERROR;
	ଯଦି ((r = sshsig_parse_preamble(signature)) != 0)
		ଫେରନ୍ତୁ r;
	ଯଦି ((r = sshkey_froms(signature, &pk)) != 0)
		ଫେରନ୍ତୁ r;

	*pubkey = pk;
	pk = ଖାଲି;
	ଫେରନ୍ତୁ 0;
}
