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

#அந்தர்பாவ "includes.h"

#அந்தர்பாவ <stdio.h>
#அந்தர்பாவ <stdlib.h>
#அந்தர்பாவ <stdarg.h>
#அந்தர்பாவ <errno.h>
#அந்தர்பாவ <string.h>
#அந்தர்பாவ <unistd.h>

#அந்தர்பாவ "authfd.h"
#அந்தர்பாவ "authfile.h"
#அந்தர்பாவ "log.h"
#அந்தர்பாவ "misc.h"
#அந்தர்பாவ "sshbuf.h"
#அந்தர்பாவ "sshsig.h"
#அந்தர்பாவ "ssherr.h"
#அந்தர்பாவ "sshkey.h"
#அந்தர்பாவ "match.h"
#அந்தர்பாவ "digest.h"

#define SIG_VERSION		0x01
#define MAGIC_PREAMBLE		"SSHSIG"
#define MAGIC_PREAMBLE_LEN	(அளவு(MAGIC_PREAMBLE) - 1)
#define BEGIN_SIGNATURE		"-----BEGIN SSH SIGNATURE-----"
#define END_SIGNATURE		"-----END SSH SIGNATURE-----"
#define RSA_SIGN_ALG		"rsa-sha2-512"
#define RSA_SIGN_ALLOWED	"rsa-sha2-512,rsa-sha2-256"
#define HASHALG_DEFAULT		"sha512"
#define HASHALG_ALLOWED		"sha256,sha512"

முழு
sshsig_armor(மாறிலி கட்டமைப்பு sshbuf *blob, கட்டமைப்பு sshbuf **out)
{
	கட்டமைப்பு sshbuf *buf = வெற்று;
	முழு r = SSH_ERR_INTERNAL_ERROR;

	*out = வெற்று;

	எனில் ((buf = sshbuf_new()) == வெற்று) {
		error_f("sshbuf_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		செல் out;
	}

	எனில் ((r = sshbuf_putf(buf, "%s\n", BEGIN_SIGNATURE)) != 0) {
		error_fr(r, "sshbuf_putf");
		செல் out;
	}

	எனில் ((r = sshbuf_dtob64(blob, buf, 1)) != 0) {
		error_fr(r, "base64 encode signature");
		செல் out;
	}

	எனில் ((r = sshbuf_put(buf, END_SIGNATURE,
	    அளவு(END_SIGNATURE)-1)) != 0 ||
	    (r = sshbuf_put_u8(buf, '\n')) != 0) {
		error_fr(r, "sshbuf_put");
		செல் out;
	}
	/* success */
	*out = buf;
	buf = வெற்று; /* transferred */
	r = 0;
 out:
	sshbuf_free(buf);
	திரும்பு r;
}

முழு
sshsig_dearmor(கட்டமைப்பு sshbuf *sig, கட்டமைப்பு sshbuf **out)
{
	முழு r;
	size_t eoffset = 0;
	கட்டமைப்பு sshbuf *buf = வெற்று;
	கட்டமைப்பு sshbuf *sbuf = வெற்று;
	எழுத்து *b64 = வெற்று;

	எனில் ((sbuf = sshbuf_fromb(sig)) == வெற்று) {
		error_f("sshbuf_fromb failed");
		திரும்பு SSH_ERR_ALLOC_FAIL;
	}

	/* Expect and consume preamble + lf/crlf */
	எனில் ((r = sshbuf_cmp(sbuf, 0,
	    BEGIN_SIGNATURE, அளவு(BEGIN_SIGNATURE)-1)) != 0) {
		error("Couldn't parse signature: missing header");
		செல் done;
	}
	எனில் ((r = sshbuf_consume(sbuf, அளவு(BEGIN_SIGNATURE)-1)) != 0) {
		error_fr(r, "consume");
		செல் done;
	}
	எனில் ((r = sshbuf_cmp(sbuf, 0, "\r\n", 2)) == 0)
		eoffset = 2;
	இல்லையெனில் எனில் ((r = sshbuf_cmp(sbuf, 0, "\n", 1)) == 0)
		eoffset = 1;
	இல்லையெனில் {
		r = SSH_ERR_INVALID_FORMAT;
		error_f("no header eol");
		செல் done;
	}
	எனில் ((r = sshbuf_consume(sbuf, eoffset)) != 0) {
		error_fr(r, "consume eol");
		செல் done;
	}
	/* Find and consume lf + suffix (any prior cr would be ignored) */
	எனில் ((r = sshbuf_find(sbuf, 0, "\n" END_SIGNATURE,
	    அளவு(END_SIGNATURE), &eoffset)) != 0) {
		error("Couldn't parse signature: missing footer");
		செல் done;
	}
	எனில் ((r = sshbuf_consume_end(sbuf, sshbuf_len(sbuf)-eoffset)) != 0) {
		error_fr(r, "consume");
		செல் done;
	}

	எனில் ((b64 = sshbuf_dup_string(sbuf)) == வெற்று) {
		error_f("sshbuf_dup_string failed");
		r = SSH_ERR_ALLOC_FAIL;
		செல் done;
	}

	எனில் ((buf = sshbuf_new()) == வெற்று) {
		error_f("sshbuf_new() failed");
		r = SSH_ERR_ALLOC_FAIL;
		செல் done;
	}

	எனில் ((r = sshbuf_b64tod(buf, b64)) != 0) {
		error_fr(r, "decode base64");
		செல் done;
	}

	/* success */
	*out = buf;
	r = 0;
	buf = வெற்று; /* transferred */
done:
	sshbuf_free(buf);
	sshbuf_free(sbuf);
	விடுவி(b64);
	திரும்பு r;
}

நிலையான முழு
sshsig_wrap_sign(கட்டமைப்பு sshkey *சாவி, மாறிலி எழுத்து *hashalg,
    மாறிலி எழுத்து *sk_provider, மாறிலி எழுத்து *sk_pin, மாறிலி கட்டமைப்பு sshbuf *h_message,
    மாறிலி எழுத்து *sig_namespace, கட்டமைப்பு sshbuf **out,
    sshsig_signer *signer, வெறுமை *signer_ctx)
{
	முழு r;
	size_t slen = 0;
	u_char *sig = வெற்று;
	கட்டமைப்பு sshbuf *blob = வெற்று;
	கட்டமைப்பு sshbuf *tosign = வெற்று;
	மாறிலி எழுத்து *sign_alg = வெற்று;

	எனில் ((tosign = sshbuf_new()) == வெற்று ||
	    (blob = sshbuf_new()) == வெற்று) {
		error_f("sshbuf_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		செல் done;
	}

	எனில் ((r = sshbuf_put(tosign, MAGIC_PREAMBLE, MAGIC_PREAMBLE_LEN)) != 0 ||
	    (r = sshbuf_put_cstring(tosign, sig_namespace)) != 0 ||
	    (r = sshbuf_put_string(tosign, வெற்று, 0)) != 0 || /* reserved */
	    (r = sshbuf_put_cstring(tosign, hashalg)) != 0 ||
	    (r = sshbuf_put_stringb(tosign, h_message)) != 0) {
		error_fr(r, "assemble message to sign");
		செல் done;
	}

	/* If using RSA keys then default to a good signature algorithm */
	எனில் (sshkey_type_plain(சாவி->type) == சாவி_RSA) {
		sign_alg = RSA_SIGN_ALG;
		எனில் (strcmp(hashalg, "sha256") == 0)
			sign_alg = "rsa-sha2-256";
		இல்லையெனில் எனில் (strcmp(hashalg, "sha512") == 0)
			sign_alg = "rsa-sha2-512";
	}

	எனில் (signer != வெற்று) {
		எனில் ((r = signer(சாவி, &sig, &slen,
		    sshbuf_ptr(tosign), sshbuf_len(tosign),
		    sign_alg, sk_provider, sk_pin, 0, signer_ctx)) != 0) {
			error_r(r, "Couldn't sign message (signer)");
			செல் done;
		}
	} இல்லையெனில் {
		எனில் ((r = sshkey_sign(சாவி, &sig, &slen,
		    sshbuf_ptr(tosign), sshbuf_len(tosign),
		    sign_alg, sk_provider, sk_pin, 0)) != 0) {
			error_r(r, "Couldn't sign message");
			செல் done;
		}
	}

	எனில் ((r = sshbuf_put(blob, MAGIC_PREAMBLE, MAGIC_PREAMBLE_LEN)) != 0 ||
	    (r = sshbuf_put_u32(blob, SIG_VERSION)) != 0 ||
	    (r = sshkey_puts(சாவி, blob)) != 0 ||
	    (r = sshbuf_put_cstring(blob, sig_namespace)) != 0 ||
	    (r = sshbuf_put_string(blob, வெற்று, 0)) != 0 || /* reserved */
	    (r = sshbuf_put_cstring(blob, hashalg)) != 0 ||
	    (r = sshbuf_put_string(blob, sig, slen)) != 0) {
		error_fr(r, "assemble signature object");
		செல் done;
	}

	எனில் (out != வெற்று) {
		*out = blob;
		blob = வெற்று;
	}
	r = 0;
done:
	விடுவி(sig);
	sshbuf_free(blob);
	sshbuf_free(tosign);
	திரும்பு r;
}

/* Check preamble and version. */
நிலையான முழு
sshsig_parse_preamble(கட்டமைப்பு sshbuf *buf)
{
	முழு r = SSH_ERR_INTERNAL_ERROR;
	uint32_t sversion;

	எனில் ((r = sshbuf_cmp(buf, 0, MAGIC_PREAMBLE, MAGIC_PREAMBLE_LEN)) != 0 ||
	    (r = sshbuf_consume(buf, (அளவு(MAGIC_PREAMBLE)-1))) != 0 ||
	    (r = sshbuf_get_u32(buf, &sversion)) != 0) {
		error("Couldn't verify signature: invalid format");
		திரும்பு r;
	}

	எனில் (sversion > SIG_VERSION) {
		error("Signature version %lu is larger than supported "
		    "version %u", (unsigned long)sversion, SIG_VERSION);
		திரும்பு SSH_ERR_INVALID_FORMAT;
	}
	திரும்பு 0;
}

நிலையான முழு
sshsig_check_hashalg(மாறிலி எழுத்து *hashalg)
{
	எனில் (hashalg == வெற்று ||
	    match_pattern_list(hashalg, HASHALG_ALLOWED, 0) == 1)
		திரும்பு 0;
	error_f("unsupported hash algorithm \"%.100s\"", hashalg);
	திரும்பு SSH_ERR_SIGN_ALG_UNSUPPORTED;
}

நிலையான முழு
sshsig_peek_hashalg(கட்டமைப்பு sshbuf *signature, எழுத்து **hashalgp)
{
	கட்டமைப்பு sshbuf *buf = வெற்று;
	எழுத்து *hashalg = வெற்று;
	முழு r = SSH_ERR_INTERNAL_ERROR;

	எனில் (hashalgp != வெற்று)
		*hashalgp = வெற்று;
	எனில் ((buf = sshbuf_fromb(signature)) == வெற்று)
		திரும்பு SSH_ERR_ALLOC_FAIL;
	எனில் ((r = sshsig_parse_preamble(buf)) != 0)
		செல் done;
	எனில் ((r = sshbuf_get_string_direct(buf, வெற்று, வெற்று)) != 0 ||
	    (r = sshbuf_get_string_direct(buf, வெற்று, வெற்று)) != 0 ||
	    (r = sshbuf_get_string(buf, வெற்று, வெற்று)) != 0 ||
	    (r = sshbuf_get_cstring(buf, &hashalg, வெற்று)) != 0 ||
	    (r = sshbuf_get_string_direct(buf, வெற்று, வெற்று)) != 0) {
		error_fr(r, "parse signature object");
		செல் done;
	}

	/* success */
	r = 0;
	*hashalgp = hashalg;
	hashalg = வெற்று;
 done:
	விடுவி(hashalg);
	sshbuf_free(buf);
	திரும்பு r;
}

நிலையான முழு
sshsig_wrap_verify(கட்டமைப்பு sshbuf *signature, மாறிலி எழுத்து *hashalg,
    மாறிலி கட்டமைப்பு sshbuf *h_message, மாறிலி எழுத்து *expect_namespace,
    கட்டமைப்பு sshkey **sign_keyp, கட்டமைப்பு sshkey_sig_details **sig_details)
{
	முழு r = SSH_ERR_INTERNAL_ERROR;
	கட்டமைப்பு sshbuf *buf = வெற்று, *toverify = வெற்று;
	கட்டமைப்பு sshkey *சாவி = வெற்று;
	மாறிலி u_char *sig;
	எழுத்து *got_namespace = வெற்று, *sigtype = வெற்று, *sig_hashalg = வெற்று;
	size_t siglen;

	debug_f("verify message length %zu", sshbuf_len(h_message));
	எனில் (sig_details != வெற்று)
		*sig_details = வெற்று;
	எனில் (sign_keyp != வெற்று)
		*sign_keyp = வெற்று;

	எனில் ((toverify = sshbuf_new()) == வெற்று) {
		error_f("sshbuf_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		செல் done;
	}
	எனில் ((r = sshbuf_put(toverify, MAGIC_PREAMBLE,
	    MAGIC_PREAMBLE_LEN)) != 0 ||
	    (r = sshbuf_put_cstring(toverify, expect_namespace)) != 0 ||
	    (r = sshbuf_put_string(toverify, வெற்று, 0)) != 0 || /* reserved */
	    (r = sshbuf_put_cstring(toverify, hashalg)) != 0 ||
	    (r = sshbuf_put_stringb(toverify, h_message)) != 0) {
		error_fr(r, "assemble message to verify");
		செல் done;
	}

	எனில் ((r = sshsig_parse_preamble(signature)) != 0)
		செல் done;

	எனில் ((r = sshkey_froms(signature, &சாவி)) != 0 ||
	    (r = sshbuf_get_cstring(signature, &got_namespace, வெற்று)) != 0 ||
	    (r = sshbuf_get_string(signature, வெற்று, வெற்று)) != 0 ||
	    (r = sshbuf_get_cstring(signature, &sig_hashalg, வெற்று)) != 0 ||
	    (r = sshbuf_get_string_direct(signature, &sig, &siglen)) != 0) {
		error_fr(r, "parse signature object");
		செல் done;
	}

	எனில் (sshbuf_len(signature) != 0) {
		error("Signature contains trailing data");
		r = SSH_ERR_INVALID_FORMAT;
		செல் done;
	}

	எனில் (strcmp(expect_namespace, got_namespace) != 0) {
		error("Couldn't verify signature: namespace does not match");
		debug_f("expected namespace \"%s\" received \"%s\"",
		    expect_namespace, got_namespace);
		r = SSH_ERR_SIGNATURE_INVALID;
		செல் done;
	}
	எனில் (strcmp(hashalg, sig_hashalg) != 0) {
		error("Couldn't verify signature: hash algorithm mismatch");
		debug_f("expected algorithm \"%s\" received \"%s\"",
		    hashalg, sig_hashalg);
		r = SSH_ERR_SIGNATURE_INVALID;
		செல் done;
	}
	/* Ensure that RSA keys use an acceptable signature algorithm */
	எனில் (sshkey_type_plain(சாவி->type) == சாவி_RSA) {
		எனில் ((r = sshkey_get_sigtype(sig, siglen, &sigtype)) != 0) {
			error_r(r, "Couldn't verify signature: unable to get "
			    "signature type");
			செல் done;
		}
		எனில் (match_pattern_list(sigtype, RSA_SIGN_ALLOWED, 0) != 1) {
			error("Couldn't verify signature: unsupported RSA "
			    "signature algorithm %s", sigtype);
			r = SSH_ERR_SIGN_ALG_UNSUPPORTED;
			செல் done;
		}
	}
	எனில் ((r = sshkey_verify(சாவி, sig, siglen, sshbuf_ptr(toverify),
	    sshbuf_len(toverify), வெற்று, 0, sig_details)) != 0) {
		error_r(r, "Signature verification failed");
		செல் done;
	}

	/* success */
	r = 0;
	எனில் (sign_keyp != வெற்று) {
		*sign_keyp = சாவி;
		சாவி = வெற்று; /* transferred */
	}
done:
	விடுவி(got_namespace);
	விடுவி(sigtype);
	விடுவி(sig_hashalg);
	sshbuf_free(buf);
	sshbuf_free(toverify);
	sshkey_free(சாவி);
	திரும்பு r;
}

நிலையான முழு
hash_buffer(மாறிலி கட்டமைப்பு sshbuf *m, மாறிலி எழுத்து *hashalg, கட்டமைப்பு sshbuf **bp)
{
	எழுத்து *hex, hash[SSH_DIGEST_MAX_LENGTH];
	முழு alg, r = SSH_ERR_INTERNAL_ERROR;
	கட்டமைப்பு sshbuf *b = வெற்று;

	*bp = வெற்று;
	memset(hash, 0, அளவு(hash));

	எனில் ((r = sshsig_check_hashalg(hashalg)) != 0)
		திரும்பு r;
	எனில் ((alg = ssh_digest_alg_by_name(hashalg)) == -1) {
		error_f("can't look up hash algorithm %s", hashalg);
		திரும்பு SSH_ERR_INTERNAL_ERROR;
	}
	எனில் ((r = ssh_digest_buffer(alg, m, hash, அளவு(hash))) != 0) {
		error_fr(r, "ssh_digest_buffer");
		திரும்பு r;
	}
	எனில் ((hex = tohex(hash, ssh_digest_bytes(alg))) != வெற்று) {
		debug3_f("final hash: %s", hex);
		freezero(hex, strlen(hex));
	}
	எனில் ((b = sshbuf_new()) == வெற்று) {
		r = SSH_ERR_ALLOC_FAIL;
		செல் out;
	}
	எனில் ((r = sshbuf_put(b, hash, ssh_digest_bytes(alg))) != 0) {
		error_fr(r, "sshbuf_put");
		செல் out;
	}
	*bp = b;
	b = வெற்று; /* transferred */
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	explicit_bzero(hash, அளவு(hash));
	திரும்பு r;
}

முழு
sshsig_signb(கட்டமைப்பு sshkey *சாவி, மாறிலி எழுத்து *hashalg,
    மாறிலி எழுத்து *sk_provider, மாறிலி எழுத்து *sk_pin,
    மாறிலி கட்டமைப்பு sshbuf *message, மாறிலி எழுத்து *sig_namespace,
    கட்டமைப்பு sshbuf **out, sshsig_signer *signer, வெறுமை *signer_ctx)
{
	கட்டமைப்பு sshbuf *b = வெற்று;
	முழு r = SSH_ERR_INTERNAL_ERROR;

	எனில் (hashalg == வெற்று)
		hashalg = HASHALG_DEFAULT;
	எனில் (out != வெற்று)
		*out = வெற்று;
	எனில் ((r = hash_buffer(message, hashalg, &b)) != 0) {
		error_fr(r, "hash buffer");
		செல் out;
	}
	எனில் ((r = sshsig_wrap_sign(சாவி, hashalg, sk_provider, sk_pin, b,
	    sig_namespace, out, signer, signer_ctx)) != 0)
		செல் out;
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	திரும்பு r;
}

முழு
sshsig_verifyb(கட்டமைப்பு sshbuf *signature, மாறிலி கட்டமைப்பு sshbuf *message,
    மாறிலி எழுத்து *expect_namespace, கட்டமைப்பு sshkey **sign_keyp,
    கட்டமைப்பு sshkey_sig_details **sig_details)
{
	கட்டமைப்பு sshbuf *b = வெற்று;
	முழு r = SSH_ERR_INTERNAL_ERROR;
	எழுத்து *hashalg = வெற்று;

	எனில் (sig_details != வெற்று)
		*sig_details = வெற்று;
	எனில் (sign_keyp != வெற்று)
		*sign_keyp = வெற்று;
	எனில் ((r = sshsig_peek_hashalg(signature, &hashalg)) != 0)
		திரும்பு r;
	debug_f("signature made with hash \"%s\"", hashalg);
	எனில் ((r = hash_buffer(message, hashalg, &b)) != 0) {
		error_fr(r, "hash buffer");
		செல் out;
	}
	எனில் ((r = sshsig_wrap_verify(signature, hashalg, b, expect_namespace,
	    sign_keyp, sig_details)) != 0)
		செல் out;
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	விடுவி(hashalg);
	திரும்பு r;
}

நிலையான முழு
hash_file(முழு fd, மாறிலி எழுத்து *hashalg, கட்டமைப்பு sshbuf **bp)
{
	எழுத்து *hex, rbuf[8192], hash[SSH_DIGEST_MAX_LENGTH];
	ssize_t n, total = 0;
	கட்டமைப்பு ssh_digest_ctx *ctx = வெற்று;
	முழு alg, oerrno, r = SSH_ERR_INTERNAL_ERROR;
	கட்டமைப்பு sshbuf *b = வெற்று;

	*bp = வெற்று;
	memset(hash, 0, அளவு(hash));

	எனில் ((r = sshsig_check_hashalg(hashalg)) != 0)
		திரும்பு r;
	எனில் ((alg = ssh_digest_alg_by_name(hashalg)) == -1) {
		error_f("can't look up hash algorithm %s", hashalg);
		திரும்பு SSH_ERR_INTERNAL_ERROR;
	}
	எனில் ((ctx = ssh_digest_start(alg)) == வெற்று) {
		error_f("ssh_digest_start failed");
		திரும்பு SSH_ERR_INTERNAL_ERROR;
	}
	க்கு (;;) {
		எனில் ((n = பட(fd, rbuf, அளவு(rbuf))) == -1) {
			எனில் (errno == EINTR || errno == EAGAIN)
				தொடர்;
			oerrno = errno;
			error_f("read: %s", strerror(errno));
			errno = oerrno;
			r = SSH_ERR_SYSTEM_ERROR;
			செல் out;
		} இல்லையெனில் எனில் (n == 0) {
			debug2_f("hashed %zu bytes", total);
			நிறுத்து; /* EOF */
		}
		total += (size_t)n;
		எனில் ((r = ssh_digest_update(ctx, rbuf, (size_t)n)) != 0) {
			error_fr(r, "ssh_digest_update");
			செல் out;
		}
	}
	எனில் ((r = ssh_digest_final(ctx, hash, அளவு(hash))) != 0) {
		error_fr(r, "ssh_digest_final");
		செல் out;
	}
	எனில் ((hex = tohex(hash, ssh_digest_bytes(alg))) != வெற்று) {
		debug3_f("final hash: %s", hex);
		freezero(hex, strlen(hex));
	}
	எனில் ((b = sshbuf_new()) == வெற்று) {
		r = SSH_ERR_ALLOC_FAIL;
		செல் out;
	}
	எனில் ((r = sshbuf_put(b, hash, ssh_digest_bytes(alg))) != 0) {
		error_fr(r, "sshbuf_put");
		செல் out;
	}
	*bp = b;
	b = வெற்று; /* transferred */
	/* success */
	r = 0;
 out:
	oerrno = errno;
	sshbuf_free(b);
	ssh_digest_free(ctx);
	explicit_bzero(hash, அளவு(hash));
	errno = oerrno;
	திரும்பு r;
}

முழு
sshsig_sign_fd(கட்டமைப்பு sshkey *சாவி, மாறிலி எழுத்து *hashalg,
    மாறிலி எழுத்து *sk_provider, மாறிலி எழுத்து *sk_pin,
    முழு fd, மாறிலி எழுத்து *sig_namespace, கட்டமைப்பு sshbuf **out,
    sshsig_signer *signer, வெறுமை *signer_ctx)
{
	கட்டமைப்பு sshbuf *b = வெற்று;
	முழு r = SSH_ERR_INTERNAL_ERROR;

	எனில் (hashalg == வெற்று)
		hashalg = HASHALG_DEFAULT;
	எனில் (out != வெற்று)
		*out = வெற்று;
	எனில் ((r = hash_file(fd, hashalg, &b)) != 0) {
		error_fr(r, "hash_file");
		திரும்பு r;
	}
	எனில் ((r = sshsig_wrap_sign(சாவி, hashalg, sk_provider, sk_pin, b,
	    sig_namespace, out, signer, signer_ctx)) != 0)
		செல் out;
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	திரும்பு r;
}

முழு
sshsig_verify_fd(கட்டமைப்பு sshbuf *signature, முழு fd,
    மாறிலி எழுத்து *expect_namespace, கட்டமைப்பு sshkey **sign_keyp,
    கட்டமைப்பு sshkey_sig_details **sig_details)
{
	கட்டமைப்பு sshbuf *b = வெற்று;
	முழு r = SSH_ERR_INTERNAL_ERROR;
	எழுத்து *hashalg = வெற்று;

	எனில் (sig_details != வெற்று)
		*sig_details = வெற்று;
	எனில் (sign_keyp != வெற்று)
		*sign_keyp = வெற்று;
	எனில் ((r = sshsig_peek_hashalg(signature, &hashalg)) != 0)
		திரும்பு r;
	debug_f("signature made with hash \"%s\"", hashalg);
	எனில் ((r = hash_file(fd, hashalg, &b)) != 0) {
		error_fr(r, "hash_file");
		செல் out;
	}
	எனில் ((r = sshsig_wrap_verify(signature, hashalg, b, expect_namespace,
	    sign_keyp, sig_details)) != 0)
		செல் out;
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	விடுவி(hashalg);
	திரும்பு r;
}

கட்டமைப்பு sshsigopt {
	முழு ca;
	எழுத்து *namespaces;
	uint64_t valid_after, valid_before;
};

கட்டமைப்பு sshsigopt *
sshsigopt_parse(மாறிலி எழுத்து *opts, மாறிலி எழுத்து *path, u_long linenum,
    மாறிலி எழுத்து **errstrp)
{
	கட்டமைப்பு sshsigopt *ret;
	முழு r;
	எழுத்து *opt;
	மாறிலி எழுத்து *errstr = வெற்று;

	எனில் ((ret = calloc(1, அளவு(*ret))) == வெற்று)
		திரும்பு வெற்று;
	எனில் (opts == வெற்று || *opts == '\0')
		திரும்பு ret; /* Empty options yields empty options :) */

	போது (*opts && *opts != ' ' && *opts != '\t') {
		/* flag options */
		எனில் ((r = opt_flag("cert-authority", 0, &opts)) != -1) {
			ret->ca = 1;
		} இல்லையெனில் எனில் (opt_match(&opts, "namespaces")) {
			எனில் (ret->namespaces != வெற்று) {
				errstr = "multiple \"namespaces\" clauses";
				செல் fail;
			}
			ret->namespaces = opt_dequote(&opts, &errstr);
			எனில் (ret->namespaces == வெற்று)
				செல் fail;
		} இல்லையெனில் எனில் (opt_match(&opts, "valid-after")) {
			எனில் (ret->valid_after != 0) {
				errstr = "multiple \"valid-after\" clauses";
				செல் fail;
			}
			எனில் ((opt = opt_dequote(&opts, &errstr)) == வெற்று)
				செல் fail;
			எனில் (parse_absolute_time(opt, &ret->valid_after) != 0 ||
			    ret->valid_after == 0) {
				விடுவி(opt);
				errstr = "invalid \"valid-after\" time";
				செல் fail;
			}
			விடுவி(opt);
		} இல்லையெனில் எனில் (opt_match(&opts, "valid-before")) {
			எனில் (ret->valid_before != 0) {
				errstr = "multiple \"valid-before\" clauses";
				செல் fail;
			}
			எனில் ((opt = opt_dequote(&opts, &errstr)) == வெற்று)
				செல் fail;
			எனில் (parse_absolute_time(opt, &ret->valid_before) != 0 ||
			    ret->valid_before == 0) {
				விடுவி(opt);
				errstr = "invalid \"valid-before\" time";
				செல் fail;
			}
			விடுவி(opt);
		}
		/*
		 * Skip the comma, and move to the next option
		 * (or break out if there are no more).
		 */
		எனில் (*opts == '\0' || *opts == ' ' || *opts == '\t')
			நிறுத்து;		/* End of options. */
		/* Anything other than a comma is an unknown option */
		எனில் (*opts != ',') {
			errstr = "unknown key option";
			செல் fail;
		}
		opts++;
		எனில் (*opts == '\0') {
			errstr = "unexpected end-of-options";
			செல் fail;
		}
	}
	/* final consistency check */
	எனில் (ret->valid_after != 0 && ret->valid_before != 0 &&
	    ret->valid_before <= ret->valid_after) {
		errstr = "\"valid-before\" time is before \"valid-after\"";
		செல் fail;
	}
	/* success */
	திரும்பு ret;
 fail:
	எனில் (errstrp != வெற்று)
		*errstrp = errstr;
	sshsigopt_free(ret);
	திரும்பு வெற்று;
}

வெறுமை
sshsigopt_free(கட்டமைப்பு sshsigopt *opts)
{
	எனில் (opts == வெற்று)
		திரும்பு;
	விடுவி(opts->namespaces);
	விடுவி(opts);
}

நிலையான முழு
parse_principals_சாவி_and_options(மாறிலி எழுத்து *path, u_long linenum, எழுத்து *வரி,
    மாறிலி எழுத்து *required_principal, எழுத்து **principalsp, கட்டமைப்பு sshkey **keyp,
    கட்டமைப்பு sshsigopt **sigoptsp)
{
	எழுத்து *opts = வெற்று, *tmp, *cp, *principals = வெற்று;
	மாறிலி எழுத்து *reason = வெற்று;
	கட்டமைப்பு sshsigopt *sigopts = வெற்று;
	கட்டமைப்பு sshkey *சாவி = வெற்று;
	முழு r = SSH_ERR_INTERNAL_ERROR;

	எனில் (principalsp != வெற்று)
		*principalsp = வெற்று;
	எனில் (sigoptsp != வெற்று)
		*sigoptsp = வெற்று;
	எனில் (keyp != வெற்று)
		*keyp = வெற்று;

	cp = வரி;
	cp = cp + strspn(cp, " \t\n\r"); /* skip leading whitespace */
	எனில் (*cp == '#' || *cp == '\0')
		திரும்பு SSH_ERR_சாவி_NOT_FOUND; /* blank or all-comment line */

	/* format: identity[,identity...] [option[,option...]] key */
	எனில் ((tmp = strdelimw(&cp)) == வெற்று || cp == வெற்று) {
		error("%s:%lu: invalid line", path, linenum);
		r = SSH_ERR_INVALID_FORMAT;
		செல் out;
	}
	எனில் ((principals = strdup(tmp)) == வெற்று) {
		error_f("strdup failed");
		r = SSH_ERR_ALLOC_FAIL;
		செல் out;
	}
	/*
	 * Bail out early if we're looking for a particular principal and this
	 * line does not list it.
	 */
	எனில் (required_principal != வெற்று) {
		எனில் (match_pattern_list(required_principal,
		    principals, 0) != 1) {
			/* principal didn't match */
			r = SSH_ERR_சாவி_NOT_FOUND;
			செல் out;
		}
		debug_f("%s:%lu: matched principal \"%s\"",
		    path, linenum, required_principal);
	}

	எனில் ((சாவி = sshkey_new(சாவி_UNSPEC)) == வெற்று) {
		error_f("sshkey_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		செல் out;
	}
	எனில் (sshkey_read(சாவி, &cp) != 0) {
		/* no key? Check for options */
		opts = cp;
		எனில் (sshkey_advance_past_options(&cp) != 0) {
			error("%s:%lu: invalid options", path, linenum);
			r = SSH_ERR_INVALID_FORMAT;
			செல் out;
		}
		எனில் (cp == வெற்று || *cp == '\0') {
			error("%s:%lu: missing key", path, linenum);
			r = SSH_ERR_INVALID_FORMAT;
			செல் out;
		}
		*cp++ = '\0';
		skip_space(&cp);
		எனில் (sshkey_read(சாவி, &cp) != 0) {
			error("%s:%lu: invalid key", path, linenum);
			r = SSH_ERR_INVALID_FORMAT;
			செல் out;
		}
	}
	debug3("%s:%lu: options %s", path, linenum, opts == வெற்று ? "" : opts);
	எனில் ((sigopts = sshsigopt_parse(opts, path, linenum, &reason)) == வெற்று) {
		error("%s:%lu: bad options: %s", path, linenum, reason);
		r = SSH_ERR_INVALID_FORMAT;
		செல் out;
	}
	/* success */
	எனில் (principalsp != வெற்று) {
		*principalsp = principals;
		principals = வெற்று; /* transferred */
	}
	எனில் (sigoptsp != வெற்று) {
		*sigoptsp = sigopts;
		sigopts = வெற்று; /* transferred */
	}
	எனில் (keyp != வெற்று) {
		*keyp = சாவி;
		சாவி = வெற்று; /* transferred */
	}
	r = 0;
 out:
	விடுவி(principals);
	sshsigopt_free(sigopts);
	sshkey_free(சாவி);
	திரும்பு r;
}

நிலையான முழு
cert_filter_principals(மாறிலி எழுத்து *path, u_long linenum,
    எழுத்து **principalsp, மாறிலி கட்டமைப்பு sshkey *cert, uint64_t verify_time)
{
	எழுத்து *cp, *oprincipals, *principals;
	மாறிலி எழுத்து *reason;
	கட்டமைப்பு sshbuf *nprincipals;
	முழு r = SSH_ERR_INTERNAL_ERROR, success = 0;
	u_int i;

	oprincipals = principals = *principalsp;
	*principalsp = வெற்று;

	எனில் ((nprincipals = sshbuf_new()) == வெற்று) {
		r = SSH_ERR_ALLOC_FAIL;
		செல் out;
	}

	போது ((cp = strsep(&principals, ",")) != வெற்று && *cp != '\0') {
		/* Check certificate validity */
		எனில் ((r = sshkey_cert_check_authority(cert, 0, 0, verify_time,
		    வெற்று, &reason)) != 0) {
			debug("%s:%lu: principal \"%s\" not authorized: %s",
			    path, linenum, cp, reason);
			தொடர்;
		}
		/* Return all matching principal names from the cert */
		க்கு (i = 0; i < cert->cert->nprincipals; i++) {
			எனில் (match_pattern(cert->cert->principals[i], cp)) {
				எனில் ((r = sshbuf_putf(nprincipals, "%s%s",
					sshbuf_len(nprincipals) != 0 ? "," : "",
						cert->cert->principals[i])) != 0) {
					error_f("buffer error");
					செல் out;
				}
			}
		}
	}
	எனில் (sshbuf_len(nprincipals) == 0) {
		error("%s:%lu: no valid principals found", path, linenum);
		r = SSH_ERR_சாவி_CERT_INVALID;
		செல் out;
	}
	எனில் ((principals = sshbuf_dup_string(nprincipals)) == வெற்று) {
		error_f("buffer error");
		r = SSH_ERR_ALLOC_FAIL;
		செல் out;
	}
	/* success */
	success = 1;
	*principalsp = principals;
 out:
	sshbuf_free(nprincipals);
	விடுவி(oprincipals);
	திரும்பு success ? 0 : r;
}

நிலையான முழு
check_allowed_சாவிகள்_வரி(மாறிலி எழுத்து *path, u_long linenum, எழுத்து *வரி,
    மாறிலி கட்டமைப்பு sshkey *sign_சாவி, மாறிலி எழுத்து *principal,
    மாறிலி எழுத்து *sig_namespace, uint64_t verify_time, எழுத்து **principalsp)
{
	கட்டமைப்பு sshkey *found_சாவி = வெற்று;
	எழுத்து *principals = வெற்று;
	முழு r, success = 0;
	மாறிலி எழுத்து *reason = வெற்று;
	கட்டமைப்பு sshsigopt *sigopts = வெற்று;
	எழுத்து tvalid[64], tverify[64];

	எனில் (principalsp != வெற்று)
		*principalsp = வெற்று;

	/* Parse the line */
	எனில் ((r = parse_principals_சாவி_and_options(path, linenum, வரி,
	    principal, &principals, &found_சாவி, &sigopts)) != 0) {
		/* error already logged */
		செல் done;
	}

	எனில் (!sigopts->ca && sshkey_equal(found_சாவி, sign_சாவி)) {
		/* Exact match of key */
		debug("%s:%lu: matched key", path, linenum);
	} இல்லையெனில் எனில் (sigopts->ca && sshkey_is_cert(sign_சாவி) &&
	    sshkey_equal_public(sign_சாவி->cert->signature_சாவி, found_சாவி)) {
		எனில் (principal) {
			/* Match certificate CA key with specified principal */
			எனில் ((r = sshkey_cert_check_authority(sign_சாவி, 0, 0,
			    verify_time, principal, &reason)) != 0) {
				error("%s:%lu: certificate not authorized: %s",
				    path, linenum, reason);
				செல் done;
			}
			debug("%s:%lu: matched certificate CA key",
			    path, linenum);
		} இல்லையெனில் {
			/* No principal specified - find all matching ones */
			எனில் ((r = cert_filter_principals(path, linenum,
			    &principals, sign_சாவி, verify_time)) != 0) {
				/* error already displayed */
				debug_r(r, "%s:%lu: cert_filter_principals",
				    path, linenum);
				செல் done;
			}
			debug("%s:%lu: matched certificate CA key",
			    path, linenum);
		}
	} இல்லையெனில் {
		/* Didn't match key */
		செல் done;
	}

	/* Check whether options preclude the use of this key */
	எனில் (sigopts->namespaces != வெற்று && sig_namespace != வெற்று &&
	    match_pattern_list(sig_namespace, sigopts->namespaces, 0) != 1) {
		error("%s:%lu: key is not permitted for use in signature "
		    "namespace \"%s\"", path, linenum, sig_namespace);
		செல் done;
	}

	/* check key time validity */
	format_absolute_time((uint64_t)verify_time, tverify, அளவு(tverify));
	எனில் (sigopts->valid_after != 0 &&
	    (uint64_t)verify_time < sigopts->valid_after) {
		format_absolute_time(sigopts->valid_after,
		    tvalid, அளவு(tvalid));
		error("%s:%lu: key is not yet valid: "
		    "verify time %s < valid-after %s", path, linenum,
		    tverify, tvalid);
		செல் done;
	}
	எனில் (sigopts->valid_before != 0 &&
	    (uint64_t)verify_time > sigopts->valid_before) {
		format_absolute_time(sigopts->valid_before,
		    tvalid, அளவு(tvalid));
		error("%s:%lu: key has expired: "
		    "verify time %s > valid-before %s", path, linenum,
		    tverify, tvalid);
		செல் done;
	}
	success = 1;

 done:
	எனில் (success && principalsp != வெற்று) {
		*principalsp = principals;
		principals = வெற்று; /* transferred */
	}
	விடுவி(principals);
	sshkey_free(found_சாவி);
	sshsigopt_free(sigopts);
	திரும்பு success ? 0 : SSH_ERR_சாவி_NOT_FOUND;
}

முழு
sshsig_check_allowed_சாவிகள்(மாறிலி எழுத்து *path, மாறிலி கட்டமைப்பு sshkey *sign_சாவி,
    மாறிலி எழுத்து *principal, மாறிலி எழுத்து *sig_namespace, uint64_t verify_time)
{
	FILE *f = வெற்று;
	எழுத்து *வரி = வெற்று;
	size_t linesize = 0;
	u_long linenum = 0;
	முழு r = SSH_ERR_சாவி_NOT_FOUND, oerrno;

	/* Check key and principal against file */
	எனில் ((f = fopen(path, "r")) == வெற்று) {
		oerrno = errno;
		error("Unable to open allowed keys file \"%s\": %s",
		    path, strerror(errno));
		errno = oerrno;
		திரும்பு SSH_ERR_SYSTEM_ERROR;
	}

	போது (getline(&வரி, &linesize, f) != -1) {
		linenum++;
		r = check_allowed_சாவிகள்_வரி(path, linenum, வரி, sign_சாவி,
		    principal, sig_namespace, verify_time, வெற்று);
		விடுவி(வரி);
		வரி = வெற்று;
		linesize = 0;
		எனில் (r == SSH_ERR_சாவி_NOT_FOUND)
			தொடர்;
		இல்லையெனில் எனில் (r == 0) {
			/* success */
			fclose(f);
			திரும்பு 0;
		} இல்லையெனில்
			நிறுத்து;
	}
	/* Either we hit an error parsing or we simply didn't find the key */
	fclose(f);
	விடுவி(வரி);
	திரும்பு r;
}

முழு
sshsig_find_principals(மாறிலி எழுத்து *path, மாறிலி கட்டமைப்பு sshkey *sign_சாவி,
    uint64_t verify_time, எழுத்து **principals)
{
	FILE *f = வெற்று;
	எழுத்து *வரி = வெற்று;
	size_t linesize = 0;
	u_long linenum = 0;
	முழு r = SSH_ERR_சாவி_NOT_FOUND, oerrno;

	எனில் ((f = fopen(path, "r")) == வெற்று) {
		oerrno = errno;
		error("Unable to open allowed keys file \"%s\": %s",
		    path, strerror(errno));
		errno = oerrno;
		திரும்பு SSH_ERR_SYSTEM_ERROR;
	}

	போது (getline(&வரி, &linesize, f) != -1) {
		linenum++;
		r = check_allowed_சாவிகள்_வரி(path, linenum, வரி,
		    sign_சாவி, வெற்று, வெற்று, verify_time, principals);
		விடுவி(வரி);
		வரி = வெற்று;
		linesize = 0;
		எனில் (r == SSH_ERR_சாவி_NOT_FOUND)
			தொடர்;
		இல்லையெனில் எனில் (r == 0) {
			/* success */
			fclose(f);
			திரும்பு 0;
		} இல்லையெனில்
			நிறுத்து;
	}
	விடுவி(வரி);
	/* Either we hit an error parsing or we simply didn't find the key */
	எனில் (ferror(f) != 0) {
		oerrno = errno;
		fclose(f);
		error("Unable to read allowed keys file \"%s\": %s",
		    path, strerror(errno));
		errno = oerrno;
		திரும்பு SSH_ERR_SYSTEM_ERROR;
	}
	fclose(f);
	திரும்பு r;
}

முழு
sshsig_match_principals(மாறிலி எழுத்து *path, மாறிலி எழுத்து *principal,
    எழுத்து ***principalsp, size_t *nprincipalsp)
{
	FILE *f = வெற்று;
	எழுத்து *found, *வரி = வெற்று, **principals = வெற்று, **tmp;
	size_t i, nprincipals = 0, linesize = 0;
	u_long linenum = 0;
	முழு oerrno = 0, r, ret = 0;

	எனில் (principalsp != வெற்று)
		*principalsp = வெற்று;
	எனில் (nprincipalsp != வெற்று)
		*nprincipalsp = 0;

	/* Check key and principal against file */
	எனில் ((f = fopen(path, "r")) == வெற்று) {
		oerrno = errno;
		error("Unable to open allowed keys file \"%s\": %s",
		    path, strerror(errno));
		errno = oerrno;
		திரும்பு SSH_ERR_SYSTEM_ERROR;
	}

	போது (getline(&வரி, &linesize, f) != -1) {
		linenum++;
		/* Parse the line */
		எனில் ((r = parse_principals_சாவி_and_options(path, linenum, வரி,
		    principal, &found, வெற்று, வெற்று)) != 0) {
			எனில் (r == SSH_ERR_சாவி_NOT_FOUND)
				தொடர்;
			ret = r;
			oerrno = errno;
			நிறுத்து; /* unexpected error */
		}
		எனில் ((tmp = recallocarray(principals, nprincipals,
		    nprincipals + 1, அளவு(*principals))) == வெற்று) {
			ret = SSH_ERR_ALLOC_FAIL;
			விடுவி(found);
			நிறுத்து;
		}
		principals = tmp;
		principals[nprincipals++] = found; /* transferred */
		விடுவி(வரி);
		வரி = வெற்று;
		linesize = 0;
	}
	fclose(f);
	விடுவி(வரி);

	எனில் (ret == 0) {
		எனில் (nprincipals == 0)
			ret = SSH_ERR_சாவி_NOT_FOUND;
		எனில் (nprincipalsp != வெற்று)
			*nprincipalsp = nprincipals;
		எனில் (principalsp != வெற்று) {
			*principalsp = principals;
			principals = வெற்று; /* transferred */
			nprincipals = 0;
		}
	}

	க்கு (i = 0; i < nprincipals; i++)
		விடுவி(principals[i]);
	விடுவி(principals);

	errno = oerrno;
	திரும்பு ret;
}

முழு
sshsig_get_pubkey(கட்டமைப்பு sshbuf *signature, கட்டமைப்பு sshkey **pubkey)
{
	கட்டமைப்பு sshkey *pk = வெற்று;
	முழு r = SSH_ERR_SIGNATURE_INVALID;

	எனில் (pubkey == வெற்று)
		திரும்பு SSH_ERR_INTERNAL_ERROR;
	எனில் ((r = sshsig_parse_preamble(signature)) != 0)
		திரும்பு r;
	எனில் ((r = sshkey_froms(signature, &pk)) != 0)
		திரும்பு r;

	*pubkey = pk;
	pk = வெற்று;
	திரும்பு 0;
}
