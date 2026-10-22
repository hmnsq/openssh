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

#ضمن "includes.h"

#ضمن <stdio.h>
#ضمن <stdlib.h>
#ضمن <stdarg.h>
#ضمن <errno.h>
#ضمن <string.h>
#ضمن <unistd.h>

#ضمن "authfd.h"
#ضمن "authfile.h"
#ضمن "log.h"
#ضمن "misc.h"
#ضمن "sshbuf.h"
#ضمن "sshsig.h"
#ضمن "ssherr.h"
#ضمن "sshkey.h"
#ضمن "match.h"
#ضمن "digest.h"

#define SIG_VERSION		0x01
#define MAGIC_PREAMBLE		"SSHSIG"
#define MAGIC_PREAMBLE_LEN	(حجم(MAGIC_PREAMBLE) - 1)
#define BEGIN_SIGNATURE		"-----BEGIN SSH SIGNATURE-----"
#define END_SIGNATURE		"-----END SSH SIGNATURE-----"
#define RSA_SIGN_ALG		"rsa-sha2-512"
#define RSA_SIGN_ALLOWED	"rsa-sha2-512,rsa-sha2-256"
#define HASHALG_DEFAULT		"sha512"
#define HASHALG_ALLOWED		"sha256,sha512"

صحيح
sshsig_armor(ثابت بنية sshbuf *blob, بنية sshbuf **out)
{
	بنية sshbuf *buf = عدم;
	صحيح r = SSH_ERR_INTERNAL_ERROR;

	*out = عدم;

	𐡄𐡍 ((buf = sshbuf_new()) == عدم) {
		error_f("sshbuf_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		اذهب out;
	}

	𐡄𐡍 ((r = sshbuf_putf(buf, "%s\n", BEGIN_SIGNATURE)) != 0) {
		error_fr(r, "sshbuf_putf");
		اذهب out;
	}

	𐡄𐡍 ((r = sshbuf_dtob64(blob, buf, 1)) != 0) {
		error_fr(r, "base64 encode signature");
		اذهب out;
	}

	𐡄𐡍 ((r = sshbuf_put(buf, END_SIGNATURE,
	    حجم(END_SIGNATURE)-1)) != 0 ||
	    (r = sshbuf_put_u8(buf, '\n')) != 0) {
		error_fr(r, "sshbuf_put");
		اذهب out;
	}
	/* success */
	*out = buf;
	buf = عدم; /* transferred */
	r = 0;
 out:
	sshbuf_free(buf);
	أرجع r;
}

صحيح
sshsig_dearmor(بنية sshbuf *sig, بنية sshbuf **out)
{
	صحيح r;
	size_t eoffset = 0;
	بنية sshbuf *buf = عدم;
	بنية sshbuf *sbuf = عدم;
	حرف *b64 = عدم;

	𐡄𐡍 ((sbuf = sshbuf_fromb(sig)) == عدم) {
		error_f("sshbuf_fromb failed");
		أرجع SSH_ERR_ALLOC_FAIL;
	}

	/* Expect and consume preamble + lf/crlf */
	𐡄𐡍 ((r = sshbuf_cmp(sbuf, 0,
	    BEGIN_SIGNATURE, حجم(BEGIN_SIGNATURE)-1)) != 0) {
		error("Couldn't parse signature: missing header");
		اذهب done;
	}
	𐡄𐡍 ((r = sshbuf_consume(sbuf, حجم(BEGIN_SIGNATURE)-1)) != 0) {
		error_fr(r, "consume");
		اذهب done;
	}
	𐡄𐡍 ((r = sshbuf_cmp(sbuf, 0, "\r\n", 2)) == 0)
		eoffset = 2;
	وإلا 𐡄𐡍 ((r = sshbuf_cmp(sbuf, 0, "\n", 1)) == 0)
		eoffset = 1;
	وإلا {
		r = SSH_ERR_INVALID_FORMAT;
		error_f("no header eol");
		اذهب done;
	}
	𐡄𐡍 ((r = sshbuf_consume(sbuf, eoffset)) != 0) {
		error_fr(r, "consume eol");
		اذهب done;
	}
	/* Find and consume lf + suffix (any prior cr would be ignored) */
	𐡄𐡍 ((r = sshbuf_find(sbuf, 0, "\n" END_SIGNATURE,
	    حجم(END_SIGNATURE), &eoffset)) != 0) {
		error("Couldn't parse signature: missing footer");
		اذهب done;
	}
	𐡄𐡍 ((r = sshbuf_consume_end(sbuf, sshbuf_len(sbuf)-eoffset)) != 0) {
		error_fr(r, "consume");
		اذهب done;
	}

	𐡄𐡍 ((b64 = sshbuf_dup_string(sbuf)) == عدم) {
		error_f("sshbuf_dup_string failed");
		r = SSH_ERR_ALLOC_FAIL;
		اذهب done;
	}

	𐡄𐡍 ((buf = sshbuf_new()) == عدم) {
		error_f("sshbuf_new() failed");
		r = SSH_ERR_ALLOC_FAIL;
		اذهب done;
	}

	𐡄𐡍 ((r = sshbuf_b64tod(buf, b64)) != 0) {
		error_fr(r, "decode base64");
		اذهب done;
	}

	/* success */
	*out = buf;
	r = 0;
	buf = عدم; /* transferred */
done:
	sshbuf_free(buf);
	sshbuf_free(sbuf);
	حرر(b64);
	أرجع r;
}

ساكن صحيح
sshsig_wrap_sign(بنية sshkey *key, ثابت حرف *hashalg,
    ثابت حرف *sk_provider, ثابت حرف *sk_pin, ثابت بنية sshbuf *h_message,
    ثابت حرف *sig_namespace, بنية sshbuf **out,
    sshsig_signer *signer, فراغ *signer_ctx)
{
	صحيح r;
	size_t slen = 0;
	u_char *sig = عدم;
	بنية sshbuf *blob = عدم;
	بنية sshbuf *tosign = عدم;
	ثابت حرف *sign_alg = عدم;

	𐡄𐡍 ((tosign = sshbuf_new()) == عدم ||
	    (blob = sshbuf_new()) == عدم) {
		error_f("sshbuf_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		اذهب done;
	}

	𐡄𐡍 ((r = sshbuf_put(tosign, MAGIC_PREAMBLE, MAGIC_PREAMBLE_LEN)) != 0 ||
	    (r = sshbuf_put_cstring(tosign, sig_namespace)) != 0 ||
	    (r = sshbuf_put_string(tosign, عدم, 0)) != 0 || /* reserved */
	    (r = sshbuf_put_cstring(tosign, hashalg)) != 0 ||
	    (r = sshbuf_put_stringb(tosign, h_message)) != 0) {
		error_fr(r, "assemble message to sign");
		اذهب done;
	}

	/* If using RSA keys then default to a good signature algorithm */
	𐡄𐡍 (sshkey_type_plain(key->type) == KEY_RSA) {
		sign_alg = RSA_SIGN_ALG;
		𐡄𐡍 (strcmp(hashalg, "sha256") == 0)
			sign_alg = "rsa-sha2-256";
		وإلا 𐡄𐡍 (strcmp(hashalg, "sha512") == 0)
			sign_alg = "rsa-sha2-512";
	}

	𐡄𐡍 (signer != عدم) {
		𐡄𐡍 ((r = signer(key, &sig, &slen,
		    sshbuf_ptr(tosign), sshbuf_len(tosign),
		    sign_alg, sk_provider, sk_pin, 0, signer_ctx)) != 0) {
			error_r(r, "Couldn't sign message (signer)");
			اذهب done;
		}
	} وإلا {
		𐡄𐡍 ((r = sshkey_sign(key, &sig, &slen,
		    sshbuf_ptr(tosign), sshbuf_len(tosign),
		    sign_alg, sk_provider, sk_pin, 0)) != 0) {
			error_r(r, "Couldn't sign message");
			اذهب done;
		}
	}

	𐡄𐡍 ((r = sshbuf_put(blob, MAGIC_PREAMBLE, MAGIC_PREAMBLE_LEN)) != 0 ||
	    (r = sshbuf_put_u32(blob, SIG_VERSION)) != 0 ||
	    (r = sshkey_puts(key, blob)) != 0 ||
	    (r = sshbuf_put_cstring(blob, sig_namespace)) != 0 ||
	    (r = sshbuf_put_string(blob, عدم, 0)) != 0 || /* reserved */
	    (r = sshbuf_put_cstring(blob, hashalg)) != 0 ||
	    (r = sshbuf_put_string(blob, sig, slen)) != 0) {
		error_fr(r, "assemble signature object");
		اذهب done;
	}

	𐡄𐡍 (out != عدم) {
		*out = blob;
		blob = عدم;
	}
	r = 0;
done:
	حرر(sig);
	sshbuf_free(blob);
	sshbuf_free(tosign);
	أرجع r;
}

/* Check preamble and version. */
ساكن صحيح
sshsig_parse_preamble(بنية sshbuf *buf)
{
	صحيح r = SSH_ERR_INTERNAL_ERROR;
	uint32_t sversion;

	𐡄𐡍 ((r = sshbuf_cmp(buf, 0, MAGIC_PREAMBLE, MAGIC_PREAMBLE_LEN)) != 0 ||
	    (r = sshbuf_consume(buf, (حجم(MAGIC_PREAMBLE)-1))) != 0 ||
	    (r = sshbuf_get_u32(buf, &sversion)) != 0) {
		error("Couldn't verify signature: invalid format");
		أرجع r;
	}

	𐡄𐡍 (sversion > SIG_VERSION) {
		error("Signature version %lu is larger than supported "
		    "version %u", (unsigned long)sversion, SIG_VERSION);
		أرجع SSH_ERR_INVALID_FORMAT;
	}
	أرجع 0;
}

ساكن صحيح
sshsig_check_hashalg(ثابت حرف *hashalg)
{
	𐡄𐡍 (hashalg == عدم ||
	    match_pattern_list(hashalg, HASHALG_ALLOWED, 0) == 1)
		أرجع 0;
	error_f("unsupported hash algorithm \"%.100s\"", hashalg);
	أرجع SSH_ERR_SIGN_ALG_UNSUPPORTED;
}

ساكن صحيح
sshsig_peek_hashalg(بنية sshbuf *signature, حرف **hashalgp)
{
	بنية sshbuf *buf = عدم;
	حرف *hashalg = عدم;
	صحيح r = SSH_ERR_INTERNAL_ERROR;

	𐡄𐡍 (hashalgp != عدم)
		*hashalgp = عدم;
	𐡄𐡍 ((buf = sshbuf_fromb(signature)) == عدم)
		أرجع SSH_ERR_ALLOC_FAIL;
	𐡄𐡍 ((r = sshsig_parse_preamble(buf)) != 0)
		اذهب done;
	𐡄𐡍 ((r = sshbuf_get_string_direct(buf, عدم, عدم)) != 0 ||
	    (r = sshbuf_get_string_direct(buf, عدم, عدم)) != 0 ||
	    (r = sshbuf_get_string(buf, عدم, عدم)) != 0 ||
	    (r = sshbuf_get_cstring(buf, &hashalg, عدم)) != 0 ||
	    (r = sshbuf_get_string_direct(buf, عدم, عدم)) != 0) {
		error_fr(r, "parse signature object");
		اذهب done;
	}

	/* success */
	r = 0;
	*hashalgp = hashalg;
	hashalg = عدم;
 done:
	حرر(hashalg);
	sshbuf_free(buf);
	أرجع r;
}

ساكن صحيح
sshsig_wrap_verify(بنية sshbuf *signature, ثابت حرف *hashalg,
    ثابت بنية sshbuf *h_message, ثابت حرف *expect_namespace,
    بنية sshkey **sign_keyp, بنية sshkey_sig_details **sig_details)
{
	صحيح r = SSH_ERR_INTERNAL_ERROR;
	بنية sshbuf *buf = عدم, *toverify = عدم;
	بنية sshkey *key = عدم;
	ثابت u_char *sig;
	حرف *got_namespace = عدم, *sigtype = عدم, *sig_hashalg = عدم;
	size_t siglen;

	debug_f("verify message length %zu", sshbuf_len(h_message));
	𐡄𐡍 (sig_details != عدم)
		*sig_details = عدم;
	𐡄𐡍 (sign_keyp != عدم)
		*sign_keyp = عدم;

	𐡄𐡍 ((toverify = sshbuf_new()) == عدم) {
		error_f("sshbuf_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		اذهب done;
	}
	𐡄𐡍 ((r = sshbuf_put(toverify, MAGIC_PREAMBLE,
	    MAGIC_PREAMBLE_LEN)) != 0 ||
	    (r = sshbuf_put_cstring(toverify, expect_namespace)) != 0 ||
	    (r = sshbuf_put_string(toverify, عدم, 0)) != 0 || /* reserved */
	    (r = sshbuf_put_cstring(toverify, hashalg)) != 0 ||
	    (r = sshbuf_put_stringb(toverify, h_message)) != 0) {
		error_fr(r, "assemble message to verify");
		اذهب done;
	}

	𐡄𐡍 ((r = sshsig_parse_preamble(signature)) != 0)
		اذهب done;

	𐡄𐡍 ((r = sshkey_froms(signature, &key)) != 0 ||
	    (r = sshbuf_get_cstring(signature, &got_namespace, عدم)) != 0 ||
	    (r = sshbuf_get_string(signature, عدم, عدم)) != 0 ||
	    (r = sshbuf_get_cstring(signature, &sig_hashalg, عدم)) != 0 ||
	    (r = sshbuf_get_string_direct(signature, &sig, &siglen)) != 0) {
		error_fr(r, "parse signature object");
		اذهب done;
	}

	𐡄𐡍 (sshbuf_len(signature) != 0) {
		error("Signature contains trailing data");
		r = SSH_ERR_INVALID_FORMAT;
		اذهب done;
	}

	𐡄𐡍 (strcmp(expect_namespace, got_namespace) != 0) {
		error("Couldn't verify signature: namespace does not match");
		debug_f("expected namespace \"%s\" received \"%s\"",
		    expect_namespace, got_namespace);
		r = SSH_ERR_SIGNATURE_INVALID;
		اذهب done;
	}
	𐡄𐡍 (strcmp(hashalg, sig_hashalg) != 0) {
		error("Couldn't verify signature: hash algorithm mismatch");
		debug_f("expected algorithm \"%s\" received \"%s\"",
		    hashalg, sig_hashalg);
		r = SSH_ERR_SIGNATURE_INVALID;
		اذهب done;
	}
	/* Ensure that RSA keys use an acceptable signature algorithm */
	𐡄𐡍 (sshkey_type_plain(key->type) == KEY_RSA) {
		𐡄𐡍 ((r = sshkey_get_sigtype(sig, siglen, &sigtype)) != 0) {
			error_r(r, "Couldn't verify signature: unable to get "
			    "signature type");
			اذهب done;
		}
		𐡄𐡍 (match_pattern_list(sigtype, RSA_SIGN_ALLOWED, 0) != 1) {
			error("Couldn't verify signature: unsupported RSA "
			    "signature algorithm %s", sigtype);
			r = SSH_ERR_SIGN_ALG_UNSUPPORTED;
			اذهب done;
		}
	}
	𐡄𐡍 ((r = sshkey_verify(key, sig, siglen, sshbuf_ptr(toverify),
	    sshbuf_len(toverify), عدم, 0, sig_details)) != 0) {
		error_r(r, "Signature verification failed");
		اذهب done;
	}

	/* success */
	r = 0;
	𐡄𐡍 (sign_keyp != عدم) {
		*sign_keyp = key;
		key = عدم; /* transferred */
	}
done:
	حرر(got_namespace);
	حرر(sigtype);
	حرر(sig_hashalg);
	sshbuf_free(buf);
	sshbuf_free(toverify);
	sshkey_free(key);
	أرجع r;
}

ساكن صحيح
hash_buffer(ثابت بنية sshbuf *m, ثابت حرف *hashalg, بنية sshbuf **bp)
{
	حرف *hex, hash[SSH_DIGEST_MAX_LENGTH];
	صحيح alg, r = SSH_ERR_INTERNAL_ERROR;
	بنية sshbuf *b = عدم;

	*bp = عدم;
	memset(hash, 0, حجم(hash));

	𐡄𐡍 ((r = sshsig_check_hashalg(hashalg)) != 0)
		أرجع r;
	𐡄𐡍 ((alg = ssh_digest_alg_by_name(hashalg)) == -1) {
		error_f("can't look up hash algorithm %s", hashalg);
		أرجع SSH_ERR_INTERNAL_ERROR;
	}
	𐡄𐡍 ((r = ssh_digest_buffer(alg, m, hash, حجم(hash))) != 0) {
		error_fr(r, "ssh_digest_buffer");
		أرجع r;
	}
	𐡄𐡍 ((hex = tohex(hash, ssh_digest_bytes(alg))) != عدم) {
		debug3_f("final hash: %s", hex);
		freezero(hex, strlen(hex));
	}
	𐡄𐡍 ((b = sshbuf_new()) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب out;
	}
	𐡄𐡍 ((r = sshbuf_put(b, hash, ssh_digest_bytes(alg))) != 0) {
		error_fr(r, "sshbuf_put");
		اذهب out;
	}
	*bp = b;
	b = عدم; /* transferred */
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	explicit_bzero(hash, حجم(hash));
	أرجع r;
}

صحيح
sshsig_signb(بنية sshkey *key, ثابت حرف *hashalg,
    ثابت حرف *sk_provider, ثابت حرف *sk_pin,
    ثابت بنية sshbuf *message, ثابت حرف *sig_namespace,
    بنية sshbuf **out, sshsig_signer *signer, فراغ *signer_ctx)
{
	بنية sshbuf *b = عدم;
	صحيح r = SSH_ERR_INTERNAL_ERROR;

	𐡄𐡍 (hashalg == عدم)
		hashalg = HASHALG_DEFAULT;
	𐡄𐡍 (out != عدم)
		*out = عدم;
	𐡄𐡍 ((r = hash_buffer(message, hashalg, &b)) != 0) {
		error_fr(r, "hash buffer");
		اذهب out;
	}
	𐡄𐡍 ((r = sshsig_wrap_sign(key, hashalg, sk_provider, sk_pin, b,
	    sig_namespace, out, signer, signer_ctx)) != 0)
		اذهب out;
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	أرجع r;
}

صحيح
sshsig_verifyb(بنية sshbuf *signature, ثابت بنية sshbuf *message,
    ثابت حرف *expect_namespace, بنية sshkey **sign_keyp,
    بنية sshkey_sig_details **sig_details)
{
	بنية sshbuf *b = عدم;
	صحيح r = SSH_ERR_INTERNAL_ERROR;
	حرف *hashalg = عدم;

	𐡄𐡍 (sig_details != عدم)
		*sig_details = عدم;
	𐡄𐡍 (sign_keyp != عدم)
		*sign_keyp = عدم;
	𐡄𐡍 ((r = sshsig_peek_hashalg(signature, &hashalg)) != 0)
		أرجع r;
	debug_f("signature made with hash \"%s\"", hashalg);
	𐡄𐡍 ((r = hash_buffer(message, hashalg, &b)) != 0) {
		error_fr(r, "hash buffer");
		اذهب out;
	}
	𐡄𐡍 ((r = sshsig_wrap_verify(signature, hashalg, b, expect_namespace,
	    sign_keyp, sig_details)) != 0)
		اذهب out;
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	حرر(hashalg);
	أرجع r;
}

ساكن صحيح
hash_file(صحيح fd, ثابت حرف *hashalg, بنية sshbuf **bp)
{
	حرف *hex, rbuf[8192], hash[SSH_DIGEST_MAX_LENGTH];
	ssize_t n, total = 0;
	بنية ssh_digest_ctx *ctx = عدم;
	صحيح alg, oerrno, r = SSH_ERR_INTERNAL_ERROR;
	بنية sshbuf *b = عدم;

	*bp = عدم;
	memset(hash, 0, حجم(hash));

	𐡄𐡍 ((r = sshsig_check_hashalg(hashalg)) != 0)
		أرجع r;
	𐡄𐡍 ((alg = ssh_digest_alg_by_name(hashalg)) == -1) {
		error_f("can't look up hash algorithm %s", hashalg);
		أرجع SSH_ERR_INTERNAL_ERROR;
	}
	𐡄𐡍 ((ctx = ssh_digest_start(alg)) == عدم) {
		error_f("ssh_digest_start failed");
		أرجع SSH_ERR_INTERNAL_ERROR;
	}
	لكل (;;) {
		𐡄𐡍 ((n = اقرأ(fd, rbuf, حجم(rbuf))) == -1) {
			𐡄𐡍 (errno == EINTR || errno == EAGAIN)
				استمر;
			oerrno = errno;
			error_f("read: %s", strerror(errno));
			errno = oerrno;
			r = SSH_ERR_SYSTEM_ERROR;
			اذهب out;
		} وإلا 𐡄𐡍 (n == 0) {
			debug2_f("hashed %zu bytes", total);
			اكسر; /* EOF */
		}
		total += (size_t)n;
		𐡄𐡍 ((r = ssh_digest_update(ctx, rbuf, (size_t)n)) != 0) {
			error_fr(r, "ssh_digest_update");
			اذهب out;
		}
	}
	𐡄𐡍 ((r = ssh_digest_final(ctx, hash, حجم(hash))) != 0) {
		error_fr(r, "ssh_digest_final");
		اذهب out;
	}
	𐡄𐡍 ((hex = tohex(hash, ssh_digest_bytes(alg))) != عدم) {
		debug3_f("final hash: %s", hex);
		freezero(hex, strlen(hex));
	}
	𐡄𐡍 ((b = sshbuf_new()) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب out;
	}
	𐡄𐡍 ((r = sshbuf_put(b, hash, ssh_digest_bytes(alg))) != 0) {
		error_fr(r, "sshbuf_put");
		اذهب out;
	}
	*bp = b;
	b = عدم; /* transferred */
	/* success */
	r = 0;
 out:
	oerrno = errno;
	sshbuf_free(b);
	ssh_digest_free(ctx);
	explicit_bzero(hash, حجم(hash));
	errno = oerrno;
	أرجع r;
}

صحيح
sshsig_sign_fd(بنية sshkey *key, ثابت حرف *hashalg,
    ثابت حرف *sk_provider, ثابت حرف *sk_pin,
    صحيح fd, ثابت حرف *sig_namespace, بنية sshbuf **out,
    sshsig_signer *signer, فراغ *signer_ctx)
{
	بنية sshbuf *b = عدم;
	صحيح r = SSH_ERR_INTERNAL_ERROR;

	𐡄𐡍 (hashalg == عدم)
		hashalg = HASHALG_DEFAULT;
	𐡄𐡍 (out != عدم)
		*out = عدم;
	𐡄𐡍 ((r = hash_file(fd, hashalg, &b)) != 0) {
		error_fr(r, "hash_file");
		أرجع r;
	}
	𐡄𐡍 ((r = sshsig_wrap_sign(key, hashalg, sk_provider, sk_pin, b,
	    sig_namespace, out, signer, signer_ctx)) != 0)
		اذهب out;
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	أرجع r;
}

صحيح
sshsig_verify_fd(بنية sshbuf *signature, صحيح fd,
    ثابت حرف *expect_namespace, بنية sshkey **sign_keyp,
    بنية sshkey_sig_details **sig_details)
{
	بنية sshbuf *b = عدم;
	صحيح r = SSH_ERR_INTERNAL_ERROR;
	حرف *hashalg = عدم;

	𐡄𐡍 (sig_details != عدم)
		*sig_details = عدم;
	𐡄𐡍 (sign_keyp != عدم)
		*sign_keyp = عدم;
	𐡄𐡍 ((r = sshsig_peek_hashalg(signature, &hashalg)) != 0)
		أرجع r;
	debug_f("signature made with hash \"%s\"", hashalg);
	𐡄𐡍 ((r = hash_file(fd, hashalg, &b)) != 0) {
		error_fr(r, "hash_file");
		اذهب out;
	}
	𐡄𐡍 ((r = sshsig_wrap_verify(signature, hashalg, b, expect_namespace,
	    sign_keyp, sig_details)) != 0)
		اذهب out;
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	حرر(hashalg);
	أرجع r;
}

بنية sshsigopt {
	صحيح ca;
	حرف *namespaces;
	uint64_t valid_after, valid_before;
};

بنية sshsigopt *
sshsigopt_parse(ثابت حرف *opts, ثابت حرف *path, u_long linenum,
    ثابت حرف **errstrp)
{
	بنية sshsigopt *ret;
	صحيح r;
	حرف *opt;
	ثابت حرف *errstr = عدم;

	𐡄𐡍 ((ret = calloc(1, حجم(*ret))) == عدم)
		أرجع عدم;
	𐡄𐡍 (opts == عدم || *opts == '\0')
		أرجع ret; /* Empty options yields empty options :) */

	طالما (*opts && *opts != ' ' && *opts != '\t') {
		/* flag options */
		𐡄𐡍 ((r = opt_flag("cert-authority", 0, &opts)) != -1) {
			ret->ca = 1;
		} وإلا 𐡄𐡍 (opt_match(&opts, "namespaces")) {
			𐡄𐡍 (ret->namespaces != عدم) {
				errstr = "multiple \"namespaces\" clauses";
				اذهب fail;
			}
			ret->namespaces = opt_dequote(&opts, &errstr);
			𐡄𐡍 (ret->namespaces == عدم)
				اذهب fail;
		} وإلا 𐡄𐡍 (opt_match(&opts, "valid-after")) {
			𐡄𐡍 (ret->valid_after != 0) {
				errstr = "multiple \"valid-after\" clauses";
				اذهب fail;
			}
			𐡄𐡍 ((opt = opt_dequote(&opts, &errstr)) == عدم)
				اذهب fail;
			𐡄𐡍 (parse_absolute_time(opt, &ret->valid_after) != 0 ||
			    ret->valid_after == 0) {
				حرر(opt);
				errstr = "invalid \"valid-after\" time";
				اذهب fail;
			}
			حرر(opt);
		} وإلا 𐡄𐡍 (opt_match(&opts, "valid-before")) {
			𐡄𐡍 (ret->valid_before != 0) {
				errstr = "multiple \"valid-before\" clauses";
				اذهب fail;
			}
			𐡄𐡍 ((opt = opt_dequote(&opts, &errstr)) == عدم)
				اذهب fail;
			𐡄𐡍 (parse_absolute_time(opt, &ret->valid_before) != 0 ||
			    ret->valid_before == 0) {
				حرر(opt);
				errstr = "invalid \"valid-before\" time";
				اذهب fail;
			}
			حرر(opt);
		}
		/*
		 * Skip the comma, and move to the next option
		 * (or break out if there are no more).
		 */
		𐡄𐡍 (*opts == '\0' || *opts == ' ' || *opts == '\t')
			اكسر;		/* End of options. */
		/* Anything other than a comma is an unknown option */
		𐡄𐡍 (*opts != ',') {
			errstr = "unknown key option";
			اذهب fail;
		}
		opts++;
		𐡄𐡍 (*opts == '\0') {
			errstr = "unexpected end-of-options";
			اذهب fail;
		}
	}
	/* final consistency check */
	𐡄𐡍 (ret->valid_after != 0 && ret->valid_before != 0 &&
	    ret->valid_before <= ret->valid_after) {
		errstr = "\"valid-before\" time is before \"valid-after\"";
		اذهب fail;
	}
	/* success */
	أرجع ret;
 fail:
	𐡄𐡍 (errstrp != عدم)
		*errstrp = errstr;
	sshsigopt_free(ret);
	أرجع عدم;
}

فراغ
sshsigopt_free(بنية sshsigopt *opts)
{
	𐡄𐡍 (opts == عدم)
		أرجع;
	حرر(opts->namespaces);
	حرر(opts);
}

ساكن صحيح
parse_principals_key_and_options(ثابت حرف *path, u_long linenum, حرف *line,
    ثابت حرف *required_principal, حرف **principalsp, بنية sshkey **keyp,
    بنية sshsigopt **sigoptsp)
{
	حرف *opts = عدم, *tmp, *cp, *principals = عدم;
	ثابت حرف *reason = عدم;
	بنية sshsigopt *sigopts = عدم;
	بنية sshkey *key = عدم;
	صحيح r = SSH_ERR_INTERNAL_ERROR;

	𐡄𐡍 (principalsp != عدم)
		*principalsp = عدم;
	𐡄𐡍 (sigoptsp != عدم)
		*sigoptsp = عدم;
	𐡄𐡍 (keyp != عدم)
		*keyp = عدم;

	cp = line;
	cp = cp + strspn(cp, " \t\n\r"); /* skip leading whitespace */
	𐡄𐡍 (*cp == '#' || *cp == '\0')
		أرجع SSH_ERR_KEY_NOT_FOUND; /* blank or all-comment line */

	/* format: identity[,identity...] [option[,option...]] key */
	𐡄𐡍 ((tmp = strdelimw(&cp)) == عدم || cp == عدم) {
		error("%s:%lu: invalid line", path, linenum);
		r = SSH_ERR_INVALID_FORMAT;
		اذهب out;
	}
	𐡄𐡍 ((principals = strdup(tmp)) == عدم) {
		error_f("strdup failed");
		r = SSH_ERR_ALLOC_FAIL;
		اذهب out;
	}
	/*
	 * Bail out early if we're looking for a particular principal and this
	 * line does not list it.
	 */
	𐡄𐡍 (required_principal != عدم) {
		𐡄𐡍 (match_pattern_list(required_principal,
		    principals, 0) != 1) {
			/* principal didn't match */
			r = SSH_ERR_KEY_NOT_FOUND;
			اذهب out;
		}
		debug_f("%s:%lu: matched principal \"%s\"",
		    path, linenum, required_principal);
	}

	𐡄𐡍 ((key = sshkey_new(KEY_UNSPEC)) == عدم) {
		error_f("sshkey_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		اذهب out;
	}
	𐡄𐡍 (sshkey_read(key, &cp) != 0) {
		/* no key? Check for options */
		opts = cp;
		𐡄𐡍 (sshkey_advance_past_options(&cp) != 0) {
			error("%s:%lu: invalid options", path, linenum);
			r = SSH_ERR_INVALID_FORMAT;
			اذهب out;
		}
		𐡄𐡍 (cp == عدم || *cp == '\0') {
			error("%s:%lu: missing key", path, linenum);
			r = SSH_ERR_INVALID_FORMAT;
			اذهب out;
		}
		*cp++ = '\0';
		skip_space(&cp);
		𐡄𐡍 (sshkey_read(key, &cp) != 0) {
			error("%s:%lu: invalid key", path, linenum);
			r = SSH_ERR_INVALID_FORMAT;
			اذهب out;
		}
	}
	debug3("%s:%lu: options %s", path, linenum, opts == عدم ? "" : opts);
	𐡄𐡍 ((sigopts = sshsigopt_parse(opts, path, linenum, &reason)) == عدم) {
		error("%s:%lu: bad options: %s", path, linenum, reason);
		r = SSH_ERR_INVALID_FORMAT;
		اذهب out;
	}
	/* success */
	𐡄𐡍 (principalsp != عدم) {
		*principalsp = principals;
		principals = عدم; /* transferred */
	}
	𐡄𐡍 (sigoptsp != عدم) {
		*sigoptsp = sigopts;
		sigopts = عدم; /* transferred */
	}
	𐡄𐡍 (keyp != عدم) {
		*keyp = key;
		key = عدم; /* transferred */
	}
	r = 0;
 out:
	حرر(principals);
	sshsigopt_free(sigopts);
	sshkey_free(key);
	أرجع r;
}

ساكن صحيح
cert_filter_principals(ثابت حرف *path, u_long linenum,
    حرف **principalsp, ثابت بنية sshkey *cert, uint64_t verify_time)
{
	حرف *cp, *oprincipals, *principals;
	ثابت حرف *reason;
	بنية sshbuf *nprincipals;
	صحيح r = SSH_ERR_INTERNAL_ERROR, success = 0;
	u_int i;

	oprincipals = principals = *principalsp;
	*principalsp = عدم;

	𐡄𐡍 ((nprincipals = sshbuf_new()) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب out;
	}

	طالما ((cp = strsep(&principals, ",")) != عدم && *cp != '\0') {
		/* Check certificate validity */
		𐡄𐡍 ((r = sshkey_cert_check_authority(cert, 0, 0, verify_time,
		    عدم, &reason)) != 0) {
			debug("%s:%lu: principal \"%s\" not authorized: %s",
			    path, linenum, cp, reason);
			استمر;
		}
		/* Return all matching principal names from the cert */
		لكل (i = 0; i < cert->cert->nprincipals; i++) {
			𐡄𐡍 (match_pattern(cert->cert->principals[i], cp)) {
				𐡄𐡍 ((r = sshbuf_putf(nprincipals, "%s%s",
					sshbuf_len(nprincipals) != 0 ? "," : "",
						cert->cert->principals[i])) != 0) {
					error_f("buffer error");
					اذهب out;
				}
			}
		}
	}
	𐡄𐡍 (sshbuf_len(nprincipals) == 0) {
		error("%s:%lu: no valid principals found", path, linenum);
		r = SSH_ERR_KEY_CERT_INVALID;
		اذهب out;
	}
	𐡄𐡍 ((principals = sshbuf_dup_string(nprincipals)) == عدم) {
		error_f("buffer error");
		r = SSH_ERR_ALLOC_FAIL;
		اذهب out;
	}
	/* success */
	success = 1;
	*principalsp = principals;
 out:
	sshbuf_free(nprincipals);
	حرر(oprincipals);
	أرجع success ? 0 : r;
}

ساكن صحيح
check_allowed_keys_line(ثابت حرف *path, u_long linenum, حرف *line,
    ثابت بنية sshkey *sign_key, ثابت حرف *principal,
    ثابت حرف *sig_namespace, uint64_t verify_time, حرف **principalsp)
{
	بنية sshkey *found_key = عدم;
	حرف *principals = عدم;
	صحيح r, success = 0;
	ثابت حرف *reason = عدم;
	بنية sshsigopt *sigopts = عدم;
	حرف tvalid[64], tverify[64];

	𐡄𐡍 (principalsp != عدم)
		*principalsp = عدم;

	/* Parse the line */
	𐡄𐡍 ((r = parse_principals_key_and_options(path, linenum, line,
	    principal, &principals, &found_key, &sigopts)) != 0) {
		/* error already logged */
		اذهب done;
	}

	𐡄𐡍 (!sigopts->ca && sshkey_equal(found_key, sign_key)) {
		/* Exact match of key */
		debug("%s:%lu: matched key", path, linenum);
	} وإلا 𐡄𐡍 (sigopts->ca && sshkey_is_cert(sign_key) &&
	    sshkey_equal_public(sign_key->cert->signature_key, found_key)) {
		𐡄𐡍 (principal) {
			/* Match certificate CA key with specified principal */
			𐡄𐡍 ((r = sshkey_cert_check_authority(sign_key, 0, 0,
			    verify_time, principal, &reason)) != 0) {
				error("%s:%lu: certificate not authorized: %s",
				    path, linenum, reason);
				اذهب done;
			}
			debug("%s:%lu: matched certificate CA key",
			    path, linenum);
		} وإلا {
			/* No principal specified - find all matching ones */
			𐡄𐡍 ((r = cert_filter_principals(path, linenum,
			    &principals, sign_key, verify_time)) != 0) {
				/* error already displayed */
				debug_r(r, "%s:%lu: cert_filter_principals",
				    path, linenum);
				اذهب done;
			}
			debug("%s:%lu: matched certificate CA key",
			    path, linenum);
		}
	} وإلا {
		/* Didn't match key */
		اذهب done;
	}

	/* Check whether options preclude the use of this key */
	𐡄𐡍 (sigopts->namespaces != عدم && sig_namespace != عدم &&
	    match_pattern_list(sig_namespace, sigopts->namespaces, 0) != 1) {
		error("%s:%lu: key is not permitted for use in signature "
		    "namespace \"%s\"", path, linenum, sig_namespace);
		اذهب done;
	}

	/* check key time validity */
	format_absolute_time((uint64_t)verify_time, tverify, حجم(tverify));
	𐡄𐡍 (sigopts->valid_after != 0 &&
	    (uint64_t)verify_time < sigopts->valid_after) {
		format_absolute_time(sigopts->valid_after,
		    tvalid, حجم(tvalid));
		error("%s:%lu: key is not yet valid: "
		    "verify time %s < valid-after %s", path, linenum,
		    tverify, tvalid);
		اذهب done;
	}
	𐡄𐡍 (sigopts->valid_before != 0 &&
	    (uint64_t)verify_time > sigopts->valid_before) {
		format_absolute_time(sigopts->valid_before,
		    tvalid, حجم(tvalid));
		error("%s:%lu: key has expired: "
		    "verify time %s > valid-before %s", path, linenum,
		    tverify, tvalid);
		اذهب done;
	}
	success = 1;

 done:
	𐡄𐡍 (success && principalsp != عدم) {
		*principalsp = principals;
		principals = عدم; /* transferred */
	}
	حرر(principals);
	sshkey_free(found_key);
	sshsigopt_free(sigopts);
	أرجع success ? 0 : SSH_ERR_KEY_NOT_FOUND;
}

صحيح
sshsig_check_allowed_keys(ثابت حرف *path, ثابت بنية sshkey *sign_key,
    ثابت حرف *principal, ثابت حرف *sig_namespace, uint64_t verify_time)
{
	FILE *f = عدم;
	حرف *line = عدم;
	size_t linesize = 0;
	u_long linenum = 0;
	صحيح r = SSH_ERR_KEY_NOT_FOUND, oerrno;

	/* Check key and principal against file */
	𐡄𐡍 ((f = fopen(path, "r")) == عدم) {
		oerrno = errno;
		error("Unable to open allowed keys file \"%s\": %s",
		    path, strerror(errno));
		errno = oerrno;
		أرجع SSH_ERR_SYSTEM_ERROR;
	}

	طالما (getline(&line, &linesize, f) != -1) {
		linenum++;
		r = check_allowed_keys_line(path, linenum, line, sign_key,
		    principal, sig_namespace, verify_time, عدم);
		حرر(line);
		line = عدم;
		linesize = 0;
		𐡄𐡍 (r == SSH_ERR_KEY_NOT_FOUND)
			استمر;
		وإلا 𐡄𐡍 (r == 0) {
			/* success */
			fclose(f);
			أرجع 0;
		} وإلا
			اكسر;
	}
	/* Either we hit an error parsing or we simply didn't find the key */
	fclose(f);
	حرر(line);
	أرجع r;
}

صحيح
sshsig_find_principals(ثابت حرف *path, ثابت بنية sshkey *sign_key,
    uint64_t verify_time, حرف **principals)
{
	FILE *f = عدم;
	حرف *line = عدم;
	size_t linesize = 0;
	u_long linenum = 0;
	صحيح r = SSH_ERR_KEY_NOT_FOUND, oerrno;

	𐡄𐡍 ((f = fopen(path, "r")) == عدم) {
		oerrno = errno;
		error("Unable to open allowed keys file \"%s\": %s",
		    path, strerror(errno));
		errno = oerrno;
		أرجع SSH_ERR_SYSTEM_ERROR;
	}

	طالما (getline(&line, &linesize, f) != -1) {
		linenum++;
		r = check_allowed_keys_line(path, linenum, line,
		    sign_key, عدم, عدم, verify_time, principals);
		حرر(line);
		line = عدم;
		linesize = 0;
		𐡄𐡍 (r == SSH_ERR_KEY_NOT_FOUND)
			استمر;
		وإلا 𐡄𐡍 (r == 0) {
			/* success */
			fclose(f);
			أرجع 0;
		} وإلا
			اكسر;
	}
	حرر(line);
	/* Either we hit an error parsing or we simply didn't find the key */
	𐡄𐡍 (ferror(f) != 0) {
		oerrno = errno;
		fclose(f);
		error("Unable to read allowed keys file \"%s\": %s",
		    path, strerror(errno));
		errno = oerrno;
		أرجع SSH_ERR_SYSTEM_ERROR;
	}
	fclose(f);
	أرجع r;
}

صحيح
sshsig_match_principals(ثابت حرف *path, ثابت حرف *principal,
    حرف ***principalsp, size_t *nprincipalsp)
{
	FILE *f = عدم;
	حرف *found, *line = عدم, **principals = عدم, **tmp;
	size_t i, nprincipals = 0, linesize = 0;
	u_long linenum = 0;
	صحيح oerrno = 0, r, ret = 0;

	𐡄𐡍 (principalsp != عدم)
		*principalsp = عدم;
	𐡄𐡍 (nprincipalsp != عدم)
		*nprincipalsp = 0;

	/* Check key and principal against file */
	𐡄𐡍 ((f = fopen(path, "r")) == عدم) {
		oerrno = errno;
		error("Unable to open allowed keys file \"%s\": %s",
		    path, strerror(errno));
		errno = oerrno;
		أرجع SSH_ERR_SYSTEM_ERROR;
	}

	طالما (getline(&line, &linesize, f) != -1) {
		linenum++;
		/* Parse the line */
		𐡄𐡍 ((r = parse_principals_key_and_options(path, linenum, line,
		    principal, &found, عدم, عدم)) != 0) {
			𐡄𐡍 (r == SSH_ERR_KEY_NOT_FOUND)
				استمر;
			ret = r;
			oerrno = errno;
			اكسر; /* unexpected error */
		}
		𐡄𐡍 ((tmp = recallocarray(principals, nprincipals,
		    nprincipals + 1, حجم(*principals))) == عدم) {
			ret = SSH_ERR_ALLOC_FAIL;
			حرر(found);
			اكسر;
		}
		principals = tmp;
		principals[nprincipals++] = found; /* transferred */
		حرر(line);
		line = عدم;
		linesize = 0;
	}
	fclose(f);
	حرر(line);

	𐡄𐡍 (ret == 0) {
		𐡄𐡍 (nprincipals == 0)
			ret = SSH_ERR_KEY_NOT_FOUND;
		𐡄𐡍 (nprincipalsp != عدم)
			*nprincipalsp = nprincipals;
		𐡄𐡍 (principalsp != عدم) {
			*principalsp = principals;
			principals = عدم; /* transferred */
			nprincipals = 0;
		}
	}

	لكل (i = 0; i < nprincipals; i++)
		حرر(principals[i]);
	حرر(principals);

	errno = oerrno;
	أرجع ret;
}

صحيح
sshsig_get_pubkey(بنية sshbuf *signature, بنية sshkey **pubkey)
{
	بنية sshkey *pk = عدم;
	صحيح r = SSH_ERR_SIGNATURE_INVALID;

	𐡄𐡍 (pubkey == عدم)
		أرجع SSH_ERR_INTERNAL_ERROR;
	𐡄𐡍 ((r = sshsig_parse_preamble(signature)) != 0)
		أرجع r;
	𐡄𐡍 ((r = sshkey_froms(signature, &pk)) != 0)
		أرجع r;

	*pubkey = pk;
	pk = عدم;
	أرجع 0;
}
