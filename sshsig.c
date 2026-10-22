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

#شامل "includes.h"

#شامل <stdio.h>
#شامل <stdlib.h>
#شامل <stdarg.h>
#شامل <errno.h>
#شامل <string.h>
#شامل <unistd.h>

#شامل "authfd.h"
#شامل "authfile.h"
#شامل "log.h"
#شامل "misc.h"
#شامل "sshbuf.h"
#شامل "sshsig.h"
#شامل "ssherr.h"
#شامل "sshkey.h"
#شامل "match.h"
#شامل "digest.h"

#define SIG_VERSION		0x01
#define MAGIC_PREAMBLE		"SSHSIG"
#define MAGIC_PREAMBLE_LEN	(اندازه(MAGIC_PREAMBLE) - 1)
#define BEGIN_SIGNATURE		"-----BEGIN SSH SIGNATURE-----"
#define END_SIGNATURE		"-----END SSH SIGNATURE-----"
#define RSA_SIGN_ALG		"rsa-sha2-512"
#define RSA_SIGN_ALLOWED	"rsa-sha2-512,rsa-sha2-256"
#define HASHALG_DEFAULT		"sha512"
#define HASHALG_ALLOWED		"sha256,sha512"

صحیح
sshsig_armor(ثابت ساختار sshbuf *blob, ساختار sshbuf **out)
{
	ساختار sshbuf *buf = پوچ;
	صحیح r = SSH_ERR_INTERNAL_ERROR;

	*out = پوچ;

	اگر ((buf = sshbuf_new()) == پوچ) {
		error_f("sshbuf_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		برو out;
	}

	اگر ((r = sshbuf_putf(buf, "%s\n", BEGIN_SIGNATURE)) != 0) {
		error_fr(r, "sshbuf_putf");
		برو out;
	}

	اگر ((r = sshbuf_dtob64(blob, buf, 1)) != 0) {
		error_fr(r, "base64 encode signature");
		برو out;
	}

	اگر ((r = sshbuf_put(buf, END_SIGNATURE,
	    اندازه(END_SIGNATURE)-1)) != 0 ||
	    (r = sshbuf_put_u8(buf, '\n')) != 0) {
		error_fr(r, "sshbuf_put");
		برو out;
	}
	/* success */
	*out = buf;
	buf = پوچ; /* transferred */
	r = 0;
 out:
	sshbuf_free(buf);
	بازگشت r;
}

صحیح
sshsig_dearmor(ساختار sshbuf *sig, ساختار sshbuf **out)
{
	صحیح r;
	size_t eoffset = 0;
	ساختار sshbuf *buf = پوچ;
	ساختار sshbuf *sbuf = پوچ;
	نویسه *b64 = پوچ;

	اگر ((sbuf = sshbuf_fromb(sig)) == پوچ) {
		error_f("sshbuf_fromb failed");
		بازگشت SSH_ERR_ALLOC_FAIL;
	}

	/* Expect and consume preamble + lf/crlf */
	اگر ((r = sshbuf_cmp(sbuf, 0,
	    BEGIN_SIGNATURE, اندازه(BEGIN_SIGNATURE)-1)) != 0) {
		error("Couldn't parse signature: missing header");
		برو done;
	}
	اگر ((r = sshbuf_consume(sbuf, اندازه(BEGIN_SIGNATURE)-1)) != 0) {
		error_fr(r, "consume");
		برو done;
	}
	اگر ((r = sshbuf_cmp(sbuf, 0, "\r\n", 2)) == 0)
		eoffset = 2;
	وگرنه اگر ((r = sshbuf_cmp(sbuf, 0, "\n", 1)) == 0)
		eoffset = 1;
	وگرنه {
		r = SSH_ERR_INVALID_FORMAT;
		error_f("no header eol");
		برو done;
	}
	اگر ((r = sshbuf_consume(sbuf, eoffset)) != 0) {
		error_fr(r, "consume eol");
		برو done;
	}
	/* Find and consume lf + suffix (any prior cr would be ignored) */
	اگر ((r = sshbuf_find(sbuf, 0, "\n" END_SIGNATURE,
	    اندازه(END_SIGNATURE), &eoffset)) != 0) {
		error("Couldn't parse signature: missing footer");
		برو done;
	}
	اگر ((r = sshbuf_consume_end(sbuf, sshbuf_len(sbuf)-eoffset)) != 0) {
		error_fr(r, "consume");
		برو done;
	}

	اگر ((b64 = sshbuf_dup_string(sbuf)) == پوچ) {
		error_f("sshbuf_dup_string failed");
		r = SSH_ERR_ALLOC_FAIL;
		برو done;
	}

	اگر ((buf = sshbuf_new()) == پوچ) {
		error_f("sshbuf_new() failed");
		r = SSH_ERR_ALLOC_FAIL;
		برو done;
	}

	اگر ((r = sshbuf_b64tod(buf, b64)) != 0) {
		error_fr(r, "decode base64");
		برو done;
	}

	/* success */
	*out = buf;
	r = 0;
	buf = پوچ; /* transferred */
done:
	sshbuf_free(buf);
	sshbuf_free(sbuf);
	آزاد(b64);
	بازگشت r;
}

ایستا صحیح
sshsig_wrap_sign(ساختار sshkey *کلید, ثابت نویسه *hashalg,
    ثابت نویسه *sk_provider, ثابت نویسه *sk_pin, ثابت ساختار sshbuf *h_message,
    ثابت نویسه *sig_namespace, ساختار sshbuf **out,
    sshsig_signer *signer, تهی *signer_ctx)
{
	صحیح r;
	size_t slen = 0;
	u_char *sig = پوچ;
	ساختار sshbuf *blob = پوچ;
	ساختار sshbuf *tosign = پوچ;
	ثابت نویسه *sign_alg = پوچ;

	اگر ((tosign = sshbuf_new()) == پوچ ||
	    (blob = sshbuf_new()) == پوچ) {
		error_f("sshbuf_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		برو done;
	}

	اگر ((r = sshbuf_put(tosign, MAGIC_PREAMBLE, MAGIC_PREAMBLE_LEN)) != 0 ||
	    (r = sshbuf_put_cstring(tosign, sig_namespace)) != 0 ||
	    (r = sshbuf_put_string(tosign, پوچ, 0)) != 0 || /* reserved */
	    (r = sshbuf_put_cstring(tosign, hashalg)) != 0 ||
	    (r = sshbuf_put_stringb(tosign, h_message)) != 0) {
		error_fr(r, "assemble message to sign");
		برو done;
	}

	/* If using RSA keys then default to a good signature algorithm */
	اگر (sshkey_type_plain(کلید->type) == کلید_RSA) {
		sign_alg = RSA_SIGN_ALG;
		اگر (strcmp(hashalg, "sha256") == 0)
			sign_alg = "rsa-sha2-256";
		وگرنه اگر (strcmp(hashalg, "sha512") == 0)
			sign_alg = "rsa-sha2-512";
	}

	اگر (signer != پوچ) {
		اگر ((r = signer(کلید, &sig, &slen,
		    sshbuf_ptr(tosign), sshbuf_len(tosign),
		    sign_alg, sk_provider, sk_pin, 0, signer_ctx)) != 0) {
			error_r(r, "Couldn't sign message (signer)");
			برو done;
		}
	} وگرنه {
		اگر ((r = sshkey_sign(کلید, &sig, &slen,
		    sshbuf_ptr(tosign), sshbuf_len(tosign),
		    sign_alg, sk_provider, sk_pin, 0)) != 0) {
			error_r(r, "Couldn't sign message");
			برو done;
		}
	}

	اگر ((r = sshbuf_put(blob, MAGIC_PREAMBLE, MAGIC_PREAMBLE_LEN)) != 0 ||
	    (r = sshbuf_put_u32(blob, SIG_VERSION)) != 0 ||
	    (r = sshkey_puts(کلید, blob)) != 0 ||
	    (r = sshbuf_put_cstring(blob, sig_namespace)) != 0 ||
	    (r = sshbuf_put_string(blob, پوچ, 0)) != 0 || /* reserved */
	    (r = sshbuf_put_cstring(blob, hashalg)) != 0 ||
	    (r = sshbuf_put_string(blob, sig, slen)) != 0) {
		error_fr(r, "assemble signature object");
		برو done;
	}

	اگر (out != پوچ) {
		*out = blob;
		blob = پوچ;
	}
	r = 0;
done:
	آزاد(sig);
	sshbuf_free(blob);
	sshbuf_free(tosign);
	بازگشت r;
}

/* Check preamble and version. */
ایستا صحیح
sshsig_parse_preamble(ساختار sshbuf *buf)
{
	صحیح r = SSH_ERR_INTERNAL_ERROR;
	uint32_t sversion;

	اگر ((r = sshbuf_cmp(buf, 0, MAGIC_PREAMBLE, MAGIC_PREAMBLE_LEN)) != 0 ||
	    (r = sshbuf_consume(buf, (اندازه(MAGIC_PREAMBLE)-1))) != 0 ||
	    (r = sshbuf_get_u32(buf, &sversion)) != 0) {
		error("Couldn't verify signature: invalid format");
		بازگشت r;
	}

	اگر (sversion > SIG_VERSION) {
		error("Signature version %lu is larger than supported "
		    "version %u", (unsigned long)sversion, SIG_VERSION);
		بازگشت SSH_ERR_INVALID_FORMAT;
	}
	بازگشت 0;
}

ایستا صحیح
sshsig_check_hashalg(ثابت نویسه *hashalg)
{
	اگر (hashalg == پوچ ||
	    match_pattern_list(hashalg, HASHALG_ALLOWED, 0) == 1)
		بازگشت 0;
	error_f("unsupported hash algorithm \"%.100s\"", hashalg);
	بازگشت SSH_ERR_SIGN_ALG_UNSUPPORTED;
}

ایستا صحیح
sshsig_peek_hashalg(ساختار sshbuf *signature, نویسه **hashalgp)
{
	ساختار sshbuf *buf = پوچ;
	نویسه *hashalg = پوچ;
	صحیح r = SSH_ERR_INTERNAL_ERROR;

	اگر (hashalgp != پوچ)
		*hashalgp = پوچ;
	اگر ((buf = sshbuf_fromb(signature)) == پوچ)
		بازگشت SSH_ERR_ALLOC_FAIL;
	اگر ((r = sshsig_parse_preamble(buf)) != 0)
		برو done;
	اگر ((r = sshbuf_get_string_direct(buf, پوچ, پوچ)) != 0 ||
	    (r = sshbuf_get_string_direct(buf, پوچ, پوچ)) != 0 ||
	    (r = sshbuf_get_string(buf, پوچ, پوچ)) != 0 ||
	    (r = sshbuf_get_cstring(buf, &hashalg, پوچ)) != 0 ||
	    (r = sshbuf_get_string_direct(buf, پوچ, پوچ)) != 0) {
		error_fr(r, "parse signature object");
		برو done;
	}

	/* success */
	r = 0;
	*hashalgp = hashalg;
	hashalg = پوچ;
 done:
	آزاد(hashalg);
	sshbuf_free(buf);
	بازگشت r;
}

ایستا صحیح
sshsig_wrap_verify(ساختار sshbuf *signature, ثابت نویسه *hashalg,
    ثابت ساختار sshbuf *h_message, ثابت نویسه *expect_namespace,
    ساختار sshkey **sign_keyp, ساختار sshkey_sig_details **sig_details)
{
	صحیح r = SSH_ERR_INTERNAL_ERROR;
	ساختار sshbuf *buf = پوچ, *toverify = پوچ;
	ساختار sshkey *کلید = پوچ;
	ثابت u_char *sig;
	نویسه *got_namespace = پوچ, *sigtype = پوچ, *sig_hashalg = پوچ;
	size_t siglen;

	debug_f("verify message length %zu", sshbuf_len(h_message));
	اگر (sig_details != پوچ)
		*sig_details = پوچ;
	اگر (sign_keyp != پوچ)
		*sign_keyp = پوچ;

	اگر ((toverify = sshbuf_new()) == پوچ) {
		error_f("sshbuf_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		برو done;
	}
	اگر ((r = sshbuf_put(toverify, MAGIC_PREAMBLE,
	    MAGIC_PREAMBLE_LEN)) != 0 ||
	    (r = sshbuf_put_cstring(toverify, expect_namespace)) != 0 ||
	    (r = sshbuf_put_string(toverify, پوچ, 0)) != 0 || /* reserved */
	    (r = sshbuf_put_cstring(toverify, hashalg)) != 0 ||
	    (r = sshbuf_put_stringb(toverify, h_message)) != 0) {
		error_fr(r, "assemble message to verify");
		برو done;
	}

	اگر ((r = sshsig_parse_preamble(signature)) != 0)
		برو done;

	اگر ((r = sshkey_froms(signature, &کلید)) != 0 ||
	    (r = sshbuf_get_cstring(signature, &got_namespace, پوچ)) != 0 ||
	    (r = sshbuf_get_string(signature, پوچ, پوچ)) != 0 ||
	    (r = sshbuf_get_cstring(signature, &sig_hashalg, پوچ)) != 0 ||
	    (r = sshbuf_get_string_direct(signature, &sig, &siglen)) != 0) {
		error_fr(r, "parse signature object");
		برو done;
	}

	اگر (sshbuf_len(signature) != 0) {
		error("Signature contains trailing data");
		r = SSH_ERR_INVALID_FORMAT;
		برو done;
	}

	اگر (strcmp(expect_namespace, got_namespace) != 0) {
		error("Couldn't verify signature: namespace does not match");
		debug_f("expected namespace \"%s\" received \"%s\"",
		    expect_namespace, got_namespace);
		r = SSH_ERR_SIGNATURE_INVALID;
		برو done;
	}
	اگر (strcmp(hashalg, sig_hashalg) != 0) {
		error("Couldn't verify signature: hash algorithm mismatch");
		debug_f("expected algorithm \"%s\" received \"%s\"",
		    hashalg, sig_hashalg);
		r = SSH_ERR_SIGNATURE_INVALID;
		برو done;
	}
	/* Ensure that RSA keys use an acceptable signature algorithm */
	اگر (sshkey_type_plain(کلید->type) == کلید_RSA) {
		اگر ((r = sshkey_get_sigtype(sig, siglen, &sigtype)) != 0) {
			error_r(r, "Couldn't verify signature: unable to get "
			    "signature type");
			برو done;
		}
		اگر (match_pattern_list(sigtype, RSA_SIGN_ALLOWED, 0) != 1) {
			error("Couldn't verify signature: unsupported RSA "
			    "signature algorithm %s", sigtype);
			r = SSH_ERR_SIGN_ALG_UNSUPPORTED;
			برو done;
		}
	}
	اگر ((r = sshkey_verify(کلید, sig, siglen, sshbuf_ptr(toverify),
	    sshbuf_len(toverify), پوچ, 0, sig_details)) != 0) {
		error_r(r, "Signature verification failed");
		برو done;
	}

	/* success */
	r = 0;
	اگر (sign_keyp != پوچ) {
		*sign_keyp = کلید;
		کلید = پوچ; /* transferred */
	}
done:
	آزاد(got_namespace);
	آزاد(sigtype);
	آزاد(sig_hashalg);
	sshbuf_free(buf);
	sshbuf_free(toverify);
	sshkey_free(کلید);
	بازگشت r;
}

ایستا صحیح
hash_buffer(ثابت ساختار sshbuf *m, ثابت نویسه *hashalg, ساختار sshbuf **bp)
{
	نویسه *hex, hash[SSH_DIGEST_MAX_LENGTH];
	صحیح alg, r = SSH_ERR_INTERNAL_ERROR;
	ساختار sshbuf *b = پوچ;

	*bp = پوچ;
	memset(hash, 0, اندازه(hash));

	اگر ((r = sshsig_check_hashalg(hashalg)) != 0)
		بازگشت r;
	اگر ((alg = ssh_digest_alg_by_name(hashalg)) == -1) {
		error_f("can't look up hash algorithm %s", hashalg);
		بازگشت SSH_ERR_INTERNAL_ERROR;
	}
	اگر ((r = ssh_digest_buffer(alg, m, hash, اندازه(hash))) != 0) {
		error_fr(r, "ssh_digest_buffer");
		بازگشت r;
	}
	اگر ((hex = tohex(hash, ssh_digest_bytes(alg))) != پوچ) {
		debug3_f("final hash: %s", hex);
		freezero(hex, strlen(hex));
	}
	اگر ((b = sshbuf_new()) == پوچ) {
		r = SSH_ERR_ALLOC_FAIL;
		برو out;
	}
	اگر ((r = sshbuf_put(b, hash, ssh_digest_bytes(alg))) != 0) {
		error_fr(r, "sshbuf_put");
		برو out;
	}
	*bp = b;
	b = پوچ; /* transferred */
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	explicit_bzero(hash, اندازه(hash));
	بازگشت r;
}

صحیح
sshsig_signb(ساختار sshkey *کلید, ثابت نویسه *hashalg,
    ثابت نویسه *sk_provider, ثابت نویسه *sk_pin,
    ثابت ساختار sshbuf *message, ثابت نویسه *sig_namespace,
    ساختار sshbuf **out, sshsig_signer *signer, تهی *signer_ctx)
{
	ساختار sshbuf *b = پوچ;
	صحیح r = SSH_ERR_INTERNAL_ERROR;

	اگر (hashalg == پوچ)
		hashalg = HASHALG_DEFAULT;
	اگر (out != پوچ)
		*out = پوچ;
	اگر ((r = hash_buffer(message, hashalg, &b)) != 0) {
		error_fr(r, "hash buffer");
		برو out;
	}
	اگر ((r = sshsig_wrap_sign(کلید, hashalg, sk_provider, sk_pin, b,
	    sig_namespace, out, signer, signer_ctx)) != 0)
		برو out;
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	بازگشت r;
}

صحیح
sshsig_verifyb(ساختار sshbuf *signature, ثابت ساختار sshbuf *message,
    ثابت نویسه *expect_namespace, ساختار sshkey **sign_keyp,
    ساختار sshkey_sig_details **sig_details)
{
	ساختار sshbuf *b = پوچ;
	صحیح r = SSH_ERR_INTERNAL_ERROR;
	نویسه *hashalg = پوچ;

	اگر (sig_details != پوچ)
		*sig_details = پوچ;
	اگر (sign_keyp != پوچ)
		*sign_keyp = پوچ;
	اگر ((r = sshsig_peek_hashalg(signature, &hashalg)) != 0)
		بازگشت r;
	debug_f("signature made with hash \"%s\"", hashalg);
	اگر ((r = hash_buffer(message, hashalg, &b)) != 0) {
		error_fr(r, "hash buffer");
		برو out;
	}
	اگر ((r = sshsig_wrap_verify(signature, hashalg, b, expect_namespace,
	    sign_keyp, sig_details)) != 0)
		برو out;
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	آزاد(hashalg);
	بازگشت r;
}

ایستا صحیح
hash_file(صحیح fd, ثابت نویسه *hashalg, ساختار sshbuf **bp)
{
	نویسه *hex, rbuf[8192], hash[SSH_DIGEST_MAX_LENGTH];
	ssize_t n, total = 0;
	ساختار ssh_digest_ctx *ctx = پوچ;
	صحیح alg, oerrno, r = SSH_ERR_INTERNAL_ERROR;
	ساختار sshbuf *b = پوچ;

	*bp = پوچ;
	memset(hash, 0, اندازه(hash));

	اگر ((r = sshsig_check_hashalg(hashalg)) != 0)
		بازگشت r;
	اگر ((alg = ssh_digest_alg_by_name(hashalg)) == -1) {
		error_f("can't look up hash algorithm %s", hashalg);
		بازگشت SSH_ERR_INTERNAL_ERROR;
	}
	اگر ((ctx = ssh_digest_start(alg)) == پوچ) {
		error_f("ssh_digest_start failed");
		بازگشت SSH_ERR_INTERNAL_ERROR;
	}
	برای (;;) {
		اگر ((n = اقرأ(fd, rbuf, اندازه(rbuf))) == -1) {
			اگر (errno == EINTR || errno == EAGAIN)
				ادامه;
			oerrno = errno;
			error_f("read: %s", strerror(errno));
			errno = oerrno;
			r = SSH_ERR_SYSTEM_ERROR;
			برو out;
		} وگرنه اگر (n == 0) {
			debug2_f("hashed %zu bytes", total);
			بشکن; /* EOF */
		}
		total += (size_t)n;
		اگر ((r = ssh_digest_update(ctx, rbuf, (size_t)n)) != 0) {
			error_fr(r, "ssh_digest_update");
			برو out;
		}
	}
	اگر ((r = ssh_digest_final(ctx, hash, اندازه(hash))) != 0) {
		error_fr(r, "ssh_digest_final");
		برو out;
	}
	اگر ((hex = tohex(hash, ssh_digest_bytes(alg))) != پوچ) {
		debug3_f("final hash: %s", hex);
		freezero(hex, strlen(hex));
	}
	اگر ((b = sshbuf_new()) == پوچ) {
		r = SSH_ERR_ALLOC_FAIL;
		برو out;
	}
	اگر ((r = sshbuf_put(b, hash, ssh_digest_bytes(alg))) != 0) {
		error_fr(r, "sshbuf_put");
		برو out;
	}
	*bp = b;
	b = پوچ; /* transferred */
	/* success */
	r = 0;
 out:
	oerrno = errno;
	sshbuf_free(b);
	ssh_digest_free(ctx);
	explicit_bzero(hash, اندازه(hash));
	errno = oerrno;
	بازگشت r;
}

صحیح
sshsig_sign_fd(ساختار sshkey *کلید, ثابت نویسه *hashalg,
    ثابت نویسه *sk_provider, ثابت نویسه *sk_pin,
    صحیح fd, ثابت نویسه *sig_namespace, ساختار sshbuf **out,
    sshsig_signer *signer, تهی *signer_ctx)
{
	ساختار sshbuf *b = پوچ;
	صحیح r = SSH_ERR_INTERNAL_ERROR;

	اگر (hashalg == پوچ)
		hashalg = HASHALG_DEFAULT;
	اگر (out != پوچ)
		*out = پوچ;
	اگر ((r = hash_file(fd, hashalg, &b)) != 0) {
		error_fr(r, "hash_file");
		بازگشت r;
	}
	اگر ((r = sshsig_wrap_sign(کلید, hashalg, sk_provider, sk_pin, b,
	    sig_namespace, out, signer, signer_ctx)) != 0)
		برو out;
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	بازگشت r;
}

صحیح
sshsig_verify_fd(ساختار sshbuf *signature, صحیح fd,
    ثابت نویسه *expect_namespace, ساختار sshkey **sign_keyp,
    ساختار sshkey_sig_details **sig_details)
{
	ساختار sshbuf *b = پوچ;
	صحیح r = SSH_ERR_INTERNAL_ERROR;
	نویسه *hashalg = پوچ;

	اگر (sig_details != پوچ)
		*sig_details = پوچ;
	اگر (sign_keyp != پوچ)
		*sign_keyp = پوچ;
	اگر ((r = sshsig_peek_hashalg(signature, &hashalg)) != 0)
		بازگشت r;
	debug_f("signature made with hash \"%s\"", hashalg);
	اگر ((r = hash_file(fd, hashalg, &b)) != 0) {
		error_fr(r, "hash_file");
		برو out;
	}
	اگر ((r = sshsig_wrap_verify(signature, hashalg, b, expect_namespace,
	    sign_keyp, sig_details)) != 0)
		برو out;
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	آزاد(hashalg);
	بازگشت r;
}

ساختار sshsigopt {
	صحیح ca;
	نویسه *namespaces;
	uint64_t valid_after, valid_before;
};

ساختار sshsigopt *
sshsigopt_parse(ثابت نویسه *opts, ثابت نویسه *path, u_long linenum,
    ثابت نویسه **errstrp)
{
	ساختار sshsigopt *ret;
	صحیح r;
	نویسه *opt;
	ثابت نویسه *errstr = پوچ;

	اگر ((ret = calloc(1, اندازه(*ret))) == پوچ)
		بازگشت پوچ;
	اگر (opts == پوچ || *opts == '\0')
		بازگشت ret; /* Empty options yields empty options :) */

	وقتی (*opts && *opts != ' ' && *opts != '\t') {
		/* flag options */
		اگر ((r = opt_flag("cert-authority", 0, &opts)) != -1) {
			ret->ca = 1;
		} وگرنه اگر (opt_match(&opts, "namespaces")) {
			اگر (ret->namespaces != پوچ) {
				errstr = "multiple \"namespaces\" clauses";
				برو fail;
			}
			ret->namespaces = opt_dequote(&opts, &errstr);
			اگر (ret->namespaces == پوچ)
				برو fail;
		} وگرنه اگر (opt_match(&opts, "valid-after")) {
			اگر (ret->valid_after != 0) {
				errstr = "multiple \"valid-after\" clauses";
				برو fail;
			}
			اگر ((opt = opt_dequote(&opts, &errstr)) == پوچ)
				برو fail;
			اگر (parse_absolute_time(opt, &ret->valid_after) != 0 ||
			    ret->valid_after == 0) {
				آزاد(opt);
				errstr = "invalid \"valid-after\" time";
				برو fail;
			}
			آزاد(opt);
		} وگرنه اگر (opt_match(&opts, "valid-before")) {
			اگر (ret->valid_before != 0) {
				errstr = "multiple \"valid-before\" clauses";
				برو fail;
			}
			اگر ((opt = opt_dequote(&opts, &errstr)) == پوچ)
				برو fail;
			اگر (parse_absolute_time(opt, &ret->valid_before) != 0 ||
			    ret->valid_before == 0) {
				آزاد(opt);
				errstr = "invalid \"valid-before\" time";
				برو fail;
			}
			آزاد(opt);
		}
		/*
		 * Skip the comma, and move to the next option
		 * (or break out if there are no more).
		 */
		اگر (*opts == '\0' || *opts == ' ' || *opts == '\t')
			بشکن;		/* End of options. */
		/* Anything other than a comma is an unknown option */
		اگر (*opts != ',') {
			errstr = "unknown key option";
			برو fail;
		}
		opts++;
		اگر (*opts == '\0') {
			errstr = "unexpected end-of-options";
			برو fail;
		}
	}
	/* final consistency check */
	اگر (ret->valid_after != 0 && ret->valid_before != 0 &&
	    ret->valid_before <= ret->valid_after) {
		errstr = "\"valid-before\" time is before \"valid-after\"";
		برو fail;
	}
	/* success */
	بازگشت ret;
 fail:
	اگر (errstrp != پوچ)
		*errstrp = errstr;
	sshsigopt_free(ret);
	بازگشت پوچ;
}

تهی
sshsigopt_free(ساختار sshsigopt *opts)
{
	اگر (opts == پوچ)
		بازگشت;
	آزاد(opts->namespaces);
	آزاد(opts);
}

ایستا صحیح
parse_principals_کلید_and_options(ثابت نویسه *path, u_long linenum, نویسه *سطر,
    ثابت نویسه *required_principal, نویسه **principalsp, ساختار sshkey **keyp,
    ساختار sshsigopt **sigoptsp)
{
	نویسه *opts = پوچ, *tmp, *cp, *principals = پوچ;
	ثابت نویسه *reason = پوچ;
	ساختار sshsigopt *sigopts = پوچ;
	ساختار sshkey *کلید = پوچ;
	صحیح r = SSH_ERR_INTERNAL_ERROR;

	اگر (principalsp != پوچ)
		*principalsp = پوچ;
	اگر (sigoptsp != پوچ)
		*sigoptsp = پوچ;
	اگر (keyp != پوچ)
		*keyp = پوچ;

	cp = سطر;
	cp = cp + strspn(cp, " \t\n\r"); /* skip leading whitespace */
	اگر (*cp == '#' || *cp == '\0')
		بازگشت SSH_ERR_کلید_NOT_FOUND; /* blank or all-comment line */

	/* format: identity[,identity...] [option[,option...]] key */
	اگر ((tmp = strdelimw(&cp)) == پوچ || cp == پوچ) {
		error("%s:%lu: invalid line", path, linenum);
		r = SSH_ERR_INVALID_FORMAT;
		برو out;
	}
	اگر ((principals = strdup(tmp)) == پوچ) {
		error_f("strdup failed");
		r = SSH_ERR_ALLOC_FAIL;
		برو out;
	}
	/*
	 * Bail out early if we're looking for a particular principal and this
	 * line does not list it.
	 */
	اگر (required_principal != پوچ) {
		اگر (match_pattern_list(required_principal,
		    principals, 0) != 1) {
			/* principal didn't match */
			r = SSH_ERR_کلید_NOT_FOUND;
			برو out;
		}
		debug_f("%s:%lu: matched principal \"%s\"",
		    path, linenum, required_principal);
	}

	اگر ((کلید = sshkey_new(کلید_UNSPEC)) == پوچ) {
		error_f("sshkey_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		برو out;
	}
	اگر (sshkey_read(کلید, &cp) != 0) {
		/* no key? Check for options */
		opts = cp;
		اگر (sshkey_advance_past_options(&cp) != 0) {
			error("%s:%lu: invalid options", path, linenum);
			r = SSH_ERR_INVALID_FORMAT;
			برو out;
		}
		اگر (cp == پوچ || *cp == '\0') {
			error("%s:%lu: missing key", path, linenum);
			r = SSH_ERR_INVALID_FORMAT;
			برو out;
		}
		*cp++ = '\0';
		skip_space(&cp);
		اگر (sshkey_read(کلید, &cp) != 0) {
			error("%s:%lu: invalid key", path, linenum);
			r = SSH_ERR_INVALID_FORMAT;
			برو out;
		}
	}
	debug3("%s:%lu: options %s", path, linenum, opts == پوچ ? "" : opts);
	اگر ((sigopts = sshsigopt_parse(opts, path, linenum, &reason)) == پوچ) {
		error("%s:%lu: bad options: %s", path, linenum, reason);
		r = SSH_ERR_INVALID_FORMAT;
		برو out;
	}
	/* success */
	اگر (principalsp != پوچ) {
		*principalsp = principals;
		principals = پوچ; /* transferred */
	}
	اگر (sigoptsp != پوچ) {
		*sigoptsp = sigopts;
		sigopts = پوچ; /* transferred */
	}
	اگر (keyp != پوچ) {
		*keyp = کلید;
		کلید = پوچ; /* transferred */
	}
	r = 0;
 out:
	آزاد(principals);
	sshsigopt_free(sigopts);
	sshkey_free(کلید);
	بازگشت r;
}

ایستا صحیح
cert_filter_principals(ثابت نویسه *path, u_long linenum,
    نویسه **principalsp, ثابت ساختار sshkey *cert, uint64_t verify_time)
{
	نویسه *cp, *oprincipals, *principals;
	ثابت نویسه *reason;
	ساختار sshbuf *nprincipals;
	صحیح r = SSH_ERR_INTERNAL_ERROR, success = 0;
	u_int i;

	oprincipals = principals = *principalsp;
	*principalsp = پوچ;

	اگر ((nprincipals = sshbuf_new()) == پوچ) {
		r = SSH_ERR_ALLOC_FAIL;
		برو out;
	}

	وقتی ((cp = strsep(&principals, ",")) != پوچ && *cp != '\0') {
		/* Check certificate validity */
		اگر ((r = sshkey_cert_check_authority(cert, 0, 0, verify_time,
		    پوچ, &reason)) != 0) {
			debug("%s:%lu: principal \"%s\" not authorized: %s",
			    path, linenum, cp, reason);
			ادامه;
		}
		/* Return all matching principal names from the cert */
		برای (i = 0; i < cert->cert->nprincipals; i++) {
			اگر (match_pattern(cert->cert->principals[i], cp)) {
				اگر ((r = sshbuf_putf(nprincipals, "%s%s",
					sshbuf_len(nprincipals) != 0 ? "," : "",
						cert->cert->principals[i])) != 0) {
					error_f("buffer error");
					برو out;
				}
			}
		}
	}
	اگر (sshbuf_len(nprincipals) == 0) {
		error("%s:%lu: no valid principals found", path, linenum);
		r = SSH_ERR_کلید_CERT_INVALID;
		برو out;
	}
	اگر ((principals = sshbuf_dup_string(nprincipals)) == پوچ) {
		error_f("buffer error");
		r = SSH_ERR_ALLOC_FAIL;
		برو out;
	}
	/* success */
	success = 1;
	*principalsp = principals;
 out:
	sshbuf_free(nprincipals);
	آزاد(oprincipals);
	بازگشت success ? 0 : r;
}

ایستا صحیح
check_allowed_کلیدها_سطر(ثابت نویسه *path, u_long linenum, نویسه *سطر,
    ثابت ساختار sshkey *sign_کلید, ثابت نویسه *principal,
    ثابت نویسه *sig_namespace, uint64_t verify_time, نویسه **principalsp)
{
	ساختار sshkey *found_کلید = پوچ;
	نویسه *principals = پوچ;
	صحیح r, success = 0;
	ثابت نویسه *reason = پوچ;
	ساختار sshsigopt *sigopts = پوچ;
	نویسه tvalid[64], tverify[64];

	اگر (principalsp != پوچ)
		*principalsp = پوچ;

	/* Parse the line */
	اگر ((r = parse_principals_کلید_and_options(path, linenum, سطر,
	    principal, &principals, &found_کلید, &sigopts)) != 0) {
		/* error already logged */
		برو done;
	}

	اگر (!sigopts->ca && sshkey_equal(found_کلید, sign_کلید)) {
		/* Exact match of key */
		debug("%s:%lu: matched key", path, linenum);
	} وگرنه اگر (sigopts->ca && sshkey_is_cert(sign_کلید) &&
	    sshkey_equal_public(sign_کلید->cert->signature_کلید, found_کلید)) {
		اگر (principal) {
			/* Match certificate CA key with specified principal */
			اگر ((r = sshkey_cert_check_authority(sign_کلید, 0, 0,
			    verify_time, principal, &reason)) != 0) {
				error("%s:%lu: certificate not authorized: %s",
				    path, linenum, reason);
				برو done;
			}
			debug("%s:%lu: matched certificate CA key",
			    path, linenum);
		} وگرنه {
			/* No principal specified - find all matching ones */
			اگر ((r = cert_filter_principals(path, linenum,
			    &principals, sign_کلید, verify_time)) != 0) {
				/* error already displayed */
				debug_r(r, "%s:%lu: cert_filter_principals",
				    path, linenum);
				برو done;
			}
			debug("%s:%lu: matched certificate CA key",
			    path, linenum);
		}
	} وگرنه {
		/* Didn't match key */
		برو done;
	}

	/* Check whether options preclude the use of this key */
	اگر (sigopts->namespaces != پوچ && sig_namespace != پوچ &&
	    match_pattern_list(sig_namespace, sigopts->namespaces, 0) != 1) {
		error("%s:%lu: key is not permitted for use in signature "
		    "namespace \"%s\"", path, linenum, sig_namespace);
		برو done;
	}

	/* check key time validity */
	format_absolute_time((uint64_t)verify_time, tverify, اندازه(tverify));
	اگر (sigopts->valid_after != 0 &&
	    (uint64_t)verify_time < sigopts->valid_after) {
		format_absolute_time(sigopts->valid_after,
		    tvalid, اندازه(tvalid));
		error("%s:%lu: key is not yet valid: "
		    "verify time %s < valid-after %s", path, linenum,
		    tverify, tvalid);
		برو done;
	}
	اگر (sigopts->valid_before != 0 &&
	    (uint64_t)verify_time > sigopts->valid_before) {
		format_absolute_time(sigopts->valid_before,
		    tvalid, اندازه(tvalid));
		error("%s:%lu: key has expired: "
		    "verify time %s > valid-before %s", path, linenum,
		    tverify, tvalid);
		برو done;
	}
	success = 1;

 done:
	اگر (success && principalsp != پوچ) {
		*principalsp = principals;
		principals = پوچ; /* transferred */
	}
	آزاد(principals);
	sshkey_free(found_کلید);
	sshsigopt_free(sigopts);
	بازگشت success ? 0 : SSH_ERR_کلید_NOT_FOUND;
}

صحیح
sshsig_check_allowed_کلیدها(ثابت نویسه *path, ثابت ساختار sshkey *sign_کلید,
    ثابت نویسه *principal, ثابت نویسه *sig_namespace, uint64_t verify_time)
{
	FILE *f = پوچ;
	نویسه *سطر = پوچ;
	size_t linesize = 0;
	u_long linenum = 0;
	صحیح r = SSH_ERR_کلید_NOT_FOUND, oerrno;

	/* Check key and principal against file */
	اگر ((f = fopen(path, "r")) == پوچ) {
		oerrno = errno;
		error("Unable to open allowed keys file \"%s\": %s",
		    path, strerror(errno));
		errno = oerrno;
		بازگشت SSH_ERR_SYSTEM_ERROR;
	}

	وقتی (getline(&سطر, &linesize, f) != -1) {
		linenum++;
		r = check_allowed_کلیدها_سطر(path, linenum, سطر, sign_کلید,
		    principal, sig_namespace, verify_time, پوچ);
		آزاد(سطر);
		سطر = پوچ;
		linesize = 0;
		اگر (r == SSH_ERR_کلید_NOT_FOUND)
			ادامه;
		وگرنه اگر (r == 0) {
			/* success */
			fclose(f);
			بازگشت 0;
		} وگرنه
			بشکن;
	}
	/* Either we hit an error parsing or we simply didn't find the key */
	fclose(f);
	آزاد(سطر);
	بازگشت r;
}

صحیح
sshsig_find_principals(ثابت نویسه *path, ثابت ساختار sshkey *sign_کلید,
    uint64_t verify_time, نویسه **principals)
{
	FILE *f = پوچ;
	نویسه *سطر = پوچ;
	size_t linesize = 0;
	u_long linenum = 0;
	صحیح r = SSH_ERR_کلید_NOT_FOUND, oerrno;

	اگر ((f = fopen(path, "r")) == پوچ) {
		oerrno = errno;
		error("Unable to open allowed keys file \"%s\": %s",
		    path, strerror(errno));
		errno = oerrno;
		بازگشت SSH_ERR_SYSTEM_ERROR;
	}

	وقتی (getline(&سطر, &linesize, f) != -1) {
		linenum++;
		r = check_allowed_کلیدها_سطر(path, linenum, سطر,
		    sign_کلید, پوچ, پوچ, verify_time, principals);
		آزاد(سطر);
		سطر = پوچ;
		linesize = 0;
		اگر (r == SSH_ERR_کلید_NOT_FOUND)
			ادامه;
		وگرنه اگر (r == 0) {
			/* success */
			fclose(f);
			بازگشت 0;
		} وگرنه
			بشکن;
	}
	آزاد(سطر);
	/* Either we hit an error parsing or we simply didn't find the key */
	اگر (ferror(f) != 0) {
		oerrno = errno;
		fclose(f);
		error("Unable to read allowed keys file \"%s\": %s",
		    path, strerror(errno));
		errno = oerrno;
		بازگشت SSH_ERR_SYSTEM_ERROR;
	}
	fclose(f);
	بازگشت r;
}

صحیح
sshsig_match_principals(ثابت نویسه *path, ثابت نویسه *principal,
    نویسه ***principalsp, size_t *nprincipalsp)
{
	FILE *f = پوچ;
	نویسه *found, *سطر = پوچ, **principals = پوچ, **tmp;
	size_t i, nprincipals = 0, linesize = 0;
	u_long linenum = 0;
	صحیح oerrno = 0, r, ret = 0;

	اگر (principalsp != پوچ)
		*principalsp = پوچ;
	اگر (nprincipalsp != پوچ)
		*nprincipalsp = 0;

	/* Check key and principal against file */
	اگر ((f = fopen(path, "r")) == پوچ) {
		oerrno = errno;
		error("Unable to open allowed keys file \"%s\": %s",
		    path, strerror(errno));
		errno = oerrno;
		بازگشت SSH_ERR_SYSTEM_ERROR;
	}

	وقتی (getline(&سطر, &linesize, f) != -1) {
		linenum++;
		/* Parse the line */
		اگر ((r = parse_principals_کلید_and_options(path, linenum, سطر,
		    principal, &found, پوچ, پوچ)) != 0) {
			اگر (r == SSH_ERR_کلید_NOT_FOUND)
				ادامه;
			ret = r;
			oerrno = errno;
			بشکن; /* unexpected error */
		}
		اگر ((tmp = recallocarray(principals, nprincipals,
		    nprincipals + 1, اندازه(*principals))) == پوچ) {
			ret = SSH_ERR_ALLOC_FAIL;
			آزاد(found);
			بشکن;
		}
		principals = tmp;
		principals[nprincipals++] = found; /* transferred */
		آزاد(سطر);
		سطر = پوچ;
		linesize = 0;
	}
	fclose(f);
	آزاد(سطر);

	اگر (ret == 0) {
		اگر (nprincipals == 0)
			ret = SSH_ERR_کلید_NOT_FOUND;
		اگر (nprincipalsp != پوچ)
			*nprincipalsp = nprincipals;
		اگر (principalsp != پوچ) {
			*principalsp = principals;
			principals = پوچ; /* transferred */
			nprincipals = 0;
		}
	}

	برای (i = 0; i < nprincipals; i++)
		آزاد(principals[i]);
	آزاد(principals);

	errno = oerrno;
	بازگشت ret;
}

صحیح
sshsig_get_pubkey(ساختار sshbuf *signature, ساختار sshkey **pubkey)
{
	ساختار sshkey *pk = پوچ;
	صحیح r = SSH_ERR_SIGNATURE_INVALID;

	اگر (pubkey == پوچ)
		بازگشت SSH_ERR_INTERNAL_ERROR;
	اگر ((r = sshsig_parse_preamble(signature)) != 0)
		بازگشت r;
	اگر ((r = sshkey_froms(signature, &pk)) != 0)
		بازگشت r;

	*pubkey = pk;
	pk = پوچ;
	بازگشت 0;
}
