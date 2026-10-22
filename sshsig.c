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

#تعریف_کرو SIG_نسخہ		0x01
#تعریف_کرو MAGIC_PREAMBLE		"SSHSIG"
#تعریف_کرو MAGIC_PREAMBLE_LEN	(حجم(MAGIC_PREAMBLE) - 1)
#تعریف_کرو BEGIN_SIGNATURE		"-----BEGIN SSH SIGNATURE-----"
#تعریف_کرو انتہا_SIGNATURE		"-----END SSH SIGNATURE-----"
#تعریف_کرو RSA_SIGN_ALG		"rsa-sha2-512"
#تعریف_کرو RSA_SIGN_ALLOWED	"rsa-sha2-512,rsa-sha2-256"
#تعریف_کرو HASHALG_DEFAULT		"sha512"
#تعریف_کرو HASHALG_ALLOWED		"sha256,sha512"

صحیح
sshsig_armor(ثابت ساخت sshbuf *blob, ساخت sshbuf **برآمد)
{
	ساخت sshbuf *buf = تہی;
	صحیح r = SSH_ERR_اندرونی_ERROR;

	*برآمد = تہی;

	اگر ((buf = sshbuf_new()) == تہی) {
		error_f("sshbuf_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		جاؤ برآمد;
	}

	اگر ((r = sshbuf_putf(buf, "%s\n", BEGIN_SIGNATURE)) != 0) {
		error_fr(r, "sshbuf_putf");
		جاؤ برآمد;
	}

	اگر ((r = sshbuf_dtob64(blob, buf, 1)) != 0) {
		error_fr(r, "base64 encode signature");
		جاؤ برآمد;
	}

	اگر ((r = sshbuf_put(buf, انتہا_SIGNATURE,
	    حجم(انتہا_SIGNATURE)-1)) != 0 ||
	    (r = sshbuf_put_u8(buf, '\n')) != 0) {
		error_fr(r, "sshbuf_put");
		جاؤ برآمد;
	}
	/* success */
	*برآمد = buf;
	buf = تہی; /* transferred */
	r = 0;
 برآمد:
	sshbuf_free(buf);
	واپس r;
}

صحیح
sshsig_dearmor(ساخت sshbuf *sig, ساخت sshbuf **برآمد)
{
	صحیح r;
	سائز_t eoffset = 0;
	ساخت sshbuf *buf = تہی;
	ساخت sshbuf *sbuf = تہی;
	حرف *b64 = تہی;

	اگر ((sbuf = sshbuf_fromb(sig)) == تہی) {
		error_f("sshbuf_fromb failed");
		واپس SSH_ERR_ALLOC_FAIL;
	}

	/* Expect and consume preamble + lf/crlf */
	اگر ((r = sshbuf_cmp(sbuf, 0,
	    BEGIN_SIGNATURE, حجم(BEGIN_SIGNATURE)-1)) != 0) {
		error("Couldn't parse signature: missing header");
		جاؤ مکمل;
	}
	اگر ((r = sshbuf_consume(sbuf, حجم(BEGIN_SIGNATURE)-1)) != 0) {
		error_fr(r, "consume");
		جاؤ مکمل;
	}
	اگر ((r = sshbuf_cmp(sbuf, 0, "\r\n", 2)) == 0)
		eoffset = 2;
	ورنہ اگر ((r = sshbuf_cmp(sbuf, 0, "\n", 1)) == 0)
		eoffset = 1;
	ورنہ {
		r = SSH_ERR_INVALID_FORMAT;
		error_f("no header eol");
		جاؤ مکمل;
	}
	اگر ((r = sshbuf_consume(sbuf, eoffset)) != 0) {
		error_fr(r, "consume eol");
		جاؤ مکمل;
	}
	/* Find and consume lf + suffix (any prior cr would be ignored) */
	اگر ((r = sshbuf_ڈھونڈو(sbuf, 0, "\n" انتہا_SIGNATURE,
	    حجم(انتہا_SIGNATURE), &eoffset)) != 0) {
		error("Couldn't parse signature: missing footer");
		جاؤ مکمل;
	}
	اگر ((r = sshbuf_consume_انتہا(sbuf, sshbuf_len(sbuf)-eoffset)) != 0) {
		error_fr(r, "consume");
		جاؤ مکمل;
	}

	اگر ((b64 = sshbuf_dup_string(sbuf)) == تہی) {
		error_f("sshbuf_dup_string failed");
		r = SSH_ERR_ALLOC_FAIL;
		جاؤ مکمل;
	}

	اگر ((buf = sshbuf_new()) == تہی) {
		error_f("sshbuf_new() failed");
		r = SSH_ERR_ALLOC_FAIL;
		جاؤ مکمل;
	}

	اگر ((r = sshbuf_b64tod(buf, b64)) != 0) {
		error_fr(r, "decode base64");
		جاؤ مکمل;
	}

	/* success */
	*برآمد = buf;
	r = 0;
	buf = تہی; /* transferred */
مکمل:
	sshbuf_free(buf);
	sshbuf_free(sbuf);
	آزاد(b64);
	واپس r;
}

ساکن صحیح
sshsig_wrap_sign(ساخت sshkey *کلید, ثابت حرف *hashalg,
    ثابت حرف *sk_provider, ثابت حرف *sk_pin, ثابت ساخت sshbuf *h_پیغام,
    ثابت حرف *sig_namespace, ساخت sshbuf **برآمد,
    sshsig_signer *signer, خالی *signer_ctx)
{
	صحیح r;
	سائز_t slen = 0;
	u_char *sig = تہی;
	ساخت sshbuf *blob = تہی;
	ساخت sshbuf *tosign = تہی;
	ثابت حرف *sign_alg = تہی;

	اگر ((tosign = sshbuf_new()) == تہی ||
	    (blob = sshbuf_new()) == تہی) {
		error_f("sshbuf_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		جاؤ مکمل;
	}

	اگر ((r = sshbuf_put(tosign, MAGIC_PREAMBLE, MAGIC_PREAMBLE_LEN)) != 0 ||
	    (r = sshbuf_put_cstring(tosign, sig_namespace)) != 0 ||
	    (r = sshbuf_put_string(tosign, تہی, 0)) != 0 || /* reserved */
	    (r = sshbuf_put_cstring(tosign, hashalg)) != 0 ||
	    (r = sshbuf_put_stringb(tosign, h_پیغام)) != 0) {
		error_fr(r, "assemble message to sign");
		جاؤ مکمل;
	}

	/* If using RSA keys then default to a good signature algorithm */
	اگر (sshkey_type_plain(کلید->type) == کلید_RSA) {
		sign_alg = RSA_SIGN_ALG;
		اگر (strcmp(hashalg, "sha256") == 0)
			sign_alg = "rsa-sha2-256";
		ورنہ اگر (strcmp(hashalg, "sha512") == 0)
			sign_alg = "rsa-sha2-512";
	}

	اگر (signer != تہی) {
		اگر ((r = signer(کلید, &sig, &slen,
		    sshbuf_ptr(tosign), sshbuf_len(tosign),
		    sign_alg, sk_provider, sk_pin, 0, signer_ctx)) != 0) {
			error_r(r, "Couldn't sign message (signer)");
			جاؤ مکمل;
		}
	} ورنہ {
		اگر ((r = sshkey_sign(کلید, &sig, &slen,
		    sshbuf_ptr(tosign), sshbuf_len(tosign),
		    sign_alg, sk_provider, sk_pin, 0)) != 0) {
			error_r(r, "Couldn't sign message");
			جاؤ مکمل;
		}
	}

	اگر ((r = sshbuf_put(blob, MAGIC_PREAMBLE, MAGIC_PREAMBLE_LEN)) != 0 ||
	    (r = sshbuf_put_u32(blob, SIG_نسخہ)) != 0 ||
	    (r = sshkey_puts(کلید, blob)) != 0 ||
	    (r = sshbuf_put_cstring(blob, sig_namespace)) != 0 ||
	    (r = sshbuf_put_string(blob, تہی, 0)) != 0 || /* reserved */
	    (r = sshbuf_put_cstring(blob, hashalg)) != 0 ||
	    (r = sshbuf_put_string(blob, sig, slen)) != 0) {
		error_fr(r, "assemble signature object");
		جاؤ مکمل;
	}

	اگر (برآمد != تہی) {
		*برآمد = blob;
		blob = تہی;
	}
	r = 0;
مکمل:
	آزاد(sig);
	sshbuf_free(blob);
	sshbuf_free(tosign);
	واپس r;
}

/* Check preamble and version. */
ساکن صحیح
sshsig_parse_preamble(ساخت sshbuf *buf)
{
	صحیح r = SSH_ERR_اندرونی_ERROR;
	uint32_t sversion;

	اگر ((r = sshbuf_cmp(buf, 0, MAGIC_PREAMBLE, MAGIC_PREAMBLE_LEN)) != 0 ||
	    (r = sshbuf_consume(buf, (حجم(MAGIC_PREAMBLE)-1))) != 0 ||
	    (r = sshbuf_get_u32(buf, &sversion)) != 0) {
		error("Couldn't verify signature: invalid format");
		واپس r;
	}

	اگر (sversion > SIG_نسخہ) {
		error("Signature version %lu is larger than supported "
		    "version %u", (غیرعلامتی طویل)sversion, SIG_نسخہ);
		واپس SSH_ERR_INVALID_FORMAT;
	}
	واپس 0;
}

ساکن صحیح
sshsig_check_hashalg(ثابت حرف *hashalg)
{
	اگر (hashalg == تہی ||
	    مطابقت_نمونہ_list(hashalg, HASHALG_ALLOWED, 0) == 1)
		واپس 0;
	error_f("unsupported hash algorithm \"%.100s\"", hashalg);
	واپس SSH_ERR_SIGN_ALG_UNSUPPORTED;
}

ساکن صحیح
sshsig_peek_hashalg(ساخت sshbuf *signature, حرف **hashalgp)
{
	ساخت sshbuf *buf = تہی;
	حرف *hashalg = تہی;
	صحیح r = SSH_ERR_اندرونی_ERROR;

	اگر (hashalgp != تہی)
		*hashalgp = تہی;
	اگر ((buf = sshbuf_fromb(signature)) == تہی)
		واپس SSH_ERR_ALLOC_FAIL;
	اگر ((r = sshsig_parse_preamble(buf)) != 0)
		جاؤ مکمل;
	اگر ((r = sshbuf_get_string_براہ_راست(buf, تہی, تہی)) != 0 ||
	    (r = sshbuf_get_string_براہ_راست(buf, تہی, تہی)) != 0 ||
	    (r = sshbuf_get_string(buf, تہی, تہی)) != 0 ||
	    (r = sshbuf_get_cstring(buf, &hashalg, تہی)) != 0 ||
	    (r = sshbuf_get_string_براہ_راست(buf, تہی, تہی)) != 0) {
		error_fr(r, "parse signature object");
		جاؤ مکمل;
	}

	/* success */
	r = 0;
	*hashalgp = hashalg;
	hashalg = تہی;
 مکمل:
	آزاد(hashalg);
	sshbuf_free(buf);
	واپس r;
}

ساکن صحیح
sshsig_wrap_verify(ساخت sshbuf *signature, ثابت حرف *hashalg,
    ثابت ساخت sshbuf *h_پیغام, ثابت حرف *expect_namespace,
    ساخت sshkey **sign_keyp, ساخت sshkey_sig_details **sig_details)
{
	صحیح r = SSH_ERR_اندرونی_ERROR;
	ساخت sshbuf *buf = تہی, *toverify = تہی;
	ساخت sshkey *کلید = تہی;
	ثابت u_char *sig;
	حرف *got_namespace = تہی, *sigtype = تہی, *sig_hashalg = تہی;
	سائز_t siglen;

	debug_f("verify message length %zu", sshbuf_len(h_پیغام));
	اگر (sig_details != تہی)
		*sig_details = تہی;
	اگر (sign_keyp != تہی)
		*sign_keyp = تہی;

	اگر ((toverify = sshbuf_new()) == تہی) {
		error_f("sshbuf_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		جاؤ مکمل;
	}
	اگر ((r = sshbuf_put(toverify, MAGIC_PREAMBLE,
	    MAGIC_PREAMBLE_LEN)) != 0 ||
	    (r = sshbuf_put_cstring(toverify, expect_namespace)) != 0 ||
	    (r = sshbuf_put_string(toverify, تہی, 0)) != 0 || /* reserved */
	    (r = sshbuf_put_cstring(toverify, hashalg)) != 0 ||
	    (r = sshbuf_put_stringb(toverify, h_پیغام)) != 0) {
		error_fr(r, "assemble message to verify");
		جاؤ مکمل;
	}

	اگر ((r = sshsig_parse_preamble(signature)) != 0)
		جاؤ مکمل;

	اگر ((r = sshkey_froms(signature, &کلید)) != 0 ||
	    (r = sshbuf_get_cstring(signature, &got_namespace, تہی)) != 0 ||
	    (r = sshbuf_get_string(signature, تہی, تہی)) != 0 ||
	    (r = sshbuf_get_cstring(signature, &sig_hashalg, تہی)) != 0 ||
	    (r = sshbuf_get_string_براہ_راست(signature, &sig, &siglen)) != 0) {
		error_fr(r, "parse signature object");
		جاؤ مکمل;
	}

	اگر (sshbuf_len(signature) != 0) {
		error("Signature contains trailing data");
		r = SSH_ERR_INVALID_FORMAT;
		جاؤ مکمل;
	}

	اگر (strcmp(expect_namespace, got_namespace) != 0) {
		error("Couldn't verify signature: namespace does not match");
		debug_f("expected namespace \"%s\" received \"%s\"",
		    expect_namespace, got_namespace);
		r = SSH_ERR_SIGNATURE_INVALID;
		جاؤ مکمل;
	}
	اگر (strcmp(hashalg, sig_hashalg) != 0) {
		error("Couldn't verify signature: hash algorithm mismatch");
		debug_f("expected algorithm \"%s\" received \"%s\"",
		    hashalg, sig_hashalg);
		r = SSH_ERR_SIGNATURE_INVALID;
		جاؤ مکمل;
	}
	/* Ensure that RSA keys use an acceptable signature algorithm */
	اگر (sshkey_type_plain(کلید->type) == کلید_RSA) {
		اگر ((r = sshkey_get_sigtype(sig, siglen, &sigtype)) != 0) {
			error_r(r, "Couldn't verify signature: unable to get "
			    "signature type");
			جاؤ مکمل;
		}
		اگر (مطابقت_نمونہ_list(sigtype, RSA_SIGN_ALLOWED, 0) != 1) {
			error("Couldn't verify signature: unsupported RSA "
			    "signature algorithm %s", sigtype);
			r = SSH_ERR_SIGN_ALG_UNSUPPORTED;
			جاؤ مکمل;
		}
	}
	اگر ((r = sshkey_verify(کلید, sig, siglen, sshbuf_ptr(toverify),
	    sshbuf_len(toverify), تہی, 0, sig_details)) != 0) {
		error_r(r, "Signature verification failed");
		جاؤ مکمل;
	}

	/* success */
	r = 0;
	اگر (sign_keyp != تہی) {
		*sign_keyp = کلید;
		کلید = تہی; /* transferred */
	}
مکمل:
	آزاد(got_namespace);
	آزاد(sigtype);
	آزاد(sig_hashalg);
	sshbuf_free(buf);
	sshbuf_free(toverify);
	sshkey_free(کلید);
	واپس r;
}

ساکن صحیح
hash_بفر(ثابت ساخت sshbuf *m, ثابت حرف *hashalg, ساخت sshbuf **bp)
{
	حرف *hex, hash[SSH_DIGEST_MAX_لمبائی];
	صحیح alg, r = SSH_ERR_اندرونی_ERROR;
	ساخت sshbuf *b = تہی;

	*bp = تہی;
	memset(hash, 0, حجم(hash));

	اگر ((r = sshsig_check_hashalg(hashalg)) != 0)
		واپس r;
	اگر ((alg = ssh_digest_alg_by_name(hashalg)) == -1) {
		error_f("can't look up hash algorithm %s", hashalg);
		واپس SSH_ERR_اندرونی_ERROR;
	}
	اگر ((r = ssh_digest_بفر(alg, m, hash, حجم(hash))) != 0) {
		error_fr(r, "ssh_digest_buffer");
		واپس r;
	}
	اگر ((hex = tohex(hash, ssh_digest_بائٹیں(alg))) != تہی) {
		debug3_f("final hash: %s", hex);
		freezero(hex, لڑی_لمبائی(hex));
	}
	اگر ((b = sshbuf_new()) == تہی) {
		r = SSH_ERR_ALLOC_FAIL;
		جاؤ برآمد;
	}
	اگر ((r = sshbuf_put(b, hash, ssh_digest_بائٹیں(alg))) != 0) {
		error_fr(r, "sshbuf_put");
		جاؤ برآمد;
	}
	*bp = b;
	b = تہی; /* transferred */
	/* success */
	r = 0;
 برآمد:
	sshbuf_free(b);
	explicit_bzero(hash, حجم(hash));
	واپس r;
}

صحیح
sshsig_signb(ساخت sshkey *کلید, ثابت حرف *hashalg,
    ثابت حرف *sk_provider, ثابت حرف *sk_pin,
    ثابت ساخت sshbuf *پیغام_2, ثابت حرف *sig_namespace,
    ساخت sshbuf **برآمد, sshsig_signer *signer, خالی *signer_ctx)
{
	ساخت sshbuf *b = تہی;
	صحیح r = SSH_ERR_اندرونی_ERROR;

	اگر (hashalg == تہی)
		hashalg = HASHALG_DEFAULT;
	اگر (برآمد != تہی)
		*برآمد = تہی;
	اگر ((r = hash_بفر(پیغام_2, hashalg, &b)) != 0) {
		error_fr(r, "hash buffer");
		جاؤ برآمد;
	}
	اگر ((r = sshsig_wrap_sign(کلید, hashalg, sk_provider, sk_pin, b,
	    sig_namespace, برآمد, signer, signer_ctx)) != 0)
		جاؤ برآمد;
	/* success */
	r = 0;
 برآمد:
	sshbuf_free(b);
	واپس r;
}

صحیح
sshsig_verifyb(ساخت sshbuf *signature, ثابت ساخت sshbuf *پیغام_2,
    ثابت حرف *expect_namespace, ساخت sshkey **sign_keyp,
    ساخت sshkey_sig_details **sig_details)
{
	ساخت sshbuf *b = تہی;
	صحیح r = SSH_ERR_اندرونی_ERROR;
	حرف *hashalg = تہی;

	اگر (sig_details != تہی)
		*sig_details = تہی;
	اگر (sign_keyp != تہی)
		*sign_keyp = تہی;
	اگر ((r = sshsig_peek_hashalg(signature, &hashalg)) != 0)
		واپس r;
	debug_f("signature made with hash \"%s\"", hashalg);
	اگر ((r = hash_بفر(پیغام_2, hashalg, &b)) != 0) {
		error_fr(r, "hash buffer");
		جاؤ برآمد;
	}
	اگر ((r = sshsig_wrap_verify(signature, hashalg, b, expect_namespace,
	    sign_keyp, sig_details)) != 0)
		جاؤ برآمد;
	/* success */
	r = 0;
 برآمد:
	sshbuf_free(b);
	آزاد(hashalg);
	واپس r;
}

ساکن صحیح
hash_file(صحیح fd, ثابت حرف *hashalg, ساخت sshbuf **bp)
{
	حرف *hex, rbuf[8192], hash[SSH_DIGEST_MAX_لمبائی];
	ssize_t n, کل = 0;
	ساخت ssh_digest_ctx *ctx = تہی;
	صحیح alg, oerrno, r = SSH_ERR_اندرونی_ERROR;
	ساخت sshbuf *b = تہی;

	*bp = تہی;
	memset(hash, 0, حجم(hash));

	اگر ((r = sshsig_check_hashalg(hashalg)) != 0)
		واپس r;
	اگر ((alg = ssh_digest_alg_by_name(hashalg)) == -1) {
		error_f("can't look up hash algorithm %s", hashalg);
		واپس SSH_ERR_اندرونی_ERROR;
	}
	اگر ((ctx = ssh_digest_آغاز(alg)) == تہی) {
		error_f("ssh_digest_start failed");
		واپس SSH_ERR_اندرونی_ERROR;
	}
	برائے (;;) {
		اگر ((n = اقرأ(fd, rbuf, حجم(rbuf))) == -1) {
			اگر (errno == EINTR || errno == EAGAIN)
				جاری;
			oerrno = errno;
			error_f("read: %s", strerror(errno));
			errno = oerrno;
			r = SSH_ERR_SYSTEM_ERROR;
			جاؤ برآمد;
		} ورنہ اگر (n == 0) {
			debug2_f("hashed %zu bytes", کل);
			توڑو; /* EOF */
		}
		کل += (سائز_t)n;
		اگر ((r = ssh_digest_update(ctx, rbuf, (سائز_t)n)) != 0) {
			error_fr(r, "ssh_digest_update");
			جاؤ برآمد;
		}
	}
	اگر ((r = ssh_digest_final(ctx, hash, حجم(hash))) != 0) {
		error_fr(r, "ssh_digest_final");
		جاؤ برآمد;
	}
	اگر ((hex = tohex(hash, ssh_digest_بائٹیں(alg))) != تہی) {
		debug3_f("final hash: %s", hex);
		freezero(hex, لڑی_لمبائی(hex));
	}
	اگر ((b = sshbuf_new()) == تہی) {
		r = SSH_ERR_ALLOC_FAIL;
		جاؤ برآمد;
	}
	اگر ((r = sshbuf_put(b, hash, ssh_digest_بائٹیں(alg))) != 0) {
		error_fr(r, "sshbuf_put");
		جاؤ برآمد;
	}
	*bp = b;
	b = تہی; /* transferred */
	/* success */
	r = 0;
 برآمد:
	oerrno = errno;
	sshbuf_free(b);
	ssh_digest_free(ctx);
	explicit_bzero(hash, حجم(hash));
	errno = oerrno;
	واپس r;
}

صحیح
sshsig_sign_fd(ساخت sshkey *کلید, ثابت حرف *hashalg,
    ثابت حرف *sk_provider, ثابت حرف *sk_pin,
    صحیح fd, ثابت حرف *sig_namespace, ساخت sshbuf **برآمد,
    sshsig_signer *signer, خالی *signer_ctx)
{
	ساخت sshbuf *b = تہی;
	صحیح r = SSH_ERR_اندرونی_ERROR;

	اگر (hashalg == تہی)
		hashalg = HASHALG_DEFAULT;
	اگر (برآمد != تہی)
		*برآمد = تہی;
	اگر ((r = hash_file(fd, hashalg, &b)) != 0) {
		error_fr(r, "hash_file");
		واپس r;
	}
	اگر ((r = sshsig_wrap_sign(کلید, hashalg, sk_provider, sk_pin, b,
	    sig_namespace, برآمد, signer, signer_ctx)) != 0)
		جاؤ برآمد;
	/* success */
	r = 0;
 برآمد:
	sshbuf_free(b);
	واپس r;
}

صحیح
sshsig_verify_fd(ساخت sshbuf *signature, صحیح fd,
    ثابت حرف *expect_namespace, ساخت sshkey **sign_keyp,
    ساخت sshkey_sig_details **sig_details)
{
	ساخت sshbuf *b = تہی;
	صحیح r = SSH_ERR_اندرونی_ERROR;
	حرف *hashalg = تہی;

	اگر (sig_details != تہی)
		*sig_details = تہی;
	اگر (sign_keyp != تہی)
		*sign_keyp = تہی;
	اگر ((r = sshsig_peek_hashalg(signature, &hashalg)) != 0)
		واپس r;
	debug_f("signature made with hash \"%s\"", hashalg);
	اگر ((r = hash_file(fd, hashalg, &b)) != 0) {
		error_fr(r, "hash_file");
		جاؤ برآمد;
	}
	اگر ((r = sshsig_wrap_verify(signature, hashalg, b, expect_namespace,
	    sign_keyp, sig_details)) != 0)
		جاؤ برآمد;
	/* success */
	r = 0;
 برآمد:
	sshbuf_free(b);
	آزاد(hashalg);
	واپس r;
}

ساخت sshsigopt {
	صحیح ca;
	حرف *namespaces;
	uint64_t valid_after, valid_before;
};

ساخت sshsigopt *
sshsigopt_parse(ثابت حرف *opts, ثابت حرف *راستہ, u_long linenum,
    ثابت حرف **errstrp)
{
	ساخت sshsigopt *ret;
	صحیح r;
	حرف *opt;
	ثابت حرف *errstr = تہی;

	اگر ((ret = صفر_حافظہ_دو(1, حجم(*ret))) == تہی)
		واپس تہی;
	اگر (opts == تہی || *opts == '\0')
		واپس ret; /* Empty options yields empty options :) */

	جب (*opts && *opts != ' ' && *opts != '\t') {
		/* flag options */
		اگر ((r = opt_flag("cert-authority", 0, &opts)) != -1) {
			ret->ca = 1;
		} ورنہ اگر (opt_مطابقت(&opts, "namespaces")) {
			اگر (ret->namespaces != تہی) {
				errstr = "multiple \"namespaces\" clauses";
				جاؤ fail;
			}
			ret->namespaces = opt_dequote(&opts, &errstr);
			اگر (ret->namespaces == تہی)
				جاؤ fail;
		} ورنہ اگر (opt_مطابقت(&opts, "valid-after")) {
			اگر (ret->valid_after != 0) {
				errstr = "multiple \"valid-after\" clauses";
				جاؤ fail;
			}
			اگر ((opt = opt_dequote(&opts, &errstr)) == تہی)
				جاؤ fail;
			اگر (parse_absolute_وقت(opt, &ret->valid_after) != 0 ||
			    ret->valid_after == 0) {
				آزاد(opt);
				errstr = "invalid \"valid-after\" time";
				جاؤ fail;
			}
			آزاد(opt);
		} ورنہ اگر (opt_مطابقت(&opts, "valid-before")) {
			اگر (ret->valid_before != 0) {
				errstr = "multiple \"valid-before\" clauses";
				جاؤ fail;
			}
			اگر ((opt = opt_dequote(&opts, &errstr)) == تہی)
				جاؤ fail;
			اگر (parse_absolute_وقت(opt, &ret->valid_before) != 0 ||
			    ret->valid_before == 0) {
				آزاد(opt);
				errstr = "invalid \"valid-before\" time";
				جاؤ fail;
			}
			آزاد(opt);
		}
		/*
		 * Skip the comma, and move to the next option
		 * (or break out if there are no more).
		 */
		اگر (*opts == '\0' || *opts == ' ' || *opts == '\t')
			توڑو;		/* End of options. */
		/* Anything other than a comma is an unknown option */
		اگر (*opts != ',') {
			errstr = "unknown key option";
			جاؤ fail;
		}
		opts++;
		اگر (*opts == '\0') {
			errstr = "unexpected end-of-options";
			جاؤ fail;
		}
	}
	/* final consistency check */
	اگر (ret->valid_after != 0 && ret->valid_before != 0 &&
	    ret->valid_before <= ret->valid_after) {
		errstr = "\"valid-before\" time is before \"valid-after\"";
		جاؤ fail;
	}
	/* success */
	واپس ret;
 fail:
	اگر (errstrp != تہی)
		*errstrp = errstr;
	sshsigopt_free(ret);
	واپس تہی;
}

خالی
sshsigopt_free(ساخت sshsigopt *opts)
{
	اگر (opts == تہی)
		واپس;
	آزاد(opts->namespaces);
	آزاد(opts);
}

ساکن صحیح
parse_principals_کلید_and_options(ثابت حرف *راستہ, u_long linenum, حرف *سطر,
    ثابت حرف *required_principal, حرف **principalsp, ساخت sshkey **keyp,
    ساخت sshsigopt **sigoptsp)
{
	حرف *opts = تہی, *tmp, *cp, *principals = تہی;
	ثابت حرف *reason = تہی;
	ساخت sshsigopt *sigopts = تہی;
	ساخت sshkey *کلید = تہی;
	صحیح r = SSH_ERR_اندرونی_ERROR;

	اگر (principalsp != تہی)
		*principalsp = تہی;
	اگر (sigoptsp != تہی)
		*sigoptsp = تہی;
	اگر (keyp != تہی)
		*keyp = تہی;

	cp = سطر;
	cp = cp + strspn(cp, " \t\n\r"); /* skip leading whitespace */
	اگر (*cp == '#' || *cp == '\0')
		واپس SSH_ERR_کلید_NOT_ملا; /* blank or all-comment line */

	/* format: identity[,identity...] [option[,option...]] key */
	اگر ((tmp = strdelimw(&cp)) == تہی || cp == تہی) {
		error("%s:%lu: invalid line", راستہ, linenum);
		r = SSH_ERR_INVALID_FORMAT;
		جاؤ برآمد;
	}
	اگر ((principals = strdup(tmp)) == تہی) {
		error_f("strdup failed");
		r = SSH_ERR_ALLOC_FAIL;
		جاؤ برآمد;
	}
	/*
	 * Bail out early if we're looking for a particular principal and this
	 * line does not list it.
	 */
	اگر (required_principal != تہی) {
		اگر (مطابقت_نمونہ_list(required_principal,
		    principals, 0) != 1) {
			/* principal didn't match */
			r = SSH_ERR_کلید_NOT_ملا;
			جاؤ برآمد;
		}
		debug_f("%s:%lu: matched principal \"%s\"",
		    راستہ, linenum, required_principal);
	}

	اگر ((کلید = sshkey_new(کلید_UNSPEC)) == تہی) {
		error_f("sshkey_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		جاؤ برآمد;
	}
	اگر (sshkey_read(کلید, &cp) != 0) {
		/* no key? Check for options */
		opts = cp;
		اگر (sshkey_advance_past_options(&cp) != 0) {
			error("%s:%lu: invalid options", راستہ, linenum);
			r = SSH_ERR_INVALID_FORMAT;
			جاؤ برآمد;
		}
		اگر (cp == تہی || *cp == '\0') {
			error("%s:%lu: missing key", راستہ, linenum);
			r = SSH_ERR_INVALID_FORMAT;
			جاؤ برآمد;
		}
		*cp++ = '\0';
		skip_space(&cp);
		اگر (sshkey_read(کلید, &cp) != 0) {
			error("%s:%lu: invalid key", راستہ, linenum);
			r = SSH_ERR_INVALID_FORMAT;
			جاؤ برآمد;
		}
	}
	debug3("%s:%lu: options %s", راستہ, linenum, opts == تہی ? "" : opts);
	اگر ((sigopts = sshsigopt_parse(opts, راستہ, linenum, &reason)) == تہی) {
		error("%s:%lu: bad options: %s", راستہ, linenum, reason);
		r = SSH_ERR_INVALID_FORMAT;
		جاؤ برآمد;
	}
	/* success */
	اگر (principalsp != تہی) {
		*principalsp = principals;
		principals = تہی; /* transferred */
	}
	اگر (sigoptsp != تہی) {
		*sigoptsp = sigopts;
		sigopts = تہی; /* transferred */
	}
	اگر (keyp != تہی) {
		*keyp = کلید;
		کلید = تہی; /* transferred */
	}
	r = 0;
 برآمد:
	آزاد(principals);
	sshsigopt_free(sigopts);
	sshkey_free(کلید);
	واپس r;
}

ساکن صحیح
cert_filter_principals(ثابت حرف *راستہ, u_long linenum,
    حرف **principalsp, ثابت ساخت sshkey *cert, uint64_t verify_وقت)
{
	حرف *cp, *oprincipals, *principals;
	ثابت حرف *reason;
	ساخت sshbuf *nprincipals;
	صحیح r = SSH_ERR_اندرونی_ERROR, success = 0;
	u_int i;

	oprincipals = principals = *principalsp;
	*principalsp = تہی;

	اگر ((nprincipals = sshbuf_new()) == تہی) {
		r = SSH_ERR_ALLOC_FAIL;
		جاؤ برآمد;
	}

	جب ((cp = strsep(&principals, ",")) != تہی && *cp != '\0') {
		/* Check certificate validity */
		اگر ((r = sshkey_cert_check_authority(cert, 0, 0, verify_وقت,
		    تہی, &reason)) != 0) {
			debug("%s:%lu: principal \"%s\" not authorized: %s",
			    راستہ, linenum, cp, reason);
			جاری;
		}
		/* Return all matching principal names from the cert */
		برائے (i = 0; i < cert->cert->nprincipals; i++) {
			اگر (مطابقت_نمونہ(cert->cert->principals[i], cp)) {
				اگر ((r = sshbuf_putf(nprincipals, "%s%s",
					sshbuf_len(nprincipals) != 0 ? "," : "",
						cert->cert->principals[i])) != 0) {
					error_f("buffer error");
					جاؤ برآمد;
				}
			}
		}
	}
	اگر (sshbuf_len(nprincipals) == 0) {
		error("%s:%lu: no valid principals found", راستہ, linenum);
		r = SSH_ERR_کلید_CERT_INVALID;
		جاؤ برآمد;
	}
	اگر ((principals = sshbuf_dup_string(nprincipals)) == تہی) {
		error_f("buffer error");
		r = SSH_ERR_ALLOC_FAIL;
		جاؤ برآمد;
	}
	/* success */
	success = 1;
	*principalsp = principals;
 برآمد:
	sshbuf_free(nprincipals);
	آزاد(oprincipals);
	واپس success ? 0 : r;
}

ساکن صحیح
check_allowed_کلیدیں_سطر(ثابت حرف *راستہ, u_long linenum, حرف *سطر,
    ثابت ساخت sshkey *sign_کلید, ثابت حرف *principal,
    ثابت حرف *sig_namespace, uint64_t verify_وقت, حرف **principalsp)
{
	ساخت sshkey *ملا_کلید = تہی;
	حرف *principals = تہی;
	صحیح r, success = 0;
	ثابت حرف *reason = تہی;
	ساخت sshsigopt *sigopts = تہی;
	حرف tvalid[64], tverify[64];

	اگر (principalsp != تہی)
		*principalsp = تہی;

	/* Parse the line */
	اگر ((r = parse_principals_کلید_and_options(راستہ, linenum, سطر,
	    principal, &principals, &ملا_کلید, &sigopts)) != 0) {
		/* error already logged */
		جاؤ مکمل;
	}

	اگر (!sigopts->ca && sshkey_equal(ملا_کلید, sign_کلید)) {
		/* Exact match of key */
		debug("%s:%lu: matched key", راستہ, linenum);
	} ورنہ اگر (sigopts->ca && sshkey_is_cert(sign_کلید) &&
	    sshkey_equal_عوامی(sign_کلید->cert->signature_کلید, ملا_کلید)) {
		اگر (principal) {
			/* Match certificate CA key with specified principal */
			اگر ((r = sshkey_cert_check_authority(sign_کلید, 0, 0,
			    verify_وقت, principal, &reason)) != 0) {
				error("%s:%lu: certificate not authorized: %s",
				    راستہ, linenum, reason);
				جاؤ مکمل;
			}
			debug("%s:%lu: matched certificate CA key",
			    راستہ, linenum);
		} ورنہ {
			/* No principal specified - find all matching ones */
			اگر ((r = cert_filter_principals(راستہ, linenum,
			    &principals, sign_کلید, verify_وقت)) != 0) {
				/* error already displayed */
				debug_r(r, "%s:%lu: cert_filter_principals",
				    راستہ, linenum);
				جاؤ مکمل;
			}
			debug("%s:%lu: matched certificate CA key",
			    راستہ, linenum);
		}
	} ورنہ {
		/* Didn't match key */
		جاؤ مکمل;
	}

	/* Check whether options preclude the use of this key */
	اگر (sigopts->namespaces != تہی && sig_namespace != تہی &&
	    مطابقت_نمونہ_list(sig_namespace, sigopts->namespaces, 0) != 1) {
		error("%s:%lu: key is not permitted for use in signature "
		    "namespace \"%s\"", راستہ, linenum, sig_namespace);
		جاؤ مکمل;
	}

	/* check key time validity */
	format_absolute_وقت((uint64_t)verify_وقت, tverify, حجم(tverify));
	اگر (sigopts->valid_after != 0 &&
	    (uint64_t)verify_وقت < sigopts->valid_after) {
		format_absolute_وقت(sigopts->valid_after,
		    tvalid, حجم(tvalid));
		error("%s:%lu: key is not yet valid: "
		    "verify time %s < valid-after %s", راستہ, linenum,
		    tverify, tvalid);
		جاؤ مکمل;
	}
	اگر (sigopts->valid_before != 0 &&
	    (uint64_t)verify_وقت > sigopts->valid_before) {
		format_absolute_وقت(sigopts->valid_before,
		    tvalid, حجم(tvalid));
		error("%s:%lu: key has expired: "
		    "verify time %s > valid-before %s", راستہ, linenum,
		    tverify, tvalid);
		جاؤ مکمل;
	}
	success = 1;

 مکمل:
	اگر (success && principalsp != تہی) {
		*principalsp = principals;
		principals = تہی; /* transferred */
	}
	آزاد(principals);
	sshkey_free(ملا_کلید);
	sshsigopt_free(sigopts);
	واپس success ? 0 : SSH_ERR_کلید_NOT_ملا;
}

صحیح
sshsig_check_allowed_کلیدیں(ثابت حرف *راستہ, ثابت ساخت sshkey *sign_کلید,
    ثابت حرف *principal, ثابت حرف *sig_namespace, uint64_t verify_وقت)
{
	FILE *f = تہی;
	حرف *سطر = تہی;
	سائز_t linesize = 0;
	u_long linenum = 0;
	صحیح r = SSH_ERR_کلید_NOT_ملا, oerrno;

	/* Check key and principal against file */
	اگر ((f = fopen(راستہ, "r")) == تہی) {
		oerrno = errno;
		error("Unable to open allowed keys file \"%s\": %s",
		    راستہ, strerror(errno));
		errno = oerrno;
		واپس SSH_ERR_SYSTEM_ERROR;
	}

	جب (getline(&سطر, &linesize, f) != -1) {
		linenum++;
		r = check_allowed_کلیدیں_سطر(راستہ, linenum, سطر, sign_کلید,
		    principal, sig_namespace, verify_وقت, تہی);
		آزاد(سطر);
		سطر = تہی;
		linesize = 0;
		اگر (r == SSH_ERR_کلید_NOT_ملا)
			جاری;
		ورنہ اگر (r == 0) {
			/* success */
			fclose(f);
			واپس 0;
		} ورنہ
			توڑو;
	}
	/* Either we hit an error parsing or we simply didn't find the key */
	fclose(f);
	آزاد(سطر);
	واپس r;
}

صحیح
sshsig_ڈھونڈو_principals(ثابت حرف *راستہ, ثابت ساخت sshkey *sign_کلید,
    uint64_t verify_وقت, حرف **principals)
{
	FILE *f = تہی;
	حرف *سطر = تہی;
	سائز_t linesize = 0;
	u_long linenum = 0;
	صحیح r = SSH_ERR_کلید_NOT_ملا, oerrno;

	اگر ((f = fopen(راستہ, "r")) == تہی) {
		oerrno = errno;
		error("Unable to open allowed keys file \"%s\": %s",
		    راستہ, strerror(errno));
		errno = oerrno;
		واپس SSH_ERR_SYSTEM_ERROR;
	}

	جب (getline(&سطر, &linesize, f) != -1) {
		linenum++;
		r = check_allowed_کلیدیں_سطر(راستہ, linenum, سطر,
		    sign_کلید, تہی, تہی, verify_وقت, principals);
		آزاد(سطر);
		سطر = تہی;
		linesize = 0;
		اگر (r == SSH_ERR_کلید_NOT_ملا)
			جاری;
		ورنہ اگر (r == 0) {
			/* success */
			fclose(f);
			واپس 0;
		} ورنہ
			توڑو;
	}
	آزاد(سطر);
	/* Either we hit an error parsing or we simply didn't find the key */
	اگر (ferror(f) != 0) {
		oerrno = errno;
		fclose(f);
		error("Unable to read allowed keys file \"%s\": %s",
		    راستہ, strerror(errno));
		errno = oerrno;
		واپس SSH_ERR_SYSTEM_ERROR;
	}
	fclose(f);
	واپس r;
}

صحیح
sshsig_مطابقت_principals(ثابت حرف *راستہ, ثابت حرف *principal,
    حرف ***principalsp, سائز_t *nprincipalsp)
{
	FILE *f = تہی;
	حرف *ملا, *سطر = تہی, **principals = تہی, **tmp;
	سائز_t i, nprincipals = 0, linesize = 0;
	u_long linenum = 0;
	صحیح oerrno = 0, r, ret = 0;

	اگر (principalsp != تہی)
		*principalsp = تہی;
	اگر (nprincipalsp != تہی)
		*nprincipalsp = 0;

	/* Check key and principal against file */
	اگر ((f = fopen(راستہ, "r")) == تہی) {
		oerrno = errno;
		error("Unable to open allowed keys file \"%s\": %s",
		    راستہ, strerror(errno));
		errno = oerrno;
		واپس SSH_ERR_SYSTEM_ERROR;
	}

	جب (getline(&سطر, &linesize, f) != -1) {
		linenum++;
		/* Parse the line */
		اگر ((r = parse_principals_کلید_and_options(راستہ, linenum, سطر,
		    principal, &ملا, تہی, تہی)) != 0) {
			اگر (r == SSH_ERR_کلید_NOT_ملا)
				جاری;
			ret = r;
			oerrno = errno;
			توڑو; /* unexpected error */
		}
		اگر ((tmp = recallocarray(principals, nprincipals,
		    nprincipals + 1, حجم(*principals))) == تہی) {
			ret = SSH_ERR_ALLOC_FAIL;
			آزاد(ملا);
			توڑو;
		}
		principals = tmp;
		principals[nprincipals++] = ملا; /* transferred */
		آزاد(سطر);
		سطر = تہی;
		linesize = 0;
	}
	fclose(f);
	آزاد(سطر);

	اگر (ret == 0) {
		اگر (nprincipals == 0)
			ret = SSH_ERR_کلید_NOT_ملا;
		اگر (nprincipalsp != تہی)
			*nprincipalsp = nprincipals;
		اگر (principalsp != تہی) {
			*principalsp = principals;
			principals = تہی; /* transferred */
			nprincipals = 0;
		}
	}

	برائے (i = 0; i < nprincipals; i++)
		آزاد(principals[i]);
	آزاد(principals);

	errno = oerrno;
	واپس ret;
}

صحیح
sshsig_get_pubkey(ساخت sshbuf *signature, ساخت sshkey **pubkey)
{
	ساخت sshkey *pk = تہی;
	صحیح r = SSH_ERR_SIGNATURE_INVALID;

	اگر (pubkey == تہی)
		واپس SSH_ERR_اندرونی_ERROR;
	اگر ((r = sshsig_parse_preamble(signature)) != 0)
		واپس r;
	اگر ((r = sshkey_froms(signature, &pk)) != 0)
		واپس r;

	*pubkey = pk;
	pk = تہی;
	واپس 0;
}
