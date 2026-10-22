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

#تعریف_کړه SIG_نسخه		0x01
#تعریف_کړه MAGIC_PREAMBLE		"SSHSIG"
#تعریف_کړه MAGIC_PREAMBLE_LEN	(حجم(MAGIC_PREAMBLE) - 1)
#تعریف_کړه BEGIN_SIGNATURE		"-----BEGIN SSH SIGNATURE-----"
#تعریف_کړه پای_ټکی_SIGNATURE		"-----END SSH SIGNATURE-----"
#تعریف_کړه RSA_SIGN_ALG		"rsa-sha2-512"
#تعریف_کړه RSA_SIGN_ALLOWED	"rsa-sha2-512,rsa-sha2-256"
#تعریف_کړه HASHALG_DEFAULT		"sha512"
#تعریف_کړه HASHALG_ALLOWED		"sha256,sha512"

صحيح
sshsig_armor(ثابت بنية sshbuf *blob, بنية sshbuf **بهر)
{
	بنية sshbuf *buf = عدم;
	صحيح r = SSH_ERR_دننی_ERROR;

	*بهر = عدم;

	إذا ((buf = sshbuf_new()) == عدم) {
		error_f("sshbuf_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		اذهب بهر;
	}

	إذا ((r = sshbuf_putf(buf, "%s\n", BEGIN_SIGNATURE)) != 0) {
		error_fr(r, "sshbuf_putf");
		اذهب بهر;
	}

	إذا ((r = sshbuf_dtob64(blob, buf, 1)) != 0) {
		error_fr(r, "base64 encode signature");
		اذهب بهر;
	}

	إذا ((r = sshbuf_put(buf, پای_ټکی_SIGNATURE,
	    حجم(پای_ټکی_SIGNATURE)-1)) != 0 ||
	    (r = sshbuf_put_u8(buf, '\n')) != 0) {
		error_fr(r, "sshbuf_put");
		اذهب بهر;
	}
	/* success */
	*بهر = buf;
	buf = عدم; /* transferred */
	r = 0;
 بهر:
	sshbuf_free(buf);
	أرجع r;
}

صحيح
sshsig_dearmor(بنية sshbuf *sig, بنية sshbuf **بهر)
{
	صحيح r;
	اندازه_t eoffset = 0;
	بنية sshbuf *buf = عدم;
	بنية sshbuf *sbuf = عدم;
	حرف *b64 = عدم;

	إذا ((sbuf = sshbuf_fromb(sig)) == عدم) {
		error_f("sshbuf_fromb failed");
		أرجع SSH_ERR_ALLOC_FAIL;
	}

	/* Expect and consume preamble + lf/crlf */
	إذا ((r = sshbuf_cmp(sbuf, 0,
	    BEGIN_SIGNATURE, حجم(BEGIN_SIGNATURE)-1)) != 0) {
		error("Couldn't parse signature: missing header");
		اذهب بشپړ;
	}
	إذا ((r = sshbuf_consume(sbuf, حجم(BEGIN_SIGNATURE)-1)) != 0) {
		error_fr(r, "consume");
		اذهب بشپړ;
	}
	إذا ((r = sshbuf_cmp(sbuf, 0, "\r\n", 2)) == 0)
		eoffset = 2;
	وإلا إذا ((r = sshbuf_cmp(sbuf, 0, "\n", 1)) == 0)
		eoffset = 1;
	وإلا {
		r = SSH_ERR_INVALID_FORMAT;
		error_f("no header eol");
		اذهب بشپړ;
	}
	إذا ((r = sshbuf_consume(sbuf, eoffset)) != 0) {
		error_fr(r, "consume eol");
		اذهب بشپړ;
	}
	/* Find and consume lf + suffix (any prior cr would be ignored) */
	إذا ((r = sshbuf_پیدا_کړه(sbuf, 0, "\n" پای_ټکی_SIGNATURE,
	    حجم(پای_ټکی_SIGNATURE), &eoffset)) != 0) {
		error("Couldn't parse signature: missing footer");
		اذهب بشپړ;
	}
	إذا ((r = sshbuf_consume_پای_ټکی(sbuf, sshbuf_len(sbuf)-eoffset)) != 0) {
		error_fr(r, "consume");
		اذهب بشپړ;
	}

	إذا ((b64 = sshbuf_dup_string(sbuf)) == عدم) {
		error_f("sshbuf_dup_string failed");
		r = SSH_ERR_ALLOC_FAIL;
		اذهب بشپړ;
	}

	إذا ((buf = sshbuf_new()) == عدم) {
		error_f("sshbuf_new() failed");
		r = SSH_ERR_ALLOC_FAIL;
		اذهب بشپړ;
	}

	إذا ((r = sshbuf_b64tod(buf, b64)) != 0) {
		error_fr(r, "decode base64");
		اذهب بشپړ;
	}

	/* success */
	*بهر = buf;
	r = 0;
	buf = عدم; /* transferred */
بشپړ:
	sshbuf_free(buf);
	sshbuf_free(sbuf);
	حرر(b64);
	أرجع r;
}

ساكن صحيح
sshsig_wrap_sign(بنية sshkey *کلی, ثابت حرف *hashalg,
    ثابت حرف *sk_provider, ثابت حرف *sk_pin, ثابت بنية sshbuf *h_پیغام,
    ثابت حرف *sig_namespace, بنية sshbuf **بهر,
    sshsig_signer *signer, فراغ *signer_ctx)
{
	صحيح r;
	اندازه_t slen = 0;
	u_char *sig = عدم;
	بنية sshbuf *blob = عدم;
	بنية sshbuf *tosign = عدم;
	ثابت حرف *sign_alg = عدم;

	إذا ((tosign = sshbuf_new()) == عدم ||
	    (blob = sshbuf_new()) == عدم) {
		error_f("sshbuf_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		اذهب بشپړ;
	}

	إذا ((r = sshbuf_put(tosign, MAGIC_PREAMBLE, MAGIC_PREAMBLE_LEN)) != 0 ||
	    (r = sshbuf_put_cstring(tosign, sig_namespace)) != 0 ||
	    (r = sshbuf_put_string(tosign, عدم, 0)) != 0 || /* reserved */
	    (r = sshbuf_put_cstring(tosign, hashalg)) != 0 ||
	    (r = sshbuf_put_stringb(tosign, h_پیغام)) != 0) {
		error_fr(r, "assemble message to sign");
		اذهب بشپړ;
	}

	/* If using RSA keys then default to a good signature algorithm */
	إذا (sshkey_type_plain(کلی->type) == کلی_RSA) {
		sign_alg = RSA_SIGN_ALG;
		إذا (strcmp(hashalg, "sha256") == 0)
			sign_alg = "rsa-sha2-256";
		وإلا إذا (strcmp(hashalg, "sha512") == 0)
			sign_alg = "rsa-sha2-512";
	}

	إذا (signer != عدم) {
		إذا ((r = signer(کلی, &sig, &slen,
		    sshbuf_ptr(tosign), sshbuf_len(tosign),
		    sign_alg, sk_provider, sk_pin, 0, signer_ctx)) != 0) {
			error_r(r, "Couldn't sign message (signer)");
			اذهب بشپړ;
		}
	} وإلا {
		إذا ((r = sshkey_sign(کلی, &sig, &slen,
		    sshbuf_ptr(tosign), sshbuf_len(tosign),
		    sign_alg, sk_provider, sk_pin, 0)) != 0) {
			error_r(r, "Couldn't sign message");
			اذهب بشپړ;
		}
	}

	إذا ((r = sshbuf_put(blob, MAGIC_PREAMBLE, MAGIC_PREAMBLE_LEN)) != 0 ||
	    (r = sshbuf_put_u32(blob, SIG_نسخه)) != 0 ||
	    (r = sshkey_puts(کلی, blob)) != 0 ||
	    (r = sshbuf_put_cstring(blob, sig_namespace)) != 0 ||
	    (r = sshbuf_put_string(blob, عدم, 0)) != 0 || /* reserved */
	    (r = sshbuf_put_cstring(blob, hashalg)) != 0 ||
	    (r = sshbuf_put_string(blob, sig, slen)) != 0) {
		error_fr(r, "assemble signature object");
		اذهب بشپړ;
	}

	إذا (بهر != عدم) {
		*بهر = blob;
		blob = عدم;
	}
	r = 0;
بشپړ:
	حرر(sig);
	sshbuf_free(blob);
	sshbuf_free(tosign);
	أرجع r;
}

/* Check preamble and version. */
ساكن صحيح
sshsig_parse_preamble(بنية sshbuf *buf)
{
	صحيح r = SSH_ERR_دننی_ERROR;
	uint32_t sversion;

	إذا ((r = sshbuf_cmp(buf, 0, MAGIC_PREAMBLE, MAGIC_PREAMBLE_LEN)) != 0 ||
	    (r = sshbuf_consume(buf, (حجم(MAGIC_PREAMBLE)-1))) != 0 ||
	    (r = sshbuf_get_u32(buf, &sversion)) != 0) {
		error("Couldn't verify signature: invalid format");
		أرجع r;
	}

	إذا (sversion > SIG_نسخه) {
		error("Signature version %lu is larger than supported "
		    "version %u", (بینښه اوږد)sversion, SIG_نسخه);
		أرجع SSH_ERR_INVALID_FORMAT;
	}
	أرجع 0;
}

ساكن صحيح
sshsig_check_hashalg(ثابت حرف *hashalg)
{
	إذا (hashalg == عدم ||
	    سمون_نمونه_list(hashalg, HASHALG_ALLOWED, 0) == 1)
		أرجع 0;
	error_f("unsupported hash algorithm \"%.100s\"", hashalg);
	أرجع SSH_ERR_SIGN_ALG_UNSUPPORTED;
}

ساكن صحيح
sshsig_peek_hashalg(بنية sshbuf *signature, حرف **hashalgp)
{
	بنية sshbuf *buf = عدم;
	حرف *hashalg = عدم;
	صحيح r = SSH_ERR_دننی_ERROR;

	إذا (hashalgp != عدم)
		*hashalgp = عدم;
	إذا ((buf = sshbuf_fromb(signature)) == عدم)
		أرجع SSH_ERR_ALLOC_FAIL;
	إذا ((r = sshsig_parse_preamble(buf)) != 0)
		اذهب بشپړ;
	إذا ((r = sshbuf_get_string_مستقیم(buf, عدم, عدم)) != 0 ||
	    (r = sshbuf_get_string_مستقیم(buf, عدم, عدم)) != 0 ||
	    (r = sshbuf_get_string(buf, عدم, عدم)) != 0 ||
	    (r = sshbuf_get_cstring(buf, &hashalg, عدم)) != 0 ||
	    (r = sshbuf_get_string_مستقیم(buf, عدم, عدم)) != 0) {
		error_fr(r, "parse signature object");
		اذهب بشپړ;
	}

	/* success */
	r = 0;
	*hashalgp = hashalg;
	hashalg = عدم;
 بشپړ:
	حرر(hashalg);
	sshbuf_free(buf);
	أرجع r;
}

ساكن صحيح
sshsig_wrap_verify(بنية sshbuf *signature, ثابت حرف *hashalg,
    ثابت بنية sshbuf *h_پیغام, ثابت حرف *expect_namespace,
    بنية sshkey **sign_keyp, بنية sshkey_sig_details **sig_details)
{
	صحيح r = SSH_ERR_دننی_ERROR;
	بنية sshbuf *buf = عدم, *toverify = عدم;
	بنية sshkey *کلی = عدم;
	ثابت u_char *sig;
	حرف *got_namespace = عدم, *sigtype = عدم, *sig_hashalg = عدم;
	اندازه_t siglen;

	debug_f("verify message length %zu", sshbuf_len(h_پیغام));
	إذا (sig_details != عدم)
		*sig_details = عدم;
	إذا (sign_keyp != عدم)
		*sign_keyp = عدم;

	إذا ((toverify = sshbuf_new()) == عدم) {
		error_f("sshbuf_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		اذهب بشپړ;
	}
	إذا ((r = sshbuf_put(toverify, MAGIC_PREAMBLE,
	    MAGIC_PREAMBLE_LEN)) != 0 ||
	    (r = sshbuf_put_cstring(toverify, expect_namespace)) != 0 ||
	    (r = sshbuf_put_string(toverify, عدم, 0)) != 0 || /* reserved */
	    (r = sshbuf_put_cstring(toverify, hashalg)) != 0 ||
	    (r = sshbuf_put_stringb(toverify, h_پیغام)) != 0) {
		error_fr(r, "assemble message to verify");
		اذهب بشپړ;
	}

	إذا ((r = sshsig_parse_preamble(signature)) != 0)
		اذهب بشپړ;

	إذا ((r = sshkey_froms(signature, &کلی)) != 0 ||
	    (r = sshbuf_get_cstring(signature, &got_namespace, عدم)) != 0 ||
	    (r = sshbuf_get_string(signature, عدم, عدم)) != 0 ||
	    (r = sshbuf_get_cstring(signature, &sig_hashalg, عدم)) != 0 ||
	    (r = sshbuf_get_string_مستقیم(signature, &sig, &siglen)) != 0) {
		error_fr(r, "parse signature object");
		اذهب بشپړ;
	}

	إذا (sshbuf_len(signature) != 0) {
		error("Signature contains trailing data");
		r = SSH_ERR_INVALID_FORMAT;
		اذهب بشپړ;
	}

	إذا (strcmp(expect_namespace, got_namespace) != 0) {
		error("Couldn't verify signature: namespace does not match");
		debug_f("expected namespace \"%s\" received \"%s\"",
		    expect_namespace, got_namespace);
		r = SSH_ERR_SIGNATURE_INVALID;
		اذهب بشپړ;
	}
	إذا (strcmp(hashalg, sig_hashalg) != 0) {
		error("Couldn't verify signature: hash algorithm mismatch");
		debug_f("expected algorithm \"%s\" received \"%s\"",
		    hashalg, sig_hashalg);
		r = SSH_ERR_SIGNATURE_INVALID;
		اذهب بشپړ;
	}
	/* Ensure that RSA keys use an acceptable signature algorithm */
	إذا (sshkey_type_plain(کلی->type) == کلی_RSA) {
		إذا ((r = sshkey_get_sigtype(sig, siglen, &sigtype)) != 0) {
			error_r(r, "Couldn't verify signature: unable to get "
			    "signature type");
			اذهب بشپړ;
		}
		إذا (سمون_نمونه_list(sigtype, RSA_SIGN_ALLOWED, 0) != 1) {
			error("Couldn't verify signature: unsupported RSA "
			    "signature algorithm %s", sigtype);
			r = SSH_ERR_SIGN_ALG_UNSUPPORTED;
			اذهب بشپړ;
		}
	}
	إذا ((r = sshkey_verify(کلی, sig, siglen, sshbuf_ptr(toverify),
	    sshbuf_len(toverify), عدم, 0, sig_details)) != 0) {
		error_r(r, "Signature verification failed");
		اذهب بشپړ;
	}

	/* success */
	r = 0;
	إذا (sign_keyp != عدم) {
		*sign_keyp = کلی;
		کلی = عدم; /* transferred */
	}
بشپړ:
	حرر(got_namespace);
	حرر(sigtype);
	حرر(sig_hashalg);
	sshbuf_free(buf);
	sshbuf_free(toverify);
	sshkey_free(کلی);
	أرجع r;
}

ساكن صحيح
hash_بفر(ثابت بنية sshbuf *m, ثابت حرف *hashalg, بنية sshbuf **bp)
{
	حرف *hex, hash[SSH_DIGEST_MAX_اوږدتیا];
	صحيح alg, r = SSH_ERR_دننی_ERROR;
	بنية sshbuf *b = عدم;

	*bp = عدم;
	memset(hash, 0, حجم(hash));

	إذا ((r = sshsig_check_hashalg(hashalg)) != 0)
		أرجع r;
	إذا ((alg = ssh_digest_alg_by_name(hashalg)) == -1) {
		error_f("can't look up hash algorithm %s", hashalg);
		أرجع SSH_ERR_دننی_ERROR;
	}
	إذا ((r = ssh_digest_بفر(alg, m, hash, حجم(hash))) != 0) {
		error_fr(r, "ssh_digest_buffer");
		أرجع r;
	}
	إذا ((hex = tohex(hash, ssh_digest_بایټونه(alg))) != عدم) {
		debug3_f("final hash: %s", hex);
		freezero(hex, مزي_اوږدوالی(hex));
	}
	إذا ((b = sshbuf_new()) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب بهر;
	}
	إذا ((r = sshbuf_put(b, hash, ssh_digest_بایټونه(alg))) != 0) {
		error_fr(r, "sshbuf_put");
		اذهب بهر;
	}
	*bp = b;
	b = عدم; /* transferred */
	/* success */
	r = 0;
 بهر:
	sshbuf_free(b);
	explicit_bzero(hash, حجم(hash));
	أرجع r;
}

صحيح
sshsig_signb(بنية sshkey *کلی, ثابت حرف *hashalg,
    ثابت حرف *sk_provider, ثابت حرف *sk_pin,
    ثابت بنية sshbuf *پیغام_2, ثابت حرف *sig_namespace,
    بنية sshbuf **بهر, sshsig_signer *signer, فراغ *signer_ctx)
{
	بنية sshbuf *b = عدم;
	صحيح r = SSH_ERR_دننی_ERROR;

	إذا (hashalg == عدم)
		hashalg = HASHALG_DEFAULT;
	إذا (بهر != عدم)
		*بهر = عدم;
	إذا ((r = hash_بفر(پیغام_2, hashalg, &b)) != 0) {
		error_fr(r, "hash buffer");
		اذهب بهر;
	}
	إذا ((r = sshsig_wrap_sign(کلی, hashalg, sk_provider, sk_pin, b,
	    sig_namespace, بهر, signer, signer_ctx)) != 0)
		اذهب بهر;
	/* success */
	r = 0;
 بهر:
	sshbuf_free(b);
	أرجع r;
}

صحيح
sshsig_verifyb(بنية sshbuf *signature, ثابت بنية sshbuf *پیغام_2,
    ثابت حرف *expect_namespace, بنية sshkey **sign_keyp,
    بنية sshkey_sig_details **sig_details)
{
	بنية sshbuf *b = عدم;
	صحيح r = SSH_ERR_دننی_ERROR;
	حرف *hashalg = عدم;

	إذا (sig_details != عدم)
		*sig_details = عدم;
	إذا (sign_keyp != عدم)
		*sign_keyp = عدم;
	إذا ((r = sshsig_peek_hashalg(signature, &hashalg)) != 0)
		أرجع r;
	debug_f("signature made with hash \"%s\"", hashalg);
	إذا ((r = hash_بفر(پیغام_2, hashalg, &b)) != 0) {
		error_fr(r, "hash buffer");
		اذهب بهر;
	}
	إذا ((r = sshsig_wrap_verify(signature, hashalg, b, expect_namespace,
	    sign_keyp, sig_details)) != 0)
		اذهب بهر;
	/* success */
	r = 0;
 بهر:
	sshbuf_free(b);
	حرر(hashalg);
	أرجع r;
}

ساكن صحيح
hash_file(صحيح fd, ثابت حرف *hashalg, بنية sshbuf **bp)
{
	حرف *hex, rbuf[8192], hash[SSH_DIGEST_MAX_اوږدتیا];
	ssize_t n, ټول = 0;
	بنية ssh_digest_ctx *ctx = عدم;
	صحيح alg, oerrno, r = SSH_ERR_دننی_ERROR;
	بنية sshbuf *b = عدم;

	*bp = عدم;
	memset(hash, 0, حجم(hash));

	إذا ((r = sshsig_check_hashalg(hashalg)) != 0)
		أرجع r;
	إذا ((alg = ssh_digest_alg_by_name(hashalg)) == -1) {
		error_f("can't look up hash algorithm %s", hashalg);
		أرجع SSH_ERR_دننی_ERROR;
	}
	إذا ((ctx = ssh_digest_پیل(alg)) == عدم) {
		error_f("ssh_digest_start failed");
		أرجع SSH_ERR_دننی_ERROR;
	}
	لكل (;;) {
		إذا ((n = اقرأ(fd, rbuf, حجم(rbuf))) == -1) {
			إذا (errno == EINTR || errno == EAGAIN)
				استمر;
			oerrno = errno;
			error_f("read: %s", strerror(errno));
			errno = oerrno;
			r = SSH_ERR_SYSTEM_ERROR;
			اذهب بهر;
		} وإلا إذا (n == 0) {
			debug2_f("hashed %zu bytes", ټول);
			اكسر; /* EOF */
		}
		ټول += (اندازه_t)n;
		إذا ((r = ssh_digest_update(ctx, rbuf, (اندازه_t)n)) != 0) {
			error_fr(r, "ssh_digest_update");
			اذهب بهر;
		}
	}
	إذا ((r = ssh_digest_final(ctx, hash, حجم(hash))) != 0) {
		error_fr(r, "ssh_digest_final");
		اذهب بهر;
	}
	إذا ((hex = tohex(hash, ssh_digest_بایټونه(alg))) != عدم) {
		debug3_f("final hash: %s", hex);
		freezero(hex, مزي_اوږدوالی(hex));
	}
	إذا ((b = sshbuf_new()) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب بهر;
	}
	إذا ((r = sshbuf_put(b, hash, ssh_digest_بایټونه(alg))) != 0) {
		error_fr(r, "sshbuf_put");
		اذهب بهر;
	}
	*bp = b;
	b = عدم; /* transferred */
	/* success */
	r = 0;
 بهر:
	oerrno = errno;
	sshbuf_free(b);
	ssh_digest_free(ctx);
	explicit_bzero(hash, حجم(hash));
	errno = oerrno;
	أرجع r;
}

صحيح
sshsig_sign_fd(بنية sshkey *کلی, ثابت حرف *hashalg,
    ثابت حرف *sk_provider, ثابت حرف *sk_pin,
    صحيح fd, ثابت حرف *sig_namespace, بنية sshbuf **بهر,
    sshsig_signer *signer, فراغ *signer_ctx)
{
	بنية sshbuf *b = عدم;
	صحيح r = SSH_ERR_دننی_ERROR;

	إذا (hashalg == عدم)
		hashalg = HASHALG_DEFAULT;
	إذا (بهر != عدم)
		*بهر = عدم;
	إذا ((r = hash_file(fd, hashalg, &b)) != 0) {
		error_fr(r, "hash_file");
		أرجع r;
	}
	إذا ((r = sshsig_wrap_sign(کلی, hashalg, sk_provider, sk_pin, b,
	    sig_namespace, بهر, signer, signer_ctx)) != 0)
		اذهب بهر;
	/* success */
	r = 0;
 بهر:
	sshbuf_free(b);
	أرجع r;
}

صحيح
sshsig_verify_fd(بنية sshbuf *signature, صحيح fd,
    ثابت حرف *expect_namespace, بنية sshkey **sign_keyp,
    بنية sshkey_sig_details **sig_details)
{
	بنية sshbuf *b = عدم;
	صحيح r = SSH_ERR_دننی_ERROR;
	حرف *hashalg = عدم;

	إذا (sig_details != عدم)
		*sig_details = عدم;
	إذا (sign_keyp != عدم)
		*sign_keyp = عدم;
	إذا ((r = sshsig_peek_hashalg(signature, &hashalg)) != 0)
		أرجع r;
	debug_f("signature made with hash \"%s\"", hashalg);
	إذا ((r = hash_file(fd, hashalg, &b)) != 0) {
		error_fr(r, "hash_file");
		اذهب بهر;
	}
	إذا ((r = sshsig_wrap_verify(signature, hashalg, b, expect_namespace,
	    sign_keyp, sig_details)) != 0)
		اذهب بهر;
	/* success */
	r = 0;
 بهر:
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
sshsigopt_parse(ثابت حرف *opts, ثابت حرف *لار, u_long linenum,
    ثابت حرف **errstrp)
{
	بنية sshsigopt *ret;
	صحيح r;
	حرف *opt;
	ثابت حرف *errstr = عدم;

	إذا ((ret = حافظه_صفر_ورکړه(1, حجم(*ret))) == عدم)
		أرجع عدم;
	إذا (opts == عدم || *opts == '\0')
		أرجع ret; /* Empty options yields empty options :) */

	طالما (*opts && *opts != ' ' && *opts != '\t') {
		/* flag options */
		إذا ((r = opt_flag("cert-authority", 0, &opts)) != -1) {
			ret->ca = 1;
		} وإلا إذا (opt_سمون(&opts, "namespaces")) {
			إذا (ret->namespaces != عدم) {
				errstr = "multiple \"namespaces\" clauses";
				اذهب fail;
			}
			ret->namespaces = opt_dequote(&opts, &errstr);
			إذا (ret->namespaces == عدم)
				اذهب fail;
		} وإلا إذا (opt_سمون(&opts, "valid-after")) {
			إذا (ret->valid_after != 0) {
				errstr = "multiple \"valid-after\" clauses";
				اذهب fail;
			}
			إذا ((opt = opt_dequote(&opts, &errstr)) == عدم)
				اذهب fail;
			إذا (parse_absolute_وخت(opt, &ret->valid_after) != 0 ||
			    ret->valid_after == 0) {
				حرر(opt);
				errstr = "invalid \"valid-after\" time";
				اذهب fail;
			}
			حرر(opt);
		} وإلا إذا (opt_سمون(&opts, "valid-before")) {
			إذا (ret->valid_before != 0) {
				errstr = "multiple \"valid-before\" clauses";
				اذهب fail;
			}
			إذا ((opt = opt_dequote(&opts, &errstr)) == عدم)
				اذهب fail;
			إذا (parse_absolute_وخت(opt, &ret->valid_before) != 0 ||
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
		إذا (*opts == '\0' || *opts == ' ' || *opts == '\t')
			اكسر;		/* End of options. */
		/* Anything other than a comma is an unknown option */
		إذا (*opts != ',') {
			errstr = "unknown key option";
			اذهب fail;
		}
		opts++;
		إذا (*opts == '\0') {
			errstr = "unexpected end-of-options";
			اذهب fail;
		}
	}
	/* final consistency check */
	إذا (ret->valid_after != 0 && ret->valid_before != 0 &&
	    ret->valid_before <= ret->valid_after) {
		errstr = "\"valid-before\" time is before \"valid-after\"";
		اذهب fail;
	}
	/* success */
	أرجع ret;
 fail:
	إذا (errstrp != عدم)
		*errstrp = errstr;
	sshsigopt_free(ret);
	أرجع عدم;
}

فراغ
sshsigopt_free(بنية sshsigopt *opts)
{
	إذا (opts == عدم)
		أرجع;
	حرر(opts->namespaces);
	حرر(opts);
}

ساكن صحيح
parse_principals_کلی_and_options(ثابت حرف *لار, u_long linenum, حرف *کرښه,
    ثابت حرف *required_principal, حرف **principalsp, بنية sshkey **keyp,
    بنية sshsigopt **sigoptsp)
{
	حرف *opts = عدم, *tmp, *cp, *principals = عدم;
	ثابت حرف *reason = عدم;
	بنية sshsigopt *sigopts = عدم;
	بنية sshkey *کلی = عدم;
	صحيح r = SSH_ERR_دننی_ERROR;

	إذا (principalsp != عدم)
		*principalsp = عدم;
	إذا (sigoptsp != عدم)
		*sigoptsp = عدم;
	إذا (keyp != عدم)
		*keyp = عدم;

	cp = کرښه;
	cp = cp + strspn(cp, " \t\n\r"); /* skip leading whitespace */
	إذا (*cp == '#' || *cp == '\0')
		أرجع SSH_ERR_کلی_NOT_وموندل; /* blank or all-comment line */

	/* format: identity[,identity...] [option[,option...]] key */
	إذا ((tmp = strdelimw(&cp)) == عدم || cp == عدم) {
		error("%s:%lu: invalid line", لار, linenum);
		r = SSH_ERR_INVALID_FORMAT;
		اذهب بهر;
	}
	إذا ((principals = strdup(tmp)) == عدم) {
		error_f("strdup failed");
		r = SSH_ERR_ALLOC_FAIL;
		اذهب بهر;
	}
	/*
	 * Bail out early if we're looking for a particular principal and this
	 * line does not list it.
	 */
	إذا (required_principal != عدم) {
		إذا (سمون_نمونه_list(required_principal,
		    principals, 0) != 1) {
			/* principal didn't match */
			r = SSH_ERR_کلی_NOT_وموندل;
			اذهب بهر;
		}
		debug_f("%s:%lu: matched principal \"%s\"",
		    لار, linenum, required_principal);
	}

	إذا ((کلی = sshkey_new(کلی_UNSPEC)) == عدم) {
		error_f("sshkey_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		اذهب بهر;
	}
	إذا (sshkey_read(کلی, &cp) != 0) {
		/* no key? Check for options */
		opts = cp;
		إذا (sshkey_advance_past_options(&cp) != 0) {
			error("%s:%lu: invalid options", لار, linenum);
			r = SSH_ERR_INVALID_FORMAT;
			اذهب بهر;
		}
		إذا (cp == عدم || *cp == '\0') {
			error("%s:%lu: missing key", لار, linenum);
			r = SSH_ERR_INVALID_FORMAT;
			اذهب بهر;
		}
		*cp++ = '\0';
		skip_space(&cp);
		إذا (sshkey_read(کلی, &cp) != 0) {
			error("%s:%lu: invalid key", لار, linenum);
			r = SSH_ERR_INVALID_FORMAT;
			اذهب بهر;
		}
	}
	debug3("%s:%lu: options %s", لار, linenum, opts == عدم ? "" : opts);
	إذا ((sigopts = sshsigopt_parse(opts, لار, linenum, &reason)) == عدم) {
		error("%s:%lu: bad options: %s", لار, linenum, reason);
		r = SSH_ERR_INVALID_FORMAT;
		اذهب بهر;
	}
	/* success */
	إذا (principalsp != عدم) {
		*principalsp = principals;
		principals = عدم; /* transferred */
	}
	إذا (sigoptsp != عدم) {
		*sigoptsp = sigopts;
		sigopts = عدم; /* transferred */
	}
	إذا (keyp != عدم) {
		*keyp = کلی;
		کلی = عدم; /* transferred */
	}
	r = 0;
 بهر:
	حرر(principals);
	sshsigopt_free(sigopts);
	sshkey_free(کلی);
	أرجع r;
}

ساكن صحيح
cert_filter_principals(ثابت حرف *لار, u_long linenum,
    حرف **principalsp, ثابت بنية sshkey *cert, uint64_t verify_وخت)
{
	حرف *cp, *oprincipals, *principals;
	ثابت حرف *reason;
	بنية sshbuf *nprincipals;
	صحيح r = SSH_ERR_دننی_ERROR, success = 0;
	u_int i;

	oprincipals = principals = *principalsp;
	*principalsp = عدم;

	إذا ((nprincipals = sshbuf_new()) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب بهر;
	}

	طالما ((cp = strsep(&principals, ",")) != عدم && *cp != '\0') {
		/* Check certificate validity */
		إذا ((r = sshkey_cert_check_authority(cert, 0, 0, verify_وخت,
		    عدم, &reason)) != 0) {
			debug("%s:%lu: principal \"%s\" not authorized: %s",
			    لار, linenum, cp, reason);
			استمر;
		}
		/* Return all matching principal names from the cert */
		لكل (i = 0; i < cert->cert->nprincipals; i++) {
			إذا (سمون_نمونه(cert->cert->principals[i], cp)) {
				إذا ((r = sshbuf_putf(nprincipals, "%s%s",
					sshbuf_len(nprincipals) != 0 ? "," : "",
						cert->cert->principals[i])) != 0) {
					error_f("buffer error");
					اذهب بهر;
				}
			}
		}
	}
	إذا (sshbuf_len(nprincipals) == 0) {
		error("%s:%lu: no valid principals found", لار, linenum);
		r = SSH_ERR_کلی_CERT_INVALID;
		اذهب بهر;
	}
	إذا ((principals = sshbuf_dup_string(nprincipals)) == عدم) {
		error_f("buffer error");
		r = SSH_ERR_ALLOC_FAIL;
		اذهب بهر;
	}
	/* success */
	success = 1;
	*principalsp = principals;
 بهر:
	sshbuf_free(nprincipals);
	حرر(oprincipals);
	أرجع success ? 0 : r;
}

ساكن صحيح
check_allowed_کلیګانې_کرښه(ثابت حرف *لار, u_long linenum, حرف *کرښه,
    ثابت بنية sshkey *sign_کلی, ثابت حرف *principal,
    ثابت حرف *sig_namespace, uint64_t verify_وخت, حرف **principalsp)
{
	بنية sshkey *وموندل_کلی = عدم;
	حرف *principals = عدم;
	صحيح r, success = 0;
	ثابت حرف *reason = عدم;
	بنية sshsigopt *sigopts = عدم;
	حرف tvalid[64], tverify[64];

	إذا (principalsp != عدم)
		*principalsp = عدم;

	/* Parse the line */
	إذا ((r = parse_principals_کلی_and_options(لار, linenum, کرښه,
	    principal, &principals, &وموندل_کلی, &sigopts)) != 0) {
		/* error already logged */
		اذهب بشپړ;
	}

	إذا (!sigopts->ca && sshkey_equal(وموندل_کلی, sign_کلی)) {
		/* Exact match of key */
		debug("%s:%lu: matched key", لار, linenum);
	} وإلا إذا (sigopts->ca && sshkey_is_cert(sign_کلی) &&
	    sshkey_equal_عامه(sign_کلی->cert->signature_کلی, وموندل_کلی)) {
		إذا (principal) {
			/* Match certificate CA key with specified principal */
			إذا ((r = sshkey_cert_check_authority(sign_کلی, 0, 0,
			    verify_وخت, principal, &reason)) != 0) {
				error("%s:%lu: certificate not authorized: %s",
				    لار, linenum, reason);
				اذهب بشپړ;
			}
			debug("%s:%lu: matched certificate CA key",
			    لار, linenum);
		} وإلا {
			/* No principal specified - find all matching ones */
			إذا ((r = cert_filter_principals(لار, linenum,
			    &principals, sign_کلی, verify_وخت)) != 0) {
				/* error already displayed */
				debug_r(r, "%s:%lu: cert_filter_principals",
				    لار, linenum);
				اذهب بشپړ;
			}
			debug("%s:%lu: matched certificate CA key",
			    لار, linenum);
		}
	} وإلا {
		/* Didn't match key */
		اذهب بشپړ;
	}

	/* Check whether options preclude the use of this key */
	إذا (sigopts->namespaces != عدم && sig_namespace != عدم &&
	    سمون_نمونه_list(sig_namespace, sigopts->namespaces, 0) != 1) {
		error("%s:%lu: key is not permitted for use in signature "
		    "namespace \"%s\"", لار, linenum, sig_namespace);
		اذهب بشپړ;
	}

	/* check key time validity */
	format_absolute_وخت((uint64_t)verify_وخت, tverify, حجم(tverify));
	إذا (sigopts->valid_after != 0 &&
	    (uint64_t)verify_وخت < sigopts->valid_after) {
		format_absolute_وخت(sigopts->valid_after,
		    tvalid, حجم(tvalid));
		error("%s:%lu: key is not yet valid: "
		    "verify time %s < valid-after %s", لار, linenum,
		    tverify, tvalid);
		اذهب بشپړ;
	}
	إذا (sigopts->valid_before != 0 &&
	    (uint64_t)verify_وخت > sigopts->valid_before) {
		format_absolute_وخت(sigopts->valid_before,
		    tvalid, حجم(tvalid));
		error("%s:%lu: key has expired: "
		    "verify time %s > valid-before %s", لار, linenum,
		    tverify, tvalid);
		اذهب بشپړ;
	}
	success = 1;

 بشپړ:
	إذا (success && principalsp != عدم) {
		*principalsp = principals;
		principals = عدم; /* transferred */
	}
	حرر(principals);
	sshkey_free(وموندل_کلی);
	sshsigopt_free(sigopts);
	أرجع success ? 0 : SSH_ERR_کلی_NOT_وموندل;
}

صحيح
sshsig_check_allowed_کلیګانې(ثابت حرف *لار, ثابت بنية sshkey *sign_کلی,
    ثابت حرف *principal, ثابت حرف *sig_namespace, uint64_t verify_وخت)
{
	FILE *f = عدم;
	حرف *کرښه = عدم;
	اندازه_t linesize = 0;
	u_long linenum = 0;
	صحيح r = SSH_ERR_کلی_NOT_وموندل, oerrno;

	/* Check key and principal against file */
	إذا ((f = fopen(لار, "r")) == عدم) {
		oerrno = errno;
		error("Unable to open allowed keys file \"%s\": %s",
		    لار, strerror(errno));
		errno = oerrno;
		أرجع SSH_ERR_SYSTEM_ERROR;
	}

	طالما (getline(&کرښه, &linesize, f) != -1) {
		linenum++;
		r = check_allowed_کلیګانې_کرښه(لار, linenum, کرښه, sign_کلی,
		    principal, sig_namespace, verify_وخت, عدم);
		حرر(کرښه);
		کرښه = عدم;
		linesize = 0;
		إذا (r == SSH_ERR_کلی_NOT_وموندل)
			استمر;
		وإلا إذا (r == 0) {
			/* success */
			fclose(f);
			أرجع 0;
		} وإلا
			اكسر;
	}
	/* Either we hit an error parsing or we simply didn't find the key */
	fclose(f);
	حرر(کرښه);
	أرجع r;
}

صحيح
sshsig_پیدا_کړه_principals(ثابت حرف *لار, ثابت بنية sshkey *sign_کلی,
    uint64_t verify_وخت, حرف **principals)
{
	FILE *f = عدم;
	حرف *کرښه = عدم;
	اندازه_t linesize = 0;
	u_long linenum = 0;
	صحيح r = SSH_ERR_کلی_NOT_وموندل, oerrno;

	إذا ((f = fopen(لار, "r")) == عدم) {
		oerrno = errno;
		error("Unable to open allowed keys file \"%s\": %s",
		    لار, strerror(errno));
		errno = oerrno;
		أرجع SSH_ERR_SYSTEM_ERROR;
	}

	طالما (getline(&کرښه, &linesize, f) != -1) {
		linenum++;
		r = check_allowed_کلیګانې_کرښه(لار, linenum, کرښه,
		    sign_کلی, عدم, عدم, verify_وخت, principals);
		حرر(کرښه);
		کرښه = عدم;
		linesize = 0;
		إذا (r == SSH_ERR_کلی_NOT_وموندل)
			استمر;
		وإلا إذا (r == 0) {
			/* success */
			fclose(f);
			أرجع 0;
		} وإلا
			اكسر;
	}
	حرر(کرښه);
	/* Either we hit an error parsing or we simply didn't find the key */
	إذا (ferror(f) != 0) {
		oerrno = errno;
		fclose(f);
		error("Unable to read allowed keys file \"%s\": %s",
		    لار, strerror(errno));
		errno = oerrno;
		أرجع SSH_ERR_SYSTEM_ERROR;
	}
	fclose(f);
	أرجع r;
}

صحيح
sshsig_سمون_principals(ثابت حرف *لار, ثابت حرف *principal,
    حرف ***principalsp, اندازه_t *nprincipalsp)
{
	FILE *f = عدم;
	حرف *وموندل, *کرښه = عدم, **principals = عدم, **tmp;
	اندازه_t i, nprincipals = 0, linesize = 0;
	u_long linenum = 0;
	صحيح oerrno = 0, r, ret = 0;

	إذا (principalsp != عدم)
		*principalsp = عدم;
	إذا (nprincipalsp != عدم)
		*nprincipalsp = 0;

	/* Check key and principal against file */
	إذا ((f = fopen(لار, "r")) == عدم) {
		oerrno = errno;
		error("Unable to open allowed keys file \"%s\": %s",
		    لار, strerror(errno));
		errno = oerrno;
		أرجع SSH_ERR_SYSTEM_ERROR;
	}

	طالما (getline(&کرښه, &linesize, f) != -1) {
		linenum++;
		/* Parse the line */
		إذا ((r = parse_principals_کلی_and_options(لار, linenum, کرښه,
		    principal, &وموندل, عدم, عدم)) != 0) {
			إذا (r == SSH_ERR_کلی_NOT_وموندل)
				استمر;
			ret = r;
			oerrno = errno;
			اكسر; /* unexpected error */
		}
		إذا ((tmp = recallocarray(principals, nprincipals,
		    nprincipals + 1, حجم(*principals))) == عدم) {
			ret = SSH_ERR_ALLOC_FAIL;
			حرر(وموندل);
			اكسر;
		}
		principals = tmp;
		principals[nprincipals++] = وموندل; /* transferred */
		حرر(کرښه);
		کرښه = عدم;
		linesize = 0;
	}
	fclose(f);
	حرر(کرښه);

	إذا (ret == 0) {
		إذا (nprincipals == 0)
			ret = SSH_ERR_کلی_NOT_وموندل;
		إذا (nprincipalsp != عدم)
			*nprincipalsp = nprincipals;
		إذا (principalsp != عدم) {
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

	إذا (pubkey == عدم)
		أرجع SSH_ERR_دننی_ERROR;
	إذا ((r = sshsig_parse_preamble(signature)) != 0)
		أرجع r;
	إذا ((r = sshkey_froms(signature, &pk)) != 0)
		أرجع r;

	*pubkey = pk;
	pk = عدم;
	أرجع 0;
}
