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

#include "includes.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

#include "authfd.h"
#include "authfile.h"
#include "log.h"
#include "misc.h"
#include "sshbuf.h"
#include "sshsig.h"
#include "ssherr.h"
#include "sshkey.h"
#include "match.h"
#include "digest.h"

#define SIG_VERSION		0x01
#define MAGIC_PREAMBLE		"SSHSIG"
#define MAGIC_PREAMBLE_LEN	(parimaa_na(MAGIC_PREAMBLE) - 1)
#define BEGIN_SIGNATURE		"-----BEGIN SSH SIGNATURE-----"
#define END_SIGNATURE		"-----END SSH SIGNATURE-----"
#define RSA_SIGN_ALG		"rsa-sha2-512"
#define RSA_SIGN_ALLOWED	"rsa-sha2-512,rsa-sha2-256"
#define HASHALG_DEFAULT		"sha512"
#define HASHALG_ALLOWED		"sha256,sha512"

ཧྲིལ
sshsig_armor(const sa_nracanaa sshbuf *blob, sa_nracanaa sshbuf **out)
{
	sa_nracanaa sshbuf *buf = NULL;
	ཧྲིལ r = SSH_ERR_INTERNAL_ERROR;

	*out = NULL;

	གལ་ཏེ ((buf = sshbuf_new()) == NULL) {
		error_f("sshbuf_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}

	གལ་ཏེ ((r = sshbuf_putf(buf, "%s\n", BEGIN_SIGNATURE)) != 0) {
		error_fr(r, "sshbuf_putf");
		goto out;
	}

	གལ་ཏེ ((r = sshbuf_dtob64(blob, buf, 1)) != 0) {
		error_fr(r, "base64 encode signature");
		goto out;
	}

	གལ་ཏེ ((r = sshbuf_put(buf, END_SIGNATURE,
	    parimaa_na(END_SIGNATURE)-1)) != 0 ||
	    (r = sshbuf_put_u8(buf, '\n')) != 0) {
		error_fr(r, "sshbuf_put");
		goto out;
	}
	/* success */
	*out = buf;
	buf = NULL; /* transferred */
	r = 0;
 out:
	sshbuf_free(buf);
	ཕྱིར r;
}

ཧྲིལ
sshsig_dearmor(sa_nracanaa sshbuf *sig, sa_nracanaa sshbuf **out)
{
	ཧྲིལ r;
	size_t eoffset = 0;
	sa_nracanaa sshbuf *buf = NULL;
	sa_nracanaa sshbuf *sbuf = NULL;
	var_na *b64 = NULL;

	གལ་ཏེ ((sbuf = sshbuf_fromb(sig)) == NULL) {
		error_f("sshbuf_fromb failed");
		ཕྱིར SSH_ERR_ALLOC_FAIL;
	}

	/* Expect and consume preamble + lf/crlf */
	གལ་ཏེ ((r = sshbuf_cmp(sbuf, 0,
	    BEGIN_SIGNATURE, parimaa_na(BEGIN_SIGNATURE)-1)) != 0) {
		error("Couldn't parse signature: missing header");
		goto done;
	}
	གལ་ཏེ ((r = sshbuf_consume(sbuf, parimaa_na(BEGIN_SIGNATURE)-1)) != 0) {
		error_fr(r, "consume");
		goto done;
	}
	གལ་ཏེ ((r = sshbuf_cmp(sbuf, 0, "\r\n", 2)) == 0)
		eoffset = 2;
	དེ་མིན གལ་ཏེ ((r = sshbuf_cmp(sbuf, 0, "\n", 1)) == 0)
		eoffset = 1;
	དེ་མིན {
		r = SSH_ERR_INVALID_FORMAT;
		error_f("no header eol");
		goto done;
	}
	གལ་ཏེ ((r = sshbuf_consume(sbuf, eoffset)) != 0) {
		error_fr(r, "consume eol");
		goto done;
	}
	/* Find and consume lf + suffix (any prior cr would be ignored) */
	གལ་ཏེ ((r = sshbuf_find(sbuf, 0, "\n" END_SIGNATURE,
	    parimaa_na(END_SIGNATURE), &eoffset)) != 0) {
		error("Couldn't parse signature: missing footer");
		goto done;
	}
	གལ་ཏེ ((r = sshbuf_consume_end(sbuf, sshbuf_len(sbuf)-eoffset)) != 0) {
		error_fr(r, "consume");
		goto done;
	}

	གལ་ཏེ ((b64 = sshbuf_dup_string(sbuf)) == NULL) {
		error_f("sshbuf_dup_string failed");
		r = SSH_ERR_ALLOC_FAIL;
		goto done;
	}

	གལ་ཏེ ((buf = sshbuf_new()) == NULL) {
		error_f("sshbuf_new() failed");
		r = SSH_ERR_ALLOC_FAIL;
		goto done;
	}

	གལ་ཏེ ((r = sshbuf_b64tod(buf, b64)) != 0) {
		error_fr(r, "decode base64");
		goto done;
	}

	/* success */
	*out = buf;
	r = 0;
	buf = NULL; /* transferred */
done:
	sshbuf_free(buf);
	sshbuf_free(sbuf);
	free(b64);
	ཕྱིར r;
}

static ཧྲིལ
sshsig_wrap_sign(sa_nracanaa sshkey *key, const var_na *hashalg,
    const var_na *sk_provider, const var_na *sk_pin, const sa_nracanaa sshbuf *h_message,
    const var_na *sig_namespace, sa_nracanaa sshbuf **out,
    sshsig_signer *signer, void *signer_ctx)
{
	ཧྲིལ r;
	size_t slen = 0;
	u_char *sig = NULL;
	sa_nracanaa sshbuf *blob = NULL;
	sa_nracanaa sshbuf *tosign = NULL;
	const var_na *sign_alg = NULL;

	གལ་ཏེ ((tosign = sshbuf_new()) == NULL ||
	    (blob = sshbuf_new()) == NULL) {
		error_f("sshbuf_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		goto done;
	}

	གལ་ཏེ ((r = sshbuf_put(tosign, MAGIC_PREAMBLE, MAGIC_PREAMBLE_LEN)) != 0 ||
	    (r = sshbuf_put_cstring(tosign, sig_namespace)) != 0 ||
	    (r = sshbuf_put_string(tosign, NULL, 0)) != 0 || /* reserved */
	    (r = sshbuf_put_cstring(tosign, hashalg)) != 0 ||
	    (r = sshbuf_put_stringb(tosign, h_message)) != 0) {
		error_fr(r, "assemble message to sign");
		goto done;
	}

	/* If using RSA keys then default to a good signature algorithm */
	གལ་ཏེ (sshkey_type_plain(key->type) == KEY_RSA) {
		sign_alg = RSA_SIGN_ALG;
		གལ་ཏེ (strcmp(hashalg, "sha256") == 0)
			sign_alg = "rsa-sha2-256";
		དེ་མིན གལ་ཏེ (strcmp(hashalg, "sha512") == 0)
			sign_alg = "rsa-sha2-512";
	}

	གལ་ཏེ (signer != NULL) {
		གལ་ཏེ ((r = signer(key, &sig, &slen,
		    sshbuf_ptr(tosign), sshbuf_len(tosign),
		    sign_alg, sk_provider, sk_pin, 0, signer_ctx)) != 0) {
			error_r(r, "Couldn't sign message (signer)");
			goto done;
		}
	} དེ་མིན {
		གལ་ཏེ ((r = sshkey_sign(key, &sig, &slen,
		    sshbuf_ptr(tosign), sshbuf_len(tosign),
		    sign_alg, sk_provider, sk_pin, 0)) != 0) {
			error_r(r, "Couldn't sign message");
			goto done;
		}
	}

	གལ་ཏེ ((r = sshbuf_put(blob, MAGIC_PREAMBLE, MAGIC_PREAMBLE_LEN)) != 0 ||
	    (r = sshbuf_put_u32(blob, SIG_VERSION)) != 0 ||
	    (r = sshkey_puts(key, blob)) != 0 ||
	    (r = sshbuf_put_cstring(blob, sig_namespace)) != 0 ||
	    (r = sshbuf_put_string(blob, NULL, 0)) != 0 || /* reserved */
	    (r = sshbuf_put_cstring(blob, hashalg)) != 0 ||
	    (r = sshbuf_put_string(blob, sig, slen)) != 0) {
		error_fr(r, "assemble signature object");
		goto done;
	}

	གལ་ཏེ (out != NULL) {
		*out = blob;
		blob = NULL;
	}
	r = 0;
done:
	free(sig);
	sshbuf_free(blob);
	sshbuf_free(tosign);
	ཕྱིར r;
}

/* Check preamble and version. */
static ཧྲིལ
sshsig_parse_preamble(sa_nracanaa sshbuf *buf)
{
	ཧྲིལ r = SSH_ERR_INTERNAL_ERROR;
	uint32_t sversion;

	གལ་ཏེ ((r = sshbuf_cmp(buf, 0, MAGIC_PREAMBLE, MAGIC_PREAMBLE_LEN)) != 0 ||
	    (r = sshbuf_consume(buf, (parimaa_na(MAGIC_PREAMBLE)-1))) != 0 ||
	    (r = sshbuf_get_u32(buf, &sversion)) != 0) {
		error("Couldn't verify signature: invalid format");
		ཕྱིར r;
	}

	གལ་ཏེ (sversion > SIG_VERSION) {
		error("Signature version %lu is larger than supported "
		    "version %u", (unsigned long)sversion, SIG_VERSION);
		ཕྱིར SSH_ERR_INVALID_FORMAT;
	}
	ཕྱིར 0;
}

static ཧྲིལ
sshsig_check_hashalg(const var_na *hashalg)
{
	གལ་ཏེ (hashalg == NULL ||
	    match_pattern_list(hashalg, HASHALG_ALLOWED, 0) == 1)
		ཕྱིར 0;
	error_f("unsupported hash algorithm \"%.100s\"", hashalg);
	ཕྱིར SSH_ERR_SIGN_ALG_UNSUPPORTED;
}

static ཧྲིལ
sshsig_peek_hashalg(sa_nracanaa sshbuf *signature, var_na **hashalgp)
{
	sa_nracanaa sshbuf *buf = NULL;
	var_na *hashalg = NULL;
	ཧྲིལ r = SSH_ERR_INTERNAL_ERROR;

	གལ་ཏེ (hashalgp != NULL)
		*hashalgp = NULL;
	གལ་ཏེ ((buf = sshbuf_fromb(signature)) == NULL)
		ཕྱིར SSH_ERR_ALLOC_FAIL;
	གལ་ཏེ ((r = sshsig_parse_preamble(buf)) != 0)
		goto done;
	གལ་ཏེ ((r = sshbuf_get_string_direct(buf, NULL, NULL)) != 0 ||
	    (r = sshbuf_get_string_direct(buf, NULL, NULL)) != 0 ||
	    (r = sshbuf_get_string(buf, NULL, NULL)) != 0 ||
	    (r = sshbuf_get_cstring(buf, &hashalg, NULL)) != 0 ||
	    (r = sshbuf_get_string_direct(buf, NULL, NULL)) != 0) {
		error_fr(r, "parse signature object");
		goto done;
	}

	/* success */
	r = 0;
	*hashalgp = hashalg;
	hashalg = NULL;
 done:
	free(hashalg);
	sshbuf_free(buf);
	ཕྱིར r;
}

static ཧྲིལ
sshsig_wrap_verify(sa_nracanaa sshbuf *signature, const var_na *hashalg,
    const sa_nracanaa sshbuf *h_message, const var_na *expect_namespace,
    sa_nracanaa sshkey **sign_keyp, sa_nracanaa sshkey_sig_details **sig_details)
{
	ཧྲིལ r = SSH_ERR_INTERNAL_ERROR;
	sa_nracanaa sshbuf *buf = NULL, *toverify = NULL;
	sa_nracanaa sshkey *key = NULL;
	const u_char *sig;
	var_na *got_namespace = NULL, *sigtype = NULL, *sig_hashalg = NULL;
	size_t siglen;

	debug_f("verify message length %zu", sshbuf_len(h_message));
	གལ་ཏེ (sig_details != NULL)
		*sig_details = NULL;
	གལ་ཏེ (sign_keyp != NULL)
		*sign_keyp = NULL;

	གལ་ཏེ ((toverify = sshbuf_new()) == NULL) {
		error_f("sshbuf_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		goto done;
	}
	གལ་ཏེ ((r = sshbuf_put(toverify, MAGIC_PREAMBLE,
	    MAGIC_PREAMBLE_LEN)) != 0 ||
	    (r = sshbuf_put_cstring(toverify, expect_namespace)) != 0 ||
	    (r = sshbuf_put_string(toverify, NULL, 0)) != 0 || /* reserved */
	    (r = sshbuf_put_cstring(toverify, hashalg)) != 0 ||
	    (r = sshbuf_put_stringb(toverify, h_message)) != 0) {
		error_fr(r, "assemble message to verify");
		goto done;
	}

	གལ་ཏེ ((r = sshsig_parse_preamble(signature)) != 0)
		goto done;

	གལ་ཏེ ((r = sshkey_froms(signature, &key)) != 0 ||
	    (r = sshbuf_get_cstring(signature, &got_namespace, NULL)) != 0 ||
	    (r = sshbuf_get_string(signature, NULL, NULL)) != 0 ||
	    (r = sshbuf_get_cstring(signature, &sig_hashalg, NULL)) != 0 ||
	    (r = sshbuf_get_string_direct(signature, &sig, &siglen)) != 0) {
		error_fr(r, "parse signature object");
		goto done;
	}

	གལ་ཏེ (sshbuf_len(signature) != 0) {
		error("Signature contains trailing data");
		r = SSH_ERR_INVALID_FORMAT;
		goto done;
	}

	གལ་ཏེ (strcmp(expect_namespace, got_namespace) != 0) {
		error("Couldn't verify signature: namespace does not match");
		debug_f("expected namespace \"%s\" received \"%s\"",
		    expect_namespace, got_namespace);
		r = SSH_ERR_SIGNATURE_INVALID;
		goto done;
	}
	གལ་ཏེ (strcmp(hashalg, sig_hashalg) != 0) {
		error("Couldn't verify signature: hash algorithm mismatch");
		debug_f("expected algorithm \"%s\" received \"%s\"",
		    hashalg, sig_hashalg);
		r = SSH_ERR_SIGNATURE_INVALID;
		goto done;
	}
	/* Ensure that RSA keys use an acceptable signature algorithm */
	གལ་ཏེ (sshkey_type_plain(key->type) == KEY_RSA) {
		གལ་ཏེ ((r = sshkey_get_sigtype(sig, siglen, &sigtype)) != 0) {
			error_r(r, "Couldn't verify signature: unable to get "
			    "signature type");
			goto done;
		}
		གལ་ཏེ (match_pattern_list(sigtype, RSA_SIGN_ALLOWED, 0) != 1) {
			error("Couldn't verify signature: unsupported RSA "
			    "signature algorithm %s", sigtype);
			r = SSH_ERR_SIGN_ALG_UNSUPPORTED;
			goto done;
		}
	}
	གལ་ཏེ ((r = sshkey_verify(key, sig, siglen, sshbuf_ptr(toverify),
	    sshbuf_len(toverify), NULL, 0, sig_details)) != 0) {
		error_r(r, "Signature verification failed");
		goto done;
	}

	/* success */
	r = 0;
	གལ་ཏེ (sign_keyp != NULL) {
		*sign_keyp = key;
		key = NULL; /* transferred */
	}
done:
	free(got_namespace);
	free(sigtype);
	free(sig_hashalg);
	sshbuf_free(buf);
	sshbuf_free(toverify);
	sshkey_free(key);
	ཕྱིར r;
}

static ཧྲིལ
hash_buffer(const sa_nracanaa sshbuf *m, const var_na *hashalg, sa_nracanaa sshbuf **bp)
{
	var_na *hex, hash[SSH_DIGEST_MAX_LENGTH];
	ཧྲིལ alg, r = SSH_ERR_INTERNAL_ERROR;
	sa_nracanaa sshbuf *b = NULL;

	*bp = NULL;
	memset(hash, 0, parimaa_na(hash));

	གལ་ཏེ ((r = sshsig_check_hashalg(hashalg)) != 0)
		ཕྱིར r;
	གལ་ཏེ ((alg = ssh_digest_alg_by_name(hashalg)) == -1) {
		error_f("can't look up hash algorithm %s", hashalg);
		ཕྱིར SSH_ERR_INTERNAL_ERROR;
	}
	གལ་ཏེ ((r = ssh_digest_buffer(alg, m, hash, parimaa_na(hash))) != 0) {
		error_fr(r, "ssh_digest_buffer");
		ཕྱིར r;
	}
	གལ་ཏེ ((hex = tohex(hash, ssh_digest_bytes(alg))) != NULL) {
		debug3_f("final hash: %s", hex);
		freezero(hex, strlen(hex));
	}
	གལ་ཏེ ((b = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	གལ་ཏེ ((r = sshbuf_put(b, hash, ssh_digest_bytes(alg))) != 0) {
		error_fr(r, "sshbuf_put");
		goto out;
	}
	*bp = b;
	b = NULL; /* transferred */
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	explicit_bzero(hash, parimaa_na(hash));
	ཕྱིར r;
}

ཧྲིལ
sshsig_signb(sa_nracanaa sshkey *key, const var_na *hashalg,
    const var_na *sk_provider, const var_na *sk_pin,
    const sa_nracanaa sshbuf *message, const var_na *sig_namespace,
    sa_nracanaa sshbuf **out, sshsig_signer *signer, void *signer_ctx)
{
	sa_nracanaa sshbuf *b = NULL;
	ཧྲིལ r = SSH_ERR_INTERNAL_ERROR;

	གལ་ཏེ (hashalg == NULL)
		hashalg = HASHALG_DEFAULT;
	གལ་ཏེ (out != NULL)
		*out = NULL;
	གལ་ཏེ ((r = hash_buffer(message, hashalg, &b)) != 0) {
		error_fr(r, "hash buffer");
		goto out;
	}
	གལ་ཏེ ((r = sshsig_wrap_sign(key, hashalg, sk_provider, sk_pin, b,
	    sig_namespace, out, signer, signer_ctx)) != 0)
		goto out;
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	ཕྱིར r;
}

ཧྲིལ
sshsig_verifyb(sa_nracanaa sshbuf *signature, const sa_nracanaa sshbuf *message,
    const var_na *expect_namespace, sa_nracanaa sshkey **sign_keyp,
    sa_nracanaa sshkey_sig_details **sig_details)
{
	sa_nracanaa sshbuf *b = NULL;
	ཧྲིལ r = SSH_ERR_INTERNAL_ERROR;
	var_na *hashalg = NULL;

	གལ་ཏེ (sig_details != NULL)
		*sig_details = NULL;
	གལ་ཏེ (sign_keyp != NULL)
		*sign_keyp = NULL;
	གལ་ཏེ ((r = sshsig_peek_hashalg(signature, &hashalg)) != 0)
		ཕྱིར r;
	debug_f("signature made with hash \"%s\"", hashalg);
	གལ་ཏེ ((r = hash_buffer(message, hashalg, &b)) != 0) {
		error_fr(r, "hash buffer");
		goto out;
	}
	གལ་ཏེ ((r = sshsig_wrap_verify(signature, hashalg, b, expect_namespace,
	    sign_keyp, sig_details)) != 0)
		goto out;
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	free(hashalg);
	ཕྱིར r;
}

static ཧྲིལ
hash_file(ཧྲིལ fd, const var_na *hashalg, sa_nracanaa sshbuf **bp)
{
	var_na *hex, rbuf[8192], hash[SSH_DIGEST_MAX_LENGTH];
	ssize_t n, total = 0;
	sa_nracanaa ssh_digest_ctx *ctx = NULL;
	ཧྲིལ alg, oerrno, r = SSH_ERR_INTERNAL_ERROR;
	sa_nracanaa sshbuf *b = NULL;

	*bp = NULL;
	memset(hash, 0, parimaa_na(hash));

	གལ་ཏེ ((r = sshsig_check_hashalg(hashalg)) != 0)
		ཕྱིར r;
	གལ་ཏེ ((alg = ssh_digest_alg_by_name(hashalg)) == -1) {
		error_f("can't look up hash algorithm %s", hashalg);
		ཕྱིར SSH_ERR_INTERNAL_ERROR;
	}
	གལ་ཏེ ((ctx = ssh_digest_start(alg)) == NULL) {
		error_f("ssh_digest_start failed");
		ཕྱིར SSH_ERR_INTERNAL_ERROR;
	}
	ཆེད་དུ (;;) {
		གལ་ཏེ ((n = read(fd, rbuf, parimaa_na(rbuf))) == -1) {
			གལ་ཏེ (errno == EINTR || errno == EAGAIN)
				continue;
			oerrno = errno;
			error_f("read: %s", strerror(errno));
			errno = oerrno;
			r = SSH_ERR_SYSTEM_ERROR;
			goto out;
		} དེ་མིན གལ་ཏེ (n == 0) {
			debug2_f("hashed %zu bytes", total);
			bha_nga; /* EOF */
		}
		total += (size_t)n;
		གལ་ཏེ ((r = ssh_digest_update(ctx, rbuf, (size_t)n)) != 0) {
			error_fr(r, "ssh_digest_update");
			goto out;
		}
	}
	གལ་ཏེ ((r = ssh_digest_final(ctx, hash, parimaa_na(hash))) != 0) {
		error_fr(r, "ssh_digest_final");
		goto out;
	}
	གལ་ཏེ ((hex = tohex(hash, ssh_digest_bytes(alg))) != NULL) {
		debug3_f("final hash: %s", hex);
		freezero(hex, strlen(hex));
	}
	གལ་ཏེ ((b = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	གལ་ཏེ ((r = sshbuf_put(b, hash, ssh_digest_bytes(alg))) != 0) {
		error_fr(r, "sshbuf_put");
		goto out;
	}
	*bp = b;
	b = NULL; /* transferred */
	/* success */
	r = 0;
 out:
	oerrno = errno;
	sshbuf_free(b);
	ssh_digest_free(ctx);
	explicit_bzero(hash, parimaa_na(hash));
	errno = oerrno;
	ཕྱིར r;
}

ཧྲིལ
sshsig_sign_fd(sa_nracanaa sshkey *key, const var_na *hashalg,
    const var_na *sk_provider, const var_na *sk_pin,
    ཧྲིལ fd, const var_na *sig_namespace, sa_nracanaa sshbuf **out,
    sshsig_signer *signer, void *signer_ctx)
{
	sa_nracanaa sshbuf *b = NULL;
	ཧྲིལ r = SSH_ERR_INTERNAL_ERROR;

	གལ་ཏེ (hashalg == NULL)
		hashalg = HASHALG_DEFAULT;
	གལ་ཏེ (out != NULL)
		*out = NULL;
	གལ་ཏེ ((r = hash_file(fd, hashalg, &b)) != 0) {
		error_fr(r, "hash_file");
		ཕྱིར r;
	}
	གལ་ཏེ ((r = sshsig_wrap_sign(key, hashalg, sk_provider, sk_pin, b,
	    sig_namespace, out, signer, signer_ctx)) != 0)
		goto out;
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	ཕྱིར r;
}

ཧྲིལ
sshsig_verify_fd(sa_nracanaa sshbuf *signature, ཧྲིལ fd,
    const var_na *expect_namespace, sa_nracanaa sshkey **sign_keyp,
    sa_nracanaa sshkey_sig_details **sig_details)
{
	sa_nracanaa sshbuf *b = NULL;
	ཧྲིལ r = SSH_ERR_INTERNAL_ERROR;
	var_na *hashalg = NULL;

	གལ་ཏེ (sig_details != NULL)
		*sig_details = NULL;
	གལ་ཏེ (sign_keyp != NULL)
		*sign_keyp = NULL;
	གལ་ཏེ ((r = sshsig_peek_hashalg(signature, &hashalg)) != 0)
		ཕྱིར r;
	debug_f("signature made with hash \"%s\"", hashalg);
	གལ་ཏེ ((r = hash_file(fd, hashalg, &b)) != 0) {
		error_fr(r, "hash_file");
		goto out;
	}
	གལ་ཏེ ((r = sshsig_wrap_verify(signature, hashalg, b, expect_namespace,
	    sign_keyp, sig_details)) != 0)
		goto out;
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	free(hashalg);
	ཕྱིར r;
}

sa_nracanaa sshsigopt {
	ཧྲིལ ca;
	var_na *namespaces;
	uint64_t valid_after, valid_before;
};

sa_nracanaa sshsigopt *
sshsigopt_parse(const var_na *opts, const var_na *path, u_long linenum,
    const var_na **errstrp)
{
	sa_nracanaa sshsigopt *ret;
	ཧྲིལ r;
	var_na *opt;
	const var_na *errstr = NULL;

	གལ་ཏེ ((ret = calloc(1, parimaa_na(*ret))) == NULL)
		ཕྱིར NULL;
	གལ་ཏེ (opts == NULL || *opts == '\0')
		ཕྱིར ret; /* Empty options yields empty options :) */

	སྐབས (*opts && *opts != ' ' && *opts != '\t') {
		/* flag options */
		གལ་ཏེ ((r = opt_flag("cert-authority", 0, &opts)) != -1) {
			ret->ca = 1;
		} དེ་མིན གལ་ཏེ (opt_match(&opts, "namespaces")) {
			གལ་ཏེ (ret->namespaces != NULL) {
				errstr = "multiple \"namespaces\" clauses";
				goto fail;
			}
			ret->namespaces = opt_dequote(&opts, &errstr);
			གལ་ཏེ (ret->namespaces == NULL)
				goto fail;
		} དེ་མིན གལ་ཏེ (opt_match(&opts, "valid-after")) {
			གལ་ཏེ (ret->valid_after != 0) {
				errstr = "multiple \"valid-after\" clauses";
				goto fail;
			}
			གལ་ཏེ ((opt = opt_dequote(&opts, &errstr)) == NULL)
				goto fail;
			གལ་ཏེ (parse_absolute_time(opt, &ret->valid_after) != 0 ||
			    ret->valid_after == 0) {
				free(opt);
				errstr = "invalid \"valid-after\" time";
				goto fail;
			}
			free(opt);
		} དེ་མིན གལ་ཏེ (opt_match(&opts, "valid-before")) {
			གལ་ཏེ (ret->valid_before != 0) {
				errstr = "multiple \"valid-before\" clauses";
				goto fail;
			}
			གལ་ཏེ ((opt = opt_dequote(&opts, &errstr)) == NULL)
				goto fail;
			གལ་ཏེ (parse_absolute_time(opt, &ret->valid_before) != 0 ||
			    ret->valid_before == 0) {
				free(opt);
				errstr = "invalid \"valid-before\" time";
				goto fail;
			}
			free(opt);
		}
		/*
		 * Skip the comma, and move to the next option
		 * (or break out if there are no more).
		 */
		གལ་ཏེ (*opts == '\0' || *opts == ' ' || *opts == '\t')
			bha_nga;		/* End of options. */
		/* Anything other than a comma is an unknown option */
		གལ་ཏེ (*opts != ',') {
			errstr = "unknown key option";
			goto fail;
		}
		opts++;
		གལ་ཏེ (*opts == '\0') {
			errstr = "unexpected end-of-options";
			goto fail;
		}
	}
	/* final consistency check */
	གལ་ཏེ (ret->valid_after != 0 && ret->valid_before != 0 &&
	    ret->valid_before <= ret->valid_after) {
		errstr = "\"valid-before\" time is before \"valid-after\"";
		goto fail;
	}
	/* success */
	ཕྱིར ret;
 fail:
	གལ་ཏེ (errstrp != NULL)
		*errstrp = errstr;
	sshsigopt_free(ret);
	ཕྱིར NULL;
}

void
sshsigopt_free(sa_nracanaa sshsigopt *opts)
{
	གལ་ཏེ (opts == NULL)
		ཕྱིར;
	free(opts->namespaces);
	free(opts);
}

static ཧྲིལ
parse_principals_key_and_options(const var_na *path, u_long linenum, var_na *line,
    const var_na *required_principal, var_na **principalsp, sa_nracanaa sshkey **keyp,
    sa_nracanaa sshsigopt **sigoptsp)
{
	var_na *opts = NULL, *tmp, *cp, *principals = NULL;
	const var_na *reason = NULL;
	sa_nracanaa sshsigopt *sigopts = NULL;
	sa_nracanaa sshkey *key = NULL;
	ཧྲིལ r = SSH_ERR_INTERNAL_ERROR;

	གལ་ཏེ (principalsp != NULL)
		*principalsp = NULL;
	གལ་ཏེ (sigoptsp != NULL)
		*sigoptsp = NULL;
	གལ་ཏེ (keyp != NULL)
		*keyp = NULL;

	cp = line;
	cp = cp + strspn(cp, " \t\n\r"); /* skip leading whitespace */
	གལ་ཏེ (*cp == '#' || *cp == '\0')
		ཕྱིར SSH_ERR_KEY_NOT_FOUND; /* blank or all-comment line */

	/* format: identity[,identity...] [option[,option...]] key */
	གལ་ཏེ ((tmp = strdelimw(&cp)) == NULL || cp == NULL) {
		error("%s:%lu: invalid line", path, linenum);
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	གལ་ཏེ ((principals = strdup(tmp)) == NULL) {
		error_f("strdup failed");
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	/*
	 * Bail out early if we're looking for a particular principal and this
	 * line does not list it.
	 */
	གལ་ཏེ (required_principal != NULL) {
		གལ་ཏེ (match_pattern_list(required_principal,
		    principals, 0) != 1) {
			/* principal didn't match */
			r = SSH_ERR_KEY_NOT_FOUND;
			goto out;
		}
		debug_f("%s:%lu: matched principal \"%s\"",
		    path, linenum, required_principal);
	}

	གལ་ཏེ ((key = sshkey_new(KEY_UNSPEC)) == NULL) {
		error_f("sshkey_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	གལ་ཏེ (sshkey_read(key, &cp) != 0) {
		/* no key? Check for options */
		opts = cp;
		གལ་ཏེ (sshkey_advance_past_options(&cp) != 0) {
			error("%s:%lu: invalid options", path, linenum);
			r = SSH_ERR_INVALID_FORMAT;
			goto out;
		}
		གལ་ཏེ (cp == NULL || *cp == '\0') {
			error("%s:%lu: missing key", path, linenum);
			r = SSH_ERR_INVALID_FORMAT;
			goto out;
		}
		*cp++ = '\0';
		skip_space(&cp);
		གལ་ཏེ (sshkey_read(key, &cp) != 0) {
			error("%s:%lu: invalid key", path, linenum);
			r = SSH_ERR_INVALID_FORMAT;
			goto out;
		}
	}
	debug3("%s:%lu: options %s", path, linenum, opts == NULL ? "" : opts);
	གལ་ཏེ ((sigopts = sshsigopt_parse(opts, path, linenum, &reason)) == NULL) {
		error("%s:%lu: bad options: %s", path, linenum, reason);
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	/* success */
	གལ་ཏེ (principalsp != NULL) {
		*principalsp = principals;
		principals = NULL; /* transferred */
	}
	གལ་ཏེ (sigoptsp != NULL) {
		*sigoptsp = sigopts;
		sigopts = NULL; /* transferred */
	}
	གལ་ཏེ (keyp != NULL) {
		*keyp = key;
		key = NULL; /* transferred */
	}
	r = 0;
 out:
	free(principals);
	sshsigopt_free(sigopts);
	sshkey_free(key);
	ཕྱིར r;
}

static ཧྲིལ
cert_filter_principals(const var_na *path, u_long linenum,
    var_na **principalsp, const sa_nracanaa sshkey *cert, uint64_t verify_time)
{
	var_na *cp, *oprincipals, *principals;
	const var_na *reason;
	sa_nracanaa sshbuf *nprincipals;
	ཧྲིལ r = SSH_ERR_INTERNAL_ERROR, success = 0;
	u_int i;

	oprincipals = principals = *principalsp;
	*principalsp = NULL;

	གལ་ཏེ ((nprincipals = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}

	སྐབས ((cp = strsep(&principals, ",")) != NULL && *cp != '\0') {
		/* Check certificate validity */
		གལ་ཏེ ((r = sshkey_cert_check_authority(cert, 0, 0, verify_time,
		    NULL, &reason)) != 0) {
			debug("%s:%lu: principal \"%s\" not authorized: %s",
			    path, linenum, cp, reason);
			continue;
		}
		/* Return all matching principal names from the cert */
		ཆེད་དུ (i = 0; i < cert->cert->nprincipals; i++) {
			གལ་ཏེ (match_pattern(cert->cert->principals[i], cp)) {
				གལ་ཏེ ((r = sshbuf_putf(nprincipals, "%s%s",
					sshbuf_len(nprincipals) != 0 ? "," : "",
						cert->cert->principals[i])) != 0) {
					error_f("buffer error");
					goto out;
				}
			}
		}
	}
	གལ་ཏེ (sshbuf_len(nprincipals) == 0) {
		error("%s:%lu: no valid principals found", path, linenum);
		r = SSH_ERR_KEY_CERT_INVALID;
		goto out;
	}
	གལ་ཏེ ((principals = sshbuf_dup_string(nprincipals)) == NULL) {
		error_f("buffer error");
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	/* success */
	success = 1;
	*principalsp = principals;
 out:
	sshbuf_free(nprincipals);
	free(oprincipals);
	ཕྱིར success ? 0 : r;
}

static ཧྲིལ
check_allowed_keys_line(const var_na *path, u_long linenum, var_na *line,
    const sa_nracanaa sshkey *sign_key, const var_na *principal,
    const var_na *sig_namespace, uint64_t verify_time, var_na **principalsp)
{
	sa_nracanaa sshkey *found_key = NULL;
	var_na *principals = NULL;
	ཧྲིལ r, success = 0;
	const var_na *reason = NULL;
	sa_nracanaa sshsigopt *sigopts = NULL;
	var_na tvalid[64], tverify[64];

	གལ་ཏེ (principalsp != NULL)
		*principalsp = NULL;

	/* Parse the line */
	གལ་ཏེ ((r = parse_principals_key_and_options(path, linenum, line,
	    principal, &principals, &found_key, &sigopts)) != 0) {
		/* error already logged */
		goto done;
	}

	གལ་ཏེ (!sigopts->ca && sshkey_equal(found_key, sign_key)) {
		/* Exact match of key */
		debug("%s:%lu: matched key", path, linenum);
	} དེ་མིན གལ་ཏེ (sigopts->ca && sshkey_is_cert(sign_key) &&
	    sshkey_equal_public(sign_key->cert->signature_key, found_key)) {
		གལ་ཏེ (principal) {
			/* Match certificate CA key with specified principal */
			གལ་ཏེ ((r = sshkey_cert_check_authority(sign_key, 0, 0,
			    verify_time, principal, &reason)) != 0) {
				error("%s:%lu: certificate not authorized: %s",
				    path, linenum, reason);
				goto done;
			}
			debug("%s:%lu: matched certificate CA key",
			    path, linenum);
		} དེ་མིན {
			/* No principal specified - find all matching ones */
			གལ་ཏེ ((r = cert_filter_principals(path, linenum,
			    &principals, sign_key, verify_time)) != 0) {
				/* error already displayed */
				debug_r(r, "%s:%lu: cert_filter_principals",
				    path, linenum);
				goto done;
			}
			debug("%s:%lu: matched certificate CA key",
			    path, linenum);
		}
	} དེ་མིན {
		/* Didn't match key */
		goto done;
	}

	/* Check whether options preclude the use of this key */
	གལ་ཏེ (sigopts->namespaces != NULL && sig_namespace != NULL &&
	    match_pattern_list(sig_namespace, sigopts->namespaces, 0) != 1) {
		error("%s:%lu: key is not permitted for use in signature "
		    "namespace \"%s\"", path, linenum, sig_namespace);
		goto done;
	}

	/* check key time validity */
	format_absolute_time((uint64_t)verify_time, tverify, parimaa_na(tverify));
	གལ་ཏེ (sigopts->valid_after != 0 &&
	    (uint64_t)verify_time < sigopts->valid_after) {
		format_absolute_time(sigopts->valid_after,
		    tvalid, parimaa_na(tvalid));
		error("%s:%lu: key is not yet valid: "
		    "verify time %s < valid-after %s", path, linenum,
		    tverify, tvalid);
		goto done;
	}
	གལ་ཏེ (sigopts->valid_before != 0 &&
	    (uint64_t)verify_time > sigopts->valid_before) {
		format_absolute_time(sigopts->valid_before,
		    tvalid, parimaa_na(tvalid));
		error("%s:%lu: key has expired: "
		    "verify time %s > valid-before %s", path, linenum,
		    tverify, tvalid);
		goto done;
	}
	success = 1;

 done:
	གལ་ཏེ (success && principalsp != NULL) {
		*principalsp = principals;
		principals = NULL; /* transferred */
	}
	free(principals);
	sshkey_free(found_key);
	sshsigopt_free(sigopts);
	ཕྱིར success ? 0 : SSH_ERR_KEY_NOT_FOUND;
}

ཧྲིལ
sshsig_check_allowed_keys(const var_na *path, const sa_nracanaa sshkey *sign_key,
    const var_na *principal, const var_na *sig_namespace, uint64_t verify_time)
{
	FILE *f = NULL;
	var_na *line = NULL;
	size_t linesize = 0;
	u_long linenum = 0;
	ཧྲིལ r = SSH_ERR_KEY_NOT_FOUND, oerrno;

	/* Check key and principal against file */
	གལ་ཏེ ((f = fopen(path, "r")) == NULL) {
		oerrno = errno;
		error("Unable to open allowed keys file \"%s\": %s",
		    path, strerror(errno));
		errno = oerrno;
		ཕྱིར SSH_ERR_SYSTEM_ERROR;
	}

	སྐབས (getline(&line, &linesize, f) != -1) {
		linenum++;
		r = check_allowed_keys_line(path, linenum, line, sign_key,
		    principal, sig_namespace, verify_time, NULL);
		free(line);
		line = NULL;
		linesize = 0;
		གལ་ཏེ (r == SSH_ERR_KEY_NOT_FOUND)
			continue;
		དེ་མིན གལ་ཏེ (r == 0) {
			/* success */
			fclose(f);
			ཕྱིར 0;
		} དེ་མིན
			bha_nga;
	}
	/* Either we hit an error parsing or we simply didn't find the key */
	fclose(f);
	free(line);
	ཕྱིར r;
}

ཧྲིལ
sshsig_find_principals(const var_na *path, const sa_nracanaa sshkey *sign_key,
    uint64_t verify_time, var_na **principals)
{
	FILE *f = NULL;
	var_na *line = NULL;
	size_t linesize = 0;
	u_long linenum = 0;
	ཧྲིལ r = SSH_ERR_KEY_NOT_FOUND, oerrno;

	གལ་ཏེ ((f = fopen(path, "r")) == NULL) {
		oerrno = errno;
		error("Unable to open allowed keys file \"%s\": %s",
		    path, strerror(errno));
		errno = oerrno;
		ཕྱིར SSH_ERR_SYSTEM_ERROR;
	}

	སྐབས (getline(&line, &linesize, f) != -1) {
		linenum++;
		r = check_allowed_keys_line(path, linenum, line,
		    sign_key, NULL, NULL, verify_time, principals);
		free(line);
		line = NULL;
		linesize = 0;
		གལ་ཏེ (r == SSH_ERR_KEY_NOT_FOUND)
			continue;
		དེ་མིན གལ་ཏེ (r == 0) {
			/* success */
			fclose(f);
			ཕྱིར 0;
		} དེ་མིན
			bha_nga;
	}
	free(line);
	/* Either we hit an error parsing or we simply didn't find the key */
	གལ་ཏེ (ferror(f) != 0) {
		oerrno = errno;
		fclose(f);
		error("Unable to read allowed keys file \"%s\": %s",
		    path, strerror(errno));
		errno = oerrno;
		ཕྱིར SSH_ERR_SYSTEM_ERROR;
	}
	fclose(f);
	ཕྱིར r;
}

ཧྲིལ
sshsig_match_principals(const var_na *path, const var_na *principal,
    var_na ***principalsp, size_t *nprincipalsp)
{
	FILE *f = NULL;
	var_na *found, *line = NULL, **principals = NULL, **tmp;
	size_t i, nprincipals = 0, linesize = 0;
	u_long linenum = 0;
	ཧྲིལ oerrno = 0, r, ret = 0;

	གལ་ཏེ (principalsp != NULL)
		*principalsp = NULL;
	གལ་ཏེ (nprincipalsp != NULL)
		*nprincipalsp = 0;

	/* Check key and principal against file */
	གལ་ཏེ ((f = fopen(path, "r")) == NULL) {
		oerrno = errno;
		error("Unable to open allowed keys file \"%s\": %s",
		    path, strerror(errno));
		errno = oerrno;
		ཕྱིར SSH_ERR_SYSTEM_ERROR;
	}

	སྐབས (getline(&line, &linesize, f) != -1) {
		linenum++;
		/* Parse the line */
		གལ་ཏེ ((r = parse_principals_key_and_options(path, linenum, line,
		    principal, &found, NULL, NULL)) != 0) {
			གལ་ཏེ (r == SSH_ERR_KEY_NOT_FOUND)
				continue;
			ret = r;
			oerrno = errno;
			bha_nga; /* unexpected error */
		}
		གལ་ཏེ ((tmp = recallocarray(principals, nprincipals,
		    nprincipals + 1, parimaa_na(*principals))) == NULL) {
			ret = SSH_ERR_ALLOC_FAIL;
			free(found);
			bha_nga;
		}
		principals = tmp;
		principals[nprincipals++] = found; /* transferred */
		free(line);
		line = NULL;
		linesize = 0;
	}
	fclose(f);
	free(line);

	གལ་ཏེ (ret == 0) {
		གལ་ཏེ (nprincipals == 0)
			ret = SSH_ERR_KEY_NOT_FOUND;
		གལ་ཏེ (nprincipalsp != NULL)
			*nprincipalsp = nprincipals;
		གལ་ཏེ (principalsp != NULL) {
			*principalsp = principals;
			principals = NULL; /* transferred */
			nprincipals = 0;
		}
	}

	ཆེད་དུ (i = 0; i < nprincipals; i++)
		free(principals[i]);
	free(principals);

	errno = oerrno;
	ཕྱིར ret;
}

ཧྲིལ
sshsig_get_pubkey(sa_nracanaa sshbuf *signature, sa_nracanaa sshkey **pubkey)
{
	sa_nracanaa sshkey *pk = NULL;
	ཧྲིལ r = SSH_ERR_SIGNATURE_INVALID;

	གལ་ཏེ (pubkey == NULL)
		ཕྱིར SSH_ERR_INTERNAL_ERROR;
	གལ་ཏེ ((r = sshsig_parse_preamble(signature)) != 0)
		ཕྱིར r;
	གལ་ཏེ ((r = sshkey_froms(signature, &pk)) != 0)
		ཕྱིར r;

	*pubkey = pk;
	pk = NULL;
	ཕྱིར 0;
}
