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
#define MAGIC_PREAMBLE_LEN	(sizeof(MAGIC_PREAMBLE) - 1)
#define BEGIN_SIGNATURE		"-----BEGIN SSH SIGNATURE-----"
#define END_SIGNATURE		"-----END SSH SIGNATURE-----"
#define RSA_SIGN_ALG		"rsa-sha2-512"
#define RSA_SIGN_ALLOWED	"rsa-sha2-512,rsa-sha2-256"
#define HASHALG_DEFAULT		"sha512"
#define HASHALG_ALLOWED		"sha256,sha512"

整数
sshsig_armor(const struct sshbuf *blob, struct sshbuf **out)
{
	struct sshbuf *buf = NULL;
	整数 r = SSH_ERR_INTERNAL_ERROR;

	*out = NULL;

	如果 ((buf = sshbuf_new()) == NULL) {
		error_f("sshbuf_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}

	如果 ((r = sshbuf_putf(buf, "%s\n", BEGIN_SIGNATURE)) != 0) {
		error_fr(r, "sshbuf_putf");
		goto out;
	}

	如果 ((r = sshbuf_dtob64(blob, buf, 1)) != 0) {
		error_fr(r, "base64 encode signature");
		goto out;
	}

	如果 ((r = sshbuf_put(buf, END_SIGNATURE,
	    sizeof(END_SIGNATURE)-1)) != 0 ||
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
	返回 r;
}

整数
sshsig_dearmor(struct sshbuf *sig, struct sshbuf **out)
{
	整数 r;
	size_t eoffset = 0;
	struct sshbuf *buf = NULL;
	struct sshbuf *sbuf = NULL;
	char *b64 = NULL;

	如果 ((sbuf = sshbuf_fromb(sig)) == NULL) {
		error_f("sshbuf_fromb failed");
		返回 SSH_ERR_ALLOC_FAIL;
	}

	/* Expect and consume preamble + lf/crlf */
	如果 ((r = sshbuf_cmp(sbuf, 0,
	    BEGIN_SIGNATURE, sizeof(BEGIN_SIGNATURE)-1)) != 0) {
		error("Couldn't parse signature: missing header");
		goto done;
	}
	如果 ((r = sshbuf_consume(sbuf, sizeof(BEGIN_SIGNATURE)-1)) != 0) {
		error_fr(r, "consume");
		goto done;
	}
	如果 ((r = sshbuf_cmp(sbuf, 0, "\r\n", 2)) == 0)
		eoffset = 2;
	否则 如果 ((r = sshbuf_cmp(sbuf, 0, "\n", 1)) == 0)
		eoffset = 1;
	否则 {
		r = SSH_ERR_INVALID_FORMAT;
		error_f("no header eol");
		goto done;
	}
	如果 ((r = sshbuf_consume(sbuf, eoffset)) != 0) {
		error_fr(r, "consume eol");
		goto done;
	}
	/* Find and consume lf + suffix (any prior cr would be ignored) */
	如果 ((r = sshbuf_find(sbuf, 0, "\n" END_SIGNATURE,
	    sizeof(END_SIGNATURE), &eoffset)) != 0) {
		error("Couldn't parse signature: missing footer");
		goto done;
	}
	如果 ((r = sshbuf_consume_end(sbuf, sshbuf_len(sbuf)-eoffset)) != 0) {
		error_fr(r, "consume");
		goto done;
	}

	如果 ((b64 = sshbuf_dup_string(sbuf)) == NULL) {
		error_f("sshbuf_dup_string failed");
		r = SSH_ERR_ALLOC_FAIL;
		goto done;
	}

	如果 ((buf = sshbuf_new()) == NULL) {
		error_f("sshbuf_new() failed");
		r = SSH_ERR_ALLOC_FAIL;
		goto done;
	}

	如果 ((r = sshbuf_b64tod(buf, b64)) != 0) {
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
	返回 r;
}

static 整数
sshsig_wrap_sign(struct sshkey *key, const char *hashalg,
    const char *sk_provider, const char *sk_pin, const struct sshbuf *h_message,
    const char *sig_namespace, struct sshbuf **out,
    sshsig_signer *signer, void *signer_ctx)
{
	整数 r;
	size_t slen = 0;
	u_char *sig = NULL;
	struct sshbuf *blob = NULL;
	struct sshbuf *tosign = NULL;
	const char *sign_alg = NULL;

	如果 ((tosign = sshbuf_new()) == NULL ||
	    (blob = sshbuf_new()) == NULL) {
		error_f("sshbuf_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		goto done;
	}

	如果 ((r = sshbuf_put(tosign, MAGIC_PREAMBLE, MAGIC_PREAMBLE_LEN)) != 0 ||
	    (r = sshbuf_put_cstring(tosign, sig_namespace)) != 0 ||
	    (r = sshbuf_put_string(tosign, NULL, 0)) != 0 || /* reserved */
	    (r = sshbuf_put_cstring(tosign, hashalg)) != 0 ||
	    (r = sshbuf_put_stringb(tosign, h_message)) != 0) {
		error_fr(r, "assemble message to sign");
		goto done;
	}

	/* If using RSA keys then default to a good signature algorithm */
	如果 (sshkey_type_plain(key->type) == KEY_RSA) {
		sign_alg = RSA_SIGN_ALG;
		如果 (strcmp(hashalg, "sha256") == 0)
			sign_alg = "rsa-sha2-256";
		否则 如果 (strcmp(hashalg, "sha512") == 0)
			sign_alg = "rsa-sha2-512";
	}

	如果 (signer != NULL) {
		如果 ((r = signer(key, &sig, &slen,
		    sshbuf_ptr(tosign), sshbuf_len(tosign),
		    sign_alg, sk_provider, sk_pin, 0, signer_ctx)) != 0) {
			error_r(r, "Couldn't sign message (signer)");
			goto done;
		}
	} 否则 {
		如果 ((r = sshkey_sign(key, &sig, &slen,
		    sshbuf_ptr(tosign), sshbuf_len(tosign),
		    sign_alg, sk_provider, sk_pin, 0)) != 0) {
			error_r(r, "Couldn't sign message");
			goto done;
		}
	}

	如果 ((r = sshbuf_put(blob, MAGIC_PREAMBLE, MAGIC_PREAMBLE_LEN)) != 0 ||
	    (r = sshbuf_put_u32(blob, SIG_VERSION)) != 0 ||
	    (r = sshkey_puts(key, blob)) != 0 ||
	    (r = sshbuf_put_cstring(blob, sig_namespace)) != 0 ||
	    (r = sshbuf_put_string(blob, NULL, 0)) != 0 || /* reserved */
	    (r = sshbuf_put_cstring(blob, hashalg)) != 0 ||
	    (r = sshbuf_put_string(blob, sig, slen)) != 0) {
		error_fr(r, "assemble signature object");
		goto done;
	}

	如果 (out != NULL) {
		*out = blob;
		blob = NULL;
	}
	r = 0;
done:
	free(sig);
	sshbuf_free(blob);
	sshbuf_free(tosign);
	返回 r;
}

/* Check preamble and version. */
static 整数
sshsig_parse_preamble(struct sshbuf *buf)
{
	整数 r = SSH_ERR_INTERNAL_ERROR;
	uint32_t sversion;

	如果 ((r = sshbuf_cmp(buf, 0, MAGIC_PREAMBLE, MAGIC_PREAMBLE_LEN)) != 0 ||
	    (r = sshbuf_consume(buf, (sizeof(MAGIC_PREAMBLE)-1))) != 0 ||
	    (r = sshbuf_get_u32(buf, &sversion)) != 0) {
		error("Couldn't verify signature: invalid format");
		返回 r;
	}

	如果 (sversion > SIG_VERSION) {
		error("Signature version %lu is larger than supported "
		    "version %u", (unsigned long)sversion, SIG_VERSION);
		返回 SSH_ERR_INVALID_FORMAT;
	}
	返回 0;
}

static 整数
sshsig_check_hashalg(const char *hashalg)
{
	如果 (hashalg == NULL ||
	    match_pattern_list(hashalg, HASHALG_ALLOWED, 0) == 1)
		返回 0;
	error_f("unsupported hash algorithm \"%.100s\"", hashalg);
	返回 SSH_ERR_SIGN_ALG_UNSUPPORTED;
}

static 整数
sshsig_peek_hashalg(struct sshbuf *signature, char **hashalgp)
{
	struct sshbuf *buf = NULL;
	char *hashalg = NULL;
	整数 r = SSH_ERR_INTERNAL_ERROR;

	如果 (hashalgp != NULL)
		*hashalgp = NULL;
	如果 ((buf = sshbuf_fromb(signature)) == NULL)
		返回 SSH_ERR_ALLOC_FAIL;
	如果 ((r = sshsig_parse_preamble(buf)) != 0)
		goto done;
	如果 ((r = sshbuf_get_string_direct(buf, NULL, NULL)) != 0 ||
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
	返回 r;
}

static 整数
sshsig_wrap_verify(struct sshbuf *signature, const char *hashalg,
    const struct sshbuf *h_message, const char *expect_namespace,
    struct sshkey **sign_keyp, struct sshkey_sig_details **sig_details)
{
	整数 r = SSH_ERR_INTERNAL_ERROR;
	struct sshbuf *buf = NULL, *toverify = NULL;
	struct sshkey *key = NULL;
	const u_char *sig;
	char *got_namespace = NULL, *sigtype = NULL, *sig_hashalg = NULL;
	size_t siglen;

	debug_f("verify message length %zu", sshbuf_len(h_message));
	如果 (sig_details != NULL)
		*sig_details = NULL;
	如果 (sign_keyp != NULL)
		*sign_keyp = NULL;

	如果 ((toverify = sshbuf_new()) == NULL) {
		error_f("sshbuf_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		goto done;
	}
	如果 ((r = sshbuf_put(toverify, MAGIC_PREAMBLE,
	    MAGIC_PREAMBLE_LEN)) != 0 ||
	    (r = sshbuf_put_cstring(toverify, expect_namespace)) != 0 ||
	    (r = sshbuf_put_string(toverify, NULL, 0)) != 0 || /* reserved */
	    (r = sshbuf_put_cstring(toverify, hashalg)) != 0 ||
	    (r = sshbuf_put_stringb(toverify, h_message)) != 0) {
		error_fr(r, "assemble message to verify");
		goto done;
	}

	如果 ((r = sshsig_parse_preamble(signature)) != 0)
		goto done;

	如果 ((r = sshkey_froms(signature, &key)) != 0 ||
	    (r = sshbuf_get_cstring(signature, &got_namespace, NULL)) != 0 ||
	    (r = sshbuf_get_string(signature, NULL, NULL)) != 0 ||
	    (r = sshbuf_get_cstring(signature, &sig_hashalg, NULL)) != 0 ||
	    (r = sshbuf_get_string_direct(signature, &sig, &siglen)) != 0) {
		error_fr(r, "parse signature object");
		goto done;
	}

	如果 (sshbuf_len(signature) != 0) {
		error("Signature contains trailing data");
		r = SSH_ERR_INVALID_FORMAT;
		goto done;
	}

	如果 (strcmp(expect_namespace, got_namespace) != 0) {
		error("Couldn't verify signature: namespace does not match");
		debug_f("expected namespace \"%s\" received \"%s\"",
		    expect_namespace, got_namespace);
		r = SSH_ERR_SIGNATURE_INVALID;
		goto done;
	}
	如果 (strcmp(hashalg, sig_hashalg) != 0) {
		error("Couldn't verify signature: hash algorithm mismatch");
		debug_f("expected algorithm \"%s\" received \"%s\"",
		    hashalg, sig_hashalg);
		r = SSH_ERR_SIGNATURE_INVALID;
		goto done;
	}
	/* Ensure that RSA keys use an acceptable signature algorithm */
	如果 (sshkey_type_plain(key->type) == KEY_RSA) {
		如果 ((r = sshkey_get_sigtype(sig, siglen, &sigtype)) != 0) {
			error_r(r, "Couldn't verify signature: unable to get "
			    "signature type");
			goto done;
		}
		如果 (match_pattern_list(sigtype, RSA_SIGN_ALLOWED, 0) != 1) {
			error("Couldn't verify signature: unsupported RSA "
			    "signature algorithm %s", sigtype);
			r = SSH_ERR_SIGN_ALG_UNSUPPORTED;
			goto done;
		}
	}
	如果 ((r = sshkey_verify(key, sig, siglen, sshbuf_ptr(toverify),
	    sshbuf_len(toverify), NULL, 0, sig_details)) != 0) {
		error_r(r, "Signature verification failed");
		goto done;
	}

	/* success */
	r = 0;
	如果 (sign_keyp != NULL) {
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
	返回 r;
}

static 整数
hash_buffer(const struct sshbuf *m, const char *hashalg, struct sshbuf **bp)
{
	char *hex, hash[SSH_DIGEST_MAX_LENGTH];
	整数 alg, r = SSH_ERR_INTERNAL_ERROR;
	struct sshbuf *b = NULL;

	*bp = NULL;
	memset(hash, 0, sizeof(hash));

	如果 ((r = sshsig_check_hashalg(hashalg)) != 0)
		返回 r;
	如果 ((alg = ssh_digest_alg_by_name(hashalg)) == -1) {
		error_f("can't look up hash algorithm %s", hashalg);
		返回 SSH_ERR_INTERNAL_ERROR;
	}
	如果 ((r = ssh_digest_buffer(alg, m, hash, sizeof(hash))) != 0) {
		error_fr(r, "ssh_digest_buffer");
		返回 r;
	}
	如果 ((hex = tohex(hash, ssh_digest_bytes(alg))) != NULL) {
		debug3_f("final hash: %s", hex);
		freezero(hex, strlen(hex));
	}
	如果 ((b = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	如果 ((r = sshbuf_put(b, hash, ssh_digest_bytes(alg))) != 0) {
		error_fr(r, "sshbuf_put");
		goto out;
	}
	*bp = b;
	b = NULL; /* transferred */
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	explicit_bzero(hash, sizeof(hash));
	返回 r;
}

整数
sshsig_signb(struct sshkey *key, const char *hashalg,
    const char *sk_provider, const char *sk_pin,
    const struct sshbuf *message, const char *sig_namespace,
    struct sshbuf **out, sshsig_signer *signer, void *signer_ctx)
{
	struct sshbuf *b = NULL;
	整数 r = SSH_ERR_INTERNAL_ERROR;

	如果 (hashalg == NULL)
		hashalg = HASHALG_DEFAULT;
	如果 (out != NULL)
		*out = NULL;
	如果 ((r = hash_buffer(message, hashalg, &b)) != 0) {
		error_fr(r, "hash buffer");
		goto out;
	}
	如果 ((r = sshsig_wrap_sign(key, hashalg, sk_provider, sk_pin, b,
	    sig_namespace, out, signer, signer_ctx)) != 0)
		goto out;
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	返回 r;
}

整数
sshsig_verifyb(struct sshbuf *signature, const struct sshbuf *message,
    const char *expect_namespace, struct sshkey **sign_keyp,
    struct sshkey_sig_details **sig_details)
{
	struct sshbuf *b = NULL;
	整数 r = SSH_ERR_INTERNAL_ERROR;
	char *hashalg = NULL;

	如果 (sig_details != NULL)
		*sig_details = NULL;
	如果 (sign_keyp != NULL)
		*sign_keyp = NULL;
	如果 ((r = sshsig_peek_hashalg(signature, &hashalg)) != 0)
		返回 r;
	debug_f("signature made with hash \"%s\"", hashalg);
	如果 ((r = hash_buffer(message, hashalg, &b)) != 0) {
		error_fr(r, "hash buffer");
		goto out;
	}
	如果 ((r = sshsig_wrap_verify(signature, hashalg, b, expect_namespace,
	    sign_keyp, sig_details)) != 0)
		goto out;
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	free(hashalg);
	返回 r;
}

static 整数
hash_file(整数 fd, const char *hashalg, struct sshbuf **bp)
{
	char *hex, rbuf[8192], hash[SSH_DIGEST_MAX_LENGTH];
	ssize_t n, total = 0;
	struct ssh_digest_ctx *ctx = NULL;
	整数 alg, oerrno, r = SSH_ERR_INTERNAL_ERROR;
	struct sshbuf *b = NULL;

	*bp = NULL;
	memset(hash, 0, sizeof(hash));

	如果 ((r = sshsig_check_hashalg(hashalg)) != 0)
		返回 r;
	如果 ((alg = ssh_digest_alg_by_name(hashalg)) == -1) {
		error_f("can't look up hash algorithm %s", hashalg);
		返回 SSH_ERR_INTERNAL_ERROR;
	}
	如果 ((ctx = ssh_digest_start(alg)) == NULL) {
		error_f("ssh_digest_start failed");
		返回 SSH_ERR_INTERNAL_ERROR;
	}
	为 (;;) {
		如果 ((n = read(fd, rbuf, sizeof(rbuf))) == -1) {
			如果 (errno == EINTR || errno == EAGAIN)
				continue;
			oerrno = errno;
			error_f("read: %s", strerror(errno));
			errno = oerrno;
			r = SSH_ERR_SYSTEM_ERROR;
			goto out;
		} 否则 如果 (n == 0) {
			debug2_f("hashed %zu bytes", total);
			break; /* EOF */
		}
		total += (size_t)n;
		如果 ((r = ssh_digest_update(ctx, rbuf, (size_t)n)) != 0) {
			error_fr(r, "ssh_digest_update");
			goto out;
		}
	}
	如果 ((r = ssh_digest_final(ctx, hash, sizeof(hash))) != 0) {
		error_fr(r, "ssh_digest_final");
		goto out;
	}
	如果 ((hex = tohex(hash, ssh_digest_bytes(alg))) != NULL) {
		debug3_f("final hash: %s", hex);
		freezero(hex, strlen(hex));
	}
	如果 ((b = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	如果 ((r = sshbuf_put(b, hash, ssh_digest_bytes(alg))) != 0) {
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
	explicit_bzero(hash, sizeof(hash));
	errno = oerrno;
	返回 r;
}

整数
sshsig_sign_fd(struct sshkey *key, const char *hashalg,
    const char *sk_provider, const char *sk_pin,
    整数 fd, const char *sig_namespace, struct sshbuf **out,
    sshsig_signer *signer, void *signer_ctx)
{
	struct sshbuf *b = NULL;
	整数 r = SSH_ERR_INTERNAL_ERROR;

	如果 (hashalg == NULL)
		hashalg = HASHALG_DEFAULT;
	如果 (out != NULL)
		*out = NULL;
	如果 ((r = hash_file(fd, hashalg, &b)) != 0) {
		error_fr(r, "hash_file");
		返回 r;
	}
	如果 ((r = sshsig_wrap_sign(key, hashalg, sk_provider, sk_pin, b,
	    sig_namespace, out, signer, signer_ctx)) != 0)
		goto out;
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	返回 r;
}

整数
sshsig_verify_fd(struct sshbuf *signature, 整数 fd,
    const char *expect_namespace, struct sshkey **sign_keyp,
    struct sshkey_sig_details **sig_details)
{
	struct sshbuf *b = NULL;
	整数 r = SSH_ERR_INTERNAL_ERROR;
	char *hashalg = NULL;

	如果 (sig_details != NULL)
		*sig_details = NULL;
	如果 (sign_keyp != NULL)
		*sign_keyp = NULL;
	如果 ((r = sshsig_peek_hashalg(signature, &hashalg)) != 0)
		返回 r;
	debug_f("signature made with hash \"%s\"", hashalg);
	如果 ((r = hash_file(fd, hashalg, &b)) != 0) {
		error_fr(r, "hash_file");
		goto out;
	}
	如果 ((r = sshsig_wrap_verify(signature, hashalg, b, expect_namespace,
	    sign_keyp, sig_details)) != 0)
		goto out;
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	free(hashalg);
	返回 r;
}

struct sshsigopt {
	整数 ca;
	char *namespaces;
	uint64_t valid_after, valid_before;
};

struct sshsigopt *
sshsigopt_parse(const char *opts, const char *path, u_long linenum,
    const char **errstrp)
{
	struct sshsigopt *ret;
	整数 r;
	char *opt;
	const char *errstr = NULL;

	如果 ((ret = calloc(1, sizeof(*ret))) == NULL)
		返回 NULL;
	如果 (opts == NULL || *opts == '\0')
		返回 ret; /* Empty options yields empty options :) */

	当 (*opts && *opts != ' ' && *opts != '\t') {
		/* flag options */
		如果 ((r = opt_flag("cert-authority", 0, &opts)) != -1) {
			ret->ca = 1;
		} 否则 如果 (opt_match(&opts, "namespaces")) {
			如果 (ret->namespaces != NULL) {
				errstr = "multiple \"namespaces\" clauses";
				goto fail;
			}
			ret->namespaces = opt_dequote(&opts, &errstr);
			如果 (ret->namespaces == NULL)
				goto fail;
		} 否则 如果 (opt_match(&opts, "valid-after")) {
			如果 (ret->valid_after != 0) {
				errstr = "multiple \"valid-after\" clauses";
				goto fail;
			}
			如果 ((opt = opt_dequote(&opts, &errstr)) == NULL)
				goto fail;
			如果 (parse_absolute_time(opt, &ret->valid_after) != 0 ||
			    ret->valid_after == 0) {
				free(opt);
				errstr = "invalid \"valid-after\" time";
				goto fail;
			}
			free(opt);
		} 否则 如果 (opt_match(&opts, "valid-before")) {
			如果 (ret->valid_before != 0) {
				errstr = "multiple \"valid-before\" clauses";
				goto fail;
			}
			如果 ((opt = opt_dequote(&opts, &errstr)) == NULL)
				goto fail;
			如果 (parse_absolute_time(opt, &ret->valid_before) != 0 ||
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
		如果 (*opts == '\0' || *opts == ' ' || *opts == '\t')
			break;		/* End of options. */
		/* Anything other than a comma is an unknown option */
		如果 (*opts != ',') {
			errstr = "unknown key option";
			goto fail;
		}
		opts++;
		如果 (*opts == '\0') {
			errstr = "unexpected end-of-options";
			goto fail;
		}
	}
	/* final consistency check */
	如果 (ret->valid_after != 0 && ret->valid_before != 0 &&
	    ret->valid_before <= ret->valid_after) {
		errstr = "\"valid-before\" time is before \"valid-after\"";
		goto fail;
	}
	/* success */
	返回 ret;
 fail:
	如果 (errstrp != NULL)
		*errstrp = errstr;
	sshsigopt_free(ret);
	返回 NULL;
}

void
sshsigopt_free(struct sshsigopt *opts)
{
	如果 (opts == NULL)
		返回;
	free(opts->namespaces);
	free(opts);
}

static 整数
parse_principals_key_and_options(const char *path, u_long linenum, char *line,
    const char *required_principal, char **principalsp, struct sshkey **keyp,
    struct sshsigopt **sigoptsp)
{
	char *opts = NULL, *tmp, *cp, *principals = NULL;
	const char *reason = NULL;
	struct sshsigopt *sigopts = NULL;
	struct sshkey *key = NULL;
	整数 r = SSH_ERR_INTERNAL_ERROR;

	如果 (principalsp != NULL)
		*principalsp = NULL;
	如果 (sigoptsp != NULL)
		*sigoptsp = NULL;
	如果 (keyp != NULL)
		*keyp = NULL;

	cp = line;
	cp = cp + strspn(cp, " \t\n\r"); /* skip leading whitespace */
	如果 (*cp == '#' || *cp == '\0')
		返回 SSH_ERR_KEY_NOT_FOUND; /* blank or all-comment line */

	/* format: identity[,identity...] [option[,option...]] key */
	如果 ((tmp = strdelimw(&cp)) == NULL || cp == NULL) {
		error("%s:%lu: invalid line", path, linenum);
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	如果 ((principals = strdup(tmp)) == NULL) {
		error_f("strdup failed");
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	/*
	 * Bail out early if we're looking for a particular principal and this
	 * line does not list it.
	 */
	如果 (required_principal != NULL) {
		如果 (match_pattern_list(required_principal,
		    principals, 0) != 1) {
			/* principal didn't match */
			r = SSH_ERR_KEY_NOT_FOUND;
			goto out;
		}
		debug_f("%s:%lu: matched principal \"%s\"",
		    path, linenum, required_principal);
	}

	如果 ((key = sshkey_new(KEY_UNSPEC)) == NULL) {
		error_f("sshkey_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	如果 (sshkey_read(key, &cp) != 0) {
		/* no key? Check for options */
		opts = cp;
		如果 (sshkey_advance_past_options(&cp) != 0) {
			error("%s:%lu: invalid options", path, linenum);
			r = SSH_ERR_INVALID_FORMAT;
			goto out;
		}
		如果 (cp == NULL || *cp == '\0') {
			error("%s:%lu: missing key", path, linenum);
			r = SSH_ERR_INVALID_FORMAT;
			goto out;
		}
		*cp++ = '\0';
		skip_space(&cp);
		如果 (sshkey_read(key, &cp) != 0) {
			error("%s:%lu: invalid key", path, linenum);
			r = SSH_ERR_INVALID_FORMAT;
			goto out;
		}
	}
	debug3("%s:%lu: options %s", path, linenum, opts == NULL ? "" : opts);
	如果 ((sigopts = sshsigopt_parse(opts, path, linenum, &reason)) == NULL) {
		error("%s:%lu: bad options: %s", path, linenum, reason);
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	/* success */
	如果 (principalsp != NULL) {
		*principalsp = principals;
		principals = NULL; /* transferred */
	}
	如果 (sigoptsp != NULL) {
		*sigoptsp = sigopts;
		sigopts = NULL; /* transferred */
	}
	如果 (keyp != NULL) {
		*keyp = key;
		key = NULL; /* transferred */
	}
	r = 0;
 out:
	free(principals);
	sshsigopt_free(sigopts);
	sshkey_free(key);
	返回 r;
}

static 整数
cert_filter_principals(const char *path, u_long linenum,
    char **principalsp, const struct sshkey *cert, uint64_t verify_time)
{
	char *cp, *oprincipals, *principals;
	const char *reason;
	struct sshbuf *nprincipals;
	整数 r = SSH_ERR_INTERNAL_ERROR, success = 0;
	u_int i;

	oprincipals = principals = *principalsp;
	*principalsp = NULL;

	如果 ((nprincipals = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}

	当 ((cp = strsep(&principals, ",")) != NULL && *cp != '\0') {
		/* Check certificate validity */
		如果 ((r = sshkey_cert_check_authority(cert, 0, 0, verify_time,
		    NULL, &reason)) != 0) {
			debug("%s:%lu: principal \"%s\" not authorized: %s",
			    path, linenum, cp, reason);
			continue;
		}
		/* Return all matching principal names from the cert */
		为 (i = 0; i < cert->cert->nprincipals; i++) {
			如果 (match_pattern(cert->cert->principals[i], cp)) {
				如果 ((r = sshbuf_putf(nprincipals, "%s%s",
					sshbuf_len(nprincipals) != 0 ? "," : "",
						cert->cert->principals[i])) != 0) {
					error_f("buffer error");
					goto out;
				}
			}
		}
	}
	如果 (sshbuf_len(nprincipals) == 0) {
		error("%s:%lu: no valid principals found", path, linenum);
		r = SSH_ERR_KEY_CERT_INVALID;
		goto out;
	}
	如果 ((principals = sshbuf_dup_string(nprincipals)) == NULL) {
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
	返回 success ? 0 : r;
}

static 整数
check_allowed_keys_line(const char *path, u_long linenum, char *line,
    const struct sshkey *sign_key, const char *principal,
    const char *sig_namespace, uint64_t verify_time, char **principalsp)
{
	struct sshkey *found_key = NULL;
	char *principals = NULL;
	整数 r, success = 0;
	const char *reason = NULL;
	struct sshsigopt *sigopts = NULL;
	char tvalid[64], tverify[64];

	如果 (principalsp != NULL)
		*principalsp = NULL;

	/* Parse the line */
	如果 ((r = parse_principals_key_and_options(path, linenum, line,
	    principal, &principals, &found_key, &sigopts)) != 0) {
		/* error already logged */
		goto done;
	}

	如果 (!sigopts->ca && sshkey_equal(found_key, sign_key)) {
		/* Exact match of key */
		debug("%s:%lu: matched key", path, linenum);
	} 否则 如果 (sigopts->ca && sshkey_is_cert(sign_key) &&
	    sshkey_equal_public(sign_key->cert->signature_key, found_key)) {
		如果 (principal) {
			/* Match certificate CA key with specified principal */
			如果 ((r = sshkey_cert_check_authority(sign_key, 0, 0,
			    verify_time, principal, &reason)) != 0) {
				error("%s:%lu: certificate not authorized: %s",
				    path, linenum, reason);
				goto done;
			}
			debug("%s:%lu: matched certificate CA key",
			    path, linenum);
		} 否则 {
			/* No principal specified - find all matching ones */
			如果 ((r = cert_filter_principals(path, linenum,
			    &principals, sign_key, verify_time)) != 0) {
				/* error already displayed */
				debug_r(r, "%s:%lu: cert_filter_principals",
				    path, linenum);
				goto done;
			}
			debug("%s:%lu: matched certificate CA key",
			    path, linenum);
		}
	} 否则 {
		/* Didn't match key */
		goto done;
	}

	/* Check whether options preclude the use of this key */
	如果 (sigopts->namespaces != NULL && sig_namespace != NULL &&
	    match_pattern_list(sig_namespace, sigopts->namespaces, 0) != 1) {
		error("%s:%lu: key is not permitted for use in signature "
		    "namespace \"%s\"", path, linenum, sig_namespace);
		goto done;
	}

	/* check key time validity */
	format_absolute_time((uint64_t)verify_time, tverify, sizeof(tverify));
	如果 (sigopts->valid_after != 0 &&
	    (uint64_t)verify_time < sigopts->valid_after) {
		format_absolute_time(sigopts->valid_after,
		    tvalid, sizeof(tvalid));
		error("%s:%lu: key is not yet valid: "
		    "verify time %s < valid-after %s", path, linenum,
		    tverify, tvalid);
		goto done;
	}
	如果 (sigopts->valid_before != 0 &&
	    (uint64_t)verify_time > sigopts->valid_before) {
		format_absolute_time(sigopts->valid_before,
		    tvalid, sizeof(tvalid));
		error("%s:%lu: key has expired: "
		    "verify time %s > valid-before %s", path, linenum,
		    tverify, tvalid);
		goto done;
	}
	success = 1;

 done:
	如果 (success && principalsp != NULL) {
		*principalsp = principals;
		principals = NULL; /* transferred */
	}
	free(principals);
	sshkey_free(found_key);
	sshsigopt_free(sigopts);
	返回 success ? 0 : SSH_ERR_KEY_NOT_FOUND;
}

整数
sshsig_check_allowed_keys(const char *path, const struct sshkey *sign_key,
    const char *principal, const char *sig_namespace, uint64_t verify_time)
{
	FILE *f = NULL;
	char *line = NULL;
	size_t linesize = 0;
	u_long linenum = 0;
	整数 r = SSH_ERR_KEY_NOT_FOUND, oerrno;

	/* Check key and principal against file */
	如果 ((f = fopen(path, "r")) == NULL) {
		oerrno = errno;
		error("Unable to open allowed keys file \"%s\": %s",
		    path, strerror(errno));
		errno = oerrno;
		返回 SSH_ERR_SYSTEM_ERROR;
	}

	当 (getline(&line, &linesize, f) != -1) {
		linenum++;
		r = check_allowed_keys_line(path, linenum, line, sign_key,
		    principal, sig_namespace, verify_time, NULL);
		free(line);
		line = NULL;
		linesize = 0;
		如果 (r == SSH_ERR_KEY_NOT_FOUND)
			continue;
		否则 如果 (r == 0) {
			/* success */
			fclose(f);
			返回 0;
		} 否则
			break;
	}
	/* Either we hit an error parsing or we simply didn't find the key */
	fclose(f);
	free(line);
	返回 r;
}

整数
sshsig_find_principals(const char *path, const struct sshkey *sign_key,
    uint64_t verify_time, char **principals)
{
	FILE *f = NULL;
	char *line = NULL;
	size_t linesize = 0;
	u_long linenum = 0;
	整数 r = SSH_ERR_KEY_NOT_FOUND, oerrno;

	如果 ((f = fopen(path, "r")) == NULL) {
		oerrno = errno;
		error("Unable to open allowed keys file \"%s\": %s",
		    path, strerror(errno));
		errno = oerrno;
		返回 SSH_ERR_SYSTEM_ERROR;
	}

	当 (getline(&line, &linesize, f) != -1) {
		linenum++;
		r = check_allowed_keys_line(path, linenum, line,
		    sign_key, NULL, NULL, verify_time, principals);
		free(line);
		line = NULL;
		linesize = 0;
		如果 (r == SSH_ERR_KEY_NOT_FOUND)
			continue;
		否则 如果 (r == 0) {
			/* success */
			fclose(f);
			返回 0;
		} 否则
			break;
	}
	free(line);
	/* Either we hit an error parsing or we simply didn't find the key */
	如果 (ferror(f) != 0) {
		oerrno = errno;
		fclose(f);
		error("Unable to read allowed keys file \"%s\": %s",
		    path, strerror(errno));
		errno = oerrno;
		返回 SSH_ERR_SYSTEM_ERROR;
	}
	fclose(f);
	返回 r;
}

整数
sshsig_match_principals(const char *path, const char *principal,
    char ***principalsp, size_t *nprincipalsp)
{
	FILE *f = NULL;
	char *found, *line = NULL, **principals = NULL, **tmp;
	size_t i, nprincipals = 0, linesize = 0;
	u_long linenum = 0;
	整数 oerrno = 0, r, ret = 0;

	如果 (principalsp != NULL)
		*principalsp = NULL;
	如果 (nprincipalsp != NULL)
		*nprincipalsp = 0;

	/* Check key and principal against file */
	如果 ((f = fopen(path, "r")) == NULL) {
		oerrno = errno;
		error("Unable to open allowed keys file \"%s\": %s",
		    path, strerror(errno));
		errno = oerrno;
		返回 SSH_ERR_SYSTEM_ERROR;
	}

	当 (getline(&line, &linesize, f) != -1) {
		linenum++;
		/* Parse the line */
		如果 ((r = parse_principals_key_and_options(path, linenum, line,
		    principal, &found, NULL, NULL)) != 0) {
			如果 (r == SSH_ERR_KEY_NOT_FOUND)
				continue;
			ret = r;
			oerrno = errno;
			break; /* unexpected error */
		}
		如果 ((tmp = recallocarray(principals, nprincipals,
		    nprincipals + 1, sizeof(*principals))) == NULL) {
			ret = SSH_ERR_ALLOC_FAIL;
			free(found);
			break;
		}
		principals = tmp;
		principals[nprincipals++] = found; /* transferred */
		free(line);
		line = NULL;
		linesize = 0;
	}
	fclose(f);
	free(line);

	如果 (ret == 0) {
		如果 (nprincipals == 0)
			ret = SSH_ERR_KEY_NOT_FOUND;
		如果 (nprincipalsp != NULL)
			*nprincipalsp = nprincipals;
		如果 (principalsp != NULL) {
			*principalsp = principals;
			principals = NULL; /* transferred */
			nprincipals = 0;
		}
	}

	为 (i = 0; i < nprincipals; i++)
		free(principals[i]);
	free(principals);

	errno = oerrno;
	返回 ret;
}

整数
sshsig_get_pubkey(struct sshbuf *signature, struct sshkey **pubkey)
{
	struct sshkey *pk = NULL;
	整数 r = SSH_ERR_SIGNATURE_INVALID;

	如果 (pubkey == NULL)
		返回 SSH_ERR_INTERNAL_ERROR;
	如果 ((r = sshsig_parse_preamble(signature)) != 0)
		返回 r;
	如果 ((r = sshkey_froms(signature, &pk)) != 0)
		返回 r;

	*pubkey = pk;
	pk = NULL;
	返回 0;
}
