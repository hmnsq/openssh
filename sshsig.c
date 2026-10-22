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

цяло
sshsig_armor(const struct sshbuf *blob, struct sshbuf **out)
{
	struct sshbuf *buf = NULL;
	цяло r = SSH_ERR_INTERNAL_ERROR;

	*out = NULL;

	ако ((buf = sshbuf_new()) == NULL) {
		error_f("sshbuf_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}

	ако ((r = sshbuf_putf(buf, "%s\n", BEGIN_SIGNATURE)) != 0) {
		error_fr(r, "sshbuf_putf");
		goto out;
	}

	ако ((r = sshbuf_dtob64(blob, buf, 1)) != 0) {
		error_fr(r, "base64 encode signature");
		goto out;
	}

	ако ((r = sshbuf_put(buf, END_SIGNATURE,
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
	върни r;
}

цяло
sshsig_dearmor(struct sshbuf *sig, struct sshbuf **out)
{
	цяло r;
	size_t eoffset = 0;
	struct sshbuf *buf = NULL;
	struct sshbuf *sbuf = NULL;
	char *b64 = NULL;

	ако ((sbuf = sshbuf_fromb(sig)) == NULL) {
		error_f("sshbuf_fromb failed");
		върни SSH_ERR_ALLOC_FAIL;
	}

	/* Expect and consume preamble + lf/crlf */
	ако ((r = sshbuf_cmp(sbuf, 0,
	    BEGIN_SIGNATURE, sizeof(BEGIN_SIGNATURE)-1)) != 0) {
		error("Couldn't parse signature: missing header");
		goto done;
	}
	ако ((r = sshbuf_consume(sbuf, sizeof(BEGIN_SIGNATURE)-1)) != 0) {
		error_fr(r, "consume");
		goto done;
	}
	ако ((r = sshbuf_cmp(sbuf, 0, "\r\n", 2)) == 0)
		eoffset = 2;
	иначе ако ((r = sshbuf_cmp(sbuf, 0, "\n", 1)) == 0)
		eoffset = 1;
	иначе {
		r = SSH_ERR_INVALID_FORMAT;
		error_f("no header eol");
		goto done;
	}
	ако ((r = sshbuf_consume(sbuf, eoffset)) != 0) {
		error_fr(r, "consume eol");
		goto done;
	}
	/* Find and consume lf + suffix (any prior cr would be ignored) */
	ако ((r = sshbuf_find(sbuf, 0, "\n" END_SIGNATURE,
	    sizeof(END_SIGNATURE), &eoffset)) != 0) {
		error("Couldn't parse signature: missing footer");
		goto done;
	}
	ако ((r = sshbuf_consume_end(sbuf, sshbuf_len(sbuf)-eoffset)) != 0) {
		error_fr(r, "consume");
		goto done;
	}

	ако ((b64 = sshbuf_dup_string(sbuf)) == NULL) {
		error_f("sshbuf_dup_string failed");
		r = SSH_ERR_ALLOC_FAIL;
		goto done;
	}

	ако ((buf = sshbuf_new()) == NULL) {
		error_f("sshbuf_new() failed");
		r = SSH_ERR_ALLOC_FAIL;
		goto done;
	}

	ако ((r = sshbuf_b64tod(buf, b64)) != 0) {
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
	върни r;
}

static цяло
sshsig_wrap_sign(struct sshkey *key, const char *hashalg,
    const char *sk_provider, const char *sk_pin, const struct sshbuf *h_message,
    const char *sig_namespace, struct sshbuf **out,
    sshsig_signer *signer, void *signer_ctx)
{
	цяло r;
	size_t slen = 0;
	u_char *sig = NULL;
	struct sshbuf *blob = NULL;
	struct sshbuf *tosign = NULL;
	const char *sign_alg = NULL;

	ако ((tosign = sshbuf_new()) == NULL ||
	    (blob = sshbuf_new()) == NULL) {
		error_f("sshbuf_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		goto done;
	}

	ако ((r = sshbuf_put(tosign, MAGIC_PREAMBLE, MAGIC_PREAMBLE_LEN)) != 0 ||
	    (r = sshbuf_put_cstring(tosign, sig_namespace)) != 0 ||
	    (r = sshbuf_put_string(tosign, NULL, 0)) != 0 || /* reserved */
	    (r = sshbuf_put_cstring(tosign, hashalg)) != 0 ||
	    (r = sshbuf_put_stringb(tosign, h_message)) != 0) {
		error_fr(r, "assemble message to sign");
		goto done;
	}

	/* If using RSA keys then default to a good signature algorithm */
	ако (sshkey_type_plain(key->type) == KEY_RSA) {
		sign_alg = RSA_SIGN_ALG;
		ако (strcmp(hashalg, "sha256") == 0)
			sign_alg = "rsa-sha2-256";
		иначе ако (strcmp(hashalg, "sha512") == 0)
			sign_alg = "rsa-sha2-512";
	}

	ако (signer != NULL) {
		ако ((r = signer(key, &sig, &slen,
		    sshbuf_ptr(tosign), sshbuf_len(tosign),
		    sign_alg, sk_provider, sk_pin, 0, signer_ctx)) != 0) {
			error_r(r, "Couldn't sign message (signer)");
			goto done;
		}
	} иначе {
		ако ((r = sshkey_sign(key, &sig, &slen,
		    sshbuf_ptr(tosign), sshbuf_len(tosign),
		    sign_alg, sk_provider, sk_pin, 0)) != 0) {
			error_r(r, "Couldn't sign message");
			goto done;
		}
	}

	ако ((r = sshbuf_put(blob, MAGIC_PREAMBLE, MAGIC_PREAMBLE_LEN)) != 0 ||
	    (r = sshbuf_put_u32(blob, SIG_VERSION)) != 0 ||
	    (r = sshkey_puts(key, blob)) != 0 ||
	    (r = sshbuf_put_cstring(blob, sig_namespace)) != 0 ||
	    (r = sshbuf_put_string(blob, NULL, 0)) != 0 || /* reserved */
	    (r = sshbuf_put_cstring(blob, hashalg)) != 0 ||
	    (r = sshbuf_put_string(blob, sig, slen)) != 0) {
		error_fr(r, "assemble signature object");
		goto done;
	}

	ако (out != NULL) {
		*out = blob;
		blob = NULL;
	}
	r = 0;
done:
	free(sig);
	sshbuf_free(blob);
	sshbuf_free(tosign);
	върни r;
}

/* Check preamble and version. */
static цяло
sshsig_parse_preamble(struct sshbuf *buf)
{
	цяло r = SSH_ERR_INTERNAL_ERROR;
	uint32_t sversion;

	ако ((r = sshbuf_cmp(buf, 0, MAGIC_PREAMBLE, MAGIC_PREAMBLE_LEN)) != 0 ||
	    (r = sshbuf_consume(buf, (sizeof(MAGIC_PREAMBLE)-1))) != 0 ||
	    (r = sshbuf_get_u32(buf, &sversion)) != 0) {
		error("Couldn't verify signature: invalid format");
		върни r;
	}

	ако (sversion > SIG_VERSION) {
		error("Signature version %lu is larger than supported "
		    "version %u", (unsigned long)sversion, SIG_VERSION);
		върни SSH_ERR_INVALID_FORMAT;
	}
	върни 0;
}

static цяло
sshsig_check_hashalg(const char *hashalg)
{
	ако (hashalg == NULL ||
	    match_pattern_list(hashalg, HASHALG_ALLOWED, 0) == 1)
		върни 0;
	error_f("unsupported hash algorithm \"%.100s\"", hashalg);
	върни SSH_ERR_SIGN_ALG_UNSUPPORTED;
}

static цяло
sshsig_peek_hashalg(struct sshbuf *signature, char **hashalgp)
{
	struct sshbuf *buf = NULL;
	char *hashalg = NULL;
	цяло r = SSH_ERR_INTERNAL_ERROR;

	ако (hashalgp != NULL)
		*hashalgp = NULL;
	ако ((buf = sshbuf_fromb(signature)) == NULL)
		върни SSH_ERR_ALLOC_FAIL;
	ако ((r = sshsig_parse_preamble(buf)) != 0)
		goto done;
	ако ((r = sshbuf_get_string_direct(buf, NULL, NULL)) != 0 ||
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
	върни r;
}

static цяло
sshsig_wrap_verify(struct sshbuf *signature, const char *hashalg,
    const struct sshbuf *h_message, const char *expect_namespace,
    struct sshkey **sign_keyp, struct sshkey_sig_details **sig_details)
{
	цяло r = SSH_ERR_INTERNAL_ERROR;
	struct sshbuf *buf = NULL, *toverify = NULL;
	struct sshkey *key = NULL;
	const u_char *sig;
	char *got_namespace = NULL, *sigtype = NULL, *sig_hashalg = NULL;
	size_t siglen;

	debug_f("verify message length %zu", sshbuf_len(h_message));
	ако (sig_details != NULL)
		*sig_details = NULL;
	ако (sign_keyp != NULL)
		*sign_keyp = NULL;

	ако ((toverify = sshbuf_new()) == NULL) {
		error_f("sshbuf_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		goto done;
	}
	ако ((r = sshbuf_put(toverify, MAGIC_PREAMBLE,
	    MAGIC_PREAMBLE_LEN)) != 0 ||
	    (r = sshbuf_put_cstring(toverify, expect_namespace)) != 0 ||
	    (r = sshbuf_put_string(toverify, NULL, 0)) != 0 || /* reserved */
	    (r = sshbuf_put_cstring(toverify, hashalg)) != 0 ||
	    (r = sshbuf_put_stringb(toverify, h_message)) != 0) {
		error_fr(r, "assemble message to verify");
		goto done;
	}

	ако ((r = sshsig_parse_preamble(signature)) != 0)
		goto done;

	ако ((r = sshkey_froms(signature, &key)) != 0 ||
	    (r = sshbuf_get_cstring(signature, &got_namespace, NULL)) != 0 ||
	    (r = sshbuf_get_string(signature, NULL, NULL)) != 0 ||
	    (r = sshbuf_get_cstring(signature, &sig_hashalg, NULL)) != 0 ||
	    (r = sshbuf_get_string_direct(signature, &sig, &siglen)) != 0) {
		error_fr(r, "parse signature object");
		goto done;
	}

	ако (sshbuf_len(signature) != 0) {
		error("Signature contains trailing data");
		r = SSH_ERR_INVALID_FORMAT;
		goto done;
	}

	ако (strcmp(expect_namespace, got_namespace) != 0) {
		error("Couldn't verify signature: namespace does not match");
		debug_f("expected namespace \"%s\" received \"%s\"",
		    expect_namespace, got_namespace);
		r = SSH_ERR_SIGNATURE_INVALID;
		goto done;
	}
	ако (strcmp(hashalg, sig_hashalg) != 0) {
		error("Couldn't verify signature: hash algorithm mismatch");
		debug_f("expected algorithm \"%s\" received \"%s\"",
		    hashalg, sig_hashalg);
		r = SSH_ERR_SIGNATURE_INVALID;
		goto done;
	}
	/* Ensure that RSA keys use an acceptable signature algorithm */
	ако (sshkey_type_plain(key->type) == KEY_RSA) {
		ако ((r = sshkey_get_sigtype(sig, siglen, &sigtype)) != 0) {
			error_r(r, "Couldn't verify signature: unable to get "
			    "signature type");
			goto done;
		}
		ако (match_pattern_list(sigtype, RSA_SIGN_ALLOWED, 0) != 1) {
			error("Couldn't verify signature: unsupported RSA "
			    "signature algorithm %s", sigtype);
			r = SSH_ERR_SIGN_ALG_UNSUPPORTED;
			goto done;
		}
	}
	ако ((r = sshkey_verify(key, sig, siglen, sshbuf_ptr(toverify),
	    sshbuf_len(toverify), NULL, 0, sig_details)) != 0) {
		error_r(r, "Signature verification failed");
		goto done;
	}

	/* success */
	r = 0;
	ако (sign_keyp != NULL) {
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
	върни r;
}

static цяло
hash_buffer(const struct sshbuf *m, const char *hashalg, struct sshbuf **bp)
{
	char *hex, hash[SSH_DIGEST_MAX_LENGTH];
	цяло alg, r = SSH_ERR_INTERNAL_ERROR;
	struct sshbuf *b = NULL;

	*bp = NULL;
	memset(hash, 0, sizeof(hash));

	ако ((r = sshsig_check_hashalg(hashalg)) != 0)
		върни r;
	ако ((alg = ssh_digest_alg_by_name(hashalg)) == -1) {
		error_f("can't look up hash algorithm %s", hashalg);
		върни SSH_ERR_INTERNAL_ERROR;
	}
	ако ((r = ssh_digest_buffer(alg, m, hash, sizeof(hash))) != 0) {
		error_fr(r, "ssh_digest_buffer");
		върни r;
	}
	ако ((hex = tohex(hash, ssh_digest_bytes(alg))) != NULL) {
		debug3_f("final hash: %s", hex);
		freezero(hex, strlen(hex));
	}
	ако ((b = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	ако ((r = sshbuf_put(b, hash, ssh_digest_bytes(alg))) != 0) {
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
	върни r;
}

цяло
sshsig_signb(struct sshkey *key, const char *hashalg,
    const char *sk_provider, const char *sk_pin,
    const struct sshbuf *message, const char *sig_namespace,
    struct sshbuf **out, sshsig_signer *signer, void *signer_ctx)
{
	struct sshbuf *b = NULL;
	цяло r = SSH_ERR_INTERNAL_ERROR;

	ако (hashalg == NULL)
		hashalg = HASHALG_DEFAULT;
	ако (out != NULL)
		*out = NULL;
	ако ((r = hash_buffer(message, hashalg, &b)) != 0) {
		error_fr(r, "hash buffer");
		goto out;
	}
	ако ((r = sshsig_wrap_sign(key, hashalg, sk_provider, sk_pin, b,
	    sig_namespace, out, signer, signer_ctx)) != 0)
		goto out;
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	върни r;
}

цяло
sshsig_verifyb(struct sshbuf *signature, const struct sshbuf *message,
    const char *expect_namespace, struct sshkey **sign_keyp,
    struct sshkey_sig_details **sig_details)
{
	struct sshbuf *b = NULL;
	цяло r = SSH_ERR_INTERNAL_ERROR;
	char *hashalg = NULL;

	ако (sig_details != NULL)
		*sig_details = NULL;
	ако (sign_keyp != NULL)
		*sign_keyp = NULL;
	ако ((r = sshsig_peek_hashalg(signature, &hashalg)) != 0)
		върни r;
	debug_f("signature made with hash \"%s\"", hashalg);
	ако ((r = hash_buffer(message, hashalg, &b)) != 0) {
		error_fr(r, "hash buffer");
		goto out;
	}
	ако ((r = sshsig_wrap_verify(signature, hashalg, b, expect_namespace,
	    sign_keyp, sig_details)) != 0)
		goto out;
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	free(hashalg);
	върни r;
}

static цяло
hash_file(цяло fd, const char *hashalg, struct sshbuf **bp)
{
	char *hex, rbuf[8192], hash[SSH_DIGEST_MAX_LENGTH];
	ssize_t n, total = 0;
	struct ssh_digest_ctx *ctx = NULL;
	цяло alg, oerrno, r = SSH_ERR_INTERNAL_ERROR;
	struct sshbuf *b = NULL;

	*bp = NULL;
	memset(hash, 0, sizeof(hash));

	ако ((r = sshsig_check_hashalg(hashalg)) != 0)
		върни r;
	ако ((alg = ssh_digest_alg_by_name(hashalg)) == -1) {
		error_f("can't look up hash algorithm %s", hashalg);
		върни SSH_ERR_INTERNAL_ERROR;
	}
	ако ((ctx = ssh_digest_start(alg)) == NULL) {
		error_f("ssh_digest_start failed");
		върни SSH_ERR_INTERNAL_ERROR;
	}
	за (;;) {
		ако ((n = read(fd, rbuf, sizeof(rbuf))) == -1) {
			ако (errno == EINTR || errno == EAGAIN)
				continue;
			oerrno = errno;
			error_f("read: %s", strerror(errno));
			errno = oerrno;
			r = SSH_ERR_SYSTEM_ERROR;
			goto out;
		} иначе ако (n == 0) {
			debug2_f("hashed %zu bytes", total);
			break; /* EOF */
		}
		total += (size_t)n;
		ако ((r = ssh_digest_update(ctx, rbuf, (size_t)n)) != 0) {
			error_fr(r, "ssh_digest_update");
			goto out;
		}
	}
	ако ((r = ssh_digest_final(ctx, hash, sizeof(hash))) != 0) {
		error_fr(r, "ssh_digest_final");
		goto out;
	}
	ако ((hex = tohex(hash, ssh_digest_bytes(alg))) != NULL) {
		debug3_f("final hash: %s", hex);
		freezero(hex, strlen(hex));
	}
	ако ((b = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	ако ((r = sshbuf_put(b, hash, ssh_digest_bytes(alg))) != 0) {
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
	върни r;
}

цяло
sshsig_sign_fd(struct sshkey *key, const char *hashalg,
    const char *sk_provider, const char *sk_pin,
    цяло fd, const char *sig_namespace, struct sshbuf **out,
    sshsig_signer *signer, void *signer_ctx)
{
	struct sshbuf *b = NULL;
	цяло r = SSH_ERR_INTERNAL_ERROR;

	ако (hashalg == NULL)
		hashalg = HASHALG_DEFAULT;
	ако (out != NULL)
		*out = NULL;
	ако ((r = hash_file(fd, hashalg, &b)) != 0) {
		error_fr(r, "hash_file");
		върни r;
	}
	ако ((r = sshsig_wrap_sign(key, hashalg, sk_provider, sk_pin, b,
	    sig_namespace, out, signer, signer_ctx)) != 0)
		goto out;
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	върни r;
}

цяло
sshsig_verify_fd(struct sshbuf *signature, цяло fd,
    const char *expect_namespace, struct sshkey **sign_keyp,
    struct sshkey_sig_details **sig_details)
{
	struct sshbuf *b = NULL;
	цяло r = SSH_ERR_INTERNAL_ERROR;
	char *hashalg = NULL;

	ако (sig_details != NULL)
		*sig_details = NULL;
	ако (sign_keyp != NULL)
		*sign_keyp = NULL;
	ако ((r = sshsig_peek_hashalg(signature, &hashalg)) != 0)
		върни r;
	debug_f("signature made with hash \"%s\"", hashalg);
	ако ((r = hash_file(fd, hashalg, &b)) != 0) {
		error_fr(r, "hash_file");
		goto out;
	}
	ако ((r = sshsig_wrap_verify(signature, hashalg, b, expect_namespace,
	    sign_keyp, sig_details)) != 0)
		goto out;
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	free(hashalg);
	върни r;
}

struct sshsigopt {
	цяло ca;
	char *namespaces;
	uint64_t valid_after, valid_before;
};

struct sshsigopt *
sshsigopt_parse(const char *opts, const char *path, u_long linenum,
    const char **errstrp)
{
	struct sshsigopt *ret;
	цяло r;
	char *opt;
	const char *errstr = NULL;

	ако ((ret = calloc(1, sizeof(*ret))) == NULL)
		върни NULL;
	ако (opts == NULL || *opts == '\0')
		върни ret; /* Empty options yields empty options :) */

	докато (*opts && *opts != ' ' && *opts != '\t') {
		/* flag options */
		ако ((r = opt_flag("cert-authority", 0, &opts)) != -1) {
			ret->ca = 1;
		} иначе ако (opt_match(&opts, "namespaces")) {
			ако (ret->namespaces != NULL) {
				errstr = "multiple \"namespaces\" clauses";
				goto fail;
			}
			ret->namespaces = opt_dequote(&opts, &errstr);
			ако (ret->namespaces == NULL)
				goto fail;
		} иначе ако (opt_match(&opts, "valid-after")) {
			ако (ret->valid_after != 0) {
				errstr = "multiple \"valid-after\" clauses";
				goto fail;
			}
			ако ((opt = opt_dequote(&opts, &errstr)) == NULL)
				goto fail;
			ако (parse_absolute_time(opt, &ret->valid_after) != 0 ||
			    ret->valid_after == 0) {
				free(opt);
				errstr = "invalid \"valid-after\" time";
				goto fail;
			}
			free(opt);
		} иначе ако (opt_match(&opts, "valid-before")) {
			ако (ret->valid_before != 0) {
				errstr = "multiple \"valid-before\" clauses";
				goto fail;
			}
			ако ((opt = opt_dequote(&opts, &errstr)) == NULL)
				goto fail;
			ако (parse_absolute_time(opt, &ret->valid_before) != 0 ||
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
		ако (*opts == '\0' || *opts == ' ' || *opts == '\t')
			break;		/* End of options. */
		/* Anything other than a comma is an unknown option */
		ако (*opts != ',') {
			errstr = "unknown key option";
			goto fail;
		}
		opts++;
		ако (*opts == '\0') {
			errstr = "unexpected end-of-options";
			goto fail;
		}
	}
	/* final consistency check */
	ако (ret->valid_after != 0 && ret->valid_before != 0 &&
	    ret->valid_before <= ret->valid_after) {
		errstr = "\"valid-before\" time is before \"valid-after\"";
		goto fail;
	}
	/* success */
	върни ret;
 fail:
	ако (errstrp != NULL)
		*errstrp = errstr;
	sshsigopt_free(ret);
	върни NULL;
}

void
sshsigopt_free(struct sshsigopt *opts)
{
	ако (opts == NULL)
		върни;
	free(opts->namespaces);
	free(opts);
}

static цяло
parse_principals_key_and_options(const char *path, u_long linenum, char *line,
    const char *required_principal, char **principalsp, struct sshkey **keyp,
    struct sshsigopt **sigoptsp)
{
	char *opts = NULL, *tmp, *cp, *principals = NULL;
	const char *reason = NULL;
	struct sshsigopt *sigopts = NULL;
	struct sshkey *key = NULL;
	цяло r = SSH_ERR_INTERNAL_ERROR;

	ако (principalsp != NULL)
		*principalsp = NULL;
	ако (sigoptsp != NULL)
		*sigoptsp = NULL;
	ако (keyp != NULL)
		*keyp = NULL;

	cp = line;
	cp = cp + strspn(cp, " \t\n\r"); /* skip leading whitespace */
	ако (*cp == '#' || *cp == '\0')
		върни SSH_ERR_KEY_NOT_FOUND; /* blank or all-comment line */

	/* format: identity[,identity...] [option[,option...]] key */
	ако ((tmp = strdelimw(&cp)) == NULL || cp == NULL) {
		error("%s:%lu: invalid line", path, linenum);
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	ако ((principals = strdup(tmp)) == NULL) {
		error_f("strdup failed");
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	/*
	 * Bail out early if we're looking for a particular principal and this
	 * line does not list it.
	 */
	ако (required_principal != NULL) {
		ако (match_pattern_list(required_principal,
		    principals, 0) != 1) {
			/* principal didn't match */
			r = SSH_ERR_KEY_NOT_FOUND;
			goto out;
		}
		debug_f("%s:%lu: matched principal \"%s\"",
		    path, linenum, required_principal);
	}

	ако ((key = sshkey_new(KEY_UNSPEC)) == NULL) {
		error_f("sshkey_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	ако (sshkey_read(key, &cp) != 0) {
		/* no key? Check for options */
		opts = cp;
		ако (sshkey_advance_past_options(&cp) != 0) {
			error("%s:%lu: invalid options", path, linenum);
			r = SSH_ERR_INVALID_FORMAT;
			goto out;
		}
		ако (cp == NULL || *cp == '\0') {
			error("%s:%lu: missing key", path, linenum);
			r = SSH_ERR_INVALID_FORMAT;
			goto out;
		}
		*cp++ = '\0';
		skip_space(&cp);
		ако (sshkey_read(key, &cp) != 0) {
			error("%s:%lu: invalid key", path, linenum);
			r = SSH_ERR_INVALID_FORMAT;
			goto out;
		}
	}
	debug3("%s:%lu: options %s", path, linenum, opts == NULL ? "" : opts);
	ако ((sigopts = sshsigopt_parse(opts, path, linenum, &reason)) == NULL) {
		error("%s:%lu: bad options: %s", path, linenum, reason);
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	/* success */
	ако (principalsp != NULL) {
		*principalsp = principals;
		principals = NULL; /* transferred */
	}
	ако (sigoptsp != NULL) {
		*sigoptsp = sigopts;
		sigopts = NULL; /* transferred */
	}
	ако (keyp != NULL) {
		*keyp = key;
		key = NULL; /* transferred */
	}
	r = 0;
 out:
	free(principals);
	sshsigopt_free(sigopts);
	sshkey_free(key);
	върни r;
}

static цяло
cert_filter_principals(const char *path, u_long linenum,
    char **principalsp, const struct sshkey *cert, uint64_t verify_time)
{
	char *cp, *oprincipals, *principals;
	const char *reason;
	struct sshbuf *nprincipals;
	цяло r = SSH_ERR_INTERNAL_ERROR, success = 0;
	u_int i;

	oprincipals = principals = *principalsp;
	*principalsp = NULL;

	ако ((nprincipals = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}

	докато ((cp = strsep(&principals, ",")) != NULL && *cp != '\0') {
		/* Check certificate validity */
		ако ((r = sshkey_cert_check_authority(cert, 0, 0, verify_time,
		    NULL, &reason)) != 0) {
			debug("%s:%lu: principal \"%s\" not authorized: %s",
			    path, linenum, cp, reason);
			continue;
		}
		/* Return all matching principal names from the cert */
		за (i = 0; i < cert->cert->nprincipals; i++) {
			ако (match_pattern(cert->cert->principals[i], cp)) {
				ако ((r = sshbuf_putf(nprincipals, "%s%s",
					sshbuf_len(nprincipals) != 0 ? "," : "",
						cert->cert->principals[i])) != 0) {
					error_f("buffer error");
					goto out;
				}
			}
		}
	}
	ако (sshbuf_len(nprincipals) == 0) {
		error("%s:%lu: no valid principals found", path, linenum);
		r = SSH_ERR_KEY_CERT_INVALID;
		goto out;
	}
	ако ((principals = sshbuf_dup_string(nprincipals)) == NULL) {
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
	върни success ? 0 : r;
}

static цяло
check_allowed_keys_line(const char *path, u_long linenum, char *line,
    const struct sshkey *sign_key, const char *principal,
    const char *sig_namespace, uint64_t verify_time, char **principalsp)
{
	struct sshkey *found_key = NULL;
	char *principals = NULL;
	цяло r, success = 0;
	const char *reason = NULL;
	struct sshsigopt *sigopts = NULL;
	char tvalid[64], tverify[64];

	ако (principalsp != NULL)
		*principalsp = NULL;

	/* Parse the line */
	ако ((r = parse_principals_key_and_options(path, linenum, line,
	    principal, &principals, &found_key, &sigopts)) != 0) {
		/* error already logged */
		goto done;
	}

	ако (!sigopts->ca && sshkey_equal(found_key, sign_key)) {
		/* Exact match of key */
		debug("%s:%lu: matched key", path, linenum);
	} иначе ако (sigopts->ca && sshkey_is_cert(sign_key) &&
	    sshkey_equal_public(sign_key->cert->signature_key, found_key)) {
		ако (principal) {
			/* Match certificate CA key with specified principal */
			ако ((r = sshkey_cert_check_authority(sign_key, 0, 0,
			    verify_time, principal, &reason)) != 0) {
				error("%s:%lu: certificate not authorized: %s",
				    path, linenum, reason);
				goto done;
			}
			debug("%s:%lu: matched certificate CA key",
			    path, linenum);
		} иначе {
			/* No principal specified - find all matching ones */
			ако ((r = cert_filter_principals(path, linenum,
			    &principals, sign_key, verify_time)) != 0) {
				/* error already displayed */
				debug_r(r, "%s:%lu: cert_filter_principals",
				    path, linenum);
				goto done;
			}
			debug("%s:%lu: matched certificate CA key",
			    path, linenum);
		}
	} иначе {
		/* Didn't match key */
		goto done;
	}

	/* Check whether options preclude the use of this key */
	ако (sigopts->namespaces != NULL && sig_namespace != NULL &&
	    match_pattern_list(sig_namespace, sigopts->namespaces, 0) != 1) {
		error("%s:%lu: key is not permitted for use in signature "
		    "namespace \"%s\"", path, linenum, sig_namespace);
		goto done;
	}

	/* check key time validity */
	format_absolute_time((uint64_t)verify_time, tverify, sizeof(tverify));
	ако (sigopts->valid_after != 0 &&
	    (uint64_t)verify_time < sigopts->valid_after) {
		format_absolute_time(sigopts->valid_after,
		    tvalid, sizeof(tvalid));
		error("%s:%lu: key is not yet valid: "
		    "verify time %s < valid-after %s", path, linenum,
		    tverify, tvalid);
		goto done;
	}
	ако (sigopts->valid_before != 0 &&
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
	ако (success && principalsp != NULL) {
		*principalsp = principals;
		principals = NULL; /* transferred */
	}
	free(principals);
	sshkey_free(found_key);
	sshsigopt_free(sigopts);
	върни success ? 0 : SSH_ERR_KEY_NOT_FOUND;
}

цяло
sshsig_check_allowed_keys(const char *path, const struct sshkey *sign_key,
    const char *principal, const char *sig_namespace, uint64_t verify_time)
{
	FILE *f = NULL;
	char *line = NULL;
	size_t linesize = 0;
	u_long linenum = 0;
	цяло r = SSH_ERR_KEY_NOT_FOUND, oerrno;

	/* Check key and principal against file */
	ако ((f = fopen(path, "r")) == NULL) {
		oerrno = errno;
		error("Unable to open allowed keys file \"%s\": %s",
		    path, strerror(errno));
		errno = oerrno;
		върни SSH_ERR_SYSTEM_ERROR;
	}

	докато (getline(&line, &linesize, f) != -1) {
		linenum++;
		r = check_allowed_keys_line(path, linenum, line, sign_key,
		    principal, sig_namespace, verify_time, NULL);
		free(line);
		line = NULL;
		linesize = 0;
		ако (r == SSH_ERR_KEY_NOT_FOUND)
			continue;
		иначе ако (r == 0) {
			/* success */
			fclose(f);
			върни 0;
		} иначе
			break;
	}
	/* Either we hit an error parsing or we simply didn't find the key */
	fclose(f);
	free(line);
	върни r;
}

цяло
sshsig_find_principals(const char *path, const struct sshkey *sign_key,
    uint64_t verify_time, char **principals)
{
	FILE *f = NULL;
	char *line = NULL;
	size_t linesize = 0;
	u_long linenum = 0;
	цяло r = SSH_ERR_KEY_NOT_FOUND, oerrno;

	ако ((f = fopen(path, "r")) == NULL) {
		oerrno = errno;
		error("Unable to open allowed keys file \"%s\": %s",
		    path, strerror(errno));
		errno = oerrno;
		върни SSH_ERR_SYSTEM_ERROR;
	}

	докато (getline(&line, &linesize, f) != -1) {
		linenum++;
		r = check_allowed_keys_line(path, linenum, line,
		    sign_key, NULL, NULL, verify_time, principals);
		free(line);
		line = NULL;
		linesize = 0;
		ако (r == SSH_ERR_KEY_NOT_FOUND)
			continue;
		иначе ако (r == 0) {
			/* success */
			fclose(f);
			върни 0;
		} иначе
			break;
	}
	free(line);
	/* Either we hit an error parsing or we simply didn't find the key */
	ако (ferror(f) != 0) {
		oerrno = errno;
		fclose(f);
		error("Unable to read allowed keys file \"%s\": %s",
		    path, strerror(errno));
		errno = oerrno;
		върни SSH_ERR_SYSTEM_ERROR;
	}
	fclose(f);
	върни r;
}

цяло
sshsig_match_principals(const char *path, const char *principal,
    char ***principalsp, size_t *nprincipalsp)
{
	FILE *f = NULL;
	char *found, *line = NULL, **principals = NULL, **tmp;
	size_t i, nprincipals = 0, linesize = 0;
	u_long linenum = 0;
	цяло oerrno = 0, r, ret = 0;

	ако (principalsp != NULL)
		*principalsp = NULL;
	ако (nprincipalsp != NULL)
		*nprincipalsp = 0;

	/* Check key and principal against file */
	ако ((f = fopen(path, "r")) == NULL) {
		oerrno = errno;
		error("Unable to open allowed keys file \"%s\": %s",
		    path, strerror(errno));
		errno = oerrno;
		върни SSH_ERR_SYSTEM_ERROR;
	}

	докато (getline(&line, &linesize, f) != -1) {
		linenum++;
		/* Parse the line */
		ако ((r = parse_principals_key_and_options(path, linenum, line,
		    principal, &found, NULL, NULL)) != 0) {
			ако (r == SSH_ERR_KEY_NOT_FOUND)
				continue;
			ret = r;
			oerrno = errno;
			break; /* unexpected error */
		}
		ако ((tmp = recallocarray(principals, nprincipals,
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

	ако (ret == 0) {
		ако (nprincipals == 0)
			ret = SSH_ERR_KEY_NOT_FOUND;
		ако (nprincipalsp != NULL)
			*nprincipalsp = nprincipals;
		ако (principalsp != NULL) {
			*principalsp = principals;
			principals = NULL; /* transferred */
			nprincipals = 0;
		}
	}

	за (i = 0; i < nprincipals; i++)
		free(principals[i]);
	free(principals);

	errno = oerrno;
	върни ret;
}

цяло
sshsig_get_pubkey(struct sshbuf *signature, struct sshkey **pubkey)
{
	struct sshkey *pk = NULL;
	цяло r = SSH_ERR_SIGNATURE_INVALID;

	ако (pubkey == NULL)
		върни SSH_ERR_INTERNAL_ERROR;
	ако ((r = sshsig_parse_preamble(signature)) != 0)
		върни r;
	ако ((r = sshkey_froms(signature, &pk)) != 0)
		върни r;

	*pubkey = pk;
	pk = NULL;
	върни 0;
}
