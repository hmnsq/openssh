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

#अन्तर्भाव "includes.h"

#अन्तर्भाव <stdio.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <stdarg.h>
#अन्तर्भाव <errno.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <unistd.h>

#अन्तर्भाव "authfd.h"
#अन्तर्भाव "authfile.h"
#अन्तर्भाव "log.h"
#अन्तर्भाव "misc.h"
#अन्तर्भाव "sshbuf.h"
#अन्तर्भाव "sshsig.h"
#अन्तर्भाव "ssherr.h"
#अन्तर्भाव "sshkey.h"
#अन्तर्भाव "match.h"
#अन्तर्भाव "digest.h"

#define SIG_VERSION		0x01
#define MAGIC_PREAMBLE		"SSHSIG"
#define MAGIC_PREAMBLE_LEN	(परिमाण(MAGIC_PREAMBLE) - 1)
#define BEGIN_SIGNATURE		"-----BEGIN SSH SIGNATURE-----"
#define END_SIGNATURE		"-----END SSH SIGNATURE-----"
#define RSA_SIGN_ALG		"rsa-sha2-512"
#define RSA_SIGN_ALLOWED	"rsa-sha2-512,rsa-sha2-256"
#define HASHALG_DEFAULT		"sha512"
#define HASHALG_ALLOWED		"sha256,sha512"

पूर्णाङ्क
sshsig_armor(ध्रुव संरचना sshbuf *blob, संरचना sshbuf **out)
{
	संरचना sshbuf *buf = रिक्त;
	पूर्णाङ्क r = SSH_ERR_INTERNAL_ERROR;

	*out = रिक्त;

	सचे ((buf = sshbuf_new()) == रिक्त) {
		error_f("sshbuf_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ out;
	}

	सचे ((r = sshbuf_putf(buf, "%s\n", BEGIN_SIGNATURE)) != 0) {
		error_fr(r, "sshbuf_putf");
		गच्छ out;
	}

	सचे ((r = sshbuf_dtob64(blob, buf, 1)) != 0) {
		error_fr(r, "base64 encode signature");
		गच्छ out;
	}

	सचे ((r = sshbuf_put(buf, END_SIGNATURE,
	    परिमाण(END_SIGNATURE)-1)) != 0 ||
	    (r = sshbuf_put_u8(buf, '\n')) != 0) {
		error_fr(r, "sshbuf_put");
		गच्छ out;
	}
	/* success */
	*out = buf;
	buf = रिक्त; /* transferred */
	r = 0;
 out:
	sshbuf_free(buf);
	पटिनिवत्त r;
}

पूर्णाङ्क
sshsig_dearmor(संरचना sshbuf *sig, संरचना sshbuf **out)
{
	पूर्णाङ्क r;
	size_t eoffset = 0;
	संरचना sshbuf *buf = रिक्त;
	संरचना sshbuf *sbuf = रिक्त;
	वर्ण *b64 = रिक्त;

	सचे ((sbuf = sshbuf_fromb(sig)) == रिक्त) {
		error_f("sshbuf_fromb failed");
		पटिनिवत्त SSH_ERR_ALLOC_FAIL;
	}

	/* Expect and consume preamble + lf/crlf */
	सचे ((r = sshbuf_cmp(sbuf, 0,
	    BEGIN_SIGNATURE, परिमाण(BEGIN_SIGNATURE)-1)) != 0) {
		error("Couldn't parse signature: missing header");
		गच्छ done;
	}
	सचे ((r = sshbuf_consume(sbuf, परिमाण(BEGIN_SIGNATURE)-1)) != 0) {
		error_fr(r, "consume");
		गच्छ done;
	}
	सचे ((r = sshbuf_cmp(sbuf, 0, "\r\n", 2)) == 0)
		eoffset = 2;
	अञ्ञथा सचे ((r = sshbuf_cmp(sbuf, 0, "\n", 1)) == 0)
		eoffset = 1;
	अञ्ञथा {
		r = SSH_ERR_INVALID_FORMAT;
		error_f("no header eol");
		गच्छ done;
	}
	सचे ((r = sshbuf_consume(sbuf, eoffset)) != 0) {
		error_fr(r, "consume eol");
		गच्छ done;
	}
	/* Find and consume lf + suffix (any prior cr would be ignored) */
	सचे ((r = sshbuf_find(sbuf, 0, "\n" END_SIGNATURE,
	    परिमाण(END_SIGNATURE), &eoffset)) != 0) {
		error("Couldn't parse signature: missing footer");
		गच्छ done;
	}
	सचे ((r = sshbuf_consume_end(sbuf, sshbuf_len(sbuf)-eoffset)) != 0) {
		error_fr(r, "consume");
		गच्छ done;
	}

	सचे ((b64 = sshbuf_dup_string(sbuf)) == रिक्त) {
		error_f("sshbuf_dup_string failed");
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ done;
	}

	सचे ((buf = sshbuf_new()) == रिक्त) {
		error_f("sshbuf_new() failed");
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ done;
	}

	सचे ((r = sshbuf_b64tod(buf, b64)) != 0) {
		error_fr(r, "decode base64");
		गच्छ done;
	}

	/* success */
	*out = buf;
	r = 0;
	buf = रिक्त; /* transferred */
done:
	sshbuf_free(buf);
	sshbuf_free(sbuf);
	मुक्त(b64);
	पटिनिवत्त r;
}

स्थिर पूर्णाङ्क
sshsig_wrap_sign(संरचना sshkey *कुञ्चिका, ध्रुव वर्ण *hashalg,
    ध्रुव वर्ण *sk_provider, ध्रुव वर्ण *sk_pin, ध्रुव संरचना sshbuf *h_message,
    ध्रुव वर्ण *sig_namespace, संरचना sshbuf **out,
    sshsig_signer *signer, शून्य *signer_ctx)
{
	पूर्णाङ्क r;
	size_t slen = 0;
	u_char *sig = रिक्त;
	संरचना sshbuf *blob = रिक्त;
	संरचना sshbuf *tosign = रिक्त;
	ध्रुव वर्ण *sign_alg = रिक्त;

	सचे ((tosign = sshbuf_new()) == रिक्त ||
	    (blob = sshbuf_new()) == रिक्त) {
		error_f("sshbuf_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ done;
	}

	सचे ((r = sshbuf_put(tosign, MAGIC_PREAMBLE, MAGIC_PREAMBLE_LEN)) != 0 ||
	    (r = sshbuf_put_cstring(tosign, sig_namespace)) != 0 ||
	    (r = sshbuf_put_string(tosign, रिक्त, 0)) != 0 || /* reserved */
	    (r = sshbuf_put_cstring(tosign, hashalg)) != 0 ||
	    (r = sshbuf_put_stringb(tosign, h_message)) != 0) {
		error_fr(r, "assemble message to sign");
		गच्छ done;
	}

	/* If using RSA keys then default to a good signature algorithm */
	सचे (sshkey_type_plain(कुञ्चिका->type) == कुञ्चिका_RSA) {
		sign_alg = RSA_SIGN_ALG;
		सचे (strcmp(hashalg, "sha256") == 0)
			sign_alg = "rsa-sha2-256";
		अञ्ञथा सचे (strcmp(hashalg, "sha512") == 0)
			sign_alg = "rsa-sha2-512";
	}

	सचे (signer != रिक्त) {
		सचे ((r = signer(कुञ्चिका, &sig, &slen,
		    sshbuf_ptr(tosign), sshbuf_len(tosign),
		    sign_alg, sk_provider, sk_pin, 0, signer_ctx)) != 0) {
			error_r(r, "Couldn't sign message (signer)");
			गच्छ done;
		}
	} अञ्ञथा {
		सचे ((r = sshkey_sign(कुञ्चिका, &sig, &slen,
		    sshbuf_ptr(tosign), sshbuf_len(tosign),
		    sign_alg, sk_provider, sk_pin, 0)) != 0) {
			error_r(r, "Couldn't sign message");
			गच्छ done;
		}
	}

	सचे ((r = sshbuf_put(blob, MAGIC_PREAMBLE, MAGIC_PREAMBLE_LEN)) != 0 ||
	    (r = sshbuf_put_u32(blob, SIG_VERSION)) != 0 ||
	    (r = sshkey_puts(कुञ्चिका, blob)) != 0 ||
	    (r = sshbuf_put_cstring(blob, sig_namespace)) != 0 ||
	    (r = sshbuf_put_string(blob, रिक्त, 0)) != 0 || /* reserved */
	    (r = sshbuf_put_cstring(blob, hashalg)) != 0 ||
	    (r = sshbuf_put_string(blob, sig, slen)) != 0) {
		error_fr(r, "assemble signature object");
		गच्छ done;
	}

	सचे (out != रिक्त) {
		*out = blob;
		blob = रिक्त;
	}
	r = 0;
done:
	मुक्त(sig);
	sshbuf_free(blob);
	sshbuf_free(tosign);
	पटिनिवत्त r;
}

/* Check preamble and version. */
स्थिर पूर्णाङ्क
sshsig_parse_preamble(संरचना sshbuf *buf)
{
	पूर्णाङ्क r = SSH_ERR_INTERNAL_ERROR;
	uint32_t sversion;

	सचे ((r = sshbuf_cmp(buf, 0, MAGIC_PREAMBLE, MAGIC_PREAMBLE_LEN)) != 0 ||
	    (r = sshbuf_consume(buf, (परिमाण(MAGIC_PREAMBLE)-1))) != 0 ||
	    (r = sshbuf_get_u32(buf, &sversion)) != 0) {
		error("Couldn't verify signature: invalid format");
		पटिनिवत्त r;
	}

	सचे (sversion > SIG_VERSION) {
		error("Signature version %lu is larger than supported "
		    "version %u", (unsigned long)sversion, SIG_VERSION);
		पटिनिवत्त SSH_ERR_INVALID_FORMAT;
	}
	पटिनिवत्त 0;
}

स्थिर पूर्णाङ्क
sshsig_check_hashalg(ध्रुव वर्ण *hashalg)
{
	सचे (hashalg == रिक्त ||
	    match_pattern_list(hashalg, HASHALG_ALLOWED, 0) == 1)
		पटिनिवत्त 0;
	error_f("unsupported hash algorithm \"%.100s\"", hashalg);
	पटिनिवत्त SSH_ERR_SIGN_ALG_UNSUPPORTED;
}

स्थिर पूर्णाङ्क
sshsig_peek_hashalg(संरचना sshbuf *signature, वर्ण **hashalgp)
{
	संरचना sshbuf *buf = रिक्त;
	वर्ण *hashalg = रिक्त;
	पूर्णाङ्क r = SSH_ERR_INTERNAL_ERROR;

	सचे (hashalgp != रिक्त)
		*hashalgp = रिक्त;
	सचे ((buf = sshbuf_fromb(signature)) == रिक्त)
		पटिनिवत्त SSH_ERR_ALLOC_FAIL;
	सचे ((r = sshsig_parse_preamble(buf)) != 0)
		गच्छ done;
	सचे ((r = sshbuf_get_string_direct(buf, रिक्त, रिक्त)) != 0 ||
	    (r = sshbuf_get_string_direct(buf, रिक्त, रिक्त)) != 0 ||
	    (r = sshbuf_get_string(buf, रिक्त, रिक्त)) != 0 ||
	    (r = sshbuf_get_cstring(buf, &hashalg, रिक्त)) != 0 ||
	    (r = sshbuf_get_string_direct(buf, रिक्त, रिक्त)) != 0) {
		error_fr(r, "parse signature object");
		गच्छ done;
	}

	/* success */
	r = 0;
	*hashalgp = hashalg;
	hashalg = रिक्त;
 done:
	मुक्त(hashalg);
	sshbuf_free(buf);
	पटिनिवत्त r;
}

स्थिर पूर्णाङ्क
sshsig_wrap_verify(संरचना sshbuf *signature, ध्रुव वर्ण *hashalg,
    ध्रुव संरचना sshbuf *h_message, ध्रुव वर्ण *expect_namespace,
    संरचना sshkey **sign_keyp, संरचना sshkey_sig_details **sig_details)
{
	पूर्णाङ्क r = SSH_ERR_INTERNAL_ERROR;
	संरचना sshbuf *buf = रिक्त, *toverify = रिक्त;
	संरचना sshkey *कुञ्चिका = रिक्त;
	ध्रुव u_char *sig;
	वर्ण *got_namespace = रिक्त, *sigtype = रिक्त, *sig_hashalg = रिक्त;
	size_t siglen;

	debug_f("verify message length %zu", sshbuf_len(h_message));
	सचे (sig_details != रिक्त)
		*sig_details = रिक्त;
	सचे (sign_keyp != रिक्त)
		*sign_keyp = रिक्त;

	सचे ((toverify = sshbuf_new()) == रिक्त) {
		error_f("sshbuf_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ done;
	}
	सचे ((r = sshbuf_put(toverify, MAGIC_PREAMBLE,
	    MAGIC_PREAMBLE_LEN)) != 0 ||
	    (r = sshbuf_put_cstring(toverify, expect_namespace)) != 0 ||
	    (r = sshbuf_put_string(toverify, रिक्त, 0)) != 0 || /* reserved */
	    (r = sshbuf_put_cstring(toverify, hashalg)) != 0 ||
	    (r = sshbuf_put_stringb(toverify, h_message)) != 0) {
		error_fr(r, "assemble message to verify");
		गच्छ done;
	}

	सचे ((r = sshsig_parse_preamble(signature)) != 0)
		गच्छ done;

	सचे ((r = sshkey_froms(signature, &कुञ्चिका)) != 0 ||
	    (r = sshbuf_get_cstring(signature, &got_namespace, रिक्त)) != 0 ||
	    (r = sshbuf_get_string(signature, रिक्त, रिक्त)) != 0 ||
	    (r = sshbuf_get_cstring(signature, &sig_hashalg, रिक्त)) != 0 ||
	    (r = sshbuf_get_string_direct(signature, &sig, &siglen)) != 0) {
		error_fr(r, "parse signature object");
		गच्छ done;
	}

	सचे (sshbuf_len(signature) != 0) {
		error("Signature contains trailing data");
		r = SSH_ERR_INVALID_FORMAT;
		गच्छ done;
	}

	सचे (strcmp(expect_namespace, got_namespace) != 0) {
		error("Couldn't verify signature: namespace does not match");
		debug_f("expected namespace \"%s\" received \"%s\"",
		    expect_namespace, got_namespace);
		r = SSH_ERR_SIGNATURE_INVALID;
		गच्छ done;
	}
	सचे (strcmp(hashalg, sig_hashalg) != 0) {
		error("Couldn't verify signature: hash algorithm mismatch");
		debug_f("expected algorithm \"%s\" received \"%s\"",
		    hashalg, sig_hashalg);
		r = SSH_ERR_SIGNATURE_INVALID;
		गच्छ done;
	}
	/* Ensure that RSA keys use an acceptable signature algorithm */
	सचे (sshkey_type_plain(कुञ्चिका->type) == कुञ्चिका_RSA) {
		सचे ((r = sshkey_get_sigtype(sig, siglen, &sigtype)) != 0) {
			error_r(r, "Couldn't verify signature: unable to get "
			    "signature type");
			गच्छ done;
		}
		सचे (match_pattern_list(sigtype, RSA_SIGN_ALLOWED, 0) != 1) {
			error("Couldn't verify signature: unsupported RSA "
			    "signature algorithm %s", sigtype);
			r = SSH_ERR_SIGN_ALG_UNSUPPORTED;
			गच्छ done;
		}
	}
	सचे ((r = sshkey_verify(कुञ्चिका, sig, siglen, sshbuf_ptr(toverify),
	    sshbuf_len(toverify), रिक्त, 0, sig_details)) != 0) {
		error_r(r, "Signature verification failed");
		गच्छ done;
	}

	/* success */
	r = 0;
	सचे (sign_keyp != रिक्त) {
		*sign_keyp = कुञ्चिका;
		कुञ्चिका = रिक्त; /* transferred */
	}
done:
	मुक्त(got_namespace);
	मुक्त(sigtype);
	मुक्त(sig_hashalg);
	sshbuf_free(buf);
	sshbuf_free(toverify);
	sshkey_free(कुञ्चिका);
	पटिनिवत्त r;
}

स्थिर पूर्णाङ्क
hash_buffer(ध्रुव संरचना sshbuf *m, ध्रुव वर्ण *hashalg, संरचना sshbuf **bp)
{
	वर्ण *hex, hash[SSH_DIGEST_MAX_LENGTH];
	पूर्णाङ्क alg, r = SSH_ERR_INTERNAL_ERROR;
	संरचना sshbuf *b = रिक्त;

	*bp = रिक्त;
	memset(hash, 0, परिमाण(hash));

	सचे ((r = sshsig_check_hashalg(hashalg)) != 0)
		पटिनिवत्त r;
	सचे ((alg = ssh_digest_alg_by_name(hashalg)) == -1) {
		error_f("can't look up hash algorithm %s", hashalg);
		पटिनिवत्त SSH_ERR_INTERNAL_ERROR;
	}
	सचे ((r = ssh_digest_buffer(alg, m, hash, परिमाण(hash))) != 0) {
		error_fr(r, "ssh_digest_buffer");
		पटिनिवत्त r;
	}
	सचे ((hex = tohex(hash, ssh_digest_bytes(alg))) != रिक्त) {
		debug3_f("final hash: %s", hex);
		freezero(hex, strlen(hex));
	}
	सचे ((b = sshbuf_new()) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ out;
	}
	सचे ((r = sshbuf_put(b, hash, ssh_digest_bytes(alg))) != 0) {
		error_fr(r, "sshbuf_put");
		गच्छ out;
	}
	*bp = b;
	b = रिक्त; /* transferred */
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	explicit_bzero(hash, परिमाण(hash));
	पटिनिवत्त r;
}

पूर्णाङ्क
sshsig_signb(संरचना sshkey *कुञ्चिका, ध्रुव वर्ण *hashalg,
    ध्रुव वर्ण *sk_provider, ध्रुव वर्ण *sk_pin,
    ध्रुव संरचना sshbuf *message, ध्रुव वर्ण *sig_namespace,
    संरचना sshbuf **out, sshsig_signer *signer, शून्य *signer_ctx)
{
	संरचना sshbuf *b = रिक्त;
	पूर्णाङ्क r = SSH_ERR_INTERNAL_ERROR;

	सचे (hashalg == रिक्त)
		hashalg = HASHALG_DEFAULT;
	सचे (out != रिक्त)
		*out = रिक्त;
	सचे ((r = hash_buffer(message, hashalg, &b)) != 0) {
		error_fr(r, "hash buffer");
		गच्छ out;
	}
	सचे ((r = sshsig_wrap_sign(कुञ्चिका, hashalg, sk_provider, sk_pin, b,
	    sig_namespace, out, signer, signer_ctx)) != 0)
		गच्छ out;
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	पटिनिवत्त r;
}

पूर्णाङ्क
sshsig_verifyb(संरचना sshbuf *signature, ध्रुव संरचना sshbuf *message,
    ध्रुव वर्ण *expect_namespace, संरचना sshkey **sign_keyp,
    संरचना sshkey_sig_details **sig_details)
{
	संरचना sshbuf *b = रिक्त;
	पूर्णाङ्क r = SSH_ERR_INTERNAL_ERROR;
	वर्ण *hashalg = रिक्त;

	सचे (sig_details != रिक्त)
		*sig_details = रिक्त;
	सचे (sign_keyp != रिक्त)
		*sign_keyp = रिक्त;
	सचे ((r = sshsig_peek_hashalg(signature, &hashalg)) != 0)
		पटिनिवत्त r;
	debug_f("signature made with hash \"%s\"", hashalg);
	सचे ((r = hash_buffer(message, hashalg, &b)) != 0) {
		error_fr(r, "hash buffer");
		गच्छ out;
	}
	सचे ((r = sshsig_wrap_verify(signature, hashalg, b, expect_namespace,
	    sign_keyp, sig_details)) != 0)
		गच्छ out;
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	मुक्त(hashalg);
	पटिनिवत्त r;
}

स्थिर पूर्णाङ्क
hash_file(पूर्णाङ्क fd, ध्रुव वर्ण *hashalg, संरचना sshbuf **bp)
{
	वर्ण *hex, rbuf[8192], hash[SSH_DIGEST_MAX_LENGTH];
	ssize_t n, total = 0;
	संरचना ssh_digest_ctx *ctx = रिक्त;
	पूर्णाङ्क alg, oerrno, r = SSH_ERR_INTERNAL_ERROR;
	संरचना sshbuf *b = रिक्त;

	*bp = रिक्त;
	memset(hash, 0, परिमाण(hash));

	सचे ((r = sshsig_check_hashalg(hashalg)) != 0)
		पटिनिवत्त r;
	सचे ((alg = ssh_digest_alg_by_name(hashalg)) == -1) {
		error_f("can't look up hash algorithm %s", hashalg);
		पटिनिवत्त SSH_ERR_INTERNAL_ERROR;
	}
	सचे ((ctx = ssh_digest_start(alg)) == रिक्त) {
		error_f("ssh_digest_start failed");
		पटिनिवत्त SSH_ERR_INTERNAL_ERROR;
	}
	अत्थाय (;;) {
		सचे ((n = पठ(fd, rbuf, परिमाण(rbuf))) == -1) {
			सचे (errno == EINTR || errno == EAGAIN)
				अनुवर्त;
			oerrno = errno;
			error_f("read: %s", strerror(errno));
			errno = oerrno;
			r = SSH_ERR_SYSTEM_ERROR;
			गच्छ out;
		} अञ्ञथा सचे (n == 0) {
			debug2_f("hashed %zu bytes", total);
			भङ्ग; /* EOF */
		}
		total += (size_t)n;
		सचे ((r = ssh_digest_update(ctx, rbuf, (size_t)n)) != 0) {
			error_fr(r, "ssh_digest_update");
			गच्छ out;
		}
	}
	सचे ((r = ssh_digest_final(ctx, hash, परिमाण(hash))) != 0) {
		error_fr(r, "ssh_digest_final");
		गच्छ out;
	}
	सचे ((hex = tohex(hash, ssh_digest_bytes(alg))) != रिक्त) {
		debug3_f("final hash: %s", hex);
		freezero(hex, strlen(hex));
	}
	सचे ((b = sshbuf_new()) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ out;
	}
	सचे ((r = sshbuf_put(b, hash, ssh_digest_bytes(alg))) != 0) {
		error_fr(r, "sshbuf_put");
		गच्छ out;
	}
	*bp = b;
	b = रिक्त; /* transferred */
	/* success */
	r = 0;
 out:
	oerrno = errno;
	sshbuf_free(b);
	ssh_digest_free(ctx);
	explicit_bzero(hash, परिमाण(hash));
	errno = oerrno;
	पटिनिवत्त r;
}

पूर्णाङ्क
sshsig_sign_fd(संरचना sshkey *कुञ्चिका, ध्रुव वर्ण *hashalg,
    ध्रुव वर्ण *sk_provider, ध्रुव वर्ण *sk_pin,
    पूर्णाङ्क fd, ध्रुव वर्ण *sig_namespace, संरचना sshbuf **out,
    sshsig_signer *signer, शून्य *signer_ctx)
{
	संरचना sshbuf *b = रिक्त;
	पूर्णाङ्क r = SSH_ERR_INTERNAL_ERROR;

	सचे (hashalg == रिक्त)
		hashalg = HASHALG_DEFAULT;
	सचे (out != रिक्त)
		*out = रिक्त;
	सचे ((r = hash_file(fd, hashalg, &b)) != 0) {
		error_fr(r, "hash_file");
		पटिनिवत्त r;
	}
	सचे ((r = sshsig_wrap_sign(कुञ्चिका, hashalg, sk_provider, sk_pin, b,
	    sig_namespace, out, signer, signer_ctx)) != 0)
		गच्छ out;
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	पटिनिवत्त r;
}

पूर्णाङ्क
sshsig_verify_fd(संरचना sshbuf *signature, पूर्णाङ्क fd,
    ध्रुव वर्ण *expect_namespace, संरचना sshkey **sign_keyp,
    संरचना sshkey_sig_details **sig_details)
{
	संरचना sshbuf *b = रिक्त;
	पूर्णाङ्क r = SSH_ERR_INTERNAL_ERROR;
	वर्ण *hashalg = रिक्त;

	सचे (sig_details != रिक्त)
		*sig_details = रिक्त;
	सचे (sign_keyp != रिक्त)
		*sign_keyp = रिक्त;
	सचे ((r = sshsig_peek_hashalg(signature, &hashalg)) != 0)
		पटिनिवत्त r;
	debug_f("signature made with hash \"%s\"", hashalg);
	सचे ((r = hash_file(fd, hashalg, &b)) != 0) {
		error_fr(r, "hash_file");
		गच्छ out;
	}
	सचे ((r = sshsig_wrap_verify(signature, hashalg, b, expect_namespace,
	    sign_keyp, sig_details)) != 0)
		गच्छ out;
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	मुक्त(hashalg);
	पटिनिवत्त r;
}

संरचना sshsigopt {
	पूर्णाङ्क ca;
	वर्ण *namespaces;
	uint64_t valid_after, valid_before;
};

संरचना sshsigopt *
sshsigopt_parse(ध्रुव वर्ण *opts, ध्रुव वर्ण *path, u_long linenum,
    ध्रुव वर्ण **errstrp)
{
	संरचना sshsigopt *ret;
	पूर्णाङ्क r;
	वर्ण *opt;
	ध्रुव वर्ण *errstr = रिक्त;

	सचे ((ret = calloc(1, परिमाण(*ret))) == रिक्त)
		पटिनिवत्त रिक्त;
	सचे (opts == रिक्त || *opts == '\0')
		पटिनिवत्त ret; /* Empty options yields empty options :) */

	याव (*opts && *opts != ' ' && *opts != '\t') {
		/* flag options */
		सचे ((r = opt_flag("cert-authority", 0, &opts)) != -1) {
			ret->ca = 1;
		} अञ्ञथा सचे (opt_match(&opts, "namespaces")) {
			सचे (ret->namespaces != रिक्त) {
				errstr = "multiple \"namespaces\" clauses";
				गच्छ fail;
			}
			ret->namespaces = opt_dequote(&opts, &errstr);
			सचे (ret->namespaces == रिक्त)
				गच्छ fail;
		} अञ्ञथा सचे (opt_match(&opts, "valid-after")) {
			सचे (ret->valid_after != 0) {
				errstr = "multiple \"valid-after\" clauses";
				गच्छ fail;
			}
			सचे ((opt = opt_dequote(&opts, &errstr)) == रिक्त)
				गच्छ fail;
			सचे (parse_absolute_time(opt, &ret->valid_after) != 0 ||
			    ret->valid_after == 0) {
				मुक्त(opt);
				errstr = "invalid \"valid-after\" time";
				गच्छ fail;
			}
			मुक्त(opt);
		} अञ्ञथा सचे (opt_match(&opts, "valid-before")) {
			सचे (ret->valid_before != 0) {
				errstr = "multiple \"valid-before\" clauses";
				गच्छ fail;
			}
			सचे ((opt = opt_dequote(&opts, &errstr)) == रिक्त)
				गच्छ fail;
			सचे (parse_absolute_time(opt, &ret->valid_before) != 0 ||
			    ret->valid_before == 0) {
				मुक्त(opt);
				errstr = "invalid \"valid-before\" time";
				गच्छ fail;
			}
			मुक्त(opt);
		}
		/*
		 * Skip the comma, and move to the next option
		 * (or break out if there are no more).
		 */
		सचे (*opts == '\0' || *opts == ' ' || *opts == '\t')
			भङ्ग;		/* End of options. */
		/* Anything other than a comma is an unknown option */
		सचे (*opts != ',') {
			errstr = "unknown key option";
			गच्छ fail;
		}
		opts++;
		सचे (*opts == '\0') {
			errstr = "unexpected end-of-options";
			गच्छ fail;
		}
	}
	/* final consistency check */
	सचे (ret->valid_after != 0 && ret->valid_before != 0 &&
	    ret->valid_before <= ret->valid_after) {
		errstr = "\"valid-before\" time is before \"valid-after\"";
		गच्छ fail;
	}
	/* success */
	पटिनिवत्त ret;
 fail:
	सचे (errstrp != रिक्त)
		*errstrp = errstr;
	sshsigopt_free(ret);
	पटिनिवत्त रिक्त;
}

शून्य
sshsigopt_free(संरचना sshsigopt *opts)
{
	सचे (opts == रिक्त)
		पटिनिवत्त;
	मुक्त(opts->namespaces);
	मुक्त(opts);
}

स्थिर पूर्णाङ्क
parse_principals_कुञ्चिका_and_options(ध्रुव वर्ण *path, u_long linenum, वर्ण *पङ्क्तिः,
    ध्रुव वर्ण *required_principal, वर्ण **principalsp, संरचना sshkey **keyp,
    संरचना sshsigopt **sigoptsp)
{
	वर्ण *opts = रिक्त, *tmp, *cp, *principals = रिक्त;
	ध्रुव वर्ण *reason = रिक्त;
	संरचना sshsigopt *sigopts = रिक्त;
	संरचना sshkey *कुञ्चिका = रिक्त;
	पूर्णाङ्क r = SSH_ERR_INTERNAL_ERROR;

	सचे (principalsp != रिक्त)
		*principalsp = रिक्त;
	सचे (sigoptsp != रिक्त)
		*sigoptsp = रिक्त;
	सचे (keyp != रिक्त)
		*keyp = रिक्त;

	cp = पङ्क्तिः;
	cp = cp + strspn(cp, " \t\n\r"); /* skip leading whitespace */
	सचे (*cp == '#' || *cp == '\0')
		पटिनिवत्त SSH_ERR_कुञ्चिका_NOT_FOUND; /* blank or all-comment line */

	/* format: identity[,identity...] [option[,option...]] key */
	सचे ((tmp = strdelimw(&cp)) == रिक्त || cp == रिक्त) {
		error("%s:%lu: invalid line", path, linenum);
		r = SSH_ERR_INVALID_FORMAT;
		गच्छ out;
	}
	सचे ((principals = strdup(tmp)) == रिक्त) {
		error_f("strdup failed");
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ out;
	}
	/*
	 * Bail out early if we're looking for a particular principal and this
	 * line does not list it.
	 */
	सचे (required_principal != रिक्त) {
		सचे (match_pattern_list(required_principal,
		    principals, 0) != 1) {
			/* principal didn't match */
			r = SSH_ERR_कुञ्चिका_NOT_FOUND;
			गच्छ out;
		}
		debug_f("%s:%lu: matched principal \"%s\"",
		    path, linenum, required_principal);
	}

	सचे ((कुञ्चिका = sshkey_new(कुञ्चिका_UNSPEC)) == रिक्त) {
		error_f("sshkey_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ out;
	}
	सचे (sshkey_read(कुञ्चिका, &cp) != 0) {
		/* no key? Check for options */
		opts = cp;
		सचे (sshkey_advance_past_options(&cp) != 0) {
			error("%s:%lu: invalid options", path, linenum);
			r = SSH_ERR_INVALID_FORMAT;
			गच्छ out;
		}
		सचे (cp == रिक्त || *cp == '\0') {
			error("%s:%lu: missing key", path, linenum);
			r = SSH_ERR_INVALID_FORMAT;
			गच्छ out;
		}
		*cp++ = '\0';
		skip_space(&cp);
		सचे (sshkey_read(कुञ्चिका, &cp) != 0) {
			error("%s:%lu: invalid key", path, linenum);
			r = SSH_ERR_INVALID_FORMAT;
			गच्छ out;
		}
	}
	debug3("%s:%lu: options %s", path, linenum, opts == रिक्त ? "" : opts);
	सचे ((sigopts = sshsigopt_parse(opts, path, linenum, &reason)) == रिक्त) {
		error("%s:%lu: bad options: %s", path, linenum, reason);
		r = SSH_ERR_INVALID_FORMAT;
		गच्छ out;
	}
	/* success */
	सचे (principalsp != रिक्त) {
		*principalsp = principals;
		principals = रिक्त; /* transferred */
	}
	सचे (sigoptsp != रिक्त) {
		*sigoptsp = sigopts;
		sigopts = रिक्त; /* transferred */
	}
	सचे (keyp != रिक्त) {
		*keyp = कुञ्चिका;
		कुञ्चिका = रिक्त; /* transferred */
	}
	r = 0;
 out:
	मुक्त(principals);
	sshsigopt_free(sigopts);
	sshkey_free(कुञ्चिका);
	पटिनिवत्त r;
}

स्थिर पूर्णाङ्क
cert_filter_principals(ध्रुव वर्ण *path, u_long linenum,
    वर्ण **principalsp, ध्रुव संरचना sshkey *cert, uint64_t verify_time)
{
	वर्ण *cp, *oprincipals, *principals;
	ध्रुव वर्ण *reason;
	संरचना sshbuf *nprincipals;
	पूर्णाङ्क r = SSH_ERR_INTERNAL_ERROR, success = 0;
	u_int i;

	oprincipals = principals = *principalsp;
	*principalsp = रिक्त;

	सचे ((nprincipals = sshbuf_new()) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ out;
	}

	याव ((cp = strsep(&principals, ",")) != रिक्त && *cp != '\0') {
		/* Check certificate validity */
		सचे ((r = sshkey_cert_check_authority(cert, 0, 0, verify_time,
		    रिक्त, &reason)) != 0) {
			debug("%s:%lu: principal \"%s\" not authorized: %s",
			    path, linenum, cp, reason);
			अनुवर्त;
		}
		/* Return all matching principal names from the cert */
		अत्थाय (i = 0; i < cert->cert->nprincipals; i++) {
			सचे (match_pattern(cert->cert->principals[i], cp)) {
				सचे ((r = sshbuf_putf(nprincipals, "%s%s",
					sshbuf_len(nprincipals) != 0 ? "," : "",
						cert->cert->principals[i])) != 0) {
					error_f("buffer error");
					गच्छ out;
				}
			}
		}
	}
	सचे (sshbuf_len(nprincipals) == 0) {
		error("%s:%lu: no valid principals found", path, linenum);
		r = SSH_ERR_कुञ्चिका_CERT_INVALID;
		गच्छ out;
	}
	सचे ((principals = sshbuf_dup_string(nprincipals)) == रिक्त) {
		error_f("buffer error");
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ out;
	}
	/* success */
	success = 1;
	*principalsp = principals;
 out:
	sshbuf_free(nprincipals);
	मुक्त(oprincipals);
	पटिनिवत्त success ? 0 : r;
}

स्थिर पूर्णाङ्क
check_allowed_कुञ्चिकाः_पङ्क्तिः(ध्रुव वर्ण *path, u_long linenum, वर्ण *पङ्क्तिः,
    ध्रुव संरचना sshkey *sign_कुञ्चिका, ध्रुव वर्ण *principal,
    ध्रुव वर्ण *sig_namespace, uint64_t verify_time, वर्ण **principalsp)
{
	संरचना sshkey *found_कुञ्चिका = रिक्त;
	वर्ण *principals = रिक्त;
	पूर्णाङ्क r, success = 0;
	ध्रुव वर्ण *reason = रिक्त;
	संरचना sshsigopt *sigopts = रिक्त;
	वर्ण tvalid[64], tverify[64];

	सचे (principalsp != रिक्त)
		*principalsp = रिक्त;

	/* Parse the line */
	सचे ((r = parse_principals_कुञ्चिका_and_options(path, linenum, पङ्क्तिः,
	    principal, &principals, &found_कुञ्चिका, &sigopts)) != 0) {
		/* error already logged */
		गच्छ done;
	}

	सचे (!sigopts->ca && sshkey_equal(found_कुञ्चिका, sign_कुञ्चिका)) {
		/* Exact match of key */
		debug("%s:%lu: matched key", path, linenum);
	} अञ्ञथा सचे (sigopts->ca && sshkey_is_cert(sign_कुञ्चिका) &&
	    sshkey_equal_public(sign_कुञ्चिका->cert->signature_कुञ्चिका, found_कुञ्चिका)) {
		सचे (principal) {
			/* Match certificate CA key with specified principal */
			सचे ((r = sshkey_cert_check_authority(sign_कुञ्चिका, 0, 0,
			    verify_time, principal, &reason)) != 0) {
				error("%s:%lu: certificate not authorized: %s",
				    path, linenum, reason);
				गच्छ done;
			}
			debug("%s:%lu: matched certificate CA key",
			    path, linenum);
		} अञ्ञथा {
			/* No principal specified - find all matching ones */
			सचे ((r = cert_filter_principals(path, linenum,
			    &principals, sign_कुञ्चिका, verify_time)) != 0) {
				/* error already displayed */
				debug_r(r, "%s:%lu: cert_filter_principals",
				    path, linenum);
				गच्छ done;
			}
			debug("%s:%lu: matched certificate CA key",
			    path, linenum);
		}
	} अञ्ञथा {
		/* Didn't match key */
		गच्छ done;
	}

	/* Check whether options preclude the use of this key */
	सचे (sigopts->namespaces != रिक्त && sig_namespace != रिक्त &&
	    match_pattern_list(sig_namespace, sigopts->namespaces, 0) != 1) {
		error("%s:%lu: key is not permitted for use in signature "
		    "namespace \"%s\"", path, linenum, sig_namespace);
		गच्छ done;
	}

	/* check key time validity */
	format_absolute_time((uint64_t)verify_time, tverify, परिमाण(tverify));
	सचे (sigopts->valid_after != 0 &&
	    (uint64_t)verify_time < sigopts->valid_after) {
		format_absolute_time(sigopts->valid_after,
		    tvalid, परिमाण(tvalid));
		error("%s:%lu: key is not yet valid: "
		    "verify time %s < valid-after %s", path, linenum,
		    tverify, tvalid);
		गच्छ done;
	}
	सचे (sigopts->valid_before != 0 &&
	    (uint64_t)verify_time > sigopts->valid_before) {
		format_absolute_time(sigopts->valid_before,
		    tvalid, परिमाण(tvalid));
		error("%s:%lu: key has expired: "
		    "verify time %s > valid-before %s", path, linenum,
		    tverify, tvalid);
		गच्छ done;
	}
	success = 1;

 done:
	सचे (success && principalsp != रिक्त) {
		*principalsp = principals;
		principals = रिक्त; /* transferred */
	}
	मुक्त(principals);
	sshkey_free(found_कुञ्चिका);
	sshsigopt_free(sigopts);
	पटिनिवत्त success ? 0 : SSH_ERR_कुञ्चिका_NOT_FOUND;
}

पूर्णाङ्क
sshsig_check_allowed_कुञ्चिकाः(ध्रुव वर्ण *path, ध्रुव संरचना sshkey *sign_कुञ्चिका,
    ध्रुव वर्ण *principal, ध्रुव वर्ण *sig_namespace, uint64_t verify_time)
{
	FILE *f = रिक्त;
	वर्ण *पङ्क्तिः = रिक्त;
	size_t linesize = 0;
	u_long linenum = 0;
	पूर्णाङ्क r = SSH_ERR_कुञ्चिका_NOT_FOUND, oerrno;

	/* Check key and principal against file */
	सचे ((f = fopen(path, "r")) == रिक्त) {
		oerrno = errno;
		error("Unable to open allowed keys file \"%s\": %s",
		    path, strerror(errno));
		errno = oerrno;
		पटिनिवत्त SSH_ERR_SYSTEM_ERROR;
	}

	याव (getline(&पङ्क्तिः, &linesize, f) != -1) {
		linenum++;
		r = check_allowed_कुञ्चिकाः_पङ्क्तिः(path, linenum, पङ्क्तिः, sign_कुञ्चिका,
		    principal, sig_namespace, verify_time, रिक्त);
		मुक्त(पङ्क्तिः);
		पङ्क्तिः = रिक्त;
		linesize = 0;
		सचे (r == SSH_ERR_कुञ्चिका_NOT_FOUND)
			अनुवर्त;
		अञ्ञथा सचे (r == 0) {
			/* success */
			fclose(f);
			पटिनिवत्त 0;
		} अञ्ञथा
			भङ्ग;
	}
	/* Either we hit an error parsing or we simply didn't find the key */
	fclose(f);
	मुक्त(पङ्क्तिः);
	पटिनिवत्त r;
}

पूर्णाङ्क
sshsig_find_principals(ध्रुव वर्ण *path, ध्रुव संरचना sshkey *sign_कुञ्चिका,
    uint64_t verify_time, वर्ण **principals)
{
	FILE *f = रिक्त;
	वर्ण *पङ्क्तिः = रिक्त;
	size_t linesize = 0;
	u_long linenum = 0;
	पूर्णाङ्क r = SSH_ERR_कुञ्चिका_NOT_FOUND, oerrno;

	सचे ((f = fopen(path, "r")) == रिक्त) {
		oerrno = errno;
		error("Unable to open allowed keys file \"%s\": %s",
		    path, strerror(errno));
		errno = oerrno;
		पटिनिवत्त SSH_ERR_SYSTEM_ERROR;
	}

	याव (getline(&पङ्क्तिः, &linesize, f) != -1) {
		linenum++;
		r = check_allowed_कुञ्चिकाः_पङ्क्तिः(path, linenum, पङ्क्तिः,
		    sign_कुञ्चिका, रिक्त, रिक्त, verify_time, principals);
		मुक्त(पङ्क्तिः);
		पङ्क्तिः = रिक्त;
		linesize = 0;
		सचे (r == SSH_ERR_कुञ्चिका_NOT_FOUND)
			अनुवर्त;
		अञ्ञथा सचे (r == 0) {
			/* success */
			fclose(f);
			पटिनिवत्त 0;
		} अञ्ञथा
			भङ्ग;
	}
	मुक्त(पङ्क्तिः);
	/* Either we hit an error parsing or we simply didn't find the key */
	सचे (ferror(f) != 0) {
		oerrno = errno;
		fclose(f);
		error("Unable to read allowed keys file \"%s\": %s",
		    path, strerror(errno));
		errno = oerrno;
		पटिनिवत्त SSH_ERR_SYSTEM_ERROR;
	}
	fclose(f);
	पटिनिवत्त r;
}

पूर्णाङ्क
sshsig_match_principals(ध्रुव वर्ण *path, ध्रुव वर्ण *principal,
    वर्ण ***principalsp, size_t *nprincipalsp)
{
	FILE *f = रिक्त;
	वर्ण *found, *पङ्क्तिः = रिक्त, **principals = रिक्त, **tmp;
	size_t i, nprincipals = 0, linesize = 0;
	u_long linenum = 0;
	पूर्णाङ्क oerrno = 0, r, ret = 0;

	सचे (principalsp != रिक्त)
		*principalsp = रिक्त;
	सचे (nprincipalsp != रिक्त)
		*nprincipalsp = 0;

	/* Check key and principal against file */
	सचे ((f = fopen(path, "r")) == रिक्त) {
		oerrno = errno;
		error("Unable to open allowed keys file \"%s\": %s",
		    path, strerror(errno));
		errno = oerrno;
		पटिनिवत्त SSH_ERR_SYSTEM_ERROR;
	}

	याव (getline(&पङ्क्तिः, &linesize, f) != -1) {
		linenum++;
		/* Parse the line */
		सचे ((r = parse_principals_कुञ्चिका_and_options(path, linenum, पङ्क्तिः,
		    principal, &found, रिक्त, रिक्त)) != 0) {
			सचे (r == SSH_ERR_कुञ्चिका_NOT_FOUND)
				अनुवर्त;
			ret = r;
			oerrno = errno;
			भङ्ग; /* unexpected error */
		}
		सचे ((tmp = recallocarray(principals, nprincipals,
		    nprincipals + 1, परिमाण(*principals))) == रिक्त) {
			ret = SSH_ERR_ALLOC_FAIL;
			मुक्त(found);
			भङ्ग;
		}
		principals = tmp;
		principals[nprincipals++] = found; /* transferred */
		मुक्त(पङ्क्तिः);
		पङ्क्तिः = रिक्त;
		linesize = 0;
	}
	fclose(f);
	मुक्त(पङ्क्तिः);

	सचे (ret == 0) {
		सचे (nprincipals == 0)
			ret = SSH_ERR_कुञ्चिका_NOT_FOUND;
		सचे (nprincipalsp != रिक्त)
			*nprincipalsp = nprincipals;
		सचे (principalsp != रिक्त) {
			*principalsp = principals;
			principals = रिक्त; /* transferred */
			nprincipals = 0;
		}
	}

	अत्थाय (i = 0; i < nprincipals; i++)
		मुक्त(principals[i]);
	मुक्त(principals);

	errno = oerrno;
	पटिनिवत्त ret;
}

पूर्णाङ्क
sshsig_get_pubkey(संरचना sshbuf *signature, संरचना sshkey **pubkey)
{
	संरचना sshkey *pk = रिक्त;
	पूर्णाङ्क r = SSH_ERR_SIGNATURE_INVALID;

	सचे (pubkey == रिक्त)
		पटिनिवत्त SSH_ERR_INTERNAL_ERROR;
	सचे ((r = sshsig_parse_preamble(signature)) != 0)
		पटिनिवत्त r;
	सचे ((r = sshkey_froms(signature, &pk)) != 0)
		पटिनिवत्त r;

	*pubkey = pk;
	pk = रिक्त;
	पटिनिवत्त 0;
}
