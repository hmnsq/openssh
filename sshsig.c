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

#অন্তর্ভাব "includes.h"

#অন্তর্ভাব <stdio.h>
#অন্তর্ভাব <stdlib.h>
#অন্তর্ভাব <stdarg.h>
#অন্তর্ভাব <errno.h>
#অন্তর্ভাব <string.h>
#অন্তর্ভাব <unistd.h>

#অন্তর্ভাব "authfd.h"
#অন্তর্ভাব "authfile.h"
#অন্তর্ভাব "log.h"
#অন্তর্ভাব "misc.h"
#অন্তর্ভাব "sshbuf.h"
#অন্তর্ভাব "sshsig.h"
#অন্তর্ভাব "ssherr.h"
#অন্তর্ভাব "sshkey.h"
#অন্তর্ভাব "match.h"
#অন্তর্ভাব "digest.h"

#define SIG_VERSION		0x01
#define MAGIC_PREAMBLE		"SSHSIG"
#define MAGIC_PREAMBLE_LEN	(আকার(MAGIC_PREAMBLE) - 1)
#define BEGIN_SIGNATURE		"-----BEGIN SSH SIGNATURE-----"
#define END_SIGNATURE		"-----END SSH SIGNATURE-----"
#define RSA_SIGN_ALG		"rsa-sha2-512"
#define RSA_SIGN_ALLOWED	"rsa-sha2-512,rsa-sha2-256"
#define HASHALG_DEFAULT		"sha512"
#define HASHALG_ALLOWED		"sha256,sha512"

পূর্ণসংখ্যা
sshsig_armor(ধ্রুবক কাঠামো sshbuf *blob, কাঠামো sshbuf **out)
{
	কাঠামো sshbuf *buf = ফাঁকা;
	পূর্ণসংখ্যা r = SSH_ERR_INTERNAL_ERROR;

	*out = ফাঁকা;

	যদি ((buf = sshbuf_new()) == ফাঁকা) {
		error_f("sshbuf_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		যাও out;
	}

	যদি ((r = sshbuf_putf(buf, "%s\n", BEGIN_SIGNATURE)) != 0) {
		error_fr(r, "sshbuf_putf");
		যাও out;
	}

	যদি ((r = sshbuf_dtob64(blob, buf, 1)) != 0) {
		error_fr(r, "base64 encode signature");
		যাও out;
	}

	যদি ((r = sshbuf_put(buf, END_SIGNATURE,
	    আকার(END_SIGNATURE)-1)) != 0 ||
	    (r = sshbuf_put_u8(buf, '\n')) != 0) {
		error_fr(r, "sshbuf_put");
		যাও out;
	}
	/* success */
	*out = buf;
	buf = ফাঁকা; /* transferred */
	r = 0;
 out:
	sshbuf_free(buf);
	ফেরত r;
}

পূর্ণসংখ্যা
sshsig_dearmor(কাঠামো sshbuf *sig, কাঠামো sshbuf **out)
{
	পূর্ণসংখ্যা r;
	আকার_t eoffset = 0;
	কাঠামো sshbuf *buf = ফাঁকা;
	কাঠামো sshbuf *sbuf = ফাঁকা;
	অক্ষর *b64 = ফাঁকা;

	যদি ((sbuf = sshbuf_fromb(sig)) == ফাঁকা) {
		error_f("sshbuf_fromb failed");
		ফেরত SSH_ERR_ALLOC_FAIL;
	}

	/* Expect and consume preamble + lf/crlf */
	যদি ((r = sshbuf_cmp(sbuf, 0,
	    BEGIN_SIGNATURE, আকার(BEGIN_SIGNATURE)-1)) != 0) {
		error("Couldn't parse signature: missing header");
		যাও done;
	}
	যদি ((r = sshbuf_consume(sbuf, আকার(BEGIN_SIGNATURE)-1)) != 0) {
		error_fr(r, "consume");
		যাও done;
	}
	যদি ((r = sshbuf_cmp(sbuf, 0, "\r\n", 2)) == 0)
		eoffset = 2;
	অন্যথা যদি ((r = sshbuf_cmp(sbuf, 0, "\n", 1)) == 0)
		eoffset = 1;
	অন্যথা {
		r = SSH_ERR_INVALID_FORMAT;
		error_f("no header eol");
		যাও done;
	}
	যদি ((r = sshbuf_consume(sbuf, eoffset)) != 0) {
		error_fr(r, "consume eol");
		যাও done;
	}
	/* Find and consume lf + suffix (any prior cr would be ignored) */
	যদি ((r = sshbuf_find(sbuf, 0, "\n" END_SIGNATURE,
	    আকার(END_SIGNATURE), &eoffset)) != 0) {
		error("Couldn't parse signature: missing footer");
		যাও done;
	}
	যদি ((r = sshbuf_consume_end(sbuf, sshbuf_len(sbuf)-eoffset)) != 0) {
		error_fr(r, "consume");
		যাও done;
	}

	যদি ((b64 = sshbuf_dup_string(sbuf)) == ফাঁকা) {
		error_f("sshbuf_dup_string failed");
		r = SSH_ERR_ALLOC_FAIL;
		যাও done;
	}

	যদি ((buf = sshbuf_new()) == ফাঁকা) {
		error_f("sshbuf_new() failed");
		r = SSH_ERR_ALLOC_FAIL;
		যাও done;
	}

	যদি ((r = sshbuf_b64tod(buf, b64)) != 0) {
		error_fr(r, "decode base64");
		যাও done;
	}

	/* success */
	*out = buf;
	r = 0;
	buf = ফাঁকা; /* transferred */
done:
	sshbuf_free(buf);
	sshbuf_free(sbuf);
	মুক্ত(b64);
	ফেরত r;
}

স্থির পূর্ণসংখ্যা
sshsig_wrap_sign(কাঠামো sshkey *চাবি, ধ্রুবক অক্ষর *hashalg,
    ধ্রুবক অক্ষর *sk_provider, ধ্রুবক অক্ষর *sk_pin, ধ্রুবক কাঠামো sshbuf *h_message,
    ধ্রুবক অক্ষর *sig_namespace, কাঠামো sshbuf **out,
    sshsig_signer *signer, শূন্য *signer_ctx)
{
	পূর্ণসংখ্যা r;
	আকার_t slen = 0;
	u_char *sig = ফাঁকা;
	কাঠামো sshbuf *blob = ফাঁকা;
	কাঠামো sshbuf *tosign = ফাঁকা;
	ধ্রুবক অক্ষর *sign_alg = ফাঁকা;

	যদি ((tosign = sshbuf_new()) == ফাঁকা ||
	    (blob = sshbuf_new()) == ফাঁকা) {
		error_f("sshbuf_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		যাও done;
	}

	যদি ((r = sshbuf_put(tosign, MAGIC_PREAMBLE, MAGIC_PREAMBLE_LEN)) != 0 ||
	    (r = sshbuf_put_cstring(tosign, sig_namespace)) != 0 ||
	    (r = sshbuf_put_string(tosign, ফাঁকা, 0)) != 0 || /* reserved */
	    (r = sshbuf_put_cstring(tosign, hashalg)) != 0 ||
	    (r = sshbuf_put_stringb(tosign, h_message)) != 0) {
		error_fr(r, "assemble message to sign");
		যাও done;
	}

	/* If using RSA keys then default to a good signature algorithm */
	যদি (sshkey_type_plain(চাবি->type) == চাবি_RSA) {
		sign_alg = RSA_SIGN_ALG;
		যদি (strcmp(hashalg, "sha256") == 0)
			sign_alg = "rsa-sha2-256";
		অন্যথা যদি (strcmp(hashalg, "sha512") == 0)
			sign_alg = "rsa-sha2-512";
	}

	যদি (signer != ফাঁকা) {
		যদি ((r = signer(চাবি, &sig, &slen,
		    sshbuf_ptr(tosign), sshbuf_len(tosign),
		    sign_alg, sk_provider, sk_pin, 0, signer_ctx)) != 0) {
			error_r(r, "Couldn't sign message (signer)");
			যাও done;
		}
	} অন্যথা {
		যদি ((r = sshkey_sign(চাবি, &sig, &slen,
		    sshbuf_ptr(tosign), sshbuf_len(tosign),
		    sign_alg, sk_provider, sk_pin, 0)) != 0) {
			error_r(r, "Couldn't sign message");
			যাও done;
		}
	}

	যদি ((r = sshbuf_put(blob, MAGIC_PREAMBLE, MAGIC_PREAMBLE_LEN)) != 0 ||
	    (r = sshbuf_put_u32(blob, SIG_VERSION)) != 0 ||
	    (r = sshkey_puts(চাবি, blob)) != 0 ||
	    (r = sshbuf_put_cstring(blob, sig_namespace)) != 0 ||
	    (r = sshbuf_put_string(blob, ফাঁকা, 0)) != 0 || /* reserved */
	    (r = sshbuf_put_cstring(blob, hashalg)) != 0 ||
	    (r = sshbuf_put_string(blob, sig, slen)) != 0) {
		error_fr(r, "assemble signature object");
		যাও done;
	}

	যদি (out != ফাঁকা) {
		*out = blob;
		blob = ফাঁকা;
	}
	r = 0;
done:
	মুক্ত(sig);
	sshbuf_free(blob);
	sshbuf_free(tosign);
	ফেরত r;
}

/* Check preamble and version. */
স্থির পূর্ণসংখ্যা
sshsig_parse_preamble(কাঠামো sshbuf *buf)
{
	পূর্ণসংখ্যা r = SSH_ERR_INTERNAL_ERROR;
	uint32_t sversion;

	যদি ((r = sshbuf_cmp(buf, 0, MAGIC_PREAMBLE, MAGIC_PREAMBLE_LEN)) != 0 ||
	    (r = sshbuf_consume(buf, (আকার(MAGIC_PREAMBLE)-1))) != 0 ||
	    (r = sshbuf_get_u32(buf, &sversion)) != 0) {
		error("Couldn't verify signature: invalid format");
		ফেরত r;
	}

	যদি (sversion > SIG_VERSION) {
		error("Signature version %lu is larger than supported "
		    "version %u", (unsigned long)sversion, SIG_VERSION);
		ফেরত SSH_ERR_INVALID_FORMAT;
	}
	ফেরত 0;
}

স্থির পূর্ণসংখ্যা
sshsig_check_hashalg(ধ্রুবক অক্ষর *hashalg)
{
	যদি (hashalg == ফাঁকা ||
	    match_pattern_list(hashalg, HASHALG_ALLOWED, 0) == 1)
		ফেরত 0;
	error_f("unsupported hash algorithm \"%.100s\"", hashalg);
	ফেরত SSH_ERR_SIGN_ALG_UNSUPPORTED;
}

স্থির পূর্ণসংখ্যা
sshsig_peek_hashalg(কাঠামো sshbuf *signature, অক্ষর **hashalgp)
{
	কাঠামো sshbuf *buf = ফাঁকা;
	অক্ষর *hashalg = ফাঁকা;
	পূর্ণসংখ্যা r = SSH_ERR_INTERNAL_ERROR;

	যদি (hashalgp != ফাঁকা)
		*hashalgp = ফাঁকা;
	যদি ((buf = sshbuf_fromb(signature)) == ফাঁকা)
		ফেরত SSH_ERR_ALLOC_FAIL;
	যদি ((r = sshsig_parse_preamble(buf)) != 0)
		যাও done;
	যদি ((r = sshbuf_get_string_direct(buf, ফাঁকা, ফাঁকা)) != 0 ||
	    (r = sshbuf_get_string_direct(buf, ফাঁকা, ফাঁকা)) != 0 ||
	    (r = sshbuf_get_string(buf, ফাঁকা, ফাঁকা)) != 0 ||
	    (r = sshbuf_get_cstring(buf, &hashalg, ফাঁকা)) != 0 ||
	    (r = sshbuf_get_string_direct(buf, ফাঁকা, ফাঁকা)) != 0) {
		error_fr(r, "parse signature object");
		যাও done;
	}

	/* success */
	r = 0;
	*hashalgp = hashalg;
	hashalg = ফাঁকা;
 done:
	মুক্ত(hashalg);
	sshbuf_free(buf);
	ফেরত r;
}

স্থির পূর্ণসংখ্যা
sshsig_wrap_verify(কাঠামো sshbuf *signature, ধ্রুবক অক্ষর *hashalg,
    ধ্রুবক কাঠামো sshbuf *h_message, ধ্রুবক অক্ষর *expect_namespace,
    কাঠামো sshkey **sign_keyp, কাঠামো sshkey_sig_details **sig_details)
{
	পূর্ণসংখ্যা r = SSH_ERR_INTERNAL_ERROR;
	কাঠামো sshbuf *buf = ফাঁকা, *toverify = ফাঁকা;
	কাঠামো sshkey *চাবি = ফাঁকা;
	ধ্রুবক u_char *sig;
	অক্ষর *got_namespace = ফাঁকা, *sigtype = ফাঁকা, *sig_hashalg = ফাঁকা;
	আকার_t siglen;

	debug_f("verify message length %zu", sshbuf_len(h_message));
	যদি (sig_details != ফাঁকা)
		*sig_details = ফাঁকা;
	যদি (sign_keyp != ফাঁকা)
		*sign_keyp = ফাঁকা;

	যদি ((toverify = sshbuf_new()) == ফাঁকা) {
		error_f("sshbuf_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		যাও done;
	}
	যদি ((r = sshbuf_put(toverify, MAGIC_PREAMBLE,
	    MAGIC_PREAMBLE_LEN)) != 0 ||
	    (r = sshbuf_put_cstring(toverify, expect_namespace)) != 0 ||
	    (r = sshbuf_put_string(toverify, ফাঁকা, 0)) != 0 || /* reserved */
	    (r = sshbuf_put_cstring(toverify, hashalg)) != 0 ||
	    (r = sshbuf_put_stringb(toverify, h_message)) != 0) {
		error_fr(r, "assemble message to verify");
		যাও done;
	}

	যদি ((r = sshsig_parse_preamble(signature)) != 0)
		যাও done;

	যদি ((r = sshkey_froms(signature, &চাবি)) != 0 ||
	    (r = sshbuf_get_cstring(signature, &got_namespace, ফাঁকা)) != 0 ||
	    (r = sshbuf_get_string(signature, ফাঁকা, ফাঁকা)) != 0 ||
	    (r = sshbuf_get_cstring(signature, &sig_hashalg, ফাঁকা)) != 0 ||
	    (r = sshbuf_get_string_direct(signature, &sig, &siglen)) != 0) {
		error_fr(r, "parse signature object");
		যাও done;
	}

	যদি (sshbuf_len(signature) != 0) {
		error("Signature contains trailing data");
		r = SSH_ERR_INVALID_FORMAT;
		যাও done;
	}

	যদি (strcmp(expect_namespace, got_namespace) != 0) {
		error("Couldn't verify signature: namespace does not match");
		debug_f("expected namespace \"%s\" received \"%s\"",
		    expect_namespace, got_namespace);
		r = SSH_ERR_SIGNATURE_INVALID;
		যাও done;
	}
	যদি (strcmp(hashalg, sig_hashalg) != 0) {
		error("Couldn't verify signature: hash algorithm mismatch");
		debug_f("expected algorithm \"%s\" received \"%s\"",
		    hashalg, sig_hashalg);
		r = SSH_ERR_SIGNATURE_INVALID;
		যাও done;
	}
	/* Ensure that RSA keys use an acceptable signature algorithm */
	যদি (sshkey_type_plain(চাবি->type) == চাবি_RSA) {
		যদি ((r = sshkey_get_sigtype(sig, siglen, &sigtype)) != 0) {
			error_r(r, "Couldn't verify signature: unable to get "
			    "signature type");
			যাও done;
		}
		যদি (match_pattern_list(sigtype, RSA_SIGN_ALLOWED, 0) != 1) {
			error("Couldn't verify signature: unsupported RSA "
			    "signature algorithm %s", sigtype);
			r = SSH_ERR_SIGN_ALG_UNSUPPORTED;
			যাও done;
		}
	}
	যদি ((r = sshkey_verify(চাবি, sig, siglen, sshbuf_ptr(toverify),
	    sshbuf_len(toverify), ফাঁকা, 0, sig_details)) != 0) {
		error_r(r, "Signature verification failed");
		যাও done;
	}

	/* success */
	r = 0;
	যদি (sign_keyp != ফাঁকা) {
		*sign_keyp = চাবি;
		চাবি = ফাঁকা; /* transferred */
	}
done:
	মুক্ত(got_namespace);
	মুক্ত(sigtype);
	মুক্ত(sig_hashalg);
	sshbuf_free(buf);
	sshbuf_free(toverify);
	sshkey_free(চাবি);
	ফেরত r;
}

স্থির পূর্ণসংখ্যা
hash_বাফার(ধ্রুবক কাঠামো sshbuf *m, ধ্রুবক অক্ষর *hashalg, কাঠামো sshbuf **bp)
{
	অক্ষর *hex, hash[SSH_DIGEST_MAX_দৈর্ঘ্য];
	পূর্ণসংখ্যা alg, r = SSH_ERR_INTERNAL_ERROR;
	কাঠামো sshbuf *b = ফাঁকা;

	*bp = ফাঁকা;
	memset(hash, 0, আকার(hash));

	যদি ((r = sshsig_check_hashalg(hashalg)) != 0)
		ফেরত r;
	যদি ((alg = ssh_digest_alg_by_name(hashalg)) == -1) {
		error_f("can't look up hash algorithm %s", hashalg);
		ফেরত SSH_ERR_INTERNAL_ERROR;
	}
	যদি ((r = ssh_digest_বাফার(alg, m, hash, আকার(hash))) != 0) {
		error_fr(r, "ssh_digest_buffer");
		ফেরত r;
	}
	যদি ((hex = tohex(hash, ssh_digest_bytes(alg))) != ফাঁকা) {
		debug3_f("final hash: %s", hex);
		freezero(hex, strlen(hex));
	}
	যদি ((b = sshbuf_new()) == ফাঁকা) {
		r = SSH_ERR_ALLOC_FAIL;
		যাও out;
	}
	যদি ((r = sshbuf_put(b, hash, ssh_digest_bytes(alg))) != 0) {
		error_fr(r, "sshbuf_put");
		যাও out;
	}
	*bp = b;
	b = ফাঁকা; /* transferred */
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	explicit_bzero(hash, আকার(hash));
	ফেরত r;
}

পূর্ণসংখ্যা
sshsig_signb(কাঠামো sshkey *চাবি, ধ্রুবক অক্ষর *hashalg,
    ধ্রুবক অক্ষর *sk_provider, ধ্রুবক অক্ষর *sk_pin,
    ধ্রুবক কাঠামো sshbuf *message, ধ্রুবক অক্ষর *sig_namespace,
    কাঠামো sshbuf **out, sshsig_signer *signer, শূন্য *signer_ctx)
{
	কাঠামো sshbuf *b = ফাঁকা;
	পূর্ণসংখ্যা r = SSH_ERR_INTERNAL_ERROR;

	যদি (hashalg == ফাঁকা)
		hashalg = HASHALG_DEFAULT;
	যদি (out != ফাঁকা)
		*out = ফাঁকা;
	যদি ((r = hash_বাফার(message, hashalg, &b)) != 0) {
		error_fr(r, "hash buffer");
		যাও out;
	}
	যদি ((r = sshsig_wrap_sign(চাবি, hashalg, sk_provider, sk_pin, b,
	    sig_namespace, out, signer, signer_ctx)) != 0)
		যাও out;
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	ফেরত r;
}

পূর্ণসংখ্যা
sshsig_verifyb(কাঠামো sshbuf *signature, ধ্রুবক কাঠামো sshbuf *message,
    ধ্রুবক অক্ষর *expect_namespace, কাঠামো sshkey **sign_keyp,
    কাঠামো sshkey_sig_details **sig_details)
{
	কাঠামো sshbuf *b = ফাঁকা;
	পূর্ণসংখ্যা r = SSH_ERR_INTERNAL_ERROR;
	অক্ষর *hashalg = ফাঁকা;

	যদি (sig_details != ফাঁকা)
		*sig_details = ফাঁকা;
	যদি (sign_keyp != ফাঁকা)
		*sign_keyp = ফাঁকা;
	যদি ((r = sshsig_peek_hashalg(signature, &hashalg)) != 0)
		ফেরত r;
	debug_f("signature made with hash \"%s\"", hashalg);
	যদি ((r = hash_বাফার(message, hashalg, &b)) != 0) {
		error_fr(r, "hash buffer");
		যাও out;
	}
	যদি ((r = sshsig_wrap_verify(signature, hashalg, b, expect_namespace,
	    sign_keyp, sig_details)) != 0)
		যাও out;
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	মুক্ত(hashalg);
	ফেরত r;
}

স্থির পূর্ণসংখ্যা
hash_file(পূর্ণসংখ্যা fd, ধ্রুবক অক্ষর *hashalg, কাঠামো sshbuf **bp)
{
	অক্ষর *hex, rbuf[8192], hash[SSH_DIGEST_MAX_দৈর্ঘ্য];
	ssize_t n, যোগ_2 = 0;
	কাঠামো ssh_digest_ctx *ctx = ফাঁকা;
	পূর্ণসংখ্যা alg, oerrno, r = SSH_ERR_INTERNAL_ERROR;
	কাঠামো sshbuf *b = ফাঁকা;

	*bp = ফাঁকা;
	memset(hash, 0, আকার(hash));

	যদি ((r = sshsig_check_hashalg(hashalg)) != 0)
		ফেরত r;
	যদি ((alg = ssh_digest_alg_by_name(hashalg)) == -1) {
		error_f("can't look up hash algorithm %s", hashalg);
		ফেরত SSH_ERR_INTERNAL_ERROR;
	}
	যদি ((ctx = ssh_digest_start(alg)) == ফাঁকা) {
		error_f("ssh_digest_start failed");
		ফেরত SSH_ERR_INTERNAL_ERROR;
	}
	জন্য (;;) {
		যদি ((n = পঠ(fd, rbuf, আকার(rbuf))) == -1) {
			যদি (errno == EINTR || errno == EAGAIN)
				চালু;
			oerrno = errno;
			error_f("read: %s", strerror(errno));
			errno = oerrno;
			r = SSH_ERR_SYSTEM_ERROR;
			যাও out;
		} অন্যথা যদি (n == 0) {
			debug2_f("hashed %zu bytes", যোগ_2);
			বিরতি; /* EOF */
		}
		যোগ_2 += (আকার_t)n;
		যদি ((r = ssh_digest_update(ctx, rbuf, (আকার_t)n)) != 0) {
			error_fr(r, "ssh_digest_update");
			যাও out;
		}
	}
	যদি ((r = ssh_digest_final(ctx, hash, আকার(hash))) != 0) {
		error_fr(r, "ssh_digest_final");
		যাও out;
	}
	যদি ((hex = tohex(hash, ssh_digest_bytes(alg))) != ফাঁকা) {
		debug3_f("final hash: %s", hex);
		freezero(hex, strlen(hex));
	}
	যদি ((b = sshbuf_new()) == ফাঁকা) {
		r = SSH_ERR_ALLOC_FAIL;
		যাও out;
	}
	যদি ((r = sshbuf_put(b, hash, ssh_digest_bytes(alg))) != 0) {
		error_fr(r, "sshbuf_put");
		যাও out;
	}
	*bp = b;
	b = ফাঁকা; /* transferred */
	/* success */
	r = 0;
 out:
	oerrno = errno;
	sshbuf_free(b);
	ssh_digest_free(ctx);
	explicit_bzero(hash, আকার(hash));
	errno = oerrno;
	ফেরত r;
}

পূর্ণসংখ্যা
sshsig_sign_fd(কাঠামো sshkey *চাবি, ধ্রুবক অক্ষর *hashalg,
    ধ্রুবক অক্ষর *sk_provider, ধ্রুবক অক্ষর *sk_pin,
    পূর্ণসংখ্যা fd, ধ্রুবক অক্ষর *sig_namespace, কাঠামো sshbuf **out,
    sshsig_signer *signer, শূন্য *signer_ctx)
{
	কাঠামো sshbuf *b = ফাঁকা;
	পূর্ণসংখ্যা r = SSH_ERR_INTERNAL_ERROR;

	যদি (hashalg == ফাঁকা)
		hashalg = HASHALG_DEFAULT;
	যদি (out != ফাঁকা)
		*out = ফাঁকা;
	যদি ((r = hash_file(fd, hashalg, &b)) != 0) {
		error_fr(r, "hash_file");
		ফেরত r;
	}
	যদি ((r = sshsig_wrap_sign(চাবি, hashalg, sk_provider, sk_pin, b,
	    sig_namespace, out, signer, signer_ctx)) != 0)
		যাও out;
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	ফেরত r;
}

পূর্ণসংখ্যা
sshsig_verify_fd(কাঠামো sshbuf *signature, পূর্ণসংখ্যা fd,
    ধ্রুবক অক্ষর *expect_namespace, কাঠামো sshkey **sign_keyp,
    কাঠামো sshkey_sig_details **sig_details)
{
	কাঠামো sshbuf *b = ফাঁকা;
	পূর্ণসংখ্যা r = SSH_ERR_INTERNAL_ERROR;
	অক্ষর *hashalg = ফাঁকা;

	যদি (sig_details != ফাঁকা)
		*sig_details = ফাঁকা;
	যদি (sign_keyp != ফাঁকা)
		*sign_keyp = ফাঁকা;
	যদি ((r = sshsig_peek_hashalg(signature, &hashalg)) != 0)
		ফেরত r;
	debug_f("signature made with hash \"%s\"", hashalg);
	যদি ((r = hash_file(fd, hashalg, &b)) != 0) {
		error_fr(r, "hash_file");
		যাও out;
	}
	যদি ((r = sshsig_wrap_verify(signature, hashalg, b, expect_namespace,
	    sign_keyp, sig_details)) != 0)
		যাও out;
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	মুক্ত(hashalg);
	ফেরত r;
}

কাঠামো sshsigopt {
	পূর্ণসংখ্যা ca;
	অক্ষর *namespaces;
	uint64_t valid_after, valid_before;
};

কাঠামো sshsigopt *
sshsigopt_parse(ধ্রুবক অক্ষর *opts, ধ্রুবক অক্ষর *path, u_long linenum,
    ধ্রুবক অক্ষর **errstrp)
{
	কাঠামো sshsigopt *ret;
	পূর্ণসংখ্যা r;
	অক্ষর *opt;
	ধ্রুবক অক্ষর *errstr = ফাঁকা;

	যদি ((ret = calloc(1, আকার(*ret))) == ফাঁকা)
		ফেরত ফাঁকা;
	যদি (opts == ফাঁকা || *opts == '\0')
		ফেরত ret; /* Empty options yields empty options :) */

	যখন (*opts && *opts != ' ' && *opts != '\t') {
		/* flag options */
		যদি ((r = opt_flag("cert-authority", 0, &opts)) != -1) {
			ret->ca = 1;
		} অন্যথা যদি (opt_match(&opts, "namespaces")) {
			যদি (ret->namespaces != ফাঁকা) {
				errstr = "multiple \"namespaces\" clauses";
				যাও fail;
			}
			ret->namespaces = opt_dequote(&opts, &errstr);
			যদি (ret->namespaces == ফাঁকা)
				যাও fail;
		} অন্যথা যদি (opt_match(&opts, "valid-after")) {
			যদি (ret->valid_after != 0) {
				errstr = "multiple \"valid-after\" clauses";
				যাও fail;
			}
			যদি ((opt = opt_dequote(&opts, &errstr)) == ফাঁকা)
				যাও fail;
			যদি (parse_absolute_time(opt, &ret->valid_after) != 0 ||
			    ret->valid_after == 0) {
				মুক্ত(opt);
				errstr = "invalid \"valid-after\" time";
				যাও fail;
			}
			মুক্ত(opt);
		} অন্যথা যদি (opt_match(&opts, "valid-before")) {
			যদি (ret->valid_before != 0) {
				errstr = "multiple \"valid-before\" clauses";
				যাও fail;
			}
			যদি ((opt = opt_dequote(&opts, &errstr)) == ফাঁকা)
				যাও fail;
			যদি (parse_absolute_time(opt, &ret->valid_before) != 0 ||
			    ret->valid_before == 0) {
				মুক্ত(opt);
				errstr = "invalid \"valid-before\" time";
				যাও fail;
			}
			মুক্ত(opt);
		}
		/*
		 * Skip the comma, and move to the next option
		 * (or break out if there are no more).
		 */
		যদি (*opts == '\0' || *opts == ' ' || *opts == '\t')
			বিরতি;		/* End of options. */
		/* Anything other than a comma is an unknown option */
		যদি (*opts != ',') {
			errstr = "unknown key option";
			যাও fail;
		}
		opts++;
		যদি (*opts == '\0') {
			errstr = "unexpected end-of-options";
			যাও fail;
		}
	}
	/* final consistency check */
	যদি (ret->valid_after != 0 && ret->valid_before != 0 &&
	    ret->valid_before <= ret->valid_after) {
		errstr = "\"valid-before\" time is before \"valid-after\"";
		যাও fail;
	}
	/* success */
	ফেরত ret;
 fail:
	যদি (errstrp != ফাঁকা)
		*errstrp = errstr;
	sshsigopt_free(ret);
	ফেরত ফাঁকা;
}

শূন্য
sshsigopt_free(কাঠামো sshsigopt *opts)
{
	যদি (opts == ফাঁকা)
		ফেরত;
	মুক্ত(opts->namespaces);
	মুক্ত(opts);
}

স্থির পূর্ণসংখ্যা
parse_principals_চাবি_and_options(ধ্রুবক অক্ষর *path, u_long linenum, অক্ষর *সারি,
    ধ্রুবক অক্ষর *required_principal, অক্ষর **principalsp, কাঠামো sshkey **keyp,
    কাঠামো sshsigopt **sigoptsp)
{
	অক্ষর *opts = ফাঁকা, *tmp, *cp, *principals = ফাঁকা;
	ধ্রুবক অক্ষর *reason = ফাঁকা;
	কাঠামো sshsigopt *sigopts = ফাঁকা;
	কাঠামো sshkey *চাবি = ফাঁকা;
	পূর্ণসংখ্যা r = SSH_ERR_INTERNAL_ERROR;

	যদি (principalsp != ফাঁকা)
		*principalsp = ফাঁকা;
	যদি (sigoptsp != ফাঁকা)
		*sigoptsp = ফাঁকা;
	যদি (keyp != ফাঁকা)
		*keyp = ফাঁকা;

	cp = সারি;
	cp = cp + strspn(cp, " \t\n\r"); /* skip leading whitespace */
	যদি (*cp == '#' || *cp == '\0')
		ফেরত SSH_ERR_চাবি_NOT_FOUND; /* blank or all-comment line */

	/* format: identity[,identity...] [option[,option...]] key */
	যদি ((tmp = strdelimw(&cp)) == ফাঁকা || cp == ফাঁকা) {
		error("%s:%lu: invalid line", path, linenum);
		r = SSH_ERR_INVALID_FORMAT;
		যাও out;
	}
	যদি ((principals = strdup(tmp)) == ফাঁকা) {
		error_f("strdup failed");
		r = SSH_ERR_ALLOC_FAIL;
		যাও out;
	}
	/*
	 * Bail out early if we're looking for a particular principal and this
	 * line does not list it.
	 */
	যদি (required_principal != ফাঁকা) {
		যদি (match_pattern_list(required_principal,
		    principals, 0) != 1) {
			/* principal didn't match */
			r = SSH_ERR_চাবি_NOT_FOUND;
			যাও out;
		}
		debug_f("%s:%lu: matched principal \"%s\"",
		    path, linenum, required_principal);
	}

	যদি ((চাবি = sshkey_new(চাবি_UNSPEC)) == ফাঁকা) {
		error_f("sshkey_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		যাও out;
	}
	যদি (sshkey_read(চাবি, &cp) != 0) {
		/* no key? Check for options */
		opts = cp;
		যদি (sshkey_advance_past_options(&cp) != 0) {
			error("%s:%lu: invalid options", path, linenum);
			r = SSH_ERR_INVALID_FORMAT;
			যাও out;
		}
		যদি (cp == ফাঁকা || *cp == '\0') {
			error("%s:%lu: missing key", path, linenum);
			r = SSH_ERR_INVALID_FORMAT;
			যাও out;
		}
		*cp++ = '\0';
		skip_space(&cp);
		যদি (sshkey_read(চাবি, &cp) != 0) {
			error("%s:%lu: invalid key", path, linenum);
			r = SSH_ERR_INVALID_FORMAT;
			যাও out;
		}
	}
	debug3("%s:%lu: options %s", path, linenum, opts == ফাঁকা ? "" : opts);
	যদি ((sigopts = sshsigopt_parse(opts, path, linenum, &reason)) == ফাঁকা) {
		error("%s:%lu: bad options: %s", path, linenum, reason);
		r = SSH_ERR_INVALID_FORMAT;
		যাও out;
	}
	/* success */
	যদি (principalsp != ফাঁকা) {
		*principalsp = principals;
		principals = ফাঁকা; /* transferred */
	}
	যদি (sigoptsp != ফাঁকা) {
		*sigoptsp = sigopts;
		sigopts = ফাঁকা; /* transferred */
	}
	যদি (keyp != ফাঁকা) {
		*keyp = চাবি;
		চাবি = ফাঁকা; /* transferred */
	}
	r = 0;
 out:
	মুক্ত(principals);
	sshsigopt_free(sigopts);
	sshkey_free(চাবি);
	ফেরত r;
}

স্থির পূর্ণসংখ্যা
cert_filter_principals(ধ্রুবক অক্ষর *path, u_long linenum,
    অক্ষর **principalsp, ধ্রুবক কাঠামো sshkey *cert, uint64_t verify_time)
{
	অক্ষর *cp, *oprincipals, *principals;
	ধ্রুবক অক্ষর *reason;
	কাঠামো sshbuf *nprincipals;
	পূর্ণসংখ্যা r = SSH_ERR_INTERNAL_ERROR, success = 0;
	u_int i;

	oprincipals = principals = *principalsp;
	*principalsp = ফাঁকা;

	যদি ((nprincipals = sshbuf_new()) == ফাঁকা) {
		r = SSH_ERR_ALLOC_FAIL;
		যাও out;
	}

	যখন ((cp = strsep(&principals, ",")) != ফাঁকা && *cp != '\0') {
		/* Check certificate validity */
		যদি ((r = sshkey_cert_check_authority(cert, 0, 0, verify_time,
		    ফাঁকা, &reason)) != 0) {
			debug("%s:%lu: principal \"%s\" not authorized: %s",
			    path, linenum, cp, reason);
			চালু;
		}
		/* Return all matching principal names from the cert */
		জন্য (i = 0; i < cert->cert->nprincipals; i++) {
			যদি (match_pattern(cert->cert->principals[i], cp)) {
				যদি ((r = sshbuf_putf(nprincipals, "%s%s",
					sshbuf_len(nprincipals) != 0 ? "," : "",
						cert->cert->principals[i])) != 0) {
					error_f("buffer error");
					যাও out;
				}
			}
		}
	}
	যদি (sshbuf_len(nprincipals) == 0) {
		error("%s:%lu: no valid principals found", path, linenum);
		r = SSH_ERR_চাবি_CERT_INVALID;
		যাও out;
	}
	যদি ((principals = sshbuf_dup_string(nprincipals)) == ফাঁকা) {
		error_f("buffer error");
		r = SSH_ERR_ALLOC_FAIL;
		যাও out;
	}
	/* success */
	success = 1;
	*principalsp = principals;
 out:
	sshbuf_free(nprincipals);
	মুক্ত(oprincipals);
	ফেরত success ? 0 : r;
}

স্থির পূর্ণসংখ্যা
check_allowed_চাবিগুলি_সারি(ধ্রুবক অক্ষর *path, u_long linenum, অক্ষর *সারি,
    ধ্রুবক কাঠামো sshkey *sign_চাবি, ধ্রুবক অক্ষর *principal,
    ধ্রুবক অক্ষর *sig_namespace, uint64_t verify_time, অক্ষর **principalsp)
{
	কাঠামো sshkey *found_চাবি = ফাঁকা;
	অক্ষর *principals = ফাঁকা;
	পূর্ণসংখ্যা r, success = 0;
	ধ্রুবক অক্ষর *reason = ফাঁকা;
	কাঠামো sshsigopt *sigopts = ফাঁকা;
	অক্ষর tvalid[64], tverify[64];

	যদি (principalsp != ফাঁকা)
		*principalsp = ফাঁকা;

	/* Parse the line */
	যদি ((r = parse_principals_চাবি_and_options(path, linenum, সারি,
	    principal, &principals, &found_চাবি, &sigopts)) != 0) {
		/* error already logged */
		যাও done;
	}

	যদি (!sigopts->ca && sshkey_equal(found_চাবি, sign_চাবি)) {
		/* Exact match of key */
		debug("%s:%lu: matched key", path, linenum);
	} অন্যথা যদি (sigopts->ca && sshkey_is_cert(sign_চাবি) &&
	    sshkey_equal_public(sign_চাবি->cert->signature_চাবি, found_চাবি)) {
		যদি (principal) {
			/* Match certificate CA key with specified principal */
			যদি ((r = sshkey_cert_check_authority(sign_চাবি, 0, 0,
			    verify_time, principal, &reason)) != 0) {
				error("%s:%lu: certificate not authorized: %s",
				    path, linenum, reason);
				যাও done;
			}
			debug("%s:%lu: matched certificate CA key",
			    path, linenum);
		} অন্যথা {
			/* No principal specified - find all matching ones */
			যদি ((r = cert_filter_principals(path, linenum,
			    &principals, sign_চাবি, verify_time)) != 0) {
				/* error already displayed */
				debug_r(r, "%s:%lu: cert_filter_principals",
				    path, linenum);
				যাও done;
			}
			debug("%s:%lu: matched certificate CA key",
			    path, linenum);
		}
	} অন্যথা {
		/* Didn't match key */
		যাও done;
	}

	/* Check whether options preclude the use of this key */
	যদি (sigopts->namespaces != ফাঁকা && sig_namespace != ফাঁকা &&
	    match_pattern_list(sig_namespace, sigopts->namespaces, 0) != 1) {
		error("%s:%lu: key is not permitted for use in signature "
		    "namespace \"%s\"", path, linenum, sig_namespace);
		যাও done;
	}

	/* check key time validity */
	format_absolute_time((uint64_t)verify_time, tverify, আকার(tverify));
	যদি (sigopts->valid_after != 0 &&
	    (uint64_t)verify_time < sigopts->valid_after) {
		format_absolute_time(sigopts->valid_after,
		    tvalid, আকার(tvalid));
		error("%s:%lu: key is not yet valid: "
		    "verify time %s < valid-after %s", path, linenum,
		    tverify, tvalid);
		যাও done;
	}
	যদি (sigopts->valid_before != 0 &&
	    (uint64_t)verify_time > sigopts->valid_before) {
		format_absolute_time(sigopts->valid_before,
		    tvalid, আকার(tvalid));
		error("%s:%lu: key has expired: "
		    "verify time %s > valid-before %s", path, linenum,
		    tverify, tvalid);
		যাও done;
	}
	success = 1;

 done:
	যদি (success && principalsp != ফাঁকা) {
		*principalsp = principals;
		principals = ফাঁকা; /* transferred */
	}
	মুক্ত(principals);
	sshkey_free(found_চাবি);
	sshsigopt_free(sigopts);
	ফেরত success ? 0 : SSH_ERR_চাবি_NOT_FOUND;
}

পূর্ণসংখ্যা
sshsig_check_allowed_চাবিগুলি(ধ্রুবক অক্ষর *path, ধ্রুবক কাঠামো sshkey *sign_চাবি,
    ধ্রুবক অক্ষর *principal, ধ্রুবক অক্ষর *sig_namespace, uint64_t verify_time)
{
	FILE *f = ফাঁকা;
	অক্ষর *সারি = ফাঁকা;
	আকার_t linesize = 0;
	u_long linenum = 0;
	পূর্ণসংখ্যা r = SSH_ERR_চাবি_NOT_FOUND, oerrno;

	/* Check key and principal against file */
	যদি ((f = fopen(path, "r")) == ফাঁকা) {
		oerrno = errno;
		error("Unable to open allowed keys file \"%s\": %s",
		    path, strerror(errno));
		errno = oerrno;
		ফেরত SSH_ERR_SYSTEM_ERROR;
	}

	যখন (getline(&সারি, &linesize, f) != -1) {
		linenum++;
		r = check_allowed_চাবিগুলি_সারি(path, linenum, সারি, sign_চাবি,
		    principal, sig_namespace, verify_time, ফাঁকা);
		মুক্ত(সারি);
		সারি = ফাঁকা;
		linesize = 0;
		যদি (r == SSH_ERR_চাবি_NOT_FOUND)
			চালু;
		অন্যথা যদি (r == 0) {
			/* success */
			fclose(f);
			ফেরত 0;
		} অন্যথা
			বিরতি;
	}
	/* Either we hit an error parsing or we simply didn't find the key */
	fclose(f);
	মুক্ত(সারি);
	ফেরত r;
}

পূর্ণসংখ্যা
sshsig_find_principals(ধ্রুবক অক্ষর *path, ধ্রুবক কাঠামো sshkey *sign_চাবি,
    uint64_t verify_time, অক্ষর **principals)
{
	FILE *f = ফাঁকা;
	অক্ষর *সারি = ফাঁকা;
	আকার_t linesize = 0;
	u_long linenum = 0;
	পূর্ণসংখ্যা r = SSH_ERR_চাবি_NOT_FOUND, oerrno;

	যদি ((f = fopen(path, "r")) == ফাঁকা) {
		oerrno = errno;
		error("Unable to open allowed keys file \"%s\": %s",
		    path, strerror(errno));
		errno = oerrno;
		ফেরত SSH_ERR_SYSTEM_ERROR;
	}

	যখন (getline(&সারি, &linesize, f) != -1) {
		linenum++;
		r = check_allowed_চাবিগুলি_সারি(path, linenum, সারি,
		    sign_চাবি, ফাঁকা, ফাঁকা, verify_time, principals);
		মুক্ত(সারি);
		সারি = ফাঁকা;
		linesize = 0;
		যদি (r == SSH_ERR_চাবি_NOT_FOUND)
			চালু;
		অন্যথা যদি (r == 0) {
			/* success */
			fclose(f);
			ফেরত 0;
		} অন্যথা
			বিরতি;
	}
	মুক্ত(সারি);
	/* Either we hit an error parsing or we simply didn't find the key */
	যদি (ferror(f) != 0) {
		oerrno = errno;
		fclose(f);
		error("Unable to read allowed keys file \"%s\": %s",
		    path, strerror(errno));
		errno = oerrno;
		ফেরত SSH_ERR_SYSTEM_ERROR;
	}
	fclose(f);
	ফেরত r;
}

পূর্ণসংখ্যা
sshsig_match_principals(ধ্রুবক অক্ষর *path, ধ্রুবক অক্ষর *principal,
    অক্ষর ***principalsp, আকার_t *nprincipalsp)
{
	FILE *f = ফাঁকা;
	অক্ষর *found, *সারি = ফাঁকা, **principals = ফাঁকা, **tmp;
	আকার_t i, nprincipals = 0, linesize = 0;
	u_long linenum = 0;
	পূর্ণসংখ্যা oerrno = 0, r, ret = 0;

	যদি (principalsp != ফাঁকা)
		*principalsp = ফাঁকা;
	যদি (nprincipalsp != ফাঁকা)
		*nprincipalsp = 0;

	/* Check key and principal against file */
	যদি ((f = fopen(path, "r")) == ফাঁকা) {
		oerrno = errno;
		error("Unable to open allowed keys file \"%s\": %s",
		    path, strerror(errno));
		errno = oerrno;
		ফেরত SSH_ERR_SYSTEM_ERROR;
	}

	যখন (getline(&সারি, &linesize, f) != -1) {
		linenum++;
		/* Parse the line */
		যদি ((r = parse_principals_চাবি_and_options(path, linenum, সারি,
		    principal, &found, ফাঁকা, ফাঁকা)) != 0) {
			যদি (r == SSH_ERR_চাবি_NOT_FOUND)
				চালু;
			ret = r;
			oerrno = errno;
			বিরতি; /* unexpected error */
		}
		যদি ((tmp = recallocarray(principals, nprincipals,
		    nprincipals + 1, আকার(*principals))) == ফাঁকা) {
			ret = SSH_ERR_ALLOC_FAIL;
			মুক্ত(found);
			বিরতি;
		}
		principals = tmp;
		principals[nprincipals++] = found; /* transferred */
		মুক্ত(সারি);
		সারি = ফাঁকা;
		linesize = 0;
	}
	fclose(f);
	মুক্ত(সারি);

	যদি (ret == 0) {
		যদি (nprincipals == 0)
			ret = SSH_ERR_চাবি_NOT_FOUND;
		যদি (nprincipalsp != ফাঁকা)
			*nprincipalsp = nprincipals;
		যদি (principalsp != ফাঁকা) {
			*principalsp = principals;
			principals = ফাঁকা; /* transferred */
			nprincipals = 0;
		}
	}

	জন্য (i = 0; i < nprincipals; i++)
		মুক্ত(principals[i]);
	মুক্ত(principals);

	errno = oerrno;
	ফেরত ret;
}

পূর্ণসংখ্যা
sshsig_get_pubkey(কাঠামো sshbuf *signature, কাঠামো sshkey **pubkey)
{
	কাঠামো sshkey *pk = ফাঁকা;
	পূর্ণসংখ্যা r = SSH_ERR_SIGNATURE_INVALID;

	যদি (pubkey == ফাঁকা)
		ফেরত SSH_ERR_INTERNAL_ERROR;
	যদি ((r = sshsig_parse_preamble(signature)) != 0)
		ফেরত r;
	যদি ((r = sshkey_froms(signature, &pk)) != 0)
		ফেরত r;

	*pubkey = pk;
	pk = ফাঁকা;
	ফেরত 0;
}
