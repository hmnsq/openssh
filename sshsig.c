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

	यदि ((buf = sshbuf_new()) == रिक्त) {
		error_f("sshbuf_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ out;
	}

	यदि ((r = sshbuf_putf(buf, "%s\n", BEGIN_SIGNATURE)) != 0) {
		error_fr(r, "sshbuf_putf");
		गच्छ out;
	}

	यदि ((r = sshbuf_dtob64(blob, buf, 1)) != 0) {
		error_fr(r, "base64 encode signature");
		गच्छ out;
	}

	यदि ((r = sshbuf_put(buf, END_SIGNATURE,
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
	प्रत्यागम r;
}

पूर्णाङ्क
sshsig_dearmor(संरचना sshbuf *sig, संरचना sshbuf **out)
{
	पूर्णाङ्क r;
	माप_प्रकार eoffset = 0;
	संरचना sshbuf *buf = रिक्त;
	संरचना sshbuf *sbuf = रिक्त;
	वर्ण *b64 = रिक्त;

	यदि ((sbuf = sshbuf_fromb(sig)) == रिक्त) {
		error_f("sshbuf_fromb failed");
		प्रत्यागम SSH_ERR_ALLOC_FAIL;
	}

	/* Expect and consume preamble + lf/crlf */
	यदि ((r = sshbuf_cmp(sbuf, 0,
	    BEGIN_SIGNATURE, परिमाण(BEGIN_SIGNATURE)-1)) != 0) {
		error("Couldn't parse signature: missing header");
		गच्छ done;
	}
	यदि ((r = sshbuf_consume(sbuf, परिमाण(BEGIN_SIGNATURE)-1)) != 0) {
		error_fr(r, "consume");
		गच्छ done;
	}
	यदि ((r = sshbuf_cmp(sbuf, 0, "\r\n", 2)) == 0)
		eoffset = 2;
	अन्यथा यदि ((r = sshbuf_cmp(sbuf, 0, "\n", 1)) == 0)
		eoffset = 1;
	अन्यथा {
		r = SSH_ERR_INVALID_FORMAT;
		error_f("no header eol");
		गच्छ done;
	}
	यदि ((r = sshbuf_consume(sbuf, eoffset)) != 0) {
		error_fr(r, "consume eol");
		गच्छ done;
	}
	/* Find and consume lf + suffix (any prior cr would be ignored) */
	यदि ((r = sshbuf_find(sbuf, 0, "\n" END_SIGNATURE,
	    परिमाण(END_SIGNATURE), &eoffset)) != 0) {
		error("Couldn't parse signature: missing footer");
		गच्छ done;
	}
	यदि ((r = sshbuf_consume_end(sbuf, sshbuf_len(sbuf)-eoffset)) != 0) {
		error_fr(r, "consume");
		गच्छ done;
	}

	यदि ((b64 = sshbuf_dup_string(sbuf)) == रिक्त) {
		error_f("sshbuf_dup_string failed");
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ done;
	}

	यदि ((buf = sshbuf_new()) == रिक्त) {
		error_f("sshbuf_new() failed");
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ done;
	}

	यदि ((r = sshbuf_b64tod(buf, b64)) != 0) {
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
	प्रत्यागम r;
}

स्थिर पूर्णाङ्क
sshsig_wrap_sign(संरचना sshkey *कुंजी, ध्रुव वर्ण *hashalg,
    ध्रुव वर्ण *sk_provider, ध्रुव वर्ण *sk_pin, ध्रुव संरचना sshbuf *h_message,
    ध्रुव वर्ण *sig_namespace, संरचना sshbuf **out,
    sshsig_signer *signer, शून्य *signer_ctx)
{
	पूर्णाङ्क r;
	माप_प्रकार slen = 0;
	u_char *sig = रिक्त;
	संरचना sshbuf *blob = रिक्त;
	संरचना sshbuf *tosign = रिक्त;
	ध्रुव वर्ण *sign_alg = रिक्त;

	यदि ((tosign = sshbuf_new()) == रिक्त ||
	    (blob = sshbuf_new()) == रिक्त) {
		error_f("sshbuf_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ done;
	}

	यदि ((r = sshbuf_put(tosign, MAGIC_PREAMBLE, MAGIC_PREAMBLE_LEN)) != 0 ||
	    (r = sshbuf_put_cstring(tosign, sig_namespace)) != 0 ||
	    (r = sshbuf_put_string(tosign, रिक्त, 0)) != 0 || /* reserved */
	    (r = sshbuf_put_cstring(tosign, hashalg)) != 0 ||
	    (r = sshbuf_put_stringb(tosign, h_message)) != 0) {
		error_fr(r, "assemble message to sign");
		गच्छ done;
	}

	/* If using RSA keys then default to a good signature algorithm */
	यदि (sshkey_type_plain(कुंजी->type) == कुंजी_RSA) {
		sign_alg = RSA_SIGN_ALG;
		यदि (म_भेद(hashalg, "sha256") == 0)
			sign_alg = "rsa-sha2-256";
		अन्यथा यदि (म_भेद(hashalg, "sha512") == 0)
			sign_alg = "rsa-sha2-512";
	}

	यदि (signer != रिक्त) {
		यदि ((r = signer(कुंजी, &sig, &slen,
		    sshbuf_ptr(tosign), sshbuf_len(tosign),
		    sign_alg, sk_provider, sk_pin, 0, signer_ctx)) != 0) {
			error_r(r, "Couldn't sign message (signer)");
			गच्छ done;
		}
	} अन्यथा {
		यदि ((r = sshkey_sign(कुंजी, &sig, &slen,
		    sshbuf_ptr(tosign), sshbuf_len(tosign),
		    sign_alg, sk_provider, sk_pin, 0)) != 0) {
			error_r(r, "Couldn't sign message");
			गच्छ done;
		}
	}

	यदि ((r = sshbuf_put(blob, MAGIC_PREAMBLE, MAGIC_PREAMBLE_LEN)) != 0 ||
	    (r = sshbuf_put_u32(blob, SIG_VERSION)) != 0 ||
	    (r = sshkey_puts(कुंजी, blob)) != 0 ||
	    (r = sshbuf_put_cstring(blob, sig_namespace)) != 0 ||
	    (r = sshbuf_put_string(blob, रिक्त, 0)) != 0 || /* reserved */
	    (r = sshbuf_put_cstring(blob, hashalg)) != 0 ||
	    (r = sshbuf_put_string(blob, sig, slen)) != 0) {
		error_fr(r, "assemble signature object");
		गच्छ done;
	}

	यदि (out != रिक्त) {
		*out = blob;
		blob = रिक्त;
	}
	r = 0;
done:
	मुक्त(sig);
	sshbuf_free(blob);
	sshbuf_free(tosign);
	प्रत्यागम r;
}

/* Check preamble and version. */
स्थिर पूर्णाङ्क
sshsig_parse_preamble(संरचना sshbuf *buf)
{
	पूर्णाङ्क r = SSH_ERR_INTERNAL_ERROR;
	uint32_t sversion;

	यदि ((r = sshbuf_cmp(buf, 0, MAGIC_PREAMBLE, MAGIC_PREAMBLE_LEN)) != 0 ||
	    (r = sshbuf_consume(buf, (परिमाण(MAGIC_PREAMBLE)-1))) != 0 ||
	    (r = sshbuf_get_u32(buf, &sversion)) != 0) {
		error("Couldn't verify signature: invalid format");
		प्रत्यागम r;
	}

	यदि (sversion > SIG_VERSION) {
		error("Signature version %lu is larger than supported "
		    "version %u", (अचिन्हित दीर्घ)sversion, SIG_VERSION);
		प्रत्यागम SSH_ERR_INVALID_FORMAT;
	}
	प्रत्यागम 0;
}

स्थिर पूर्णाङ्क
sshsig_check_hashalg(ध्रुव वर्ण *hashalg)
{
	यदि (hashalg == रिक्त ||
	    match_pattern_list(hashalg, HASHALG_ALLOWED, 0) == 1)
		प्रत्यागम 0;
	error_f("unsupported hash algorithm \"%.100s\"", hashalg);
	प्रत्यागम SSH_ERR_SIGN_ALG_UNSUPPORTED;
}

स्थिर पूर्णाङ्क
sshsig_peek_hashalg(संरचना sshbuf *signature, वर्ण **hashalgp)
{
	संरचना sshbuf *buf = रिक्त;
	वर्ण *hashalg = रिक्त;
	पूर्णाङ्क r = SSH_ERR_INTERNAL_ERROR;

	यदि (hashalgp != रिक्त)
		*hashalgp = रिक्त;
	यदि ((buf = sshbuf_fromb(signature)) == रिक्त)
		प्रत्यागम SSH_ERR_ALLOC_FAIL;
	यदि ((r = sshsig_parse_preamble(buf)) != 0)
		गच्छ done;
	यदि ((r = sshbuf_get_string_direct(buf, रिक्त, रिक्त)) != 0 ||
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
	प्रत्यागम r;
}

स्थिर पूर्णाङ्क
sshsig_wrap_verify(संरचना sshbuf *signature, ध्रुव वर्ण *hashalg,
    ध्रुव संरचना sshbuf *h_message, ध्रुव वर्ण *expect_namespace,
    संरचना sshkey **sign_keyp, संरचना sshkey_sig_details **sig_details)
{
	पूर्णाङ्क r = SSH_ERR_INTERNAL_ERROR;
	संरचना sshbuf *buf = रिक्त, *toverify = रिक्त;
	संरचना sshkey *कुंजी = रिक्त;
	ध्रुव u_char *sig;
	वर्ण *got_namespace = रिक्त, *sigtype = रिक्त, *sig_hashalg = रिक्त;
	माप_प्रकार siglen;

	debug_f("verify message length %zu", sshbuf_len(h_message));
	यदि (sig_details != रिक्त)
		*sig_details = रिक्त;
	यदि (sign_keyp != रिक्त)
		*sign_keyp = रिक्त;

	यदि ((toverify = sshbuf_new()) == रिक्त) {
		error_f("sshbuf_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ done;
	}
	यदि ((r = sshbuf_put(toverify, MAGIC_PREAMBLE,
	    MAGIC_PREAMBLE_LEN)) != 0 ||
	    (r = sshbuf_put_cstring(toverify, expect_namespace)) != 0 ||
	    (r = sshbuf_put_string(toverify, रिक्त, 0)) != 0 || /* reserved */
	    (r = sshbuf_put_cstring(toverify, hashalg)) != 0 ||
	    (r = sshbuf_put_stringb(toverify, h_message)) != 0) {
		error_fr(r, "assemble message to verify");
		गच्छ done;
	}

	यदि ((r = sshsig_parse_preamble(signature)) != 0)
		गच्छ done;

	यदि ((r = sshkey_froms(signature, &कुंजी)) != 0 ||
	    (r = sshbuf_get_cstring(signature, &got_namespace, रिक्त)) != 0 ||
	    (r = sshbuf_get_string(signature, रिक्त, रिक्त)) != 0 ||
	    (r = sshbuf_get_cstring(signature, &sig_hashalg, रिक्त)) != 0 ||
	    (r = sshbuf_get_string_direct(signature, &sig, &siglen)) != 0) {
		error_fr(r, "parse signature object");
		गच्छ done;
	}

	यदि (sshbuf_len(signature) != 0) {
		error("Signature contains trailing data");
		r = SSH_ERR_INVALID_FORMAT;
		गच्छ done;
	}

	यदि (म_भेद(expect_namespace, got_namespace) != 0) {
		error("Couldn't verify signature: namespace does not match");
		debug_f("expected namespace \"%s\" received \"%s\"",
		    expect_namespace, got_namespace);
		r = SSH_ERR_SIGNATURE_INVALID;
		गच्छ done;
	}
	यदि (म_भेद(hashalg, sig_hashalg) != 0) {
		error("Couldn't verify signature: hash algorithm mismatch");
		debug_f("expected algorithm \"%s\" received \"%s\"",
		    hashalg, sig_hashalg);
		r = SSH_ERR_SIGNATURE_INVALID;
		गच्छ done;
	}
	/* Ensure that RSA keys use an acceptable signature algorithm */
	यदि (sshkey_type_plain(कुंजी->type) == कुंजी_RSA) {
		यदि ((r = sshkey_get_sigtype(sig, siglen, &sigtype)) != 0) {
			error_r(r, "Couldn't verify signature: unable to get "
			    "signature type");
			गच्छ done;
		}
		यदि (match_pattern_list(sigtype, RSA_SIGN_ALLOWED, 0) != 1) {
			error("Couldn't verify signature: unsupported RSA "
			    "signature algorithm %s", sigtype);
			r = SSH_ERR_SIGN_ALG_UNSUPPORTED;
			गच्छ done;
		}
	}
	यदि ((r = sshkey_verify(कुंजी, sig, siglen, sshbuf_ptr(toverify),
	    sshbuf_len(toverify), रिक्त, 0, sig_details)) != 0) {
		error_r(r, "Signature verification failed");
		गच्छ done;
	}

	/* success */
	r = 0;
	यदि (sign_keyp != रिक्त) {
		*sign_keyp = कुंजी;
		कुंजी = रिक्त; /* transferred */
	}
done:
	मुक्त(got_namespace);
	मुक्त(sigtype);
	मुक्त(sig_hashalg);
	sshbuf_free(buf);
	sshbuf_free(toverify);
	sshkey_free(कुंजी);
	प्रत्यागम r;
}

स्थिर पूर्णाङ्क
hash_buffer(ध्रुव संरचना sshbuf *m, ध्रुव वर्ण *hashalg, संरचना sshbuf **bp)
{
	वर्ण *hex, hash[SSH_DIGEST_MAX_LENGTH];
	पूर्णाङ्क alg, r = SSH_ERR_INTERNAL_ERROR;
	संरचना sshbuf *b = रिक्त;

	*bp = रिक्त;
	स_रखो(hash, 0, परिमाण(hash));

	यदि ((r = sshsig_check_hashalg(hashalg)) != 0)
		प्रत्यागम r;
	यदि ((alg = ssh_digest_alg_by_name(hashalg)) == -1) {
		error_f("can't look up hash algorithm %s", hashalg);
		प्रत्यागम SSH_ERR_INTERNAL_ERROR;
	}
	यदि ((r = ssh_digest_buffer(alg, m, hash, परिमाण(hash))) != 0) {
		error_fr(r, "ssh_digest_buffer");
		प्रत्यागम r;
	}
	यदि ((hex = tohex(hash, ssh_digest_bytes(alg))) != रिक्त) {
		debug3_f("final hash: %s", hex);
		freezero(hex, म_माप(hex));
	}
	यदि ((b = sshbuf_new()) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ out;
	}
	यदि ((r = sshbuf_put(b, hash, ssh_digest_bytes(alg))) != 0) {
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
	प्रत्यागम r;
}

पूर्णाङ्क
sshsig_signb(संरचना sshkey *कुंजी, ध्रुव वर्ण *hashalg,
    ध्रुव वर्ण *sk_provider, ध्रुव वर्ण *sk_pin,
    ध्रुव संरचना sshbuf *message, ध्रुव वर्ण *sig_namespace,
    संरचना sshbuf **out, sshsig_signer *signer, शून्य *signer_ctx)
{
	संरचना sshbuf *b = रिक्त;
	पूर्णाङ्क r = SSH_ERR_INTERNAL_ERROR;

	यदि (hashalg == रिक्त)
		hashalg = HASHALG_DEFAULT;
	यदि (out != रिक्त)
		*out = रिक्त;
	यदि ((r = hash_buffer(message, hashalg, &b)) != 0) {
		error_fr(r, "hash buffer");
		गच्छ out;
	}
	यदि ((r = sshsig_wrap_sign(कुंजी, hashalg, sk_provider, sk_pin, b,
	    sig_namespace, out, signer, signer_ctx)) != 0)
		गच्छ out;
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	प्रत्यागम r;
}

पूर्णाङ्क
sshsig_verifyb(संरचना sshbuf *signature, ध्रुव संरचना sshbuf *message,
    ध्रुव वर्ण *expect_namespace, संरचना sshkey **sign_keyp,
    संरचना sshkey_sig_details **sig_details)
{
	संरचना sshbuf *b = रिक्त;
	पूर्णाङ्क r = SSH_ERR_INTERNAL_ERROR;
	वर्ण *hashalg = रिक्त;

	यदि (sig_details != रिक्त)
		*sig_details = रिक्त;
	यदि (sign_keyp != रिक्त)
		*sign_keyp = रिक्त;
	यदि ((r = sshsig_peek_hashalg(signature, &hashalg)) != 0)
		प्रत्यागम r;
	debug_f("signature made with hash \"%s\"", hashalg);
	यदि ((r = hash_buffer(message, hashalg, &b)) != 0) {
		error_fr(r, "hash buffer");
		गच्छ out;
	}
	यदि ((r = sshsig_wrap_verify(signature, hashalg, b, expect_namespace,
	    sign_keyp, sig_details)) != 0)
		गच्छ out;
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	मुक्त(hashalg);
	प्रत्यागम r;
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
	स_रखो(hash, 0, परिमाण(hash));

	यदि ((r = sshsig_check_hashalg(hashalg)) != 0)
		प्रत्यागम r;
	यदि ((alg = ssh_digest_alg_by_name(hashalg)) == -1) {
		error_f("can't look up hash algorithm %s", hashalg);
		प्रत्यागम SSH_ERR_INTERNAL_ERROR;
	}
	यदि ((ctx = ssh_digest_start(alg)) == रिक्त) {
		error_f("ssh_digest_start failed");
		प्रत्यागम SSH_ERR_INTERNAL_ERROR;
	}
	प्रति (;;) {
		यदि ((n = पठ(fd, rbuf, परिमाण(rbuf))) == -1) {
			यदि (त्रुटि_सं == EINTR || त्रुटि_सं == EAGAIN)
				अनुवर्त;
			oerrno = त्रुटि_सं;
			error_f("read: %s", म_त्रुटि(त्रुटि_सं));
			त्रुटि_सं = oerrno;
			r = SSH_ERR_SYSTEM_ERROR;
			गच्छ out;
		} अन्यथा यदि (n == 0) {
			debug2_f("hashed %zu bytes", total);
			भङ्ग; /* EOF */
		}
		total += (माप_प्रकार)n;
		यदि ((r = ssh_digest_update(ctx, rbuf, (माप_प्रकार)n)) != 0) {
			error_fr(r, "ssh_digest_update");
			गच्छ out;
		}
	}
	यदि ((r = ssh_digest_final(ctx, hash, परिमाण(hash))) != 0) {
		error_fr(r, "ssh_digest_final");
		गच्छ out;
	}
	यदि ((hex = tohex(hash, ssh_digest_bytes(alg))) != रिक्त) {
		debug3_f("final hash: %s", hex);
		freezero(hex, म_माप(hex));
	}
	यदि ((b = sshbuf_new()) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ out;
	}
	यदि ((r = sshbuf_put(b, hash, ssh_digest_bytes(alg))) != 0) {
		error_fr(r, "sshbuf_put");
		गच्छ out;
	}
	*bp = b;
	b = रिक्त; /* transferred */
	/* success */
	r = 0;
 out:
	oerrno = त्रुटि_सं;
	sshbuf_free(b);
	ssh_digest_free(ctx);
	explicit_bzero(hash, परिमाण(hash));
	त्रुटि_सं = oerrno;
	प्रत्यागम r;
}

पूर्णाङ्क
sshsig_sign_fd(संरचना sshkey *कुंजी, ध्रुव वर्ण *hashalg,
    ध्रुव वर्ण *sk_provider, ध्रुव वर्ण *sk_pin,
    पूर्णाङ्क fd, ध्रुव वर्ण *sig_namespace, संरचना sshbuf **out,
    sshsig_signer *signer, शून्य *signer_ctx)
{
	संरचना sshbuf *b = रिक्त;
	पूर्णाङ्क r = SSH_ERR_INTERNAL_ERROR;

	यदि (hashalg == रिक्त)
		hashalg = HASHALG_DEFAULT;
	यदि (out != रिक्त)
		*out = रिक्त;
	यदि ((r = hash_file(fd, hashalg, &b)) != 0) {
		error_fr(r, "hash_file");
		प्रत्यागम r;
	}
	यदि ((r = sshsig_wrap_sign(कुंजी, hashalg, sk_provider, sk_pin, b,
	    sig_namespace, out, signer, signer_ctx)) != 0)
		गच्छ out;
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	प्रत्यागम r;
}

पूर्णाङ्क
sshsig_verify_fd(संरचना sshbuf *signature, पूर्णाङ्क fd,
    ध्रुव वर्ण *expect_namespace, संरचना sshkey **sign_keyp,
    संरचना sshkey_sig_details **sig_details)
{
	संरचना sshbuf *b = रिक्त;
	पूर्णाङ्क r = SSH_ERR_INTERNAL_ERROR;
	वर्ण *hashalg = रिक्त;

	यदि (sig_details != रिक्त)
		*sig_details = रिक्त;
	यदि (sign_keyp != रिक्त)
		*sign_keyp = रिक्त;
	यदि ((r = sshsig_peek_hashalg(signature, &hashalg)) != 0)
		प्रत्यागम r;
	debug_f("signature made with hash \"%s\"", hashalg);
	यदि ((r = hash_file(fd, hashalg, &b)) != 0) {
		error_fr(r, "hash_file");
		गच्छ out;
	}
	यदि ((r = sshsig_wrap_verify(signature, hashalg, b, expect_namespace,
	    sign_keyp, sig_details)) != 0)
		गच्छ out;
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	मुक्त(hashalg);
	प्रत्यागम r;
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

	यदि ((ret = सुस्मृति(1, परिमाण(*ret))) == रिक्त)
		प्रत्यागम रिक्त;
	यदि (opts == रिक्त || *opts == '\0')
		प्रत्यागम ret; /* Empty options yields empty options :) */

	यावत् (*opts && *opts != ' ' && *opts != '\t') {
		/* flag options */
		यदि ((r = opt_flag("cert-authority", 0, &opts)) != -1) {
			ret->ca = 1;
		} अन्यथा यदि (opt_match(&opts, "namespaces")) {
			यदि (ret->namespaces != रिक्त) {
				errstr = "multiple \"namespaces\" clauses";
				गच्छ fail;
			}
			ret->namespaces = opt_dequote(&opts, &errstr);
			यदि (ret->namespaces == रिक्त)
				गच्छ fail;
		} अन्यथा यदि (opt_match(&opts, "valid-after")) {
			यदि (ret->valid_after != 0) {
				errstr = "multiple \"valid-after\" clauses";
				गच्छ fail;
			}
			यदि ((opt = opt_dequote(&opts, &errstr)) == रिक्त)
				गच्छ fail;
			यदि (parse_absolute_time(opt, &ret->valid_after) != 0 ||
			    ret->valid_after == 0) {
				मुक्त(opt);
				errstr = "invalid \"valid-after\" time";
				गच्छ fail;
			}
			मुक्त(opt);
		} अन्यथा यदि (opt_match(&opts, "valid-before")) {
			यदि (ret->valid_before != 0) {
				errstr = "multiple \"valid-before\" clauses";
				गच्छ fail;
			}
			यदि ((opt = opt_dequote(&opts, &errstr)) == रिक्त)
				गच्छ fail;
			यदि (parse_absolute_time(opt, &ret->valid_before) != 0 ||
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
		यदि (*opts == '\0' || *opts == ' ' || *opts == '\t')
			भङ्ग;		/* End of options. */
		/* Anything other than a comma is an unknown option */
		यदि (*opts != ',') {
			errstr = "unknown key option";
			गच्छ fail;
		}
		opts++;
		यदि (*opts == '\0') {
			errstr = "unexpected end-of-options";
			गच्छ fail;
		}
	}
	/* final consistency check */
	यदि (ret->valid_after != 0 && ret->valid_before != 0 &&
	    ret->valid_before <= ret->valid_after) {
		errstr = "\"valid-before\" time is before \"valid-after\"";
		गच्छ fail;
	}
	/* success */
	प्रत्यागम ret;
 fail:
	यदि (errstrp != रिक्त)
		*errstrp = errstr;
	sshsigopt_free(ret);
	प्रत्यागम रिक्त;
}

शून्य
sshsigopt_free(संरचना sshsigopt *opts)
{
	यदि (opts == रिक्त)
		प्रत्यागम;
	मुक्त(opts->namespaces);
	मुक्त(opts);
}

स्थिर पूर्णाङ्क
parse_principals_कुंजी_and_options(ध्रुव वर्ण *path, u_long linenum, वर्ण *पंक्ति,
    ध्रुव वर्ण *required_principal, वर्ण **principalsp, संरचना sshkey **keyp,
    संरचना sshsigopt **sigoptsp)
{
	वर्ण *opts = रिक्त, *tmp, *cp, *principals = रिक्त;
	ध्रुव वर्ण *reason = रिक्त;
	संरचना sshsigopt *sigopts = रिक्त;
	संरचना sshkey *कुंजी = रिक्त;
	पूर्णाङ्क r = SSH_ERR_INTERNAL_ERROR;

	यदि (principalsp != रिक्त)
		*principalsp = रिक्त;
	यदि (sigoptsp != रिक्त)
		*sigoptsp = रिक्त;
	यदि (keyp != रिक्त)
		*keyp = रिक्त;

	cp = पंक्ति;
	cp = cp + म_अखोज(cp, " \t\n\r"); /* skip leading whitespace */
	यदि (*cp == '#' || *cp == '\0')
		प्रत्यागम SSH_ERR_कुंजी_NOT_FOUND; /* blank or all-comment line */

	/* format: identity[,identity...] [option[,option...]] key */
	यदि ((tmp = strdelimw(&cp)) == रिक्त || cp == रिक्त) {
		error("%s:%lu: invalid line", path, linenum);
		r = SSH_ERR_INVALID_FORMAT;
		गच्छ out;
	}
	यदि ((principals = strdup(tmp)) == रिक्त) {
		error_f("strdup failed");
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ out;
	}
	/*
	 * Bail out early if we're looking for a particular principal and this
	 * line does not list it.
	 */
	यदि (required_principal != रिक्त) {
		यदि (match_pattern_list(required_principal,
		    principals, 0) != 1) {
			/* principal didn't match */
			r = SSH_ERR_कुंजी_NOT_FOUND;
			गच्छ out;
		}
		debug_f("%s:%lu: matched principal \"%s\"",
		    path, linenum, required_principal);
	}

	यदि ((कुंजी = sshkey_new(कुंजी_UNSPEC)) == रिक्त) {
		error_f("sshkey_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ out;
	}
	यदि (sshkey_read(कुंजी, &cp) != 0) {
		/* no key? Check for options */
		opts = cp;
		यदि (sshkey_advance_past_options(&cp) != 0) {
			error("%s:%lu: invalid options", path, linenum);
			r = SSH_ERR_INVALID_FORMAT;
			गच्छ out;
		}
		यदि (cp == रिक्त || *cp == '\0') {
			error("%s:%lu: missing key", path, linenum);
			r = SSH_ERR_INVALID_FORMAT;
			गच्छ out;
		}
		*cp++ = '\0';
		skip_space(&cp);
		यदि (sshkey_read(कुंजी, &cp) != 0) {
			error("%s:%lu: invalid key", path, linenum);
			r = SSH_ERR_INVALID_FORMAT;
			गच्छ out;
		}
	}
	debug3("%s:%lu: options %s", path, linenum, opts == रिक्त ? "" : opts);
	यदि ((sigopts = sshsigopt_parse(opts, path, linenum, &reason)) == रिक्त) {
		error("%s:%lu: bad options: %s", path, linenum, reason);
		r = SSH_ERR_INVALID_FORMAT;
		गच्छ out;
	}
	/* success */
	यदि (principalsp != रिक्त) {
		*principalsp = principals;
		principals = रिक्त; /* transferred */
	}
	यदि (sigoptsp != रिक्त) {
		*sigoptsp = sigopts;
		sigopts = रिक्त; /* transferred */
	}
	यदि (keyp != रिक्त) {
		*keyp = कुंजी;
		कुंजी = रिक्त; /* transferred */
	}
	r = 0;
 out:
	मुक्त(principals);
	sshsigopt_free(sigopts);
	sshkey_free(कुंजी);
	प्रत्यागम r;
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

	यदि ((nprincipals = sshbuf_new()) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ out;
	}

	यावत् ((cp = strsep(&principals, ",")) != रिक्त && *cp != '\0') {
		/* Check certificate validity */
		यदि ((r = sshkey_cert_check_authority(cert, 0, 0, verify_time,
		    रिक्त, &reason)) != 0) {
			debug("%s:%lu: principal \"%s\" not authorized: %s",
			    path, linenum, cp, reason);
			अनुवर्त;
		}
		/* Return all matching principal names from the cert */
		प्रति (i = 0; i < cert->cert->nprincipals; i++) {
			यदि (match_pattern(cert->cert->principals[i], cp)) {
				यदि ((r = sshbuf_putf(nprincipals, "%s%s",
					sshbuf_len(nprincipals) != 0 ? "," : "",
						cert->cert->principals[i])) != 0) {
					error_f("buffer error");
					गच्छ out;
				}
			}
		}
	}
	यदि (sshbuf_len(nprincipals) == 0) {
		error("%s:%lu: no valid principals found", path, linenum);
		r = SSH_ERR_कुंजी_CERT_INVALID;
		गच्छ out;
	}
	यदि ((principals = sshbuf_dup_string(nprincipals)) == रिक्त) {
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
	प्रत्यागम success ? 0 : r;
}

स्थिर पूर्णाङ्क
check_allowed_कुंजियाँ_पंक्ति(ध्रुव वर्ण *path, u_long linenum, वर्ण *पंक्ति,
    ध्रुव संरचना sshkey *sign_कुंजी, ध्रुव वर्ण *principal,
    ध्रुव वर्ण *sig_namespace, uint64_t verify_time, वर्ण **principalsp)
{
	संरचना sshkey *found_कुंजी = रिक्त;
	वर्ण *principals = रिक्त;
	पूर्णाङ्क r, success = 0;
	ध्रुव वर्ण *reason = रिक्त;
	संरचना sshsigopt *sigopts = रिक्त;
	वर्ण tvalid[64], tverify[64];

	यदि (principalsp != रिक्त)
		*principalsp = रिक्त;

	/* Parse the line */
	यदि ((r = parse_principals_कुंजी_and_options(path, linenum, पंक्ति,
	    principal, &principals, &found_कुंजी, &sigopts)) != 0) {
		/* error already logged */
		गच्छ done;
	}

	यदि (!sigopts->ca && sshkey_equal(found_कुंजी, sign_कुंजी)) {
		/* Exact match of key */
		debug("%s:%lu: matched key", path, linenum);
	} अन्यथा यदि (sigopts->ca && sshkey_is_cert(sign_कुंजी) &&
	    sshkey_equal_public(sign_कुंजी->cert->signature_कुंजी, found_कुंजी)) {
		यदि (principal) {
			/* Match certificate CA key with specified principal */
			यदि ((r = sshkey_cert_check_authority(sign_कुंजी, 0, 0,
			    verify_time, principal, &reason)) != 0) {
				error("%s:%lu: certificate not authorized: %s",
				    path, linenum, reason);
				गच्छ done;
			}
			debug("%s:%lu: matched certificate CA key",
			    path, linenum);
		} अन्यथा {
			/* No principal specified - find all matching ones */
			यदि ((r = cert_filter_principals(path, linenum,
			    &principals, sign_कुंजी, verify_time)) != 0) {
				/* error already displayed */
				debug_r(r, "%s:%lu: cert_filter_principals",
				    path, linenum);
				गच्छ done;
			}
			debug("%s:%lu: matched certificate CA key",
			    path, linenum);
		}
	} अन्यथा {
		/* Didn't match key */
		गच्छ done;
	}

	/* Check whether options preclude the use of this key */
	यदि (sigopts->namespaces != रिक्त && sig_namespace != रिक्त &&
	    match_pattern_list(sig_namespace, sigopts->namespaces, 0) != 1) {
		error("%s:%lu: key is not permitted for use in signature "
		    "namespace \"%s\"", path, linenum, sig_namespace);
		गच्छ done;
	}

	/* check key time validity */
	format_absolute_time((uint64_t)verify_time, tverify, परिमाण(tverify));
	यदि (sigopts->valid_after != 0 &&
	    (uint64_t)verify_time < sigopts->valid_after) {
		format_absolute_time(sigopts->valid_after,
		    tvalid, परिमाण(tvalid));
		error("%s:%lu: key is not yet valid: "
		    "verify time %s < valid-after %s", path, linenum,
		    tverify, tvalid);
		गच्छ done;
	}
	यदि (sigopts->valid_before != 0 &&
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
	यदि (success && principalsp != रिक्त) {
		*principalsp = principals;
		principals = रिक्त; /* transferred */
	}
	मुक्त(principals);
	sshkey_free(found_कुंजी);
	sshsigopt_free(sigopts);
	प्रत्यागम success ? 0 : SSH_ERR_कुंजी_NOT_FOUND;
}

पूर्णाङ्क
sshsig_check_allowed_कुंजियाँ(ध्रुव वर्ण *path, ध्रुव संरचना sshkey *sign_कुंजी,
    ध्रुव वर्ण *principal, ध्रुव वर्ण *sig_namespace, uint64_t verify_time)
{
	खाता *f = रिक्त;
	वर्ण *पंक्ति = रिक्त;
	माप_प्रकार linesize = 0;
	u_long linenum = 0;
	पूर्णाङ्क r = SSH_ERR_कुंजी_NOT_FOUND, oerrno;

	/* Check key and principal against file */
	यदि ((f = ख_खोलो(path, "r")) == रिक्त) {
		oerrno = त्रुटि_सं;
		error("Unable to open allowed keys file \"%s\": %s",
		    path, म_त्रुटि(त्रुटि_सं));
		त्रुटि_सं = oerrno;
		प्रत्यागम SSH_ERR_SYSTEM_ERROR;
	}

	यावत् (getline(&पंक्ति, &linesize, f) != -1) {
		linenum++;
		r = check_allowed_कुंजियाँ_पंक्ति(path, linenum, पंक्ति, sign_कुंजी,
		    principal, sig_namespace, verify_time, रिक्त);
		मुक्त(पंक्ति);
		पंक्ति = रिक्त;
		linesize = 0;
		यदि (r == SSH_ERR_कुंजी_NOT_FOUND)
			अनुवर्त;
		अन्यथा यदि (r == 0) {
			/* success */
			ख_बंद(f);
			प्रत्यागम 0;
		} अन्यथा
			भङ्ग;
	}
	/* Either we hit an error parsing or we simply didn't find the key */
	ख_बंद(f);
	मुक्त(पंक्ति);
	प्रत्यागम r;
}

पूर्णाङ्क
sshsig_find_principals(ध्रुव वर्ण *path, ध्रुव संरचना sshkey *sign_कुंजी,
    uint64_t verify_time, वर्ण **principals)
{
	खाता *f = रिक्त;
	वर्ण *पंक्ति = रिक्त;
	माप_प्रकार linesize = 0;
	u_long linenum = 0;
	पूर्णाङ्क r = SSH_ERR_कुंजी_NOT_FOUND, oerrno;

	यदि ((f = ख_खोलो(path, "r")) == रिक्त) {
		oerrno = त्रुटि_सं;
		error("Unable to open allowed keys file \"%s\": %s",
		    path, म_त्रुटि(त्रुटि_सं));
		त्रुटि_सं = oerrno;
		प्रत्यागम SSH_ERR_SYSTEM_ERROR;
	}

	यावत् (getline(&पंक्ति, &linesize, f) != -1) {
		linenum++;
		r = check_allowed_कुंजियाँ_पंक्ति(path, linenum, पंक्ति,
		    sign_कुंजी, रिक्त, रिक्त, verify_time, principals);
		मुक्त(पंक्ति);
		पंक्ति = रिक्त;
		linesize = 0;
		यदि (r == SSH_ERR_कुंजी_NOT_FOUND)
			अनुवर्त;
		अन्यथा यदि (r == 0) {
			/* success */
			ख_बंद(f);
			प्रत्यागम 0;
		} अन्यथा
			भङ्ग;
	}
	मुक्त(पंक्ति);
	/* Either we hit an error parsing or we simply didn't find the key */
	यदि (ख_त्रुटि(f) != 0) {
		oerrno = त्रुटि_सं;
		ख_बंद(f);
		error("Unable to read allowed keys file \"%s\": %s",
		    path, म_त्रुटि(त्रुटि_सं));
		त्रुटि_सं = oerrno;
		प्रत्यागम SSH_ERR_SYSTEM_ERROR;
	}
	ख_बंद(f);
	प्रत्यागम r;
}

पूर्णाङ्क
sshsig_match_principals(ध्रुव वर्ण *path, ध्रुव वर्ण *principal,
    वर्ण ***principalsp, माप_प्रकार *nprincipalsp)
{
	खाता *f = रिक्त;
	वर्ण *found, *पंक्ति = रिक्त, **principals = रिक्त, **tmp;
	माप_प्रकार i, nprincipals = 0, linesize = 0;
	u_long linenum = 0;
	पूर्णाङ्क oerrno = 0, r, ret = 0;

	यदि (principalsp != रिक्त)
		*principalsp = रिक्त;
	यदि (nprincipalsp != रिक्त)
		*nprincipalsp = 0;

	/* Check key and principal against file */
	यदि ((f = ख_खोलो(path, "r")) == रिक्त) {
		oerrno = त्रुटि_सं;
		error("Unable to open allowed keys file \"%s\": %s",
		    path, म_त्रुटि(त्रुटि_सं));
		त्रुटि_सं = oerrno;
		प्रत्यागम SSH_ERR_SYSTEM_ERROR;
	}

	यावत् (getline(&पंक्ति, &linesize, f) != -1) {
		linenum++;
		/* Parse the line */
		यदि ((r = parse_principals_कुंजी_and_options(path, linenum, पंक्ति,
		    principal, &found, रिक्त, रिक्त)) != 0) {
			यदि (r == SSH_ERR_कुंजी_NOT_FOUND)
				अनुवर्त;
			ret = r;
			oerrno = त्रुटि_सं;
			भङ्ग; /* unexpected error */
		}
		यदि ((tmp = recallocarray(principals, nprincipals,
		    nprincipals + 1, परिमाण(*principals))) == रिक्त) {
			ret = SSH_ERR_ALLOC_FAIL;
			मुक्त(found);
			भङ्ग;
		}
		principals = tmp;
		principals[nprincipals++] = found; /* transferred */
		मुक्त(पंक्ति);
		पंक्ति = रिक्त;
		linesize = 0;
	}
	ख_बंद(f);
	मुक्त(पंक्ति);

	यदि (ret == 0) {
		यदि (nprincipals == 0)
			ret = SSH_ERR_कुंजी_NOT_FOUND;
		यदि (nprincipalsp != रिक्त)
			*nprincipalsp = nprincipals;
		यदि (principalsp != रिक्त) {
			*principalsp = principals;
			principals = रिक्त; /* transferred */
			nprincipals = 0;
		}
	}

	प्रति (i = 0; i < nprincipals; i++)
		मुक्त(principals[i]);
	मुक्त(principals);

	त्रुटि_सं = oerrno;
	प्रत्यागम ret;
}

पूर्णाङ्क
sshsig_get_pubkey(संरचना sshbuf *signature, संरचना sshkey **pubkey)
{
	संरचना sshkey *pk = रिक्त;
	पूर्णाङ्क r = SSH_ERR_SIGNATURE_INVALID;

	यदि (pubkey == रिक्त)
		प्रत्यागम SSH_ERR_INTERNAL_ERROR;
	यदि ((r = sshsig_parse_preamble(signature)) != 0)
		प्रत्यागम r;
	यदि ((r = sshkey_froms(signature, &pk)) != 0)
		प्रत्यागम r;

	*pubkey = pk;
	pk = रिक्त;
	प्रत्यागम 0;
}
