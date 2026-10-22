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

#परिभाषय SIG_संस्करणम्		0x01
#परिभाषय MAGIC_PREAMBLE		"SSHSIG"
#परिभाषय MAGIC_PREAMBLE_LEN	(परिमाण(MAGIC_PREAMBLE) - 1)
#परिभाषय BEGIN_SIGNATURE		"-----BEGIN SSH SIGNATURE-----"
#परिभाषय अन्तः_SIGNATURE		"-----END SSH SIGNATURE-----"
#परिभाषय RSA_SIGN_ALG		"rsa-sha2-512"
#परिभाषय RSA_SIGN_ALLOWED	"rsa-sha2-512,rsa-sha2-256"
#परिभाषय HASHALG_DEFAULT		"sha512"
#परिभाषय HASHALG_ALLOWED		"sha256,sha512"

पूर्णाङ्क
sshsig_armor(ध्रुव संरचना sshbuf *blob, संरचना sshbuf **बहिर्गमनम्)
{
	संरचना sshbuf *buf = रिक्त;
	पूर्णाङ्क r = SSH_ERR_आन्तरिकम्_ERROR;

	*बहिर्गमनम् = रिक्त;

	यदि ((buf = sshbuf_new()) == रिक्त) {
		error_f("sshbuf_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ बहिर्गमनम्;
	}

	यदि ((r = sshbuf_putf(buf, "%s\n", BEGIN_SIGNATURE)) != 0) {
		error_fr(r, "sshbuf_putf");
		गच्छ बहिर्गमनम्;
	}

	यदि ((r = sshbuf_dtob64(blob, buf, 1)) != 0) {
		error_fr(r, "base64 encode signature");
		गच्छ बहिर्गमनम्;
	}

	यदि ((r = sshbuf_put(buf, अन्तः_SIGNATURE,
	    परिमाण(अन्तः_SIGNATURE)-1)) != 0 ||
	    (r = sshbuf_put_u8(buf, '\n')) != 0) {
		error_fr(r, "sshbuf_put");
		गच्छ बहिर्गमनम्;
	}
	/* success */
	*बहिर्गमनम् = buf;
	buf = रिक्त; /* transferred */
	r = 0;
 बहिर्गमनम्:
	sshbuf_free(buf);
	प्रत्यागम r;
}

पूर्णाङ्क
sshsig_dearmor(संरचना sshbuf *sig, संरचना sshbuf **बहिर्गमनम्)
{
	पूर्णाङ्क r;
	आकार_t eoffset = 0;
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
		गच्छ समाप्तम्;
	}
	यदि ((r = sshbuf_consume(sbuf, परिमाण(BEGIN_SIGNATURE)-1)) != 0) {
		error_fr(r, "consume");
		गच्छ समाप्तम्;
	}
	यदि ((r = sshbuf_cmp(sbuf, 0, "\r\n", 2)) == 0)
		eoffset = 2;
	अन्यथा यदि ((r = sshbuf_cmp(sbuf, 0, "\n", 1)) == 0)
		eoffset = 1;
	अन्यथा {
		r = SSH_ERR_INVALID_FORMAT;
		error_f("no header eol");
		गच्छ समाप्तम्;
	}
	यदि ((r = sshbuf_consume(sbuf, eoffset)) != 0) {
		error_fr(r, "consume eol");
		गच्छ समाप्तम्;
	}
	/* Find and consume lf + suffix (any prior cr would be ignored) */
	यदि ((r = sshbuf_find(sbuf, 0, "\n" अन्तः_SIGNATURE,
	    परिमाण(अन्तः_SIGNATURE), &eoffset)) != 0) {
		error("Couldn't parse signature: missing footer");
		गच्छ समाप्तम्;
	}
	यदि ((r = sshbuf_consume_अन्तः(sbuf, sshbuf_len(sbuf)-eoffset)) != 0) {
		error_fr(r, "consume");
		गच्छ समाप्तम्;
	}

	यदि ((b64 = sshbuf_dup_string(sbuf)) == रिक्त) {
		error_f("sshbuf_dup_string failed");
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ समाप्तम्;
	}

	यदि ((buf = sshbuf_new()) == रिक्त) {
		error_f("sshbuf_new() failed");
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ समाप्तम्;
	}

	यदि ((r = sshbuf_b64tod(buf, b64)) != 0) {
		error_fr(r, "decode base64");
		गच्छ समाप्तम्;
	}

	/* success */
	*बहिर्गमनम् = buf;
	r = 0;
	buf = रिक्त; /* transferred */
समाप्तम्:
	sshbuf_free(buf);
	sshbuf_free(sbuf);
	मुक्त(b64);
	प्रत्यागम r;
}

स्थिर पूर्णाङ्क
sshsig_wrap_sign(संरचना sshkey *कुञ्चिका, ध्रुव वर्ण *hashalg,
    ध्रुव वर्ण *sk_provider, ध्रुव वर्ण *sk_pin, ध्रुव संरचना sshbuf *h_सन्देशः,
    ध्रुव वर्ण *sig_namespace, संरचना sshbuf **बहिर्गमनम्,
    sshsig_signer *signer, शून्य *signer_ctx)
{
	पूर्णाङ्क r;
	आकार_t slen = 0;
	u_char *sig = रिक्त;
	संरचना sshbuf *blob = रिक्त;
	संरचना sshbuf *tosign = रिक्त;
	ध्रुव वर्ण *sign_alg = रिक्त;

	यदि ((tosign = sshbuf_new()) == रिक्त ||
	    (blob = sshbuf_new()) == रिक्त) {
		error_f("sshbuf_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ समाप्तम्;
	}

	यदि ((r = sshbuf_put(tosign, MAGIC_PREAMBLE, MAGIC_PREAMBLE_LEN)) != 0 ||
	    (r = sshbuf_put_cstring(tosign, sig_namespace)) != 0 ||
	    (r = sshbuf_put_string(tosign, रिक्त, 0)) != 0 || /* reserved */
	    (r = sshbuf_put_cstring(tosign, hashalg)) != 0 ||
	    (r = sshbuf_put_stringb(tosign, h_सन्देशः)) != 0) {
		error_fr(r, "assemble message to sign");
		गच्छ समाप्तम्;
	}

	/* If using RSA keys then default to a good signature algorithm */
	यदि (sshkey_type_plain(कुञ्चिका->type) == कुञ्चिका_RSA) {
		sign_alg = RSA_SIGN_ALG;
		यदि (वाक्यं_तुलय(hashalg, "sha256") == 0)
			sign_alg = "rsa-sha2-256";
		अन्यथा यदि (वाक्यं_तुलय(hashalg, "sha512") == 0)
			sign_alg = "rsa-sha2-512";
	}

	यदि (signer != रिक्त) {
		यदि ((r = signer(कुञ्चिका, &sig, &slen,
		    sshbuf_ptr(tosign), sshbuf_len(tosign),
		    sign_alg, sk_provider, sk_pin, 0, signer_ctx)) != 0) {
			error_r(r, "Couldn't sign message (signer)");
			गच्छ समाप्तम्;
		}
	} अन्यथा {
		यदि ((r = sshkey_sign(कुञ्चिका, &sig, &slen,
		    sshbuf_ptr(tosign), sshbuf_len(tosign),
		    sign_alg, sk_provider, sk_pin, 0)) != 0) {
			error_r(r, "Couldn't sign message");
			गच्छ समाप्तम्;
		}
	}

	यदि ((r = sshbuf_put(blob, MAGIC_PREAMBLE, MAGIC_PREAMBLE_LEN)) != 0 ||
	    (r = sshbuf_put_u32(blob, SIG_संस्करणम्)) != 0 ||
	    (r = sshkey_puts(कुञ्चिका, blob)) != 0 ||
	    (r = sshbuf_put_cstring(blob, sig_namespace)) != 0 ||
	    (r = sshbuf_put_string(blob, रिक्त, 0)) != 0 || /* reserved */
	    (r = sshbuf_put_cstring(blob, hashalg)) != 0 ||
	    (r = sshbuf_put_string(blob, sig, slen)) != 0) {
		error_fr(r, "assemble signature object");
		गच्छ समाप्तम्;
	}

	यदि (बहिर्गमनम् != रिक्त) {
		*बहिर्गमनम् = blob;
		blob = रिक्त;
	}
	r = 0;
समाप्तम्:
	मुक्त(sig);
	sshbuf_free(blob);
	sshbuf_free(tosign);
	प्रत्यागम r;
}

/* Check preamble and version. */
स्थिर पूर्णाङ्क
sshsig_parse_preamble(संरचना sshbuf *buf)
{
	पूर्णाङ्क r = SSH_ERR_आन्तरिकम्_ERROR;
	uint32_t sversion;

	यदि ((r = sshbuf_cmp(buf, 0, MAGIC_PREAMBLE, MAGIC_PREAMBLE_LEN)) != 0 ||
	    (r = sshbuf_consume(buf, (परिमाण(MAGIC_PREAMBLE)-1))) != 0 ||
	    (r = sshbuf_get_u32(buf, &sversion)) != 0) {
		error("Couldn't verify signature: invalid format");
		प्रत्यागम r;
	}

	यदि (sversion > SIG_संस्करणम्) {
		error("Signature version %lu is larger than supported "
		    "version %u", (अचिह्नित दीर्घ)sversion, SIG_संस्करणम्);
		प्रत्यागम SSH_ERR_INVALID_FORMAT;
	}
	प्रत्यागम 0;
}

स्थिर पूर्णाङ्क
sshsig_check_hashalg(ध्रुव वर्ण *hashalg)
{
	यदि (hashalg == रिक्त ||
	    मेलनम्_आदर्शः_list(hashalg, HASHALG_ALLOWED, 0) == 1)
		प्रत्यागम 0;
	error_f("unsupported hash algorithm \"%.100s\"", hashalg);
	प्रत्यागम SSH_ERR_SIGN_ALG_UNSUPPORTED;
}

स्थिर पूर्णाङ्क
sshsig_peek_hashalg(संरचना sshbuf *signature, वर्ण **hashalgp)
{
	संरचना sshbuf *buf = रिक्त;
	वर्ण *hashalg = रिक्त;
	पूर्णाङ्क r = SSH_ERR_आन्तरिकम्_ERROR;

	यदि (hashalgp != रिक्त)
		*hashalgp = रिक्त;
	यदि ((buf = sshbuf_fromb(signature)) == रिक्त)
		प्रत्यागम SSH_ERR_ALLOC_FAIL;
	यदि ((r = sshsig_parse_preamble(buf)) != 0)
		गच्छ समाप्तम्;
	यदि ((r = sshbuf_get_string_प्रत्यक्षम्(buf, रिक्त, रिक्त)) != 0 ||
	    (r = sshbuf_get_string_प्रत्यक्षम्(buf, रिक्त, रिक्त)) != 0 ||
	    (r = sshbuf_get_string(buf, रिक्त, रिक्त)) != 0 ||
	    (r = sshbuf_get_cstring(buf, &hashalg, रिक्त)) != 0 ||
	    (r = sshbuf_get_string_प्रत्यक्षम्(buf, रिक्त, रिक्त)) != 0) {
		error_fr(r, "parse signature object");
		गच्छ समाप्तम्;
	}

	/* success */
	r = 0;
	*hashalgp = hashalg;
	hashalg = रिक्त;
 समाप्तम्:
	मुक्त(hashalg);
	sshbuf_free(buf);
	प्रत्यागम r;
}

स्थिर पूर्णाङ्क
sshsig_wrap_verify(संरचना sshbuf *signature, ध्रुव वर्ण *hashalg,
    ध्रुव संरचना sshbuf *h_सन्देशः, ध्रुव वर्ण *expect_namespace,
    संरचना sshkey **sign_keyp, संरचना sshkey_sig_details **sig_details)
{
	पूर्णाङ्क r = SSH_ERR_आन्तरिकम्_ERROR;
	संरचना sshbuf *buf = रिक्त, *toverify = रिक्त;
	संरचना sshkey *कुञ्चिका = रिक्त;
	ध्रुव u_char *sig;
	वर्ण *got_namespace = रिक्त, *sigtype = रिक्त, *sig_hashalg = रिक्त;
	आकार_t siglen;

	debug_f("verify message length %zu", sshbuf_len(h_सन्देशः));
	यदि (sig_details != रिक्त)
		*sig_details = रिक्त;
	यदि (sign_keyp != रिक्त)
		*sign_keyp = रिक्त;

	यदि ((toverify = sshbuf_new()) == रिक्त) {
		error_f("sshbuf_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ समाप्तम्;
	}
	यदि ((r = sshbuf_put(toverify, MAGIC_PREAMBLE,
	    MAGIC_PREAMBLE_LEN)) != 0 ||
	    (r = sshbuf_put_cstring(toverify, expect_namespace)) != 0 ||
	    (r = sshbuf_put_string(toverify, रिक्त, 0)) != 0 || /* reserved */
	    (r = sshbuf_put_cstring(toverify, hashalg)) != 0 ||
	    (r = sshbuf_put_stringb(toverify, h_सन्देशः)) != 0) {
		error_fr(r, "assemble message to verify");
		गच्छ समाप्तम्;
	}

	यदि ((r = sshsig_parse_preamble(signature)) != 0)
		गच्छ समाप्तम्;

	यदि ((r = sshkey_froms(signature, &कुञ्चिका)) != 0 ||
	    (r = sshbuf_get_cstring(signature, &got_namespace, रिक्त)) != 0 ||
	    (r = sshbuf_get_string(signature, रिक्त, रिक्त)) != 0 ||
	    (r = sshbuf_get_cstring(signature, &sig_hashalg, रिक्त)) != 0 ||
	    (r = sshbuf_get_string_प्रत्यक्षम्(signature, &sig, &siglen)) != 0) {
		error_fr(r, "parse signature object");
		गच्छ समाप्तम्;
	}

	यदि (sshbuf_len(signature) != 0) {
		error("Signature contains trailing data");
		r = SSH_ERR_INVALID_FORMAT;
		गच्छ समाप्तम्;
	}

	यदि (वाक्यं_तुलय(expect_namespace, got_namespace) != 0) {
		error("Couldn't verify signature: namespace does not match");
		debug_f("expected namespace \"%s\" received \"%s\"",
		    expect_namespace, got_namespace);
		r = SSH_ERR_SIGNATURE_INVALID;
		गच्छ समाप्तम्;
	}
	यदि (वाक्यं_तुलय(hashalg, sig_hashalg) != 0) {
		error("Couldn't verify signature: hash algorithm mismatch");
		debug_f("expected algorithm \"%s\" received \"%s\"",
		    hashalg, sig_hashalg);
		r = SSH_ERR_SIGNATURE_INVALID;
		गच्छ समाप्तम्;
	}
	/* Ensure that RSA keys use an acceptable signature algorithm */
	यदि (sshkey_type_plain(कुञ्चिका->type) == कुञ्चिका_RSA) {
		यदि ((r = sshkey_get_sigtype(sig, siglen, &sigtype)) != 0) {
			error_r(r, "Couldn't verify signature: unable to get "
			    "signature type");
			गच्छ समाप्तम्;
		}
		यदि (मेलनम्_आदर्शः_list(sigtype, RSA_SIGN_ALLOWED, 0) != 1) {
			error("Couldn't verify signature: unsupported RSA "
			    "signature algorithm %s", sigtype);
			r = SSH_ERR_SIGN_ALG_UNSUPPORTED;
			गच्छ समाप्तम्;
		}
	}
	यदि ((r = sshkey_verify(कुञ्चिका, sig, siglen, sshbuf_ptr(toverify),
	    sshbuf_len(toverify), रिक्त, 0, sig_details)) != 0) {
		error_r(r, "Signature verification failed");
		गच्छ समाप्तम्;
	}

	/* success */
	r = 0;
	यदि (sign_keyp != रिक्त) {
		*sign_keyp = कुञ्चिका;
		कुञ्चिका = रिक्त; /* transferred */
	}
समाप्तम्:
	मुक्त(got_namespace);
	मुक्त(sigtype);
	मुक्त(sig_hashalg);
	sshbuf_free(buf);
	sshbuf_free(toverify);
	sshkey_free(कुञ्चिका);
	प्रत्यागम r;
}

स्थिर पूर्णाङ्क
hash_बफर(ध्रुव संरचना sshbuf *m, ध्रुव वर्ण *hashalg, संरचना sshbuf **bp)
{
	वर्ण *hex, hash[SSH_DIGEST_MAX_दीर्घता];
	पूर्णाङ्क alg, r = SSH_ERR_आन्तरिकम्_ERROR;
	संरचना sshbuf *b = रिक्त;

	*bp = रिक्त;
	स्मृतिं_पूरय(hash, 0, परिमाण(hash));

	यदि ((r = sshsig_check_hashalg(hashalg)) != 0)
		प्रत्यागम r;
	यदि ((alg = ssh_digest_alg_by_name(hashalg)) == -1) {
		error_f("can't look up hash algorithm %s", hashalg);
		प्रत्यागम SSH_ERR_आन्तरिकम्_ERROR;
	}
	यदि ((r = ssh_digest_बफर(alg, m, hash, परिमाण(hash))) != 0) {
		error_fr(r, "ssh_digest_buffer");
		प्रत्यागम r;
	}
	यदि ((hex = tohex(hash, ssh_digest_अष्टकानि(alg))) != रिक्त) {
		debug3_f("final hash: %s", hex);
		freezero(hex, वाक्यदैर्घ्यम्(hex));
	}
	यदि ((b = sshbuf_new()) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ बहिर्गमनम्;
	}
	यदि ((r = sshbuf_put(b, hash, ssh_digest_अष्टकानि(alg))) != 0) {
		error_fr(r, "sshbuf_put");
		गच्छ बहिर्गमनम्;
	}
	*bp = b;
	b = रिक्त; /* transferred */
	/* success */
	r = 0;
 बहिर्गमनम्:
	sshbuf_free(b);
	explicit_bzero(hash, परिमाण(hash));
	प्रत्यागम r;
}

पूर्णाङ्क
sshsig_signb(संरचना sshkey *कुञ्चिका, ध्रुव वर्ण *hashalg,
    ध्रुव वर्ण *sk_provider, ध्रुव वर्ण *sk_pin,
    ध्रुव संरचना sshbuf *सन्देशः_2, ध्रुव वर्ण *sig_namespace,
    संरचना sshbuf **बहिर्गमनम्, sshsig_signer *signer, शून्य *signer_ctx)
{
	संरचना sshbuf *b = रिक्त;
	पूर्णाङ्क r = SSH_ERR_आन्तरिकम्_ERROR;

	यदि (hashalg == रिक्त)
		hashalg = HASHALG_DEFAULT;
	यदि (बहिर्गमनम् != रिक्त)
		*बहिर्गमनम् = रिक्त;
	यदि ((r = hash_बफर(सन्देशः_2, hashalg, &b)) != 0) {
		error_fr(r, "hash buffer");
		गच्छ बहिर्गमनम्;
	}
	यदि ((r = sshsig_wrap_sign(कुञ्चिका, hashalg, sk_provider, sk_pin, b,
	    sig_namespace, बहिर्गमनम्, signer, signer_ctx)) != 0)
		गच्छ बहिर्गमनम्;
	/* success */
	r = 0;
 बहिर्गमनम्:
	sshbuf_free(b);
	प्रत्यागम r;
}

पूर्णाङ्क
sshsig_verifyb(संरचना sshbuf *signature, ध्रुव संरचना sshbuf *सन्देशः_2,
    ध्रुव वर्ण *expect_namespace, संरचना sshkey **sign_keyp,
    संरचना sshkey_sig_details **sig_details)
{
	संरचना sshbuf *b = रिक्त;
	पूर्णाङ्क r = SSH_ERR_आन्तरिकम्_ERROR;
	वर्ण *hashalg = रिक्त;

	यदि (sig_details != रिक्त)
		*sig_details = रिक्त;
	यदि (sign_keyp != रिक्त)
		*sign_keyp = रिक्त;
	यदि ((r = sshsig_peek_hashalg(signature, &hashalg)) != 0)
		प्रत्यागम r;
	debug_f("signature made with hash \"%s\"", hashalg);
	यदि ((r = hash_बफर(सन्देशः_2, hashalg, &b)) != 0) {
		error_fr(r, "hash buffer");
		गच्छ बहिर्गमनम्;
	}
	यदि ((r = sshsig_wrap_verify(signature, hashalg, b, expect_namespace,
	    sign_keyp, sig_details)) != 0)
		गच्छ बहिर्गमनम्;
	/* success */
	r = 0;
 बहिर्गमनम्:
	sshbuf_free(b);
	मुक्त(hashalg);
	प्रत्यागम r;
}

स्थिर पूर्णाङ्क
hash_file(पूर्णाङ्क fd, ध्रुव वर्ण *hashalg, संरचना sshbuf **bp)
{
	वर्ण *hex, rbuf[8192], hash[SSH_DIGEST_MAX_दीर्घता];
	ssize_t n, योग_2 = 0;
	संरचना ssh_digest_ctx *ctx = रिक्त;
	पूर्णाङ्क alg, oerrno, r = SSH_ERR_आन्तरिकम्_ERROR;
	संरचना sshbuf *b = रिक्त;

	*bp = रिक्त;
	स्मृतिं_पूरय(hash, 0, परिमाण(hash));

	यदि ((r = sshsig_check_hashalg(hashalg)) != 0)
		प्रत्यागम r;
	यदि ((alg = ssh_digest_alg_by_name(hashalg)) == -1) {
		error_f("can't look up hash algorithm %s", hashalg);
		प्रत्यागम SSH_ERR_आन्तरिकम्_ERROR;
	}
	यदि ((ctx = ssh_digest_start(alg)) == रिक्त) {
		error_f("ssh_digest_start failed");
		प्रत्यागम SSH_ERR_आन्तरिकम्_ERROR;
	}
	प्रति (;;) {
		यदि ((n = पठ(fd, rbuf, परिमाण(rbuf))) == -1) {
			यदि (errno == EINTR || errno == EAGAIN)
				अनुवर्त;
			oerrno = errno;
			error_f("read: %s", strerror(errno));
			errno = oerrno;
			r = SSH_ERR_SYSTEM_ERROR;
			गच्छ बहिर्गमनम्;
		} अन्यथा यदि (n == 0) {
			debug2_f("hashed %zu bytes", योग_2);
			भङ्ग; /* EOF */
		}
		योग_2 += (आकार_t)n;
		यदि ((r = ssh_digest_update(ctx, rbuf, (आकार_t)n)) != 0) {
			error_fr(r, "ssh_digest_update");
			गच्छ बहिर्गमनम्;
		}
	}
	यदि ((r = ssh_digest_final(ctx, hash, परिमाण(hash))) != 0) {
		error_fr(r, "ssh_digest_final");
		गच्छ बहिर्गमनम्;
	}
	यदि ((hex = tohex(hash, ssh_digest_अष्टकानि(alg))) != रिक्त) {
		debug3_f("final hash: %s", hex);
		freezero(hex, वाक्यदैर्घ्यम्(hex));
	}
	यदि ((b = sshbuf_new()) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ बहिर्गमनम्;
	}
	यदि ((r = sshbuf_put(b, hash, ssh_digest_अष्टकानि(alg))) != 0) {
		error_fr(r, "sshbuf_put");
		गच्छ बहिर्गमनम्;
	}
	*bp = b;
	b = रिक्त; /* transferred */
	/* success */
	r = 0;
 बहिर्गमनम्:
	oerrno = errno;
	sshbuf_free(b);
	ssh_digest_free(ctx);
	explicit_bzero(hash, परिमाण(hash));
	errno = oerrno;
	प्रत्यागम r;
}

पूर्णाङ्क
sshsig_sign_fd(संरचना sshkey *कुञ्चिका, ध्रुव वर्ण *hashalg,
    ध्रुव वर्ण *sk_provider, ध्रुव वर्ण *sk_pin,
    पूर्णाङ्क fd, ध्रुव वर्ण *sig_namespace, संरचना sshbuf **बहिर्गमनम्,
    sshsig_signer *signer, शून्य *signer_ctx)
{
	संरचना sshbuf *b = रिक्त;
	पूर्णाङ्क r = SSH_ERR_आन्तरिकम्_ERROR;

	यदि (hashalg == रिक्त)
		hashalg = HASHALG_DEFAULT;
	यदि (बहिर्गमनम् != रिक्त)
		*बहिर्गमनम् = रिक्त;
	यदि ((r = hash_file(fd, hashalg, &b)) != 0) {
		error_fr(r, "hash_file");
		प्रत्यागम r;
	}
	यदि ((r = sshsig_wrap_sign(कुञ्चिका, hashalg, sk_provider, sk_pin, b,
	    sig_namespace, बहिर्गमनम्, signer, signer_ctx)) != 0)
		गच्छ बहिर्गमनम्;
	/* success */
	r = 0;
 बहिर्गमनम्:
	sshbuf_free(b);
	प्रत्यागम r;
}

पूर्णाङ्क
sshsig_verify_fd(संरचना sshbuf *signature, पूर्णाङ्क fd,
    ध्रुव वर्ण *expect_namespace, संरचना sshkey **sign_keyp,
    संरचना sshkey_sig_details **sig_details)
{
	संरचना sshbuf *b = रिक्त;
	पूर्णाङ्क r = SSH_ERR_आन्तरिकम्_ERROR;
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
		गच्छ बहिर्गमनम्;
	}
	यदि ((r = sshsig_wrap_verify(signature, hashalg, b, expect_namespace,
	    sign_keyp, sig_details)) != 0)
		गच्छ बहिर्गमनम्;
	/* success */
	r = 0;
 बहिर्गमनम्:
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
sshsigopt_parse(ध्रुव वर्ण *opts, ध्रुव वर्ण *मार्गः, u_long linenum,
    ध्रुव वर्ण **errstrp)
{
	संरचना sshsigopt *ret;
	पूर्णाङ्क r;
	वर्ण *opt;
	ध्रुव वर्ण *errstr = रिक्त;

	यदि ((ret = शून्यस्मृतिं_देहि(1, परिमाण(*ret))) == रिक्त)
		प्रत्यागम रिक्त;
	यदि (opts == रिक्त || *opts == '\0')
		प्रत्यागम ret; /* Empty options yields empty options :) */

	यावत् (*opts && *opts != ' ' && *opts != '\t') {
		/* flag options */
		यदि ((r = opt_flag("cert-authority", 0, &opts)) != -1) {
			ret->ca = 1;
		} अन्यथा यदि (opt_मेलनम्(&opts, "namespaces")) {
			यदि (ret->namespaces != रिक्त) {
				errstr = "multiple \"namespaces\" clauses";
				गच्छ fail;
			}
			ret->namespaces = opt_dequote(&opts, &errstr);
			यदि (ret->namespaces == रिक्त)
				गच्छ fail;
		} अन्यथा यदि (opt_मेलनम्(&opts, "valid-after")) {
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
		} अन्यथा यदि (opt_मेलनम्(&opts, "valid-before")) {
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
parse_principals_कुञ्चिका_and_options(ध्रुव वर्ण *मार्गः, u_long linenum, वर्ण *पङ्क्तिः,
    ध्रुव वर्ण *required_principal, वर्ण **principalsp, संरचना sshkey **keyp,
    संरचना sshsigopt **sigoptsp)
{
	वर्ण *opts = रिक्त, *tmp, *cp, *principals = रिक्त;
	ध्रुव वर्ण *reason = रिक्त;
	संरचना sshsigopt *sigopts = रिक्त;
	संरचना sshkey *कुञ्चिका = रिक्त;
	पूर्णाङ्क r = SSH_ERR_आन्तरिकम्_ERROR;

	यदि (principalsp != रिक्त)
		*principalsp = रिक्त;
	यदि (sigoptsp != रिक्त)
		*sigoptsp = रिक्त;
	यदि (keyp != रिक्त)
		*keyp = रिक्त;

	cp = पङ्क्तिः;
	cp = cp + strspn(cp, " \t\n\r"); /* skip leading whitespace */
	यदि (*cp == '#' || *cp == '\0')
		प्रत्यागम SSH_ERR_कुञ्चिका_NOT_प्राप्तम्; /* blank or all-comment line */

	/* format: identity[,identity...] [option[,option...]] key */
	यदि ((tmp = strdelimw(&cp)) == रिक्त || cp == रिक्त) {
		error("%s:%lu: invalid line", मार्गः, linenum);
		r = SSH_ERR_INVALID_FORMAT;
		गच्छ बहिर्गमनम्;
	}
	यदि ((principals = strdup(tmp)) == रिक्त) {
		error_f("strdup failed");
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ बहिर्गमनम्;
	}
	/*
	 * Bail out early if we're looking for a particular principal and this
	 * line does not list it.
	 */
	यदि (required_principal != रिक्त) {
		यदि (मेलनम्_आदर्शः_list(required_principal,
		    principals, 0) != 1) {
			/* principal didn't match */
			r = SSH_ERR_कुञ्चिका_NOT_प्राप्तम्;
			गच्छ बहिर्गमनम्;
		}
		debug_f("%s:%lu: matched principal \"%s\"",
		    मार्गः, linenum, required_principal);
	}

	यदि ((कुञ्चिका = sshkey_new(कुञ्चिका_UNSPEC)) == रिक्त) {
		error_f("sshkey_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ बहिर्गमनम्;
	}
	यदि (sshkey_read(कुञ्चिका, &cp) != 0) {
		/* no key? Check for options */
		opts = cp;
		यदि (sshkey_advance_past_options(&cp) != 0) {
			error("%s:%lu: invalid options", मार्गः, linenum);
			r = SSH_ERR_INVALID_FORMAT;
			गच्छ बहिर्गमनम्;
		}
		यदि (cp == रिक्त || *cp == '\0') {
			error("%s:%lu: missing key", मार्गः, linenum);
			r = SSH_ERR_INVALID_FORMAT;
			गच्छ बहिर्गमनम्;
		}
		*cp++ = '\0';
		skip_space(&cp);
		यदि (sshkey_read(कुञ्चिका, &cp) != 0) {
			error("%s:%lu: invalid key", मार्गः, linenum);
			r = SSH_ERR_INVALID_FORMAT;
			गच्छ बहिर्गमनम्;
		}
	}
	debug3("%s:%lu: options %s", मार्गः, linenum, opts == रिक्त ? "" : opts);
	यदि ((sigopts = sshsigopt_parse(opts, मार्गः, linenum, &reason)) == रिक्त) {
		error("%s:%lu: bad options: %s", मार्गः, linenum, reason);
		r = SSH_ERR_INVALID_FORMAT;
		गच्छ बहिर्गमनम्;
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
		*keyp = कुञ्चिका;
		कुञ्चिका = रिक्त; /* transferred */
	}
	r = 0;
 बहिर्गमनम्:
	मुक्त(principals);
	sshsigopt_free(sigopts);
	sshkey_free(कुञ्चिका);
	प्रत्यागम r;
}

स्थिर पूर्णाङ्क
cert_filter_principals(ध्रुव वर्ण *मार्गः, u_long linenum,
    वर्ण **principalsp, ध्रुव संरचना sshkey *cert, uint64_t verify_time)
{
	वर्ण *cp, *oprincipals, *principals;
	ध्रुव वर्ण *reason;
	संरचना sshbuf *nprincipals;
	पूर्णाङ्क r = SSH_ERR_आन्तरिकम्_ERROR, success = 0;
	u_int i;

	oprincipals = principals = *principalsp;
	*principalsp = रिक्त;

	यदि ((nprincipals = sshbuf_new()) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ बहिर्गमनम्;
	}

	यावत् ((cp = strsep(&principals, ",")) != रिक्त && *cp != '\0') {
		/* Check certificate validity */
		यदि ((r = sshkey_cert_check_authority(cert, 0, 0, verify_time,
		    रिक्त, &reason)) != 0) {
			debug("%s:%lu: principal \"%s\" not authorized: %s",
			    मार्गः, linenum, cp, reason);
			अनुवर्त;
		}
		/* Return all matching principal names from the cert */
		प्रति (i = 0; i < cert->cert->nprincipals; i++) {
			यदि (मेलनम्_आदर्शः(cert->cert->principals[i], cp)) {
				यदि ((r = sshbuf_putf(nprincipals, "%s%s",
					sshbuf_len(nprincipals) != 0 ? "," : "",
						cert->cert->principals[i])) != 0) {
					error_f("buffer error");
					गच्छ बहिर्गमनम्;
				}
			}
		}
	}
	यदि (sshbuf_len(nprincipals) == 0) {
		error("%s:%lu: no valid principals found", मार्गः, linenum);
		r = SSH_ERR_कुञ्चिका_CERT_INVALID;
		गच्छ बहिर्गमनम्;
	}
	यदि ((principals = sshbuf_dup_string(nprincipals)) == रिक्त) {
		error_f("buffer error");
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ बहिर्गमनम्;
	}
	/* success */
	success = 1;
	*principalsp = principals;
 बहिर्गमनम्:
	sshbuf_free(nprincipals);
	मुक्त(oprincipals);
	प्रत्यागम success ? 0 : r;
}

स्थिर पूर्णाङ्क
check_allowed_कुञ्चिकाः_पङ्क्तिः(ध्रुव वर्ण *मार्गः, u_long linenum, वर्ण *पङ्क्तिः,
    ध्रुव संरचना sshkey *sign_कुञ्चिका, ध्रुव वर्ण *principal,
    ध्रुव वर्ण *sig_namespace, uint64_t verify_time, वर्ण **principalsp)
{
	संरचना sshkey *प्राप्तम्_कुञ्चिका = रिक्त;
	वर्ण *principals = रिक्त;
	पूर्णाङ्क r, success = 0;
	ध्रुव वर्ण *reason = रिक्त;
	संरचना sshsigopt *sigopts = रिक्त;
	वर्ण tvalid[64], tverify[64];

	यदि (principalsp != रिक्त)
		*principalsp = रिक्त;

	/* Parse the line */
	यदि ((r = parse_principals_कुञ्चिका_and_options(मार्गः, linenum, पङ्क्तिः,
	    principal, &principals, &प्राप्तम्_कुञ्चिका, &sigopts)) != 0) {
		/* error already logged */
		गच्छ समाप्तम्;
	}

	यदि (!sigopts->ca && sshkey_equal(प्राप्तम्_कुञ्चिका, sign_कुञ्चिका)) {
		/* Exact match of key */
		debug("%s:%lu: matched key", मार्गः, linenum);
	} अन्यथा यदि (sigopts->ca && sshkey_is_cert(sign_कुञ्चिका) &&
	    sshkey_equal_लौकिकम्(sign_कुञ्चिका->cert->signature_कुञ्चिका, प्राप्तम्_कुञ्चिका)) {
		यदि (principal) {
			/* Match certificate CA key with specified principal */
			यदि ((r = sshkey_cert_check_authority(sign_कुञ्चिका, 0, 0,
			    verify_time, principal, &reason)) != 0) {
				error("%s:%lu: certificate not authorized: %s",
				    मार्गः, linenum, reason);
				गच्छ समाप्तम्;
			}
			debug("%s:%lu: matched certificate CA key",
			    मार्गः, linenum);
		} अन्यथा {
			/* No principal specified - find all matching ones */
			यदि ((r = cert_filter_principals(मार्गः, linenum,
			    &principals, sign_कुञ्चिका, verify_time)) != 0) {
				/* error already displayed */
				debug_r(r, "%s:%lu: cert_filter_principals",
				    मार्गः, linenum);
				गच्छ समाप्तम्;
			}
			debug("%s:%lu: matched certificate CA key",
			    मार्गः, linenum);
		}
	} अन्यथा {
		/* Didn't match key */
		गच्छ समाप्तम्;
	}

	/* Check whether options preclude the use of this key */
	यदि (sigopts->namespaces != रिक्त && sig_namespace != रिक्त &&
	    मेलनम्_आदर्शः_list(sig_namespace, sigopts->namespaces, 0) != 1) {
		error("%s:%lu: key is not permitted for use in signature "
		    "namespace \"%s\"", मार्गः, linenum, sig_namespace);
		गच्छ समाप्तम्;
	}

	/* check key time validity */
	format_absolute_time((uint64_t)verify_time, tverify, परिमाण(tverify));
	यदि (sigopts->valid_after != 0 &&
	    (uint64_t)verify_time < sigopts->valid_after) {
		format_absolute_time(sigopts->valid_after,
		    tvalid, परिमाण(tvalid));
		error("%s:%lu: key is not yet valid: "
		    "verify time %s < valid-after %s", मार्गः, linenum,
		    tverify, tvalid);
		गच्छ समाप्तम्;
	}
	यदि (sigopts->valid_before != 0 &&
	    (uint64_t)verify_time > sigopts->valid_before) {
		format_absolute_time(sigopts->valid_before,
		    tvalid, परिमाण(tvalid));
		error("%s:%lu: key has expired: "
		    "verify time %s > valid-before %s", मार्गः, linenum,
		    tverify, tvalid);
		गच्छ समाप्तम्;
	}
	success = 1;

 समाप्तम्:
	यदि (success && principalsp != रिक्त) {
		*principalsp = principals;
		principals = रिक्त; /* transferred */
	}
	मुक्त(principals);
	sshkey_free(प्राप्तम्_कुञ्चिका);
	sshsigopt_free(sigopts);
	प्रत्यागम success ? 0 : SSH_ERR_कुञ्चिका_NOT_प्राप्तम्;
}

पूर्णाङ्क
sshsig_check_allowed_कुञ्चिकाः(ध्रुव वर्ण *मार्गः, ध्रुव संरचना sshkey *sign_कुञ्चिका,
    ध्रुव वर्ण *principal, ध्रुव वर्ण *sig_namespace, uint64_t verify_time)
{
	FILE *f = रिक्त;
	वर्ण *पङ्क्तिः = रिक्त;
	आकार_t linesize = 0;
	u_long linenum = 0;
	पूर्णाङ्क r = SSH_ERR_कुञ्चिका_NOT_प्राप्तम्, oerrno;

	/* Check key and principal against file */
	यदि ((f = fopen(मार्गः, "r")) == रिक्त) {
		oerrno = errno;
		error("Unable to open allowed keys file \"%s\": %s",
		    मार्गः, strerror(errno));
		errno = oerrno;
		प्रत्यागम SSH_ERR_SYSTEM_ERROR;
	}

	यावत् (getline(&पङ्क्तिः, &linesize, f) != -1) {
		linenum++;
		r = check_allowed_कुञ्चिकाः_पङ्क्तिः(मार्गः, linenum, पङ्क्तिः, sign_कुञ्चिका,
		    principal, sig_namespace, verify_time, रिक्त);
		मुक्त(पङ्क्तिः);
		पङ्क्तिः = रिक्त;
		linesize = 0;
		यदि (r == SSH_ERR_कुञ्चिका_NOT_प्राप्तम्)
			अनुवर्त;
		अन्यथा यदि (r == 0) {
			/* success */
			fclose(f);
			प्रत्यागम 0;
		} अन्यथा
			भङ्ग;
	}
	/* Either we hit an error parsing or we simply didn't find the key */
	fclose(f);
	मुक्त(पङ्क्तिः);
	प्रत्यागम r;
}

पूर्णाङ्क
sshsig_find_principals(ध्रुव वर्ण *मार्गः, ध्रुव संरचना sshkey *sign_कुञ्चिका,
    uint64_t verify_time, वर्ण **principals)
{
	FILE *f = रिक्त;
	वर्ण *पङ्क्तिः = रिक्त;
	आकार_t linesize = 0;
	u_long linenum = 0;
	पूर्णाङ्क r = SSH_ERR_कुञ्चिका_NOT_प्राप्तम्, oerrno;

	यदि ((f = fopen(मार्गः, "r")) == रिक्त) {
		oerrno = errno;
		error("Unable to open allowed keys file \"%s\": %s",
		    मार्गः, strerror(errno));
		errno = oerrno;
		प्रत्यागम SSH_ERR_SYSTEM_ERROR;
	}

	यावत् (getline(&पङ्क्तिः, &linesize, f) != -1) {
		linenum++;
		r = check_allowed_कुञ्चिकाः_पङ्क्तिः(मार्गः, linenum, पङ्क्तिः,
		    sign_कुञ्चिका, रिक्त, रिक्त, verify_time, principals);
		मुक्त(पङ्क्तिः);
		पङ्क्तिः = रिक्त;
		linesize = 0;
		यदि (r == SSH_ERR_कुञ्चिका_NOT_प्राप्तम्)
			अनुवर्त;
		अन्यथा यदि (r == 0) {
			/* success */
			fclose(f);
			प्रत्यागम 0;
		} अन्यथा
			भङ्ग;
	}
	मुक्त(पङ्क्तिः);
	/* Either we hit an error parsing or we simply didn't find the key */
	यदि (ferror(f) != 0) {
		oerrno = errno;
		fclose(f);
		error("Unable to read allowed keys file \"%s\": %s",
		    मार्गः, strerror(errno));
		errno = oerrno;
		प्रत्यागम SSH_ERR_SYSTEM_ERROR;
	}
	fclose(f);
	प्रत्यागम r;
}

पूर्णाङ्क
sshsig_मेलनम्_principals(ध्रुव वर्ण *मार्गः, ध्रुव वर्ण *principal,
    वर्ण ***principalsp, आकार_t *nprincipalsp)
{
	FILE *f = रिक्त;
	वर्ण *प्राप्तम्, *पङ्क्तिः = रिक्त, **principals = रिक्त, **tmp;
	आकार_t i, nprincipals = 0, linesize = 0;
	u_long linenum = 0;
	पूर्णाङ्क oerrno = 0, r, ret = 0;

	यदि (principalsp != रिक्त)
		*principalsp = रिक्त;
	यदि (nprincipalsp != रिक्त)
		*nprincipalsp = 0;

	/* Check key and principal against file */
	यदि ((f = fopen(मार्गः, "r")) == रिक्त) {
		oerrno = errno;
		error("Unable to open allowed keys file \"%s\": %s",
		    मार्गः, strerror(errno));
		errno = oerrno;
		प्रत्यागम SSH_ERR_SYSTEM_ERROR;
	}

	यावत् (getline(&पङ्क्तिः, &linesize, f) != -1) {
		linenum++;
		/* Parse the line */
		यदि ((r = parse_principals_कुञ्चिका_and_options(मार्गः, linenum, पङ्क्तिः,
		    principal, &प्राप्तम्, रिक्त, रिक्त)) != 0) {
			यदि (r == SSH_ERR_कुञ्चिका_NOT_प्राप्तम्)
				अनुवर्त;
			ret = r;
			oerrno = errno;
			भङ्ग; /* unexpected error */
		}
		यदि ((tmp = recallocarray(principals, nprincipals,
		    nprincipals + 1, परिमाण(*principals))) == रिक्त) {
			ret = SSH_ERR_ALLOC_FAIL;
			मुक्त(प्राप्तम्);
			भङ्ग;
		}
		principals = tmp;
		principals[nprincipals++] = प्राप्तम्; /* transferred */
		मुक्त(पङ्क्तिः);
		पङ्क्तिः = रिक्त;
		linesize = 0;
	}
	fclose(f);
	मुक्त(पङ्क्तिः);

	यदि (ret == 0) {
		यदि (nprincipals == 0)
			ret = SSH_ERR_कुञ्चिका_NOT_प्राप्तम्;
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

	errno = oerrno;
	प्रत्यागम ret;
}

पूर्णाङ्क
sshsig_get_pubkey(संरचना sshbuf *signature, संरचना sshkey **pubkey)
{
	संरचना sshkey *pk = रिक्त;
	पूर्णाङ्क r = SSH_ERR_SIGNATURE_INVALID;

	यदि (pubkey == रिक्त)
		प्रत्यागम SSH_ERR_आन्तरिकम्_ERROR;
	यदि ((r = sshsig_parse_preamble(signature)) != 0)
		प्रत्यागम r;
	यदि ((r = sshkey_froms(signature, &pk)) != 0)
		प्रत्यागम r;

	*pubkey = pk;
	pk = रिक्त;
	प्रत्यागम 0;
}
