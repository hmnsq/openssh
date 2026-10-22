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
#define MAGIC_PREAMBLE_LEN	(आकार(MAGIC_PREAMBLE) - 1)
#define BEGIN_SIGNATURE		"-----BEGIN SSH SIGNATURE-----"
#define END_SIGNATURE		"-----END SSH SIGNATURE-----"
#define RSA_SIGN_ALG		"rsa-sha2-512"
#define RSA_SIGN_ALLOWED	"rsa-sha2-512,rsa-sha2-256"
#define HASHALG_DEFAULT		"sha512"
#define HASHALG_ALLOWED		"sha256,sha512"

पूर्णांक
sshsig_armor(स्थिरांक संरचना sshbuf *blob, संरचना sshbuf **out)
{
	संरचना sshbuf *buf = रिक्त;
	पूर्णांक r = SSH_ERR_INTERNAL_ERROR;

	*out = रिक्त;

	जर ((buf = sshbuf_new()) == रिक्त) {
		error_f("sshbuf_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		जा out;
	}

	जर ((r = sshbuf_putf(buf, "%s\n", BEGIN_SIGNATURE)) != 0) {
		error_fr(r, "sshbuf_putf");
		जा out;
	}

	जर ((r = sshbuf_dtob64(blob, buf, 1)) != 0) {
		error_fr(r, "base64 encode signature");
		जा out;
	}

	जर ((r = sshbuf_put(buf, END_SIGNATURE,
	    आकार(END_SIGNATURE)-1)) != 0 ||
	    (r = sshbuf_put_u8(buf, '\n')) != 0) {
		error_fr(r, "sshbuf_put");
		जा out;
	}
	/* success */
	*out = buf;
	buf = रिक्त; /* transferred */
	r = 0;
 out:
	sshbuf_free(buf);
	परत r;
}

पूर्णांक
sshsig_dearmor(संरचना sshbuf *sig, संरचना sshbuf **out)
{
	पूर्णांक r;
	माप_प्रकार eoffset = 0;
	संरचना sshbuf *buf = रिक्त;
	संरचना sshbuf *sbuf = रिक्त;
	अक्षर *b64 = रिक्त;

	जर ((sbuf = sshbuf_fromb(sig)) == रिक्त) {
		error_f("sshbuf_fromb failed");
		परत SSH_ERR_ALLOC_FAIL;
	}

	/* Expect and consume preamble + lf/crlf */
	जर ((r = sshbuf_cmp(sbuf, 0,
	    BEGIN_SIGNATURE, आकार(BEGIN_SIGNATURE)-1)) != 0) {
		error("Couldn't parse signature: missing header");
		जा done;
	}
	जर ((r = sshbuf_consume(sbuf, आकार(BEGIN_SIGNATURE)-1)) != 0) {
		error_fr(r, "consume");
		जा done;
	}
	जर ((r = sshbuf_cmp(sbuf, 0, "\r\n", 2)) == 0)
		eoffset = 2;
	अन्यथा जर ((r = sshbuf_cmp(sbuf, 0, "\n", 1)) == 0)
		eoffset = 1;
	अन्यथा {
		r = SSH_ERR_INVALID_FORMAT;
		error_f("no header eol");
		जा done;
	}
	जर ((r = sshbuf_consume(sbuf, eoffset)) != 0) {
		error_fr(r, "consume eol");
		जा done;
	}
	/* Find and consume lf + suffix (any prior cr would be ignored) */
	जर ((r = sshbuf_find(sbuf, 0, "\n" END_SIGNATURE,
	    आकार(END_SIGNATURE), &eoffset)) != 0) {
		error("Couldn't parse signature: missing footer");
		जा done;
	}
	जर ((r = sshbuf_consume_end(sbuf, sshbuf_len(sbuf)-eoffset)) != 0) {
		error_fr(r, "consume");
		जा done;
	}

	जर ((b64 = sshbuf_dup_string(sbuf)) == रिक्त) {
		error_f("sshbuf_dup_string failed");
		r = SSH_ERR_ALLOC_FAIL;
		जा done;
	}

	जर ((buf = sshbuf_new()) == रिक्त) {
		error_f("sshbuf_new() failed");
		r = SSH_ERR_ALLOC_FAIL;
		जा done;
	}

	जर ((r = sshbuf_b64tod(buf, b64)) != 0) {
		error_fr(r, "decode base64");
		जा done;
	}

	/* success */
	*out = buf;
	r = 0;
	buf = रिक्त; /* transferred */
done:
	sshbuf_free(buf);
	sshbuf_free(sbuf);
	मुक्त(b64);
	परत r;
}

स्थिर पूर्णांक
sshsig_wrap_sign(संरचना sshkey *किल्ली, स्थिरांक अक्षर *hashalg,
    स्थिरांक अक्षर *sk_provider, स्थिरांक अक्षर *sk_pin, स्थिरांक संरचना sshbuf *h_message,
    स्थिरांक अक्षर *sig_namespace, संरचना sshbuf **out,
    sshsig_signer *signer, शून्य *signer_ctx)
{
	पूर्णांक r;
	माप_प्रकार slen = 0;
	u_char *sig = रिक्त;
	संरचना sshbuf *blob = रिक्त;
	संरचना sshbuf *tosign = रिक्त;
	स्थिरांक अक्षर *sign_alg = रिक्त;

	जर ((tosign = sshbuf_new()) == रिक्त ||
	    (blob = sshbuf_new()) == रिक्त) {
		error_f("sshbuf_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		जा done;
	}

	जर ((r = sshbuf_put(tosign, MAGIC_PREAMBLE, MAGIC_PREAMBLE_LEN)) != 0 ||
	    (r = sshbuf_put_cstring(tosign, sig_namespace)) != 0 ||
	    (r = sshbuf_put_string(tosign, रिक्त, 0)) != 0 || /* reserved */
	    (r = sshbuf_put_cstring(tosign, hashalg)) != 0 ||
	    (r = sshbuf_put_stringb(tosign, h_message)) != 0) {
		error_fr(r, "assemble message to sign");
		जा done;
	}

	/* If using RSA keys then default to a good signature algorithm */
	जर (sshkey_type_plain(किल्ली->type) == किल्ली_RSA) {
		sign_alg = RSA_SIGN_ALG;
		जर (म_भेद(hashalg, "sha256") == 0)
			sign_alg = "rsa-sha2-256";
		अन्यथा जर (म_भेद(hashalg, "sha512") == 0)
			sign_alg = "rsa-sha2-512";
	}

	जर (signer != रिक्त) {
		जर ((r = signer(किल्ली, &sig, &slen,
		    sshbuf_ptr(tosign), sshbuf_len(tosign),
		    sign_alg, sk_provider, sk_pin, 0, signer_ctx)) != 0) {
			error_r(r, "Couldn't sign message (signer)");
			जा done;
		}
	} अन्यथा {
		जर ((r = sshkey_sign(किल्ली, &sig, &slen,
		    sshbuf_ptr(tosign), sshbuf_len(tosign),
		    sign_alg, sk_provider, sk_pin, 0)) != 0) {
			error_r(r, "Couldn't sign message");
			जा done;
		}
	}

	जर ((r = sshbuf_put(blob, MAGIC_PREAMBLE, MAGIC_PREAMBLE_LEN)) != 0 ||
	    (r = sshbuf_put_u32(blob, SIG_VERSION)) != 0 ||
	    (r = sshkey_puts(किल्ली, blob)) != 0 ||
	    (r = sshbuf_put_cstring(blob, sig_namespace)) != 0 ||
	    (r = sshbuf_put_string(blob, रिक्त, 0)) != 0 || /* reserved */
	    (r = sshbuf_put_cstring(blob, hashalg)) != 0 ||
	    (r = sshbuf_put_string(blob, sig, slen)) != 0) {
		error_fr(r, "assemble signature object");
		जा done;
	}

	जर (out != रिक्त) {
		*out = blob;
		blob = रिक्त;
	}
	r = 0;
done:
	मुक्त(sig);
	sshbuf_free(blob);
	sshbuf_free(tosign);
	परत r;
}

/* Check preamble and version. */
स्थिर पूर्णांक
sshsig_parse_preamble(संरचना sshbuf *buf)
{
	पूर्णांक r = SSH_ERR_INTERNAL_ERROR;
	uint32_t sversion;

	जर ((r = sshbuf_cmp(buf, 0, MAGIC_PREAMBLE, MAGIC_PREAMBLE_LEN)) != 0 ||
	    (r = sshbuf_consume(buf, (आकार(MAGIC_PREAMBLE)-1))) != 0 ||
	    (r = sshbuf_get_u32(buf, &sversion)) != 0) {
		error("Couldn't verify signature: invalid format");
		परत r;
	}

	जर (sversion > SIG_VERSION) {
		error("Signature version %lu is larger than supported "
		    "version %u", (अचिन्हित दीर्घ)sversion, SIG_VERSION);
		परत SSH_ERR_INVALID_FORMAT;
	}
	परत 0;
}

स्थिर पूर्णांक
sshsig_check_hashalg(स्थिरांक अक्षर *hashalg)
{
	जर (hashalg == रिक्त ||
	    match_pattern_list(hashalg, HASHALG_ALLOWED, 0) == 1)
		परत 0;
	error_f("unsupported hash algorithm \"%.100s\"", hashalg);
	परत SSH_ERR_SIGN_ALG_UNSUPPORTED;
}

स्थिर पूर्णांक
sshsig_peek_hashalg(संरचना sshbuf *signature, अक्षर **hashalgp)
{
	संरचना sshbuf *buf = रिक्त;
	अक्षर *hashalg = रिक्त;
	पूर्णांक r = SSH_ERR_INTERNAL_ERROR;

	जर (hashalgp != रिक्त)
		*hashalgp = रिक्त;
	जर ((buf = sshbuf_fromb(signature)) == रिक्त)
		परत SSH_ERR_ALLOC_FAIL;
	जर ((r = sshsig_parse_preamble(buf)) != 0)
		जा done;
	जर ((r = sshbuf_get_string_direct(buf, रिक्त, रिक्त)) != 0 ||
	    (r = sshbuf_get_string_direct(buf, रिक्त, रिक्त)) != 0 ||
	    (r = sshbuf_get_string(buf, रिक्त, रिक्त)) != 0 ||
	    (r = sshbuf_get_cstring(buf, &hashalg, रिक्त)) != 0 ||
	    (r = sshbuf_get_string_direct(buf, रिक्त, रिक्त)) != 0) {
		error_fr(r, "parse signature object");
		जा done;
	}

	/* success */
	r = 0;
	*hashalgp = hashalg;
	hashalg = रिक्त;
 done:
	मुक्त(hashalg);
	sshbuf_free(buf);
	परत r;
}

स्थिर पूर्णांक
sshsig_wrap_verify(संरचना sshbuf *signature, स्थिरांक अक्षर *hashalg,
    स्थिरांक संरचना sshbuf *h_message, स्थिरांक अक्षर *expect_namespace,
    संरचना sshkey **sign_keyp, संरचना sshkey_sig_details **sig_details)
{
	पूर्णांक r = SSH_ERR_INTERNAL_ERROR;
	संरचना sshbuf *buf = रिक्त, *toverify = रिक्त;
	संरचना sshkey *किल्ली = रिक्त;
	स्थिरांक u_char *sig;
	अक्षर *got_namespace = रिक्त, *sigtype = रिक्त, *sig_hashalg = रिक्त;
	माप_प्रकार siglen;

	debug_f("verify message length %zu", sshbuf_len(h_message));
	जर (sig_details != रिक्त)
		*sig_details = रिक्त;
	जर (sign_keyp != रिक्त)
		*sign_keyp = रिक्त;

	जर ((toverify = sshbuf_new()) == रिक्त) {
		error_f("sshbuf_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		जा done;
	}
	जर ((r = sshbuf_put(toverify, MAGIC_PREAMBLE,
	    MAGIC_PREAMBLE_LEN)) != 0 ||
	    (r = sshbuf_put_cstring(toverify, expect_namespace)) != 0 ||
	    (r = sshbuf_put_string(toverify, रिक्त, 0)) != 0 || /* reserved */
	    (r = sshbuf_put_cstring(toverify, hashalg)) != 0 ||
	    (r = sshbuf_put_stringb(toverify, h_message)) != 0) {
		error_fr(r, "assemble message to verify");
		जा done;
	}

	जर ((r = sshsig_parse_preamble(signature)) != 0)
		जा done;

	जर ((r = sshkey_froms(signature, &किल्ली)) != 0 ||
	    (r = sshbuf_get_cstring(signature, &got_namespace, रिक्त)) != 0 ||
	    (r = sshbuf_get_string(signature, रिक्त, रिक्त)) != 0 ||
	    (r = sshbuf_get_cstring(signature, &sig_hashalg, रिक्त)) != 0 ||
	    (r = sshbuf_get_string_direct(signature, &sig, &siglen)) != 0) {
		error_fr(r, "parse signature object");
		जा done;
	}

	जर (sshbuf_len(signature) != 0) {
		error("Signature contains trailing data");
		r = SSH_ERR_INVALID_FORMAT;
		जा done;
	}

	जर (म_भेद(expect_namespace, got_namespace) != 0) {
		error("Couldn't verify signature: namespace does not match");
		debug_f("expected namespace \"%s\" received \"%s\"",
		    expect_namespace, got_namespace);
		r = SSH_ERR_SIGNATURE_INVALID;
		जा done;
	}
	जर (म_भेद(hashalg, sig_hashalg) != 0) {
		error("Couldn't verify signature: hash algorithm mismatch");
		debug_f("expected algorithm \"%s\" received \"%s\"",
		    hashalg, sig_hashalg);
		r = SSH_ERR_SIGNATURE_INVALID;
		जा done;
	}
	/* Ensure that RSA keys use an acceptable signature algorithm */
	जर (sshkey_type_plain(किल्ली->type) == किल्ली_RSA) {
		जर ((r = sshkey_get_sigtype(sig, siglen, &sigtype)) != 0) {
			error_r(r, "Couldn't verify signature: unable to get "
			    "signature type");
			जा done;
		}
		जर (match_pattern_list(sigtype, RSA_SIGN_ALLOWED, 0) != 1) {
			error("Couldn't verify signature: unsupported RSA "
			    "signature algorithm %s", sigtype);
			r = SSH_ERR_SIGN_ALG_UNSUPPORTED;
			जा done;
		}
	}
	जर ((r = sshkey_verify(किल्ली, sig, siglen, sshbuf_ptr(toverify),
	    sshbuf_len(toverify), रिक्त, 0, sig_details)) != 0) {
		error_r(r, "Signature verification failed");
		जा done;
	}

	/* success */
	r = 0;
	जर (sign_keyp != रिक्त) {
		*sign_keyp = किल्ली;
		किल्ली = रिक्त; /* transferred */
	}
done:
	मुक्त(got_namespace);
	मुक्त(sigtype);
	मुक्त(sig_hashalg);
	sshbuf_free(buf);
	sshbuf_free(toverify);
	sshkey_free(किल्ली);
	परत r;
}

स्थिर पूर्णांक
hash_buffer(स्थिरांक संरचना sshbuf *m, स्थिरांक अक्षर *hashalg, संरचना sshbuf **bp)
{
	अक्षर *hex, hash[SSH_DIGEST_MAX_LENGTH];
	पूर्णांक alg, r = SSH_ERR_INTERNAL_ERROR;
	संरचना sshbuf *b = रिक्त;

	*bp = रिक्त;
	स_रखो(hash, 0, आकार(hash));

	जर ((r = sshsig_check_hashalg(hashalg)) != 0)
		परत r;
	जर ((alg = ssh_digest_alg_by_name(hashalg)) == -1) {
		error_f("can't look up hash algorithm %s", hashalg);
		परत SSH_ERR_INTERNAL_ERROR;
	}
	जर ((r = ssh_digest_buffer(alg, m, hash, आकार(hash))) != 0) {
		error_fr(r, "ssh_digest_buffer");
		परत r;
	}
	जर ((hex = tohex(hash, ssh_digest_bytes(alg))) != रिक्त) {
		debug3_f("final hash: %s", hex);
		freezero(hex, म_माप(hex));
	}
	जर ((b = sshbuf_new()) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		जा out;
	}
	जर ((r = sshbuf_put(b, hash, ssh_digest_bytes(alg))) != 0) {
		error_fr(r, "sshbuf_put");
		जा out;
	}
	*bp = b;
	b = रिक्त; /* transferred */
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	explicit_bzero(hash, आकार(hash));
	परत r;
}

पूर्णांक
sshsig_signb(संरचना sshkey *किल्ली, स्थिरांक अक्षर *hashalg,
    स्थिरांक अक्षर *sk_provider, स्थिरांक अक्षर *sk_pin,
    स्थिरांक संरचना sshbuf *message, स्थिरांक अक्षर *sig_namespace,
    संरचना sshbuf **out, sshsig_signer *signer, शून्य *signer_ctx)
{
	संरचना sshbuf *b = रिक्त;
	पूर्णांक r = SSH_ERR_INTERNAL_ERROR;

	जर (hashalg == रिक्त)
		hashalg = HASHALG_DEFAULT;
	जर (out != रिक्त)
		*out = रिक्त;
	जर ((r = hash_buffer(message, hashalg, &b)) != 0) {
		error_fr(r, "hash buffer");
		जा out;
	}
	जर ((r = sshsig_wrap_sign(किल्ली, hashalg, sk_provider, sk_pin, b,
	    sig_namespace, out, signer, signer_ctx)) != 0)
		जा out;
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	परत r;
}

पूर्णांक
sshsig_verifyb(संरचना sshbuf *signature, स्थिरांक संरचना sshbuf *message,
    स्थिरांक अक्षर *expect_namespace, संरचना sshkey **sign_keyp,
    संरचना sshkey_sig_details **sig_details)
{
	संरचना sshbuf *b = रिक्त;
	पूर्णांक r = SSH_ERR_INTERNAL_ERROR;
	अक्षर *hashalg = रिक्त;

	जर (sig_details != रिक्त)
		*sig_details = रिक्त;
	जर (sign_keyp != रिक्त)
		*sign_keyp = रिक्त;
	जर ((r = sshsig_peek_hashalg(signature, &hashalg)) != 0)
		परत r;
	debug_f("signature made with hash \"%s\"", hashalg);
	जर ((r = hash_buffer(message, hashalg, &b)) != 0) {
		error_fr(r, "hash buffer");
		जा out;
	}
	जर ((r = sshsig_wrap_verify(signature, hashalg, b, expect_namespace,
	    sign_keyp, sig_details)) != 0)
		जा out;
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	मुक्त(hashalg);
	परत r;
}

स्थिर पूर्णांक
hash_file(पूर्णांक fd, स्थिरांक अक्षर *hashalg, संरचना sshbuf **bp)
{
	अक्षर *hex, rbuf[8192], hash[SSH_DIGEST_MAX_LENGTH];
	ssize_t n, total = 0;
	संरचना ssh_digest_ctx *ctx = रिक्त;
	पूर्णांक alg, oerrno, r = SSH_ERR_INTERNAL_ERROR;
	संरचना sshbuf *b = रिक्त;

	*bp = रिक्त;
	स_रखो(hash, 0, आकार(hash));

	जर ((r = sshsig_check_hashalg(hashalg)) != 0)
		परत r;
	जर ((alg = ssh_digest_alg_by_name(hashalg)) == -1) {
		error_f("can't look up hash algorithm %s", hashalg);
		परत SSH_ERR_INTERNAL_ERROR;
	}
	जर ((ctx = ssh_digest_start(alg)) == रिक्त) {
		error_f("ssh_digest_start failed");
		परत SSH_ERR_INTERNAL_ERROR;
	}
	साठी (;;) {
		जर ((n = पठ(fd, rbuf, आकार(rbuf))) == -1) {
			जर (त्रुटि_सं == EINTR || त्रुटि_सं == EAGAIN)
				सुरूठेवा;
			oerrno = त्रुटि_सं;
			error_f("read: %s", म_त्रुटि(त्रुटि_सं));
			त्रुटि_सं = oerrno;
			r = SSH_ERR_SYSTEM_ERROR;
			जा out;
		} अन्यथा जर (n == 0) {
			debug2_f("hashed %zu bytes", total);
			थांबा; /* EOF */
		}
		total += (माप_प्रकार)n;
		जर ((r = ssh_digest_update(ctx, rbuf, (माप_प्रकार)n)) != 0) {
			error_fr(r, "ssh_digest_update");
			जा out;
		}
	}
	जर ((r = ssh_digest_final(ctx, hash, आकार(hash))) != 0) {
		error_fr(r, "ssh_digest_final");
		जा out;
	}
	जर ((hex = tohex(hash, ssh_digest_bytes(alg))) != रिक्त) {
		debug3_f("final hash: %s", hex);
		freezero(hex, म_माप(hex));
	}
	जर ((b = sshbuf_new()) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		जा out;
	}
	जर ((r = sshbuf_put(b, hash, ssh_digest_bytes(alg))) != 0) {
		error_fr(r, "sshbuf_put");
		जा out;
	}
	*bp = b;
	b = रिक्त; /* transferred */
	/* success */
	r = 0;
 out:
	oerrno = त्रुटि_सं;
	sshbuf_free(b);
	ssh_digest_free(ctx);
	explicit_bzero(hash, आकार(hash));
	त्रुटि_सं = oerrno;
	परत r;
}

पूर्णांक
sshsig_sign_fd(संरचना sshkey *किल्ली, स्थिरांक अक्षर *hashalg,
    स्थिरांक अक्षर *sk_provider, स्थिरांक अक्षर *sk_pin,
    पूर्णांक fd, स्थिरांक अक्षर *sig_namespace, संरचना sshbuf **out,
    sshsig_signer *signer, शून्य *signer_ctx)
{
	संरचना sshbuf *b = रिक्त;
	पूर्णांक r = SSH_ERR_INTERNAL_ERROR;

	जर (hashalg == रिक्त)
		hashalg = HASHALG_DEFAULT;
	जर (out != रिक्त)
		*out = रिक्त;
	जर ((r = hash_file(fd, hashalg, &b)) != 0) {
		error_fr(r, "hash_file");
		परत r;
	}
	जर ((r = sshsig_wrap_sign(किल्ली, hashalg, sk_provider, sk_pin, b,
	    sig_namespace, out, signer, signer_ctx)) != 0)
		जा out;
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	परत r;
}

पूर्णांक
sshsig_verify_fd(संरचना sshbuf *signature, पूर्णांक fd,
    स्थिरांक अक्षर *expect_namespace, संरचना sshkey **sign_keyp,
    संरचना sshkey_sig_details **sig_details)
{
	संरचना sshbuf *b = रिक्त;
	पूर्णांक r = SSH_ERR_INTERNAL_ERROR;
	अक्षर *hashalg = रिक्त;

	जर (sig_details != रिक्त)
		*sig_details = रिक्त;
	जर (sign_keyp != रिक्त)
		*sign_keyp = रिक्त;
	जर ((r = sshsig_peek_hashalg(signature, &hashalg)) != 0)
		परत r;
	debug_f("signature made with hash \"%s\"", hashalg);
	जर ((r = hash_file(fd, hashalg, &b)) != 0) {
		error_fr(r, "hash_file");
		जा out;
	}
	जर ((r = sshsig_wrap_verify(signature, hashalg, b, expect_namespace,
	    sign_keyp, sig_details)) != 0)
		जा out;
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	मुक्त(hashalg);
	परत r;
}

संरचना sshsigopt {
	पूर्णांक ca;
	अक्षर *namespaces;
	uint64_t valid_after, valid_before;
};

संरचना sshsigopt *
sshsigopt_parse(स्थिरांक अक्षर *opts, स्थिरांक अक्षर *path, u_long linenum,
    स्थिरांक अक्षर **errstrp)
{
	संरचना sshsigopt *ret;
	पूर्णांक r;
	अक्षर *opt;
	स्थिरांक अक्षर *errstr = रिक्त;

	जर ((ret = सुस्मृति(1, आकार(*ret))) == रिक्त)
		परत रिक्त;
	जर (opts == रिक्त || *opts == '\0')
		परत ret; /* Empty options yields empty options :) */

	पर्यंत (*opts && *opts != ' ' && *opts != '\t') {
		/* flag options */
		जर ((r = opt_flag("cert-authority", 0, &opts)) != -1) {
			ret->ca = 1;
		} अन्यथा जर (opt_match(&opts, "namespaces")) {
			जर (ret->namespaces != रिक्त) {
				errstr = "multiple \"namespaces\" clauses";
				जा fail;
			}
			ret->namespaces = opt_dequote(&opts, &errstr);
			जर (ret->namespaces == रिक्त)
				जा fail;
		} अन्यथा जर (opt_match(&opts, "valid-after")) {
			जर (ret->valid_after != 0) {
				errstr = "multiple \"valid-after\" clauses";
				जा fail;
			}
			जर ((opt = opt_dequote(&opts, &errstr)) == रिक्त)
				जा fail;
			जर (parse_absolute_time(opt, &ret->valid_after) != 0 ||
			    ret->valid_after == 0) {
				मुक्त(opt);
				errstr = "invalid \"valid-after\" time";
				जा fail;
			}
			मुक्त(opt);
		} अन्यथा जर (opt_match(&opts, "valid-before")) {
			जर (ret->valid_before != 0) {
				errstr = "multiple \"valid-before\" clauses";
				जा fail;
			}
			जर ((opt = opt_dequote(&opts, &errstr)) == रिक्त)
				जा fail;
			जर (parse_absolute_time(opt, &ret->valid_before) != 0 ||
			    ret->valid_before == 0) {
				मुक्त(opt);
				errstr = "invalid \"valid-before\" time";
				जा fail;
			}
			मुक्त(opt);
		}
		/*
		 * Skip the comma, and move to the next option
		 * (or break out if there are no more).
		 */
		जर (*opts == '\0' || *opts == ' ' || *opts == '\t')
			थांबा;		/* End of options. */
		/* Anything other than a comma is an unknown option */
		जर (*opts != ',') {
			errstr = "unknown key option";
			जा fail;
		}
		opts++;
		जर (*opts == '\0') {
			errstr = "unexpected end-of-options";
			जा fail;
		}
	}
	/* final consistency check */
	जर (ret->valid_after != 0 && ret->valid_before != 0 &&
	    ret->valid_before <= ret->valid_after) {
		errstr = "\"valid-before\" time is before \"valid-after\"";
		जा fail;
	}
	/* success */
	परत ret;
 fail:
	जर (errstrp != रिक्त)
		*errstrp = errstr;
	sshsigopt_free(ret);
	परत रिक्त;
}

शून्य
sshsigopt_free(संरचना sshsigopt *opts)
{
	जर (opts == रिक्त)
		परत;
	मुक्त(opts->namespaces);
	मुक्त(opts);
}

स्थिर पूर्णांक
parse_principals_किल्ली_and_options(स्थिरांक अक्षर *path, u_long linenum, अक्षर *ओळ,
    स्थिरांक अक्षर *required_principal, अक्षर **principalsp, संरचना sshkey **keyp,
    संरचना sshsigopt **sigoptsp)
{
	अक्षर *opts = रिक्त, *tmp, *cp, *principals = रिक्त;
	स्थिरांक अक्षर *reason = रिक्त;
	संरचना sshsigopt *sigopts = रिक्त;
	संरचना sshkey *किल्ली = रिक्त;
	पूर्णांक r = SSH_ERR_INTERNAL_ERROR;

	जर (principalsp != रिक्त)
		*principalsp = रिक्त;
	जर (sigoptsp != रिक्त)
		*sigoptsp = रिक्त;
	जर (keyp != रिक्त)
		*keyp = रिक्त;

	cp = ओळ;
	cp = cp + म_अखोज(cp, " \t\n\r"); /* skip leading whitespace */
	जर (*cp == '#' || *cp == '\0')
		परत SSH_ERR_किल्ली_NOT_FOUND; /* blank or all-comment line */

	/* format: identity[,identity...] [option[,option...]] key */
	जर ((tmp = strdelimw(&cp)) == रिक्त || cp == रिक्त) {
		error("%s:%lu: invalid line", path, linenum);
		r = SSH_ERR_INVALID_FORMAT;
		जा out;
	}
	जर ((principals = strdup(tmp)) == रिक्त) {
		error_f("strdup failed");
		r = SSH_ERR_ALLOC_FAIL;
		जा out;
	}
	/*
	 * Bail out early if we're looking for a particular principal and this
	 * line does not list it.
	 */
	जर (required_principal != रिक्त) {
		जर (match_pattern_list(required_principal,
		    principals, 0) != 1) {
			/* principal didn't match */
			r = SSH_ERR_किल्ली_NOT_FOUND;
			जा out;
		}
		debug_f("%s:%lu: matched principal \"%s\"",
		    path, linenum, required_principal);
	}

	जर ((किल्ली = sshkey_new(किल्ली_UNSPEC)) == रिक्त) {
		error_f("sshkey_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		जा out;
	}
	जर (sshkey_read(किल्ली, &cp) != 0) {
		/* no key? Check for options */
		opts = cp;
		जर (sshkey_advance_past_options(&cp) != 0) {
			error("%s:%lu: invalid options", path, linenum);
			r = SSH_ERR_INVALID_FORMAT;
			जा out;
		}
		जर (cp == रिक्त || *cp == '\0') {
			error("%s:%lu: missing key", path, linenum);
			r = SSH_ERR_INVALID_FORMAT;
			जा out;
		}
		*cp++ = '\0';
		skip_space(&cp);
		जर (sshkey_read(किल्ली, &cp) != 0) {
			error("%s:%lu: invalid key", path, linenum);
			r = SSH_ERR_INVALID_FORMAT;
			जा out;
		}
	}
	debug3("%s:%lu: options %s", path, linenum, opts == रिक्त ? "" : opts);
	जर ((sigopts = sshsigopt_parse(opts, path, linenum, &reason)) == रिक्त) {
		error("%s:%lu: bad options: %s", path, linenum, reason);
		r = SSH_ERR_INVALID_FORMAT;
		जा out;
	}
	/* success */
	जर (principalsp != रिक्त) {
		*principalsp = principals;
		principals = रिक्त; /* transferred */
	}
	जर (sigoptsp != रिक्त) {
		*sigoptsp = sigopts;
		sigopts = रिक्त; /* transferred */
	}
	जर (keyp != रिक्त) {
		*keyp = किल्ली;
		किल्ली = रिक्त; /* transferred */
	}
	r = 0;
 out:
	मुक्त(principals);
	sshsigopt_free(sigopts);
	sshkey_free(किल्ली);
	परत r;
}

स्थिर पूर्णांक
cert_filter_principals(स्थिरांक अक्षर *path, u_long linenum,
    अक्षर **principalsp, स्थिरांक संरचना sshkey *cert, uint64_t verify_time)
{
	अक्षर *cp, *oprincipals, *principals;
	स्थिरांक अक्षर *reason;
	संरचना sshbuf *nprincipals;
	पूर्णांक r = SSH_ERR_INTERNAL_ERROR, success = 0;
	u_int i;

	oprincipals = principals = *principalsp;
	*principalsp = रिक्त;

	जर ((nprincipals = sshbuf_new()) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		जा out;
	}

	पर्यंत ((cp = strsep(&principals, ",")) != रिक्त && *cp != '\0') {
		/* Check certificate validity */
		जर ((r = sshkey_cert_check_authority(cert, 0, 0, verify_time,
		    रिक्त, &reason)) != 0) {
			debug("%s:%lu: principal \"%s\" not authorized: %s",
			    path, linenum, cp, reason);
			सुरूठेवा;
		}
		/* Return all matching principal names from the cert */
		साठी (i = 0; i < cert->cert->nprincipals; i++) {
			जर (match_pattern(cert->cert->principals[i], cp)) {
				जर ((r = sshbuf_putf(nprincipals, "%s%s",
					sshbuf_len(nprincipals) != 0 ? "," : "",
						cert->cert->principals[i])) != 0) {
					error_f("buffer error");
					जा out;
				}
			}
		}
	}
	जर (sshbuf_len(nprincipals) == 0) {
		error("%s:%lu: no valid principals found", path, linenum);
		r = SSH_ERR_किल्ली_CERT_INVALID;
		जा out;
	}
	जर ((principals = sshbuf_dup_string(nprincipals)) == रिक्त) {
		error_f("buffer error");
		r = SSH_ERR_ALLOC_FAIL;
		जा out;
	}
	/* success */
	success = 1;
	*principalsp = principals;
 out:
	sshbuf_free(nprincipals);
	मुक्त(oprincipals);
	परत success ? 0 : r;
}

स्थिर पूर्णांक
check_allowed_किल्ल्या_ओळ(स्थिरांक अक्षर *path, u_long linenum, अक्षर *ओळ,
    स्थिरांक संरचना sshkey *sign_किल्ली, स्थिरांक अक्षर *principal,
    स्थिरांक अक्षर *sig_namespace, uint64_t verify_time, अक्षर **principalsp)
{
	संरचना sshkey *found_किल्ली = रिक्त;
	अक्षर *principals = रिक्त;
	पूर्णांक r, success = 0;
	स्थिरांक अक्षर *reason = रिक्त;
	संरचना sshsigopt *sigopts = रिक्त;
	अक्षर tvalid[64], tverify[64];

	जर (principalsp != रिक्त)
		*principalsp = रिक्त;

	/* Parse the line */
	जर ((r = parse_principals_किल्ली_and_options(path, linenum, ओळ,
	    principal, &principals, &found_किल्ली, &sigopts)) != 0) {
		/* error already logged */
		जा done;
	}

	जर (!sigopts->ca && sshkey_equal(found_किल्ली, sign_किल्ली)) {
		/* Exact match of key */
		debug("%s:%lu: matched key", path, linenum);
	} अन्यथा जर (sigopts->ca && sshkey_is_cert(sign_किल्ली) &&
	    sshkey_equal_public(sign_किल्ली->cert->signature_किल्ली, found_किल्ली)) {
		जर (principal) {
			/* Match certificate CA key with specified principal */
			जर ((r = sshkey_cert_check_authority(sign_किल्ली, 0, 0,
			    verify_time, principal, &reason)) != 0) {
				error("%s:%lu: certificate not authorized: %s",
				    path, linenum, reason);
				जा done;
			}
			debug("%s:%lu: matched certificate CA key",
			    path, linenum);
		} अन्यथा {
			/* No principal specified - find all matching ones */
			जर ((r = cert_filter_principals(path, linenum,
			    &principals, sign_किल्ली, verify_time)) != 0) {
				/* error already displayed */
				debug_r(r, "%s:%lu: cert_filter_principals",
				    path, linenum);
				जा done;
			}
			debug("%s:%lu: matched certificate CA key",
			    path, linenum);
		}
	} अन्यथा {
		/* Didn't match key */
		जा done;
	}

	/* Check whether options preclude the use of this key */
	जर (sigopts->namespaces != रिक्त && sig_namespace != रिक्त &&
	    match_pattern_list(sig_namespace, sigopts->namespaces, 0) != 1) {
		error("%s:%lu: key is not permitted for use in signature "
		    "namespace \"%s\"", path, linenum, sig_namespace);
		जा done;
	}

	/* check key time validity */
	format_absolute_time((uint64_t)verify_time, tverify, आकार(tverify));
	जर (sigopts->valid_after != 0 &&
	    (uint64_t)verify_time < sigopts->valid_after) {
		format_absolute_time(sigopts->valid_after,
		    tvalid, आकार(tvalid));
		error("%s:%lu: key is not yet valid: "
		    "verify time %s < valid-after %s", path, linenum,
		    tverify, tvalid);
		जा done;
	}
	जर (sigopts->valid_before != 0 &&
	    (uint64_t)verify_time > sigopts->valid_before) {
		format_absolute_time(sigopts->valid_before,
		    tvalid, आकार(tvalid));
		error("%s:%lu: key has expired: "
		    "verify time %s > valid-before %s", path, linenum,
		    tverify, tvalid);
		जा done;
	}
	success = 1;

 done:
	जर (success && principalsp != रिक्त) {
		*principalsp = principals;
		principals = रिक्त; /* transferred */
	}
	मुक्त(principals);
	sshkey_free(found_किल्ली);
	sshsigopt_free(sigopts);
	परत success ? 0 : SSH_ERR_किल्ली_NOT_FOUND;
}

पूर्णांक
sshsig_check_allowed_किल्ल्या(स्थिरांक अक्षर *path, स्थिरांक संरचना sshkey *sign_किल्ली,
    स्थिरांक अक्षर *principal, स्थिरांक अक्षर *sig_namespace, uint64_t verify_time)
{
	खाता *f = रिक्त;
	अक्षर *ओळ = रिक्त;
	माप_प्रकार linesize = 0;
	u_long linenum = 0;
	पूर्णांक r = SSH_ERR_किल्ली_NOT_FOUND, oerrno;

	/* Check key and principal against file */
	जर ((f = ख_खोलो(path, "r")) == रिक्त) {
		oerrno = त्रुटि_सं;
		error("Unable to open allowed keys file \"%s\": %s",
		    path, म_त्रुटि(त्रुटि_सं));
		त्रुटि_सं = oerrno;
		परत SSH_ERR_SYSTEM_ERROR;
	}

	पर्यंत (getline(&ओळ, &linesize, f) != -1) {
		linenum++;
		r = check_allowed_किल्ल्या_ओळ(path, linenum, ओळ, sign_किल्ली,
		    principal, sig_namespace, verify_time, रिक्त);
		मुक्त(ओळ);
		ओळ = रिक्त;
		linesize = 0;
		जर (r == SSH_ERR_किल्ली_NOT_FOUND)
			सुरूठेवा;
		अन्यथा जर (r == 0) {
			/* success */
			ख_बंद(f);
			परत 0;
		} अन्यथा
			थांबा;
	}
	/* Either we hit an error parsing or we simply didn't find the key */
	ख_बंद(f);
	मुक्त(ओळ);
	परत r;
}

पूर्णांक
sshsig_find_principals(स्थिरांक अक्षर *path, स्थिरांक संरचना sshkey *sign_किल्ली,
    uint64_t verify_time, अक्षर **principals)
{
	खाता *f = रिक्त;
	अक्षर *ओळ = रिक्त;
	माप_प्रकार linesize = 0;
	u_long linenum = 0;
	पूर्णांक r = SSH_ERR_किल्ली_NOT_FOUND, oerrno;

	जर ((f = ख_खोलो(path, "r")) == रिक्त) {
		oerrno = त्रुटि_सं;
		error("Unable to open allowed keys file \"%s\": %s",
		    path, म_त्रुटि(त्रुटि_सं));
		त्रुटि_सं = oerrno;
		परत SSH_ERR_SYSTEM_ERROR;
	}

	पर्यंत (getline(&ओळ, &linesize, f) != -1) {
		linenum++;
		r = check_allowed_किल्ल्या_ओळ(path, linenum, ओळ,
		    sign_किल्ली, रिक्त, रिक्त, verify_time, principals);
		मुक्त(ओळ);
		ओळ = रिक्त;
		linesize = 0;
		जर (r == SSH_ERR_किल्ली_NOT_FOUND)
			सुरूठेवा;
		अन्यथा जर (r == 0) {
			/* success */
			ख_बंद(f);
			परत 0;
		} अन्यथा
			थांबा;
	}
	मुक्त(ओळ);
	/* Either we hit an error parsing or we simply didn't find the key */
	जर (ख_त्रुटि(f) != 0) {
		oerrno = त्रुटि_सं;
		ख_बंद(f);
		error("Unable to read allowed keys file \"%s\": %s",
		    path, म_त्रुटि(त्रुटि_सं));
		त्रुटि_सं = oerrno;
		परत SSH_ERR_SYSTEM_ERROR;
	}
	ख_बंद(f);
	परत r;
}

पूर्णांक
sshsig_match_principals(स्थिरांक अक्षर *path, स्थिरांक अक्षर *principal,
    अक्षर ***principalsp, माप_प्रकार *nprincipalsp)
{
	खाता *f = रिक्त;
	अक्षर *found, *ओळ = रिक्त, **principals = रिक्त, **tmp;
	माप_प्रकार i, nprincipals = 0, linesize = 0;
	u_long linenum = 0;
	पूर्णांक oerrno = 0, r, ret = 0;

	जर (principalsp != रिक्त)
		*principalsp = रिक्त;
	जर (nprincipalsp != रिक्त)
		*nprincipalsp = 0;

	/* Check key and principal against file */
	जर ((f = ख_खोलो(path, "r")) == रिक्त) {
		oerrno = त्रुटि_सं;
		error("Unable to open allowed keys file \"%s\": %s",
		    path, म_त्रुटि(त्रुटि_सं));
		त्रुटि_सं = oerrno;
		परत SSH_ERR_SYSTEM_ERROR;
	}

	पर्यंत (getline(&ओळ, &linesize, f) != -1) {
		linenum++;
		/* Parse the line */
		जर ((r = parse_principals_किल्ली_and_options(path, linenum, ओळ,
		    principal, &found, रिक्त, रिक्त)) != 0) {
			जर (r == SSH_ERR_किल्ली_NOT_FOUND)
				सुरूठेवा;
			ret = r;
			oerrno = त्रुटि_सं;
			थांबा; /* unexpected error */
		}
		जर ((tmp = recallocarray(principals, nprincipals,
		    nprincipals + 1, आकार(*principals))) == रिक्त) {
			ret = SSH_ERR_ALLOC_FAIL;
			मुक्त(found);
			थांबा;
		}
		principals = tmp;
		principals[nprincipals++] = found; /* transferred */
		मुक्त(ओळ);
		ओळ = रिक्त;
		linesize = 0;
	}
	ख_बंद(f);
	मुक्त(ओळ);

	जर (ret == 0) {
		जर (nprincipals == 0)
			ret = SSH_ERR_किल्ली_NOT_FOUND;
		जर (nprincipalsp != रिक्त)
			*nprincipalsp = nprincipals;
		जर (principalsp != रिक्त) {
			*principalsp = principals;
			principals = रिक्त; /* transferred */
			nprincipals = 0;
		}
	}

	साठी (i = 0; i < nprincipals; i++)
		मुक्त(principals[i]);
	मुक्त(principals);

	त्रुटि_सं = oerrno;
	परत ret;
}

पूर्णांक
sshsig_get_pubkey(संरचना sshbuf *signature, संरचना sshkey **pubkey)
{
	संरचना sshkey *pk = रिक्त;
	पूर्णांक r = SSH_ERR_SIGNATURE_INVALID;

	जर (pubkey == रिक्त)
		परत SSH_ERR_INTERNAL_ERROR;
	जर ((r = sshsig_parse_preamble(signature)) != 0)
		परत r;
	जर ((r = sshkey_froms(signature, &pk)) != 0)
		परत r;

	*pubkey = pk;
	pk = रिक्त;
	परत 0;
}
