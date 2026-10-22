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

#समावेश "includes.h"

#समावेश <stdio.h>
#समावेश <stdlib.h>
#समावेश <stdarg.h>
#समावेश <errno.h>
#समावेश <string.h>
#समावेश <unistd.h>

#समावेश "authfd.h"
#समावेश "authfile.h"
#समावेश "log.h"
#समावेश "misc.h"
#समावेश "sshbuf.h"
#समावेश "sshsig.h"
#समावेश "ssherr.h"
#समावेश "sshkey.h"
#समावेश "match.h"
#समावेश "digest.h"

#घोषणा SIG_VERSION		0x01
#घोषणा MAGIC_PREAMBLE		"SSHSIG"
#घोषणा MAGIC_PREAMBLE_LEN	(माप(MAGIC_PREAMBLE) - 1)
#घोषणा BEGIN_SIGNATURE		"-----BEGIN SSH SIGNATURE-----"
#घोषणा END_SIGNATURE		"-----END SSH SIGNATURE-----"
#घोषणा RSA_SIGN_ALG		"rsa-sha2-512"
#घोषणा RSA_SIGN_ALLOWED	"rsa-sha2-512,rsa-sha2-256"
#घोषणा HASHALG_DEFAULT		"sha512"
#घोषणा HASHALG_ALLOWED		"sha256,sha512"

पूर्णांक
sshsig_armor(स्थिर काष्ठा sshbuf *blob, काष्ठा sshbuf **out)
{
	काष्ठा sshbuf *buf = शून्य;
	पूर्णांक r = SSH_ERR_INTERNAL_ERROR;

	*out = शून्य;

	अगर ((buf = sshbuf_new()) == शून्य) {
		error_f("sshbuf_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		जाओ out;
	}

	अगर ((r = sshbuf_putf(buf, "%s\n", BEGIN_SIGNATURE)) != 0) {
		error_fr(r, "sshbuf_putf");
		जाओ out;
	}

	अगर ((r = sshbuf_dtob64(blob, buf, 1)) != 0) {
		error_fr(r, "base64 encode signature");
		जाओ out;
	}

	अगर ((r = sshbuf_put(buf, END_SIGNATURE,
	    माप(END_SIGNATURE)-1)) != 0 ||
	    (r = sshbuf_put_u8(buf, '\n')) != 0) {
		error_fr(r, "sshbuf_put");
		जाओ out;
	}
	/* success */
	*out = buf;
	buf = शून्य; /* transferred */
	r = 0;
 out:
	sshbuf_free(buf);
	वापस r;
}

पूर्णांक
sshsig_dearmor(काष्ठा sshbuf *sig, काष्ठा sshbuf **out)
{
	पूर्णांक r;
	माप_प्रकार eoffset = 0;
	काष्ठा sshbuf *buf = शून्य;
	काष्ठा sshbuf *sbuf = शून्य;
	अक्षर *b64 = शून्य;

	अगर ((sbuf = sshbuf_fromb(sig)) == शून्य) {
		error_f("sshbuf_fromb failed");
		वापस SSH_ERR_ALLOC_FAIL;
	}

	/* Expect and consume preamble + lf/crlf */
	अगर ((r = sshbuf_cmp(sbuf, 0,
	    BEGIN_SIGNATURE, माप(BEGIN_SIGNATURE)-1)) != 0) {
		error("Couldn't parse signature: missing header");
		जाओ done;
	}
	अगर ((r = sshbuf_consume(sbuf, माप(BEGIN_SIGNATURE)-1)) != 0) {
		error_fr(r, "consume");
		जाओ done;
	}
	अगर ((r = sshbuf_cmp(sbuf, 0, "\r\n", 2)) == 0)
		eoffset = 2;
	अन्यथा अगर ((r = sshbuf_cmp(sbuf, 0, "\n", 1)) == 0)
		eoffset = 1;
	अन्यथा {
		r = SSH_ERR_INVALID_FORMAT;
		error_f("no header eol");
		जाओ done;
	}
	अगर ((r = sshbuf_consume(sbuf, eoffset)) != 0) {
		error_fr(r, "consume eol");
		जाओ done;
	}
	/* Find and consume lf + suffix (any prior cr would be ignored) */
	अगर ((r = sshbuf_find(sbuf, 0, "\n" END_SIGNATURE,
	    माप(END_SIGNATURE), &eoffset)) != 0) {
		error("Couldn't parse signature: missing footer");
		जाओ done;
	}
	अगर ((r = sshbuf_consume_end(sbuf, sshbuf_len(sbuf)-eoffset)) != 0) {
		error_fr(r, "consume");
		जाओ done;
	}

	अगर ((b64 = sshbuf_dup_string(sbuf)) == शून्य) {
		error_f("sshbuf_dup_string failed");
		r = SSH_ERR_ALLOC_FAIL;
		जाओ done;
	}

	अगर ((buf = sshbuf_new()) == शून्य) {
		error_f("sshbuf_new() failed");
		r = SSH_ERR_ALLOC_FAIL;
		जाओ done;
	}

	अगर ((r = sshbuf_b64tod(buf, b64)) != 0) {
		error_fr(r, "decode base64");
		जाओ done;
	}

	/* success */
	*out = buf;
	r = 0;
	buf = शून्य; /* transferred */
done:
	sshbuf_free(buf);
	sshbuf_free(sbuf);
	मुक्त(b64);
	वापस r;
}

अटल पूर्णांक
sshsig_wrap_sign(काष्ठा sshkey *कुंजी, स्थिर अक्षर *hashalg,
    स्थिर अक्षर *sk_provider, स्थिर अक्षर *sk_pin, स्थिर काष्ठा sshbuf *h_message,
    स्थिर अक्षर *sig_namespace, काष्ठा sshbuf **out,
    sshsig_signer *signer, व्योम *signer_ctx)
{
	पूर्णांक r;
	माप_प्रकार slen = 0;
	u_char *sig = शून्य;
	काष्ठा sshbuf *blob = शून्य;
	काष्ठा sshbuf *tosign = शून्य;
	स्थिर अक्षर *sign_alg = शून्य;

	अगर ((tosign = sshbuf_new()) == शून्य ||
	    (blob = sshbuf_new()) == शून्य) {
		error_f("sshbuf_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		जाओ done;
	}

	अगर ((r = sshbuf_put(tosign, MAGIC_PREAMBLE, MAGIC_PREAMBLE_LEN)) != 0 ||
	    (r = sshbuf_put_cstring(tosign, sig_namespace)) != 0 ||
	    (r = sshbuf_put_string(tosign, शून्य, 0)) != 0 || /* reserved */
	    (r = sshbuf_put_cstring(tosign, hashalg)) != 0 ||
	    (r = sshbuf_put_stringb(tosign, h_message)) != 0) {
		error_fr(r, "assemble message to sign");
		जाओ done;
	}

	/* If using RSA keys then default to a good signature algorithm */
	अगर (sshkey_type_plain(कुंजी->type) == कुंजी_RSA) {
		sign_alg = RSA_SIGN_ALG;
		अगर (म_भेद(hashalg, "sha256") == 0)
			sign_alg = "rsa-sha2-256";
		अन्यथा अगर (म_भेद(hashalg, "sha512") == 0)
			sign_alg = "rsa-sha2-512";
	}

	अगर (signer != शून्य) {
		अगर ((r = signer(कुंजी, &sig, &slen,
		    sshbuf_ptr(tosign), sshbuf_len(tosign),
		    sign_alg, sk_provider, sk_pin, 0, signer_ctx)) != 0) {
			error_r(r, "Couldn't sign message (signer)");
			जाओ done;
		}
	} अन्यथा {
		अगर ((r = sshkey_sign(कुंजी, &sig, &slen,
		    sshbuf_ptr(tosign), sshbuf_len(tosign),
		    sign_alg, sk_provider, sk_pin, 0)) != 0) {
			error_r(r, "Couldn't sign message");
			जाओ done;
		}
	}

	अगर ((r = sshbuf_put(blob, MAGIC_PREAMBLE, MAGIC_PREAMBLE_LEN)) != 0 ||
	    (r = sshbuf_put_u32(blob, SIG_VERSION)) != 0 ||
	    (r = sshkey_puts(कुंजी, blob)) != 0 ||
	    (r = sshbuf_put_cstring(blob, sig_namespace)) != 0 ||
	    (r = sshbuf_put_string(blob, शून्य, 0)) != 0 || /* reserved */
	    (r = sshbuf_put_cstring(blob, hashalg)) != 0 ||
	    (r = sshbuf_put_string(blob, sig, slen)) != 0) {
		error_fr(r, "assemble signature object");
		जाओ done;
	}

	अगर (out != शून्य) {
		*out = blob;
		blob = शून्य;
	}
	r = 0;
done:
	मुक्त(sig);
	sshbuf_free(blob);
	sshbuf_free(tosign);
	वापस r;
}

/* Check preamble and version. */
अटल पूर्णांक
sshsig_parse_preamble(काष्ठा sshbuf *buf)
{
	पूर्णांक r = SSH_ERR_INTERNAL_ERROR;
	uint32_t sversion;

	अगर ((r = sshbuf_cmp(buf, 0, MAGIC_PREAMBLE, MAGIC_PREAMBLE_LEN)) != 0 ||
	    (r = sshbuf_consume(buf, (माप(MAGIC_PREAMBLE)-1))) != 0 ||
	    (r = sshbuf_get_u32(buf, &sversion)) != 0) {
		error("Couldn't verify signature: invalid format");
		वापस r;
	}

	अगर (sversion > SIG_VERSION) {
		error("Signature version %lu is larger than supported "
		    "version %u", (अचिन्हित दीर्घ)sversion, SIG_VERSION);
		वापस SSH_ERR_INVALID_FORMAT;
	}
	वापस 0;
}

अटल पूर्णांक
sshsig_check_hashalg(स्थिर अक्षर *hashalg)
{
	अगर (hashalg == शून्य ||
	    match_pattern_list(hashalg, HASHALG_ALLOWED, 0) == 1)
		वापस 0;
	error_f("unsupported hash algorithm \"%.100s\"", hashalg);
	वापस SSH_ERR_SIGN_ALG_UNSUPPORTED;
}

अटल पूर्णांक
sshsig_peek_hashalg(काष्ठा sshbuf *signature, अक्षर **hashalgp)
{
	काष्ठा sshbuf *buf = शून्य;
	अक्षर *hashalg = शून्य;
	पूर्णांक r = SSH_ERR_INTERNAL_ERROR;

	अगर (hashalgp != शून्य)
		*hashalgp = शून्य;
	अगर ((buf = sshbuf_fromb(signature)) == शून्य)
		वापस SSH_ERR_ALLOC_FAIL;
	अगर ((r = sshsig_parse_preamble(buf)) != 0)
		जाओ done;
	अगर ((r = sshbuf_get_string_direct(buf, शून्य, शून्य)) != 0 ||
	    (r = sshbuf_get_string_direct(buf, शून्य, शून्य)) != 0 ||
	    (r = sshbuf_get_string(buf, शून्य, शून्य)) != 0 ||
	    (r = sshbuf_get_cstring(buf, &hashalg, शून्य)) != 0 ||
	    (r = sshbuf_get_string_direct(buf, शून्य, शून्य)) != 0) {
		error_fr(r, "parse signature object");
		जाओ done;
	}

	/* success */
	r = 0;
	*hashalgp = hashalg;
	hashalg = शून्य;
 done:
	मुक्त(hashalg);
	sshbuf_free(buf);
	वापस r;
}

अटल पूर्णांक
sshsig_wrap_verify(काष्ठा sshbuf *signature, स्थिर अक्षर *hashalg,
    स्थिर काष्ठा sshbuf *h_message, स्थिर अक्षर *expect_namespace,
    काष्ठा sshkey **sign_keyp, काष्ठा sshkey_sig_details **sig_details)
{
	पूर्णांक r = SSH_ERR_INTERNAL_ERROR;
	काष्ठा sshbuf *buf = शून्य, *toverify = शून्य;
	काष्ठा sshkey *कुंजी = शून्य;
	स्थिर u_char *sig;
	अक्षर *got_namespace = शून्य, *sigtype = शून्य, *sig_hashalg = शून्य;
	माप_प्रकार siglen;

	debug_f("verify message length %zu", sshbuf_len(h_message));
	अगर (sig_details != शून्य)
		*sig_details = शून्य;
	अगर (sign_keyp != शून्य)
		*sign_keyp = शून्य;

	अगर ((toverify = sshbuf_new()) == शून्य) {
		error_f("sshbuf_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		जाओ done;
	}
	अगर ((r = sshbuf_put(toverify, MAGIC_PREAMBLE,
	    MAGIC_PREAMBLE_LEN)) != 0 ||
	    (r = sshbuf_put_cstring(toverify, expect_namespace)) != 0 ||
	    (r = sshbuf_put_string(toverify, शून्य, 0)) != 0 || /* reserved */
	    (r = sshbuf_put_cstring(toverify, hashalg)) != 0 ||
	    (r = sshbuf_put_stringb(toverify, h_message)) != 0) {
		error_fr(r, "assemble message to verify");
		जाओ done;
	}

	अगर ((r = sshsig_parse_preamble(signature)) != 0)
		जाओ done;

	अगर ((r = sshkey_froms(signature, &कुंजी)) != 0 ||
	    (r = sshbuf_get_cstring(signature, &got_namespace, शून्य)) != 0 ||
	    (r = sshbuf_get_string(signature, शून्य, शून्य)) != 0 ||
	    (r = sshbuf_get_cstring(signature, &sig_hashalg, शून्य)) != 0 ||
	    (r = sshbuf_get_string_direct(signature, &sig, &siglen)) != 0) {
		error_fr(r, "parse signature object");
		जाओ done;
	}

	अगर (sshbuf_len(signature) != 0) {
		error("Signature contains trailing data");
		r = SSH_ERR_INVALID_FORMAT;
		जाओ done;
	}

	अगर (म_भेद(expect_namespace, got_namespace) != 0) {
		error("Couldn't verify signature: namespace does not match");
		debug_f("expected namespace \"%s\" received \"%s\"",
		    expect_namespace, got_namespace);
		r = SSH_ERR_SIGNATURE_INVALID;
		जाओ done;
	}
	अगर (म_भेद(hashalg, sig_hashalg) != 0) {
		error("Couldn't verify signature: hash algorithm mismatch");
		debug_f("expected algorithm \"%s\" received \"%s\"",
		    hashalg, sig_hashalg);
		r = SSH_ERR_SIGNATURE_INVALID;
		जाओ done;
	}
	/* Ensure that RSA keys use an acceptable signature algorithm */
	अगर (sshkey_type_plain(कुंजी->type) == कुंजी_RSA) {
		अगर ((r = sshkey_get_sigtype(sig, siglen, &sigtype)) != 0) {
			error_r(r, "Couldn't verify signature: unable to get "
			    "signature type");
			जाओ done;
		}
		अगर (match_pattern_list(sigtype, RSA_SIGN_ALLOWED, 0) != 1) {
			error("Couldn't verify signature: unsupported RSA "
			    "signature algorithm %s", sigtype);
			r = SSH_ERR_SIGN_ALG_UNSUPPORTED;
			जाओ done;
		}
	}
	अगर ((r = sshkey_verify(कुंजी, sig, siglen, sshbuf_ptr(toverify),
	    sshbuf_len(toverify), शून्य, 0, sig_details)) != 0) {
		error_r(r, "Signature verification failed");
		जाओ done;
	}

	/* success */
	r = 0;
	अगर (sign_keyp != शून्य) {
		*sign_keyp = कुंजी;
		कुंजी = शून्य; /* transferred */
	}
done:
	मुक्त(got_namespace);
	मुक्त(sigtype);
	मुक्त(sig_hashalg);
	sshbuf_free(buf);
	sshbuf_free(toverify);
	sshkey_free(कुंजी);
	वापस r;
}

अटल पूर्णांक
hash_बफर(स्थिर काष्ठा sshbuf *m, स्थिर अक्षर *hashalg, काष्ठा sshbuf **bp)
{
	अक्षर *hex, hash[SSH_DIGEST_MAX_लंबाई];
	पूर्णांक alg, r = SSH_ERR_INTERNAL_ERROR;
	काष्ठा sshbuf *b = शून्य;

	*bp = शून्य;
	स_रखो(hash, 0, माप(hash));

	अगर ((r = sshsig_check_hashalg(hashalg)) != 0)
		वापस r;
	अगर ((alg = ssh_digest_alg_by_name(hashalg)) == -1) {
		error_f("can't look up hash algorithm %s", hashalg);
		वापस SSH_ERR_INTERNAL_ERROR;
	}
	अगर ((r = ssh_digest_बफर(alg, m, hash, माप(hash))) != 0) {
		error_fr(r, "ssh_digest_buffer");
		वापस r;
	}
	अगर ((hex = tohex(hash, ssh_digest_bytes(alg))) != शून्य) {
		debug3_f("final hash: %s", hex);
		freezero(hex, म_माप(hex));
	}
	अगर ((b = sshbuf_new()) == शून्य) {
		r = SSH_ERR_ALLOC_FAIL;
		जाओ out;
	}
	अगर ((r = sshbuf_put(b, hash, ssh_digest_bytes(alg))) != 0) {
		error_fr(r, "sshbuf_put");
		जाओ out;
	}
	*bp = b;
	b = शून्य; /* transferred */
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	explicit_bzero(hash, माप(hash));
	वापस r;
}

पूर्णांक
sshsig_signb(काष्ठा sshkey *कुंजी, स्थिर अक्षर *hashalg,
    स्थिर अक्षर *sk_provider, स्थिर अक्षर *sk_pin,
    स्थिर काष्ठा sshbuf *message, स्थिर अक्षर *sig_namespace,
    काष्ठा sshbuf **out, sshsig_signer *signer, व्योम *signer_ctx)
{
	काष्ठा sshbuf *b = शून्य;
	पूर्णांक r = SSH_ERR_INTERNAL_ERROR;

	अगर (hashalg == शून्य)
		hashalg = HASHALG_DEFAULT;
	अगर (out != शून्य)
		*out = शून्य;
	अगर ((r = hash_बफर(message, hashalg, &b)) != 0) {
		error_fr(r, "hash buffer");
		जाओ out;
	}
	अगर ((r = sshsig_wrap_sign(कुंजी, hashalg, sk_provider, sk_pin, b,
	    sig_namespace, out, signer, signer_ctx)) != 0)
		जाओ out;
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	वापस r;
}

पूर्णांक
sshsig_verifyb(काष्ठा sshbuf *signature, स्थिर काष्ठा sshbuf *message,
    स्थिर अक्षर *expect_namespace, काष्ठा sshkey **sign_keyp,
    काष्ठा sshkey_sig_details **sig_details)
{
	काष्ठा sshbuf *b = शून्य;
	पूर्णांक r = SSH_ERR_INTERNAL_ERROR;
	अक्षर *hashalg = शून्य;

	अगर (sig_details != शून्य)
		*sig_details = शून्य;
	अगर (sign_keyp != शून्य)
		*sign_keyp = शून्य;
	अगर ((r = sshsig_peek_hashalg(signature, &hashalg)) != 0)
		वापस r;
	debug_f("signature made with hash \"%s\"", hashalg);
	अगर ((r = hash_बफर(message, hashalg, &b)) != 0) {
		error_fr(r, "hash buffer");
		जाओ out;
	}
	अगर ((r = sshsig_wrap_verify(signature, hashalg, b, expect_namespace,
	    sign_keyp, sig_details)) != 0)
		जाओ out;
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	मुक्त(hashalg);
	वापस r;
}

अटल पूर्णांक
hash_file(पूर्णांक fd, स्थिर अक्षर *hashalg, काष्ठा sshbuf **bp)
{
	अक्षर *hex, rbuf[8192], hash[SSH_DIGEST_MAX_लंबाई];
	ssize_t n, योग_2 = 0;
	काष्ठा ssh_digest_ctx *ctx = शून्य;
	पूर्णांक alg, oerrno, r = SSH_ERR_INTERNAL_ERROR;
	काष्ठा sshbuf *b = शून्य;

	*bp = शून्य;
	स_रखो(hash, 0, माप(hash));

	अगर ((r = sshsig_check_hashalg(hashalg)) != 0)
		वापस r;
	अगर ((alg = ssh_digest_alg_by_name(hashalg)) == -1) {
		error_f("can't look up hash algorithm %s", hashalg);
		वापस SSH_ERR_INTERNAL_ERROR;
	}
	अगर ((ctx = ssh_digest_start(alg)) == शून्य) {
		error_f("ssh_digest_start failed");
		वापस SSH_ERR_INTERNAL_ERROR;
	}
	क्रम (;;) {
		अगर ((n = पढ़ो(fd, rbuf, माप(rbuf))) == -1) {
			अगर (त्रुटि_सं == EINTR || त्रुटि_सं == EAGAIN)
				जारी;
			oerrno = त्रुटि_सं;
			error_f("read: %s", म_त्रुटि(त्रुटि_सं));
			त्रुटि_सं = oerrno;
			r = SSH_ERR_SYSTEM_ERROR;
			जाओ out;
		} अन्यथा अगर (n == 0) {
			debug2_f("hashed %zu bytes", योग_2);
			अवरोध; /* EOF */
		}
		योग_2 += (माप_प्रकार)n;
		अगर ((r = ssh_digest_update(ctx, rbuf, (माप_प्रकार)n)) != 0) {
			error_fr(r, "ssh_digest_update");
			जाओ out;
		}
	}
	अगर ((r = ssh_digest_final(ctx, hash, माप(hash))) != 0) {
		error_fr(r, "ssh_digest_final");
		जाओ out;
	}
	अगर ((hex = tohex(hash, ssh_digest_bytes(alg))) != शून्य) {
		debug3_f("final hash: %s", hex);
		freezero(hex, म_माप(hex));
	}
	अगर ((b = sshbuf_new()) == शून्य) {
		r = SSH_ERR_ALLOC_FAIL;
		जाओ out;
	}
	अगर ((r = sshbuf_put(b, hash, ssh_digest_bytes(alg))) != 0) {
		error_fr(r, "sshbuf_put");
		जाओ out;
	}
	*bp = b;
	b = शून्य; /* transferred */
	/* success */
	r = 0;
 out:
	oerrno = त्रुटि_सं;
	sshbuf_free(b);
	ssh_digest_free(ctx);
	explicit_bzero(hash, माप(hash));
	त्रुटि_सं = oerrno;
	वापस r;
}

पूर्णांक
sshsig_sign_fd(काष्ठा sshkey *कुंजी, स्थिर अक्षर *hashalg,
    स्थिर अक्षर *sk_provider, स्थिर अक्षर *sk_pin,
    पूर्णांक fd, स्थिर अक्षर *sig_namespace, काष्ठा sshbuf **out,
    sshsig_signer *signer, व्योम *signer_ctx)
{
	काष्ठा sshbuf *b = शून्य;
	पूर्णांक r = SSH_ERR_INTERNAL_ERROR;

	अगर (hashalg == शून्य)
		hashalg = HASHALG_DEFAULT;
	अगर (out != शून्य)
		*out = शून्य;
	अगर ((r = hash_file(fd, hashalg, &b)) != 0) {
		error_fr(r, "hash_file");
		वापस r;
	}
	अगर ((r = sshsig_wrap_sign(कुंजी, hashalg, sk_provider, sk_pin, b,
	    sig_namespace, out, signer, signer_ctx)) != 0)
		जाओ out;
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	वापस r;
}

पूर्णांक
sshsig_verify_fd(काष्ठा sshbuf *signature, पूर्णांक fd,
    स्थिर अक्षर *expect_namespace, काष्ठा sshkey **sign_keyp,
    काष्ठा sshkey_sig_details **sig_details)
{
	काष्ठा sshbuf *b = शून्य;
	पूर्णांक r = SSH_ERR_INTERNAL_ERROR;
	अक्षर *hashalg = शून्य;

	अगर (sig_details != शून्य)
		*sig_details = शून्य;
	अगर (sign_keyp != शून्य)
		*sign_keyp = शून्य;
	अगर ((r = sshsig_peek_hashalg(signature, &hashalg)) != 0)
		वापस r;
	debug_f("signature made with hash \"%s\"", hashalg);
	अगर ((r = hash_file(fd, hashalg, &b)) != 0) {
		error_fr(r, "hash_file");
		जाओ out;
	}
	अगर ((r = sshsig_wrap_verify(signature, hashalg, b, expect_namespace,
	    sign_keyp, sig_details)) != 0)
		जाओ out;
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	मुक्त(hashalg);
	वापस r;
}

काष्ठा sshsigopt {
	पूर्णांक ca;
	अक्षर *namespaces;
	uint64_t valid_after, valid_before;
};

काष्ठा sshsigopt *
sshsigopt_parse(स्थिर अक्षर *opts, स्थिर अक्षर *path, u_long linenum,
    स्थिर अक्षर **errstrp)
{
	काष्ठा sshsigopt *ret;
	पूर्णांक r;
	अक्षर *opt;
	स्थिर अक्षर *errstr = शून्य;

	अगर ((ret = सुस्मृति(1, माप(*ret))) == शून्य)
		वापस शून्य;
	अगर (opts == शून्य || *opts == '\0')
		वापस ret; /* Empty options yields empty options :) */

	जबतक (*opts && *opts != ' ' && *opts != '\t') {
		/* flag options */
		अगर ((r = opt_flag("cert-authority", 0, &opts)) != -1) {
			ret->ca = 1;
		} अन्यथा अगर (opt_match(&opts, "namespaces")) {
			अगर (ret->namespaces != शून्य) {
				errstr = "multiple \"namespaces\" clauses";
				जाओ fail;
			}
			ret->namespaces = opt_dequote(&opts, &errstr);
			अगर (ret->namespaces == शून्य)
				जाओ fail;
		} अन्यथा अगर (opt_match(&opts, "valid-after")) {
			अगर (ret->valid_after != 0) {
				errstr = "multiple \"valid-after\" clauses";
				जाओ fail;
			}
			अगर ((opt = opt_dequote(&opts, &errstr)) == शून्य)
				जाओ fail;
			अगर (parse_absolute_time(opt, &ret->valid_after) != 0 ||
			    ret->valid_after == 0) {
				मुक्त(opt);
				errstr = "invalid \"valid-after\" time";
				जाओ fail;
			}
			मुक्त(opt);
		} अन्यथा अगर (opt_match(&opts, "valid-before")) {
			अगर (ret->valid_before != 0) {
				errstr = "multiple \"valid-before\" clauses";
				जाओ fail;
			}
			अगर ((opt = opt_dequote(&opts, &errstr)) == शून्य)
				जाओ fail;
			अगर (parse_absolute_time(opt, &ret->valid_before) != 0 ||
			    ret->valid_before == 0) {
				मुक्त(opt);
				errstr = "invalid \"valid-before\" time";
				जाओ fail;
			}
			मुक्त(opt);
		}
		/*
		 * Skip the comma, and move to the next option
		 * (or break out if there are no more).
		 */
		अगर (*opts == '\0' || *opts == ' ' || *opts == '\t')
			अवरोध;		/* End of options. */
		/* Anything other than a comma is an unknown option */
		अगर (*opts != ',') {
			errstr = "unknown key option";
			जाओ fail;
		}
		opts++;
		अगर (*opts == '\0') {
			errstr = "unexpected end-of-options";
			जाओ fail;
		}
	}
	/* final consistency check */
	अगर (ret->valid_after != 0 && ret->valid_before != 0 &&
	    ret->valid_before <= ret->valid_after) {
		errstr = "\"valid-before\" time is before \"valid-after\"";
		जाओ fail;
	}
	/* success */
	वापस ret;
 fail:
	अगर (errstrp != शून्य)
		*errstrp = errstr;
	sshsigopt_free(ret);
	वापस शून्य;
}

व्योम
sshsigopt_free(काष्ठा sshsigopt *opts)
{
	अगर (opts == शून्य)
		वापस;
	मुक्त(opts->namespaces);
	मुक्त(opts);
}

अटल पूर्णांक
parse_principals_कुंजी_and_options(स्थिर अक्षर *path, u_long linenum, अक्षर *पंक्ति,
    स्थिर अक्षर *required_principal, अक्षर **principalsp, काष्ठा sshkey **keyp,
    काष्ठा sshsigopt **sigoptsp)
{
	अक्षर *opts = शून्य, *tmp, *cp, *principals = शून्य;
	स्थिर अक्षर *reason = शून्य;
	काष्ठा sshsigopt *sigopts = शून्य;
	काष्ठा sshkey *कुंजी = शून्य;
	पूर्णांक r = SSH_ERR_INTERNAL_ERROR;

	अगर (principalsp != शून्य)
		*principalsp = शून्य;
	अगर (sigoptsp != शून्य)
		*sigoptsp = शून्य;
	अगर (keyp != शून्य)
		*keyp = शून्य;

	cp = पंक्ति;
	cp = cp + म_अखोज(cp, " \t\n\r"); /* skip leading whitespace */
	अगर (*cp == '#' || *cp == '\0')
		वापस SSH_ERR_कुंजी_NOT_FOUND; /* blank or all-comment line */

	/* format: identity[,identity...] [option[,option...]] key */
	अगर ((tmp = strdelimw(&cp)) == शून्य || cp == शून्य) {
		error("%s:%lu: invalid line", path, linenum);
		r = SSH_ERR_INVALID_FORMAT;
		जाओ out;
	}
	अगर ((principals = strdup(tmp)) == शून्य) {
		error_f("strdup failed");
		r = SSH_ERR_ALLOC_FAIL;
		जाओ out;
	}
	/*
	 * Bail out early if we're looking for a particular principal and this
	 * line does not list it.
	 */
	अगर (required_principal != शून्य) {
		अगर (match_pattern_list(required_principal,
		    principals, 0) != 1) {
			/* principal didn't match */
			r = SSH_ERR_कुंजी_NOT_FOUND;
			जाओ out;
		}
		debug_f("%s:%lu: matched principal \"%s\"",
		    path, linenum, required_principal);
	}

	अगर ((कुंजी = sshkey_new(कुंजी_UNSPEC)) == शून्य) {
		error_f("sshkey_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		जाओ out;
	}
	अगर (sshkey_read(कुंजी, &cp) != 0) {
		/* no key? Check for options */
		opts = cp;
		अगर (sshkey_advance_past_options(&cp) != 0) {
			error("%s:%lu: invalid options", path, linenum);
			r = SSH_ERR_INVALID_FORMAT;
			जाओ out;
		}
		अगर (cp == शून्य || *cp == '\0') {
			error("%s:%lu: missing key", path, linenum);
			r = SSH_ERR_INVALID_FORMAT;
			जाओ out;
		}
		*cp++ = '\0';
		skip_space(&cp);
		अगर (sshkey_read(कुंजी, &cp) != 0) {
			error("%s:%lu: invalid key", path, linenum);
			r = SSH_ERR_INVALID_FORMAT;
			जाओ out;
		}
	}
	debug3("%s:%lu: options %s", path, linenum, opts == शून्य ? "" : opts);
	अगर ((sigopts = sshsigopt_parse(opts, path, linenum, &reason)) == शून्य) {
		error("%s:%lu: bad options: %s", path, linenum, reason);
		r = SSH_ERR_INVALID_FORMAT;
		जाओ out;
	}
	/* success */
	अगर (principalsp != शून्य) {
		*principalsp = principals;
		principals = शून्य; /* transferred */
	}
	अगर (sigoptsp != शून्य) {
		*sigoptsp = sigopts;
		sigopts = शून्य; /* transferred */
	}
	अगर (keyp != शून्य) {
		*keyp = कुंजी;
		कुंजी = शून्य; /* transferred */
	}
	r = 0;
 out:
	मुक्त(principals);
	sshsigopt_free(sigopts);
	sshkey_free(कुंजी);
	वापस r;
}

अटल पूर्णांक
cert_filter_principals(स्थिर अक्षर *path, u_long linenum,
    अक्षर **principalsp, स्थिर काष्ठा sshkey *cert, uint64_t verify_time)
{
	अक्षर *cp, *oprincipals, *principals;
	स्थिर अक्षर *reason;
	काष्ठा sshbuf *nprincipals;
	पूर्णांक r = SSH_ERR_INTERNAL_ERROR, success = 0;
	u_int i;

	oprincipals = principals = *principalsp;
	*principalsp = शून्य;

	अगर ((nprincipals = sshbuf_new()) == शून्य) {
		r = SSH_ERR_ALLOC_FAIL;
		जाओ out;
	}

	जबतक ((cp = strsep(&principals, ",")) != शून्य && *cp != '\0') {
		/* Check certificate validity */
		अगर ((r = sshkey_cert_check_authority(cert, 0, 0, verify_time,
		    शून्य, &reason)) != 0) {
			debug("%s:%lu: principal \"%s\" not authorized: %s",
			    path, linenum, cp, reason);
			जारी;
		}
		/* Return all matching principal names from the cert */
		क्रम (i = 0; i < cert->cert->nprincipals; i++) {
			अगर (match_pattern(cert->cert->principals[i], cp)) {
				अगर ((r = sshbuf_putf(nprincipals, "%s%s",
					sshbuf_len(nprincipals) != 0 ? "," : "",
						cert->cert->principals[i])) != 0) {
					error_f("buffer error");
					जाओ out;
				}
			}
		}
	}
	अगर (sshbuf_len(nprincipals) == 0) {
		error("%s:%lu: no valid principals found", path, linenum);
		r = SSH_ERR_कुंजी_CERT_INVALID;
		जाओ out;
	}
	अगर ((principals = sshbuf_dup_string(nprincipals)) == शून्य) {
		error_f("buffer error");
		r = SSH_ERR_ALLOC_FAIL;
		जाओ out;
	}
	/* success */
	success = 1;
	*principalsp = principals;
 out:
	sshbuf_free(nprincipals);
	मुक्त(oprincipals);
	वापस success ? 0 : r;
}

अटल पूर्णांक
check_allowed_कुंजियाँ_पंक्ति(स्थिर अक्षर *path, u_long linenum, अक्षर *पंक्ति,
    स्थिर काष्ठा sshkey *sign_कुंजी, स्थिर अक्षर *principal,
    स्थिर अक्षर *sig_namespace, uint64_t verify_time, अक्षर **principalsp)
{
	काष्ठा sshkey *found_कुंजी = शून्य;
	अक्षर *principals = शून्य;
	पूर्णांक r, success = 0;
	स्थिर अक्षर *reason = शून्य;
	काष्ठा sshsigopt *sigopts = शून्य;
	अक्षर tvalid[64], tverify[64];

	अगर (principalsp != शून्य)
		*principalsp = शून्य;

	/* Parse the line */
	अगर ((r = parse_principals_कुंजी_and_options(path, linenum, पंक्ति,
	    principal, &principals, &found_कुंजी, &sigopts)) != 0) {
		/* error already logged */
		जाओ done;
	}

	अगर (!sigopts->ca && sshkey_equal(found_कुंजी, sign_कुंजी)) {
		/* Exact match of key */
		debug("%s:%lu: matched key", path, linenum);
	} अन्यथा अगर (sigopts->ca && sshkey_is_cert(sign_कुंजी) &&
	    sshkey_equal_public(sign_कुंजी->cert->signature_कुंजी, found_कुंजी)) {
		अगर (principal) {
			/* Match certificate CA key with specified principal */
			अगर ((r = sshkey_cert_check_authority(sign_कुंजी, 0, 0,
			    verify_time, principal, &reason)) != 0) {
				error("%s:%lu: certificate not authorized: %s",
				    path, linenum, reason);
				जाओ done;
			}
			debug("%s:%lu: matched certificate CA key",
			    path, linenum);
		} अन्यथा {
			/* No principal specified - find all matching ones */
			अगर ((r = cert_filter_principals(path, linenum,
			    &principals, sign_कुंजी, verify_time)) != 0) {
				/* error already displayed */
				debug_r(r, "%s:%lu: cert_filter_principals",
				    path, linenum);
				जाओ done;
			}
			debug("%s:%lu: matched certificate CA key",
			    path, linenum);
		}
	} अन्यथा {
		/* Didn't match key */
		जाओ done;
	}

	/* Check whether options preclude the use of this key */
	अगर (sigopts->namespaces != शून्य && sig_namespace != शून्य &&
	    match_pattern_list(sig_namespace, sigopts->namespaces, 0) != 1) {
		error("%s:%lu: key is not permitted for use in signature "
		    "namespace \"%s\"", path, linenum, sig_namespace);
		जाओ done;
	}

	/* check key time validity */
	format_absolute_time((uint64_t)verify_time, tverify, माप(tverify));
	अगर (sigopts->valid_after != 0 &&
	    (uint64_t)verify_time < sigopts->valid_after) {
		format_absolute_time(sigopts->valid_after,
		    tvalid, माप(tvalid));
		error("%s:%lu: key is not yet valid: "
		    "verify time %s < valid-after %s", path, linenum,
		    tverify, tvalid);
		जाओ done;
	}
	अगर (sigopts->valid_before != 0 &&
	    (uint64_t)verify_time > sigopts->valid_before) {
		format_absolute_time(sigopts->valid_before,
		    tvalid, माप(tvalid));
		error("%s:%lu: key has expired: "
		    "verify time %s > valid-before %s", path, linenum,
		    tverify, tvalid);
		जाओ done;
	}
	success = 1;

 done:
	अगर (success && principalsp != शून्य) {
		*principalsp = principals;
		principals = शून्य; /* transferred */
	}
	मुक्त(principals);
	sshkey_free(found_कुंजी);
	sshsigopt_free(sigopts);
	वापस success ? 0 : SSH_ERR_कुंजी_NOT_FOUND;
}

पूर्णांक
sshsig_check_allowed_कुंजियाँ(स्थिर अक्षर *path, स्थिर काष्ठा sshkey *sign_कुंजी,
    स्थिर अक्षर *principal, स्थिर अक्षर *sig_namespace, uint64_t verify_time)
{
	खाता *f = शून्य;
	अक्षर *पंक्ति = शून्य;
	माप_प्रकार linesize = 0;
	u_long linenum = 0;
	पूर्णांक r = SSH_ERR_कुंजी_NOT_FOUND, oerrno;

	/* Check key and principal against file */
	अगर ((f = ख_खोलो(path, "r")) == शून्य) {
		oerrno = त्रुटि_सं;
		error("Unable to open allowed keys file \"%s\": %s",
		    path, म_त्रुटि(त्रुटि_सं));
		त्रुटि_सं = oerrno;
		वापस SSH_ERR_SYSTEM_ERROR;
	}

	जबतक (getline(&पंक्ति, &linesize, f) != -1) {
		linenum++;
		r = check_allowed_कुंजियाँ_पंक्ति(path, linenum, पंक्ति, sign_कुंजी,
		    principal, sig_namespace, verify_time, शून्य);
		मुक्त(पंक्ति);
		पंक्ति = शून्य;
		linesize = 0;
		अगर (r == SSH_ERR_कुंजी_NOT_FOUND)
			जारी;
		अन्यथा अगर (r == 0) {
			/* success */
			ख_बंद(f);
			वापस 0;
		} अन्यथा
			अवरोध;
	}
	/* Either we hit an error parsing or we simply didn't find the key */
	ख_बंद(f);
	मुक्त(पंक्ति);
	वापस r;
}

पूर्णांक
sshsig_find_principals(स्थिर अक्षर *path, स्थिर काष्ठा sshkey *sign_कुंजी,
    uint64_t verify_time, अक्षर **principals)
{
	खाता *f = शून्य;
	अक्षर *पंक्ति = शून्य;
	माप_प्रकार linesize = 0;
	u_long linenum = 0;
	पूर्णांक r = SSH_ERR_कुंजी_NOT_FOUND, oerrno;

	अगर ((f = ख_खोलो(path, "r")) == शून्य) {
		oerrno = त्रुटि_सं;
		error("Unable to open allowed keys file \"%s\": %s",
		    path, म_त्रुटि(त्रुटि_सं));
		त्रुटि_सं = oerrno;
		वापस SSH_ERR_SYSTEM_ERROR;
	}

	जबतक (getline(&पंक्ति, &linesize, f) != -1) {
		linenum++;
		r = check_allowed_कुंजियाँ_पंक्ति(path, linenum, पंक्ति,
		    sign_कुंजी, शून्य, शून्य, verify_time, principals);
		मुक्त(पंक्ति);
		पंक्ति = शून्य;
		linesize = 0;
		अगर (r == SSH_ERR_कुंजी_NOT_FOUND)
			जारी;
		अन्यथा अगर (r == 0) {
			/* success */
			ख_बंद(f);
			वापस 0;
		} अन्यथा
			अवरोध;
	}
	मुक्त(पंक्ति);
	/* Either we hit an error parsing or we simply didn't find the key */
	अगर (ख_त्रुटि(f) != 0) {
		oerrno = त्रुटि_सं;
		ख_बंद(f);
		error("Unable to read allowed keys file \"%s\": %s",
		    path, म_त्रुटि(त्रुटि_सं));
		त्रुटि_सं = oerrno;
		वापस SSH_ERR_SYSTEM_ERROR;
	}
	ख_बंद(f);
	वापस r;
}

पूर्णांक
sshsig_match_principals(स्थिर अक्षर *path, स्थिर अक्षर *principal,
    अक्षर ***principalsp, माप_प्रकार *nprincipalsp)
{
	खाता *f = शून्य;
	अक्षर *found, *पंक्ति = शून्य, **principals = शून्य, **tmp;
	माप_प्रकार i, nprincipals = 0, linesize = 0;
	u_long linenum = 0;
	पूर्णांक oerrno = 0, r, ret = 0;

	अगर (principalsp != शून्य)
		*principalsp = शून्य;
	अगर (nprincipalsp != शून्य)
		*nprincipalsp = 0;

	/* Check key and principal against file */
	अगर ((f = ख_खोलो(path, "r")) == शून्य) {
		oerrno = त्रुटि_सं;
		error("Unable to open allowed keys file \"%s\": %s",
		    path, म_त्रुटि(त्रुटि_सं));
		त्रुटि_सं = oerrno;
		वापस SSH_ERR_SYSTEM_ERROR;
	}

	जबतक (getline(&पंक्ति, &linesize, f) != -1) {
		linenum++;
		/* Parse the line */
		अगर ((r = parse_principals_कुंजी_and_options(path, linenum, पंक्ति,
		    principal, &found, शून्य, शून्य)) != 0) {
			अगर (r == SSH_ERR_कुंजी_NOT_FOUND)
				जारी;
			ret = r;
			oerrno = त्रुटि_सं;
			अवरोध; /* unexpected error */
		}
		अगर ((tmp = recallocarray(principals, nprincipals,
		    nprincipals + 1, माप(*principals))) == शून्य) {
			ret = SSH_ERR_ALLOC_FAIL;
			मुक्त(found);
			अवरोध;
		}
		principals = tmp;
		principals[nprincipals++] = found; /* transferred */
		मुक्त(पंक्ति);
		पंक्ति = शून्य;
		linesize = 0;
	}
	ख_बंद(f);
	मुक्त(पंक्ति);

	अगर (ret == 0) {
		अगर (nprincipals == 0)
			ret = SSH_ERR_कुंजी_NOT_FOUND;
		अगर (nprincipalsp != शून्य)
			*nprincipalsp = nprincipals;
		अगर (principalsp != शून्य) {
			*principalsp = principals;
			principals = शून्य; /* transferred */
			nprincipals = 0;
		}
	}

	क्रम (i = 0; i < nprincipals; i++)
		मुक्त(principals[i]);
	मुक्त(principals);

	त्रुटि_सं = oerrno;
	वापस ret;
}

पूर्णांक
sshsig_get_pubkey(काष्ठा sshbuf *signature, काष्ठा sshkey **pubkey)
{
	काष्ठा sshkey *pk = शून्य;
	पूर्णांक r = SSH_ERR_SIGNATURE_INVALID;

	अगर (pubkey == शून्य)
		वापस SSH_ERR_INTERNAL_ERROR;
	अगर ((r = sshsig_parse_preamble(signature)) != 0)
		वापस r;
	अगर ((r = sshkey_froms(signature, &pk)) != 0)
		वापस r;

	*pubkey = pk;
	pk = शून्य;
	वापस 0;
}
