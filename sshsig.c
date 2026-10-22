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

#અન્તર્ભાવ "includes.h"

#અન્તર્ભાવ <stdio.h>
#અન્તર્ભાવ <stdlib.h>
#અન્તર્ભાવ <stdarg.h>
#અન્તર્ભાવ <errno.h>
#અન્તર્ભાવ <string.h>
#અન્તર્ભાવ <unistd.h>

#અન્તર્ભાવ "authfd.h"
#અન્તર્ભાવ "authfile.h"
#અન્તર્ભાવ "log.h"
#અન્તર્ભાવ "misc.h"
#અન્તર્ભાવ "sshbuf.h"
#અન્તર્ભાવ "sshsig.h"
#અન્તર્ભાવ "ssherr.h"
#અન્તર્ભાવ "sshkey.h"
#અન્તર્ભાવ "match.h"
#અન્તર્ભાવ "digest.h"

#define SIG_VERSION		0x01
#define MAGIC_PREAMBLE		"SSHSIG"
#define MAGIC_PREAMBLE_LEN	(કદ(MAGIC_PREAMBLE) - 1)
#define BEGIN_SIGNATURE		"-----BEGIN SSH SIGNATURE-----"
#define END_SIGNATURE		"-----END SSH SIGNATURE-----"
#define RSA_SIGN_ALG		"rsa-sha2-512"
#define RSA_SIGN_ALLOWED	"rsa-sha2-512,rsa-sha2-256"
#define HASHALG_DEFAULT		"sha512"
#define HASHALG_ALLOWED		"sha256,sha512"

પૂર્ણાંક
sshsig_armor(અચલ સંરચના sshbuf *blob, સંરચના sshbuf **out)
{
	સંરચના sshbuf *buf = ખાલી;
	પૂર્ણાંક r = SSH_ERR_INTERNAL_ERROR;

	*out = ખાલી;

	જો ((buf = sshbuf_new()) == ખાલી) {
		error_f("sshbuf_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		જાઓ out;
	}

	જો ((r = sshbuf_putf(buf, "%s\n", BEGIN_SIGNATURE)) != 0) {
		error_fr(r, "sshbuf_putf");
		જાઓ out;
	}

	જો ((r = sshbuf_dtob64(blob, buf, 1)) != 0) {
		error_fr(r, "base64 encode signature");
		જાઓ out;
	}

	જો ((r = sshbuf_put(buf, END_SIGNATURE,
	    કદ(END_SIGNATURE)-1)) != 0 ||
	    (r = sshbuf_put_u8(buf, '\n')) != 0) {
		error_fr(r, "sshbuf_put");
		જાઓ out;
	}
	/* success */
	*out = buf;
	buf = ખાલી; /* transferred */
	r = 0;
 out:
	sshbuf_free(buf);
	પાછા r;
}

પૂર્ણાંક
sshsig_dearmor(સંરચના sshbuf *sig, સંરચના sshbuf **out)
{
	પૂર્ણાંક r;
	size_t eoffset = 0;
	સંરચના sshbuf *buf = ખાલી;
	સંરચના sshbuf *sbuf = ખાલી;
	અક્ષર *b64 = ખાલી;

	જો ((sbuf = sshbuf_fromb(sig)) == ખાલી) {
		error_f("sshbuf_fromb failed");
		પાછા SSH_ERR_ALLOC_FAIL;
	}

	/* Expect and consume preamble + lf/crlf */
	જો ((r = sshbuf_cmp(sbuf, 0,
	    BEGIN_SIGNATURE, કદ(BEGIN_SIGNATURE)-1)) != 0) {
		error("Couldn't parse signature: missing header");
		જાઓ done;
	}
	જો ((r = sshbuf_consume(sbuf, કદ(BEGIN_SIGNATURE)-1)) != 0) {
		error_fr(r, "consume");
		જાઓ done;
	}
	જો ((r = sshbuf_cmp(sbuf, 0, "\r\n", 2)) == 0)
		eoffset = 2;
	નહીંતર જો ((r = sshbuf_cmp(sbuf, 0, "\n", 1)) == 0)
		eoffset = 1;
	નહીંતર {
		r = SSH_ERR_INVALID_FORMAT;
		error_f("no header eol");
		જાઓ done;
	}
	જો ((r = sshbuf_consume(sbuf, eoffset)) != 0) {
		error_fr(r, "consume eol");
		જાઓ done;
	}
	/* Find and consume lf + suffix (any prior cr would be ignored) */
	જો ((r = sshbuf_find(sbuf, 0, "\n" END_SIGNATURE,
	    કદ(END_SIGNATURE), &eoffset)) != 0) {
		error("Couldn't parse signature: missing footer");
		જાઓ done;
	}
	જો ((r = sshbuf_consume_end(sbuf, sshbuf_len(sbuf)-eoffset)) != 0) {
		error_fr(r, "consume");
		જાઓ done;
	}

	જો ((b64 = sshbuf_dup_string(sbuf)) == ખાલી) {
		error_f("sshbuf_dup_string failed");
		r = SSH_ERR_ALLOC_FAIL;
		જાઓ done;
	}

	જો ((buf = sshbuf_new()) == ખાલી) {
		error_f("sshbuf_new() failed");
		r = SSH_ERR_ALLOC_FAIL;
		જાઓ done;
	}

	જો ((r = sshbuf_b64tod(buf, b64)) != 0) {
		error_fr(r, "decode base64");
		જાઓ done;
	}

	/* success */
	*out = buf;
	r = 0;
	buf = ખાલી; /* transferred */
done:
	sshbuf_free(buf);
	sshbuf_free(sbuf);
	મુક્ત(b64);
	પાછા r;
}

સ્થિર પૂર્ણાંક
sshsig_wrap_sign(સંરચના sshkey *ચાવી, અચલ અક્ષર *hashalg,
    અચલ અક્ષર *sk_provider, અચલ અક્ષર *sk_pin, અચલ સંરચના sshbuf *h_message,
    અચલ અક્ષર *sig_namespace, સંરચના sshbuf **out,
    sshsig_signer *signer, શૂન્ય *signer_ctx)
{
	પૂર્ણાંક r;
	size_t slen = 0;
	u_char *sig = ખાલી;
	સંરચના sshbuf *blob = ખાલી;
	સંરચના sshbuf *tosign = ખાલી;
	અચલ અક્ષર *sign_alg = ખાલી;

	જો ((tosign = sshbuf_new()) == ખાલી ||
	    (blob = sshbuf_new()) == ખાલી) {
		error_f("sshbuf_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		જાઓ done;
	}

	જો ((r = sshbuf_put(tosign, MAGIC_PREAMBLE, MAGIC_PREAMBLE_LEN)) != 0 ||
	    (r = sshbuf_put_cstring(tosign, sig_namespace)) != 0 ||
	    (r = sshbuf_put_string(tosign, ખાલી, 0)) != 0 || /* reserved */
	    (r = sshbuf_put_cstring(tosign, hashalg)) != 0 ||
	    (r = sshbuf_put_stringb(tosign, h_message)) != 0) {
		error_fr(r, "assemble message to sign");
		જાઓ done;
	}

	/* If using RSA keys then default to a good signature algorithm */
	જો (sshkey_type_plain(ચાવી->type) == ચાવી_RSA) {
		sign_alg = RSA_SIGN_ALG;
		જો (strcmp(hashalg, "sha256") == 0)
			sign_alg = "rsa-sha2-256";
		નહીંતર જો (strcmp(hashalg, "sha512") == 0)
			sign_alg = "rsa-sha2-512";
	}

	જો (signer != ખાલી) {
		જો ((r = signer(ચાવી, &sig, &slen,
		    sshbuf_ptr(tosign), sshbuf_len(tosign),
		    sign_alg, sk_provider, sk_pin, 0, signer_ctx)) != 0) {
			error_r(r, "Couldn't sign message (signer)");
			જાઓ done;
		}
	} નહીંતર {
		જો ((r = sshkey_sign(ચાવી, &sig, &slen,
		    sshbuf_ptr(tosign), sshbuf_len(tosign),
		    sign_alg, sk_provider, sk_pin, 0)) != 0) {
			error_r(r, "Couldn't sign message");
			જાઓ done;
		}
	}

	જો ((r = sshbuf_put(blob, MAGIC_PREAMBLE, MAGIC_PREAMBLE_LEN)) != 0 ||
	    (r = sshbuf_put_u32(blob, SIG_VERSION)) != 0 ||
	    (r = sshkey_puts(ચાવી, blob)) != 0 ||
	    (r = sshbuf_put_cstring(blob, sig_namespace)) != 0 ||
	    (r = sshbuf_put_string(blob, ખાલી, 0)) != 0 || /* reserved */
	    (r = sshbuf_put_cstring(blob, hashalg)) != 0 ||
	    (r = sshbuf_put_string(blob, sig, slen)) != 0) {
		error_fr(r, "assemble signature object");
		જાઓ done;
	}

	જો (out != ખાલી) {
		*out = blob;
		blob = ખાલી;
	}
	r = 0;
done:
	મુક્ત(sig);
	sshbuf_free(blob);
	sshbuf_free(tosign);
	પાછા r;
}

/* Check preamble and version. */
સ્થિર પૂર્ણાંક
sshsig_parse_preamble(સંરચના sshbuf *buf)
{
	પૂર્ણાંક r = SSH_ERR_INTERNAL_ERROR;
	uint32_t sversion;

	જો ((r = sshbuf_cmp(buf, 0, MAGIC_PREAMBLE, MAGIC_PREAMBLE_LEN)) != 0 ||
	    (r = sshbuf_consume(buf, (કદ(MAGIC_PREAMBLE)-1))) != 0 ||
	    (r = sshbuf_get_u32(buf, &sversion)) != 0) {
		error("Couldn't verify signature: invalid format");
		પાછા r;
	}

	જો (sversion > SIG_VERSION) {
		error("Signature version %lu is larger than supported "
		    "version %u", (unsigned long)sversion, SIG_VERSION);
		પાછા SSH_ERR_INVALID_FORMAT;
	}
	પાછા 0;
}

સ્થિર પૂર્ણાંક
sshsig_check_hashalg(અચલ અક્ષર *hashalg)
{
	જો (hashalg == ખાલી ||
	    match_pattern_list(hashalg, HASHALG_ALLOWED, 0) == 1)
		પાછા 0;
	error_f("unsupported hash algorithm \"%.100s\"", hashalg);
	પાછા SSH_ERR_SIGN_ALG_UNSUPPORTED;
}

સ્થિર પૂર્ણાંક
sshsig_peek_hashalg(સંરચના sshbuf *signature, અક્ષર **hashalgp)
{
	સંરચના sshbuf *buf = ખાલી;
	અક્ષર *hashalg = ખાલી;
	પૂર્ણાંક r = SSH_ERR_INTERNAL_ERROR;

	જો (hashalgp != ખાલી)
		*hashalgp = ખાલી;
	જો ((buf = sshbuf_fromb(signature)) == ખાલી)
		પાછા SSH_ERR_ALLOC_FAIL;
	જો ((r = sshsig_parse_preamble(buf)) != 0)
		જાઓ done;
	જો ((r = sshbuf_get_string_direct(buf, ખાલી, ખાલી)) != 0 ||
	    (r = sshbuf_get_string_direct(buf, ખાલી, ખાલી)) != 0 ||
	    (r = sshbuf_get_string(buf, ખાલી, ખાલી)) != 0 ||
	    (r = sshbuf_get_cstring(buf, &hashalg, ખાલી)) != 0 ||
	    (r = sshbuf_get_string_direct(buf, ખાલી, ખાલી)) != 0) {
		error_fr(r, "parse signature object");
		જાઓ done;
	}

	/* success */
	r = 0;
	*hashalgp = hashalg;
	hashalg = ખાલી;
 done:
	મુક્ત(hashalg);
	sshbuf_free(buf);
	પાછા r;
}

સ્થિર પૂર્ણાંક
sshsig_wrap_verify(સંરચના sshbuf *signature, અચલ અક્ષર *hashalg,
    અચલ સંરચના sshbuf *h_message, અચલ અક્ષર *expect_namespace,
    સંરચના sshkey **sign_keyp, સંરચના sshkey_sig_details **sig_details)
{
	પૂર્ણાંક r = SSH_ERR_INTERNAL_ERROR;
	સંરચના sshbuf *buf = ખાલી, *toverify = ખાલી;
	સંરચના sshkey *ચાવી = ખાલી;
	અચલ u_char *sig;
	અક્ષર *got_namespace = ખાલી, *sigtype = ખાલી, *sig_hashalg = ખાલી;
	size_t siglen;

	debug_f("verify message length %zu", sshbuf_len(h_message));
	જો (sig_details != ખાલી)
		*sig_details = ખાલી;
	જો (sign_keyp != ખાલી)
		*sign_keyp = ખાલી;

	જો ((toverify = sshbuf_new()) == ખાલી) {
		error_f("sshbuf_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		જાઓ done;
	}
	જો ((r = sshbuf_put(toverify, MAGIC_PREAMBLE,
	    MAGIC_PREAMBLE_LEN)) != 0 ||
	    (r = sshbuf_put_cstring(toverify, expect_namespace)) != 0 ||
	    (r = sshbuf_put_string(toverify, ખાલી, 0)) != 0 || /* reserved */
	    (r = sshbuf_put_cstring(toverify, hashalg)) != 0 ||
	    (r = sshbuf_put_stringb(toverify, h_message)) != 0) {
		error_fr(r, "assemble message to verify");
		જાઓ done;
	}

	જો ((r = sshsig_parse_preamble(signature)) != 0)
		જાઓ done;

	જો ((r = sshkey_froms(signature, &ચાવી)) != 0 ||
	    (r = sshbuf_get_cstring(signature, &got_namespace, ખાલી)) != 0 ||
	    (r = sshbuf_get_string(signature, ખાલી, ખાલી)) != 0 ||
	    (r = sshbuf_get_cstring(signature, &sig_hashalg, ખાલી)) != 0 ||
	    (r = sshbuf_get_string_direct(signature, &sig, &siglen)) != 0) {
		error_fr(r, "parse signature object");
		જાઓ done;
	}

	જો (sshbuf_len(signature) != 0) {
		error("Signature contains trailing data");
		r = SSH_ERR_INVALID_FORMAT;
		જાઓ done;
	}

	જો (strcmp(expect_namespace, got_namespace) != 0) {
		error("Couldn't verify signature: namespace does not match");
		debug_f("expected namespace \"%s\" received \"%s\"",
		    expect_namespace, got_namespace);
		r = SSH_ERR_SIGNATURE_INVALID;
		જાઓ done;
	}
	જો (strcmp(hashalg, sig_hashalg) != 0) {
		error("Couldn't verify signature: hash algorithm mismatch");
		debug_f("expected algorithm \"%s\" received \"%s\"",
		    hashalg, sig_hashalg);
		r = SSH_ERR_SIGNATURE_INVALID;
		જાઓ done;
	}
	/* Ensure that RSA keys use an acceptable signature algorithm */
	જો (sshkey_type_plain(ચાવી->type) == ચાવી_RSA) {
		જો ((r = sshkey_get_sigtype(sig, siglen, &sigtype)) != 0) {
			error_r(r, "Couldn't verify signature: unable to get "
			    "signature type");
			જાઓ done;
		}
		જો (match_pattern_list(sigtype, RSA_SIGN_ALLOWED, 0) != 1) {
			error("Couldn't verify signature: unsupported RSA "
			    "signature algorithm %s", sigtype);
			r = SSH_ERR_SIGN_ALG_UNSUPPORTED;
			જાઓ done;
		}
	}
	જો ((r = sshkey_verify(ચાવી, sig, siglen, sshbuf_ptr(toverify),
	    sshbuf_len(toverify), ખાલી, 0, sig_details)) != 0) {
		error_r(r, "Signature verification failed");
		જાઓ done;
	}

	/* success */
	r = 0;
	જો (sign_keyp != ખાલી) {
		*sign_keyp = ચાવી;
		ચાવી = ખાલી; /* transferred */
	}
done:
	મુક્ત(got_namespace);
	મુક્ત(sigtype);
	મુક્ત(sig_hashalg);
	sshbuf_free(buf);
	sshbuf_free(toverify);
	sshkey_free(ચાવી);
	પાછા r;
}

સ્થિર પૂર્ણાંક
hash_buffer(અચલ સંરચના sshbuf *m, અચલ અક્ષર *hashalg, સંરચના sshbuf **bp)
{
	અક્ષર *hex, hash[SSH_DIGEST_MAX_LENGTH];
	પૂર્ણાંક alg, r = SSH_ERR_INTERNAL_ERROR;
	સંરચના sshbuf *b = ખાલી;

	*bp = ખાલી;
	memset(hash, 0, કદ(hash));

	જો ((r = sshsig_check_hashalg(hashalg)) != 0)
		પાછા r;
	જો ((alg = ssh_digest_alg_by_name(hashalg)) == -1) {
		error_f("can't look up hash algorithm %s", hashalg);
		પાછા SSH_ERR_INTERNAL_ERROR;
	}
	જો ((r = ssh_digest_buffer(alg, m, hash, કદ(hash))) != 0) {
		error_fr(r, "ssh_digest_buffer");
		પાછા r;
	}
	જો ((hex = tohex(hash, ssh_digest_bytes(alg))) != ખાલી) {
		debug3_f("final hash: %s", hex);
		freezero(hex, strlen(hex));
	}
	જો ((b = sshbuf_new()) == ખાલી) {
		r = SSH_ERR_ALLOC_FAIL;
		જાઓ out;
	}
	જો ((r = sshbuf_put(b, hash, ssh_digest_bytes(alg))) != 0) {
		error_fr(r, "sshbuf_put");
		જાઓ out;
	}
	*bp = b;
	b = ખાલી; /* transferred */
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	explicit_bzero(hash, કદ(hash));
	પાછા r;
}

પૂર્ણાંક
sshsig_signb(સંરચના sshkey *ચાવી, અચલ અક્ષર *hashalg,
    અચલ અક્ષર *sk_provider, અચલ અક્ષર *sk_pin,
    અચલ સંરચના sshbuf *message, અચલ અક્ષર *sig_namespace,
    સંરચના sshbuf **out, sshsig_signer *signer, શૂન્ય *signer_ctx)
{
	સંરચના sshbuf *b = ખાલી;
	પૂર્ણાંક r = SSH_ERR_INTERNAL_ERROR;

	જો (hashalg == ખાલી)
		hashalg = HASHALG_DEFAULT;
	જો (out != ખાલી)
		*out = ખાલી;
	જો ((r = hash_buffer(message, hashalg, &b)) != 0) {
		error_fr(r, "hash buffer");
		જાઓ out;
	}
	જો ((r = sshsig_wrap_sign(ચાવી, hashalg, sk_provider, sk_pin, b,
	    sig_namespace, out, signer, signer_ctx)) != 0)
		જાઓ out;
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	પાછા r;
}

પૂર્ણાંક
sshsig_verifyb(સંરચના sshbuf *signature, અચલ સંરચના sshbuf *message,
    અચલ અક્ષર *expect_namespace, સંરચના sshkey **sign_keyp,
    સંરચના sshkey_sig_details **sig_details)
{
	સંરચના sshbuf *b = ખાલી;
	પૂર્ણાંક r = SSH_ERR_INTERNAL_ERROR;
	અક્ષર *hashalg = ખાલી;

	જો (sig_details != ખાલી)
		*sig_details = ખાલી;
	જો (sign_keyp != ખાલી)
		*sign_keyp = ખાલી;
	જો ((r = sshsig_peek_hashalg(signature, &hashalg)) != 0)
		પાછા r;
	debug_f("signature made with hash \"%s\"", hashalg);
	જો ((r = hash_buffer(message, hashalg, &b)) != 0) {
		error_fr(r, "hash buffer");
		જાઓ out;
	}
	જો ((r = sshsig_wrap_verify(signature, hashalg, b, expect_namespace,
	    sign_keyp, sig_details)) != 0)
		જાઓ out;
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	મુક્ત(hashalg);
	પાછા r;
}

સ્થિર પૂર્ણાંક
hash_file(પૂર્ણાંક fd, અચલ અક્ષર *hashalg, સંરચના sshbuf **bp)
{
	અક્ષર *hex, rbuf[8192], hash[SSH_DIGEST_MAX_LENGTH];
	ssize_t n, total = 0;
	સંરચના ssh_digest_ctx *ctx = ખાલી;
	પૂર્ણાંક alg, oerrno, r = SSH_ERR_INTERNAL_ERROR;
	સંરચના sshbuf *b = ખાલી;

	*bp = ખાલી;
	memset(hash, 0, કદ(hash));

	જો ((r = sshsig_check_hashalg(hashalg)) != 0)
		પાછા r;
	જો ((alg = ssh_digest_alg_by_name(hashalg)) == -1) {
		error_f("can't look up hash algorithm %s", hashalg);
		પાછા SSH_ERR_INTERNAL_ERROR;
	}
	જો ((ctx = ssh_digest_start(alg)) == ખાલી) {
		error_f("ssh_digest_start failed");
		પાછા SSH_ERR_INTERNAL_ERROR;
	}
	માટે (;;) {
		જો ((n = પઠ(fd, rbuf, કદ(rbuf))) == -1) {
			જો (errno == EINTR || errno == EAGAIN)
				ચાલુ;
			oerrno = errno;
			error_f("read: %s", strerror(errno));
			errno = oerrno;
			r = SSH_ERR_SYSTEM_ERROR;
			જાઓ out;
		} નહીંતર જો (n == 0) {
			debug2_f("hashed %zu bytes", total);
			તોડો; /* EOF */
		}
		total += (size_t)n;
		જો ((r = ssh_digest_update(ctx, rbuf, (size_t)n)) != 0) {
			error_fr(r, "ssh_digest_update");
			જાઓ out;
		}
	}
	જો ((r = ssh_digest_final(ctx, hash, કદ(hash))) != 0) {
		error_fr(r, "ssh_digest_final");
		જાઓ out;
	}
	જો ((hex = tohex(hash, ssh_digest_bytes(alg))) != ખાલી) {
		debug3_f("final hash: %s", hex);
		freezero(hex, strlen(hex));
	}
	જો ((b = sshbuf_new()) == ખાલી) {
		r = SSH_ERR_ALLOC_FAIL;
		જાઓ out;
	}
	જો ((r = sshbuf_put(b, hash, ssh_digest_bytes(alg))) != 0) {
		error_fr(r, "sshbuf_put");
		જાઓ out;
	}
	*bp = b;
	b = ખાલી; /* transferred */
	/* success */
	r = 0;
 out:
	oerrno = errno;
	sshbuf_free(b);
	ssh_digest_free(ctx);
	explicit_bzero(hash, કદ(hash));
	errno = oerrno;
	પાછા r;
}

પૂર્ણાંક
sshsig_sign_fd(સંરચના sshkey *ચાવી, અચલ અક્ષર *hashalg,
    અચલ અક્ષર *sk_provider, અચલ અક્ષર *sk_pin,
    પૂર્ણાંક fd, અચલ અક્ષર *sig_namespace, સંરચના sshbuf **out,
    sshsig_signer *signer, શૂન્ય *signer_ctx)
{
	સંરચના sshbuf *b = ખાલી;
	પૂર્ણાંક r = SSH_ERR_INTERNAL_ERROR;

	જો (hashalg == ખાલી)
		hashalg = HASHALG_DEFAULT;
	જો (out != ખાલી)
		*out = ખાલી;
	જો ((r = hash_file(fd, hashalg, &b)) != 0) {
		error_fr(r, "hash_file");
		પાછા r;
	}
	જો ((r = sshsig_wrap_sign(ચાવી, hashalg, sk_provider, sk_pin, b,
	    sig_namespace, out, signer, signer_ctx)) != 0)
		જાઓ out;
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	પાછા r;
}

પૂર્ણાંક
sshsig_verify_fd(સંરચના sshbuf *signature, પૂર્ણાંક fd,
    અચલ અક્ષર *expect_namespace, સંરચના sshkey **sign_keyp,
    સંરચના sshkey_sig_details **sig_details)
{
	સંરચના sshbuf *b = ખાલી;
	પૂર્ણાંક r = SSH_ERR_INTERNAL_ERROR;
	અક્ષર *hashalg = ખાલી;

	જો (sig_details != ખાલી)
		*sig_details = ખાલી;
	જો (sign_keyp != ખાલી)
		*sign_keyp = ખાલી;
	જો ((r = sshsig_peek_hashalg(signature, &hashalg)) != 0)
		પાછા r;
	debug_f("signature made with hash \"%s\"", hashalg);
	જો ((r = hash_file(fd, hashalg, &b)) != 0) {
		error_fr(r, "hash_file");
		જાઓ out;
	}
	જો ((r = sshsig_wrap_verify(signature, hashalg, b, expect_namespace,
	    sign_keyp, sig_details)) != 0)
		જાઓ out;
	/* success */
	r = 0;
 out:
	sshbuf_free(b);
	મુક્ત(hashalg);
	પાછા r;
}

સંરચના sshsigopt {
	પૂર્ણાંક ca;
	અક્ષર *namespaces;
	uint64_t valid_after, valid_before;
};

સંરચના sshsigopt *
sshsigopt_parse(અચલ અક્ષર *opts, અચલ અક્ષર *path, u_long linenum,
    અચલ અક્ષર **errstrp)
{
	સંરચના sshsigopt *ret;
	પૂર્ણાંક r;
	અક્ષર *opt;
	અચલ અક્ષર *errstr = ખાલી;

	જો ((ret = calloc(1, કદ(*ret))) == ખાલી)
		પાછા ખાલી;
	જો (opts == ખાલી || *opts == '\0')
		પાછા ret; /* Empty options yields empty options :) */

	જ્યારે (*opts && *opts != ' ' && *opts != '\t') {
		/* flag options */
		જો ((r = opt_flag("cert-authority", 0, &opts)) != -1) {
			ret->ca = 1;
		} નહીંતર જો (opt_match(&opts, "namespaces")) {
			જો (ret->namespaces != ખાલી) {
				errstr = "multiple \"namespaces\" clauses";
				જાઓ fail;
			}
			ret->namespaces = opt_dequote(&opts, &errstr);
			જો (ret->namespaces == ખાલી)
				જાઓ fail;
		} નહીંતર જો (opt_match(&opts, "valid-after")) {
			જો (ret->valid_after != 0) {
				errstr = "multiple \"valid-after\" clauses";
				જાઓ fail;
			}
			જો ((opt = opt_dequote(&opts, &errstr)) == ખાલી)
				જાઓ fail;
			જો (parse_absolute_time(opt, &ret->valid_after) != 0 ||
			    ret->valid_after == 0) {
				મુક્ત(opt);
				errstr = "invalid \"valid-after\" time";
				જાઓ fail;
			}
			મુક્ત(opt);
		} નહીંતર જો (opt_match(&opts, "valid-before")) {
			જો (ret->valid_before != 0) {
				errstr = "multiple \"valid-before\" clauses";
				જાઓ fail;
			}
			જો ((opt = opt_dequote(&opts, &errstr)) == ખાલી)
				જાઓ fail;
			જો (parse_absolute_time(opt, &ret->valid_before) != 0 ||
			    ret->valid_before == 0) {
				મુક્ત(opt);
				errstr = "invalid \"valid-before\" time";
				જાઓ fail;
			}
			મુક્ત(opt);
		}
		/*
		 * Skip the comma, and move to the next option
		 * (or break out if there are no more).
		 */
		જો (*opts == '\0' || *opts == ' ' || *opts == '\t')
			તોડો;		/* End of options. */
		/* Anything other than a comma is an unknown option */
		જો (*opts != ',') {
			errstr = "unknown key option";
			જાઓ fail;
		}
		opts++;
		જો (*opts == '\0') {
			errstr = "unexpected end-of-options";
			જાઓ fail;
		}
	}
	/* final consistency check */
	જો (ret->valid_after != 0 && ret->valid_before != 0 &&
	    ret->valid_before <= ret->valid_after) {
		errstr = "\"valid-before\" time is before \"valid-after\"";
		જાઓ fail;
	}
	/* success */
	પાછા ret;
 fail:
	જો (errstrp != ખાલી)
		*errstrp = errstr;
	sshsigopt_free(ret);
	પાછા ખાલી;
}

શૂન્ય
sshsigopt_free(સંરચના sshsigopt *opts)
{
	જો (opts == ખાલી)
		પાછા;
	મુક્ત(opts->namespaces);
	મુક્ત(opts);
}

સ્થિર પૂર્ણાંક
parse_principals_ચાવી_and_options(અચલ અક્ષર *path, u_long linenum, અક્ષર *લીટી,
    અચલ અક્ષર *required_principal, અક્ષર **principalsp, સંરચના sshkey **keyp,
    સંરચના sshsigopt **sigoptsp)
{
	અક્ષર *opts = ખાલી, *tmp, *cp, *principals = ખાલી;
	અચલ અક્ષર *reason = ખાલી;
	સંરચના sshsigopt *sigopts = ખાલી;
	સંરચના sshkey *ચાવી = ખાલી;
	પૂર્ણાંક r = SSH_ERR_INTERNAL_ERROR;

	જો (principalsp != ખાલી)
		*principalsp = ખાલી;
	જો (sigoptsp != ખાલી)
		*sigoptsp = ખાલી;
	જો (keyp != ખાલી)
		*keyp = ખાલી;

	cp = લીટી;
	cp = cp + strspn(cp, " \t\n\r"); /* skip leading whitespace */
	જો (*cp == '#' || *cp == '\0')
		પાછા SSH_ERR_ચાવી_NOT_FOUND; /* blank or all-comment line */

	/* format: identity[,identity...] [option[,option...]] key */
	જો ((tmp = strdelimw(&cp)) == ખાલી || cp == ખાલી) {
		error("%s:%lu: invalid line", path, linenum);
		r = SSH_ERR_INVALID_FORMAT;
		જાઓ out;
	}
	જો ((principals = strdup(tmp)) == ખાલી) {
		error_f("strdup failed");
		r = SSH_ERR_ALLOC_FAIL;
		જાઓ out;
	}
	/*
	 * Bail out early if we're looking for a particular principal and this
	 * line does not list it.
	 */
	જો (required_principal != ખાલી) {
		જો (match_pattern_list(required_principal,
		    principals, 0) != 1) {
			/* principal didn't match */
			r = SSH_ERR_ચાવી_NOT_FOUND;
			જાઓ out;
		}
		debug_f("%s:%lu: matched principal \"%s\"",
		    path, linenum, required_principal);
	}

	જો ((ચાવી = sshkey_new(ચાવી_UNSPEC)) == ખાલી) {
		error_f("sshkey_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		જાઓ out;
	}
	જો (sshkey_read(ચાવી, &cp) != 0) {
		/* no key? Check for options */
		opts = cp;
		જો (sshkey_advance_past_options(&cp) != 0) {
			error("%s:%lu: invalid options", path, linenum);
			r = SSH_ERR_INVALID_FORMAT;
			જાઓ out;
		}
		જો (cp == ખાલી || *cp == '\0') {
			error("%s:%lu: missing key", path, linenum);
			r = SSH_ERR_INVALID_FORMAT;
			જાઓ out;
		}
		*cp++ = '\0';
		skip_space(&cp);
		જો (sshkey_read(ચાવી, &cp) != 0) {
			error("%s:%lu: invalid key", path, linenum);
			r = SSH_ERR_INVALID_FORMAT;
			જાઓ out;
		}
	}
	debug3("%s:%lu: options %s", path, linenum, opts == ખાલી ? "" : opts);
	જો ((sigopts = sshsigopt_parse(opts, path, linenum, &reason)) == ખાલી) {
		error("%s:%lu: bad options: %s", path, linenum, reason);
		r = SSH_ERR_INVALID_FORMAT;
		જાઓ out;
	}
	/* success */
	જો (principalsp != ખાલી) {
		*principalsp = principals;
		principals = ખાલી; /* transferred */
	}
	જો (sigoptsp != ખાલી) {
		*sigoptsp = sigopts;
		sigopts = ખાલી; /* transferred */
	}
	જો (keyp != ખાલી) {
		*keyp = ચાવી;
		ચાવી = ખાલી; /* transferred */
	}
	r = 0;
 out:
	મુક્ત(principals);
	sshsigopt_free(sigopts);
	sshkey_free(ચાવી);
	પાછા r;
}

સ્થિર પૂર્ણાંક
cert_filter_principals(અચલ અક્ષર *path, u_long linenum,
    અક્ષર **principalsp, અચલ સંરચના sshkey *cert, uint64_t verify_time)
{
	અક્ષર *cp, *oprincipals, *principals;
	અચલ અક્ષર *reason;
	સંરચના sshbuf *nprincipals;
	પૂર્ણાંક r = SSH_ERR_INTERNAL_ERROR, success = 0;
	u_int i;

	oprincipals = principals = *principalsp;
	*principalsp = ખાલી;

	જો ((nprincipals = sshbuf_new()) == ખાલી) {
		r = SSH_ERR_ALLOC_FAIL;
		જાઓ out;
	}

	જ્યારે ((cp = strsep(&principals, ",")) != ખાલી && *cp != '\0') {
		/* Check certificate validity */
		જો ((r = sshkey_cert_check_authority(cert, 0, 0, verify_time,
		    ખાલી, &reason)) != 0) {
			debug("%s:%lu: principal \"%s\" not authorized: %s",
			    path, linenum, cp, reason);
			ચાલુ;
		}
		/* Return all matching principal names from the cert */
		માટે (i = 0; i < cert->cert->nprincipals; i++) {
			જો (match_pattern(cert->cert->principals[i], cp)) {
				જો ((r = sshbuf_putf(nprincipals, "%s%s",
					sshbuf_len(nprincipals) != 0 ? "," : "",
						cert->cert->principals[i])) != 0) {
					error_f("buffer error");
					જાઓ out;
				}
			}
		}
	}
	જો (sshbuf_len(nprincipals) == 0) {
		error("%s:%lu: no valid principals found", path, linenum);
		r = SSH_ERR_ચાવી_CERT_INVALID;
		જાઓ out;
	}
	જો ((principals = sshbuf_dup_string(nprincipals)) == ખાલી) {
		error_f("buffer error");
		r = SSH_ERR_ALLOC_FAIL;
		જાઓ out;
	}
	/* success */
	success = 1;
	*principalsp = principals;
 out:
	sshbuf_free(nprincipals);
	મુક્ત(oprincipals);
	પાછા success ? 0 : r;
}

સ્થિર પૂર્ણાંક
check_allowed_ચાવીઓ_લીટી(અચલ અક્ષર *path, u_long linenum, અક્ષર *લીટી,
    અચલ સંરચના sshkey *sign_ચાવી, અચલ અક્ષર *principal,
    અચલ અક્ષર *sig_namespace, uint64_t verify_time, અક્ષર **principalsp)
{
	સંરચના sshkey *found_ચાવી = ખાલી;
	અક્ષર *principals = ખાલી;
	પૂર્ણાંક r, success = 0;
	અચલ અક્ષર *reason = ખાલી;
	સંરચના sshsigopt *sigopts = ખાલી;
	અક્ષર tvalid[64], tverify[64];

	જો (principalsp != ખાલી)
		*principalsp = ખાલી;

	/* Parse the line */
	જો ((r = parse_principals_ચાવી_and_options(path, linenum, લીટી,
	    principal, &principals, &found_ચાવી, &sigopts)) != 0) {
		/* error already logged */
		જાઓ done;
	}

	જો (!sigopts->ca && sshkey_equal(found_ચાવી, sign_ચાવી)) {
		/* Exact match of key */
		debug("%s:%lu: matched key", path, linenum);
	} નહીંતર જો (sigopts->ca && sshkey_is_cert(sign_ચાવી) &&
	    sshkey_equal_public(sign_ચાવી->cert->signature_ચાવી, found_ચાવી)) {
		જો (principal) {
			/* Match certificate CA key with specified principal */
			જો ((r = sshkey_cert_check_authority(sign_ચાવી, 0, 0,
			    verify_time, principal, &reason)) != 0) {
				error("%s:%lu: certificate not authorized: %s",
				    path, linenum, reason);
				જાઓ done;
			}
			debug("%s:%lu: matched certificate CA key",
			    path, linenum);
		} નહીંતર {
			/* No principal specified - find all matching ones */
			જો ((r = cert_filter_principals(path, linenum,
			    &principals, sign_ચાવી, verify_time)) != 0) {
				/* error already displayed */
				debug_r(r, "%s:%lu: cert_filter_principals",
				    path, linenum);
				જાઓ done;
			}
			debug("%s:%lu: matched certificate CA key",
			    path, linenum);
		}
	} નહીંતર {
		/* Didn't match key */
		જાઓ done;
	}

	/* Check whether options preclude the use of this key */
	જો (sigopts->namespaces != ખાલી && sig_namespace != ખાલી &&
	    match_pattern_list(sig_namespace, sigopts->namespaces, 0) != 1) {
		error("%s:%lu: key is not permitted for use in signature "
		    "namespace \"%s\"", path, linenum, sig_namespace);
		જાઓ done;
	}

	/* check key time validity */
	format_absolute_time((uint64_t)verify_time, tverify, કદ(tverify));
	જો (sigopts->valid_after != 0 &&
	    (uint64_t)verify_time < sigopts->valid_after) {
		format_absolute_time(sigopts->valid_after,
		    tvalid, કદ(tvalid));
		error("%s:%lu: key is not yet valid: "
		    "verify time %s < valid-after %s", path, linenum,
		    tverify, tvalid);
		જાઓ done;
	}
	જો (sigopts->valid_before != 0 &&
	    (uint64_t)verify_time > sigopts->valid_before) {
		format_absolute_time(sigopts->valid_before,
		    tvalid, કદ(tvalid));
		error("%s:%lu: key has expired: "
		    "verify time %s > valid-before %s", path, linenum,
		    tverify, tvalid);
		જાઓ done;
	}
	success = 1;

 done:
	જો (success && principalsp != ખાલી) {
		*principalsp = principals;
		principals = ખાલી; /* transferred */
	}
	મુક્ત(principals);
	sshkey_free(found_ચાવી);
	sshsigopt_free(sigopts);
	પાછા success ? 0 : SSH_ERR_ચાવી_NOT_FOUND;
}

પૂર્ણાંક
sshsig_check_allowed_ચાવીઓ(અચલ અક્ષર *path, અચલ સંરચના sshkey *sign_ચાવી,
    અચલ અક્ષર *principal, અચલ અક્ષર *sig_namespace, uint64_t verify_time)
{
	FILE *f = ખાલી;
	અક્ષર *લીટી = ખાલી;
	size_t linesize = 0;
	u_long linenum = 0;
	પૂર્ણાંક r = SSH_ERR_ચાવી_NOT_FOUND, oerrno;

	/* Check key and principal against file */
	જો ((f = fopen(path, "r")) == ખાલી) {
		oerrno = errno;
		error("Unable to open allowed keys file \"%s\": %s",
		    path, strerror(errno));
		errno = oerrno;
		પાછા SSH_ERR_SYSTEM_ERROR;
	}

	જ્યારે (getline(&લીટી, &linesize, f) != -1) {
		linenum++;
		r = check_allowed_ચાવીઓ_લીટી(path, linenum, લીટી, sign_ચાવી,
		    principal, sig_namespace, verify_time, ખાલી);
		મુક્ત(લીટી);
		લીટી = ખાલી;
		linesize = 0;
		જો (r == SSH_ERR_ચાવી_NOT_FOUND)
			ચાલુ;
		નહીંતર જો (r == 0) {
			/* success */
			fclose(f);
			પાછા 0;
		} નહીંતર
			તોડો;
	}
	/* Either we hit an error parsing or we simply didn't find the key */
	fclose(f);
	મુક્ત(લીટી);
	પાછા r;
}

પૂર્ણાંક
sshsig_find_principals(અચલ અક્ષર *path, અચલ સંરચના sshkey *sign_ચાવી,
    uint64_t verify_time, અક્ષર **principals)
{
	FILE *f = ખાલી;
	અક્ષર *લીટી = ખાલી;
	size_t linesize = 0;
	u_long linenum = 0;
	પૂર્ણાંક r = SSH_ERR_ચાવી_NOT_FOUND, oerrno;

	જો ((f = fopen(path, "r")) == ખાલી) {
		oerrno = errno;
		error("Unable to open allowed keys file \"%s\": %s",
		    path, strerror(errno));
		errno = oerrno;
		પાછા SSH_ERR_SYSTEM_ERROR;
	}

	જ્યારે (getline(&લીટી, &linesize, f) != -1) {
		linenum++;
		r = check_allowed_ચાવીઓ_લીટી(path, linenum, લીટી,
		    sign_ચાવી, ખાલી, ખાલી, verify_time, principals);
		મુક્ત(લીટી);
		લીટી = ખાલી;
		linesize = 0;
		જો (r == SSH_ERR_ચાવી_NOT_FOUND)
			ચાલુ;
		નહીંતર જો (r == 0) {
			/* success */
			fclose(f);
			પાછા 0;
		} નહીંતર
			તોડો;
	}
	મુક્ત(લીટી);
	/* Either we hit an error parsing or we simply didn't find the key */
	જો (ferror(f) != 0) {
		oerrno = errno;
		fclose(f);
		error("Unable to read allowed keys file \"%s\": %s",
		    path, strerror(errno));
		errno = oerrno;
		પાછા SSH_ERR_SYSTEM_ERROR;
	}
	fclose(f);
	પાછા r;
}

પૂર્ણાંક
sshsig_match_principals(અચલ અક્ષર *path, અચલ અક્ષર *principal,
    અક્ષર ***principalsp, size_t *nprincipalsp)
{
	FILE *f = ખાલી;
	અક્ષર *found, *લીટી = ખાલી, **principals = ખાલી, **tmp;
	size_t i, nprincipals = 0, linesize = 0;
	u_long linenum = 0;
	પૂર્ણાંક oerrno = 0, r, ret = 0;

	જો (principalsp != ખાલી)
		*principalsp = ખાલી;
	જો (nprincipalsp != ખાલી)
		*nprincipalsp = 0;

	/* Check key and principal against file */
	જો ((f = fopen(path, "r")) == ખાલી) {
		oerrno = errno;
		error("Unable to open allowed keys file \"%s\": %s",
		    path, strerror(errno));
		errno = oerrno;
		પાછા SSH_ERR_SYSTEM_ERROR;
	}

	જ્યારે (getline(&લીટી, &linesize, f) != -1) {
		linenum++;
		/* Parse the line */
		જો ((r = parse_principals_ચાવી_and_options(path, linenum, લીટી,
		    principal, &found, ખાલી, ખાલી)) != 0) {
			જો (r == SSH_ERR_ચાવી_NOT_FOUND)
				ચાલુ;
			ret = r;
			oerrno = errno;
			તોડો; /* unexpected error */
		}
		જો ((tmp = recallocarray(principals, nprincipals,
		    nprincipals + 1, કદ(*principals))) == ખાલી) {
			ret = SSH_ERR_ALLOC_FAIL;
			મુક્ત(found);
			તોડો;
		}
		principals = tmp;
		principals[nprincipals++] = found; /* transferred */
		મુક્ત(લીટી);
		લીટી = ખાલી;
		linesize = 0;
	}
	fclose(f);
	મુક્ત(લીટી);

	જો (ret == 0) {
		જો (nprincipals == 0)
			ret = SSH_ERR_ચાવી_NOT_FOUND;
		જો (nprincipalsp != ખાલી)
			*nprincipalsp = nprincipals;
		જો (principalsp != ખાલી) {
			*principalsp = principals;
			principals = ખાલી; /* transferred */
			nprincipals = 0;
		}
	}

	માટે (i = 0; i < nprincipals; i++)
		મુક્ત(principals[i]);
	મુક્ત(principals);

	errno = oerrno;
	પાછા ret;
}

પૂર્ણાંક
sshsig_get_pubkey(સંરચના sshbuf *signature, સંરચના sshkey **pubkey)
{
	સંરચના sshkey *pk = ખાલી;
	પૂર્ણાંક r = SSH_ERR_SIGNATURE_INVALID;

	જો (pubkey == ખાલી)
		પાછા SSH_ERR_INTERNAL_ERROR;
	જો ((r = sshsig_parse_preamble(signature)) != 0)
		પાછા r;
	જો ((r = sshkey_froms(signature, &pk)) != 0)
		પાછા r;

	*pubkey = pk;
	pk = ખાલી;
	પાછા 0;
}
