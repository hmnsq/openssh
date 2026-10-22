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

#అన్తర్భావ "includes.h"

#అన్తర్భావ <stdio.h>
#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <stdarg.h>
#అన్తర్భావ <errno.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <unistd.h>

#అన్తర్భావ "authfd.h"
#అన్తర్భావ "authfile.h"
#అన్తర్భావ "log.h"
#అన్తర్భావ "misc.h"
#అన్తర్భావ "sshbuf.h"
#అన్తర్భావ "sshsig.h"
#అన్తర్భావ "ssherr.h"
#అన్తర్భావ "sshkey.h"
#అన్తర్భావ "match.h"
#అన్తర్భావ "digest.h"

#నిర్వచించు SIG_సంస్కరణ		0x01
#నిర్వచించు MAGIC_PREAMBLE		"SSHSIG"
#నిర్వచించు MAGIC_PREAMBLE_LEN	(పరిమాణం(MAGIC_PREAMBLE) - 1)
#నిర్వచించు BEGIN_SIGNATURE		"-----BEGIN SSH SIGNATURE-----"
#నిర్వచించు చివర_SIGNATURE		"-----END SSH SIGNATURE-----"
#నిర్వచించు RSA_SIGN_ALG		"rsa-sha2-512"
#నిర్వచించు RSA_SIGN_ALLOWED	"rsa-sha2-512,rsa-sha2-256"
#నిర్వచించు HASHALG_DEFAULT		"sha512"
#నిర్వచించు HASHALG_ALLOWED		"sha256,sha512"

పూర్ణాంకం
sshsig_armor(స్థిరరాశి నిర్మాణం sshbuf *blob, నిర్మాణం sshbuf **బహిర్గతం)
{
	నిర్మాణం sshbuf *buf = ఖాళీ;
	పూర్ణాంకం r = SSH_ERR_అంతర్గత_ERROR;

	*బహిర్గతం = ఖాళీ;

	ఒకవేళ ((buf = sshbuf_new()) == ఖాళీ) {
		error_f("sshbuf_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		వెళ్ళు బహిర్గతం;
	}

	ఒకవేళ ((r = sshbuf_putf(buf, "%s\n", BEGIN_SIGNATURE)) != 0) {
		error_fr(r, "sshbuf_putf");
		వెళ్ళు బహిర్గతం;
	}

	ఒకవేళ ((r = sshbuf_dtob64(blob, buf, 1)) != 0) {
		error_fr(r, "base64 encode signature");
		వెళ్ళు బహిర్గతం;
	}

	ఒకవేళ ((r = sshbuf_put(buf, చివర_SIGNATURE,
	    పరిమాణం(చివర_SIGNATURE)-1)) != 0 ||
	    (r = sshbuf_put_u8(buf, '\n')) != 0) {
		error_fr(r, "sshbuf_put");
		వెళ్ళు బహిర్గతం;
	}
	/* success */
	*బహిర్గతం = buf;
	buf = ఖాళీ; /* transferred */
	r = 0;
 బహిర్గతం:
	sshbuf_free(buf);
	తిరిగి r;
}

పూర్ణాంకం
sshsig_dearmor(నిర్మాణం sshbuf *sig, నిర్మాణం sshbuf **బహిర్గతం)
{
	పూర్ణాంకం r;
	కొలత_t eoffset = 0;
	నిర్మాణం sshbuf *buf = ఖాళీ;
	నిర్మాణం sshbuf *sbuf = ఖాళీ;
	అక్షరం *b64 = ఖాళీ;

	ఒకవేళ ((sbuf = sshbuf_fromb(sig)) == ఖాళీ) {
		error_f("sshbuf_fromb failed");
		తిరిగి SSH_ERR_ALLOC_FAIL;
	}

	/* Expect and consume preamble + lf/crlf */
	ఒకవేళ ((r = sshbuf_cmp(sbuf, 0,
	    BEGIN_SIGNATURE, పరిమాణం(BEGIN_SIGNATURE)-1)) != 0) {
		error("Couldn't parse signature: missing header");
		వెళ్ళు పూర్తి;
	}
	ఒకవేళ ((r = sshbuf_consume(sbuf, పరిమాణం(BEGIN_SIGNATURE)-1)) != 0) {
		error_fr(r, "consume");
		వెళ్ళు పూర్తి;
	}
	ఒకవేళ ((r = sshbuf_cmp(sbuf, 0, "\r\n", 2)) == 0)
		eoffset = 2;
	లేకపోతే ఒకవేళ ((r = sshbuf_cmp(sbuf, 0, "\n", 1)) == 0)
		eoffset = 1;
	లేకపోతే {
		r = SSH_ERR_INVALID_FORMAT;
		error_f("no header eol");
		వెళ్ళు పూర్తి;
	}
	ఒకవేళ ((r = sshbuf_consume(sbuf, eoffset)) != 0) {
		error_fr(r, "consume eol");
		వెళ్ళు పూర్తి;
	}
	/* Find and consume lf + suffix (any prior cr would be ignored) */
	ఒకవేళ ((r = sshbuf_కనుగొను(sbuf, 0, "\n" చివర_SIGNATURE,
	    పరిమాణం(చివర_SIGNATURE), &eoffset)) != 0) {
		error("Couldn't parse signature: missing footer");
		వెళ్ళు పూర్తి;
	}
	ఒకవేళ ((r = sshbuf_consume_చివర(sbuf, sshbuf_len(sbuf)-eoffset)) != 0) {
		error_fr(r, "consume");
		వెళ్ళు పూర్తి;
	}

	ఒకవేళ ((b64 = sshbuf_dup_string(sbuf)) == ఖాళీ) {
		error_f("sshbuf_dup_string failed");
		r = SSH_ERR_ALLOC_FAIL;
		వెళ్ళు పూర్తి;
	}

	ఒకవేళ ((buf = sshbuf_new()) == ఖాళీ) {
		error_f("sshbuf_new() failed");
		r = SSH_ERR_ALLOC_FAIL;
		వెళ్ళు పూర్తి;
	}

	ఒకవేళ ((r = sshbuf_b64tod(buf, b64)) != 0) {
		error_fr(r, "decode base64");
		వెళ్ళు పూర్తి;
	}

	/* success */
	*బహిర్గతం = buf;
	r = 0;
	buf = ఖాళీ; /* transferred */
పూర్తి:
	sshbuf_free(buf);
	sshbuf_free(sbuf);
	విడుదల(b64);
	తిరిగి r;
}

స్థిర పూర్ణాంకం
sshsig_wrap_sign(నిర్మాణం sshkey *కీలకం, స్థిరరాశి అక్షరం *hashalg,
    స్థిరరాశి అక్షరం *sk_provider, స్థిరరాశి అక్షరం *sk_pin, స్థిరరాశి నిర్మాణం sshbuf *h_సందేశం,
    స్థిరరాశి అక్షరం *sig_namespace, నిర్మాణం sshbuf **బహిర్గతం,
    sshsig_signer *signer, శూన్య *signer_ctx)
{
	పూర్ణాంకం r;
	కొలత_t slen = 0;
	u_char *sig = ఖాళీ;
	నిర్మాణం sshbuf *blob = ఖాళీ;
	నిర్మాణం sshbuf *tosign = ఖాళీ;
	స్థిరరాశి అక్షరం *sign_alg = ఖాళీ;

	ఒకవేళ ((tosign = sshbuf_new()) == ఖాళీ ||
	    (blob = sshbuf_new()) == ఖాళీ) {
		error_f("sshbuf_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		వెళ్ళు పూర్తి;
	}

	ఒకవేళ ((r = sshbuf_put(tosign, MAGIC_PREAMBLE, MAGIC_PREAMBLE_LEN)) != 0 ||
	    (r = sshbuf_put_cstring(tosign, sig_namespace)) != 0 ||
	    (r = sshbuf_put_string(tosign, ఖాళీ, 0)) != 0 || /* reserved */
	    (r = sshbuf_put_cstring(tosign, hashalg)) != 0 ||
	    (r = sshbuf_put_stringb(tosign, h_సందేశం)) != 0) {
		error_fr(r, "assemble message to sign");
		వెళ్ళు పూర్తి;
	}

	/* If using RSA keys then default to a good signature algorithm */
	ఒకవేళ (sshkey_type_plain(కీలకం->type) == కీలకం_RSA) {
		sign_alg = RSA_SIGN_ALG;
		ఒకవేళ (strcmp(hashalg, "sha256") == 0)
			sign_alg = "rsa-sha2-256";
		లేకపోతే ఒకవేళ (strcmp(hashalg, "sha512") == 0)
			sign_alg = "rsa-sha2-512";
	}

	ఒకవేళ (signer != ఖాళీ) {
		ఒకవేళ ((r = signer(కీలకం, &sig, &slen,
		    sshbuf_ptr(tosign), sshbuf_len(tosign),
		    sign_alg, sk_provider, sk_pin, 0, signer_ctx)) != 0) {
			error_r(r, "Couldn't sign message (signer)");
			వెళ్ళు పూర్తి;
		}
	} లేకపోతే {
		ఒకవేళ ((r = sshkey_sign(కీలకం, &sig, &slen,
		    sshbuf_ptr(tosign), sshbuf_len(tosign),
		    sign_alg, sk_provider, sk_pin, 0)) != 0) {
			error_r(r, "Couldn't sign message");
			వెళ్ళు పూర్తి;
		}
	}

	ఒకవేళ ((r = sshbuf_put(blob, MAGIC_PREAMBLE, MAGIC_PREAMBLE_LEN)) != 0 ||
	    (r = sshbuf_put_u32(blob, SIG_సంస్కరణ)) != 0 ||
	    (r = sshkey_puts(కీలకం, blob)) != 0 ||
	    (r = sshbuf_put_cstring(blob, sig_namespace)) != 0 ||
	    (r = sshbuf_put_string(blob, ఖాళీ, 0)) != 0 || /* reserved */
	    (r = sshbuf_put_cstring(blob, hashalg)) != 0 ||
	    (r = sshbuf_put_string(blob, sig, slen)) != 0) {
		error_fr(r, "assemble signature object");
		వెళ్ళు పూర్తి;
	}

	ఒకవేళ (బహిర్గతం != ఖాళీ) {
		*బహిర్గతం = blob;
		blob = ఖాళీ;
	}
	r = 0;
పూర్తి:
	విడుదల(sig);
	sshbuf_free(blob);
	sshbuf_free(tosign);
	తిరిగి r;
}

/* Check preamble and version. */
స్థిర పూర్ణాంకం
sshsig_parse_preamble(నిర్మాణం sshbuf *buf)
{
	పూర్ణాంకం r = SSH_ERR_అంతర్గత_ERROR;
	uint32_t sversion;

	ఒకవేళ ((r = sshbuf_cmp(buf, 0, MAGIC_PREAMBLE, MAGIC_PREAMBLE_LEN)) != 0 ||
	    (r = sshbuf_consume(buf, (పరిమాణం(MAGIC_PREAMBLE)-1))) != 0 ||
	    (r = sshbuf_get_u32(buf, &sversion)) != 0) {
		error("Couldn't verify signature: invalid format");
		తిరిగి r;
	}

	ఒకవేళ (sversion > SIG_సంస్కరణ) {
		error("Signature version %lu is larger than supported "
		    "version %u", (గుర్తులేని దీర్ఘ)sversion, SIG_సంస్కరణ);
		తిరిగి SSH_ERR_INVALID_FORMAT;
	}
	తిరిగి 0;
}

స్థిర పూర్ణాంకం
sshsig_check_hashalg(స్థిరరాశి అక్షరం *hashalg)
{
	ఒకవేళ (hashalg == ఖాళీ ||
	    సరిపోలిక_నమూనా_list(hashalg, HASHALG_ALLOWED, 0) == 1)
		తిరిగి 0;
	error_f("unsupported hash algorithm \"%.100s\"", hashalg);
	తిరిగి SSH_ERR_SIGN_ALG_UNSUPPORTED;
}

స్థిర పూర్ణాంకం
sshsig_peek_hashalg(నిర్మాణం sshbuf *signature, అక్షరం **hashalgp)
{
	నిర్మాణం sshbuf *buf = ఖాళీ;
	అక్షరం *hashalg = ఖాళీ;
	పూర్ణాంకం r = SSH_ERR_అంతర్గత_ERROR;

	ఒకవేళ (hashalgp != ఖాళీ)
		*hashalgp = ఖాళీ;
	ఒకవేళ ((buf = sshbuf_fromb(signature)) == ఖాళీ)
		తిరిగి SSH_ERR_ALLOC_FAIL;
	ఒకవేళ ((r = sshsig_parse_preamble(buf)) != 0)
		వెళ్ళు పూర్తి;
	ఒకవేళ ((r = sshbuf_get_string_ప్రత్యక్ష(buf, ఖాళీ, ఖాళీ)) != 0 ||
	    (r = sshbuf_get_string_ప్రత్యక్ష(buf, ఖాళీ, ఖాళీ)) != 0 ||
	    (r = sshbuf_get_string(buf, ఖాళీ, ఖాళీ)) != 0 ||
	    (r = sshbuf_get_cstring(buf, &hashalg, ఖాళీ)) != 0 ||
	    (r = sshbuf_get_string_ప్రత్యక్ష(buf, ఖాళీ, ఖాళీ)) != 0) {
		error_fr(r, "parse signature object");
		వెళ్ళు పూర్తి;
	}

	/* success */
	r = 0;
	*hashalgp = hashalg;
	hashalg = ఖాళీ;
 పూర్తి:
	విడుదల(hashalg);
	sshbuf_free(buf);
	తిరిగి r;
}

స్థిర పూర్ణాంకం
sshsig_wrap_verify(నిర్మాణం sshbuf *signature, స్థిరరాశి అక్షరం *hashalg,
    స్థిరరాశి నిర్మాణం sshbuf *h_సందేశం, స్థిరరాశి అక్షరం *expect_namespace,
    నిర్మాణం sshkey **sign_keyp, నిర్మాణం sshkey_sig_details **sig_details)
{
	పూర్ణాంకం r = SSH_ERR_అంతర్గత_ERROR;
	నిర్మాణం sshbuf *buf = ఖాళీ, *toverify = ఖాళీ;
	నిర్మాణం sshkey *కీలకం = ఖాళీ;
	స్థిరరాశి u_char *sig;
	అక్షరం *got_namespace = ఖాళీ, *sigtype = ఖాళీ, *sig_hashalg = ఖాళీ;
	కొలత_t siglen;

	debug_f("verify message length %zu", sshbuf_len(h_సందేశం));
	ఒకవేళ (sig_details != ఖాళీ)
		*sig_details = ఖాళీ;
	ఒకవేళ (sign_keyp != ఖాళీ)
		*sign_keyp = ఖాళీ;

	ఒకవేళ ((toverify = sshbuf_new()) == ఖాళీ) {
		error_f("sshbuf_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		వెళ్ళు పూర్తి;
	}
	ఒకవేళ ((r = sshbuf_put(toverify, MAGIC_PREAMBLE,
	    MAGIC_PREAMBLE_LEN)) != 0 ||
	    (r = sshbuf_put_cstring(toverify, expect_namespace)) != 0 ||
	    (r = sshbuf_put_string(toverify, ఖాళీ, 0)) != 0 || /* reserved */
	    (r = sshbuf_put_cstring(toverify, hashalg)) != 0 ||
	    (r = sshbuf_put_stringb(toverify, h_సందేశం)) != 0) {
		error_fr(r, "assemble message to verify");
		వెళ్ళు పూర్తి;
	}

	ఒకవేళ ((r = sshsig_parse_preamble(signature)) != 0)
		వెళ్ళు పూర్తి;

	ఒకవేళ ((r = sshkey_froms(signature, &కీలకం)) != 0 ||
	    (r = sshbuf_get_cstring(signature, &got_namespace, ఖాళీ)) != 0 ||
	    (r = sshbuf_get_string(signature, ఖాళీ, ఖాళీ)) != 0 ||
	    (r = sshbuf_get_cstring(signature, &sig_hashalg, ఖాళీ)) != 0 ||
	    (r = sshbuf_get_string_ప్రత్యక్ష(signature, &sig, &siglen)) != 0) {
		error_fr(r, "parse signature object");
		వెళ్ళు పూర్తి;
	}

	ఒకవేళ (sshbuf_len(signature) != 0) {
		error("Signature contains trailing data");
		r = SSH_ERR_INVALID_FORMAT;
		వెళ్ళు పూర్తి;
	}

	ఒకవేళ (strcmp(expect_namespace, got_namespace) != 0) {
		error("Couldn't verify signature: namespace does not match");
		debug_f("expected namespace \"%s\" received \"%s\"",
		    expect_namespace, got_namespace);
		r = SSH_ERR_SIGNATURE_INVALID;
		వెళ్ళు పూర్తి;
	}
	ఒకవేళ (strcmp(hashalg, sig_hashalg) != 0) {
		error("Couldn't verify signature: hash algorithm mismatch");
		debug_f("expected algorithm \"%s\" received \"%s\"",
		    hashalg, sig_hashalg);
		r = SSH_ERR_SIGNATURE_INVALID;
		వెళ్ళు పూర్తి;
	}
	/* Ensure that RSA keys use an acceptable signature algorithm */
	ఒకవేళ (sshkey_type_plain(కీలకం->type) == కీలకం_RSA) {
		ఒకవేళ ((r = sshkey_get_sigtype(sig, siglen, &sigtype)) != 0) {
			error_r(r, "Couldn't verify signature: unable to get "
			    "signature type");
			వెళ్ళు పూర్తి;
		}
		ఒకవేళ (సరిపోలిక_నమూనా_list(sigtype, RSA_SIGN_ALLOWED, 0) != 1) {
			error("Couldn't verify signature: unsupported RSA "
			    "signature algorithm %s", sigtype);
			r = SSH_ERR_SIGN_ALG_UNSUPPORTED;
			వెళ్ళు పూర్తి;
		}
	}
	ఒకవేళ ((r = sshkey_verify(కీలకం, sig, siglen, sshbuf_ptr(toverify),
	    sshbuf_len(toverify), ఖాళీ, 0, sig_details)) != 0) {
		error_r(r, "Signature verification failed");
		వెళ్ళు పూర్తి;
	}

	/* success */
	r = 0;
	ఒకవేళ (sign_keyp != ఖాళీ) {
		*sign_keyp = కీలకం;
		కీలకం = ఖాళీ; /* transferred */
	}
పూర్తి:
	విడుదల(got_namespace);
	విడుదల(sigtype);
	విడుదల(sig_hashalg);
	sshbuf_free(buf);
	sshbuf_free(toverify);
	sshkey_free(కీలకం);
	తిరిగి r;
}

స్థిర పూర్ణాంకం
hash_బఫరు(స్థిరరాశి నిర్మాణం sshbuf *m, స్థిరరాశి అక్షరం *hashalg, నిర్మాణం sshbuf **bp)
{
	అక్షరం *hex, hash[SSH_DIGEST_MAX_నిడివి];
	పూర్ణాంకం alg, r = SSH_ERR_అంతర్గత_ERROR;
	నిర్మాణం sshbuf *b = ఖాళీ;

	*bp = ఖాళీ;
	memset(hash, 0, పరిమాణం(hash));

	ఒకవేళ ((r = sshsig_check_hashalg(hashalg)) != 0)
		తిరిగి r;
	ఒకవేళ ((alg = ssh_digest_alg_by_name(hashalg)) == -1) {
		error_f("can't look up hash algorithm %s", hashalg);
		తిరిగి SSH_ERR_అంతర్గత_ERROR;
	}
	ఒకవేళ ((r = ssh_digest_బఫరు(alg, m, hash, పరిమాణం(hash))) != 0) {
		error_fr(r, "ssh_digest_buffer");
		తిరిగి r;
	}
	ఒకవేళ ((hex = tohex(hash, ssh_digest_బైట్లు(alg))) != ఖాళీ) {
		debug3_f("final hash: %s", hex);
		freezero(hex, అక్షరశ్రేణి_పొడవు(hex));
	}
	ఒకవేళ ((b = sshbuf_new()) == ఖాళీ) {
		r = SSH_ERR_ALLOC_FAIL;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((r = sshbuf_put(b, hash, ssh_digest_బైట్లు(alg))) != 0) {
		error_fr(r, "sshbuf_put");
		వెళ్ళు బహిర్గతం;
	}
	*bp = b;
	b = ఖాళీ; /* transferred */
	/* success */
	r = 0;
 బహిర్గతం:
	sshbuf_free(b);
	explicit_bzero(hash, పరిమాణం(hash));
	తిరిగి r;
}

పూర్ణాంకం
sshsig_signb(నిర్మాణం sshkey *కీలకం, స్థిరరాశి అక్షరం *hashalg,
    స్థిరరాశి అక్షరం *sk_provider, స్థిరరాశి అక్షరం *sk_pin,
    స్థిరరాశి నిర్మాణం sshbuf *సందేశం_2, స్థిరరాశి అక్షరం *sig_namespace,
    నిర్మాణం sshbuf **బహిర్గతం, sshsig_signer *signer, శూన్య *signer_ctx)
{
	నిర్మాణం sshbuf *b = ఖాళీ;
	పూర్ణాంకం r = SSH_ERR_అంతర్గత_ERROR;

	ఒకవేళ (hashalg == ఖాళీ)
		hashalg = HASHALG_DEFAULT;
	ఒకవేళ (బహిర్గతం != ఖాళీ)
		*బహిర్గతం = ఖాళీ;
	ఒకవేళ ((r = hash_బఫరు(సందేశం_2, hashalg, &b)) != 0) {
		error_fr(r, "hash buffer");
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((r = sshsig_wrap_sign(కీలకం, hashalg, sk_provider, sk_pin, b,
	    sig_namespace, బహిర్గతం, signer, signer_ctx)) != 0)
		వెళ్ళు బహిర్గతం;
	/* success */
	r = 0;
 బహిర్గతం:
	sshbuf_free(b);
	తిరిగి r;
}

పూర్ణాంకం
sshsig_verifyb(నిర్మాణం sshbuf *signature, స్థిరరాశి నిర్మాణం sshbuf *సందేశం_2,
    స్థిరరాశి అక్షరం *expect_namespace, నిర్మాణం sshkey **sign_keyp,
    నిర్మాణం sshkey_sig_details **sig_details)
{
	నిర్మాణం sshbuf *b = ఖాళీ;
	పూర్ణాంకం r = SSH_ERR_అంతర్గత_ERROR;
	అక్షరం *hashalg = ఖాళీ;

	ఒకవేళ (sig_details != ఖాళీ)
		*sig_details = ఖాళీ;
	ఒకవేళ (sign_keyp != ఖాళీ)
		*sign_keyp = ఖాళీ;
	ఒకవేళ ((r = sshsig_peek_hashalg(signature, &hashalg)) != 0)
		తిరిగి r;
	debug_f("signature made with hash \"%s\"", hashalg);
	ఒకవేళ ((r = hash_బఫరు(సందేశం_2, hashalg, &b)) != 0) {
		error_fr(r, "hash buffer");
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((r = sshsig_wrap_verify(signature, hashalg, b, expect_namespace,
	    sign_keyp, sig_details)) != 0)
		వెళ్ళు బహిర్గతం;
	/* success */
	r = 0;
 బహిర్గతం:
	sshbuf_free(b);
	విడుదల(hashalg);
	తిరిగి r;
}

స్థిర పూర్ణాంకం
hash_file(పూర్ణాంకం fd, స్థిరరాశి అక్షరం *hashalg, నిర్మాణం sshbuf **bp)
{
	అక్షరం *hex, rbuf[8192], hash[SSH_DIGEST_MAX_నిడివి];
	ssize_t n, మొత్తం = 0;
	నిర్మాణం ssh_digest_ctx *ctx = ఖాళీ;
	పూర్ణాంకం alg, oerrno, r = SSH_ERR_అంతర్గత_ERROR;
	నిర్మాణం sshbuf *b = ఖాళీ;

	*bp = ఖాళీ;
	memset(hash, 0, పరిమాణం(hash));

	ఒకవేళ ((r = sshsig_check_hashalg(hashalg)) != 0)
		తిరిగి r;
	ఒకవేళ ((alg = ssh_digest_alg_by_name(hashalg)) == -1) {
		error_f("can't look up hash algorithm %s", hashalg);
		తిరిగి SSH_ERR_అంతర్గత_ERROR;
	}
	ఒకవేళ ((ctx = ssh_digest_ప్రారంభం(alg)) == ఖాళీ) {
		error_f("ssh_digest_start failed");
		తిరిగి SSH_ERR_అంతర్గత_ERROR;
	}
	కొరకు (;;) {
		ఒకవేళ ((n = పఠ(fd, rbuf, పరిమాణం(rbuf))) == -1) {
			ఒకవేళ (errno == EINTR || errno == EAGAIN)
				కొనసాగు;
			oerrno = errno;
			error_f("read: %s", strerror(errno));
			errno = oerrno;
			r = SSH_ERR_SYSTEM_ERROR;
			వెళ్ళు బహిర్గతం;
		} లేకపోతే ఒకవేళ (n == 0) {
			debug2_f("hashed %zu bytes", మొత్తం);
			ఆపు; /* EOF */
		}
		మొత్తం += (కొలత_t)n;
		ఒకవేళ ((r = ssh_digest_update(ctx, rbuf, (కొలత_t)n)) != 0) {
			error_fr(r, "ssh_digest_update");
			వెళ్ళు బహిర్గతం;
		}
	}
	ఒకవేళ ((r = ssh_digest_final(ctx, hash, పరిమాణం(hash))) != 0) {
		error_fr(r, "ssh_digest_final");
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((hex = tohex(hash, ssh_digest_బైట్లు(alg))) != ఖాళీ) {
		debug3_f("final hash: %s", hex);
		freezero(hex, అక్షరశ్రేణి_పొడవు(hex));
	}
	ఒకవేళ ((b = sshbuf_new()) == ఖాళీ) {
		r = SSH_ERR_ALLOC_FAIL;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((r = sshbuf_put(b, hash, ssh_digest_బైట్లు(alg))) != 0) {
		error_fr(r, "sshbuf_put");
		వెళ్ళు బహిర్గతం;
	}
	*bp = b;
	b = ఖాళీ; /* transferred */
	/* success */
	r = 0;
 బహిర్గతం:
	oerrno = errno;
	sshbuf_free(b);
	ssh_digest_free(ctx);
	explicit_bzero(hash, పరిమాణం(hash));
	errno = oerrno;
	తిరిగి r;
}

పూర్ణాంకం
sshsig_sign_fd(నిర్మాణం sshkey *కీలకం, స్థిరరాశి అక్షరం *hashalg,
    స్థిరరాశి అక్షరం *sk_provider, స్థిరరాశి అక్షరం *sk_pin,
    పూర్ణాంకం fd, స్థిరరాశి అక్షరం *sig_namespace, నిర్మాణం sshbuf **బహిర్గతం,
    sshsig_signer *signer, శూన్య *signer_ctx)
{
	నిర్మాణం sshbuf *b = ఖాళీ;
	పూర్ణాంకం r = SSH_ERR_అంతర్గత_ERROR;

	ఒకవేళ (hashalg == ఖాళీ)
		hashalg = HASHALG_DEFAULT;
	ఒకవేళ (బహిర్గతం != ఖాళీ)
		*బహిర్గతం = ఖాళీ;
	ఒకవేళ ((r = hash_file(fd, hashalg, &b)) != 0) {
		error_fr(r, "hash_file");
		తిరిగి r;
	}
	ఒకవేళ ((r = sshsig_wrap_sign(కీలకం, hashalg, sk_provider, sk_pin, b,
	    sig_namespace, బహిర్గతం, signer, signer_ctx)) != 0)
		వెళ్ళు బహిర్గతం;
	/* success */
	r = 0;
 బహిర్గతం:
	sshbuf_free(b);
	తిరిగి r;
}

పూర్ణాంకం
sshsig_verify_fd(నిర్మాణం sshbuf *signature, పూర్ణాంకం fd,
    స్థిరరాశి అక్షరం *expect_namespace, నిర్మాణం sshkey **sign_keyp,
    నిర్మాణం sshkey_sig_details **sig_details)
{
	నిర్మాణం sshbuf *b = ఖాళీ;
	పూర్ణాంకం r = SSH_ERR_అంతర్గత_ERROR;
	అక్షరం *hashalg = ఖాళీ;

	ఒకవేళ (sig_details != ఖాళీ)
		*sig_details = ఖాళీ;
	ఒకవేళ (sign_keyp != ఖాళీ)
		*sign_keyp = ఖాళీ;
	ఒకవేళ ((r = sshsig_peek_hashalg(signature, &hashalg)) != 0)
		తిరిగి r;
	debug_f("signature made with hash \"%s\"", hashalg);
	ఒకవేళ ((r = hash_file(fd, hashalg, &b)) != 0) {
		error_fr(r, "hash_file");
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((r = sshsig_wrap_verify(signature, hashalg, b, expect_namespace,
	    sign_keyp, sig_details)) != 0)
		వెళ్ళు బహిర్గతం;
	/* success */
	r = 0;
 బహిర్గతం:
	sshbuf_free(b);
	విడుదల(hashalg);
	తిరిగి r;
}

నిర్మాణం sshsigopt {
	పూర్ణాంకం ca;
	అక్షరం *namespaces;
	uint64_t valid_after, valid_before;
};

నిర్మాణం sshsigopt *
sshsigopt_parse(స్థిరరాశి అక్షరం *opts, స్థిరరాశి అక్షరం *మార్గం, u_long linenum,
    స్థిరరాశి అక్షరం **errstrp)
{
	నిర్మాణం sshsigopt *ret;
	పూర్ణాంకం r;
	అక్షరం *opt;
	స్థిరరాశి అక్షరం *errstr = ఖాళీ;

	ఒకవేళ ((ret = సున్నా_జ్ఞాపకం_ఇవ్వు(1, పరిమాణం(*ret))) == ఖాళీ)
		తిరిగి ఖాళీ;
	ఒకవేళ (opts == ఖాళీ || *opts == '\0')
		తిరిగి ret; /* Empty options yields empty options :) */

	అయితే (*opts && *opts != ' ' && *opts != '\t') {
		/* flag options */
		ఒకవేళ ((r = opt_flag("cert-authority", 0, &opts)) != -1) {
			ret->ca = 1;
		} లేకపోతే ఒకవేళ (opt_సరిపోలిక(&opts, "namespaces")) {
			ఒకవేళ (ret->namespaces != ఖాళీ) {
				errstr = "multiple \"namespaces\" clauses";
				వెళ్ళు fail;
			}
			ret->namespaces = opt_dequote(&opts, &errstr);
			ఒకవేళ (ret->namespaces == ఖాళీ)
				వెళ్ళు fail;
		} లేకపోతే ఒకవేళ (opt_సరిపోలిక(&opts, "valid-after")) {
			ఒకవేళ (ret->valid_after != 0) {
				errstr = "multiple \"valid-after\" clauses";
				వెళ్ళు fail;
			}
			ఒకవేళ ((opt = opt_dequote(&opts, &errstr)) == ఖాళీ)
				వెళ్ళు fail;
			ఒకవేళ (parse_absolute_సమయం(opt, &ret->valid_after) != 0 ||
			    ret->valid_after == 0) {
				విడుదల(opt);
				errstr = "invalid \"valid-after\" time";
				వెళ్ళు fail;
			}
			విడుదల(opt);
		} లేకపోతే ఒకవేళ (opt_సరిపోలిక(&opts, "valid-before")) {
			ఒకవేళ (ret->valid_before != 0) {
				errstr = "multiple \"valid-before\" clauses";
				వెళ్ళు fail;
			}
			ఒకవేళ ((opt = opt_dequote(&opts, &errstr)) == ఖాళీ)
				వెళ్ళు fail;
			ఒకవేళ (parse_absolute_సమయం(opt, &ret->valid_before) != 0 ||
			    ret->valid_before == 0) {
				విడుదల(opt);
				errstr = "invalid \"valid-before\" time";
				వెళ్ళు fail;
			}
			విడుదల(opt);
		}
		/*
		 * Skip the comma, and move to the next option
		 * (or break out if there are no more).
		 */
		ఒకవేళ (*opts == '\0' || *opts == ' ' || *opts == '\t')
			ఆపు;		/* End of options. */
		/* Anything other than a comma is an unknown option */
		ఒకవేళ (*opts != ',') {
			errstr = "unknown key option";
			వెళ్ళు fail;
		}
		opts++;
		ఒకవేళ (*opts == '\0') {
			errstr = "unexpected end-of-options";
			వెళ్ళు fail;
		}
	}
	/* final consistency check */
	ఒకవేళ (ret->valid_after != 0 && ret->valid_before != 0 &&
	    ret->valid_before <= ret->valid_after) {
		errstr = "\"valid-before\" time is before \"valid-after\"";
		వెళ్ళు fail;
	}
	/* success */
	తిరిగి ret;
 fail:
	ఒకవేళ (errstrp != ఖాళీ)
		*errstrp = errstr;
	sshsigopt_free(ret);
	తిరిగి ఖాళీ;
}

శూన్య
sshsigopt_free(నిర్మాణం sshsigopt *opts)
{
	ఒకవేళ (opts == ఖాళీ)
		తిరిగి;
	విడుదల(opts->namespaces);
	విడుదల(opts);
}

స్థిర పూర్ణాంకం
parse_principals_కీలకం_and_options(స్థిరరాశి అక్షరం *మార్గం, u_long linenum, అక్షరం *పంక్తి,
    స్థిరరాశి అక్షరం *required_principal, అక్షరం **principalsp, నిర్మాణం sshkey **keyp,
    నిర్మాణం sshsigopt **sigoptsp)
{
	అక్షరం *opts = ఖాళీ, *tmp, *cp, *principals = ఖాళీ;
	స్థిరరాశి అక్షరం *reason = ఖాళీ;
	నిర్మాణం sshsigopt *sigopts = ఖాళీ;
	నిర్మాణం sshkey *కీలకం = ఖాళీ;
	పూర్ణాంకం r = SSH_ERR_అంతర్గత_ERROR;

	ఒకవేళ (principalsp != ఖాళీ)
		*principalsp = ఖాళీ;
	ఒకవేళ (sigoptsp != ఖాళీ)
		*sigoptsp = ఖాళీ;
	ఒకవేళ (keyp != ఖాళీ)
		*keyp = ఖాళీ;

	cp = పంక్తి;
	cp = cp + strspn(cp, " \t\n\r"); /* skip leading whitespace */
	ఒకవేళ (*cp == '#' || *cp == '\0')
		తిరిగి SSH_ERR_కీలకం_NOT_దొరికింది; /* blank or all-comment line */

	/* format: identity[,identity...] [option[,option...]] key */
	ఒకవేళ ((tmp = strdelimw(&cp)) == ఖాళీ || cp == ఖాళీ) {
		error("%s:%lu: invalid line", మార్గం, linenum);
		r = SSH_ERR_INVALID_FORMAT;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((principals = strdup(tmp)) == ఖాళీ) {
		error_f("strdup failed");
		r = SSH_ERR_ALLOC_FAIL;
		వెళ్ళు బహిర్గతం;
	}
	/*
	 * Bail out early if we're looking for a particular principal and this
	 * line does not list it.
	 */
	ఒకవేళ (required_principal != ఖాళీ) {
		ఒకవేళ (సరిపోలిక_నమూనా_list(required_principal,
		    principals, 0) != 1) {
			/* principal didn't match */
			r = SSH_ERR_కీలకం_NOT_దొరికింది;
			వెళ్ళు బహిర్గతం;
		}
		debug_f("%s:%lu: matched principal \"%s\"",
		    మార్గం, linenum, required_principal);
	}

	ఒకవేళ ((కీలకం = sshkey_new(కీలకం_UNSPEC)) == ఖాళీ) {
		error_f("sshkey_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ (sshkey_read(కీలకం, &cp) != 0) {
		/* no key? Check for options */
		opts = cp;
		ఒకవేళ (sshkey_advance_past_options(&cp) != 0) {
			error("%s:%lu: invalid options", మార్గం, linenum);
			r = SSH_ERR_INVALID_FORMAT;
			వెళ్ళు బహిర్గతం;
		}
		ఒకవేళ (cp == ఖాళీ || *cp == '\0') {
			error("%s:%lu: missing key", మార్గం, linenum);
			r = SSH_ERR_INVALID_FORMAT;
			వెళ్ళు బహిర్గతం;
		}
		*cp++ = '\0';
		skip_space(&cp);
		ఒకవేళ (sshkey_read(కీలకం, &cp) != 0) {
			error("%s:%lu: invalid key", మార్గం, linenum);
			r = SSH_ERR_INVALID_FORMAT;
			వెళ్ళు బహిర్గతం;
		}
	}
	debug3("%s:%lu: options %s", మార్గం, linenum, opts == ఖాళీ ? "" : opts);
	ఒకవేళ ((sigopts = sshsigopt_parse(opts, మార్గం, linenum, &reason)) == ఖాళీ) {
		error("%s:%lu: bad options: %s", మార్గం, linenum, reason);
		r = SSH_ERR_INVALID_FORMAT;
		వెళ్ళు బహిర్గతం;
	}
	/* success */
	ఒకవేళ (principalsp != ఖాళీ) {
		*principalsp = principals;
		principals = ఖాళీ; /* transferred */
	}
	ఒకవేళ (sigoptsp != ఖాళీ) {
		*sigoptsp = sigopts;
		sigopts = ఖాళీ; /* transferred */
	}
	ఒకవేళ (keyp != ఖాళీ) {
		*keyp = కీలకం;
		కీలకం = ఖాళీ; /* transferred */
	}
	r = 0;
 బహిర్గతం:
	విడుదల(principals);
	sshsigopt_free(sigopts);
	sshkey_free(కీలకం);
	తిరిగి r;
}

స్థిర పూర్ణాంకం
cert_filter_principals(స్థిరరాశి అక్షరం *మార్గం, u_long linenum,
    అక్షరం **principalsp, స్థిరరాశి నిర్మాణం sshkey *cert, uint64_t verify_సమయం)
{
	అక్షరం *cp, *oprincipals, *principals;
	స్థిరరాశి అక్షరం *reason;
	నిర్మాణం sshbuf *nprincipals;
	పూర్ణాంకం r = SSH_ERR_అంతర్గత_ERROR, success = 0;
	u_int i;

	oprincipals = principals = *principalsp;
	*principalsp = ఖాళీ;

	ఒకవేళ ((nprincipals = sshbuf_new()) == ఖాళీ) {
		r = SSH_ERR_ALLOC_FAIL;
		వెళ్ళు బహిర్గతం;
	}

	అయితే ((cp = strsep(&principals, ",")) != ఖాళీ && *cp != '\0') {
		/* Check certificate validity */
		ఒకవేళ ((r = sshkey_cert_check_authority(cert, 0, 0, verify_సమయం,
		    ఖాళీ, &reason)) != 0) {
			debug("%s:%lu: principal \"%s\" not authorized: %s",
			    మార్గం, linenum, cp, reason);
			కొనసాగు;
		}
		/* Return all matching principal names from the cert */
		కొరకు (i = 0; i < cert->cert->nprincipals; i++) {
			ఒకవేళ (సరిపోలిక_నమూనా(cert->cert->principals[i], cp)) {
				ఒకవేళ ((r = sshbuf_putf(nprincipals, "%s%s",
					sshbuf_len(nprincipals) != 0 ? "," : "",
						cert->cert->principals[i])) != 0) {
					error_f("buffer error");
					వెళ్ళు బహిర్గతం;
				}
			}
		}
	}
	ఒకవేళ (sshbuf_len(nprincipals) == 0) {
		error("%s:%lu: no valid principals found", మార్గం, linenum);
		r = SSH_ERR_కీలకం_CERT_INVALID;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((principals = sshbuf_dup_string(nprincipals)) == ఖాళీ) {
		error_f("buffer error");
		r = SSH_ERR_ALLOC_FAIL;
		వెళ్ళు బహిర్గతం;
	}
	/* success */
	success = 1;
	*principalsp = principals;
 బహిర్గతం:
	sshbuf_free(nprincipals);
	విడుదల(oprincipals);
	తిరిగి success ? 0 : r;
}

స్థిర పూర్ణాంకం
check_allowed_కీలకాలు_పంక్తి(స్థిరరాశి అక్షరం *మార్గం, u_long linenum, అక్షరం *పంక్తి,
    స్థిరరాశి నిర్మాణం sshkey *sign_కీలకం, స్థిరరాశి అక్షరం *principal,
    స్థిరరాశి అక్షరం *sig_namespace, uint64_t verify_సమయం, అక్షరం **principalsp)
{
	నిర్మాణం sshkey *దొరికింది_కీలకం = ఖాళీ;
	అక్షరం *principals = ఖాళీ;
	పూర్ణాంకం r, success = 0;
	స్థిరరాశి అక్షరం *reason = ఖాళీ;
	నిర్మాణం sshsigopt *sigopts = ఖాళీ;
	అక్షరం tvalid[64], tverify[64];

	ఒకవేళ (principalsp != ఖాళీ)
		*principalsp = ఖాళీ;

	/* Parse the line */
	ఒకవేళ ((r = parse_principals_కీలకం_and_options(మార్గం, linenum, పంక్తి,
	    principal, &principals, &దొరికింది_కీలకం, &sigopts)) != 0) {
		/* error already logged */
		వెళ్ళు పూర్తి;
	}

	ఒకవేళ (!sigopts->ca && sshkey_equal(దొరికింది_కీలకం, sign_కీలకం)) {
		/* Exact match of key */
		debug("%s:%lu: matched key", మార్గం, linenum);
	} లేకపోతే ఒకవేళ (sigopts->ca && sshkey_is_cert(sign_కీలకం) &&
	    sshkey_equal_ప్రజా(sign_కీలకం->cert->signature_కీలకం, దొరికింది_కీలకం)) {
		ఒకవేళ (principal) {
			/* Match certificate CA key with specified principal */
			ఒకవేళ ((r = sshkey_cert_check_authority(sign_కీలకం, 0, 0,
			    verify_సమయం, principal, &reason)) != 0) {
				error("%s:%lu: certificate not authorized: %s",
				    మార్గం, linenum, reason);
				వెళ్ళు పూర్తి;
			}
			debug("%s:%lu: matched certificate CA key",
			    మార్గం, linenum);
		} లేకపోతే {
			/* No principal specified - find all matching ones */
			ఒకవేళ ((r = cert_filter_principals(మార్గం, linenum,
			    &principals, sign_కీలకం, verify_సమయం)) != 0) {
				/* error already displayed */
				debug_r(r, "%s:%lu: cert_filter_principals",
				    మార్గం, linenum);
				వెళ్ళు పూర్తి;
			}
			debug("%s:%lu: matched certificate CA key",
			    మార్గం, linenum);
		}
	} లేకపోతే {
		/* Didn't match key */
		వెళ్ళు పూర్తి;
	}

	/* Check whether options preclude the use of this key */
	ఒకవేళ (sigopts->namespaces != ఖాళీ && sig_namespace != ఖాళీ &&
	    సరిపోలిక_నమూనా_list(sig_namespace, sigopts->namespaces, 0) != 1) {
		error("%s:%lu: key is not permitted for use in signature "
		    "namespace \"%s\"", మార్గం, linenum, sig_namespace);
		వెళ్ళు పూర్తి;
	}

	/* check key time validity */
	format_absolute_సమయం((uint64_t)verify_సమయం, tverify, పరిమాణం(tverify));
	ఒకవేళ (sigopts->valid_after != 0 &&
	    (uint64_t)verify_సమయం < sigopts->valid_after) {
		format_absolute_సమయం(sigopts->valid_after,
		    tvalid, పరిమాణం(tvalid));
		error("%s:%lu: key is not yet valid: "
		    "verify time %s < valid-after %s", మార్గం, linenum,
		    tverify, tvalid);
		వెళ్ళు పూర్తి;
	}
	ఒకవేళ (sigopts->valid_before != 0 &&
	    (uint64_t)verify_సమయం > sigopts->valid_before) {
		format_absolute_సమయం(sigopts->valid_before,
		    tvalid, పరిమాణం(tvalid));
		error("%s:%lu: key has expired: "
		    "verify time %s > valid-before %s", మార్గం, linenum,
		    tverify, tvalid);
		వెళ్ళు పూర్తి;
	}
	success = 1;

 పూర్తి:
	ఒకవేళ (success && principalsp != ఖాళీ) {
		*principalsp = principals;
		principals = ఖాళీ; /* transferred */
	}
	విడుదల(principals);
	sshkey_free(దొరికింది_కీలకం);
	sshsigopt_free(sigopts);
	తిరిగి success ? 0 : SSH_ERR_కీలకం_NOT_దొరికింది;
}

పూర్ణాంకం
sshsig_check_allowed_కీలకాలు(స్థిరరాశి అక్షరం *మార్గం, స్థిరరాశి నిర్మాణం sshkey *sign_కీలకం,
    స్థిరరాశి అక్షరం *principal, స్థిరరాశి అక్షరం *sig_namespace, uint64_t verify_సమయం)
{
	FILE *f = ఖాళీ;
	అక్షరం *పంక్తి = ఖాళీ;
	కొలత_t linesize = 0;
	u_long linenum = 0;
	పూర్ణాంకం r = SSH_ERR_కీలకం_NOT_దొరికింది, oerrno;

	/* Check key and principal against file */
	ఒకవేళ ((f = fopen(మార్గం, "r")) == ఖాళీ) {
		oerrno = errno;
		error("Unable to open allowed keys file \"%s\": %s",
		    మార్గం, strerror(errno));
		errno = oerrno;
		తిరిగి SSH_ERR_SYSTEM_ERROR;
	}

	అయితే (getline(&పంక్తి, &linesize, f) != -1) {
		linenum++;
		r = check_allowed_కీలకాలు_పంక్తి(మార్గం, linenum, పంక్తి, sign_కీలకం,
		    principal, sig_namespace, verify_సమయం, ఖాళీ);
		విడుదల(పంక్తి);
		పంక్తి = ఖాళీ;
		linesize = 0;
		ఒకవేళ (r == SSH_ERR_కీలకం_NOT_దొరికింది)
			కొనసాగు;
		లేకపోతే ఒకవేళ (r == 0) {
			/* success */
			fclose(f);
			తిరిగి 0;
		} లేకపోతే
			ఆపు;
	}
	/* Either we hit an error parsing or we simply didn't find the key */
	fclose(f);
	విడుదల(పంక్తి);
	తిరిగి r;
}

పూర్ణాంకం
sshsig_కనుగొను_principals(స్థిరరాశి అక్షరం *మార్గం, స్థిరరాశి నిర్మాణం sshkey *sign_కీలకం,
    uint64_t verify_సమయం, అక్షరం **principals)
{
	FILE *f = ఖాళీ;
	అక్షరం *పంక్తి = ఖాళీ;
	కొలత_t linesize = 0;
	u_long linenum = 0;
	పూర్ణాంకం r = SSH_ERR_కీలకం_NOT_దొరికింది, oerrno;

	ఒకవేళ ((f = fopen(మార్గం, "r")) == ఖాళీ) {
		oerrno = errno;
		error("Unable to open allowed keys file \"%s\": %s",
		    మార్గం, strerror(errno));
		errno = oerrno;
		తిరిగి SSH_ERR_SYSTEM_ERROR;
	}

	అయితే (getline(&పంక్తి, &linesize, f) != -1) {
		linenum++;
		r = check_allowed_కీలకాలు_పంక్తి(మార్గం, linenum, పంక్తి,
		    sign_కీలకం, ఖాళీ, ఖాళీ, verify_సమయం, principals);
		విడుదల(పంక్తి);
		పంక్తి = ఖాళీ;
		linesize = 0;
		ఒకవేళ (r == SSH_ERR_కీలకం_NOT_దొరికింది)
			కొనసాగు;
		లేకపోతే ఒకవేళ (r == 0) {
			/* success */
			fclose(f);
			తిరిగి 0;
		} లేకపోతే
			ఆపు;
	}
	విడుదల(పంక్తి);
	/* Either we hit an error parsing or we simply didn't find the key */
	ఒకవేళ (ferror(f) != 0) {
		oerrno = errno;
		fclose(f);
		error("Unable to read allowed keys file \"%s\": %s",
		    మార్గం, strerror(errno));
		errno = oerrno;
		తిరిగి SSH_ERR_SYSTEM_ERROR;
	}
	fclose(f);
	తిరిగి r;
}

పూర్ణాంకం
sshsig_సరిపోలిక_principals(స్థిరరాశి అక్షరం *మార్గం, స్థిరరాశి అక్షరం *principal,
    అక్షరం ***principalsp, కొలత_t *nprincipalsp)
{
	FILE *f = ఖాళీ;
	అక్షరం *దొరికింది, *పంక్తి = ఖాళీ, **principals = ఖాళీ, **tmp;
	కొలత_t i, nprincipals = 0, linesize = 0;
	u_long linenum = 0;
	పూర్ణాంకం oerrno = 0, r, ret = 0;

	ఒకవేళ (principalsp != ఖాళీ)
		*principalsp = ఖాళీ;
	ఒకవేళ (nprincipalsp != ఖాళీ)
		*nprincipalsp = 0;

	/* Check key and principal against file */
	ఒకవేళ ((f = fopen(మార్గం, "r")) == ఖాళీ) {
		oerrno = errno;
		error("Unable to open allowed keys file \"%s\": %s",
		    మార్గం, strerror(errno));
		errno = oerrno;
		తిరిగి SSH_ERR_SYSTEM_ERROR;
	}

	అయితే (getline(&పంక్తి, &linesize, f) != -1) {
		linenum++;
		/* Parse the line */
		ఒకవేళ ((r = parse_principals_కీలకం_and_options(మార్గం, linenum, పంక్తి,
		    principal, &దొరికింది, ఖాళీ, ఖాళీ)) != 0) {
			ఒకవేళ (r == SSH_ERR_కీలకం_NOT_దొరికింది)
				కొనసాగు;
			ret = r;
			oerrno = errno;
			ఆపు; /* unexpected error */
		}
		ఒకవేళ ((tmp = recallocarray(principals, nprincipals,
		    nprincipals + 1, పరిమాణం(*principals))) == ఖాళీ) {
			ret = SSH_ERR_ALLOC_FAIL;
			విడుదల(దొరికింది);
			ఆపు;
		}
		principals = tmp;
		principals[nprincipals++] = దొరికింది; /* transferred */
		విడుదల(పంక్తి);
		పంక్తి = ఖాళీ;
		linesize = 0;
	}
	fclose(f);
	విడుదల(పంక్తి);

	ఒకవేళ (ret == 0) {
		ఒకవేళ (nprincipals == 0)
			ret = SSH_ERR_కీలకం_NOT_దొరికింది;
		ఒకవేళ (nprincipalsp != ఖాళీ)
			*nprincipalsp = nprincipals;
		ఒకవేళ (principalsp != ఖాళీ) {
			*principalsp = principals;
			principals = ఖాళీ; /* transferred */
			nprincipals = 0;
		}
	}

	కొరకు (i = 0; i < nprincipals; i++)
		విడుదల(principals[i]);
	విడుదల(principals);

	errno = oerrno;
	తిరిగి ret;
}

పూర్ణాంకం
sshsig_get_pubkey(నిర్మాణం sshbuf *signature, నిర్మాణం sshkey **pubkey)
{
	నిర్మాణం sshkey *pk = ఖాళీ;
	పూర్ణాంకం r = SSH_ERR_SIGNATURE_INVALID;

	ఒకవేళ (pubkey == ఖాళీ)
		తిరిగి SSH_ERR_అంతర్గత_ERROR;
	ఒకవేళ ((r = sshsig_parse_preamble(signature)) != 0)
		తిరిగి r;
	ఒకవేళ ((r = sshkey_froms(signature, &pk)) != 0)
		తిరిగి r;

	*pubkey = pk;
	pk = ఖాళీ;
	తిరిగి 0;
}
