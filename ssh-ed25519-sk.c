/* $OpenBSD: ssh-ed25519-sk.c,v 1.17 2026/09/16 00:43:00 djm Exp $ */
/*
 * Copyright (c) 2019 Markus Friedl.  All rights reserved.
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

/* #define DEBUG_SK 1 */

#అన్తర్భావ "includes.h"

#నిర్వచించు SSHKEY_అంతర్గత
#అన్తర్భావ <sys/types.h>

#అన్తర్భావ "crypto_api.h"

#అన్తర్భావ <string.h>
#అన్తర్భావ <stdarg.h>

#అన్తర్భావ "log.h"
#అన్తర్భావ "sshbuf.h"
#అన్తర్భావ "sshkey.h"
#అన్తర్భావ "ssherr.h"
#అన్తర్భావ "digest.h"

/* Reuse some ED25519 internals */
బాహ్య నిర్మాణం sshkey_impl_funcs sshkey_ed25519_funcs;

స్థిర శూన్య
ssh_ed25519_sk_cleanup(నిర్మాణం sshkey *k)
{
	sshkey_sk_cleanup(k);
	sshkey_ed25519_funcs.cleanup(k);
}

స్థిర పూర్ణాంకం
ssh_ed25519_sk_equal(స్థిరరాశి నిర్మాణం sshkey *a, స్థిరరాశి నిర్మాణం sshkey *b)
{
	ఒకవేళ (!sshkey_sk_fields_equal(a, b))
		తిరిగి 0;
	ఒకవేళ (!sshkey_ed25519_funcs.equal(a, b))
		తిరిగి 0;
	తిరిగి 1;
}

స్థిర పూర్ణాంకం
ssh_ed25519_sk_serialize_ప్రజా(స్థిరరాశి నిర్మాణం sshkey *కీలకం, నిర్మాణం sshbuf *b,
    గణన sshkey_serialize_rep opts)
{
	పూర్ణాంకం r;

	ఒకవేళ ((r = sshkey_ed25519_funcs.serialize_ప్రజా(కీలకం, b, opts)) != 0)
		తిరిగి r;
	ఒకవేళ ((r = sshkey_serialize_sk(కీలకం, b)) != 0)
		తిరిగి r;

	తిరిగి 0;
}

స్థిర పూర్ణాంకం
ssh_ed25519_sk_serialize_వ్యక్తిగత(స్థిరరాశి నిర్మాణం sshkey *కీలకం, నిర్మాణం sshbuf *b,
    గణన sshkey_serialize_rep opts)
{
	పూర్ణాంకం r;

	ఒకవేళ ((r = sshkey_ed25519_funcs.serialize_ప్రజా(కీలకం, b, opts)) != 0)
		తిరిగి r;
	ఒకవేళ ((r = sshkey_serialize_వ్యక్తిగత_sk(కీలకం, b)) != 0)
		తిరిగి r;

	తిరిగి 0;
}

స్థిర పూర్ణాంకం
ssh_ed25519_sk_copy_ప్రజా(స్థిరరాశి నిర్మాణం sshkey *from, నిర్మాణం sshkey *గమ్యం)
{
	పూర్ణాంకం r;

	ఒకవేళ ((r = sshkey_ed25519_funcs.copy_ప్రజా(from, గమ్యం)) != 0)
		తిరిగి r;
	ఒకవేళ ((r = sshkey_copy_ప్రజా_sk(from, గమ్యం)) != 0)
		తిరిగి r;
	తిరిగి 0;
}

స్థిర పూర్ణాంకం
ssh_ed25519_sk_deserialize_ప్రజా(స్థిరరాశి అక్షరం *ktype, నిర్మాణం sshbuf *b,
    నిర్మాణం sshkey *కీలకం)
{
	పూర్ణాంకం r;

	ఒకవేళ ((r = sshkey_ed25519_funcs.deserialize_ప్రజా(ktype, b, కీలకం)) != 0)
		తిరిగి r;
	ఒకవేళ ((r = sshkey_deserialize_sk(b, కీలకం)) != 0)
		తిరిగి r;
	తిరిగి 0;
}

స్థిర పూర్ణాంకం
ssh_ed25519_sk_deserialize_వ్యక్తిగత(స్థిరరాశి అక్షరం *ktype, నిర్మాణం sshbuf *b,
    నిర్మాణం sshkey *కీలకం)
{
	పూర్ణాంకం r;

	ఒకవేళ ((r = sshkey_ed25519_funcs.deserialize_ప్రజా(ktype, b, కీలకం)) != 0)
		తిరిగి r;
	ఒకవేళ ((r = sshkey_వ్యక్తిగత_deserialize_sk(b, కీలకం)) != 0)
		తిరిగి r;
	తిరిగి 0;
}

స్థిర పూర్ణాంకం
ssh_ed25519_sk_verify(స్థిరరాశి నిర్మాణం sshkey *కీలకం,
    స్థిరరాశి u_char *sig, కొలత_t siglen,
    స్థిరరాశి u_char *దత్తాంశం, కొలత_t dlen, స్థిరరాశి అక్షరం *alg, u_int compat,
    నిర్మాణం sshkey_sig_details **detailsp)
{
	నిర్మాణం sshbuf *b = ఖాళీ;
	నిర్మాణం sshbuf *encoded = ఖాళీ;
	అక్షరం *ktype = ఖాళీ;
	స్థిరరాశి u_char *sigblob;
	u_char apphash[32];
	u_char msghash[32];
	u_char sig_flags;
	u_int sig_counter;
	కొలత_t len;
	పూర్ణాంకం r = SSH_ERR_అంతర్గత_ERROR;
	పూర్ణాంకం ret;
	నిర్మాణం sshkey_sig_details *details = ఖాళీ;

	ఒకవేళ (detailsp != ఖాళీ)
		*detailsp = ఖాళీ;

	ఒకవేళ (కీలకం == ఖాళీ ||
	    sshkey_type_plain(కీలకం->type) != కీలకం_ED25519_SK ||
	    కీలకం->ed25519_pk == ఖాళీ ||
	    sig == ఖాళీ || siglen == 0)
		తిరిగి SSH_ERR_INVALID_వాదం;

	ఒకవేళ ((b = sshbuf_from(sig, siglen)) == ఖాళీ)
		తిరిగి SSH_ERR_ALLOC_FAIL;
	ఒకవేళ (sshbuf_get_cstring(b, &ktype, ఖాళీ) != 0 ||
	    sshbuf_get_string_ప్రత్యక్ష(b, &sigblob, &len) != 0 ||
	    sshbuf_get_u8(b, &sig_flags) != 0 ||
	    sshbuf_get_u32(b, &sig_counter) != 0) {
		r = SSH_ERR_INVALID_FORMAT;
		వెళ్ళు బహిర్గతం;
	}
#నిర్వచితమైతే DEBUG_SK
	fprintf(stderr, "%s: data:\n", __func__);
	/* sshbuf_dump_data(data, datalen, stderr); */
	fprintf(stderr, "%s: sigblob:\n", __func__);
	sshbuf_dump_దత్తాంశం(sigblob, len, stderr);
	fprintf(stderr, "%s: sig_flags = 0x%02x, sig_counter = %u\n",
	    __func__, sig_flags, sig_counter);
#అయితే_ముగింపు
	ఒకవేళ (strcmp(sshkey_ssh_name_plain(కీలకం), ktype) != 0) {
		r = SSH_ERR_కీలకం_TYPE_MISMATCH;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ (sshbuf_len(b) != 0) {
		r = SSH_ERR_UNEXPECTED_TRAILING_దత్తాంశం;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ (len != crypto_sign_ed25519_బైట్లు) {
		r = SSH_ERR_INVALID_FORMAT;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ (ssh_digest_జ్ఞాపకం(SSH_DIGEST_SHA256, కీలకం->sk_application,
	    అక్షరశ్రేణి_పొడవు(కీలకం->sk_application), apphash, పరిమాణం(apphash)) != 0 ||
	    ssh_digest_జ్ఞాపకం(SSH_DIGEST_SHA256, దత్తాంశం, dlen,
	    msghash, పరిమాణం(msghash)) != 0) {
		r = SSH_ERR_INVALID_వాదం;
		వెళ్ళు బహిర్గతం;
	}
#నిర్వచితమైతే DEBUG_SK
	fprintf(stderr, "%s: hashed application:\n", __func__);
	sshbuf_dump_దత్తాంశం(apphash, పరిమాణం(apphash), stderr);
	fprintf(stderr, "%s: hashed message:\n", __func__);
	sshbuf_dump_దత్తాంశం(msghash, పరిమాణం(msghash), stderr);
#అయితే_ముగింపు
	ఒకవేళ ((details = సున్నా_జ్ఞాపకం_ఇవ్వు(1, పరిమాణం(*details))) == ఖాళీ) {
		r = SSH_ERR_ALLOC_FAIL;
		వెళ్ళు బహిర్గతం;
	}
	details->sk_counter = sig_counter;
	details->sk_flags = sig_flags;
	ఒకవేళ ((encoded = sshbuf_new()) == ఖాళీ) {
		r = SSH_ERR_ALLOC_FAIL;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ (sshbuf_put(encoded, apphash, పరిమాణం(apphash)) != 0 ||
	    sshbuf_put_u8(encoded, sig_flags) != 0 ||
	    sshbuf_put_u32(encoded, sig_counter) != 0 ||
	    sshbuf_put(encoded, msghash, పరిమాణం(msghash)) != 0) {
		r = SSH_ERR_ALLOC_FAIL;
		వెళ్ళు బహిర్గతం;
	}
#నిర్వచితమైతే DEBUG_SK
	fprintf(stderr, "%s: signed buf:\n", __func__);
	sshbuf_dump(encoded, stderr);
#అయితే_ముగింపు
	ఒకవేళ ((ret = crypto_sign_ed25519_verify_detached(sigblob,
	    sshbuf_ptr(encoded), sshbuf_len(encoded),
	    కీలకం->ed25519_pk)) != 0) {
		debug2_f("crypto_sign_ed25519_verify_detached failed: %d", ret);
	}
	ఒకవేళ (ret != 0) {
		r = SSH_ERR_SIGNATURE_INVALID;
		వెళ్ళు బహిర్గతం;
	}
	/* success */
	r = 0;
	ఒకవేళ (detailsp != ఖాళీ) {
		*detailsp = details;
		details = ఖాళీ;
	}
 బహిర్గతం:
	sshkey_sig_details_free(details);
	sshbuf_free(b);
	sshbuf_free(encoded);
	విడుదల(ktype);
	తిరిగి r;
}

స్థిర స్థిరరాశి నిర్మాణం sshkey_impl_funcs sshkey_ed25519_sk_funcs = {
	/* .size = */		ఖాళీ,
	/* .alloc = */		ఖాళీ,
	/* .cleanup = */	ssh_ed25519_sk_cleanup,
	/* .equal = */		ssh_ed25519_sk_equal,
	/* .ssh_serialize_public = */ ssh_ed25519_sk_serialize_ప్రజా,
	/* .ssh_deserialize_public = */ ssh_ed25519_sk_deserialize_ప్రజా,
	/* .ssh_serialize_private = */ ssh_ed25519_sk_serialize_వ్యక్తిగత,
	/* .ssh_deserialize_private = */ ssh_ed25519_sk_deserialize_వ్యక్తిగత,
	/* .generate = */	ఖాళీ,
	/* .copy_public = */	ssh_ed25519_sk_copy_ప్రజా,
	/* .sign = */		ఖాళీ,
	/* .verify = */		ssh_ed25519_sk_verify,
};

స్థిరరాశి నిర్మాణం sshkey_impl sshkey_ed25519_sk_impl = {
	/* .name = */		"sk-ssh-ed25519@openssh.com",
	/* .shortname = */	"ED25519-SK",
	/* .sigalg = */		ఖాళీ,
	/* .type = */		కీలకం_ED25519_SK,
	/* .nid = */		0,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	256,
	/* .funcs = */		&sshkey_ed25519_sk_funcs,
};

స్థిరరాశి నిర్మాణం sshkey_impl sshkey_ed25519_sk_cert_impl = {
	/* .name = */		"sk-ssh-ed25519-cert-v01@openssh.com",
	/* .shortname = */	"ED25519-SK-CERT",
	/* .sigalg = */		ఖాళీ,
	/* .type = */		కీలకం_ED25519_SK_CERT,
	/* .nid = */		0,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	256,
	/* .funcs = */		&sshkey_ed25519_sk_funcs,
};
