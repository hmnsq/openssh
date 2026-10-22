/* $OpenBSD: ssh-ed25519.c,v 1.24 2026/09/16 00:43:00 djm Exp $ */
/*
 * Copyright (c) 2013 Markus Friedl <markus@openbsd.org>
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

#అన్తర్భావ <sys/types.h>
#అన్తర్భావ <limits.h>

#అన్తర్భావ "crypto_api.h"

#అన్తర్భావ <string.h>
#అన్తర్భావ <stdarg.h>

#అన్తర్భావ "log.h"
#అన్తర్భావ "sshbuf.h"
#నిర్వచించు SSHKEY_అంతర్గత
#అన్తర్భావ "sshkey.h"
#అన్తర్భావ "ssherr.h"

స్థిర శూన్య
ssh_ed25519_cleanup(నిర్మాణం sshkey *k)
{
	freezero(k->ed25519_pk, ED25519_PK_SZ);
	freezero(k->ed25519_sk, ED25519_SK_SZ);
	k->ed25519_pk = ఖాళీ;
	k->ed25519_sk = ఖాళీ;
}

స్థిర పూర్ణాంకం
ssh_ed25519_equal(స్థిరరాశి నిర్మాణం sshkey *a, స్థిరరాశి నిర్మాణం sshkey *b)
{
	ఒకవేళ (a->ed25519_pk == ఖాళీ || b->ed25519_pk == ఖాళీ)
		తిరిగి 0;
	ఒకవేళ (memcmp(a->ed25519_pk, b->ed25519_pk, ED25519_PK_SZ) != 0)
		తిరిగి 0;
	తిరిగి 1;
}

స్థిర పూర్ణాంకం
ssh_ed25519_serialize_ప్రజా(స్థిరరాశి నిర్మాణం sshkey *కీలకం, నిర్మాణం sshbuf *b,
    గణన sshkey_serialize_rep opts)
{
	పూర్ణాంకం r;

	ఒకవేళ (కీలకం->ed25519_pk == ఖాళీ)
		తిరిగి SSH_ERR_INVALID_వాదం;
	ఒకవేళ ((r = sshbuf_put_string(b, కీలకం->ed25519_pk, ED25519_PK_SZ)) != 0)
		తిరిగి r;

	తిరిగి 0;
}

స్థిర పూర్ణాంకం
ssh_ed25519_serialize_వ్యక్తిగత(స్థిరరాశి నిర్మాణం sshkey *కీలకం, నిర్మాణం sshbuf *b,
    గణన sshkey_serialize_rep opts)
{
	పూర్ణాంకం r;

	ఒకవేళ ((r = sshbuf_put_string(b, కీలకం->ed25519_pk, ED25519_PK_SZ)) != 0 ||
	    (r = sshbuf_put_string(b, కీలకం->ed25519_sk, ED25519_SK_SZ)) != 0)
		తిరిగి r;

	తిరిగి 0;
}

స్థిర పూర్ణాంకం
ssh_ed25519_generate(నిర్మాణం sshkey *k, పూర్ణాంకం బిట్లు)
{
	ఒకవేళ ((k->ed25519_pk = జ్ఞాపకం_ఇవ్వు(ED25519_PK_SZ)) == ఖాళీ ||
	    (k->ed25519_sk = జ్ఞాపకం_ఇవ్వు(ED25519_SK_SZ)) == ఖాళీ)
		తిరిగి SSH_ERR_ALLOC_FAIL;
	ఒకవేళ (crypto_sign_ed25519_keypair(k->ed25519_pk, k->ed25519_sk) != 0)
		తిరిగి SSH_ERR_CRYPTO_ERROR;
	తిరిగి 0;
}

స్థిర పూర్ణాంకం
ssh_ed25519_copy_ప్రజా(స్థిరరాశి నిర్మాణం sshkey *from, నిర్మాణం sshkey *గమ్యం)
{
	ఒకవేళ (from->ed25519_pk == ఖాళీ)
		తిరిగి 0; /* XXX SSH_ERR_INTERNAL_ERROR ? */
	ఒకవేళ ((గమ్యం->ed25519_pk = జ్ఞాపకం_ఇవ్వు(ED25519_PK_SZ)) == ఖాళీ)
		తిరిగి SSH_ERR_ALLOC_FAIL;
	జ్ఞాపకం_నకలు(గమ్యం->ed25519_pk, from->ed25519_pk, ED25519_PK_SZ);
	తిరిగి 0;
}

స్థిర పూర్ణాంకం
ssh_ed25519_deserialize_ప్రజా(స్థిరరాశి అక్షరం *ktype, నిర్మాణం sshbuf *b,
    నిర్మాణం sshkey *కీలకం)
{
	u_char *pk = ఖాళీ;
	కొలత_t len = 0;
	పూర్ణాంకం r;

	ఒకవేళ ((r = sshbuf_get_string(b, &pk, &len)) != 0)
		తిరిగి r;
	ఒకవేళ (len != ED25519_PK_SZ) {
		freezero(pk, len);
		తిరిగి SSH_ERR_INVALID_FORMAT;
	}
	కీలకం->ed25519_pk = pk;
	తిరిగి 0;
}

స్థిర పూర్ణాంకం
ssh_ed25519_deserialize_వ్యక్తిగత(స్థిరరాశి అక్షరం *ktype, నిర్మాణం sshbuf *b,
    నిర్మాణం sshkey *కీలకం)
{
	పూర్ణాంకం r;
	కొలత_t sklen = 0;
	u_char *ed25519_sk = ఖాళీ;

	ఒకవేళ ((r = ssh_ed25519_deserialize_ప్రజా(ఖాళీ, b, కీలకం)) != 0)
		వెళ్ళు బహిర్గతం;
	ఒకవేళ ((r = sshbuf_get_string(b, &ed25519_sk, &sklen)) != 0)
		వెళ్ళు బహిర్గతం;
	ఒకవేళ (sklen != ED25519_SK_SZ) {
		r = SSH_ERR_INVALID_FORMAT;
		వెళ్ళు బహిర్గతం;
	}
	కీలకం->ed25519_sk = ed25519_sk;
	ed25519_sk = ఖాళీ; /* transferred */
	/* success */
	r = 0;
 బహిర్గతం:
	freezero(ed25519_sk, sklen);
	తిరిగి r;
}

స్థిర పూర్ణాంకం
ssh_ed25519_sign(నిర్మాణం sshkey *కీలకం,
    u_char **sigp, కొలత_t *lenp,
    స్థిరరాశి u_char *దత్తాంశం, కొలత_t datalen,
    స్థిరరాశి అక్షరం *alg, స్థిరరాశి అక్షరం *sk_provider, స్థిరరాశి అక్షరం *sk_pin, u_int compat)
{
	u_char sig[crypto_sign_ed25519_బైట్లు];
	గుర్తులేని దీర్ఘ దీర్ఘ siglen = 0;
	పూర్ణాంకం r, ret;

	ఒకవేళ (lenp != ఖాళీ)
		*lenp = 0;
	ఒకవేళ (sigp != ఖాళీ)
		*sigp = ఖాళీ;

	ఒకవేళ (కీలకం == ఖాళీ ||
	    sshkey_type_plain(కీలకం->type) != కీలకం_ED25519 ||
	    కీలకం->ed25519_sk == ఖాళీ)
		తిరిగి SSH_ERR_INVALID_వాదం;

	ఒకవేళ ((ret = crypto_sign_ed25519_detached(sig, &siglen, దత్తాంశం, datalen,
	    కీలకం->ed25519_sk)) != 0 || siglen != పరిమాణం(sig)) {
		r = SSH_ERR_INVALID_వాదం; /* XXX better error? */
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((r = ssh_ed25519_encode_store_sig(sig, siglen,
	    sigp, lenp)) != 0)
		వెళ్ళు బహిర్గతం;

	/* success */
	r = 0;
 బహిర్గతం:
	explicit_bzero(sig, పరిమాణం(sig));
	తిరిగి r;
}

పూర్ణాంకం
ssh_ed25519_encode_store_sig(స్థిరరాశి u_char *sig, కొలత_t slen,
    u_char **sigp, కొలత_t *lenp)
{
	నిర్మాణం sshbuf *b = ఖాళీ;
	పూర్ణాంకం r = -1;
	కొలత_t len;

	ఒకవేళ (lenp != ఖాళీ)
		*lenp = 0;
	ఒకవేళ (sigp != ఖాళీ)
		*sigp = ఖాళీ;

	ఒకవేళ (slen != crypto_sign_ed25519_బైట్లు)
		తిరిగి SSH_ERR_INVALID_వాదం;

	/* encode signature */
	ఒకవేళ ((b = sshbuf_new()) == ఖాళీ) {
		r = SSH_ERR_ALLOC_FAIL;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((r = sshbuf_put_cstring(b, "ssh-ed25519")) != 0 ||
	    (r = sshbuf_put_string(b, sig, slen)) != 0)
		వెళ్ళు బహిర్గతం;
	len = sshbuf_len(b);
	ఒకవేళ (sigp != ఖాళీ) {
		ఒకవేళ ((*sigp = జ్ఞాపకం_ఇవ్వు(len)) == ఖాళీ) {
			r = SSH_ERR_ALLOC_FAIL;
			వెళ్ళు బహిర్గతం;
		}
		జ్ఞాపకం_నకలు(*sigp, sshbuf_ptr(b), len);
	}
	ఒకవేళ (lenp != ఖాళీ)
		*lenp = len;
	/* success */
	r = 0;
 బహిర్గతం:
	sshbuf_free(b);
	తిరిగి r;
}

స్థిర పూర్ణాంకం
ssh_ed25519_verify(స్థిరరాశి నిర్మాణం sshkey *కీలకం,
    స్థిరరాశి u_char *sig, కొలత_t siglen,
    స్థిరరాశి u_char *దత్తాంశం, కొలత_t dlen, స్థిరరాశి అక్షరం *alg, u_int compat,
    నిర్మాణం sshkey_sig_details **detailsp)
{
	నిర్మాణం sshbuf *b = ఖాళీ;
	అక్షరం *ktype = ఖాళీ;
	స్థిరరాశి u_char *sigblob;
	కొలత_t len;
	పూర్ణాంకం r, ret;

	ఒకవేళ (కీలకం == ఖాళీ ||
	    sshkey_type_plain(కీలకం->type) != కీలకం_ED25519 ||
	    కీలకం->ed25519_pk == ఖాళీ ||
	    sig == ఖాళీ || siglen == 0)
		తిరిగి SSH_ERR_INVALID_వాదం;

	ఒకవేళ ((b = sshbuf_from(sig, siglen)) == ఖాళీ)
		తిరిగి SSH_ERR_ALLOC_FAIL;
	ఒకవేళ ((r = sshbuf_get_cstring(b, &ktype, ఖాళీ)) != 0 ||
	    (r = sshbuf_get_string_ప్రత్యక్ష(b, &sigblob, &len)) != 0)
		వెళ్ళు బహిర్గతం;
	ఒకవేళ (strcmp("ssh-ed25519", ktype) != 0) {
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
	ఒకవేళ ((ret = crypto_sign_ed25519_verify_detached(sigblob, దత్తాంశం, dlen,
	    కీలకం->ed25519_pk)) != 0) {
		debug2_f("crypto_sign_ed25519_verify_detached failed: %d", ret);
	}
	ఒకవేళ (ret != 0) {
		r = SSH_ERR_SIGNATURE_INVALID;
		వెళ్ళు బహిర్గతం;
	}
	/* success */
	r = 0;
 బహిర్గతం:
	sshbuf_free(b);
	విడుదల(ktype);
	తిరిగి r;
}

/* NB. not static; used by ED25519-SK */
స్థిరరాశి నిర్మాణం sshkey_impl_funcs sshkey_ed25519_funcs = {
	/* .size = */		ఖాళీ,
	/* .alloc = */		ఖాళీ,
	/* .cleanup = */	ssh_ed25519_cleanup,
	/* .equal = */		ssh_ed25519_equal,
	/* .ssh_serialize_public = */ ssh_ed25519_serialize_ప్రజా,
	/* .ssh_deserialize_public = */ ssh_ed25519_deserialize_ప్రజా,
	/* .ssh_serialize_private = */ ssh_ed25519_serialize_వ్యక్తిగత,
	/* .ssh_deserialize_private = */ ssh_ed25519_deserialize_వ్యక్తిగత,
	/* .generate = */	ssh_ed25519_generate,
	/* .copy_public = */	ssh_ed25519_copy_ప్రజా,
	/* .sign = */		ssh_ed25519_sign,
	/* .verify = */		ssh_ed25519_verify,
};

స్థిరరాశి నిర్మాణం sshkey_impl sshkey_ed25519_impl = {
	/* .name = */		"ssh-ed25519",
	/* .shortname = */	"ED25519",
	/* .sigalg = */		ఖాళీ,
	/* .type = */		కీలకం_ED25519,
	/* .nid = */		0,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	256,
	/* .funcs = */		&sshkey_ed25519_funcs,
};

స్థిరరాశి నిర్మాణం sshkey_impl sshkey_ed25519_cert_impl = {
	/* .name = */		"ssh-ed25519-cert-v01@openssh.com",
	/* .shortname = */	"ED25519-CERT",
	/* .sigalg = */		ఖాళీ,
	/* .type = */		కీలకం_ED25519_CERT,
	/* .nid = */		0,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	256,
	/* .funcs = */		&sshkey_ed25519_funcs,
};
