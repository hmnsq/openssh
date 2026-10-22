/* $OpenBSD: ssh-ecdsa-sk.c,v 1.21 2026/02/06 22:59:18 dtucker Exp $ */
/*
 * Copyright (c) 2000 Markus Friedl.  All rights reserved.
 * Copyright (c) 2010 Damien Miller.  All rights reserved.
 * Copyright (c) 2019 Google Inc.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/* #define DEBUG_SK 1 */

#అన్తర్భావ "includes.h"

#అన్తర్భావ <sys/types.h>

#నిర్వచితమైతే WITH_OPENSSL
#అన్తర్భావ "openbsd-compat/openssl-compat.h"
#అన్తర్భావ <openssl/bn.h>
#అన్తర్భావ <openssl/ec.h>
#అన్తర్భావ <openssl/ecdsa.h>
#అన్తర్భావ <openssl/evp.h>

#అన్తర్భావ <string.h>
#అన్తర్భావ <stdio.h> /* needed for DEBUG_SK only */

#అన్తర్భావ "sshbuf.h"
#అన్తర్భావ "ssherr.h"
#అన్తర్భావ "digest.h"
#నిర్వచించు SSHKEY_అంతర్గత
#అన్తర్భావ "sshkey.h"

/* Reuse some ECDSA internals */
బాహ్య నిర్మాణం sshkey_impl_funcs sshkey_ecdsa_funcs;

స్థిర శూన్య
ssh_ecdsa_sk_cleanup(నిర్మాణం sshkey *k)
{
	sshkey_sk_cleanup(k);
	sshkey_ecdsa_funcs.cleanup(k);
}

స్థిర పూర్ణాంకం
ssh_ecdsa_sk_equal(స్థిరరాశి నిర్మాణం sshkey *a, స్థిరరాశి నిర్మాణం sshkey *b)
{
	ఒకవేళ (!sshkey_sk_fields_equal(a, b))
		తిరిగి 0;
	ఒకవేళ (!sshkey_ecdsa_funcs.equal(a, b))
		తిరిగి 0;
	తిరిగి 1;
}

స్థిర పూర్ణాంకం
ssh_ecdsa_sk_serialize_ప్రజా(స్థిరరాశి నిర్మాణం sshkey *కీలకం, నిర్మాణం sshbuf *b,
    గణన sshkey_serialize_rep opts)
{
	పూర్ణాంకం r;

	ఒకవేళ ((r = sshkey_ecdsa_funcs.serialize_ప్రజా(కీలకం, b, opts)) != 0)
		తిరిగి r;
	ఒకవేళ ((r = sshkey_serialize_sk(కీలకం, b)) != 0)
		తిరిగి r;

	తిరిగి 0;
}

స్థిర పూర్ణాంకం
ssh_ecdsa_sk_serialize_వ్యక్తిగత(స్థిరరాశి నిర్మాణం sshkey *కీలకం, నిర్మాణం sshbuf *b,
    గణన sshkey_serialize_rep opts)
{
	పూర్ణాంకం r;

	ఒకవేళ (!sshkey_is_cert(కీలకం)) {
		ఒకవేళ ((r = sshkey_ecdsa_funcs.serialize_ప్రజా(కీలకం,
		    b, opts)) != 0)
			తిరిగి r;
	}
	ఒకవేళ ((r = sshkey_serialize_వ్యక్తిగత_sk(కీలకం, b)) != 0)
		తిరిగి r;

	తిరిగి 0;
}

స్థిర పూర్ణాంకం
ssh_ecdsa_sk_copy_ప్రజా(స్థిరరాశి నిర్మాణం sshkey *from, నిర్మాణం sshkey *గమ్యం)
{
	పూర్ణాంకం r;

	ఒకవేళ ((r = sshkey_ecdsa_funcs.copy_ప్రజా(from, గమ్యం)) != 0)
		తిరిగి r;
	ఒకవేళ ((r = sshkey_copy_ప్రజా_sk(from, గమ్యం)) != 0)
		తిరిగి r;
	తిరిగి 0;
}

స్థిర పూర్ణాంకం
ssh_ecdsa_sk_deserialize_ప్రజా(స్థిరరాశి అక్షరం *ktype, నిర్మాణం sshbuf *b,
    నిర్మాణం sshkey *కీలకం)
{
	పూర్ణాంకం r;

	ఒకవేళ ((r = sshkey_ecdsa_funcs.deserialize_ప్రజా(ktype, b, కీలకం)) != 0)
		తిరిగి r;
	ఒకవేళ ((r = sshkey_deserialize_sk(b, కీలకం)) != 0)
		తిరిగి r;
	తిరిగి 0;
}

స్థిర పూర్ణాంకం
ssh_ecdsa_sk_deserialize_వ్యక్తిగత(స్థిరరాశి అక్షరం *ktype, నిర్మాణం sshbuf *b,
    నిర్మాణం sshkey *కీలకం)
{
	పూర్ణాంకం r;

	ఒకవేళ (!sshkey_is_cert(కీలకం)) {
		ఒకవేళ ((r = sshkey_ecdsa_funcs.deserialize_ప్రజా(ktype,
		    b, కీలకం)) != 0)
			తిరిగి r;
	}
	ఒకవేళ ((r = sshkey_వ్యక్తిగత_deserialize_sk(b, కీలకం)) != 0)
		తిరిగి r;

	తిరిగి 0;
}

/*
 * Check FIDO/W3C webauthn signatures clientData field against the expected
 * format and prepare a hash of it for use in signature verification.
 *
 * webauthn signatures do not sign the hash of the message directly, but
 * instead sign a JSON-like "clientData" wrapper structure that contains the
 * message hash along with a other information.
 *
 * Fortunately this structure has a fixed format so it is possible to verify
 * that the hash of the signed message is present within the clientData
 * structure without needing to implement any JSON parsing.
 */
స్థిర పూర్ణాంకం
webauthn_check_prepare_hash(స్థిరరాశి u_char *దత్తాంశం, కొలత_t datalen,
    స్థిరరాశి అక్షరం *origin, స్థిరరాశి నిర్మాణం sshbuf *wrapper,
    uint8_t flags, స్థిరరాశి నిర్మాణం sshbuf *extensions,
    u_char *msghash, కొలత_t msghashlen)
{
	పూర్ణాంకం r = SSH_ERR_అంతర్గత_ERROR;
	నిర్మాణం sshbuf *chall = ఖాళీ, *m = ఖాళీ;

	ఒకవేళ ((m = sshbuf_new()) == ఖాళీ ||
	    (chall = sshbuf_from(దత్తాంశం, datalen)) == ఖాళీ) {
		r = SSH_ERR_ALLOC_FAIL;
		వెళ్ళు బహిర్గతం;
	}
	/*
	 * Ensure origin contains no quote character and that the flags are
	 * consistent with what we received
	 */
	ఒకవేళ (strchr(origin, '\"') != ఖాళీ ||
	    (flags & 0x40) != 0 /* AD */ ||
	    ((flags & 0x80) == 0 /* ED */) != (sshbuf_len(extensions) == 0)) {
		r = SSH_ERR_INVALID_FORMAT;
		వెళ్ళు బహిర్గతం;
	}

	/*
	 * Prepare the preamble to clientData that we expect, poking the
	 * challenge and origin into their canonical positions in the
	 * structure. The crossOrigin flag and any additional extension
	 * fields present are ignored.
	 */
#నిర్వచించు WEBAUTHN_0	"{\"type\":\"webauthn.get\",\"challenge\":\""
#నిర్వచించు WEBAUTHN_1	"\",\"origin\":\""
#నిర్వచించు WEBAUTHN_2	"\""
	ఒకవేళ ((r = sshbuf_put(m, WEBAUTHN_0, పరిమాణం(WEBAUTHN_0) - 1)) != 0 ||
	    (r = sshbuf_dtourlb64(chall, m, 0)) != 0 ||
	    (r = sshbuf_put(m, WEBAUTHN_1, పరిమాణం(WEBAUTHN_1) - 1)) != 0 ||
	    (r = sshbuf_put(m, origin, అక్షరశ్రేణి_పొడవు(origin))) != 0 ||
	    (r = sshbuf_put(m, WEBAUTHN_2, పరిమాణం(WEBAUTHN_2) - 1)) != 0)
		వెళ్ళు బహిర్గతం;
#నిర్వచితమైతే DEBUG_SK
	fprintf(stderr, "%s: received origin: %s\n", __func__, origin);
	fprintf(stderr, "%s: received clientData:\n", __func__);
	sshbuf_dump(wrapper, stderr);
	fprintf(stderr, "%s: expected clientData preamble:\n", __func__);
	sshbuf_dump(m, stderr);
#అయితే_ముగింపు
	/* Check that the supplied clientData has the preamble we expect */
	ఒకవేళ ((r = sshbuf_cmp(wrapper, 0, sshbuf_ptr(m), sshbuf_len(m))) != 0)
		వెళ్ళు బహిర్గతం;

	/* Prepare hash of clientData */
	ఒకవేళ ((r = ssh_digest_బఫరు(SSH_DIGEST_SHA256, wrapper,
	    msghash, msghashlen)) != 0)
		వెళ్ళు బహిర్గతం;

	/* success */
	r = 0;
 బహిర్గతం:
	sshbuf_free(chall);
	sshbuf_free(m);
	తిరిగి r;
}

స్థిర పూర్ణాంకం
ssh_ecdsa_sk_verify(స్థిరరాశి నిర్మాణం sshkey *కీలకం,
    స్థిరరాశి u_char *sig, కొలత_t siglen,
    స్థిరరాశి u_char *దత్తాంశం, కొలత_t dlen, స్థిరరాశి అక్షరం *alg, u_int compat,
    నిర్మాణం sshkey_sig_details **detailsp)
{
	ECDSA_SIG *esig = ఖాళీ;
	EVP_MD_CTX *md_ctx = ఖాళీ;
	BIGNUM *sig_r = ఖాళీ, *sig_s = ఖాళీ;
	u_char sig_flags;
	u_char msghash[32], apphash[32];
	u_int sig_counter;
	u_char *sigb = ఖాళీ, *cp;
	పూర్ణాంకం is_webauthn = 0, ret = SSH_ERR_అంతర్గత_ERROR, len = 0;
	నిర్మాణం sshbuf *b = ఖాళీ, *sigbuf = ఖాళీ, *original_signed = ఖాళీ;
	నిర్మాణం sshbuf *webauthn_wrapper = ఖాళీ, *webauthn_exts = ఖాళీ;
	అక్షరం *ktype = ఖాళీ, *webauthn_origin = ఖాళీ;
	నిర్మాణం sshkey_sig_details *details = ఖాళీ;
#నిర్వచితమైతే DEBUG_SK
	అక్షరం *tmp = ఖాళీ;
#అయితే_ముగింపు

	ఒకవేళ (detailsp != ఖాళీ)
		*detailsp = ఖాళీ;
	ఒకవేళ (కీలకం == ఖాళీ || కీలకం->pkey == ఖాళీ ||
	    sshkey_type_plain(కీలకం->type) != కీలకం_ECDSA_SK ||
	    sig == ఖాళీ || siglen == 0)
		తిరిగి SSH_ERR_INVALID_వాదం;

	ఒకవేళ (కీలకం->ecdsa_nid != NID_X9_62_prime256v1)
		తిరిగి SSH_ERR_అంతర్గత_ERROR;

	/* fetch signature */
	ఒకవేళ ((b = sshbuf_from(sig, siglen)) == ఖాళీ)
		తిరిగి SSH_ERR_ALLOC_FAIL;
	ఒకవేళ ((details = సున్నా_జ్ఞాపకం_ఇవ్వు(1, పరిమాణం(*details))) == ఖాళీ) {
		ret = SSH_ERR_ALLOC_FAIL;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ (sshbuf_get_cstring(b, &ktype, ఖాళీ) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ (strcmp(ktype, "webauthn-sk-ecdsa-sha2-nistp256@openssh.com") == 0 ||
	    strcmp(ktype, "webauthn-sk-ecdsa-sha2-nistp256-cert-v01@openssh.com")
	      == 0)
		is_webauthn = 1;
	లేకపోతే ఒకవేళ (strcmp(ktype, "sk-ecdsa-sha2-nistp256@openssh.com") != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ (sshbuf_froms(b, &sigbuf) != 0 ||
	    sshbuf_get_u8(b, &sig_flags) != 0 ||
	    sshbuf_get_u32(b, &sig_counter) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ (is_webauthn) {
		ఒకవేళ (sshbuf_get_cstring(b, &webauthn_origin, ఖాళీ) != 0 ||
		    sshbuf_froms(b, &webauthn_wrapper) != 0 ||
		    sshbuf_froms(b, &webauthn_exts) != 0) {
			ret = SSH_ERR_INVALID_FORMAT;
			వెళ్ళు బహిర్గతం;
		}
	}
	ఒకవేళ (sshbuf_len(b) != 0) {
		ret = SSH_ERR_UNEXPECTED_TRAILING_దత్తాంశం;
		వెళ్ళు బహిర్గతం;
	}

	/* parse signature */
	ఒకవేళ (sshbuf_get_bignum2(sigbuf, &sig_r) != 0 ||
	    sshbuf_get_bignum2(sigbuf, &sig_s) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ (sshbuf_len(sigbuf) != 0) {
		ret = SSH_ERR_UNEXPECTED_TRAILING_దత్తాంశం;
		వెళ్ళు బహిర్గతం;
	}

#నిర్వచితమైతే DEBUG_SK
	fprintf(stderr, "%s: data: (len %zu)\n", __func__, dlen);
	/* sshbuf_dump_data(data, datalen, stderr); */
	fprintf(stderr, "%s: sig_r: %s\n", __func__, (tmp = BN_bn2hex(sig_r)));
	విడుదల(tmp);
	fprintf(stderr, "%s: sig_s: %s\n", __func__, (tmp = BN_bn2hex(sig_s)));
	విడుదల(tmp);
	fprintf(stderr, "%s: sig_flags = 0x%02x, sig_counter = %u\n",
	    __func__, sig_flags, sig_counter);
	ఒకవేళ (is_webauthn) {
		fprintf(stderr, "%s: webauthn origin: %s\n", __func__,
		    webauthn_origin);
		fprintf(stderr, "%s: webauthn_wrapper:\n", __func__);
		sshbuf_dump(webauthn_wrapper, stderr);
	}
#అయితే_ముగింపు
	ఒకవేళ ((esig = ECDSA_SIG_new()) == ఖాళీ) {
		ret = SSH_ERR_ALLOC_FAIL;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ (!ECDSA_SIG_set0(esig, sig_r, sig_s)) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		వెళ్ళు బహిర్గతం;
	}
	sig_r = sig_s = ఖాళీ; /* transferred */

	/* Reconstruct data that was supposedly signed */
	ఒకవేళ ((original_signed = sshbuf_new()) == ఖాళీ) {
		ret = SSH_ERR_ALLOC_FAIL;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ (is_webauthn) {
		ఒకవేళ ((ret = webauthn_check_prepare_hash(దత్తాంశం, dlen,
		    webauthn_origin, webauthn_wrapper, sig_flags, webauthn_exts,
		    msghash, పరిమాణం(msghash))) != 0)
			వెళ్ళు బహిర్గతం;
	} లేకపోతే ఒకవేళ ((ret = ssh_digest_జ్ఞాపకం(SSH_DIGEST_SHA256, దత్తాంశం, dlen,
	    msghash, పరిమాణం(msghash))) != 0)
		వెళ్ళు బహిర్గతం;
	/* Application value is hashed before signature */
	ఒకవేళ ((ret = ssh_digest_జ్ఞాపకం(SSH_DIGEST_SHA256, కీలకం->sk_application,
	    అక్షరశ్రేణి_పొడవు(కీలకం->sk_application), apphash, పరిమాణం(apphash))) != 0)
		వెళ్ళు బహిర్గతం;
#నిర్వచితమైతే DEBUG_SK
	fprintf(stderr, "%s: hashed application:\n", __func__);
	sshbuf_dump_దత్తాంశం(apphash, పరిమాణం(apphash), stderr);
	fprintf(stderr, "%s: hashed message:\n", __func__);
	sshbuf_dump_దత్తాంశం(msghash, పరిమాణం(msghash), stderr);
#అయితే_ముగింపు
	ఒకవేళ ((ret = sshbuf_put(original_signed,
	    apphash, పరిమాణం(apphash))) != 0 ||
	    (ret = sshbuf_put_u8(original_signed, sig_flags)) != 0 ||
	    (ret = sshbuf_put_u32(original_signed, sig_counter)) != 0 ||
	    (ret = sshbuf_putb(original_signed, webauthn_exts)) != 0 ||
	    (ret = sshbuf_put(original_signed, msghash, పరిమాణం(msghash))) != 0)
		వెళ్ళు బహిర్గతం;
	details->sk_counter = sig_counter;
	details->sk_flags = sig_flags;
#నిర్వచితమైతే DEBUG_SK
	fprintf(stderr, "%s: signed buf:\n", __func__);
	sshbuf_dump(original_signed, stderr);
#అయితే_ముగింపు

	ఒకవేళ ((md_ctx = EVP_MD_CTX_new()) == ఖాళీ) {
		ret = SSH_ERR_ALLOC_FAIL;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((len = i2d_ECDSA_SIG(esig, ఖాళీ)) <= 0) {
		len = 0;
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((sigb = సున్నా_జ్ఞాపకం_ఇవ్వు(1, len)) == ఖాళీ) {
		ret = SSH_ERR_ALLOC_FAIL;
		వెళ్ళు బహిర్గతం;
	}
	cp = sigb; /* ASN1_item_i2d increments the pointer past the object */
	ఒకవేళ (i2d_ECDSA_SIG(esig, &cp) != len) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		వెళ్ళు బహిర్గతం;
	}
#నిర్వచితమైతే DEBUG_SK
	fprintf(stderr, "%s: signed hash:\n", __func__);
	sshbuf_dump_దత్తాంశం(sigb, len, stderr);
#అయితే_ముగింపు
	/* Verify it */
	ఒకవేళ (EVP_DigestVerifyInit(md_ctx, ఖాళీ, EVP_sha256(), ఖాళీ,
	    కీలకం->pkey) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		వెళ్ళు బహిర్గతం;
	}
	ఎంపిక (EVP_DigestVerify(md_ctx, sigb, len,
	    sshbuf_ptr(original_signed), sshbuf_len(original_signed))) {
	స్థితి 1:
		ret = 0;
		ఆపు;
	స్థితి 0:
		ret = SSH_ERR_SIGNATURE_INVALID;
		వెళ్ళు బహిర్గతం;
	అప్రమేయ:
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		వెళ్ళు బహిర్గతం;
	}
	/* success */
	ఒకవేళ (detailsp != ఖాళీ) {
		*detailsp = details;
		details = ఖాళీ;
	}
 బహిర్గతం:
	explicit_bzero(&sig_flags, పరిమాణం(sig_flags));
	explicit_bzero(&sig_counter, పరిమాణం(sig_counter));
	explicit_bzero(msghash, పరిమాణం(msghash));
	explicit_bzero(apphash, పరిమాణం(apphash));
	sshkey_sig_details_free(details);
	sshbuf_free(webauthn_wrapper);
	sshbuf_free(webauthn_exts);
	విడుదల(webauthn_origin);
	sshbuf_free(original_signed);
	sshbuf_free(sigbuf);
	sshbuf_free(b);
	ECDSA_SIG_free(esig);
	BN_clear_free(sig_r);
	BN_clear_free(sig_s);
	విడుదల(ktype);
	freezero(sigb, len);
	EVP_MD_CTX_free(md_ctx);
	తిరిగి ret;
}

స్థిర స్థిరరాశి నిర్మాణం sshkey_impl_funcs sshkey_ecdsa_sk_funcs = {
	/* .size = */		ఖాళీ,
	/* .alloc = */		ఖాళీ,
	/* .cleanup = */	ssh_ecdsa_sk_cleanup,
	/* .equal = */		ssh_ecdsa_sk_equal,
	/* .ssh_serialize_public = */ ssh_ecdsa_sk_serialize_ప్రజా,
	/* .ssh_deserialize_public = */ ssh_ecdsa_sk_deserialize_ప్రజా,
	/* .ssh_serialize_private = */ ssh_ecdsa_sk_serialize_వ్యక్తిగత,
	/* .ssh_deserialize_private = */ ssh_ecdsa_sk_deserialize_వ్యక్తిగత,
	/* .generate = */	ఖాళీ,
	/* .copy_public = */	ssh_ecdsa_sk_copy_ప్రజా,
	/* .sign = */		ఖాళీ,
	/* .verify = */		ssh_ecdsa_sk_verify,
};

స్థిరరాశి నిర్మాణం sshkey_impl sshkey_ecdsa_sk_impl = {
	/* .name = */		"sk-ecdsa-sha2-nistp256@openssh.com",
	/* .shortname = */	"ECDSA-SK",
	/* .sigalg = */		ఖాళీ,
	/* .type = */		కీలకం_ECDSA_SK,
	/* .nid = */		NID_X9_62_prime256v1,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	256,
	/* .funcs = */		&sshkey_ecdsa_sk_funcs,
};

స్థిరరాశి నిర్మాణం sshkey_impl sshkey_ecdsa_sk_cert_impl = {
	/* .name = */		"sk-ecdsa-sha2-nistp256-cert-v01@openssh.com",
	/* .shortname = */	"ECDSA-SK-CERT",
	/* .sigalg = */		ఖాళీ,
	/* .type = */		కీలకం_ECDSA_SK_CERT,
	/* .nid = */		NID_X9_62_prime256v1,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	256,
	/* .funcs = */		&sshkey_ecdsa_sk_funcs,
};

స్థిరరాశి నిర్మాణం sshkey_impl sshkey_ecdsa_sk_webauthn_impl = {
	/* .name = */		"webauthn-sk-ecdsa-sha2-nistp256@openssh.com",
	/* .shortname = */	"ECDSA-SK",
	/* .sigalg = */		ఖాళీ,
	/* .type = */		కీలకం_ECDSA_SK,
	/* .nid = */		NID_X9_62_prime256v1,
	/* .cert = */		0,
	/* .sigonly = */	1,
	/* .keybits = */	256,
	/* .funcs = */		&sshkey_ecdsa_sk_funcs,
};

స్థిరరాశి నిర్మాణం sshkey_impl sshkey_ecdsa_sk_webauthn_cert_impl = {
	/* .name = */		"webauthn-sk-ecdsa-sha2-nistp256-cert-v01@openssh.com",
	/* .shortname = */	"ECDSA-SK-CERT",
	/* .sigalg = */		ఖాళీ,
	/* .type = */		కీలకం_ECDSA_SK_CERT,
	/* .nid = */		NID_X9_62_prime256v1,
	/* .cert = */		1,
	/* .sigonly = */	1,
	/* .keybits = */	256,
	/* .funcs = */		&sshkey_ecdsa_sk_funcs,
};
#అయితే_ముగింపు /* WITH_OPENSSL */
