/* $OpenBSD: ssh-sk.c,v 1.41 2024/08/15 00:51:51 djm Exp $ */
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

/* #define DEBUG_SK 1 */

#అన్తర్భావ "includes.h"

#నిర్వచితమైతే ENABLE_SK

#అన్తర్భావ <dlfcn.h>
#అన్తర్భావ <stddef.h>
#అన్తర్భావ <stdint.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <stdio.h>

#నిర్వచితమైతే WITH_OPENSSL
#అన్తర్భావ <openssl/objects.h>
#అన్తర్భావ <openssl/ec.h>
#అన్తర్భావ <openssl/evp.h>
#అయితే_ముగింపు /* WITH_OPENSSL */

#అన్తర్భావ "log.h"
#అన్తర్భావ "misc.h"
#అన్తర్భావ "sshbuf.h"
#అన్తర్భావ "sshkey.h"
#అన్తర్భావ "ssherr.h"
#అన్తర్భావ "digest.h"

#అన్తర్భావ "ssh-sk.h"
#అన్తర్భావ "sk-api.h"
#అన్తర్భావ "crypto_api.h"

నిర్మాణం sshsk_provider {
	అక్షరం *మార్గం;
	శూన్య *dlhandle;

	/* Return the version of the middleware API */
	uint32_t (*sk_api_సంస్కరణ)(శూన్య);

	/* Enroll a U2F key (private key generation) */
	పూర్ణాంకం (*sk_enroll)(పూర్ణాంకం alg, స్థిరరాశి uint8_t *challenge,
	    కొలత_t challenge_len, స్థిరరాశి అక్షరం *application, uint8_t flags,
	    స్థిరరాశి అక్షరం *pin, నిర్మాణం sk_option **opts,
	    నిర్మాణం sk_enroll_response **enroll_response);

	/* Sign a challenge */
	పూర్ణాంకం (*sk_sign)(పూర్ణాంకం alg, స్థిరరాశి uint8_t *సందేశం_2, కొలత_t సందేశం_len_2,
	    స్థిరరాశి అక్షరం *application,
	    స్థిరరాశి uint8_t *కీలకం_handle, కొలత_t కీలకం_handle_len,
	    uint8_t flags, స్థిరరాశి అక్షరం *pin, నిర్మాణం sk_option **opts,
	    నిర్మాణం sk_sign_response **sign_response);

	/* Enumerate resident keys */
	పూర్ణాంకం (*sk_ఎక్కించు_resident_కీలకాలు)(స్థిరరాశి అక్షరం *pin, నిర్మాణం sk_option **opts,
	    నిర్మాణం sk_resident_కీలకం ***rks, కొలత_t *nrks);
};

/* Built-in version */
పూర్ణాంకం ssh_sk_enroll(పూర్ణాంకం alg, స్థిరరాశి uint8_t *challenge,
    కొలత_t challenge_len, స్థిరరాశి అక్షరం *application, uint8_t flags,
    స్థిరరాశి అక్షరం *pin, నిర్మాణం sk_option **opts,
    నిర్మాణం sk_enroll_response **enroll_response);
పూర్ణాంకం ssh_sk_sign(పూర్ణాంకం alg, స్థిరరాశి uint8_t *సందేశం_2, కొలత_t సందేశం_len_2,
    స్థిరరాశి అక్షరం *application,
    స్థిరరాశి uint8_t *కీలకం_handle, కొలత_t కీలకం_handle_len,
    uint8_t flags, స్థిరరాశి అక్షరం *pin, నిర్మాణం sk_option **opts,
    నిర్మాణం sk_sign_response **sign_response);
పూర్ణాంకం ssh_sk_ఎక్కించు_resident_కీలకాలు(స్థిరరాశి అక్షరం *pin, నిర్మాణం sk_option **opts,
    నిర్మాణం sk_resident_కీలకం ***rks, కొలత_t *nrks);

స్థిర శూన్య
sshsk_free(నిర్మాణం sshsk_provider *p)
{
	ఒకవేళ (p == ఖాళీ)
		తిరిగి;
	విడుదల(p->మార్గం);
	ఒకవేళ (p->dlhandle != ఖాళీ)
		dlclose(p->dlhandle);
	విడుదల(p);
}

స్థిర నిర్మాణం sshsk_provider *
sshsk_open(స్థిరరాశి అక్షరం *మార్గం)
{
	నిర్మాణం sshsk_provider *ret = ఖాళీ;
	uint32_t సంస్కరణ;

	ఒకవేళ (మార్గం == ఖాళీ || *మార్గం == '\0') {
		error("No FIDO SecurityKeyProvider specified");
		తిరిగి ఖాళీ;
	}
	ఒకవేళ ((ret = సున్నా_జ్ఞాపకం_ఇవ్వు(1, పరిమాణం(*ret))) == ఖాళీ) {
		error_f("calloc failed");
		తిరిగి ఖాళీ;
	}
	ఒకవేళ ((ret->మార్గం = strdup(మార్గం)) == ఖాళీ) {
		error_f("strdup failed");
		వెళ్ళు fail;
	}
	/* Skip the rest if we're using the linked in middleware */
	ఒకవేళ (strcasecmp(ret->మార్గం, "internal") == 0) {
#నిర్వచితమైతే ENABLE_SK_అంతర్గత
		ret->sk_enroll = ssh_sk_enroll;
		ret->sk_sign = ssh_sk_sign;
		ret->sk_ఎక్కించు_resident_కీలకాలు = ssh_sk_ఎక్కించు_resident_కీలకాలు;
		తిరిగి ret;
#లేకపోతే
		error("internal security key support not enabled");
		వెళ్ళు fail;
#అయితే_ముగింపు
	}
	ఒకవేళ (lib_కలిగియుంది_చిహ్నం(మార్గం, "sk_api_version") != 0) {
		error("provider %s is not an OpenSSH FIDO library", మార్గం);
		వెళ్ళు fail;
	}
	ఒకవేళ ((ret->dlhandle = dlopen(మార్గం, RTLD_NOW)) == ఖాళీ)
		fatal("Provider \"%s\" dlopen failed: %s", మార్గం, dlerror());
	ఒకవేళ ((ret->sk_api_సంస్కరణ = dlsym(ret->dlhandle,
	    "sk_api_version")) == ఖాళీ) {
		error("Provider \"%s\" dlsym(sk_api_version) failed: %s",
		    మార్గం, dlerror());
		వెళ్ళు fail;
	}
	సంస్కరణ = ret->sk_api_సంస్కరణ();
	debug_f("provider %s implements version 0x%08lx", ret->మార్గం,
	    (u_long)సంస్కరణ);
	ఒకవేళ ((సంస్కరణ & SSH_SK_సంస్కరణ_MAJOR_ముసుగు) != SSH_SK_సంస్కరణ_MAJOR) {
		error("Provider \"%s\" implements unsupported "
		    "version 0x%08lx (supported: 0x%08lx)",
		    మార్గం, (u_long)సంస్కరణ, (u_long)SSH_SK_సంస్కరణ_MAJOR);
		వెళ్ళు fail;
	}
	ఒకవేళ ((ret->sk_enroll = dlsym(ret->dlhandle, "sk_enroll")) == ఖాళీ) {
		error("Provider %s dlsym(sk_enroll) failed: %s",
		    మార్గం, dlerror());
		వెళ్ళు fail;
	}
	ఒకవేళ ((ret->sk_sign = dlsym(ret->dlhandle, "sk_sign")) == ఖాళీ) {
		error("Provider \"%s\" dlsym(sk_sign) failed: %s",
		    మార్గం, dlerror());
		వెళ్ళు fail;
	}
	ఒకవేళ ((ret->sk_ఎక్కించు_resident_కీలకాలు = dlsym(ret->dlhandle,
	    "sk_load_resident_keys")) == ఖాళీ) {
		error("Provider \"%s\" dlsym(sk_load_resident_keys) "
		    "failed: %s", మార్గం, dlerror());
		వెళ్ళు fail;
	}
	/* success */
	తిరిగి ret;
fail:
	sshsk_free(ret);
	తిరిగి ఖాళీ;
}

స్థిర శూన్య
sshsk_free_enroll_response(నిర్మాణం sk_enroll_response *r)
{
	ఒకవేళ (r == ఖాళీ)
		తిరిగి;
	freezero(r->కీలకం_handle, r->కీలకం_handle_len);
	freezero(r->ప్రజా_కీలకం, r->ప్రజా_కీలకం_len);
	freezero(r->signature, r->signature_len);
	freezero(r->attestation_cert, r->attestation_cert_len);
	freezero(r->authdata, r->authdata_len);
	freezero(r, పరిమాణం(*r));
}

స్థిర శూన్య
sshsk_free_sign_response(నిర్మాణం sk_sign_response *r)
{
	ఒకవేళ (r == ఖాళీ)
		తిరిగి;
	freezero(r->sig_r, r->sig_r_len);
	freezero(r->sig_s, r->sig_s_len);
	freezero(r, పరిమాణం(*r));
}

#నిర్వచితమైతే WITH_OPENSSL
/* Assemble key from response */
స్థిర పూర్ణాంకం
sshsk_ecdsa_assemble(నిర్మాణం sk_enroll_response *resp, నిర్మాణం sshkey **keyp)
{
	నిర్మాణం sshkey *కీలకం = ఖాళీ;
	నిర్మాణం sshbuf *b = ఖాళీ;
	EC_కీలకం *ecdsa = ఖాళీ;
	EC_బిందువు *q = ఖాళీ;
	స్థిరరాశి EC_సమూహం *g = ఖాళీ;
	పూర్ణాంకం r;

	*keyp = ఖాళీ;
	ఒకవేళ ((కీలకం = sshkey_new(కీలకం_ECDSA_SK)) == ఖాళీ) {
		error_f("sshkey_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		వెళ్ళు బహిర్గతం;
	}
	కీలకం->ecdsa_nid = NID_X9_62_prime256v1;
	ఒకవేళ ((ecdsa = EC_కీలకం_new_by_వక్రం_name(కీలకం->ecdsa_nid)) == ఖాళీ ||
	    (g = EC_కీలకం_get0_సమూహం(ecdsa)) == ఖాళీ ||
	    (q = EC_బిందువు_new(g)) == ఖాళీ ||
	    (b = sshbuf_new()) == ఖాళీ) {
		error_f("allocation failed");
		r = SSH_ERR_ALLOC_FAIL;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((r = sshbuf_put_string(b,
	    resp->ప్రజా_కీలకం, resp->ప్రజా_కీలకం_len)) != 0) {
		error_fr(r, "sshbuf_put_string");
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((r = sshbuf_get_ec(b, q, g)) != 0) {
		error_fr(r, "parse");
		r = SSH_ERR_INVALID_FORMAT;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ (sshkey_ec_validate_ప్రజా(g, q) != 0) {
		error("Authenticator returned invalid ECDSA key");
		r = SSH_ERR_కీలకం_INVALID_EC_విలువ;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ (EC_కీలకం_సమితి_ప్రజా_కీలకం(ecdsa, q) != 1) {
		/* XXX assume it is a allocation error */
		error_f("allocation failed");
		r = SSH_ERR_ALLOC_FAIL;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((కీలకం->pkey = EVP_PKEY_new()) == ఖాళీ) {
		error_f("allocation failed");
		r = SSH_ERR_ALLOC_FAIL;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ (EVP_PKEY_set1_EC_కీలకం(కీలకం->pkey, ecdsa) != 1) {
		error_f("Assigning EC_KEY failed");
		r = SSH_ERR_LIBCRYPTO_ERROR;
		వెళ్ళు బహిర్గతం;
	}
	/* success */
	*keyp = కీలకం;
	కీలకం = ఖాళీ; /* transferred */
	r = 0;
 బహిర్గతం:
	sshkey_free(కీలకం);
	sshbuf_free(b);
	EC_కీలకం_free(ecdsa);
	EC_బిందువు_free(q);
	తిరిగి r;
}
#అయితే_ముగింపు /* WITH_OPENSSL */

స్థిర పూర్ణాంకం
sshsk_ed25519_assemble(నిర్మాణం sk_enroll_response *resp, నిర్మాణం sshkey **keyp)
{
	నిర్మాణం sshkey *కీలకం = ఖాళీ;
	పూర్ణాంకం r;

	*keyp = ఖాళీ;
	ఒకవేళ (resp->ప్రజా_కీలకం_len != ED25519_PK_SZ) {
		error_f("invalid size: %zu", resp->ప్రజా_కీలకం_len);
		r = SSH_ERR_INVALID_FORMAT;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((కీలకం = sshkey_new(కీలకం_ED25519_SK)) == ఖాళీ) {
		error_f("sshkey_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((కీలకం->ed25519_pk = జ్ఞాపకం_ఇవ్వు(ED25519_PK_SZ)) == ఖాళీ) {
		error_f("malloc failed");
		r = SSH_ERR_ALLOC_FAIL;
		వెళ్ళు బహిర్గతం;
	}
	జ్ఞాపకం_నకలు(కీలకం->ed25519_pk, resp->ప్రజా_కీలకం, ED25519_PK_SZ);
	/* success */
	*keyp = కీలకం;
	కీలకం = ఖాళీ; /* transferred */
	r = 0;
 బహిర్గతం:
	sshkey_free(కీలకం);
	తిరిగి r;
}

స్థిర పూర్ణాంకం
sshsk_కీలకం_from_response(పూర్ణాంకం alg, స్థిరరాశి అక్షరం *application, uint8_t flags,
    నిర్మాణం sk_enroll_response *resp, నిర్మాణం sshkey **keyp)
{
	నిర్మాణం sshkey *కీలకం = ఖాళీ;
	పూర్ణాంకం r = SSH_ERR_అంతర్గత_ERROR;

	*keyp = ఖాళీ;

	/* Check response validity */
	ఒకవేళ (resp->ప్రజా_కీలకం == ఖాళీ || resp->కీలకం_handle == ఖాళీ) {
		error_f("sk_enroll response invalid");
		r = SSH_ERR_INVALID_FORMAT;
		వెళ్ళు బహిర్గతం;
	}
	ఎంపిక (alg) {
#నిర్వచితమైతే WITH_OPENSSL
	స్థితి SSH_SK_ECDSA:
		ఒకవేళ ((r = sshsk_ecdsa_assemble(resp, &కీలకం)) != 0)
			వెళ్ళు బహిర్గతం;
		ఆపు;
#అయితే_ముగింపు /* WITH_OPENSSL */
	స్థితి SSH_SK_ED25519:
		ఒకవేళ ((r = sshsk_ed25519_assemble(resp, &కీలకం)) != 0)
			వెళ్ళు బహిర్గతం;
		ఆపు;
	అప్రమేయ:
		error_f("unsupported algorithm %d", alg);
		r = SSH_ERR_INVALID_వాదం;
		వెళ్ళు బహిర్గతం;
	}
	కీలకం->sk_flags = flags;
	ఒకవేళ ((కీలకం->sk_కీలకం_handle = sshbuf_new()) == ఖాళీ ||
	    (కీలకం->sk_reserved = sshbuf_new()) == ఖాళీ) {
		error_f("allocation failed");
		r = SSH_ERR_ALLOC_FAIL;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((కీలకం->sk_application = strdup(application)) == ఖాళీ) {
		error_f("strdup application failed");
		r = SSH_ERR_ALLOC_FAIL;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((r = sshbuf_put(కీలకం->sk_కీలకం_handle, resp->కీలకం_handle,
	    resp->కీలకం_handle_len)) != 0) {
		error_fr(r, "put key handle");
		వెళ్ళు బహిర్గతం;
	}
	/* success */
	r = 0;
	*keyp = కీలకం;
	కీలకం = ఖాళీ;
 బహిర్గతం:
	sshkey_free(కీలకం);
	తిరిగి r;
}

స్థిర పూర్ణాంకం
skerr_గమ్యం_ssherr(పూర్ణాంకం skerr)
{
	ఎంపిక (skerr) {
	స్థితి SSH_SK_ERR_UNSUPPORTED:
		తిరిగి SSH_ERR_FEATURE_UNSUPPORTED;
	స్థితి SSH_SK_ERR_PIN_REQUIRED:
		తిరిగి SSH_ERR_కీలకం_WRONG_PASSPHRASE;
	స్థితి SSH_SK_ERR_DEVICE_NOT_దొరికింది:
		తిరిగి SSH_ERR_DEVICE_NOT_దొరికింది;
	స్థితి SSH_SK_ERR_CREDENTIAL_EXISTS:
		తిరిగి SSH_ERR_కీలకం_BAD_PERMISSIONS;
	స్థితి SSH_SK_ERR_GENERAL:
	అప్రమేయ:
		తిరిగి SSH_ERR_INVALID_FORMAT;
	}
}

స్థిర శూన్య
sshsk_free_options(నిర్మాణం sk_option **opts)
{
	కొలత_t i;

	ఒకవేళ (opts == ఖాళీ)
		తిరిగి;
	కొరకు (i = 0; opts[i] != ఖాళీ; i++) {
		విడుదల(opts[i]->name);
		విడుదల(opts[i]->విలువ);
		విడుదల(opts[i]);
	}
	విడుదల(opts);
}

స్థిర పూర్ణాంకం
sshsk_కూడు_option(నిర్మాణం sk_option ***optsp, కొలత_t *noptsp,
    స్థిరరాశి అక్షరం *name, స్థిరరాశి అక్షరం *విలువ, uint8_t required)
{
	నిర్మాణం sk_option **opts = *optsp;
	కొలత_t nopts = *noptsp;

	ఒకవేళ ((opts = recallocarray(opts, nopts, nopts + 2, /* extra for NULL */
	    పరిమాణం(*opts))) == ఖాళీ) {
		error_f("array alloc failed");
		తిరిగి SSH_ERR_ALLOC_FAIL;
	}
	*optsp = opts;
	*noptsp = nopts + 1;
	ఒకవేళ ((opts[nopts] = సున్నా_జ్ఞాపకం_ఇవ్వు(1, పరిమాణం(**opts))) == ఖాళీ) {
		error_f("alloc failed");
		తిరిగి SSH_ERR_ALLOC_FAIL;
	}
	ఒకవేళ ((opts[nopts]->name = strdup(name)) == ఖాళీ ||
	    (opts[nopts]->విలువ = strdup(విలువ)) == ఖాళీ) {
		error_f("alloc failed");
		తిరిగి SSH_ERR_ALLOC_FAIL;
	}
	opts[nopts]->required = required;
	తిరిగి 0;
}

స్థిర పూర్ణాంకం
make_options(స్థిరరాశి అక్షరం *device, స్థిరరాశి అక్షరం *user_id,
    నిర్మాణం sk_option ***optsp)
{
	నిర్మాణం sk_option **opts = ఖాళీ;
	కొలత_t nopts = 0;
	పూర్ణాంకం r, ret = SSH_ERR_అంతర్గత_ERROR;

	ఒకవేళ (device != ఖాళీ &&
	    (r = sshsk_కూడు_option(&opts, &nopts, "device", device, 0)) != 0) {
		ret = r;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ (user_id != ఖాళీ &&
	    (r = sshsk_కూడు_option(&opts, &nopts, "user", user_id, 0)) != 0) {
		ret = r;
		వెళ్ళు బహిర్గతం;
	}
	/* success */
	*optsp = opts;
	opts = ఖాళీ;
	nopts = 0;
	ret = 0;
 బహిర్గతం:
	sshsk_free_options(opts);
	తిరిగి ret;
}


స్థిర పూర్ణాంకం
fill_attestation_blob(స్థిరరాశి నిర్మాణం sk_enroll_response *resp,
    నిర్మాణం sshbuf *attest)
{
	పూర్ణాంకం r;

	ఒకవేళ (attest == ఖాళీ)
		తిరిగి 0; /* nothing to do */
	ఒకవేళ ((r = sshbuf_put_cstring(attest, "ssh-sk-attest-v01")) != 0 ||
	    (r = sshbuf_put_string(attest,
	    resp->attestation_cert, resp->attestation_cert_len)) != 0 ||
	    (r = sshbuf_put_string(attest,
	    resp->signature, resp->signature_len)) != 0 ||
	    (r = sshbuf_put_string(attest,
	    resp->authdata, resp->authdata_len)) != 0 ||
	    (r = sshbuf_put_u32(attest, 0)) != 0 || /* resvd flags */
	    (r = sshbuf_put_string(attest, ఖాళీ, 0)) != 0 /* resvd */) {
		error_fr(r, "compose");
		తిరిగి r;
	}
	/* success */
	తిరిగి 0;
}

పూర్ణాంకం
sshsk_enroll(పూర్ణాంకం type, స్థిరరాశి అక్షరం *provider_మార్గం, స్థిరరాశి అక్షరం *device,
    స్థిరరాశి అక్షరం *application, స్థిరరాశి అక్షరం *userid, uint8_t flags,
    స్థిరరాశి అక్షరం *pin, నిర్మాణం sshbuf *challenge_buf,
    నిర్మాణం sshkey **keyp, నిర్మాణం sshbuf *attest)
{
	నిర్మాణం sshsk_provider *skp = ఖాళీ;
	నిర్మాణం sshkey *కీలకం = ఖాళీ;
	u_char randchall[32];
	స్థిరరాశి u_char *challenge;
	కొలత_t challenge_len;
	నిర్మాణం sk_enroll_response *resp = ఖాళీ;
	నిర్మాణం sk_option **opts = ఖాళీ;
	పూర్ణాంకం r = SSH_ERR_అంతర్గత_ERROR;
	పూర్ణాంకం alg;

	debug_f("provider \"%s\", device \"%s\", application \"%s\", "
	    "userid \"%s\", flags 0x%02x, challenge len %zu%s",
	    provider_మార్గం, device, application, userid, flags,
	    challenge_buf == ఖాళీ ? 0 : sshbuf_len(challenge_buf),
	    (pin != ఖాళీ && *pin != '\0') ? " with-pin" : "");

	*keyp = ఖాళీ;
	ఒకవేళ (attest)
		sshbuf_reset(attest);

	ఒకవేళ ((r = make_options(device, userid, &opts)) != 0)
		వెళ్ళు బహిర్గతం;

	ఎంపిక (type) {
#నిర్వచితమైతే WITH_OPENSSL
	స్థితి కీలకం_ECDSA_SK:
		alg = SSH_SK_ECDSA;
		ఆపు;
#అయితే_ముగింపు /* WITH_OPENSSL */
	స్థితి కీలకం_ED25519_SK:
		alg = SSH_SK_ED25519;
		ఆపు;
	అప్రమేయ:
		error_f("unsupported key type");
		r = SSH_ERR_INVALID_వాదం;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ (provider_మార్గం == ఖాళీ) {
		error_f("missing provider");
		r = SSH_ERR_INVALID_వాదం;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ (application == ఖాళీ || *application == '\0') {
		error_f("missing application");
		r = SSH_ERR_INVALID_వాదం;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ (challenge_buf == ఖాళీ) {
		debug_f("using random challenge");
		arc4random_buf(randchall, పరిమాణం(randchall));
		challenge = randchall;
		challenge_len = పరిమాణం(randchall);
	} లేకపోతే ఒకవేళ (sshbuf_len(challenge_buf) == 0) {
		error("Missing enrollment challenge");
		r = SSH_ERR_INVALID_వాదం;
		వెళ్ళు బహిర్గతం;
	} లేకపోతే {
		challenge = sshbuf_ptr(challenge_buf);
		challenge_len = sshbuf_len(challenge_buf);
		debug3_f("using explicit challenge len=%zd", challenge_len);
	}
	ఒకవేళ ((skp = sshsk_open(provider_మార్గం)) == ఖాళీ) {
		r = SSH_ERR_INVALID_FORMAT; /* XXX sshsk_open return code? */
		వెళ్ళు బహిర్గతం;
	}
	/* XXX validate flags? */
	/* enroll key */
	ఒకవేళ ((r = skp->sk_enroll(alg, challenge, challenge_len, application,
	    flags, pin, opts, &resp)) != 0) {
		debug_f("provider \"%s\" failure %d", provider_మార్గం, r);
		r = skerr_గమ్యం_ssherr(r);
		వెళ్ళు బహిర్గతం;
	}

	ఒకవేళ ((r = sshsk_కీలకం_from_response(alg, application, resp->flags,
	    resp, &కీలకం)) != 0)
		వెళ్ళు బహిర్గతం;

	/* Optionally fill in the attestation information */
	ఒకవేళ ((r = fill_attestation_blob(resp, attest)) != 0)
		వెళ్ళు బహిర్గతం;

	/* success */
	*keyp = కీలకం;
	కీలకం = ఖాళీ; /* transferred */
	r = 0;
 బహిర్గతం:
	sshsk_free_options(opts);
	sshsk_free(skp);
	sshkey_free(కీలకం);
	sshsk_free_enroll_response(resp);
	explicit_bzero(randchall, పరిమాణం(randchall));
	తిరిగి r;
}

#నిర్వచితమైతే WITH_OPENSSL
స్థిర పూర్ణాంకం
sshsk_ecdsa_sig(నిర్మాణం sk_sign_response *resp, నిర్మాణం sshbuf *sig)
{
	నిర్మాణం sshbuf *inner_sig = ఖాళీ;
	పూర్ణాంకం r = SSH_ERR_అంతర్గత_ERROR;

	/* Check response validity */
	ఒకవేళ (resp->sig_r == ఖాళీ || resp->sig_s == ఖాళీ) {
		error_f("sk_sign response invalid");
		r = SSH_ERR_INVALID_FORMAT;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((inner_sig = sshbuf_new()) == ఖాళీ) {
		r = SSH_ERR_ALLOC_FAIL;
		వెళ్ళు బహిర్గతం;
	}
	/* Prepare and append inner signature object */
	ఒకవేళ ((r = sshbuf_put_bignum2_బైట్లు(inner_sig,
	    resp->sig_r, resp->sig_r_len)) != 0 ||
	    (r = sshbuf_put_bignum2_బైట్లు(inner_sig,
	    resp->sig_s, resp->sig_s_len)) != 0) {
		error_fr(r, "compose inner");
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((r = sshbuf_put_stringb(sig, inner_sig)) != 0 ||
	    (r = sshbuf_put_u8(sig, resp->flags)) != 0 ||
	    (r = sshbuf_put_u32(sig, resp->counter)) != 0) {
		error_fr(r, "compose");
		వెళ్ళు బహిర్గతం;
	}
#నిర్వచితమైతే DEBUG_SK
	fprintf(stderr, "%s: sig_r:\n", __func__);
	sshbuf_dump_దత్తాంశం(resp->sig_r, resp->sig_r_len, stderr);
	fprintf(stderr, "%s: sig_s:\n", __func__);
	sshbuf_dump_దత్తాంశం(resp->sig_s, resp->sig_s_len, stderr);
	fprintf(stderr, "%s: inner:\n", __func__);
	sshbuf_dump(inner_sig, stderr);
#అయితే_ముగింపు
	r = 0;
 బహిర్గతం:
	sshbuf_free(inner_sig);
	తిరిగి r;
}
#అయితే_ముగింపు /* WITH_OPENSSL */

స్థిర పూర్ణాంకం
sshsk_ed25519_sig(నిర్మాణం sk_sign_response *resp, నిర్మాణం sshbuf *sig)
{
	పూర్ణాంకం r = SSH_ERR_అంతర్గత_ERROR;

	/* Check response validity */
	ఒకవేళ (resp->sig_r == ఖాళీ) {
		error_f("sk_sign response invalid");
		r = SSH_ERR_INVALID_FORMAT;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((r = sshbuf_put_string(sig,
	    resp->sig_r, resp->sig_r_len)) != 0 ||
	    (r = sshbuf_put_u8(sig, resp->flags)) != 0 ||
	    (r = sshbuf_put_u32(sig, resp->counter)) != 0) {
		error_fr(r, "compose");
		వెళ్ళు బహిర్గతం;
	}
#నిర్వచితమైతే DEBUG_SK
	fprintf(stderr, "%s: sig_r:\n", __func__);
	sshbuf_dump_దత్తాంశం(resp->sig_r, resp->sig_r_len, stderr);
#అయితే_ముగింపు
	r = 0;
 బహిర్గతం:
	తిరిగి r;
}

పూర్ణాంకం
sshsk_sign(స్థిరరాశి అక్షరం *provider_మార్గం, నిర్మాణం sshkey *కీలకం,
    u_char **sigp, కొలత_t *lenp, స్థిరరాశి u_char *దత్తాంశం, కొలత_t datalen,
    u_int compat, స్థిరరాశి అక్షరం *pin)
{
	నిర్మాణం sshsk_provider *skp = ఖాళీ;
	పూర్ణాంకం r = SSH_ERR_అంతర్గత_ERROR;
	పూర్ణాంకం type, alg;
	నిర్మాణం sk_sign_response *resp = ఖాళీ;
	నిర్మాణం sshbuf *inner_sig = ఖాళీ, *sig = ఖాళీ;
	నిర్మాణం sk_option **opts = ఖాళీ;

	debug_f("provider \"%s\", key %s, flags 0x%02x%s",
	    provider_మార్గం, sshkey_type(కీలకం), కీలకం->sk_flags,
	    (pin != ఖాళీ && *pin != '\0') ? " with-pin" : "");

	ఒకవేళ (sigp != ఖాళీ)
		*sigp = ఖాళీ;
	ఒకవేళ (lenp != ఖాళీ)
		*lenp = 0;
	type = sshkey_type_plain(కీలకం->type);
	ఎంపిక (type) {
#నిర్వచితమైతే WITH_OPENSSL
	స్థితి కీలకం_ECDSA_SK:
		alg = SSH_SK_ECDSA;
		ఆపు;
#అయితే_ముగింపు /* WITH_OPENSSL */
	స్థితి కీలకం_ED25519_SK:
		alg = SSH_SK_ED25519;
		ఆపు;
	అప్రమేయ:
		తిరిగి SSH_ERR_INVALID_వాదం;
	}
	ఒకవేళ (provider_మార్గం == ఖాళీ ||
	    కీలకం->sk_కీలకం_handle == ఖాళీ ||
	    కీలకం->sk_application == ఖాళీ || *కీలకం->sk_application == '\0') {
		r = SSH_ERR_INVALID_వాదం;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((skp = sshsk_open(provider_మార్గం)) == ఖాళీ) {
		r = SSH_ERR_INVALID_FORMAT; /* XXX sshsk_open return code? */
		వెళ్ళు బహిర్గతం;
	}
#నిర్వచితమైతే DEBUG_SK
	fprintf(stderr, "%s: sk_flags = 0x%02x, sk_application = \"%s\"\n",
	    __func__, కీలకం->sk_flags, కీలకం->sk_application);
	fprintf(stderr, "%s: sk_key_handle:\n", __func__);
	sshbuf_dump(కీలకం->sk_కీలకం_handle, stderr);
#అయితే_ముగింపు
	ఒకవేళ ((r = skp->sk_sign(alg, దత్తాంశం, datalen, కీలకం->sk_application,
	    sshbuf_ptr(కీలకం->sk_కీలకం_handle), sshbuf_len(కీలకం->sk_కీలకం_handle),
	    కీలకం->sk_flags, pin, opts, &resp)) != 0) {
		debug_f("sk_sign failed with code %d", r);
		r = skerr_గమ్యం_ssherr(r);
		వెళ్ళు బహిర్గతం;
	}
	/* Assemble signature */
	ఒకవేళ ((sig = sshbuf_new()) == ఖాళీ) {
		r = SSH_ERR_ALLOC_FAIL;
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((r = sshbuf_put_cstring(sig, sshkey_ssh_name_plain(కీలకం))) != 0) {
		error_fr(r, "compose outer");
		వెళ్ళు బహిర్గతం;
	}
	ఎంపిక (type) {
#నిర్వచితమైతే WITH_OPENSSL
	స్థితి కీలకం_ECDSA_SK:
		ఒకవేళ ((r = sshsk_ecdsa_sig(resp, sig)) != 0)
			వెళ్ళు బహిర్గతం;
		ఆపు;
#అయితే_ముగింపు /* WITH_OPENSSL */
	స్థితి కీలకం_ED25519_SK:
		ఒకవేళ ((r = sshsk_ed25519_sig(resp, sig)) != 0)
			వెళ్ళు బహిర్గతం;
		ఆపు;
	}
#నిర్వచితమైతే DEBUG_SK
	fprintf(stderr, "%s: sig_flags = 0x%02x, sig_counter = %u\n",
	    __func__, resp->flags, resp->counter);
	fprintf(stderr, "%s: data to sign:\n", __func__);
	sshbuf_dump_దత్తాంశం(దత్తాంశం, datalen, stderr);
	fprintf(stderr, "%s: sigbuf:\n", __func__);
	sshbuf_dump(sig, stderr);
#అయితే_ముగింపు
	ఒకవేళ (sigp != ఖాళీ) {
		ఒకవేళ ((*sigp = జ్ఞాపకం_ఇవ్వు(sshbuf_len(sig))) == ఖాళీ) {
			r = SSH_ERR_ALLOC_FAIL;
			వెళ్ళు బహిర్గతం;
		}
		జ్ఞాపకం_నకలు(*sigp, sshbuf_ptr(sig), sshbuf_len(sig));
	}
	ఒకవేళ (lenp != ఖాళీ)
		*lenp = sshbuf_len(sig);
	/* success */
	r = 0;
 బహిర్గతం:
	sshsk_free_options(opts);
	sshsk_free(skp);
	sshsk_free_sign_response(resp);
	sshbuf_free(sig);
	sshbuf_free(inner_sig);
	తిరిగి r;
}

స్థిర శూన్య
sshsk_free_sk_resident_కీలకాలు(నిర్మాణం sk_resident_కీలకం **rks, కొలత_t nrks)
{
	కొలత_t i;

	ఒకవేళ (nrks == 0 || rks == ఖాళీ)
		తిరిగి;
	కొరకు (i = 0; i < nrks; i++) {
		విడుదల(rks[i]->application);
		freezero(rks[i]->user_id, rks[i]->user_id_len);
		freezero(rks[i]->కీలకం.కీలకం_handle, rks[i]->కీలకం.కీలకం_handle_len);
		freezero(rks[i]->కీలకం.ప్రజా_కీలకం, rks[i]->కీలకం.ప్రజా_కీలకం_len);
		freezero(rks[i]->కీలకం.signature, rks[i]->కీలకం.signature_len);
		freezero(rks[i]->కీలకం.attestation_cert,
		    rks[i]->కీలకం.attestation_cert_len);
		freezero(rks[i], పరిమాణం(**rks));
	}
	విడుదల(rks);
}

స్థిర శూన్య
sshsk_free_resident_కీలకం(నిర్మాణం sshsk_resident_కీలకం *srk)
{
	ఒకవేళ (srk == ఖాళీ)
		తిరిగి;
	sshkey_free(srk->కీలకం);
	freezero(srk->user_id, srk->user_id_len);
	విడుదల(srk);
}


శూన్య
sshsk_free_resident_కీలకాలు(నిర్మాణం sshsk_resident_కీలకం **srks, కొలత_t nsrks)
{
	కొలత_t i;

	ఒకవేళ (srks == ఖాళీ || nsrks == 0)
		తిరిగి;

	కొరకు (i = 0; i < nsrks; i++)
		sshsk_free_resident_కీలకం(srks[i]);
	విడుదల(srks);
}

పూర్ణాంకం
sshsk_ఎక్కించు_resident(స్థిరరాశి అక్షరం *provider_మార్గం, స్థిరరాశి అక్షరం *device,
    స్థిరరాశి అక్షరం *pin, u_int flags, నిర్మాణం sshsk_resident_కీలకం ***srksp,
    కొలత_t *nsrksp)
{
	నిర్మాణం sshsk_provider *skp = ఖాళీ;
	పూర్ణాంకం r = SSH_ERR_అంతర్గత_ERROR;
	నిర్మాణం sk_resident_కీలకం **rks = ఖాళీ;
	కొలత_t i, nrks = 0, nsrks = 0;
	నిర్మాణం sshkey *కీలకం = ఖాళీ;
	నిర్మాణం sshsk_resident_కీలకం *srk = ఖాళీ, **srks = ఖాళీ, **tmp;
	uint8_t sk_flags;
	నిర్మాణం sk_option **opts = ఖాళీ;

	debug_f("provider \"%s\"%s", provider_మార్గం,
	    (pin != ఖాళీ && *pin != '\0') ? ", have-pin": "");

	ఒకవేళ (srksp == ఖాళీ || nsrksp == ఖాళీ)
		తిరిగి SSH_ERR_INVALID_వాదం;
	*srksp = ఖాళీ;
	*nsrksp = 0;

	ఒకవేళ ((r = make_options(device, ఖాళీ, &opts)) != 0)
		వెళ్ళు బహిర్గతం;
	ఒకవేళ ((skp = sshsk_open(provider_మార్గం)) == ఖాళీ) {
		r = SSH_ERR_INVALID_FORMAT; /* XXX sshsk_open return code? */
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((r = skp->sk_ఎక్కించు_resident_కీలకాలు(pin, opts, &rks, &nrks)) != 0) {
		error("Provider \"%s\" returned failure %d", provider_మార్గం, r);
		r = skerr_గమ్యం_ssherr(r);
		వెళ్ళు బహిర్గతం;
	}
	కొరకు (i = 0; i < nrks; i++) {
		debug3_f("rk %zu: slot %zu, alg %d, app \"%s\", uidlen %zu",
		    i, rks[i]->స్థానం, rks[i]->alg, rks[i]->application,
		    rks[i]->user_id_len);
		/* XXX need better filter here */
		ఒకవేళ (అక్షరశ్రేణి_పోలిక(rks[i]->application, "ssh:", 4) != 0)
			కొనసాగు;
		ఎంపిక (rks[i]->alg) {
		స్థితి SSH_SK_ECDSA:
		స్థితి SSH_SK_ED25519:
			ఆపు;
		అప్రమేయ:
			కొనసాగు;
		}
		sk_flags = SSH_SK_USER_PRESENCE_REQD|SSH_SK_RESIDENT_కీలకం;
		ఒకవేళ ((rks[i]->flags & SSH_SK_USER_VERIFICATION_REQD))
			sk_flags |= SSH_SK_USER_VERIFICATION_REQD;
		ఒకవేళ ((r = sshsk_కీలకం_from_response(rks[i]->alg,
		    rks[i]->application, sk_flags, &rks[i]->కీలకం, &కీలకం)) != 0)
			వెళ్ళు బహిర్గతం;
		ఒకవేళ ((srk = సున్నా_జ్ఞాపకం_ఇవ్వు(1, పరిమాణం(*srk))) == ఖాళీ) {
			error_f("calloc failed");
			r = SSH_ERR_ALLOC_FAIL;
			వెళ్ళు బహిర్గతం;
		}
		srk->కీలకం = కీలకం;
		కీలకం = ఖాళీ; /* transferred */
		ఒకవేళ ((srk->user_id = సున్నా_జ్ఞాపకం_ఇవ్వు(1, rks[i]->user_id_len)) == ఖాళీ) {
			error_f("calloc failed");
			r = SSH_ERR_ALLOC_FAIL;
			వెళ్ళు బహిర్గతం;
		}
		జ్ఞాపకం_నకలు(srk->user_id, rks[i]->user_id, rks[i]->user_id_len);
		srk->user_id_len = rks[i]->user_id_len;
		ఒకవేళ ((tmp = recallocarray(srks, nsrks, nsrks + 1,
		    పరిమాణం(*tmp))) == ఖాళీ) {
			error_f("recallocarray failed");
			r = SSH_ERR_ALLOC_FAIL;
			వెళ్ళు బహిర్గతం;
		}
		srks = tmp;
		srks[nsrks++] = srk;
		srk = ఖాళీ;
		/* XXX synthesise comment */
	}
	/* success */
	*srksp = srks;
	*nsrksp = nsrks;
	srks = ఖాళీ;
	nsrks = 0;
	r = 0;
 బహిర్గతం:
	sshsk_free_options(opts);
	sshsk_free(skp);
	sshsk_free_sk_resident_కీలకాలు(rks, nrks);
	sshkey_free(కీలకం);
	sshsk_free_resident_కీలకం(srk);
	sshsk_free_resident_కీలకాలు(srks, nsrks);
	తిరిగి r;
}

#అయితే_ముగింపు /* ENABLE_SK */
