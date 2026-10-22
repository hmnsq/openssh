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

#अन्तर्भाव "includes.h"

#यदि_परिभाषितम् ENABLE_SK

#अन्तर्भाव <dlfcn.h>
#अन्तर्भाव <stddef.h>
#अन्तर्भाव <stdint.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <stdio.h>

#यदि_परिभाषितम् WITH_OPENSSL
#अन्तर्भाव <openssl/objects.h>
#अन्तर्भाव <openssl/ec.h>
#अन्तर्भाव <openssl/evp.h>
#यदि_अन्तः /* WITH_OPENSSL */

#अन्तर्भाव "log.h"
#अन्तर्भाव "misc.h"
#अन्तर्भाव "sshbuf.h"
#अन्तर्भाव "sshkey.h"
#अन्तर्भाव "ssherr.h"
#अन्तर्भाव "digest.h"

#अन्तर्भाव "ssh-sk.h"
#अन्तर्भाव "sk-api.h"
#अन्तर्भाव "crypto_api.h"

संरचना sshsk_provider {
	वर्ण *मार्गः;
	शून्य *dlhandle;

	/* Return the version of the middleware API */
	uint32_t (*sk_api_संस्करणम्)(शून्य);

	/* Enroll a U2F key (private key generation) */
	पूर्णाङ्क (*sk_enroll)(पूर्णाङ्क alg, ध्रुव uint8_t *challenge,
	    आकार_t challenge_len, ध्रुव वर्ण *application, uint8_t flags,
	    ध्रुव वर्ण *pin, संरचना sk_option **opts,
	    संरचना sk_enroll_response **enroll_response);

	/* Sign a challenge */
	पूर्णाङ्क (*sk_sign)(पूर्णाङ्क alg, ध्रुव uint8_t *सन्देशः_2, आकार_t सन्देशः_len_2,
	    ध्रुव वर्ण *application,
	    ध्रुव uint8_t *कुञ्चिका_handle, आकार_t कुञ्चिका_handle_len,
	    uint8_t flags, ध्रुव वर्ण *pin, संरचना sk_option **opts,
	    संरचना sk_sign_response **sign_response);

	/* Enumerate resident keys */
	पूर्णाङ्क (*sk_आरोपय_resident_कुञ्चिकाः)(ध्रुव वर्ण *pin, संरचना sk_option **opts,
	    संरचना sk_resident_कुञ्चिका ***rks, आकार_t *nrks);
};

/* Built-in version */
पूर्णाङ्क ssh_sk_enroll(पूर्णाङ्क alg, ध्रुव uint8_t *challenge,
    आकार_t challenge_len, ध्रुव वर्ण *application, uint8_t flags,
    ध्रुव वर्ण *pin, संरचना sk_option **opts,
    संरचना sk_enroll_response **enroll_response);
पूर्णाङ्क ssh_sk_sign(पूर्णाङ्क alg, ध्रुव uint8_t *सन्देशः_2, आकार_t सन्देशः_len_2,
    ध्रुव वर्ण *application,
    ध्रुव uint8_t *कुञ्चिका_handle, आकार_t कुञ्चिका_handle_len,
    uint8_t flags, ध्रुव वर्ण *pin, संरचना sk_option **opts,
    संरचना sk_sign_response **sign_response);
पूर्णाङ्क ssh_sk_आरोपय_resident_कुञ्चिकाः(ध्रुव वर्ण *pin, संरचना sk_option **opts,
    संरचना sk_resident_कुञ्चिका ***rks, आकार_t *nrks);

स्थिर शून्य
sshsk_free(संरचना sshsk_provider *p)
{
	यदि (p == रिक्त)
		प्रत्यागम;
	मुक्त(p->मार्गः);
	यदि (p->dlhandle != रिक्त)
		dlclose(p->dlhandle);
	मुक्त(p);
}

स्थिर संरचना sshsk_provider *
sshsk_open(ध्रुव वर्ण *मार्गः)
{
	संरचना sshsk_provider *ret = रिक्त;
	uint32_t संस्करणम्;

	यदि (मार्गः == रिक्त || *मार्गः == '\0') {
		error("No FIDO SecurityKeyProvider specified");
		प्रत्यागम रिक्त;
	}
	यदि ((ret = शून्यस्मृतिं_देहि(1, परिमाण(*ret))) == रिक्त) {
		error_f("calloc failed");
		प्रत्यागम रिक्त;
	}
	यदि ((ret->मार्गः = strdup(मार्गः)) == रिक्त) {
		error_f("strdup failed");
		गच्छ fail;
	}
	/* Skip the rest if we're using the linked in middleware */
	यदि (strcasecmp(ret->मार्गः, "internal") == 0) {
#यदि_परिभाषितम् ENABLE_SK_आन्तरिकम्
		ret->sk_enroll = ssh_sk_enroll;
		ret->sk_sign = ssh_sk_sign;
		ret->sk_आरोपय_resident_कुञ्चिकाः = ssh_sk_आरोपय_resident_कुञ्चिकाः;
		प्रत्यागम ret;
#अन्यथा
		error("internal security key support not enabled");
		गच्छ fail;
#यदि_अन्तः
	}
	यदि (lib_अन्तर्भवति_चिह्नम्(मार्गः, "sk_api_version") != 0) {
		error("provider %s is not an OpenSSH FIDO library", मार्गः);
		गच्छ fail;
	}
	यदि ((ret->dlhandle = dlopen(मार्गः, RTLD_NOW)) == रिक्त)
		fatal("Provider \"%s\" dlopen failed: %s", मार्गः, dlerror());
	यदि ((ret->sk_api_संस्करणम् = dlsym(ret->dlhandle,
	    "sk_api_version")) == रिक्त) {
		error("Provider \"%s\" dlsym(sk_api_version) failed: %s",
		    मार्गः, dlerror());
		गच्छ fail;
	}
	संस्करणम् = ret->sk_api_संस्करणम्();
	debug_f("provider %s implements version 0x%08lx", ret->मार्गः,
	    (u_long)संस्करणम्);
	यदि ((संस्करणम् & SSH_SK_संस्करणम्_MAJOR_आवरणम्) != SSH_SK_संस्करणम्_MAJOR) {
		error("Provider \"%s\" implements unsupported "
		    "version 0x%08lx (supported: 0x%08lx)",
		    मार्गः, (u_long)संस्करणम्, (u_long)SSH_SK_संस्करणम्_MAJOR);
		गच्छ fail;
	}
	यदि ((ret->sk_enroll = dlsym(ret->dlhandle, "sk_enroll")) == रिक्त) {
		error("Provider %s dlsym(sk_enroll) failed: %s",
		    मार्गः, dlerror());
		गच्छ fail;
	}
	यदि ((ret->sk_sign = dlsym(ret->dlhandle, "sk_sign")) == रिक्त) {
		error("Provider \"%s\" dlsym(sk_sign) failed: %s",
		    मार्गः, dlerror());
		गच्छ fail;
	}
	यदि ((ret->sk_आरोपय_resident_कुञ्चिकाः = dlsym(ret->dlhandle,
	    "sk_load_resident_keys")) == रिक्त) {
		error("Provider \"%s\" dlsym(sk_load_resident_keys) "
		    "failed: %s", मार्गः, dlerror());
		गच्छ fail;
	}
	/* success */
	प्रत्यागम ret;
fail:
	sshsk_free(ret);
	प्रत्यागम रिक्त;
}

स्थिर शून्य
sshsk_free_enroll_response(संरचना sk_enroll_response *r)
{
	यदि (r == रिक्त)
		प्रत्यागम;
	freezero(r->कुञ्चिका_handle, r->कुञ्चिका_handle_len);
	freezero(r->लौकिकम्_कुञ्चिका, r->लौकिकम्_कुञ्चिका_len);
	freezero(r->signature, r->signature_len);
	freezero(r->attestation_cert, r->attestation_cert_len);
	freezero(r->authdata, r->authdata_len);
	freezero(r, परिमाण(*r));
}

स्थिर शून्य
sshsk_free_sign_response(संरचना sk_sign_response *r)
{
	यदि (r == रिक्त)
		प्रत्यागम;
	freezero(r->sig_r, r->sig_r_len);
	freezero(r->sig_s, r->sig_s_len);
	freezero(r, परिमाण(*r));
}

#यदि_परिभाषितम् WITH_OPENSSL
/* Assemble key from response */
स्थिर पूर्णाङ्क
sshsk_ecdsa_assemble(संरचना sk_enroll_response *resp, संरचना sshkey **keyp)
{
	संरचना sshkey *कुञ्चिका = रिक्त;
	संरचना sshbuf *b = रिक्त;
	EC_कुञ्चिका *ecdsa = रिक्त;
	EC_POINT *q = रिक्त;
	ध्रुव EC_गणः *g = रिक्त;
	पूर्णाङ्क r;

	*keyp = रिक्त;
	यदि ((कुञ्चिका = sshkey_new(कुञ्चिका_ECDSA_SK)) == रिक्त) {
		error_f("sshkey_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ बहिर्गमनम्;
	}
	कुञ्चिका->ecdsa_nid = NID_X9_62_prime256v1;
	यदि ((ecdsa = EC_कुञ्चिका_new_by_वक्रम्_name(कुञ्चिका->ecdsa_nid)) == रिक्त ||
	    (g = EC_कुञ्चिका_get0_गणः(ecdsa)) == रिक्त ||
	    (q = EC_POINT_new(g)) == रिक्त ||
	    (b = sshbuf_new()) == रिक्त) {
		error_f("allocation failed");
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ बहिर्गमनम्;
	}
	यदि ((r = sshbuf_put_string(b,
	    resp->लौकिकम्_कुञ्चिका, resp->लौकिकम्_कुञ्चिका_len)) != 0) {
		error_fr(r, "sshbuf_put_string");
		गच्छ बहिर्गमनम्;
	}
	यदि ((r = sshbuf_get_ec(b, q, g)) != 0) {
		error_fr(r, "parse");
		r = SSH_ERR_INVALID_FORMAT;
		गच्छ बहिर्गमनम्;
	}
	यदि (sshkey_ec_validate_लौकिकम्(g, q) != 0) {
		error("Authenticator returned invalid ECDSA key");
		r = SSH_ERR_कुञ्चिका_INVALID_EC_मानम्;
		गच्छ बहिर्गमनम्;
	}
	यदि (EC_कुञ्चिका_समुच्चयः_लौकिकम्_कुञ्चिका(ecdsa, q) != 1) {
		/* XXX assume it is a allocation error */
		error_f("allocation failed");
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ बहिर्गमनम्;
	}
	यदि ((कुञ्चिका->pkey = EVP_PKEY_new()) == रिक्त) {
		error_f("allocation failed");
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ बहिर्गमनम्;
	}
	यदि (EVP_PKEY_set1_EC_कुञ्चिका(कुञ्चिका->pkey, ecdsa) != 1) {
		error_f("Assigning EC_KEY failed");
		r = SSH_ERR_LIBCRYPTO_ERROR;
		गच्छ बहिर्गमनम्;
	}
	/* success */
	*keyp = कुञ्चिका;
	कुञ्चिका = रिक्त; /* transferred */
	r = 0;
 बहिर्गमनम्:
	sshkey_free(कुञ्चिका);
	sshbuf_free(b);
	EC_कुञ्चिका_free(ecdsa);
	EC_POINT_free(q);
	प्रत्यागम r;
}
#यदि_अन्तः /* WITH_OPENSSL */

स्थिर पूर्णाङ्क
sshsk_ed25519_assemble(संरचना sk_enroll_response *resp, संरचना sshkey **keyp)
{
	संरचना sshkey *कुञ्चिका = रिक्त;
	पूर्णाङ्क r;

	*keyp = रिक्त;
	यदि (resp->लौकिकम्_कुञ्चिका_len != ED25519_PK_SZ) {
		error_f("invalid size: %zu", resp->लौकिकम्_कुञ्चिका_len);
		r = SSH_ERR_INVALID_FORMAT;
		गच्छ बहिर्गमनम्;
	}
	यदि ((कुञ्चिका = sshkey_new(कुञ्चिका_ED25519_SK)) == रिक्त) {
		error_f("sshkey_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ बहिर्गमनम्;
	}
	यदि ((कुञ्चिका->ed25519_pk = स्मृतिं_देहि(ED25519_PK_SZ)) == रिक्त) {
		error_f("malloc failed");
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ बहिर्गमनम्;
	}
	स्मृतिं_प्रतिलिख(कुञ्चिका->ed25519_pk, resp->लौकिकम्_कुञ्चिका, ED25519_PK_SZ);
	/* success */
	*keyp = कुञ्चिका;
	कुञ्चिका = रिक्त; /* transferred */
	r = 0;
 बहिर्गमनम्:
	sshkey_free(कुञ्चिका);
	प्रत्यागम r;
}

स्थिर पूर्णाङ्क
sshsk_कुञ्चिका_from_response(पूर्णाङ्क alg, ध्रुव वर्ण *application, uint8_t flags,
    संरचना sk_enroll_response *resp, संरचना sshkey **keyp)
{
	संरचना sshkey *कुञ्चिका = रिक्त;
	पूर्णाङ्क r = SSH_ERR_आन्तरिकम्_ERROR;

	*keyp = रिक्त;

	/* Check response validity */
	यदि (resp->लौकिकम्_कुञ्चिका == रिक्त || resp->कुञ्चिका_handle == रिक्त) {
		error_f("sk_enroll response invalid");
		r = SSH_ERR_INVALID_FORMAT;
		गच्छ बहिर्गमनम्;
	}
	विकल्प (alg) {
#यदि_परिभाषितम् WITH_OPENSSL
	पक्ष SSH_SK_ECDSA:
		यदि ((r = sshsk_ecdsa_assemble(resp, &कुञ्चिका)) != 0)
			गच्छ बहिर्गमनम्;
		भङ्ग;
#यदि_अन्तः /* WITH_OPENSSL */
	पक्ष SSH_SK_ED25519:
		यदि ((r = sshsk_ed25519_assemble(resp, &कुञ्चिका)) != 0)
			गच्छ बहिर्गमनम्;
		भङ्ग;
	स्वभाव:
		error_f("unsupported algorithm %d", alg);
		r = SSH_ERR_INVALID_तर्कः;
		गच्छ बहिर्गमनम्;
	}
	कुञ्चिका->sk_flags = flags;
	यदि ((कुञ्चिका->sk_कुञ्चिका_handle = sshbuf_new()) == रिक्त ||
	    (कुञ्चिका->sk_reserved = sshbuf_new()) == रिक्त) {
		error_f("allocation failed");
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ बहिर्गमनम्;
	}
	यदि ((कुञ्चिका->sk_application = strdup(application)) == रिक्त) {
		error_f("strdup application failed");
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ बहिर्गमनम्;
	}
	यदि ((r = sshbuf_put(कुञ्चिका->sk_कुञ्चिका_handle, resp->कुञ्चिका_handle,
	    resp->कुञ्चिका_handle_len)) != 0) {
		error_fr(r, "put key handle");
		गच्छ बहिर्गमनम्;
	}
	/* success */
	r = 0;
	*keyp = कुञ्चिका;
	कुञ्चिका = रिक्त;
 बहिर्गमनम्:
	sshkey_free(कुञ्चिका);
	प्रत्यागम r;
}

स्थिर पूर्णाङ्क
skerr_गन्तव्यम्_ssherr(पूर्णाङ्क skerr)
{
	विकल्प (skerr) {
	पक्ष SSH_SK_ERR_UNSUPPORTED:
		प्रत्यागम SSH_ERR_FEATURE_UNSUPPORTED;
	पक्ष SSH_SK_ERR_PIN_REQUIRED:
		प्रत्यागम SSH_ERR_कुञ्चिका_WRONG_PASSPHRASE;
	पक्ष SSH_SK_ERR_DEVICE_NOT_प्राप्तम्:
		प्रत्यागम SSH_ERR_DEVICE_NOT_प्राप्तम्;
	पक्ष SSH_SK_ERR_CREDENTIAL_EXISTS:
		प्रत्यागम SSH_ERR_कुञ्चिका_BAD_PERMISSIONS;
	पक्ष SSH_SK_ERR_GENERAL:
	स्वभाव:
		प्रत्यागम SSH_ERR_INVALID_FORMAT;
	}
}

स्थिर शून्य
sshsk_free_options(संरचना sk_option **opts)
{
	आकार_t i;

	यदि (opts == रिक्त)
		प्रत्यागम;
	प्रति (i = 0; opts[i] != रिक्त; i++) {
		मुक्त(opts[i]->name);
		मुक्त(opts[i]->मानम्);
		मुक्त(opts[i]);
	}
	मुक्त(opts);
}

स्थिर पूर्णाङ्क
sshsk_सङ्कलय_option(संरचना sk_option ***optsp, आकार_t *noptsp,
    ध्रुव वर्ण *name, ध्रुव वर्ण *मानम्, uint8_t required)
{
	संरचना sk_option **opts = *optsp;
	आकार_t nopts = *noptsp;

	यदि ((opts = recallocarray(opts, nopts, nopts + 2, /* extra for NULL */
	    परिमाण(*opts))) == रिक्त) {
		error_f("array alloc failed");
		प्रत्यागम SSH_ERR_ALLOC_FAIL;
	}
	*optsp = opts;
	*noptsp = nopts + 1;
	यदि ((opts[nopts] = शून्यस्मृतिं_देहि(1, परिमाण(**opts))) == रिक्त) {
		error_f("alloc failed");
		प्रत्यागम SSH_ERR_ALLOC_FAIL;
	}
	यदि ((opts[nopts]->name = strdup(name)) == रिक्त ||
	    (opts[nopts]->मानम् = strdup(मानम्)) == रिक्त) {
		error_f("alloc failed");
		प्रत्यागम SSH_ERR_ALLOC_FAIL;
	}
	opts[nopts]->required = required;
	प्रत्यागम 0;
}

स्थिर पूर्णाङ्क
make_options(ध्रुव वर्ण *device, ध्रुव वर्ण *user_id,
    संरचना sk_option ***optsp)
{
	संरचना sk_option **opts = रिक्त;
	आकार_t nopts = 0;
	पूर्णाङ्क r, ret = SSH_ERR_आन्तरिकम्_ERROR;

	यदि (device != रिक्त &&
	    (r = sshsk_सङ्कलय_option(&opts, &nopts, "device", device, 0)) != 0) {
		ret = r;
		गच्छ बहिर्गमनम्;
	}
	यदि (user_id != रिक्त &&
	    (r = sshsk_सङ्कलय_option(&opts, &nopts, "user", user_id, 0)) != 0) {
		ret = r;
		गच्छ बहिर्गमनम्;
	}
	/* success */
	*optsp = opts;
	opts = रिक्त;
	nopts = 0;
	ret = 0;
 बहिर्गमनम्:
	sshsk_free_options(opts);
	प्रत्यागम ret;
}


स्थिर पूर्णाङ्क
fill_attestation_blob(ध्रुव संरचना sk_enroll_response *resp,
    संरचना sshbuf *attest)
{
	पूर्णाङ्क r;

	यदि (attest == रिक्त)
		प्रत्यागम 0; /* nothing to do */
	यदि ((r = sshbuf_put_cstring(attest, "ssh-sk-attest-v01")) != 0 ||
	    (r = sshbuf_put_string(attest,
	    resp->attestation_cert, resp->attestation_cert_len)) != 0 ||
	    (r = sshbuf_put_string(attest,
	    resp->signature, resp->signature_len)) != 0 ||
	    (r = sshbuf_put_string(attest,
	    resp->authdata, resp->authdata_len)) != 0 ||
	    (r = sshbuf_put_u32(attest, 0)) != 0 || /* resvd flags */
	    (r = sshbuf_put_string(attest, रिक्त, 0)) != 0 /* resvd */) {
		error_fr(r, "compose");
		प्रत्यागम r;
	}
	/* success */
	प्रत्यागम 0;
}

पूर्णाङ्क
sshsk_enroll(पूर्णाङ्क type, ध्रुव वर्ण *provider_मार्गः, ध्रुव वर्ण *device,
    ध्रुव वर्ण *application, ध्रुव वर्ण *userid, uint8_t flags,
    ध्रुव वर्ण *pin, संरचना sshbuf *challenge_buf,
    संरचना sshkey **keyp, संरचना sshbuf *attest)
{
	संरचना sshsk_provider *skp = रिक्त;
	संरचना sshkey *कुञ्चिका = रिक्त;
	u_char randchall[32];
	ध्रुव u_char *challenge;
	आकार_t challenge_len;
	संरचना sk_enroll_response *resp = रिक्त;
	संरचना sk_option **opts = रिक्त;
	पूर्णाङ्क r = SSH_ERR_आन्तरिकम्_ERROR;
	पूर्णाङ्क alg;

	debug_f("provider \"%s\", device \"%s\", application \"%s\", "
	    "userid \"%s\", flags 0x%02x, challenge len %zu%s",
	    provider_मार्गः, device, application, userid, flags,
	    challenge_buf == रिक्त ? 0 : sshbuf_len(challenge_buf),
	    (pin != रिक्त && *pin != '\0') ? " with-pin" : "");

	*keyp = रिक्त;
	यदि (attest)
		sshbuf_reset(attest);

	यदि ((r = make_options(device, userid, &opts)) != 0)
		गच्छ बहिर्गमनम्;

	विकल्प (type) {
#यदि_परिभाषितम् WITH_OPENSSL
	पक्ष कुञ्चिका_ECDSA_SK:
		alg = SSH_SK_ECDSA;
		भङ्ग;
#यदि_अन्तः /* WITH_OPENSSL */
	पक्ष कुञ्चिका_ED25519_SK:
		alg = SSH_SK_ED25519;
		भङ्ग;
	स्वभाव:
		error_f("unsupported key type");
		r = SSH_ERR_INVALID_तर्कः;
		गच्छ बहिर्गमनम्;
	}
	यदि (provider_मार्गः == रिक्त) {
		error_f("missing provider");
		r = SSH_ERR_INVALID_तर्कः;
		गच्छ बहिर्गमनम्;
	}
	यदि (application == रिक्त || *application == '\0') {
		error_f("missing application");
		r = SSH_ERR_INVALID_तर्कः;
		गच्छ बहिर्गमनम्;
	}
	यदि (challenge_buf == रिक्त) {
		debug_f("using random challenge");
		arc4random_buf(randchall, परिमाण(randchall));
		challenge = randchall;
		challenge_len = परिमाण(randchall);
	} अन्यथा यदि (sshbuf_len(challenge_buf) == 0) {
		error("Missing enrollment challenge");
		r = SSH_ERR_INVALID_तर्कः;
		गच्छ बहिर्गमनम्;
	} अन्यथा {
		challenge = sshbuf_ptr(challenge_buf);
		challenge_len = sshbuf_len(challenge_buf);
		debug3_f("using explicit challenge len=%zd", challenge_len);
	}
	यदि ((skp = sshsk_open(provider_मार्गः)) == रिक्त) {
		r = SSH_ERR_INVALID_FORMAT; /* XXX sshsk_open return code? */
		गच्छ बहिर्गमनम्;
	}
	/* XXX validate flags? */
	/* enroll key */
	यदि ((r = skp->sk_enroll(alg, challenge, challenge_len, application,
	    flags, pin, opts, &resp)) != 0) {
		debug_f("provider \"%s\" failure %d", provider_मार्गः, r);
		r = skerr_गन्तव्यम्_ssherr(r);
		गच्छ बहिर्गमनम्;
	}

	यदि ((r = sshsk_कुञ्चिका_from_response(alg, application, resp->flags,
	    resp, &कुञ्चिका)) != 0)
		गच्छ बहिर्गमनम्;

	/* Optionally fill in the attestation information */
	यदि ((r = fill_attestation_blob(resp, attest)) != 0)
		गच्छ बहिर्गमनम्;

	/* success */
	*keyp = कुञ्चिका;
	कुञ्चिका = रिक्त; /* transferred */
	r = 0;
 बहिर्गमनम्:
	sshsk_free_options(opts);
	sshsk_free(skp);
	sshkey_free(कुञ्चिका);
	sshsk_free_enroll_response(resp);
	explicit_bzero(randchall, परिमाण(randchall));
	प्रत्यागम r;
}

#यदि_परिभाषितम् WITH_OPENSSL
स्थिर पूर्णाङ्क
sshsk_ecdsa_sig(संरचना sk_sign_response *resp, संरचना sshbuf *sig)
{
	संरचना sshbuf *inner_sig = रिक्त;
	पूर्णाङ्क r = SSH_ERR_आन्तरिकम्_ERROR;

	/* Check response validity */
	यदि (resp->sig_r == रिक्त || resp->sig_s == रिक्त) {
		error_f("sk_sign response invalid");
		r = SSH_ERR_INVALID_FORMAT;
		गच्छ बहिर्गमनम्;
	}
	यदि ((inner_sig = sshbuf_new()) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ बहिर्गमनम्;
	}
	/* Prepare and append inner signature object */
	यदि ((r = sshbuf_put_bignum2_अष्टकानि(inner_sig,
	    resp->sig_r, resp->sig_r_len)) != 0 ||
	    (r = sshbuf_put_bignum2_अष्टकानि(inner_sig,
	    resp->sig_s, resp->sig_s_len)) != 0) {
		error_fr(r, "compose inner");
		गच्छ बहिर्गमनम्;
	}
	यदि ((r = sshbuf_put_stringb(sig, inner_sig)) != 0 ||
	    (r = sshbuf_put_u8(sig, resp->flags)) != 0 ||
	    (r = sshbuf_put_u32(sig, resp->गणक)) != 0) {
		error_fr(r, "compose");
		गच्छ बहिर्गमनम्;
	}
#यदि_परिभाषितम् DEBUG_SK
	fprintf(stderr, "%s: sig_r:\n", __func__);
	sshbuf_dump_दत्त(resp->sig_r, resp->sig_r_len, stderr);
	fprintf(stderr, "%s: sig_s:\n", __func__);
	sshbuf_dump_दत्त(resp->sig_s, resp->sig_s_len, stderr);
	fprintf(stderr, "%s: inner:\n", __func__);
	sshbuf_dump(inner_sig, stderr);
#यदि_अन्तः
	r = 0;
 बहिर्गमनम्:
	sshbuf_free(inner_sig);
	प्रत्यागम r;
}
#यदि_अन्तः /* WITH_OPENSSL */

स्थिर पूर्णाङ्क
sshsk_ed25519_sig(संरचना sk_sign_response *resp, संरचना sshbuf *sig)
{
	पूर्णाङ्क r = SSH_ERR_आन्तरिकम्_ERROR;

	/* Check response validity */
	यदि (resp->sig_r == रिक्त) {
		error_f("sk_sign response invalid");
		r = SSH_ERR_INVALID_FORMAT;
		गच्छ बहिर्गमनम्;
	}
	यदि ((r = sshbuf_put_string(sig,
	    resp->sig_r, resp->sig_r_len)) != 0 ||
	    (r = sshbuf_put_u8(sig, resp->flags)) != 0 ||
	    (r = sshbuf_put_u32(sig, resp->गणक)) != 0) {
		error_fr(r, "compose");
		गच्छ बहिर्गमनम्;
	}
#यदि_परिभाषितम् DEBUG_SK
	fprintf(stderr, "%s: sig_r:\n", __func__);
	sshbuf_dump_दत्त(resp->sig_r, resp->sig_r_len, stderr);
#यदि_अन्तः
	r = 0;
 बहिर्गमनम्:
	प्रत्यागम r;
}

पूर्णाङ्क
sshsk_sign(ध्रुव वर्ण *provider_मार्गः, संरचना sshkey *कुञ्चिका,
    u_char **sigp, आकार_t *lenp, ध्रुव u_char *दत्त, आकार_t datalen,
    u_int compat, ध्रुव वर्ण *pin)
{
	संरचना sshsk_provider *skp = रिक्त;
	पूर्णाङ्क r = SSH_ERR_आन्तरिकम्_ERROR;
	पूर्णाङ्क type, alg;
	संरचना sk_sign_response *resp = रिक्त;
	संरचना sshbuf *inner_sig = रिक्त, *sig = रिक्त;
	संरचना sk_option **opts = रिक्त;

	debug_f("provider \"%s\", key %s, flags 0x%02x%s",
	    provider_मार्गः, sshkey_type(कुञ्चिका), कुञ्चिका->sk_flags,
	    (pin != रिक्त && *pin != '\0') ? " with-pin" : "");

	यदि (sigp != रिक्त)
		*sigp = रिक्त;
	यदि (lenp != रिक्त)
		*lenp = 0;
	type = sshkey_type_plain(कुञ्चिका->type);
	विकल्प (type) {
#यदि_परिभाषितम् WITH_OPENSSL
	पक्ष कुञ्चिका_ECDSA_SK:
		alg = SSH_SK_ECDSA;
		भङ्ग;
#यदि_अन्तः /* WITH_OPENSSL */
	पक्ष कुञ्चिका_ED25519_SK:
		alg = SSH_SK_ED25519;
		भङ्ग;
	स्वभाव:
		प्रत्यागम SSH_ERR_INVALID_तर्कः;
	}
	यदि (provider_मार्गः == रिक्त ||
	    कुञ्चिका->sk_कुञ्चिका_handle == रिक्त ||
	    कुञ्चिका->sk_application == रिक्त || *कुञ्चिका->sk_application == '\0') {
		r = SSH_ERR_INVALID_तर्कः;
		गच्छ बहिर्गमनम्;
	}
	यदि ((skp = sshsk_open(provider_मार्गः)) == रिक्त) {
		r = SSH_ERR_INVALID_FORMAT; /* XXX sshsk_open return code? */
		गच्छ बहिर्गमनम्;
	}
#यदि_परिभाषितम् DEBUG_SK
	fprintf(stderr, "%s: sk_flags = 0x%02x, sk_application = \"%s\"\n",
	    __func__, कुञ्चिका->sk_flags, कुञ्चिका->sk_application);
	fprintf(stderr, "%s: sk_key_handle:\n", __func__);
	sshbuf_dump(कुञ्चिका->sk_कुञ्चिका_handle, stderr);
#यदि_अन्तः
	यदि ((r = skp->sk_sign(alg, दत्त, datalen, कुञ्चिका->sk_application,
	    sshbuf_ptr(कुञ्चिका->sk_कुञ्चिका_handle), sshbuf_len(कुञ्चिका->sk_कुञ्चिका_handle),
	    कुञ्चिका->sk_flags, pin, opts, &resp)) != 0) {
		debug_f("sk_sign failed with code %d", r);
		r = skerr_गन्तव्यम्_ssherr(r);
		गच्छ बहिर्गमनम्;
	}
	/* Assemble signature */
	यदि ((sig = sshbuf_new()) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ बहिर्गमनम्;
	}
	यदि ((r = sshbuf_put_cstring(sig, sshkey_ssh_name_plain(कुञ्चिका))) != 0) {
		error_fr(r, "compose outer");
		गच्छ बहिर्गमनम्;
	}
	विकल्प (type) {
#यदि_परिभाषितम् WITH_OPENSSL
	पक्ष कुञ्चिका_ECDSA_SK:
		यदि ((r = sshsk_ecdsa_sig(resp, sig)) != 0)
			गच्छ बहिर्गमनम्;
		भङ्ग;
#यदि_अन्तः /* WITH_OPENSSL */
	पक्ष कुञ्चिका_ED25519_SK:
		यदि ((r = sshsk_ed25519_sig(resp, sig)) != 0)
			गच्छ बहिर्गमनम्;
		भङ्ग;
	}
#यदि_परिभाषितम् DEBUG_SK
	fprintf(stderr, "%s: sig_flags = 0x%02x, sig_counter = %u\n",
	    __func__, resp->flags, resp->गणक);
	fprintf(stderr, "%s: data to sign:\n", __func__);
	sshbuf_dump_दत्त(दत्त, datalen, stderr);
	fprintf(stderr, "%s: sigbuf:\n", __func__);
	sshbuf_dump(sig, stderr);
#यदि_अन्तः
	यदि (sigp != रिक्त) {
		यदि ((*sigp = स्मृतिं_देहि(sshbuf_len(sig))) == रिक्त) {
			r = SSH_ERR_ALLOC_FAIL;
			गच्छ बहिर्गमनम्;
		}
		स्मृतिं_प्रतिलिख(*sigp, sshbuf_ptr(sig), sshbuf_len(sig));
	}
	यदि (lenp != रिक्त)
		*lenp = sshbuf_len(sig);
	/* success */
	r = 0;
 बहिर्गमनम्:
	sshsk_free_options(opts);
	sshsk_free(skp);
	sshsk_free_sign_response(resp);
	sshbuf_free(sig);
	sshbuf_free(inner_sig);
	प्रत्यागम r;
}

स्थिर शून्य
sshsk_free_sk_resident_कुञ्चिकाः(संरचना sk_resident_कुञ्चिका **rks, आकार_t nrks)
{
	आकार_t i;

	यदि (nrks == 0 || rks == रिक्त)
		प्रत्यागम;
	प्रति (i = 0; i < nrks; i++) {
		मुक्त(rks[i]->application);
		freezero(rks[i]->user_id, rks[i]->user_id_len);
		freezero(rks[i]->कुञ्चिका.कुञ्चिका_handle, rks[i]->कुञ्चिका.कुञ्चिका_handle_len);
		freezero(rks[i]->कुञ्चिका.लौकिकम्_कुञ्चिका, rks[i]->कुञ्चिका.लौकिकम्_कुञ्चिका_len);
		freezero(rks[i]->कुञ्चिका.signature, rks[i]->कुञ्चिका.signature_len);
		freezero(rks[i]->कुञ्चिका.attestation_cert,
		    rks[i]->कुञ्चिका.attestation_cert_len);
		freezero(rks[i], परिमाण(**rks));
	}
	मुक्त(rks);
}

स्थिर शून्य
sshsk_free_resident_कुञ्चिका(संरचना sshsk_resident_कुञ्चिका *srk)
{
	यदि (srk == रिक्त)
		प्रत्यागम;
	sshkey_free(srk->कुञ्चिका);
	freezero(srk->user_id, srk->user_id_len);
	मुक्त(srk);
}


शून्य
sshsk_free_resident_कुञ्चिकाः(संरचना sshsk_resident_कुञ्चिका **srks, आकार_t nsrks)
{
	आकार_t i;

	यदि (srks == रिक्त || nsrks == 0)
		प्रत्यागम;

	प्रति (i = 0; i < nsrks; i++)
		sshsk_free_resident_कुञ्चिका(srks[i]);
	मुक्त(srks);
}

पूर्णाङ्क
sshsk_आरोपय_resident(ध्रुव वर्ण *provider_मार्गः, ध्रुव वर्ण *device,
    ध्रुव वर्ण *pin, u_int flags, संरचना sshsk_resident_कुञ्चिका ***srksp,
    आकार_t *nsrksp)
{
	संरचना sshsk_provider *skp = रिक्त;
	पूर्णाङ्क r = SSH_ERR_आन्तरिकम्_ERROR;
	संरचना sk_resident_कुञ्चिका **rks = रिक्त;
	आकार_t i, nrks = 0, nsrks = 0;
	संरचना sshkey *कुञ्चिका = रिक्त;
	संरचना sshsk_resident_कुञ्चिका *srk = रिक्त, **srks = रिक्त, **tmp;
	uint8_t sk_flags;
	संरचना sk_option **opts = रिक्त;

	debug_f("provider \"%s\"%s", provider_मार्गः,
	    (pin != रिक्त && *pin != '\0') ? ", have-pin": "");

	यदि (srksp == रिक्त || nsrksp == रिक्त)
		प्रत्यागम SSH_ERR_INVALID_तर्कः;
	*srksp = रिक्त;
	*nsrksp = 0;

	यदि ((r = make_options(device, रिक्त, &opts)) != 0)
		गच्छ बहिर्गमनम्;
	यदि ((skp = sshsk_open(provider_मार्गः)) == रिक्त) {
		r = SSH_ERR_INVALID_FORMAT; /* XXX sshsk_open return code? */
		गच्छ बहिर्गमनम्;
	}
	यदि ((r = skp->sk_आरोपय_resident_कुञ्चिकाः(pin, opts, &rks, &nrks)) != 0) {
		error("Provider \"%s\" returned failure %d", provider_मार्गः, r);
		r = skerr_गन्तव्यम्_ssherr(r);
		गच्छ बहिर्गमनम्;
	}
	प्रति (i = 0; i < nrks; i++) {
		debug3_f("rk %zu: slot %zu, alg %d, app \"%s\", uidlen %zu",
		    i, rks[i]->slot, rks[i]->alg, rks[i]->application,
		    rks[i]->user_id_len);
		/* XXX need better filter here */
		यदि (वाक्ये_तुलय(rks[i]->application, "ssh:", 4) != 0)
			अनुवर्त;
		विकल्प (rks[i]->alg) {
		पक्ष SSH_SK_ECDSA:
		पक्ष SSH_SK_ED25519:
			भङ्ग;
		स्वभाव:
			अनुवर्त;
		}
		sk_flags = SSH_SK_USER_PRESENCE_REQD|SSH_SK_RESIDENT_कुञ्चिका;
		यदि ((rks[i]->flags & SSH_SK_USER_VERIFICATION_REQD))
			sk_flags |= SSH_SK_USER_VERIFICATION_REQD;
		यदि ((r = sshsk_कुञ्चिका_from_response(rks[i]->alg,
		    rks[i]->application, sk_flags, &rks[i]->कुञ्चिका, &कुञ्चिका)) != 0)
			गच्छ बहिर्गमनम्;
		यदि ((srk = शून्यस्मृतिं_देहि(1, परिमाण(*srk))) == रिक्त) {
			error_f("calloc failed");
			r = SSH_ERR_ALLOC_FAIL;
			गच्छ बहिर्गमनम्;
		}
		srk->कुञ्चिका = कुञ्चिका;
		कुञ्चिका = रिक्त; /* transferred */
		यदि ((srk->user_id = शून्यस्मृतिं_देहि(1, rks[i]->user_id_len)) == रिक्त) {
			error_f("calloc failed");
			r = SSH_ERR_ALLOC_FAIL;
			गच्छ बहिर्गमनम्;
		}
		स्मृतिं_प्रतिलिख(srk->user_id, rks[i]->user_id, rks[i]->user_id_len);
		srk->user_id_len = rks[i]->user_id_len;
		यदि ((tmp = recallocarray(srks, nsrks, nsrks + 1,
		    परिमाण(*tmp))) == रिक्त) {
			error_f("recallocarray failed");
			r = SSH_ERR_ALLOC_FAIL;
			गच्छ बहिर्गमनम्;
		}
		srks = tmp;
		srks[nsrks++] = srk;
		srk = रिक्त;
		/* XXX synthesise comment */
	}
	/* success */
	*srksp = srks;
	*nsrksp = nsrks;
	srks = रिक्त;
	nsrks = 0;
	r = 0;
 बहिर्गमनम्:
	sshsk_free_options(opts);
	sshsk_free(skp);
	sshsk_free_sk_resident_कुञ्चिकाः(rks, nrks);
	sshkey_free(कुञ्चिका);
	sshsk_free_resident_कुञ्चिका(srk);
	sshsk_free_resident_कुञ्चिकाः(srks, nsrks);
	प्रत्यागम r;
}

#यदि_अन्तः /* ENABLE_SK */
