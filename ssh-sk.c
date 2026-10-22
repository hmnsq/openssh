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

#ifdef ENABLE_SK

#अन्तर्भाव <dlfcn.h>
#अन्तर्भाव <stddef.h>
#अन्तर्भाव <stdint.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <stdio.h>

#ifdef WITH_OPENSSL
#अन्तर्भाव <openssl/objects.h>
#अन्तर्भाव <openssl/ec.h>
#अन्तर्भाव <openssl/evp.h>
#endif /* WITH_OPENSSL */

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
	वर्ण *path;
	शून्य *dlhandle;

	/* Return the version of the middleware API */
	uint32_t (*sk_api_version)(शून्य);

	/* Enroll a U2F key (private key generation) */
	पूर्णाङ्क (*sk_enroll)(पूर्णाङ्क alg, ध्रुव uint8_t *challenge,
	    size_t challenge_len, ध्रुव वर्ण *application, uint8_t flags,
	    ध्रुव वर्ण *pin, संरचना sk_option **opts,
	    संरचना sk_enroll_response **enroll_response);

	/* Sign a challenge */
	पूर्णाङ्क (*sk_sign)(पूर्णाङ्क alg, ध्रुव uint8_t *message, size_t message_len,
	    ध्रुव वर्ण *application,
	    ध्रुव uint8_t *कुञ्चिका_handle, size_t कुञ्चिका_handle_len,
	    uint8_t flags, ध्रुव वर्ण *pin, संरचना sk_option **opts,
	    संरचना sk_sign_response **sign_response);

	/* Enumerate resident keys */
	पूर्णाङ्क (*sk_load_resident_कुञ्चिकाः)(ध्रुव वर्ण *pin, संरचना sk_option **opts,
	    संरचना sk_resident_कुञ्चिका ***rks, size_t *nrks);
};

/* Built-in version */
पूर्णाङ्क ssh_sk_enroll(पूर्णाङ्क alg, ध्रुव uint8_t *challenge,
    size_t challenge_len, ध्रुव वर्ण *application, uint8_t flags,
    ध्रुव वर्ण *pin, संरचना sk_option **opts,
    संरचना sk_enroll_response **enroll_response);
पूर्णाङ्क ssh_sk_sign(पूर्णाङ्क alg, ध्रुव uint8_t *message, size_t message_len,
    ध्रुव वर्ण *application,
    ध्रुव uint8_t *कुञ्चिका_handle, size_t कुञ्चिका_handle_len,
    uint8_t flags, ध्रुव वर्ण *pin, संरचना sk_option **opts,
    संरचना sk_sign_response **sign_response);
पूर्णाङ्क ssh_sk_load_resident_कुञ्चिकाः(ध्रुव वर्ण *pin, संरचना sk_option **opts,
    संरचना sk_resident_कुञ्चिका ***rks, size_t *nrks);

स्थिर शून्य
sshsk_free(संरचना sshsk_provider *p)
{
	सचे (p == रिक्त)
		पटिनिवत्त;
	मुक्त(p->path);
	सचे (p->dlhandle != रिक्त)
		dlclose(p->dlhandle);
	मुक्त(p);
}

स्थिर संरचना sshsk_provider *
sshsk_open(ध्रुव वर्ण *path)
{
	संरचना sshsk_provider *ret = रिक्त;
	uint32_t version;

	सचे (path == रिक्त || *path == '\0') {
		error("No FIDO SecurityKeyProvider specified");
		पटिनिवत्त रिक्त;
	}
	सचे ((ret = calloc(1, परिमाण(*ret))) == रिक्त) {
		error_f("calloc failed");
		पटिनिवत्त रिक्त;
	}
	सचे ((ret->path = strdup(path)) == रिक्त) {
		error_f("strdup failed");
		गच्छ fail;
	}
	/* Skip the rest if we're using the linked in middleware */
	सचे (strcasecmp(ret->path, "internal") == 0) {
#ifdef ENABLE_SK_INTERNAL
		ret->sk_enroll = ssh_sk_enroll;
		ret->sk_sign = ssh_sk_sign;
		ret->sk_load_resident_कुञ्चिकाः = ssh_sk_load_resident_कुञ्चिकाः;
		पटिनिवत्त ret;
#अञ्ञथा
		error("internal security key support not enabled");
		गच्छ fail;
#endif
	}
	सचे (lib_contains_चिह्नम्(path, "sk_api_version") != 0) {
		error("provider %s is not an OpenSSH FIDO library", path);
		गच्छ fail;
	}
	सचे ((ret->dlhandle = dlopen(path, RTLD_NOW)) == रिक्त)
		fatal("Provider \"%s\" dlopen failed: %s", path, dlerror());
	सचे ((ret->sk_api_version = dlsym(ret->dlhandle,
	    "sk_api_version")) == रिक्त) {
		error("Provider \"%s\" dlsym(sk_api_version) failed: %s",
		    path, dlerror());
		गच्छ fail;
	}
	version = ret->sk_api_version();
	debug_f("provider %s implements version 0x%08lx", ret->path,
	    (u_long)version);
	सचे ((version & SSH_SK_VERSION_MAJOR_MASK) != SSH_SK_VERSION_MAJOR) {
		error("Provider \"%s\" implements unsupported "
		    "version 0x%08lx (supported: 0x%08lx)",
		    path, (u_long)version, (u_long)SSH_SK_VERSION_MAJOR);
		गच्छ fail;
	}
	सचे ((ret->sk_enroll = dlsym(ret->dlhandle, "sk_enroll")) == रिक्त) {
		error("Provider %s dlsym(sk_enroll) failed: %s",
		    path, dlerror());
		गच्छ fail;
	}
	सचे ((ret->sk_sign = dlsym(ret->dlhandle, "sk_sign")) == रिक्त) {
		error("Provider \"%s\" dlsym(sk_sign) failed: %s",
		    path, dlerror());
		गच्छ fail;
	}
	सचे ((ret->sk_load_resident_कुञ्चिकाः = dlsym(ret->dlhandle,
	    "sk_load_resident_keys")) == रिक्त) {
		error("Provider \"%s\" dlsym(sk_load_resident_keys) "
		    "failed: %s", path, dlerror());
		गच्छ fail;
	}
	/* success */
	पटिनिवत्त ret;
fail:
	sshsk_free(ret);
	पटिनिवत्त रिक्त;
}

स्थिर शून्य
sshsk_free_enroll_response(संरचना sk_enroll_response *r)
{
	सचे (r == रिक्त)
		पटिनिवत्त;
	freezero(r->कुञ्चिका_handle, r->कुञ्चिका_handle_len);
	freezero(r->public_कुञ्चिका, r->public_कुञ्चिका_len);
	freezero(r->signature, r->signature_len);
	freezero(r->attestation_cert, r->attestation_cert_len);
	freezero(r->authdata, r->authdata_len);
	freezero(r, परिमाण(*r));
}

स्थिर शून्य
sshsk_free_sign_response(संरचना sk_sign_response *r)
{
	सचे (r == रिक्त)
		पटिनिवत्त;
	freezero(r->sig_r, r->sig_r_len);
	freezero(r->sig_s, r->sig_s_len);
	freezero(r, परिमाण(*r));
}

#ifdef WITH_OPENSSL
/* Assemble key from response */
स्थिर पूर्णाङ्क
sshsk_ecdsa_assemble(संरचना sk_enroll_response *resp, संरचना sshkey **keyp)
{
	संरचना sshkey *कुञ्चिका = रिक्त;
	संरचना sshbuf *b = रिक्त;
	EC_कुञ्चिका *ecdsa = रिक्त;
	EC_POINT *q = रिक्त;
	ध्रुव EC_GROUP *g = रिक्त;
	पूर्णाङ्क r;

	*keyp = रिक्त;
	सचे ((कुञ्चिका = sshkey_new(कुञ्चिका_ECDSA_SK)) == रिक्त) {
		error_f("sshkey_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ out;
	}
	कुञ्चिका->ecdsa_nid = NID_X9_62_prime256v1;
	सचे ((ecdsa = EC_कुञ्चिका_new_by_curve_name(कुञ्चिका->ecdsa_nid)) == रिक्त ||
	    (g = EC_कुञ्चिका_get0_group(ecdsa)) == रिक्त ||
	    (q = EC_POINT_new(g)) == रिक्त ||
	    (b = sshbuf_new()) == रिक्त) {
		error_f("allocation failed");
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ out;
	}
	सचे ((r = sshbuf_put_string(b,
	    resp->public_कुञ्चिका, resp->public_कुञ्चिका_len)) != 0) {
		error_fr(r, "sshbuf_put_string");
		गच्छ out;
	}
	सचे ((r = sshbuf_get_ec(b, q, g)) != 0) {
		error_fr(r, "parse");
		r = SSH_ERR_INVALID_FORMAT;
		गच्छ out;
	}
	सचे (sshkey_ec_validate_public(g, q) != 0) {
		error("Authenticator returned invalid ECDSA key");
		r = SSH_ERR_कुञ्चिका_INVALID_EC_मानम्;
		गच्छ out;
	}
	सचे (EC_कुञ्चिका_set_public_कुञ्चिका(ecdsa, q) != 1) {
		/* XXX assume it is a allocation error */
		error_f("allocation failed");
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ out;
	}
	सचे ((कुञ्चिका->pkey = EVP_PKEY_new()) == रिक्त) {
		error_f("allocation failed");
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ out;
	}
	सचे (EVP_PKEY_set1_EC_कुञ्चिका(कुञ्चिका->pkey, ecdsa) != 1) {
		error_f("Assigning EC_KEY failed");
		r = SSH_ERR_LIBCRYPTO_ERROR;
		गच्छ out;
	}
	/* success */
	*keyp = कुञ्चिका;
	कुञ्चिका = रिक्त; /* transferred */
	r = 0;
 out:
	sshkey_free(कुञ्चिका);
	sshbuf_free(b);
	EC_कुञ्चिका_free(ecdsa);
	EC_POINT_free(q);
	पटिनिवत्त r;
}
#endif /* WITH_OPENSSL */

स्थिर पूर्णाङ्क
sshsk_ed25519_assemble(संरचना sk_enroll_response *resp, संरचना sshkey **keyp)
{
	संरचना sshkey *कुञ्चिका = रिक्त;
	पूर्णाङ्क r;

	*keyp = रिक्त;
	सचे (resp->public_कुञ्चिका_len != ED25519_PK_SZ) {
		error_f("invalid size: %zu", resp->public_कुञ्चिका_len);
		r = SSH_ERR_INVALID_FORMAT;
		गच्छ out;
	}
	सचे ((कुञ्चिका = sshkey_new(कुञ्चिका_ED25519_SK)) == रिक्त) {
		error_f("sshkey_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ out;
	}
	सचे ((कुञ्चिका->ed25519_pk = malloc(ED25519_PK_SZ)) == रिक्त) {
		error_f("malloc failed");
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ out;
	}
	memcpy(कुञ्चिका->ed25519_pk, resp->public_कुञ्चिका, ED25519_PK_SZ);
	/* success */
	*keyp = कुञ्चिका;
	कुञ्चिका = रिक्त; /* transferred */
	r = 0;
 out:
	sshkey_free(कुञ्चिका);
	पटिनिवत्त r;
}

स्थिर पूर्णाङ्क
sshsk_कुञ्चिका_from_response(पूर्णाङ्क alg, ध्रुव वर्ण *application, uint8_t flags,
    संरचना sk_enroll_response *resp, संरचना sshkey **keyp)
{
	संरचना sshkey *कुञ्चिका = रिक्त;
	पूर्णाङ्क r = SSH_ERR_INTERNAL_ERROR;

	*keyp = रिक्त;

	/* Check response validity */
	सचे (resp->public_कुञ्चिका == रिक्त || resp->कुञ्चिका_handle == रिक्त) {
		error_f("sk_enroll response invalid");
		r = SSH_ERR_INVALID_FORMAT;
		गच्छ out;
	}
	विकल्प (alg) {
#ifdef WITH_OPENSSL
	पक्ष SSH_SK_ECDSA:
		सचे ((r = sshsk_ecdsa_assemble(resp, &कुञ्चिका)) != 0)
			गच्छ out;
		भङ्ग;
#endif /* WITH_OPENSSL */
	पक्ष SSH_SK_ED25519:
		सचे ((r = sshsk_ed25519_assemble(resp, &कुञ्चिका)) != 0)
			गच्छ out;
		भङ्ग;
	स्वभाव:
		error_f("unsupported algorithm %d", alg);
		r = SSH_ERR_INVALID_ARGUMENT;
		गच्छ out;
	}
	कुञ्चिका->sk_flags = flags;
	सचे ((कुञ्चिका->sk_कुञ्चिका_handle = sshbuf_new()) == रिक्त ||
	    (कुञ्चिका->sk_reserved = sshbuf_new()) == रिक्त) {
		error_f("allocation failed");
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ out;
	}
	सचे ((कुञ्चिका->sk_application = strdup(application)) == रिक्त) {
		error_f("strdup application failed");
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ out;
	}
	सचे ((r = sshbuf_put(कुञ्चिका->sk_कुञ्चिका_handle, resp->कुञ्चिका_handle,
	    resp->कुञ्चिका_handle_len)) != 0) {
		error_fr(r, "put key handle");
		गच्छ out;
	}
	/* success */
	r = 0;
	*keyp = कुञ्चिका;
	कुञ्चिका = रिक्त;
 out:
	sshkey_free(कुञ्चिका);
	पटिनिवत्त r;
}

स्थिर पूर्णाङ्क
skerr_to_ssherr(पूर्णाङ्क skerr)
{
	विकल्प (skerr) {
	पक्ष SSH_SK_ERR_UNSUPPORTED:
		पटिनिवत्त SSH_ERR_FEATURE_UNSUPPORTED;
	पक्ष SSH_SK_ERR_PIN_REQUIRED:
		पटिनिवत्त SSH_ERR_कुञ्चिका_WRONG_PASSPHRASE;
	पक्ष SSH_SK_ERR_DEVICE_NOT_FOUND:
		पटिनिवत्त SSH_ERR_DEVICE_NOT_FOUND;
	पक्ष SSH_SK_ERR_CREDENTIAL_EXISTS:
		पटिनिवत्त SSH_ERR_कुञ्चिका_BAD_PERMISSIONS;
	पक्ष SSH_SK_ERR_GENERAL:
	स्वभाव:
		पटिनिवत्त SSH_ERR_INVALID_FORMAT;
	}
}

स्थिर शून्य
sshsk_free_options(संरचना sk_option **opts)
{
	size_t i;

	सचे (opts == रिक्त)
		पटिनिवत्त;
	अत्थाय (i = 0; opts[i] != रिक्त; i++) {
		मुक्त(opts[i]->name);
		मुक्त(opts[i]->मानम्);
		मुक्त(opts[i]);
	}
	मुक्त(opts);
}

स्थिर पूर्णाङ्क
sshsk_add_option(संरचना sk_option ***optsp, size_t *noptsp,
    ध्रुव वर्ण *name, ध्रुव वर्ण *मानम्, uint8_t required)
{
	संरचना sk_option **opts = *optsp;
	size_t nopts = *noptsp;

	सचे ((opts = recallocarray(opts, nopts, nopts + 2, /* extra for NULL */
	    परिमाण(*opts))) == रिक्त) {
		error_f("array alloc failed");
		पटिनिवत्त SSH_ERR_ALLOC_FAIL;
	}
	*optsp = opts;
	*noptsp = nopts + 1;
	सचे ((opts[nopts] = calloc(1, परिमाण(**opts))) == रिक्त) {
		error_f("alloc failed");
		पटिनिवत्त SSH_ERR_ALLOC_FAIL;
	}
	सचे ((opts[nopts]->name = strdup(name)) == रिक्त ||
	    (opts[nopts]->मानम् = strdup(मानम्)) == रिक्त) {
		error_f("alloc failed");
		पटिनिवत्त SSH_ERR_ALLOC_FAIL;
	}
	opts[nopts]->required = required;
	पटिनिवत्त 0;
}

स्थिर पूर्णाङ्क
make_options(ध्रुव वर्ण *device, ध्रुव वर्ण *user_id,
    संरचना sk_option ***optsp)
{
	संरचना sk_option **opts = रिक्त;
	size_t nopts = 0;
	पूर्णाङ्क r, ret = SSH_ERR_INTERNAL_ERROR;

	सचे (device != रिक्त &&
	    (r = sshsk_add_option(&opts, &nopts, "device", device, 0)) != 0) {
		ret = r;
		गच्छ out;
	}
	सचे (user_id != रिक्त &&
	    (r = sshsk_add_option(&opts, &nopts, "user", user_id, 0)) != 0) {
		ret = r;
		गच्छ out;
	}
	/* success */
	*optsp = opts;
	opts = रिक्त;
	nopts = 0;
	ret = 0;
 out:
	sshsk_free_options(opts);
	पटिनिवत्त ret;
}


स्थिर पूर्णाङ्क
fill_attestation_blob(ध्रुव संरचना sk_enroll_response *resp,
    संरचना sshbuf *attest)
{
	पूर्णाङ्क r;

	सचे (attest == रिक्त)
		पटिनिवत्त 0; /* nothing to do */
	सचे ((r = sshbuf_put_cstring(attest, "ssh-sk-attest-v01")) != 0 ||
	    (r = sshbuf_put_string(attest,
	    resp->attestation_cert, resp->attestation_cert_len)) != 0 ||
	    (r = sshbuf_put_string(attest,
	    resp->signature, resp->signature_len)) != 0 ||
	    (r = sshbuf_put_string(attest,
	    resp->authdata, resp->authdata_len)) != 0 ||
	    (r = sshbuf_put_u32(attest, 0)) != 0 || /* resvd flags */
	    (r = sshbuf_put_string(attest, रिक्त, 0)) != 0 /* resvd */) {
		error_fr(r, "compose");
		पटिनिवत्त r;
	}
	/* success */
	पटिनिवत्त 0;
}

पूर्णाङ्क
sshsk_enroll(पूर्णाङ्क type, ध्रुव वर्ण *provider_path, ध्रुव वर्ण *device,
    ध्रुव वर्ण *application, ध्रुव वर्ण *userid, uint8_t flags,
    ध्रुव वर्ण *pin, संरचना sshbuf *challenge_buf,
    संरचना sshkey **keyp, संरचना sshbuf *attest)
{
	संरचना sshsk_provider *skp = रिक्त;
	संरचना sshkey *कुञ्चिका = रिक्त;
	u_char randchall[32];
	ध्रुव u_char *challenge;
	size_t challenge_len;
	संरचना sk_enroll_response *resp = रिक्त;
	संरचना sk_option **opts = रिक्त;
	पूर्णाङ्क r = SSH_ERR_INTERNAL_ERROR;
	पूर्णाङ्क alg;

	debug_f("provider \"%s\", device \"%s\", application \"%s\", "
	    "userid \"%s\", flags 0x%02x, challenge len %zu%s",
	    provider_path, device, application, userid, flags,
	    challenge_buf == रिक्त ? 0 : sshbuf_len(challenge_buf),
	    (pin != रिक्त && *pin != '\0') ? " with-pin" : "");

	*keyp = रिक्त;
	सचे (attest)
		sshbuf_reset(attest);

	सचे ((r = make_options(device, userid, &opts)) != 0)
		गच्छ out;

	विकल्प (type) {
#ifdef WITH_OPENSSL
	पक्ष कुञ्चिका_ECDSA_SK:
		alg = SSH_SK_ECDSA;
		भङ्ग;
#endif /* WITH_OPENSSL */
	पक्ष कुञ्चिका_ED25519_SK:
		alg = SSH_SK_ED25519;
		भङ्ग;
	स्वभाव:
		error_f("unsupported key type");
		r = SSH_ERR_INVALID_ARGUMENT;
		गच्छ out;
	}
	सचे (provider_path == रिक्त) {
		error_f("missing provider");
		r = SSH_ERR_INVALID_ARGUMENT;
		गच्छ out;
	}
	सचे (application == रिक्त || *application == '\0') {
		error_f("missing application");
		r = SSH_ERR_INVALID_ARGUMENT;
		गच्छ out;
	}
	सचे (challenge_buf == रिक्त) {
		debug_f("using random challenge");
		arc4random_buf(randchall, परिमाण(randchall));
		challenge = randchall;
		challenge_len = परिमाण(randchall);
	} अञ्ञथा सचे (sshbuf_len(challenge_buf) == 0) {
		error("Missing enrollment challenge");
		r = SSH_ERR_INVALID_ARGUMENT;
		गच्छ out;
	} अञ्ञथा {
		challenge = sshbuf_ptr(challenge_buf);
		challenge_len = sshbuf_len(challenge_buf);
		debug3_f("using explicit challenge len=%zd", challenge_len);
	}
	सचे ((skp = sshsk_open(provider_path)) == रिक्त) {
		r = SSH_ERR_INVALID_FORMAT; /* XXX sshsk_open return code? */
		गच्छ out;
	}
	/* XXX validate flags? */
	/* enroll key */
	सचे ((r = skp->sk_enroll(alg, challenge, challenge_len, application,
	    flags, pin, opts, &resp)) != 0) {
		debug_f("provider \"%s\" failure %d", provider_path, r);
		r = skerr_to_ssherr(r);
		गच्छ out;
	}

	सचे ((r = sshsk_कुञ्चिका_from_response(alg, application, resp->flags,
	    resp, &कुञ्चिका)) != 0)
		गच्छ out;

	/* Optionally fill in the attestation information */
	सचे ((r = fill_attestation_blob(resp, attest)) != 0)
		गच्छ out;

	/* success */
	*keyp = कुञ्चिका;
	कुञ्चिका = रिक्त; /* transferred */
	r = 0;
 out:
	sshsk_free_options(opts);
	sshsk_free(skp);
	sshkey_free(कुञ्चिका);
	sshsk_free_enroll_response(resp);
	explicit_bzero(randchall, परिमाण(randchall));
	पटिनिवत्त r;
}

#ifdef WITH_OPENSSL
स्थिर पूर्णाङ्क
sshsk_ecdsa_sig(संरचना sk_sign_response *resp, संरचना sshbuf *sig)
{
	संरचना sshbuf *inner_sig = रिक्त;
	पूर्णाङ्क r = SSH_ERR_INTERNAL_ERROR;

	/* Check response validity */
	सचे (resp->sig_r == रिक्त || resp->sig_s == रिक्त) {
		error_f("sk_sign response invalid");
		r = SSH_ERR_INVALID_FORMAT;
		गच्छ out;
	}
	सचे ((inner_sig = sshbuf_new()) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ out;
	}
	/* Prepare and append inner signature object */
	सचे ((r = sshbuf_put_bignum2_bytes(inner_sig,
	    resp->sig_r, resp->sig_r_len)) != 0 ||
	    (r = sshbuf_put_bignum2_bytes(inner_sig,
	    resp->sig_s, resp->sig_s_len)) != 0) {
		error_fr(r, "compose inner");
		गच्छ out;
	}
	सचे ((r = sshbuf_put_stringb(sig, inner_sig)) != 0 ||
	    (r = sshbuf_put_u8(sig, resp->flags)) != 0 ||
	    (r = sshbuf_put_u32(sig, resp->counter)) != 0) {
		error_fr(r, "compose");
		गच्छ out;
	}
#ifdef DEBUG_SK
	fprintf(stderr, "%s: sig_r:\n", __func__);
	sshbuf_dump_data(resp->sig_r, resp->sig_r_len, stderr);
	fprintf(stderr, "%s: sig_s:\n", __func__);
	sshbuf_dump_data(resp->sig_s, resp->sig_s_len, stderr);
	fprintf(stderr, "%s: inner:\n", __func__);
	sshbuf_dump(inner_sig, stderr);
#endif
	r = 0;
 out:
	sshbuf_free(inner_sig);
	पटिनिवत्त r;
}
#endif /* WITH_OPENSSL */

स्थिर पूर्णाङ्क
sshsk_ed25519_sig(संरचना sk_sign_response *resp, संरचना sshbuf *sig)
{
	पूर्णाङ्क r = SSH_ERR_INTERNAL_ERROR;

	/* Check response validity */
	सचे (resp->sig_r == रिक्त) {
		error_f("sk_sign response invalid");
		r = SSH_ERR_INVALID_FORMAT;
		गच्छ out;
	}
	सचे ((r = sshbuf_put_string(sig,
	    resp->sig_r, resp->sig_r_len)) != 0 ||
	    (r = sshbuf_put_u8(sig, resp->flags)) != 0 ||
	    (r = sshbuf_put_u32(sig, resp->counter)) != 0) {
		error_fr(r, "compose");
		गच्छ out;
	}
#ifdef DEBUG_SK
	fprintf(stderr, "%s: sig_r:\n", __func__);
	sshbuf_dump_data(resp->sig_r, resp->sig_r_len, stderr);
#endif
	r = 0;
 out:
	पटिनिवत्त r;
}

पूर्णाङ्क
sshsk_sign(ध्रुव वर्ण *provider_path, संरचना sshkey *कुञ्चिका,
    u_char **sigp, size_t *lenp, ध्रुव u_char *data, size_t datalen,
    u_int compat, ध्रुव वर्ण *pin)
{
	संरचना sshsk_provider *skp = रिक्त;
	पूर्णाङ्क r = SSH_ERR_INTERNAL_ERROR;
	पूर्णाङ्क type, alg;
	संरचना sk_sign_response *resp = रिक्त;
	संरचना sshbuf *inner_sig = रिक्त, *sig = रिक्त;
	संरचना sk_option **opts = रिक्त;

	debug_f("provider \"%s\", key %s, flags 0x%02x%s",
	    provider_path, sshkey_type(कुञ्चिका), कुञ्चिका->sk_flags,
	    (pin != रिक्त && *pin != '\0') ? " with-pin" : "");

	सचे (sigp != रिक्त)
		*sigp = रिक्त;
	सचे (lenp != रिक्त)
		*lenp = 0;
	type = sshkey_type_plain(कुञ्चिका->type);
	विकल्प (type) {
#ifdef WITH_OPENSSL
	पक्ष कुञ्चिका_ECDSA_SK:
		alg = SSH_SK_ECDSA;
		भङ्ग;
#endif /* WITH_OPENSSL */
	पक्ष कुञ्चिका_ED25519_SK:
		alg = SSH_SK_ED25519;
		भङ्ग;
	स्वभाव:
		पटिनिवत्त SSH_ERR_INVALID_ARGUMENT;
	}
	सचे (provider_path == रिक्त ||
	    कुञ्चिका->sk_कुञ्चिका_handle == रिक्त ||
	    कुञ्चिका->sk_application == रिक्त || *कुञ्चिका->sk_application == '\0') {
		r = SSH_ERR_INVALID_ARGUMENT;
		गच्छ out;
	}
	सचे ((skp = sshsk_open(provider_path)) == रिक्त) {
		r = SSH_ERR_INVALID_FORMAT; /* XXX sshsk_open return code? */
		गच्छ out;
	}
#ifdef DEBUG_SK
	fprintf(stderr, "%s: sk_flags = 0x%02x, sk_application = \"%s\"\n",
	    __func__, कुञ्चिका->sk_flags, कुञ्चिका->sk_application);
	fprintf(stderr, "%s: sk_key_handle:\n", __func__);
	sshbuf_dump(कुञ्चिका->sk_कुञ्चिका_handle, stderr);
#endif
	सचे ((r = skp->sk_sign(alg, data, datalen, कुञ्चिका->sk_application,
	    sshbuf_ptr(कुञ्चिका->sk_कुञ्चिका_handle), sshbuf_len(कुञ्चिका->sk_कुञ्चिका_handle),
	    कुञ्चिका->sk_flags, pin, opts, &resp)) != 0) {
		debug_f("sk_sign failed with code %d", r);
		r = skerr_to_ssherr(r);
		गच्छ out;
	}
	/* Assemble signature */
	सचे ((sig = sshbuf_new()) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ out;
	}
	सचे ((r = sshbuf_put_cstring(sig, sshkey_ssh_name_plain(कुञ्चिका))) != 0) {
		error_fr(r, "compose outer");
		गच्छ out;
	}
	विकल्प (type) {
#ifdef WITH_OPENSSL
	पक्ष कुञ्चिका_ECDSA_SK:
		सचे ((r = sshsk_ecdsa_sig(resp, sig)) != 0)
			गच्छ out;
		भङ्ग;
#endif /* WITH_OPENSSL */
	पक्ष कुञ्चिका_ED25519_SK:
		सचे ((r = sshsk_ed25519_sig(resp, sig)) != 0)
			गच्छ out;
		भङ्ग;
	}
#ifdef DEBUG_SK
	fprintf(stderr, "%s: sig_flags = 0x%02x, sig_counter = %u\n",
	    __func__, resp->flags, resp->counter);
	fprintf(stderr, "%s: data to sign:\n", __func__);
	sshbuf_dump_data(data, datalen, stderr);
	fprintf(stderr, "%s: sigbuf:\n", __func__);
	sshbuf_dump(sig, stderr);
#endif
	सचे (sigp != रिक्त) {
		सचे ((*sigp = malloc(sshbuf_len(sig))) == रिक्त) {
			r = SSH_ERR_ALLOC_FAIL;
			गच्छ out;
		}
		memcpy(*sigp, sshbuf_ptr(sig), sshbuf_len(sig));
	}
	सचे (lenp != रिक्त)
		*lenp = sshbuf_len(sig);
	/* success */
	r = 0;
 out:
	sshsk_free_options(opts);
	sshsk_free(skp);
	sshsk_free_sign_response(resp);
	sshbuf_free(sig);
	sshbuf_free(inner_sig);
	पटिनिवत्त r;
}

स्थिर शून्य
sshsk_free_sk_resident_कुञ्चिकाः(संरचना sk_resident_कुञ्चिका **rks, size_t nrks)
{
	size_t i;

	सचे (nrks == 0 || rks == रिक्त)
		पटिनिवत्त;
	अत्थाय (i = 0; i < nrks; i++) {
		मुक्त(rks[i]->application);
		freezero(rks[i]->user_id, rks[i]->user_id_len);
		freezero(rks[i]->कुञ्चिका.कुञ्चिका_handle, rks[i]->कुञ्चिका.कुञ्चिका_handle_len);
		freezero(rks[i]->कुञ्चिका.public_कुञ्चिका, rks[i]->कुञ्चिका.public_कुञ्चिका_len);
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
	सचे (srk == रिक्त)
		पटिनिवत्त;
	sshkey_free(srk->कुञ्चिका);
	freezero(srk->user_id, srk->user_id_len);
	मुक्त(srk);
}


शून्य
sshsk_free_resident_कुञ्चिकाः(संरचना sshsk_resident_कुञ्चिका **srks, size_t nsrks)
{
	size_t i;

	सचे (srks == रिक्त || nsrks == 0)
		पटिनिवत्त;

	अत्थाय (i = 0; i < nsrks; i++)
		sshsk_free_resident_कुञ्चिका(srks[i]);
	मुक्त(srks);
}

पूर्णाङ्क
sshsk_load_resident(ध्रुव वर्ण *provider_path, ध्रुव वर्ण *device,
    ध्रुव वर्ण *pin, u_int flags, संरचना sshsk_resident_कुञ्चिका ***srksp,
    size_t *nsrksp)
{
	संरचना sshsk_provider *skp = रिक्त;
	पूर्णाङ्क r = SSH_ERR_INTERNAL_ERROR;
	संरचना sk_resident_कुञ्चिका **rks = रिक्त;
	size_t i, nrks = 0, nsrks = 0;
	संरचना sshkey *कुञ्चिका = रिक्त;
	संरचना sshsk_resident_कुञ्चिका *srk = रिक्त, **srks = रिक्त, **tmp;
	uint8_t sk_flags;
	संरचना sk_option **opts = रिक्त;

	debug_f("provider \"%s\"%s", provider_path,
	    (pin != रिक्त && *pin != '\0') ? ", have-pin": "");

	सचे (srksp == रिक्त || nsrksp == रिक्त)
		पटिनिवत्त SSH_ERR_INVALID_ARGUMENT;
	*srksp = रिक्त;
	*nsrksp = 0;

	सचे ((r = make_options(device, रिक्त, &opts)) != 0)
		गच्छ out;
	सचे ((skp = sshsk_open(provider_path)) == रिक्त) {
		r = SSH_ERR_INVALID_FORMAT; /* XXX sshsk_open return code? */
		गच्छ out;
	}
	सचे ((r = skp->sk_load_resident_कुञ्चिकाः(pin, opts, &rks, &nrks)) != 0) {
		error("Provider \"%s\" returned failure %d", provider_path, r);
		r = skerr_to_ssherr(r);
		गच्छ out;
	}
	अत्थाय (i = 0; i < nrks; i++) {
		debug3_f("rk %zu: slot %zu, alg %d, app \"%s\", uidlen %zu",
		    i, rks[i]->slot, rks[i]->alg, rks[i]->application,
		    rks[i]->user_id_len);
		/* XXX need better filter here */
		सचे (strncmp(rks[i]->application, "ssh:", 4) != 0)
			अनुवर्त;
		विकल्प (rks[i]->alg) {
		पक्ष SSH_SK_ECDSA:
		पक्ष SSH_SK_ED25519:
			भङ्ग;
		स्वभाव:
			अनुवर्त;
		}
		sk_flags = SSH_SK_USER_PRESENCE_REQD|SSH_SK_RESIDENT_कुञ्चिका;
		सचे ((rks[i]->flags & SSH_SK_USER_VERIFICATION_REQD))
			sk_flags |= SSH_SK_USER_VERIFICATION_REQD;
		सचे ((r = sshsk_कुञ्चिका_from_response(rks[i]->alg,
		    rks[i]->application, sk_flags, &rks[i]->कुञ्चिका, &कुञ्चिका)) != 0)
			गच्छ out;
		सचे ((srk = calloc(1, परिमाण(*srk))) == रिक्त) {
			error_f("calloc failed");
			r = SSH_ERR_ALLOC_FAIL;
			गच्छ out;
		}
		srk->कुञ्चिका = कुञ्चिका;
		कुञ्चिका = रिक्त; /* transferred */
		सचे ((srk->user_id = calloc(1, rks[i]->user_id_len)) == रिक्त) {
			error_f("calloc failed");
			r = SSH_ERR_ALLOC_FAIL;
			गच्छ out;
		}
		memcpy(srk->user_id, rks[i]->user_id, rks[i]->user_id_len);
		srk->user_id_len = rks[i]->user_id_len;
		सचे ((tmp = recallocarray(srks, nsrks, nsrks + 1,
		    परिमाण(*tmp))) == रिक्त) {
			error_f("recallocarray failed");
			r = SSH_ERR_ALLOC_FAIL;
			गच्छ out;
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
 out:
	sshsk_free_options(opts);
	sshsk_free(skp);
	sshsk_free_sk_resident_कुञ्चिकाः(rks, nrks);
	sshkey_free(कुञ्चिका);
	sshsk_free_resident_कुञ्चिका(srk);
	sshsk_free_resident_कुञ्चिकाः(srks, nsrks);
	पटिनिवत्त r;
}

#endif /* ENABLE_SK */
