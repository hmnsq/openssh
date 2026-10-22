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
	    माप_प्रकार challenge_len, ध्रुव वर्ण *application, uint8_t flags,
	    ध्रुव वर्ण *pin, संरचना sk_option **opts,
	    संरचना sk_enroll_response **enroll_response);

	/* Sign a challenge */
	पूर्णाङ्क (*sk_sign)(पूर्णाङ्क alg, ध्रुव uint8_t *message, माप_प्रकार message_len,
	    ध्रुव वर्ण *application,
	    ध्रुव uint8_t *कुंजी_handle, माप_प्रकार कुंजी_handle_len,
	    uint8_t flags, ध्रुव वर्ण *pin, संरचना sk_option **opts,
	    संरचना sk_sign_response **sign_response);

	/* Enumerate resident keys */
	पूर्णाङ्क (*sk_load_resident_कुंजियाँ)(ध्रुव वर्ण *pin, संरचना sk_option **opts,
	    संरचना sk_resident_कुंजी ***rks, माप_प्रकार *nrks);
};

/* Built-in version */
पूर्णाङ्क ssh_sk_enroll(पूर्णाङ्क alg, ध्रुव uint8_t *challenge,
    माप_प्रकार challenge_len, ध्रुव वर्ण *application, uint8_t flags,
    ध्रुव वर्ण *pin, संरचना sk_option **opts,
    संरचना sk_enroll_response **enroll_response);
पूर्णाङ्क ssh_sk_sign(पूर्णाङ्क alg, ध्रुव uint8_t *message, माप_प्रकार message_len,
    ध्रुव वर्ण *application,
    ध्रुव uint8_t *कुंजी_handle, माप_प्रकार कुंजी_handle_len,
    uint8_t flags, ध्रुव वर्ण *pin, संरचना sk_option **opts,
    संरचना sk_sign_response **sign_response);
पूर्णाङ्क ssh_sk_load_resident_कुंजियाँ(ध्रुव वर्ण *pin, संरचना sk_option **opts,
    संरचना sk_resident_कुंजी ***rks, माप_प्रकार *nrks);

स्थिर शून्य
sshsk_free(संरचना sshsk_provider *p)
{
	यदि (p == रिक्त)
		प्रत्यागम;
	मुक्त(p->path);
	यदि (p->dlhandle != रिक्त)
		dlclose(p->dlhandle);
	मुक्त(p);
}

स्थिर संरचना sshsk_provider *
sshsk_open(ध्रुव वर्ण *path)
{
	संरचना sshsk_provider *ret = रिक्त;
	uint32_t version;

	यदि (path == रिक्त || *path == '\0') {
		error("No FIDO SecurityKeyProvider specified");
		प्रत्यागम रिक्त;
	}
	यदि ((ret = सुस्मृति(1, परिमाण(*ret))) == रिक्त) {
		error_f("calloc failed");
		प्रत्यागम रिक्त;
	}
	यदि ((ret->path = strdup(path)) == रिक्त) {
		error_f("strdup failed");
		गच्छ fail;
	}
	/* Skip the rest if we're using the linked in middleware */
	यदि (strcasecmp(ret->path, "internal") == 0) {
#ifdef ENABLE_SK_INTERNAL
		ret->sk_enroll = ssh_sk_enroll;
		ret->sk_sign = ssh_sk_sign;
		ret->sk_load_resident_कुंजियाँ = ssh_sk_load_resident_कुंजियाँ;
		प्रत्यागम ret;
#अन्यथा
		error("internal security key support not enabled");
		गच्छ fail;
#endif
	}
	यदि (lib_contains_प्रतीक(path, "sk_api_version") != 0) {
		error("provider %s is not an OpenSSH FIDO library", path);
		गच्छ fail;
	}
	यदि ((ret->dlhandle = dlopen(path, RTLD_NOW)) == रिक्त)
		fatal("Provider \"%s\" dlopen failed: %s", path, dlerror());
	यदि ((ret->sk_api_version = dlsym(ret->dlhandle,
	    "sk_api_version")) == रिक्त) {
		error("Provider \"%s\" dlsym(sk_api_version) failed: %s",
		    path, dlerror());
		गच्छ fail;
	}
	version = ret->sk_api_version();
	debug_f("provider %s implements version 0x%08lx", ret->path,
	    (u_long)version);
	यदि ((version & SSH_SK_VERSION_MAJOR_MASK) != SSH_SK_VERSION_MAJOR) {
		error("Provider \"%s\" implements unsupported "
		    "version 0x%08lx (supported: 0x%08lx)",
		    path, (u_long)version, (u_long)SSH_SK_VERSION_MAJOR);
		गच्छ fail;
	}
	यदि ((ret->sk_enroll = dlsym(ret->dlhandle, "sk_enroll")) == रिक्त) {
		error("Provider %s dlsym(sk_enroll) failed: %s",
		    path, dlerror());
		गच्छ fail;
	}
	यदि ((ret->sk_sign = dlsym(ret->dlhandle, "sk_sign")) == रिक्त) {
		error("Provider \"%s\" dlsym(sk_sign) failed: %s",
		    path, dlerror());
		गच्छ fail;
	}
	यदि ((ret->sk_load_resident_कुंजियाँ = dlsym(ret->dlhandle,
	    "sk_load_resident_keys")) == रिक्त) {
		error("Provider \"%s\" dlsym(sk_load_resident_keys) "
		    "failed: %s", path, dlerror());
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
	freezero(r->कुंजी_handle, r->कुंजी_handle_len);
	freezero(r->public_कुंजी, r->public_कुंजी_len);
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

#ifdef WITH_OPENSSL
/* Assemble key from response */
स्थिर पूर्णाङ्क
sshsk_ecdsa_assemble(संरचना sk_enroll_response *resp, संरचना sshkey **keyp)
{
	संरचना sshkey *कुंजी = रिक्त;
	संरचना sshbuf *b = रिक्त;
	EC_कुंजी *ecdsa = रिक्त;
	EC_POINT *q = रिक्त;
	ध्रुव EC_GROUP *g = रिक्त;
	पूर्णाङ्क r;

	*keyp = रिक्त;
	यदि ((कुंजी = sshkey_new(कुंजी_ECDSA_SK)) == रिक्त) {
		error_f("sshkey_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ out;
	}
	कुंजी->ecdsa_nid = NID_X9_62_prime256v1;
	यदि ((ecdsa = EC_कुंजी_new_by_curve_name(कुंजी->ecdsa_nid)) == रिक्त ||
	    (g = EC_कुंजी_get0_group(ecdsa)) == रिक्त ||
	    (q = EC_POINT_new(g)) == रिक्त ||
	    (b = sshbuf_new()) == रिक्त) {
		error_f("allocation failed");
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ out;
	}
	यदि ((r = sshbuf_put_string(b,
	    resp->public_कुंजी, resp->public_कुंजी_len)) != 0) {
		error_fr(r, "sshbuf_put_string");
		गच्छ out;
	}
	यदि ((r = sshbuf_get_ec(b, q, g)) != 0) {
		error_fr(r, "parse");
		r = SSH_ERR_INVALID_FORMAT;
		गच्छ out;
	}
	यदि (sshkey_ec_validate_public(g, q) != 0) {
		error("Authenticator returned invalid ECDSA key");
		r = SSH_ERR_कुंजी_INVALID_EC_मूल्य;
		गच्छ out;
	}
	यदि (EC_कुंजी_set_public_कुंजी(ecdsa, q) != 1) {
		/* XXX assume it is a allocation error */
		error_f("allocation failed");
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ out;
	}
	यदि ((कुंजी->pkey = EVP_PKEY_new()) == रिक्त) {
		error_f("allocation failed");
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ out;
	}
	यदि (EVP_PKEY_set1_EC_कुंजी(कुंजी->pkey, ecdsa) != 1) {
		error_f("Assigning EC_KEY failed");
		r = SSH_ERR_LIBCRYPTO_ERROR;
		गच्छ out;
	}
	/* success */
	*keyp = कुंजी;
	कुंजी = रिक्त; /* transferred */
	r = 0;
 out:
	sshkey_free(कुंजी);
	sshbuf_free(b);
	EC_कुंजी_free(ecdsa);
	EC_POINT_free(q);
	प्रत्यागम r;
}
#endif /* WITH_OPENSSL */

स्थिर पूर्णाङ्क
sshsk_ed25519_assemble(संरचना sk_enroll_response *resp, संरचना sshkey **keyp)
{
	संरचना sshkey *कुंजी = रिक्त;
	पूर्णाङ्क r;

	*keyp = रिक्त;
	यदि (resp->public_कुंजी_len != ED25519_PK_SZ) {
		error_f("invalid size: %zu", resp->public_कुंजी_len);
		r = SSH_ERR_INVALID_FORMAT;
		गच्छ out;
	}
	यदि ((कुंजी = sshkey_new(कुंजी_ED25519_SK)) == रिक्त) {
		error_f("sshkey_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ out;
	}
	यदि ((कुंजी->ed25519_pk = दो_स्मृति(ED25519_PK_SZ)) == रिक्त) {
		error_f("malloc failed");
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ out;
	}
	स_नकल(कुंजी->ed25519_pk, resp->public_कुंजी, ED25519_PK_SZ);
	/* success */
	*keyp = कुंजी;
	कुंजी = रिक्त; /* transferred */
	r = 0;
 out:
	sshkey_free(कुंजी);
	प्रत्यागम r;
}

स्थिर पूर्णाङ्क
sshsk_कुंजी_from_response(पूर्णाङ्क alg, ध्रुव वर्ण *application, uint8_t flags,
    संरचना sk_enroll_response *resp, संरचना sshkey **keyp)
{
	संरचना sshkey *कुंजी = रिक्त;
	पूर्णाङ्क r = SSH_ERR_INTERNAL_ERROR;

	*keyp = रिक्त;

	/* Check response validity */
	यदि (resp->public_कुंजी == रिक्त || resp->कुंजी_handle == रिक्त) {
		error_f("sk_enroll response invalid");
		r = SSH_ERR_INVALID_FORMAT;
		गच्छ out;
	}
	विकल्प (alg) {
#ifdef WITH_OPENSSL
	पक्ष SSH_SK_ECDSA:
		यदि ((r = sshsk_ecdsa_assemble(resp, &कुंजी)) != 0)
			गच्छ out;
		भङ्ग;
#endif /* WITH_OPENSSL */
	पक्ष SSH_SK_ED25519:
		यदि ((r = sshsk_ed25519_assemble(resp, &कुंजी)) != 0)
			गच्छ out;
		भङ्ग;
	स्वभाव:
		error_f("unsupported algorithm %d", alg);
		r = SSH_ERR_INVALID_ARGUMENT;
		गच्छ out;
	}
	कुंजी->sk_flags = flags;
	यदि ((कुंजी->sk_कुंजी_handle = sshbuf_new()) == रिक्त ||
	    (कुंजी->sk_reserved = sshbuf_new()) == रिक्त) {
		error_f("allocation failed");
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ out;
	}
	यदि ((कुंजी->sk_application = strdup(application)) == रिक्त) {
		error_f("strdup application failed");
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ out;
	}
	यदि ((r = sshbuf_put(कुंजी->sk_कुंजी_handle, resp->कुंजी_handle,
	    resp->कुंजी_handle_len)) != 0) {
		error_fr(r, "put key handle");
		गच्छ out;
	}
	/* success */
	r = 0;
	*keyp = कुंजी;
	कुंजी = रिक्त;
 out:
	sshkey_free(कुंजी);
	प्रत्यागम r;
}

स्थिर पूर्णाङ्क
skerr_to_ssherr(पूर्णाङ्क skerr)
{
	विकल्प (skerr) {
	पक्ष SSH_SK_ERR_UNSUPPORTED:
		प्रत्यागम SSH_ERR_FEATURE_UNSUPPORTED;
	पक्ष SSH_SK_ERR_PIN_REQUIRED:
		प्रत्यागम SSH_ERR_कुंजी_WRONG_PASSPHRASE;
	पक्ष SSH_SK_ERR_DEVICE_NOT_FOUND:
		प्रत्यागम SSH_ERR_DEVICE_NOT_FOUND;
	पक्ष SSH_SK_ERR_CREDENTIAL_EXISTS:
		प्रत्यागम SSH_ERR_कुंजी_BAD_PERMISSIONS;
	पक्ष SSH_SK_ERR_GENERAL:
	स्वभाव:
		प्रत्यागम SSH_ERR_INVALID_FORMAT;
	}
}

स्थिर शून्य
sshsk_free_options(संरचना sk_option **opts)
{
	माप_प्रकार i;

	यदि (opts == रिक्त)
		प्रत्यागम;
	प्रति (i = 0; opts[i] != रिक्त; i++) {
		मुक्त(opts[i]->name);
		मुक्त(opts[i]->मूल्य);
		मुक्त(opts[i]);
	}
	मुक्त(opts);
}

स्थिर पूर्णाङ्क
sshsk_add_option(संरचना sk_option ***optsp, माप_प्रकार *noptsp,
    ध्रुव वर्ण *name, ध्रुव वर्ण *मूल्य, uint8_t required)
{
	संरचना sk_option **opts = *optsp;
	माप_प्रकार nopts = *noptsp;

	यदि ((opts = recallocarray(opts, nopts, nopts + 2, /* extra for NULL */
	    परिमाण(*opts))) == रिक्त) {
		error_f("array alloc failed");
		प्रत्यागम SSH_ERR_ALLOC_FAIL;
	}
	*optsp = opts;
	*noptsp = nopts + 1;
	यदि ((opts[nopts] = सुस्मृति(1, परिमाण(**opts))) == रिक्त) {
		error_f("alloc failed");
		प्रत्यागम SSH_ERR_ALLOC_FAIL;
	}
	यदि ((opts[nopts]->name = strdup(name)) == रिक्त ||
	    (opts[nopts]->मूल्य = strdup(मूल्य)) == रिक्त) {
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
	माप_प्रकार nopts = 0;
	पूर्णाङ्क r, ret = SSH_ERR_INTERNAL_ERROR;

	यदि (device != रिक्त &&
	    (r = sshsk_add_option(&opts, &nopts, "device", device, 0)) != 0) {
		ret = r;
		गच्छ out;
	}
	यदि (user_id != रिक्त &&
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
sshsk_enroll(पूर्णाङ्क type, ध्रुव वर्ण *provider_path, ध्रुव वर्ण *device,
    ध्रुव वर्ण *application, ध्रुव वर्ण *userid, uint8_t flags,
    ध्रुव वर्ण *pin, संरचना sshbuf *challenge_buf,
    संरचना sshkey **keyp, संरचना sshbuf *attest)
{
	संरचना sshsk_provider *skp = रिक्त;
	संरचना sshkey *कुंजी = रिक्त;
	u_char randchall[32];
	ध्रुव u_char *challenge;
	माप_प्रकार challenge_len;
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
	यदि (attest)
		sshbuf_reset(attest);

	यदि ((r = make_options(device, userid, &opts)) != 0)
		गच्छ out;

	विकल्प (type) {
#ifdef WITH_OPENSSL
	पक्ष कुंजी_ECDSA_SK:
		alg = SSH_SK_ECDSA;
		भङ्ग;
#endif /* WITH_OPENSSL */
	पक्ष कुंजी_ED25519_SK:
		alg = SSH_SK_ED25519;
		भङ्ग;
	स्वभाव:
		error_f("unsupported key type");
		r = SSH_ERR_INVALID_ARGUMENT;
		गच्छ out;
	}
	यदि (provider_path == रिक्त) {
		error_f("missing provider");
		r = SSH_ERR_INVALID_ARGUMENT;
		गच्छ out;
	}
	यदि (application == रिक्त || *application == '\0') {
		error_f("missing application");
		r = SSH_ERR_INVALID_ARGUMENT;
		गच्छ out;
	}
	यदि (challenge_buf == रिक्त) {
		debug_f("using random challenge");
		arc4random_buf(randchall, परिमाण(randchall));
		challenge = randchall;
		challenge_len = परिमाण(randchall);
	} अन्यथा यदि (sshbuf_len(challenge_buf) == 0) {
		error("Missing enrollment challenge");
		r = SSH_ERR_INVALID_ARGUMENT;
		गच्छ out;
	} अन्यथा {
		challenge = sshbuf_ptr(challenge_buf);
		challenge_len = sshbuf_len(challenge_buf);
		debug3_f("using explicit challenge len=%zd", challenge_len);
	}
	यदि ((skp = sshsk_open(provider_path)) == रिक्त) {
		r = SSH_ERR_INVALID_FORMAT; /* XXX sshsk_open return code? */
		गच्छ out;
	}
	/* XXX validate flags? */
	/* enroll key */
	यदि ((r = skp->sk_enroll(alg, challenge, challenge_len, application,
	    flags, pin, opts, &resp)) != 0) {
		debug_f("provider \"%s\" failure %d", provider_path, r);
		r = skerr_to_ssherr(r);
		गच्छ out;
	}

	यदि ((r = sshsk_कुंजी_from_response(alg, application, resp->flags,
	    resp, &कुंजी)) != 0)
		गच्छ out;

	/* Optionally fill in the attestation information */
	यदि ((r = fill_attestation_blob(resp, attest)) != 0)
		गच्छ out;

	/* success */
	*keyp = कुंजी;
	कुंजी = रिक्त; /* transferred */
	r = 0;
 out:
	sshsk_free_options(opts);
	sshsk_free(skp);
	sshkey_free(कुंजी);
	sshsk_free_enroll_response(resp);
	explicit_bzero(randchall, परिमाण(randchall));
	प्रत्यागम r;
}

#ifdef WITH_OPENSSL
स्थिर पूर्णाङ्क
sshsk_ecdsa_sig(संरचना sk_sign_response *resp, संरचना sshbuf *sig)
{
	संरचना sshbuf *inner_sig = रिक्त;
	पूर्णाङ्क r = SSH_ERR_INTERNAL_ERROR;

	/* Check response validity */
	यदि (resp->sig_r == रिक्त || resp->sig_s == रिक्त) {
		error_f("sk_sign response invalid");
		r = SSH_ERR_INVALID_FORMAT;
		गच्छ out;
	}
	यदि ((inner_sig = sshbuf_new()) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ out;
	}
	/* Prepare and append inner signature object */
	यदि ((r = sshbuf_put_bignum2_bytes(inner_sig,
	    resp->sig_r, resp->sig_r_len)) != 0 ||
	    (r = sshbuf_put_bignum2_bytes(inner_sig,
	    resp->sig_s, resp->sig_s_len)) != 0) {
		error_fr(r, "compose inner");
		गच्छ out;
	}
	यदि ((r = sshbuf_put_stringb(sig, inner_sig)) != 0 ||
	    (r = sshbuf_put_u8(sig, resp->flags)) != 0 ||
	    (r = sshbuf_put_u32(sig, resp->counter)) != 0) {
		error_fr(r, "compose");
		गच्छ out;
	}
#ifdef DEBUG_SK
	ख_लिखो(मानक_त्रुटि, "%s: sig_r:\n", __func__);
	sshbuf_dump_data(resp->sig_r, resp->sig_r_len, मानक_त्रुटि);
	ख_लिखो(मानक_त्रुटि, "%s: sig_s:\n", __func__);
	sshbuf_dump_data(resp->sig_s, resp->sig_s_len, मानक_त्रुटि);
	ख_लिखो(मानक_त्रुटि, "%s: inner:\n", __func__);
	sshbuf_dump(inner_sig, मानक_त्रुटि);
#endif
	r = 0;
 out:
	sshbuf_free(inner_sig);
	प्रत्यागम r;
}
#endif /* WITH_OPENSSL */

स्थिर पूर्णाङ्क
sshsk_ed25519_sig(संरचना sk_sign_response *resp, संरचना sshbuf *sig)
{
	पूर्णाङ्क r = SSH_ERR_INTERNAL_ERROR;

	/* Check response validity */
	यदि (resp->sig_r == रिक्त) {
		error_f("sk_sign response invalid");
		r = SSH_ERR_INVALID_FORMAT;
		गच्छ out;
	}
	यदि ((r = sshbuf_put_string(sig,
	    resp->sig_r, resp->sig_r_len)) != 0 ||
	    (r = sshbuf_put_u8(sig, resp->flags)) != 0 ||
	    (r = sshbuf_put_u32(sig, resp->counter)) != 0) {
		error_fr(r, "compose");
		गच्छ out;
	}
#ifdef DEBUG_SK
	ख_लिखो(मानक_त्रुटि, "%s: sig_r:\n", __func__);
	sshbuf_dump_data(resp->sig_r, resp->sig_r_len, मानक_त्रुटि);
#endif
	r = 0;
 out:
	प्रत्यागम r;
}

पूर्णाङ्क
sshsk_sign(ध्रुव वर्ण *provider_path, संरचना sshkey *कुंजी,
    u_char **sigp, माप_प्रकार *lenp, ध्रुव u_char *data, माप_प्रकार datalen,
    u_int compat, ध्रुव वर्ण *pin)
{
	संरचना sshsk_provider *skp = रिक्त;
	पूर्णाङ्क r = SSH_ERR_INTERNAL_ERROR;
	पूर्णाङ्क type, alg;
	संरचना sk_sign_response *resp = रिक्त;
	संरचना sshbuf *inner_sig = रिक्त, *sig = रिक्त;
	संरचना sk_option **opts = रिक्त;

	debug_f("provider \"%s\", key %s, flags 0x%02x%s",
	    provider_path, sshkey_type(कुंजी), कुंजी->sk_flags,
	    (pin != रिक्त && *pin != '\0') ? " with-pin" : "");

	यदि (sigp != रिक्त)
		*sigp = रिक्त;
	यदि (lenp != रिक्त)
		*lenp = 0;
	type = sshkey_type_plain(कुंजी->type);
	विकल्प (type) {
#ifdef WITH_OPENSSL
	पक्ष कुंजी_ECDSA_SK:
		alg = SSH_SK_ECDSA;
		भङ्ग;
#endif /* WITH_OPENSSL */
	पक्ष कुंजी_ED25519_SK:
		alg = SSH_SK_ED25519;
		भङ्ग;
	स्वभाव:
		प्रत्यागम SSH_ERR_INVALID_ARGUMENT;
	}
	यदि (provider_path == रिक्त ||
	    कुंजी->sk_कुंजी_handle == रिक्त ||
	    कुंजी->sk_application == रिक्त || *कुंजी->sk_application == '\0') {
		r = SSH_ERR_INVALID_ARGUMENT;
		गच्छ out;
	}
	यदि ((skp = sshsk_open(provider_path)) == रिक्त) {
		r = SSH_ERR_INVALID_FORMAT; /* XXX sshsk_open return code? */
		गच्छ out;
	}
#ifdef DEBUG_SK
	ख_लिखो(मानक_त्रुटि, "%s: sk_flags = 0x%02x, sk_application = \"%s\"\n",
	    __func__, कुंजी->sk_flags, कुंजी->sk_application);
	ख_लिखो(मानक_त्रुटि, "%s: sk_key_handle:\n", __func__);
	sshbuf_dump(कुंजी->sk_कुंजी_handle, मानक_त्रुटि);
#endif
	यदि ((r = skp->sk_sign(alg, data, datalen, कुंजी->sk_application,
	    sshbuf_ptr(कुंजी->sk_कुंजी_handle), sshbuf_len(कुंजी->sk_कुंजी_handle),
	    कुंजी->sk_flags, pin, opts, &resp)) != 0) {
		debug_f("sk_sign failed with code %d", r);
		r = skerr_to_ssherr(r);
		गच्छ out;
	}
	/* Assemble signature */
	यदि ((sig = sshbuf_new()) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		गच्छ out;
	}
	यदि ((r = sshbuf_put_cstring(sig, sshkey_ssh_name_plain(कुंजी))) != 0) {
		error_fr(r, "compose outer");
		गच्छ out;
	}
	विकल्प (type) {
#ifdef WITH_OPENSSL
	पक्ष कुंजी_ECDSA_SK:
		यदि ((r = sshsk_ecdsa_sig(resp, sig)) != 0)
			गच्छ out;
		भङ्ग;
#endif /* WITH_OPENSSL */
	पक्ष कुंजी_ED25519_SK:
		यदि ((r = sshsk_ed25519_sig(resp, sig)) != 0)
			गच्छ out;
		भङ्ग;
	}
#ifdef DEBUG_SK
	ख_लिखो(मानक_त्रुटि, "%s: sig_flags = 0x%02x, sig_counter = %u\n",
	    __func__, resp->flags, resp->counter);
	ख_लिखो(मानक_त्रुटि, "%s: data to sign:\n", __func__);
	sshbuf_dump_data(data, datalen, मानक_त्रुटि);
	ख_लिखो(मानक_त्रुटि, "%s: sigbuf:\n", __func__);
	sshbuf_dump(sig, मानक_त्रुटि);
#endif
	यदि (sigp != रिक्त) {
		यदि ((*sigp = दो_स्मृति(sshbuf_len(sig))) == रिक्त) {
			r = SSH_ERR_ALLOC_FAIL;
			गच्छ out;
		}
		स_नकल(*sigp, sshbuf_ptr(sig), sshbuf_len(sig));
	}
	यदि (lenp != रिक्त)
		*lenp = sshbuf_len(sig);
	/* success */
	r = 0;
 out:
	sshsk_free_options(opts);
	sshsk_free(skp);
	sshsk_free_sign_response(resp);
	sshbuf_free(sig);
	sshbuf_free(inner_sig);
	प्रत्यागम r;
}

स्थिर शून्य
sshsk_free_sk_resident_कुंजियाँ(संरचना sk_resident_कुंजी **rks, माप_प्रकार nrks)
{
	माप_प्रकार i;

	यदि (nrks == 0 || rks == रिक्त)
		प्रत्यागम;
	प्रति (i = 0; i < nrks; i++) {
		मुक्त(rks[i]->application);
		freezero(rks[i]->user_id, rks[i]->user_id_len);
		freezero(rks[i]->कुंजी.कुंजी_handle, rks[i]->कुंजी.कुंजी_handle_len);
		freezero(rks[i]->कुंजी.public_कुंजी, rks[i]->कुंजी.public_कुंजी_len);
		freezero(rks[i]->कुंजी.signature, rks[i]->कुंजी.signature_len);
		freezero(rks[i]->कुंजी.attestation_cert,
		    rks[i]->कुंजी.attestation_cert_len);
		freezero(rks[i], परिमाण(**rks));
	}
	मुक्त(rks);
}

स्थिर शून्य
sshsk_free_resident_कुंजी(संरचना sshsk_resident_कुंजी *srk)
{
	यदि (srk == रिक्त)
		प्रत्यागम;
	sshkey_free(srk->कुंजी);
	freezero(srk->user_id, srk->user_id_len);
	मुक्त(srk);
}


शून्य
sshsk_free_resident_कुंजियाँ(संरचना sshsk_resident_कुंजी **srks, माप_प्रकार nsrks)
{
	माप_प्रकार i;

	यदि (srks == रिक्त || nsrks == 0)
		प्रत्यागम;

	प्रति (i = 0; i < nsrks; i++)
		sshsk_free_resident_कुंजी(srks[i]);
	मुक्त(srks);
}

पूर्णाङ्क
sshsk_load_resident(ध्रुव वर्ण *provider_path, ध्रुव वर्ण *device,
    ध्रुव वर्ण *pin, u_int flags, संरचना sshsk_resident_कुंजी ***srksp,
    माप_प्रकार *nsrksp)
{
	संरचना sshsk_provider *skp = रिक्त;
	पूर्णाङ्क r = SSH_ERR_INTERNAL_ERROR;
	संरचना sk_resident_कुंजी **rks = रिक्त;
	माप_प्रकार i, nrks = 0, nsrks = 0;
	संरचना sshkey *कुंजी = रिक्त;
	संरचना sshsk_resident_कुंजी *srk = रिक्त, **srks = रिक्त, **tmp;
	uint8_t sk_flags;
	संरचना sk_option **opts = रिक्त;

	debug_f("provider \"%s\"%s", provider_path,
	    (pin != रिक्त && *pin != '\0') ? ", have-pin": "");

	यदि (srksp == रिक्त || nsrksp == रिक्त)
		प्रत्यागम SSH_ERR_INVALID_ARGUMENT;
	*srksp = रिक्त;
	*nsrksp = 0;

	यदि ((r = make_options(device, रिक्त, &opts)) != 0)
		गच्छ out;
	यदि ((skp = sshsk_open(provider_path)) == रिक्त) {
		r = SSH_ERR_INVALID_FORMAT; /* XXX sshsk_open return code? */
		गच्छ out;
	}
	यदि ((r = skp->sk_load_resident_कुंजियाँ(pin, opts, &rks, &nrks)) != 0) {
		error("Provider \"%s\" returned failure %d", provider_path, r);
		r = skerr_to_ssherr(r);
		गच्छ out;
	}
	प्रति (i = 0; i < nrks; i++) {
		debug3_f("rk %zu: slot %zu, alg %d, app \"%s\", uidlen %zu",
		    i, rks[i]->slot, rks[i]->alg, rks[i]->application,
		    rks[i]->user_id_len);
		/* XXX need better filter here */
		यदि (म_भेदन(rks[i]->application, "ssh:", 4) != 0)
			अनुवर्त;
		विकल्प (rks[i]->alg) {
		पक्ष SSH_SK_ECDSA:
		पक्ष SSH_SK_ED25519:
			भङ्ग;
		स्वभाव:
			अनुवर्त;
		}
		sk_flags = SSH_SK_USER_PRESENCE_REQD|SSH_SK_RESIDENT_कुंजी;
		यदि ((rks[i]->flags & SSH_SK_USER_VERIFICATION_REQD))
			sk_flags |= SSH_SK_USER_VERIFICATION_REQD;
		यदि ((r = sshsk_कुंजी_from_response(rks[i]->alg,
		    rks[i]->application, sk_flags, &rks[i]->कुंजी, &कुंजी)) != 0)
			गच्छ out;
		यदि ((srk = सुस्मृति(1, परिमाण(*srk))) == रिक्त) {
			error_f("calloc failed");
			r = SSH_ERR_ALLOC_FAIL;
			गच्छ out;
		}
		srk->कुंजी = कुंजी;
		कुंजी = रिक्त; /* transferred */
		यदि ((srk->user_id = सुस्मृति(1, rks[i]->user_id_len)) == रिक्त) {
			error_f("calloc failed");
			r = SSH_ERR_ALLOC_FAIL;
			गच्छ out;
		}
		स_नकल(srk->user_id, rks[i]->user_id, rks[i]->user_id_len);
		srk->user_id_len = rks[i]->user_id_len;
		यदि ((tmp = recallocarray(srks, nsrks, nsrks + 1,
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
	sshsk_free_sk_resident_कुंजियाँ(rks, nrks);
	sshkey_free(कुंजी);
	sshsk_free_resident_कुंजी(srk);
	sshsk_free_resident_कुंजियाँ(srks, nsrks);
	प्रत्यागम r;
}

#endif /* ENABLE_SK */
