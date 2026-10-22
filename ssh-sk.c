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
	अक्षर *path;
	शून्य *dlhandle;

	/* Return the version of the middleware API */
	uint32_t (*sk_api_version)(शून्य);

	/* Enroll a U2F key (private key generation) */
	पूर्णांक (*sk_enroll)(पूर्णांक alg, स्थिरांक uint8_t *challenge,
	    माप_प्रकार challenge_len, स्थिरांक अक्षर *application, uint8_t flags,
	    स्थिरांक अक्षर *pin, संरचना sk_option **opts,
	    संरचना sk_enroll_response **enroll_response);

	/* Sign a challenge */
	पूर्णांक (*sk_sign)(पूर्णांक alg, स्थिरांक uint8_t *message, माप_प्रकार message_len,
	    स्थिरांक अक्षर *application,
	    स्थिरांक uint8_t *किल्ली_handle, माप_प्रकार किल्ली_handle_len,
	    uint8_t flags, स्थिरांक अक्षर *pin, संरचना sk_option **opts,
	    संरचना sk_sign_response **sign_response);

	/* Enumerate resident keys */
	पूर्णांक (*sk_load_resident_किल्ल्या)(स्थिरांक अक्षर *pin, संरचना sk_option **opts,
	    संरचना sk_resident_किल्ली ***rks, माप_प्रकार *nrks);
};

/* Built-in version */
पूर्णांक ssh_sk_enroll(पूर्णांक alg, स्थिरांक uint8_t *challenge,
    माप_प्रकार challenge_len, स्थिरांक अक्षर *application, uint8_t flags,
    स्थिरांक अक्षर *pin, संरचना sk_option **opts,
    संरचना sk_enroll_response **enroll_response);
पूर्णांक ssh_sk_sign(पूर्णांक alg, स्थिरांक uint8_t *message, माप_प्रकार message_len,
    स्थिरांक अक्षर *application,
    स्थिरांक uint8_t *किल्ली_handle, माप_प्रकार किल्ली_handle_len,
    uint8_t flags, स्थिरांक अक्षर *pin, संरचना sk_option **opts,
    संरचना sk_sign_response **sign_response);
पूर्णांक ssh_sk_load_resident_किल्ल्या(स्थिरांक अक्षर *pin, संरचना sk_option **opts,
    संरचना sk_resident_किल्ली ***rks, माप_प्रकार *nrks);

स्थिर शून्य
sshsk_free(संरचना sshsk_provider *p)
{
	जर (p == रिक्त)
		परत;
	मुक्त(p->path);
	जर (p->dlhandle != रिक्त)
		dlclose(p->dlhandle);
	मुक्त(p);
}

स्थिर संरचना sshsk_provider *
sshsk_open(स्थिरांक अक्षर *path)
{
	संरचना sshsk_provider *ret = रिक्त;
	uint32_t version;

	जर (path == रिक्त || *path == '\0') {
		error("No FIDO SecurityKeyProvider specified");
		परत रिक्त;
	}
	जर ((ret = सुस्मृति(1, आकार(*ret))) == रिक्त) {
		error_f("calloc failed");
		परत रिक्त;
	}
	जर ((ret->path = strdup(path)) == रिक्त) {
		error_f("strdup failed");
		जा fail;
	}
	/* Skip the rest if we're using the linked in middleware */
	जर (strcasecmp(ret->path, "internal") == 0) {
#ifdef ENABLE_SK_INTERNAL
		ret->sk_enroll = ssh_sk_enroll;
		ret->sk_sign = ssh_sk_sign;
		ret->sk_load_resident_किल्ल्या = ssh_sk_load_resident_किल्ल्या;
		परत ret;
#अन्यथा
		error("internal security key support not enabled");
		जा fail;
#endif
	}
	जर (lib_contains_चिन्ह(path, "sk_api_version") != 0) {
		error("provider %s is not an OpenSSH FIDO library", path);
		जा fail;
	}
	जर ((ret->dlhandle = dlopen(path, RTLD_NOW)) == रिक्त)
		fatal("Provider \"%s\" dlopen failed: %s", path, dlerror());
	जर ((ret->sk_api_version = dlsym(ret->dlhandle,
	    "sk_api_version")) == रिक्त) {
		error("Provider \"%s\" dlsym(sk_api_version) failed: %s",
		    path, dlerror());
		जा fail;
	}
	version = ret->sk_api_version();
	debug_f("provider %s implements version 0x%08lx", ret->path,
	    (u_long)version);
	जर ((version & SSH_SK_VERSION_MAJOR_MASK) != SSH_SK_VERSION_MAJOR) {
		error("Provider \"%s\" implements unsupported "
		    "version 0x%08lx (supported: 0x%08lx)",
		    path, (u_long)version, (u_long)SSH_SK_VERSION_MAJOR);
		जा fail;
	}
	जर ((ret->sk_enroll = dlsym(ret->dlhandle, "sk_enroll")) == रिक्त) {
		error("Provider %s dlsym(sk_enroll) failed: %s",
		    path, dlerror());
		जा fail;
	}
	जर ((ret->sk_sign = dlsym(ret->dlhandle, "sk_sign")) == रिक्त) {
		error("Provider \"%s\" dlsym(sk_sign) failed: %s",
		    path, dlerror());
		जा fail;
	}
	जर ((ret->sk_load_resident_किल्ल्या = dlsym(ret->dlhandle,
	    "sk_load_resident_keys")) == रिक्त) {
		error("Provider \"%s\" dlsym(sk_load_resident_keys) "
		    "failed: %s", path, dlerror());
		जा fail;
	}
	/* success */
	परत ret;
fail:
	sshsk_free(ret);
	परत रिक्त;
}

स्थिर शून्य
sshsk_free_enroll_response(संरचना sk_enroll_response *r)
{
	जर (r == रिक्त)
		परत;
	freezero(r->किल्ली_handle, r->किल्ली_handle_len);
	freezero(r->public_किल्ली, r->public_किल्ली_len);
	freezero(r->signature, r->signature_len);
	freezero(r->attestation_cert, r->attestation_cert_len);
	freezero(r->authdata, r->authdata_len);
	freezero(r, आकार(*r));
}

स्थिर शून्य
sshsk_free_sign_response(संरचना sk_sign_response *r)
{
	जर (r == रिक्त)
		परत;
	freezero(r->sig_r, r->sig_r_len);
	freezero(r->sig_s, r->sig_s_len);
	freezero(r, आकार(*r));
}

#ifdef WITH_OPENSSL
/* Assemble key from response */
स्थिर पूर्णांक
sshsk_ecdsa_assemble(संरचना sk_enroll_response *resp, संरचना sshkey **keyp)
{
	संरचना sshkey *किल्ली = रिक्त;
	संरचना sshbuf *b = रिक्त;
	EC_किल्ली *ecdsa = रिक्त;
	EC_POINT *q = रिक्त;
	स्थिरांक EC_GROUP *g = रिक्त;
	पूर्णांक r;

	*keyp = रिक्त;
	जर ((किल्ली = sshkey_new(किल्ली_ECDSA_SK)) == रिक्त) {
		error_f("sshkey_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		जा out;
	}
	किल्ली->ecdsa_nid = NID_X9_62_prime256v1;
	जर ((ecdsa = EC_किल्ली_new_by_curve_name(किल्ली->ecdsa_nid)) == रिक्त ||
	    (g = EC_किल्ली_get0_group(ecdsa)) == रिक्त ||
	    (q = EC_POINT_new(g)) == रिक्त ||
	    (b = sshbuf_new()) == रिक्त) {
		error_f("allocation failed");
		r = SSH_ERR_ALLOC_FAIL;
		जा out;
	}
	जर ((r = sshbuf_put_string(b,
	    resp->public_किल्ली, resp->public_किल्ली_len)) != 0) {
		error_fr(r, "sshbuf_put_string");
		जा out;
	}
	जर ((r = sshbuf_get_ec(b, q, g)) != 0) {
		error_fr(r, "parse");
		r = SSH_ERR_INVALID_FORMAT;
		जा out;
	}
	जर (sshkey_ec_validate_public(g, q) != 0) {
		error("Authenticator returned invalid ECDSA key");
		r = SSH_ERR_किल्ली_INVALID_EC_मूल्य;
		जा out;
	}
	जर (EC_किल्ली_set_public_किल्ली(ecdsa, q) != 1) {
		/* XXX assume it is a allocation error */
		error_f("allocation failed");
		r = SSH_ERR_ALLOC_FAIL;
		जा out;
	}
	जर ((किल्ली->pkey = EVP_PKEY_new()) == रिक्त) {
		error_f("allocation failed");
		r = SSH_ERR_ALLOC_FAIL;
		जा out;
	}
	जर (EVP_PKEY_set1_EC_किल्ली(किल्ली->pkey, ecdsa) != 1) {
		error_f("Assigning EC_KEY failed");
		r = SSH_ERR_LIBCRYPTO_ERROR;
		जा out;
	}
	/* success */
	*keyp = किल्ली;
	किल्ली = रिक्त; /* transferred */
	r = 0;
 out:
	sshkey_free(किल्ली);
	sshbuf_free(b);
	EC_किल्ली_free(ecdsa);
	EC_POINT_free(q);
	परत r;
}
#endif /* WITH_OPENSSL */

स्थिर पूर्णांक
sshsk_ed25519_assemble(संरचना sk_enroll_response *resp, संरचना sshkey **keyp)
{
	संरचना sshkey *किल्ली = रिक्त;
	पूर्णांक r;

	*keyp = रिक्त;
	जर (resp->public_किल्ली_len != ED25519_PK_SZ) {
		error_f("invalid size: %zu", resp->public_किल्ली_len);
		r = SSH_ERR_INVALID_FORMAT;
		जा out;
	}
	जर ((किल्ली = sshkey_new(किल्ली_ED25519_SK)) == रिक्त) {
		error_f("sshkey_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		जा out;
	}
	जर ((किल्ली->ed25519_pk = दो_स्मृति(ED25519_PK_SZ)) == रिक्त) {
		error_f("malloc failed");
		r = SSH_ERR_ALLOC_FAIL;
		जा out;
	}
	स_नकल(किल्ली->ed25519_pk, resp->public_किल्ली, ED25519_PK_SZ);
	/* success */
	*keyp = किल्ली;
	किल्ली = रिक्त; /* transferred */
	r = 0;
 out:
	sshkey_free(किल्ली);
	परत r;
}

स्थिर पूर्णांक
sshsk_किल्ली_from_response(पूर्णांक alg, स्थिरांक अक्षर *application, uint8_t flags,
    संरचना sk_enroll_response *resp, संरचना sshkey **keyp)
{
	संरचना sshkey *किल्ली = रिक्त;
	पूर्णांक r = SSH_ERR_INTERNAL_ERROR;

	*keyp = रिक्त;

	/* Check response validity */
	जर (resp->public_किल्ली == रिक्त || resp->किल्ली_handle == रिक्त) {
		error_f("sk_enroll response invalid");
		r = SSH_ERR_INVALID_FORMAT;
		जा out;
	}
	निवड (alg) {
#ifdef WITH_OPENSSL
	स्थिती SSH_SK_ECDSA:
		जर ((r = sshsk_ecdsa_assemble(resp, &किल्ली)) != 0)
			जा out;
		थांबा;
#endif /* WITH_OPENSSL */
	स्थिती SSH_SK_ED25519:
		जर ((r = sshsk_ed25519_assemble(resp, &किल्ली)) != 0)
			जा out;
		थांबा;
	पूर्वनिर्धारित:
		error_f("unsupported algorithm %d", alg);
		r = SSH_ERR_INVALID_ARGUMENT;
		जा out;
	}
	किल्ली->sk_flags = flags;
	जर ((किल्ली->sk_किल्ली_handle = sshbuf_new()) == रिक्त ||
	    (किल्ली->sk_reserved = sshbuf_new()) == रिक्त) {
		error_f("allocation failed");
		r = SSH_ERR_ALLOC_FAIL;
		जा out;
	}
	जर ((किल्ली->sk_application = strdup(application)) == रिक्त) {
		error_f("strdup application failed");
		r = SSH_ERR_ALLOC_FAIL;
		जा out;
	}
	जर ((r = sshbuf_put(किल्ली->sk_किल्ली_handle, resp->किल्ली_handle,
	    resp->किल्ली_handle_len)) != 0) {
		error_fr(r, "put key handle");
		जा out;
	}
	/* success */
	r = 0;
	*keyp = किल्ली;
	किल्ली = रिक्त;
 out:
	sshkey_free(किल्ली);
	परत r;
}

स्थिर पूर्णांक
skerr_to_ssherr(पूर्णांक skerr)
{
	निवड (skerr) {
	स्थिती SSH_SK_ERR_UNSUPPORTED:
		परत SSH_ERR_FEATURE_UNSUPPORTED;
	स्थिती SSH_SK_ERR_PIN_REQUIRED:
		परत SSH_ERR_किल्ली_WRONG_PASSPHRASE;
	स्थिती SSH_SK_ERR_DEVICE_NOT_FOUND:
		परत SSH_ERR_DEVICE_NOT_FOUND;
	स्थिती SSH_SK_ERR_CREDENTIAL_EXISTS:
		परत SSH_ERR_किल्ली_BAD_PERMISSIONS;
	स्थिती SSH_SK_ERR_GENERAL:
	पूर्वनिर्धारित:
		परत SSH_ERR_INVALID_FORMAT;
	}
}

स्थिर शून्य
sshsk_free_options(संरचना sk_option **opts)
{
	माप_प्रकार i;

	जर (opts == रिक्त)
		परत;
	साठी (i = 0; opts[i] != रिक्त; i++) {
		मुक्त(opts[i]->name);
		मुक्त(opts[i]->मूल्य);
		मुक्त(opts[i]);
	}
	मुक्त(opts);
}

स्थिर पूर्णांक
sshsk_add_option(संरचना sk_option ***optsp, माप_प्रकार *noptsp,
    स्थिरांक अक्षर *name, स्थिरांक अक्षर *मूल्य, uint8_t required)
{
	संरचना sk_option **opts = *optsp;
	माप_प्रकार nopts = *noptsp;

	जर ((opts = recallocarray(opts, nopts, nopts + 2, /* extra for NULL */
	    आकार(*opts))) == रिक्त) {
		error_f("array alloc failed");
		परत SSH_ERR_ALLOC_FAIL;
	}
	*optsp = opts;
	*noptsp = nopts + 1;
	जर ((opts[nopts] = सुस्मृति(1, आकार(**opts))) == रिक्त) {
		error_f("alloc failed");
		परत SSH_ERR_ALLOC_FAIL;
	}
	जर ((opts[nopts]->name = strdup(name)) == रिक्त ||
	    (opts[nopts]->मूल्य = strdup(मूल्य)) == रिक्त) {
		error_f("alloc failed");
		परत SSH_ERR_ALLOC_FAIL;
	}
	opts[nopts]->required = required;
	परत 0;
}

स्थिर पूर्णांक
make_options(स्थिरांक अक्षर *device, स्थिरांक अक्षर *user_id,
    संरचना sk_option ***optsp)
{
	संरचना sk_option **opts = रिक्त;
	माप_प्रकार nopts = 0;
	पूर्णांक r, ret = SSH_ERR_INTERNAL_ERROR;

	जर (device != रिक्त &&
	    (r = sshsk_add_option(&opts, &nopts, "device", device, 0)) != 0) {
		ret = r;
		जा out;
	}
	जर (user_id != रिक्त &&
	    (r = sshsk_add_option(&opts, &nopts, "user", user_id, 0)) != 0) {
		ret = r;
		जा out;
	}
	/* success */
	*optsp = opts;
	opts = रिक्त;
	nopts = 0;
	ret = 0;
 out:
	sshsk_free_options(opts);
	परत ret;
}


स्थिर पूर्णांक
fill_attestation_blob(स्थिरांक संरचना sk_enroll_response *resp,
    संरचना sshbuf *attest)
{
	पूर्णांक r;

	जर (attest == रिक्त)
		परत 0; /* nothing to do */
	जर ((r = sshbuf_put_cstring(attest, "ssh-sk-attest-v01")) != 0 ||
	    (r = sshbuf_put_string(attest,
	    resp->attestation_cert, resp->attestation_cert_len)) != 0 ||
	    (r = sshbuf_put_string(attest,
	    resp->signature, resp->signature_len)) != 0 ||
	    (r = sshbuf_put_string(attest,
	    resp->authdata, resp->authdata_len)) != 0 ||
	    (r = sshbuf_put_u32(attest, 0)) != 0 || /* resvd flags */
	    (r = sshbuf_put_string(attest, रिक्त, 0)) != 0 /* resvd */) {
		error_fr(r, "compose");
		परत r;
	}
	/* success */
	परत 0;
}

पूर्णांक
sshsk_enroll(पूर्णांक type, स्थिरांक अक्षर *provider_path, स्थिरांक अक्षर *device,
    स्थिरांक अक्षर *application, स्थिरांक अक्षर *userid, uint8_t flags,
    स्थिरांक अक्षर *pin, संरचना sshbuf *challenge_buf,
    संरचना sshkey **keyp, संरचना sshbuf *attest)
{
	संरचना sshsk_provider *skp = रिक्त;
	संरचना sshkey *किल्ली = रिक्त;
	u_char randchall[32];
	स्थिरांक u_char *challenge;
	माप_प्रकार challenge_len;
	संरचना sk_enroll_response *resp = रिक्त;
	संरचना sk_option **opts = रिक्त;
	पूर्णांक r = SSH_ERR_INTERNAL_ERROR;
	पूर्णांक alg;

	debug_f("provider \"%s\", device \"%s\", application \"%s\", "
	    "userid \"%s\", flags 0x%02x, challenge len %zu%s",
	    provider_path, device, application, userid, flags,
	    challenge_buf == रिक्त ? 0 : sshbuf_len(challenge_buf),
	    (pin != रिक्त && *pin != '\0') ? " with-pin" : "");

	*keyp = रिक्त;
	जर (attest)
		sshbuf_reset(attest);

	जर ((r = make_options(device, userid, &opts)) != 0)
		जा out;

	निवड (type) {
#ifdef WITH_OPENSSL
	स्थिती किल्ली_ECDSA_SK:
		alg = SSH_SK_ECDSA;
		थांबा;
#endif /* WITH_OPENSSL */
	स्थिती किल्ली_ED25519_SK:
		alg = SSH_SK_ED25519;
		थांबा;
	पूर्वनिर्धारित:
		error_f("unsupported key type");
		r = SSH_ERR_INVALID_ARGUMENT;
		जा out;
	}
	जर (provider_path == रिक्त) {
		error_f("missing provider");
		r = SSH_ERR_INVALID_ARGUMENT;
		जा out;
	}
	जर (application == रिक्त || *application == '\0') {
		error_f("missing application");
		r = SSH_ERR_INVALID_ARGUMENT;
		जा out;
	}
	जर (challenge_buf == रिक्त) {
		debug_f("using random challenge");
		arc4random_buf(randchall, आकार(randchall));
		challenge = randchall;
		challenge_len = आकार(randchall);
	} अन्यथा जर (sshbuf_len(challenge_buf) == 0) {
		error("Missing enrollment challenge");
		r = SSH_ERR_INVALID_ARGUMENT;
		जा out;
	} अन्यथा {
		challenge = sshbuf_ptr(challenge_buf);
		challenge_len = sshbuf_len(challenge_buf);
		debug3_f("using explicit challenge len=%zd", challenge_len);
	}
	जर ((skp = sshsk_open(provider_path)) == रिक्त) {
		r = SSH_ERR_INVALID_FORMAT; /* XXX sshsk_open return code? */
		जा out;
	}
	/* XXX validate flags? */
	/* enroll key */
	जर ((r = skp->sk_enroll(alg, challenge, challenge_len, application,
	    flags, pin, opts, &resp)) != 0) {
		debug_f("provider \"%s\" failure %d", provider_path, r);
		r = skerr_to_ssherr(r);
		जा out;
	}

	जर ((r = sshsk_किल्ली_from_response(alg, application, resp->flags,
	    resp, &किल्ली)) != 0)
		जा out;

	/* Optionally fill in the attestation information */
	जर ((r = fill_attestation_blob(resp, attest)) != 0)
		जा out;

	/* success */
	*keyp = किल्ली;
	किल्ली = रिक्त; /* transferred */
	r = 0;
 out:
	sshsk_free_options(opts);
	sshsk_free(skp);
	sshkey_free(किल्ली);
	sshsk_free_enroll_response(resp);
	explicit_bzero(randchall, आकार(randchall));
	परत r;
}

#ifdef WITH_OPENSSL
स्थिर पूर्णांक
sshsk_ecdsa_sig(संरचना sk_sign_response *resp, संरचना sshbuf *sig)
{
	संरचना sshbuf *inner_sig = रिक्त;
	पूर्णांक r = SSH_ERR_INTERNAL_ERROR;

	/* Check response validity */
	जर (resp->sig_r == रिक्त || resp->sig_s == रिक्त) {
		error_f("sk_sign response invalid");
		r = SSH_ERR_INVALID_FORMAT;
		जा out;
	}
	जर ((inner_sig = sshbuf_new()) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		जा out;
	}
	/* Prepare and append inner signature object */
	जर ((r = sshbuf_put_bignum2_bytes(inner_sig,
	    resp->sig_r, resp->sig_r_len)) != 0 ||
	    (r = sshbuf_put_bignum2_bytes(inner_sig,
	    resp->sig_s, resp->sig_s_len)) != 0) {
		error_fr(r, "compose inner");
		जा out;
	}
	जर ((r = sshbuf_put_stringb(sig, inner_sig)) != 0 ||
	    (r = sshbuf_put_u8(sig, resp->flags)) != 0 ||
	    (r = sshbuf_put_u32(sig, resp->counter)) != 0) {
		error_fr(r, "compose");
		जा out;
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
	परत r;
}
#endif /* WITH_OPENSSL */

स्थिर पूर्णांक
sshsk_ed25519_sig(संरचना sk_sign_response *resp, संरचना sshbuf *sig)
{
	पूर्णांक r = SSH_ERR_INTERNAL_ERROR;

	/* Check response validity */
	जर (resp->sig_r == रिक्त) {
		error_f("sk_sign response invalid");
		r = SSH_ERR_INVALID_FORMAT;
		जा out;
	}
	जर ((r = sshbuf_put_string(sig,
	    resp->sig_r, resp->sig_r_len)) != 0 ||
	    (r = sshbuf_put_u8(sig, resp->flags)) != 0 ||
	    (r = sshbuf_put_u32(sig, resp->counter)) != 0) {
		error_fr(r, "compose");
		जा out;
	}
#ifdef DEBUG_SK
	ख_लिखो(मानक_त्रुटि, "%s: sig_r:\n", __func__);
	sshbuf_dump_data(resp->sig_r, resp->sig_r_len, मानक_त्रुटि);
#endif
	r = 0;
 out:
	परत r;
}

पूर्णांक
sshsk_sign(स्थिरांक अक्षर *provider_path, संरचना sshkey *किल्ली,
    u_char **sigp, माप_प्रकार *lenp, स्थिरांक u_char *data, माप_प्रकार datalen,
    u_int compat, स्थिरांक अक्षर *pin)
{
	संरचना sshsk_provider *skp = रिक्त;
	पूर्णांक r = SSH_ERR_INTERNAL_ERROR;
	पूर्णांक type, alg;
	संरचना sk_sign_response *resp = रिक्त;
	संरचना sshbuf *inner_sig = रिक्त, *sig = रिक्त;
	संरचना sk_option **opts = रिक्त;

	debug_f("provider \"%s\", key %s, flags 0x%02x%s",
	    provider_path, sshkey_type(किल्ली), किल्ली->sk_flags,
	    (pin != रिक्त && *pin != '\0') ? " with-pin" : "");

	जर (sigp != रिक्त)
		*sigp = रिक्त;
	जर (lenp != रिक्त)
		*lenp = 0;
	type = sshkey_type_plain(किल्ली->type);
	निवड (type) {
#ifdef WITH_OPENSSL
	स्थिती किल्ली_ECDSA_SK:
		alg = SSH_SK_ECDSA;
		थांबा;
#endif /* WITH_OPENSSL */
	स्थिती किल्ली_ED25519_SK:
		alg = SSH_SK_ED25519;
		थांबा;
	पूर्वनिर्धारित:
		परत SSH_ERR_INVALID_ARGUMENT;
	}
	जर (provider_path == रिक्त ||
	    किल्ली->sk_किल्ली_handle == रिक्त ||
	    किल्ली->sk_application == रिक्त || *किल्ली->sk_application == '\0') {
		r = SSH_ERR_INVALID_ARGUMENT;
		जा out;
	}
	जर ((skp = sshsk_open(provider_path)) == रिक्त) {
		r = SSH_ERR_INVALID_FORMAT; /* XXX sshsk_open return code? */
		जा out;
	}
#ifdef DEBUG_SK
	ख_लिखो(मानक_त्रुटि, "%s: sk_flags = 0x%02x, sk_application = \"%s\"\n",
	    __func__, किल्ली->sk_flags, किल्ली->sk_application);
	ख_लिखो(मानक_त्रुटि, "%s: sk_key_handle:\n", __func__);
	sshbuf_dump(किल्ली->sk_किल्ली_handle, मानक_त्रुटि);
#endif
	जर ((r = skp->sk_sign(alg, data, datalen, किल्ली->sk_application,
	    sshbuf_ptr(किल्ली->sk_किल्ली_handle), sshbuf_len(किल्ली->sk_किल्ली_handle),
	    किल्ली->sk_flags, pin, opts, &resp)) != 0) {
		debug_f("sk_sign failed with code %d", r);
		r = skerr_to_ssherr(r);
		जा out;
	}
	/* Assemble signature */
	जर ((sig = sshbuf_new()) == रिक्त) {
		r = SSH_ERR_ALLOC_FAIL;
		जा out;
	}
	जर ((r = sshbuf_put_cstring(sig, sshkey_ssh_name_plain(किल्ली))) != 0) {
		error_fr(r, "compose outer");
		जा out;
	}
	निवड (type) {
#ifdef WITH_OPENSSL
	स्थिती किल्ली_ECDSA_SK:
		जर ((r = sshsk_ecdsa_sig(resp, sig)) != 0)
			जा out;
		थांबा;
#endif /* WITH_OPENSSL */
	स्थिती किल्ली_ED25519_SK:
		जर ((r = sshsk_ed25519_sig(resp, sig)) != 0)
			जा out;
		थांबा;
	}
#ifdef DEBUG_SK
	ख_लिखो(मानक_त्रुटि, "%s: sig_flags = 0x%02x, sig_counter = %u\n",
	    __func__, resp->flags, resp->counter);
	ख_लिखो(मानक_त्रुटि, "%s: data to sign:\n", __func__);
	sshbuf_dump_data(data, datalen, मानक_त्रुटि);
	ख_लिखो(मानक_त्रुटि, "%s: sigbuf:\n", __func__);
	sshbuf_dump(sig, मानक_त्रुटि);
#endif
	जर (sigp != रिक्त) {
		जर ((*sigp = दो_स्मृति(sshbuf_len(sig))) == रिक्त) {
			r = SSH_ERR_ALLOC_FAIL;
			जा out;
		}
		स_नकल(*sigp, sshbuf_ptr(sig), sshbuf_len(sig));
	}
	जर (lenp != रिक्त)
		*lenp = sshbuf_len(sig);
	/* success */
	r = 0;
 out:
	sshsk_free_options(opts);
	sshsk_free(skp);
	sshsk_free_sign_response(resp);
	sshbuf_free(sig);
	sshbuf_free(inner_sig);
	परत r;
}

स्थिर शून्य
sshsk_free_sk_resident_किल्ल्या(संरचना sk_resident_किल्ली **rks, माप_प्रकार nrks)
{
	माप_प्रकार i;

	जर (nrks == 0 || rks == रिक्त)
		परत;
	साठी (i = 0; i < nrks; i++) {
		मुक्त(rks[i]->application);
		freezero(rks[i]->user_id, rks[i]->user_id_len);
		freezero(rks[i]->किल्ली.किल्ली_handle, rks[i]->किल्ली.किल्ली_handle_len);
		freezero(rks[i]->किल्ली.public_किल्ली, rks[i]->किल्ली.public_किल्ली_len);
		freezero(rks[i]->किल्ली.signature, rks[i]->किल्ली.signature_len);
		freezero(rks[i]->किल्ली.attestation_cert,
		    rks[i]->किल्ली.attestation_cert_len);
		freezero(rks[i], आकार(**rks));
	}
	मुक्त(rks);
}

स्थिर शून्य
sshsk_free_resident_किल्ली(संरचना sshsk_resident_किल्ली *srk)
{
	जर (srk == रिक्त)
		परत;
	sshkey_free(srk->किल्ली);
	freezero(srk->user_id, srk->user_id_len);
	मुक्त(srk);
}


शून्य
sshsk_free_resident_किल्ल्या(संरचना sshsk_resident_किल्ली **srks, माप_प्रकार nsrks)
{
	माप_प्रकार i;

	जर (srks == रिक्त || nsrks == 0)
		परत;

	साठी (i = 0; i < nsrks; i++)
		sshsk_free_resident_किल्ली(srks[i]);
	मुक्त(srks);
}

पूर्णांक
sshsk_load_resident(स्थिरांक अक्षर *provider_path, स्थिरांक अक्षर *device,
    स्थिरांक अक्षर *pin, u_int flags, संरचना sshsk_resident_किल्ली ***srksp,
    माप_प्रकार *nsrksp)
{
	संरचना sshsk_provider *skp = रिक्त;
	पूर्णांक r = SSH_ERR_INTERNAL_ERROR;
	संरचना sk_resident_किल्ली **rks = रिक्त;
	माप_प्रकार i, nrks = 0, nsrks = 0;
	संरचना sshkey *किल्ली = रिक्त;
	संरचना sshsk_resident_किल्ली *srk = रिक्त, **srks = रिक्त, **tmp;
	uint8_t sk_flags;
	संरचना sk_option **opts = रिक्त;

	debug_f("provider \"%s\"%s", provider_path,
	    (pin != रिक्त && *pin != '\0') ? ", have-pin": "");

	जर (srksp == रिक्त || nsrksp == रिक्त)
		परत SSH_ERR_INVALID_ARGUMENT;
	*srksp = रिक्त;
	*nsrksp = 0;

	जर ((r = make_options(device, रिक्त, &opts)) != 0)
		जा out;
	जर ((skp = sshsk_open(provider_path)) == रिक्त) {
		r = SSH_ERR_INVALID_FORMAT; /* XXX sshsk_open return code? */
		जा out;
	}
	जर ((r = skp->sk_load_resident_किल्ल्या(pin, opts, &rks, &nrks)) != 0) {
		error("Provider \"%s\" returned failure %d", provider_path, r);
		r = skerr_to_ssherr(r);
		जा out;
	}
	साठी (i = 0; i < nrks; i++) {
		debug3_f("rk %zu: slot %zu, alg %d, app \"%s\", uidlen %zu",
		    i, rks[i]->slot, rks[i]->alg, rks[i]->application,
		    rks[i]->user_id_len);
		/* XXX need better filter here */
		जर (म_भेदन(rks[i]->application, "ssh:", 4) != 0)
			सुरूठेवा;
		निवड (rks[i]->alg) {
		स्थिती SSH_SK_ECDSA:
		स्थिती SSH_SK_ED25519:
			थांबा;
		पूर्वनिर्धारित:
			सुरूठेवा;
		}
		sk_flags = SSH_SK_USER_PRESENCE_REQD|SSH_SK_RESIDENT_किल्ली;
		जर ((rks[i]->flags & SSH_SK_USER_VERIFICATION_REQD))
			sk_flags |= SSH_SK_USER_VERIFICATION_REQD;
		जर ((r = sshsk_किल्ली_from_response(rks[i]->alg,
		    rks[i]->application, sk_flags, &rks[i]->किल्ली, &किल्ली)) != 0)
			जा out;
		जर ((srk = सुस्मृति(1, आकार(*srk))) == रिक्त) {
			error_f("calloc failed");
			r = SSH_ERR_ALLOC_FAIL;
			जा out;
		}
		srk->किल्ली = किल्ली;
		किल्ली = रिक्त; /* transferred */
		जर ((srk->user_id = सुस्मृति(1, rks[i]->user_id_len)) == रिक्त) {
			error_f("calloc failed");
			r = SSH_ERR_ALLOC_FAIL;
			जा out;
		}
		स_नकल(srk->user_id, rks[i]->user_id, rks[i]->user_id_len);
		srk->user_id_len = rks[i]->user_id_len;
		जर ((tmp = recallocarray(srks, nsrks, nsrks + 1,
		    आकार(*tmp))) == रिक्त) {
			error_f("recallocarray failed");
			r = SSH_ERR_ALLOC_FAIL;
			जा out;
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
	sshsk_free_sk_resident_किल्ल्या(rks, nrks);
	sshkey_free(किल्ली);
	sshsk_free_resident_किल्ली(srk);
	sshsk_free_resident_किल्ल्या(srks, nsrks);
	परत r;
}

#endif /* ENABLE_SK */
