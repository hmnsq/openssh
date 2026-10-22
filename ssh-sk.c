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

#समावेश "includes.h"

#अगर_घोषित ENABLE_SK

#समावेश <dlfcn.h>
#समावेश <stddef.h>
#समावेश <stdint.h>
#समावेश <string.h>
#समावेश <stdio.h>

#अगर_घोषित WITH_OPENSSL
#समावेश <openssl/objects.h>
#समावेश <openssl/ec.h>
#समावेश <openssl/evp.h>
#पूर्ण_अगर /* WITH_OPENSSL */

#समावेश "log.h"
#समावेश "misc.h"
#समावेश "sshbuf.h"
#समावेश "sshkey.h"
#समावेश "ssherr.h"
#समावेश "digest.h"

#समावेश "ssh-sk.h"
#समावेश "sk-api.h"
#समावेश "crypto_api.h"

काष्ठा sshsk_provider {
	अक्षर *path;
	व्योम *dlhandle;

	/* Return the version of the middleware API */
	uint32_t (*sk_api_version)(व्योम);

	/* Enroll a U2F key (private key generation) */
	पूर्णांक (*sk_enroll)(पूर्णांक alg, स्थिर uint8_t *challenge,
	    माप_प्रकार challenge_len, स्थिर अक्षर *application, uint8_t flags,
	    स्थिर अक्षर *pin, काष्ठा sk_option **opts,
	    काष्ठा sk_enroll_response **enroll_response);

	/* Sign a challenge */
	पूर्णांक (*sk_sign)(पूर्णांक alg, स्थिर uint8_t *message, माप_प्रकार message_len,
	    स्थिर अक्षर *application,
	    स्थिर uint8_t *कुंजी_handle, माप_प्रकार कुंजी_handle_len,
	    uint8_t flags, स्थिर अक्षर *pin, काष्ठा sk_option **opts,
	    काष्ठा sk_sign_response **sign_response);

	/* Enumerate resident keys */
	पूर्णांक (*sk_load_resident_कुंजियाँ)(स्थिर अक्षर *pin, काष्ठा sk_option **opts,
	    काष्ठा sk_resident_कुंजी ***rks, माप_प्रकार *nrks);
};

/* Built-in version */
पूर्णांक ssh_sk_enroll(पूर्णांक alg, स्थिर uint8_t *challenge,
    माप_प्रकार challenge_len, स्थिर अक्षर *application, uint8_t flags,
    स्थिर अक्षर *pin, काष्ठा sk_option **opts,
    काष्ठा sk_enroll_response **enroll_response);
पूर्णांक ssh_sk_sign(पूर्णांक alg, स्थिर uint8_t *message, माप_प्रकार message_len,
    स्थिर अक्षर *application,
    स्थिर uint8_t *कुंजी_handle, माप_प्रकार कुंजी_handle_len,
    uint8_t flags, स्थिर अक्षर *pin, काष्ठा sk_option **opts,
    काष्ठा sk_sign_response **sign_response);
पूर्णांक ssh_sk_load_resident_कुंजियाँ(स्थिर अक्षर *pin, काष्ठा sk_option **opts,
    काष्ठा sk_resident_कुंजी ***rks, माप_प्रकार *nrks);

अटल व्योम
sshsk_free(काष्ठा sshsk_provider *p)
{
	अगर (p == शून्य)
		वापस;
	मुक्त(p->path);
	अगर (p->dlhandle != शून्य)
		dlclose(p->dlhandle);
	मुक्त(p);
}

अटल काष्ठा sshsk_provider *
sshsk_open(स्थिर अक्षर *path)
{
	काष्ठा sshsk_provider *ret = शून्य;
	uint32_t version;

	अगर (path == शून्य || *path == '\0') {
		error("No FIDO SecurityKeyProvider specified");
		वापस शून्य;
	}
	अगर ((ret = सुस्मृति(1, माप(*ret))) == शून्य) {
		error_f("calloc failed");
		वापस शून्य;
	}
	अगर ((ret->path = strdup(path)) == शून्य) {
		error_f("strdup failed");
		जाओ fail;
	}
	/* Skip the rest if we're using the linked in middleware */
	अगर (strcasecmp(ret->path, "internal") == 0) {
#अगर_घोषित ENABLE_SK_INTERNAL
		ret->sk_enroll = ssh_sk_enroll;
		ret->sk_sign = ssh_sk_sign;
		ret->sk_load_resident_कुंजियाँ = ssh_sk_load_resident_कुंजियाँ;
		वापस ret;
#अन्यथा
		error("internal security key support not enabled");
		जाओ fail;
#पूर्ण_अगर
	}
	अगर (lib_contains_प्रतीक(path, "sk_api_version") != 0) {
		error("provider %s is not an OpenSSH FIDO library", path);
		जाओ fail;
	}
	अगर ((ret->dlhandle = dlopen(path, RTLD_NOW)) == शून्य)
		fatal("Provider \"%s\" dlopen failed: %s", path, dlerror());
	अगर ((ret->sk_api_version = dlsym(ret->dlhandle,
	    "sk_api_version")) == शून्य) {
		error("Provider \"%s\" dlsym(sk_api_version) failed: %s",
		    path, dlerror());
		जाओ fail;
	}
	version = ret->sk_api_version();
	debug_f("provider %s implements version 0x%08lx", ret->path,
	    (u_long)version);
	अगर ((version & SSH_SK_VERSION_MAJOR_MASK) != SSH_SK_VERSION_MAJOR) {
		error("Provider \"%s\" implements unsupported "
		    "version 0x%08lx (supported: 0x%08lx)",
		    path, (u_long)version, (u_long)SSH_SK_VERSION_MAJOR);
		जाओ fail;
	}
	अगर ((ret->sk_enroll = dlsym(ret->dlhandle, "sk_enroll")) == शून्य) {
		error("Provider %s dlsym(sk_enroll) failed: %s",
		    path, dlerror());
		जाओ fail;
	}
	अगर ((ret->sk_sign = dlsym(ret->dlhandle, "sk_sign")) == शून्य) {
		error("Provider \"%s\" dlsym(sk_sign) failed: %s",
		    path, dlerror());
		जाओ fail;
	}
	अगर ((ret->sk_load_resident_कुंजियाँ = dlsym(ret->dlhandle,
	    "sk_load_resident_keys")) == शून्य) {
		error("Provider \"%s\" dlsym(sk_load_resident_keys) "
		    "failed: %s", path, dlerror());
		जाओ fail;
	}
	/* success */
	वापस ret;
fail:
	sshsk_free(ret);
	वापस शून्य;
}

अटल व्योम
sshsk_free_enroll_response(काष्ठा sk_enroll_response *r)
{
	अगर (r == शून्य)
		वापस;
	freezero(r->कुंजी_handle, r->कुंजी_handle_len);
	freezero(r->public_कुंजी, r->public_कुंजी_len);
	freezero(r->signature, r->signature_len);
	freezero(r->attestation_cert, r->attestation_cert_len);
	freezero(r->authdata, r->authdata_len);
	freezero(r, माप(*r));
}

अटल व्योम
sshsk_free_sign_response(काष्ठा sk_sign_response *r)
{
	अगर (r == शून्य)
		वापस;
	freezero(r->sig_r, r->sig_r_len);
	freezero(r->sig_s, r->sig_s_len);
	freezero(r, माप(*r));
}

#अगर_घोषित WITH_OPENSSL
/* Assemble key from response */
अटल पूर्णांक
sshsk_ecdsa_assemble(काष्ठा sk_enroll_response *resp, काष्ठा sshkey **keyp)
{
	काष्ठा sshkey *कुंजी = शून्य;
	काष्ठा sshbuf *b = शून्य;
	EC_कुंजी *ecdsa = शून्य;
	EC_POINT *q = शून्य;
	स्थिर EC_GROUP *g = शून्य;
	पूर्णांक r;

	*keyp = शून्य;
	अगर ((कुंजी = sshkey_new(कुंजी_ECDSA_SK)) == शून्य) {
		error_f("sshkey_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		जाओ out;
	}
	कुंजी->ecdsa_nid = NID_X9_62_prime256v1;
	अगर ((ecdsa = EC_कुंजी_new_by_curve_name(कुंजी->ecdsa_nid)) == शून्य ||
	    (g = EC_कुंजी_get0_group(ecdsa)) == शून्य ||
	    (q = EC_POINT_new(g)) == शून्य ||
	    (b = sshbuf_new()) == शून्य) {
		error_f("allocation failed");
		r = SSH_ERR_ALLOC_FAIL;
		जाओ out;
	}
	अगर ((r = sshbuf_put_string(b,
	    resp->public_कुंजी, resp->public_कुंजी_len)) != 0) {
		error_fr(r, "sshbuf_put_string");
		जाओ out;
	}
	अगर ((r = sshbuf_get_ec(b, q, g)) != 0) {
		error_fr(r, "parse");
		r = SSH_ERR_INVALID_FORMAT;
		जाओ out;
	}
	अगर (sshkey_ec_validate_public(g, q) != 0) {
		error("Authenticator returned invalid ECDSA key");
		r = SSH_ERR_कुंजी_INVALID_EC_मूल्य;
		जाओ out;
	}
	अगर (EC_कुंजी_set_public_कुंजी(ecdsa, q) != 1) {
		/* XXX assume it is a allocation error */
		error_f("allocation failed");
		r = SSH_ERR_ALLOC_FAIL;
		जाओ out;
	}
	अगर ((कुंजी->pkey = EVP_PKEY_new()) == शून्य) {
		error_f("allocation failed");
		r = SSH_ERR_ALLOC_FAIL;
		जाओ out;
	}
	अगर (EVP_PKEY_set1_EC_कुंजी(कुंजी->pkey, ecdsa) != 1) {
		error_f("Assigning EC_KEY failed");
		r = SSH_ERR_LIBCRYPTO_ERROR;
		जाओ out;
	}
	/* success */
	*keyp = कुंजी;
	कुंजी = शून्य; /* transferred */
	r = 0;
 out:
	sshkey_free(कुंजी);
	sshbuf_free(b);
	EC_कुंजी_free(ecdsa);
	EC_POINT_free(q);
	वापस r;
}
#पूर्ण_अगर /* WITH_OPENSSL */

अटल पूर्णांक
sshsk_ed25519_assemble(काष्ठा sk_enroll_response *resp, काष्ठा sshkey **keyp)
{
	काष्ठा sshkey *कुंजी = शून्य;
	पूर्णांक r;

	*keyp = शून्य;
	अगर (resp->public_कुंजी_len != ED25519_PK_SZ) {
		error_f("invalid size: %zu", resp->public_कुंजी_len);
		r = SSH_ERR_INVALID_FORMAT;
		जाओ out;
	}
	अगर ((कुंजी = sshkey_new(कुंजी_ED25519_SK)) == शून्य) {
		error_f("sshkey_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		जाओ out;
	}
	अगर ((कुंजी->ed25519_pk = दो_स्मृति(ED25519_PK_SZ)) == शून्य) {
		error_f("malloc failed");
		r = SSH_ERR_ALLOC_FAIL;
		जाओ out;
	}
	स_नकल(कुंजी->ed25519_pk, resp->public_कुंजी, ED25519_PK_SZ);
	/* success */
	*keyp = कुंजी;
	कुंजी = शून्य; /* transferred */
	r = 0;
 out:
	sshkey_free(कुंजी);
	वापस r;
}

अटल पूर्णांक
sshsk_कुंजी_from_response(पूर्णांक alg, स्थिर अक्षर *application, uint8_t flags,
    काष्ठा sk_enroll_response *resp, काष्ठा sshkey **keyp)
{
	काष्ठा sshkey *कुंजी = शून्य;
	पूर्णांक r = SSH_ERR_INTERNAL_ERROR;

	*keyp = शून्य;

	/* Check response validity */
	अगर (resp->public_कुंजी == शून्य || resp->कुंजी_handle == शून्य) {
		error_f("sk_enroll response invalid");
		r = SSH_ERR_INVALID_FORMAT;
		जाओ out;
	}
	चयन (alg) {
#अगर_घोषित WITH_OPENSSL
	हाल SSH_SK_ECDSA:
		अगर ((r = sshsk_ecdsa_assemble(resp, &कुंजी)) != 0)
			जाओ out;
		अवरोध;
#पूर्ण_अगर /* WITH_OPENSSL */
	हाल SSH_SK_ED25519:
		अगर ((r = sshsk_ed25519_assemble(resp, &कुंजी)) != 0)
			जाओ out;
		अवरोध;
	शेष:
		error_f("unsupported algorithm %d", alg);
		r = SSH_ERR_INVALID_ARGUMENT;
		जाओ out;
	}
	कुंजी->sk_flags = flags;
	अगर ((कुंजी->sk_कुंजी_handle = sshbuf_new()) == शून्य ||
	    (कुंजी->sk_reserved = sshbuf_new()) == शून्य) {
		error_f("allocation failed");
		r = SSH_ERR_ALLOC_FAIL;
		जाओ out;
	}
	अगर ((कुंजी->sk_application = strdup(application)) == शून्य) {
		error_f("strdup application failed");
		r = SSH_ERR_ALLOC_FAIL;
		जाओ out;
	}
	अगर ((r = sshbuf_put(कुंजी->sk_कुंजी_handle, resp->कुंजी_handle,
	    resp->कुंजी_handle_len)) != 0) {
		error_fr(r, "put key handle");
		जाओ out;
	}
	/* success */
	r = 0;
	*keyp = कुंजी;
	कुंजी = शून्य;
 out:
	sshkey_free(कुंजी);
	वापस r;
}

अटल पूर्णांक
skerr_to_ssherr(पूर्णांक skerr)
{
	चयन (skerr) {
	हाल SSH_SK_ERR_UNSUPPORTED:
		वापस SSH_ERR_FEATURE_UNSUPPORTED;
	हाल SSH_SK_ERR_PIN_REQUIRED:
		वापस SSH_ERR_कुंजी_WRONG_PASSPHRASE;
	हाल SSH_SK_ERR_DEVICE_NOT_FOUND:
		वापस SSH_ERR_DEVICE_NOT_FOUND;
	हाल SSH_SK_ERR_CREDENTIAL_EXISTS:
		वापस SSH_ERR_कुंजी_BAD_PERMISSIONS;
	हाल SSH_SK_ERR_GENERAL:
	शेष:
		वापस SSH_ERR_INVALID_FORMAT;
	}
}

अटल व्योम
sshsk_free_options(काष्ठा sk_option **opts)
{
	माप_प्रकार i;

	अगर (opts == शून्य)
		वापस;
	क्रम (i = 0; opts[i] != शून्य; i++) {
		मुक्त(opts[i]->name);
		मुक्त(opts[i]->मूल्य);
		मुक्त(opts[i]);
	}
	मुक्त(opts);
}

अटल पूर्णांक
sshsk_add_option(काष्ठा sk_option ***optsp, माप_प्रकार *noptsp,
    स्थिर अक्षर *name, स्थिर अक्षर *मूल्य, uint8_t required)
{
	काष्ठा sk_option **opts = *optsp;
	माप_प्रकार nopts = *noptsp;

	अगर ((opts = recallocarray(opts, nopts, nopts + 2, /* extra for NULL */
	    माप(*opts))) == शून्य) {
		error_f("array alloc failed");
		वापस SSH_ERR_ALLOC_FAIL;
	}
	*optsp = opts;
	*noptsp = nopts + 1;
	अगर ((opts[nopts] = सुस्मृति(1, माप(**opts))) == शून्य) {
		error_f("alloc failed");
		वापस SSH_ERR_ALLOC_FAIL;
	}
	अगर ((opts[nopts]->name = strdup(name)) == शून्य ||
	    (opts[nopts]->मूल्य = strdup(मूल्य)) == शून्य) {
		error_f("alloc failed");
		वापस SSH_ERR_ALLOC_FAIL;
	}
	opts[nopts]->required = required;
	वापस 0;
}

अटल पूर्णांक
make_options(स्थिर अक्षर *device, स्थिर अक्षर *user_id,
    काष्ठा sk_option ***optsp)
{
	काष्ठा sk_option **opts = शून्य;
	माप_प्रकार nopts = 0;
	पूर्णांक r, ret = SSH_ERR_INTERNAL_ERROR;

	अगर (device != शून्य &&
	    (r = sshsk_add_option(&opts, &nopts, "device", device, 0)) != 0) {
		ret = r;
		जाओ out;
	}
	अगर (user_id != शून्य &&
	    (r = sshsk_add_option(&opts, &nopts, "user", user_id, 0)) != 0) {
		ret = r;
		जाओ out;
	}
	/* success */
	*optsp = opts;
	opts = शून्य;
	nopts = 0;
	ret = 0;
 out:
	sshsk_free_options(opts);
	वापस ret;
}


अटल पूर्णांक
fill_attestation_blob(स्थिर काष्ठा sk_enroll_response *resp,
    काष्ठा sshbuf *attest)
{
	पूर्णांक r;

	अगर (attest == शून्य)
		वापस 0; /* nothing to do */
	अगर ((r = sshbuf_put_cstring(attest, "ssh-sk-attest-v01")) != 0 ||
	    (r = sshbuf_put_string(attest,
	    resp->attestation_cert, resp->attestation_cert_len)) != 0 ||
	    (r = sshbuf_put_string(attest,
	    resp->signature, resp->signature_len)) != 0 ||
	    (r = sshbuf_put_string(attest,
	    resp->authdata, resp->authdata_len)) != 0 ||
	    (r = sshbuf_put_u32(attest, 0)) != 0 || /* resvd flags */
	    (r = sshbuf_put_string(attest, शून्य, 0)) != 0 /* resvd */) {
		error_fr(r, "compose");
		वापस r;
	}
	/* success */
	वापस 0;
}

पूर्णांक
sshsk_enroll(पूर्णांक type, स्थिर अक्षर *provider_path, स्थिर अक्षर *device,
    स्थिर अक्षर *application, स्थिर अक्षर *userid, uint8_t flags,
    स्थिर अक्षर *pin, काष्ठा sshbuf *challenge_buf,
    काष्ठा sshkey **keyp, काष्ठा sshbuf *attest)
{
	काष्ठा sshsk_provider *skp = शून्य;
	काष्ठा sshkey *कुंजी = शून्य;
	u_char randchall[32];
	स्थिर u_char *challenge;
	माप_प्रकार challenge_len;
	काष्ठा sk_enroll_response *resp = शून्य;
	काष्ठा sk_option **opts = शून्य;
	पूर्णांक r = SSH_ERR_INTERNAL_ERROR;
	पूर्णांक alg;

	debug_f("provider \"%s\", device \"%s\", application \"%s\", "
	    "userid \"%s\", flags 0x%02x, challenge len %zu%s",
	    provider_path, device, application, userid, flags,
	    challenge_buf == शून्य ? 0 : sshbuf_len(challenge_buf),
	    (pin != शून्य && *pin != '\0') ? " with-pin" : "");

	*keyp = शून्य;
	अगर (attest)
		sshbuf_reset(attest);

	अगर ((r = make_options(device, userid, &opts)) != 0)
		जाओ out;

	चयन (type) {
#अगर_घोषित WITH_OPENSSL
	हाल कुंजी_ECDSA_SK:
		alg = SSH_SK_ECDSA;
		अवरोध;
#पूर्ण_अगर /* WITH_OPENSSL */
	हाल कुंजी_ED25519_SK:
		alg = SSH_SK_ED25519;
		अवरोध;
	शेष:
		error_f("unsupported key type");
		r = SSH_ERR_INVALID_ARGUMENT;
		जाओ out;
	}
	अगर (provider_path == शून्य) {
		error_f("missing provider");
		r = SSH_ERR_INVALID_ARGUMENT;
		जाओ out;
	}
	अगर (application == शून्य || *application == '\0') {
		error_f("missing application");
		r = SSH_ERR_INVALID_ARGUMENT;
		जाओ out;
	}
	अगर (challenge_buf == शून्य) {
		debug_f("using random challenge");
		arc4random_buf(randchall, माप(randchall));
		challenge = randchall;
		challenge_len = माप(randchall);
	} अन्यथा अगर (sshbuf_len(challenge_buf) == 0) {
		error("Missing enrollment challenge");
		r = SSH_ERR_INVALID_ARGUMENT;
		जाओ out;
	} अन्यथा {
		challenge = sshbuf_ptr(challenge_buf);
		challenge_len = sshbuf_len(challenge_buf);
		debug3_f("using explicit challenge len=%zd", challenge_len);
	}
	अगर ((skp = sshsk_open(provider_path)) == शून्य) {
		r = SSH_ERR_INVALID_FORMAT; /* XXX sshsk_open return code? */
		जाओ out;
	}
	/* XXX validate flags? */
	/* enroll key */
	अगर ((r = skp->sk_enroll(alg, challenge, challenge_len, application,
	    flags, pin, opts, &resp)) != 0) {
		debug_f("provider \"%s\" failure %d", provider_path, r);
		r = skerr_to_ssherr(r);
		जाओ out;
	}

	अगर ((r = sshsk_कुंजी_from_response(alg, application, resp->flags,
	    resp, &कुंजी)) != 0)
		जाओ out;

	/* Optionally fill in the attestation information */
	अगर ((r = fill_attestation_blob(resp, attest)) != 0)
		जाओ out;

	/* success */
	*keyp = कुंजी;
	कुंजी = शून्य; /* transferred */
	r = 0;
 out:
	sshsk_free_options(opts);
	sshsk_free(skp);
	sshkey_free(कुंजी);
	sshsk_free_enroll_response(resp);
	explicit_bzero(randchall, माप(randchall));
	वापस r;
}

#अगर_घोषित WITH_OPENSSL
अटल पूर्णांक
sshsk_ecdsa_sig(काष्ठा sk_sign_response *resp, काष्ठा sshbuf *sig)
{
	काष्ठा sshbuf *inner_sig = शून्य;
	पूर्णांक r = SSH_ERR_INTERNAL_ERROR;

	/* Check response validity */
	अगर (resp->sig_r == शून्य || resp->sig_s == शून्य) {
		error_f("sk_sign response invalid");
		r = SSH_ERR_INVALID_FORMAT;
		जाओ out;
	}
	अगर ((inner_sig = sshbuf_new()) == शून्य) {
		r = SSH_ERR_ALLOC_FAIL;
		जाओ out;
	}
	/* Prepare and append inner signature object */
	अगर ((r = sshbuf_put_bignum2_bytes(inner_sig,
	    resp->sig_r, resp->sig_r_len)) != 0 ||
	    (r = sshbuf_put_bignum2_bytes(inner_sig,
	    resp->sig_s, resp->sig_s_len)) != 0) {
		error_fr(r, "compose inner");
		जाओ out;
	}
	अगर ((r = sshbuf_put_stringb(sig, inner_sig)) != 0 ||
	    (r = sshbuf_put_u8(sig, resp->flags)) != 0 ||
	    (r = sshbuf_put_u32(sig, resp->गणक)) != 0) {
		error_fr(r, "compose");
		जाओ out;
	}
#अगर_घोषित DEBUG_SK
	ख_लिखो(मानक_त्रुटि, "%s: sig_r:\n", __func__);
	sshbuf_dump_तथ्य(resp->sig_r, resp->sig_r_len, मानक_त्रुटि);
	ख_लिखो(मानक_त्रुटि, "%s: sig_s:\n", __func__);
	sshbuf_dump_तथ्य(resp->sig_s, resp->sig_s_len, मानक_त्रुटि);
	ख_लिखो(मानक_त्रुटि, "%s: inner:\n", __func__);
	sshbuf_dump(inner_sig, मानक_त्रुटि);
#पूर्ण_अगर
	r = 0;
 out:
	sshbuf_free(inner_sig);
	वापस r;
}
#पूर्ण_अगर /* WITH_OPENSSL */

अटल पूर्णांक
sshsk_ed25519_sig(काष्ठा sk_sign_response *resp, काष्ठा sshbuf *sig)
{
	पूर्णांक r = SSH_ERR_INTERNAL_ERROR;

	/* Check response validity */
	अगर (resp->sig_r == शून्य) {
		error_f("sk_sign response invalid");
		r = SSH_ERR_INVALID_FORMAT;
		जाओ out;
	}
	अगर ((r = sshbuf_put_string(sig,
	    resp->sig_r, resp->sig_r_len)) != 0 ||
	    (r = sshbuf_put_u8(sig, resp->flags)) != 0 ||
	    (r = sshbuf_put_u32(sig, resp->गणक)) != 0) {
		error_fr(r, "compose");
		जाओ out;
	}
#अगर_घोषित DEBUG_SK
	ख_लिखो(मानक_त्रुटि, "%s: sig_r:\n", __func__);
	sshbuf_dump_तथ्य(resp->sig_r, resp->sig_r_len, मानक_त्रुटि);
#पूर्ण_अगर
	r = 0;
 out:
	वापस r;
}

पूर्णांक
sshsk_sign(स्थिर अक्षर *provider_path, काष्ठा sshkey *कुंजी,
    u_char **sigp, माप_प्रकार *lenp, स्थिर u_char *तथ्य, माप_प्रकार datalen,
    u_int compat, स्थिर अक्षर *pin)
{
	काष्ठा sshsk_provider *skp = शून्य;
	पूर्णांक r = SSH_ERR_INTERNAL_ERROR;
	पूर्णांक type, alg;
	काष्ठा sk_sign_response *resp = शून्य;
	काष्ठा sshbuf *inner_sig = शून्य, *sig = शून्य;
	काष्ठा sk_option **opts = शून्य;

	debug_f("provider \"%s\", key %s, flags 0x%02x%s",
	    provider_path, sshkey_type(कुंजी), कुंजी->sk_flags,
	    (pin != शून्य && *pin != '\0') ? " with-pin" : "");

	अगर (sigp != शून्य)
		*sigp = शून्य;
	अगर (lenp != शून्य)
		*lenp = 0;
	type = sshkey_type_plain(कुंजी->type);
	चयन (type) {
#अगर_घोषित WITH_OPENSSL
	हाल कुंजी_ECDSA_SK:
		alg = SSH_SK_ECDSA;
		अवरोध;
#पूर्ण_अगर /* WITH_OPENSSL */
	हाल कुंजी_ED25519_SK:
		alg = SSH_SK_ED25519;
		अवरोध;
	शेष:
		वापस SSH_ERR_INVALID_ARGUMENT;
	}
	अगर (provider_path == शून्य ||
	    कुंजी->sk_कुंजी_handle == शून्य ||
	    कुंजी->sk_application == शून्य || *कुंजी->sk_application == '\0') {
		r = SSH_ERR_INVALID_ARGUMENT;
		जाओ out;
	}
	अगर ((skp = sshsk_open(provider_path)) == शून्य) {
		r = SSH_ERR_INVALID_FORMAT; /* XXX sshsk_open return code? */
		जाओ out;
	}
#अगर_घोषित DEBUG_SK
	ख_लिखो(मानक_त्रुटि, "%s: sk_flags = 0x%02x, sk_application = \"%s\"\n",
	    __func__, कुंजी->sk_flags, कुंजी->sk_application);
	ख_लिखो(मानक_त्रुटि, "%s: sk_key_handle:\n", __func__);
	sshbuf_dump(कुंजी->sk_कुंजी_handle, मानक_त्रुटि);
#पूर्ण_अगर
	अगर ((r = skp->sk_sign(alg, तथ्य, datalen, कुंजी->sk_application,
	    sshbuf_ptr(कुंजी->sk_कुंजी_handle), sshbuf_len(कुंजी->sk_कुंजी_handle),
	    कुंजी->sk_flags, pin, opts, &resp)) != 0) {
		debug_f("sk_sign failed with code %d", r);
		r = skerr_to_ssherr(r);
		जाओ out;
	}
	/* Assemble signature */
	अगर ((sig = sshbuf_new()) == शून्य) {
		r = SSH_ERR_ALLOC_FAIL;
		जाओ out;
	}
	अगर ((r = sshbuf_put_cstring(sig, sshkey_ssh_name_plain(कुंजी))) != 0) {
		error_fr(r, "compose outer");
		जाओ out;
	}
	चयन (type) {
#अगर_घोषित WITH_OPENSSL
	हाल कुंजी_ECDSA_SK:
		अगर ((r = sshsk_ecdsa_sig(resp, sig)) != 0)
			जाओ out;
		अवरोध;
#पूर्ण_अगर /* WITH_OPENSSL */
	हाल कुंजी_ED25519_SK:
		अगर ((r = sshsk_ed25519_sig(resp, sig)) != 0)
			जाओ out;
		अवरोध;
	}
#अगर_घोषित DEBUG_SK
	ख_लिखो(मानक_त्रुटि, "%s: sig_flags = 0x%02x, sig_counter = %u\n",
	    __func__, resp->flags, resp->गणक);
	ख_लिखो(मानक_त्रुटि, "%s: data to sign:\n", __func__);
	sshbuf_dump_तथ्य(तथ्य, datalen, मानक_त्रुटि);
	ख_लिखो(मानक_त्रुटि, "%s: sigbuf:\n", __func__);
	sshbuf_dump(sig, मानक_त्रुटि);
#पूर्ण_अगर
	अगर (sigp != शून्य) {
		अगर ((*sigp = दो_स्मृति(sshbuf_len(sig))) == शून्य) {
			r = SSH_ERR_ALLOC_FAIL;
			जाओ out;
		}
		स_नकल(*sigp, sshbuf_ptr(sig), sshbuf_len(sig));
	}
	अगर (lenp != शून्य)
		*lenp = sshbuf_len(sig);
	/* success */
	r = 0;
 out:
	sshsk_free_options(opts);
	sshsk_free(skp);
	sshsk_free_sign_response(resp);
	sshbuf_free(sig);
	sshbuf_free(inner_sig);
	वापस r;
}

अटल व्योम
sshsk_free_sk_resident_कुंजियाँ(काष्ठा sk_resident_कुंजी **rks, माप_प्रकार nrks)
{
	माप_प्रकार i;

	अगर (nrks == 0 || rks == शून्य)
		वापस;
	क्रम (i = 0; i < nrks; i++) {
		मुक्त(rks[i]->application);
		freezero(rks[i]->user_id, rks[i]->user_id_len);
		freezero(rks[i]->कुंजी.कुंजी_handle, rks[i]->कुंजी.कुंजी_handle_len);
		freezero(rks[i]->कुंजी.public_कुंजी, rks[i]->कुंजी.public_कुंजी_len);
		freezero(rks[i]->कुंजी.signature, rks[i]->कुंजी.signature_len);
		freezero(rks[i]->कुंजी.attestation_cert,
		    rks[i]->कुंजी.attestation_cert_len);
		freezero(rks[i], माप(**rks));
	}
	मुक्त(rks);
}

अटल व्योम
sshsk_free_resident_कुंजी(काष्ठा sshsk_resident_कुंजी *srk)
{
	अगर (srk == शून्य)
		वापस;
	sshkey_free(srk->कुंजी);
	freezero(srk->user_id, srk->user_id_len);
	मुक्त(srk);
}


व्योम
sshsk_free_resident_कुंजियाँ(काष्ठा sshsk_resident_कुंजी **srks, माप_प्रकार nsrks)
{
	माप_प्रकार i;

	अगर (srks == शून्य || nsrks == 0)
		वापस;

	क्रम (i = 0; i < nsrks; i++)
		sshsk_free_resident_कुंजी(srks[i]);
	मुक्त(srks);
}

पूर्णांक
sshsk_load_resident(स्थिर अक्षर *provider_path, स्थिर अक्षर *device,
    स्थिर अक्षर *pin, u_int flags, काष्ठा sshsk_resident_कुंजी ***srksp,
    माप_प्रकार *nsrksp)
{
	काष्ठा sshsk_provider *skp = शून्य;
	पूर्णांक r = SSH_ERR_INTERNAL_ERROR;
	काष्ठा sk_resident_कुंजी **rks = शून्य;
	माप_प्रकार i, nrks = 0, nsrks = 0;
	काष्ठा sshkey *कुंजी = शून्य;
	काष्ठा sshsk_resident_कुंजी *srk = शून्य, **srks = शून्य, **tmp;
	uint8_t sk_flags;
	काष्ठा sk_option **opts = शून्य;

	debug_f("provider \"%s\"%s", provider_path,
	    (pin != शून्य && *pin != '\0') ? ", have-pin": "");

	अगर (srksp == शून्य || nsrksp == शून्य)
		वापस SSH_ERR_INVALID_ARGUMENT;
	*srksp = शून्य;
	*nsrksp = 0;

	अगर ((r = make_options(device, शून्य, &opts)) != 0)
		जाओ out;
	अगर ((skp = sshsk_open(provider_path)) == शून्य) {
		r = SSH_ERR_INVALID_FORMAT; /* XXX sshsk_open return code? */
		जाओ out;
	}
	अगर ((r = skp->sk_load_resident_कुंजियाँ(pin, opts, &rks, &nrks)) != 0) {
		error("Provider \"%s\" returned failure %d", provider_path, r);
		r = skerr_to_ssherr(r);
		जाओ out;
	}
	क्रम (i = 0; i < nrks; i++) {
		debug3_f("rk %zu: slot %zu, alg %d, app \"%s\", uidlen %zu",
		    i, rks[i]->slot, rks[i]->alg, rks[i]->application,
		    rks[i]->user_id_len);
		/* XXX need better filter here */
		अगर (म_भेदन(rks[i]->application, "ssh:", 4) != 0)
			जारी;
		चयन (rks[i]->alg) {
		हाल SSH_SK_ECDSA:
		हाल SSH_SK_ED25519:
			अवरोध;
		शेष:
			जारी;
		}
		sk_flags = SSH_SK_USER_PRESENCE_REQD|SSH_SK_RESIDENT_कुंजी;
		अगर ((rks[i]->flags & SSH_SK_USER_VERIFICATION_REQD))
			sk_flags |= SSH_SK_USER_VERIFICATION_REQD;
		अगर ((r = sshsk_कुंजी_from_response(rks[i]->alg,
		    rks[i]->application, sk_flags, &rks[i]->कुंजी, &कुंजी)) != 0)
			जाओ out;
		अगर ((srk = सुस्मृति(1, माप(*srk))) == शून्य) {
			error_f("calloc failed");
			r = SSH_ERR_ALLOC_FAIL;
			जाओ out;
		}
		srk->कुंजी = कुंजी;
		कुंजी = शून्य; /* transferred */
		अगर ((srk->user_id = सुस्मृति(1, rks[i]->user_id_len)) == शून्य) {
			error_f("calloc failed");
			r = SSH_ERR_ALLOC_FAIL;
			जाओ out;
		}
		स_नकल(srk->user_id, rks[i]->user_id, rks[i]->user_id_len);
		srk->user_id_len = rks[i]->user_id_len;
		अगर ((tmp = recallocarray(srks, nsrks, nsrks + 1,
		    माप(*tmp))) == शून्य) {
			error_f("recallocarray failed");
			r = SSH_ERR_ALLOC_FAIL;
			जाओ out;
		}
		srks = tmp;
		srks[nsrks++] = srk;
		srk = शून्य;
		/* XXX synthesise comment */
	}
	/* success */
	*srksp = srks;
	*nsrksp = nsrks;
	srks = शून्य;
	nsrks = 0;
	r = 0;
 out:
	sshsk_free_options(opts);
	sshsk_free(skp);
	sshsk_free_sk_resident_कुंजियाँ(rks, nrks);
	sshkey_free(कुंजी);
	sshsk_free_resident_कुंजी(srk);
	sshsk_free_resident_कुंजियाँ(srks, nsrks);
	वापस r;
}

#पूर्ण_अगर /* ENABLE_SK */
