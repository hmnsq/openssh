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

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ifdef ENABLE_SK

#ଅନ୍ତର୍ଭାଵ <dlfcn.h>
#ଅନ୍ତର୍ଭାଵ <stddef.h>
#ଅନ୍ତର୍ଭାଵ <stdint.h>
#ଅନ୍ତର୍ଭାଵ <string.h>
#ଅନ୍ତର୍ଭାଵ <stdio.h>

#ifdef WITH_OPENSSL
#ଅନ୍ତର୍ଭାଵ <openssl/objects.h>
#ଅନ୍ତର୍ଭାଵ <openssl/ec.h>
#ଅନ୍ତର୍ଭାଵ <openssl/evp.h>
#endif /* WITH_OPENSSL */

#ଅନ୍ତର୍ଭାଵ "log.h"
#ଅନ୍ତର୍ଭାଵ "misc.h"
#ଅନ୍ତର୍ଭାଵ "sshbuf.h"
#ଅନ୍ତର୍ଭାଵ "sshkey.h"
#ଅନ୍ତର୍ଭାଵ "ssherr.h"
#ଅନ୍ତର୍ଭାଵ "digest.h"

#ଅନ୍ତର୍ଭାଵ "ssh-sk.h"
#ଅନ୍ତର୍ଭାଵ "sk-api.h"
#ଅନ୍ତର୍ଭାଵ "crypto_api.h"

ସଂରଚନା sshsk_provider {
	ଅକ୍ଷର *path;
	ଶୂନ୍ୟ *dlhandle;

	/* Return the version of the middleware API */
	uint32_t (*sk_api_version)(ଶୂନ୍ୟ);

	/* Enroll a U2F key (private key generation) */
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା (*sk_enroll)(ପୂର୍ଣ୍ଣସଂଖ୍ୟା alg, ଅଚଳ uint8_t *challenge,
	    size_t challenge_len, ଅଚଳ ଅକ୍ଷର *application, uint8_t flags,
	    ଅଚଳ ଅକ୍ଷର *pin, ସଂରଚନା sk_option **opts,
	    ସଂରଚନା sk_enroll_response **enroll_response);

	/* Sign a challenge */
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା (*sk_sign)(ପୂର୍ଣ୍ଣସଂଖ୍ୟା alg, ଅଚଳ uint8_t *message, size_t message_len,
	    ଅଚଳ ଅକ୍ଷର *application,
	    ଅଚଳ uint8_t *ଚାବି_handle, size_t ଚାବି_handle_len,
	    uint8_t flags, ଅଚଳ ଅକ୍ଷର *pin, ସଂରଚନା sk_option **opts,
	    ସଂରଚନା sk_sign_response **sign_response);

	/* Enumerate resident keys */
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା (*sk_load_resident_ଚାବିଗୁଡ଼ିକ)(ଅଚଳ ଅକ୍ଷର *pin, ସଂରଚନା sk_option **opts,
	    ସଂରଚନା sk_resident_ଚାବି ***rks, size_t *nrks);
};

/* Built-in version */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା ssh_sk_enroll(ପୂର୍ଣ୍ଣସଂଖ୍ୟା alg, ଅଚଳ uint8_t *challenge,
    size_t challenge_len, ଅଚଳ ଅକ୍ଷର *application, uint8_t flags,
    ଅଚଳ ଅକ୍ଷର *pin, ସଂରଚନା sk_option **opts,
    ସଂରଚନା sk_enroll_response **enroll_response);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା ssh_sk_sign(ପୂର୍ଣ୍ଣସଂଖ୍ୟା alg, ଅଚଳ uint8_t *message, size_t message_len,
    ଅଚଳ ଅକ୍ଷର *application,
    ଅଚଳ uint8_t *ଚାବି_handle, size_t ଚାବି_handle_len,
    uint8_t flags, ଅଚଳ ଅକ୍ଷର *pin, ସଂରଚନା sk_option **opts,
    ସଂରଚନା sk_sign_response **sign_response);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା ssh_sk_load_resident_ଚାବିଗୁଡ଼ିକ(ଅଚଳ ଅକ୍ଷର *pin, ସଂରଚନା sk_option **opts,
    ସଂରଚନା sk_resident_ଚାବି ***rks, size_t *nrks);

ସ୍ଥିର ଶୂନ୍ୟ
sshsk_free(ସଂରଚନା sshsk_provider *p)
{
	ଯଦି (p == ଖାଲି)
		ଫେରନ୍ତୁ;
	ମୁକ୍ତ(p->path);
	ଯଦି (p->dlhandle != ଖାଲି)
		dlclose(p->dlhandle);
	ମୁକ୍ତ(p);
}

ସ୍ଥିର ସଂରଚନା sshsk_provider *
sshsk_open(ଅଚଳ ଅକ୍ଷର *path)
{
	ସଂରଚନା sshsk_provider *ret = ଖାଲି;
	uint32_t version;

	ଯଦି (path == ଖାଲି || *path == '\0') {
		error("No FIDO SecurityKeyProvider specified");
		ଫେରନ୍ତୁ ଖାଲି;
	}
	ଯଦି ((ret = calloc(1, ଆକାର(*ret))) == ଖାଲି) {
		error_f("calloc failed");
		ଫେରନ୍ତୁ ଖାଲି;
	}
	ଯଦି ((ret->path = strdup(path)) == ଖାଲି) {
		error_f("strdup failed");
		ଯାଅ fail;
	}
	/* Skip the rest if we're using the linked in middleware */
	ଯଦି (strcasecmp(ret->path, "internal") == 0) {
#ifdef ENABLE_SK_INTERNAL
		ret->sk_enroll = ssh_sk_enroll;
		ret->sk_sign = ssh_sk_sign;
		ret->sk_load_resident_ଚାବିଗୁଡ଼ିକ = ssh_sk_load_resident_ଚାବିଗୁଡ଼ିକ;
		ଫେରନ୍ତୁ ret;
#ଅନ୍ୟଥା
		error("internal security key support not enabled");
		ଯାଅ fail;
#endif
	}
	ଯଦି (lib_contains_ପ୍ରତୀକ(path, "sk_api_version") != 0) {
		error("provider %s is not an OpenSSH FIDO library", path);
		ଯାଅ fail;
	}
	ଯଦି ((ret->dlhandle = dlopen(path, RTLD_NOW)) == ଖାଲି)
		fatal("Provider \"%s\" dlopen failed: %s", path, dlerror());
	ଯଦି ((ret->sk_api_version = dlsym(ret->dlhandle,
	    "sk_api_version")) == ଖାଲି) {
		error("Provider \"%s\" dlsym(sk_api_version) failed: %s",
		    path, dlerror());
		ଯାଅ fail;
	}
	version = ret->sk_api_version();
	debug_f("provider %s implements version 0x%08lx", ret->path,
	    (u_long)version);
	ଯଦି ((version & SSH_SK_VERSION_MAJOR_MASK) != SSH_SK_VERSION_MAJOR) {
		error("Provider \"%s\" implements unsupported "
		    "version 0x%08lx (supported: 0x%08lx)",
		    path, (u_long)version, (u_long)SSH_SK_VERSION_MAJOR);
		ଯାଅ fail;
	}
	ଯଦି ((ret->sk_enroll = dlsym(ret->dlhandle, "sk_enroll")) == ଖାଲି) {
		error("Provider %s dlsym(sk_enroll) failed: %s",
		    path, dlerror());
		ଯାଅ fail;
	}
	ଯଦି ((ret->sk_sign = dlsym(ret->dlhandle, "sk_sign")) == ଖାଲି) {
		error("Provider \"%s\" dlsym(sk_sign) failed: %s",
		    path, dlerror());
		ଯାଅ fail;
	}
	ଯଦି ((ret->sk_load_resident_ଚାବିଗୁଡ଼ିକ = dlsym(ret->dlhandle,
	    "sk_load_resident_keys")) == ଖାଲି) {
		error("Provider \"%s\" dlsym(sk_load_resident_keys) "
		    "failed: %s", path, dlerror());
		ଯାଅ fail;
	}
	/* success */
	ଫେରନ୍ତୁ ret;
fail:
	sshsk_free(ret);
	ଫେରନ୍ତୁ ଖାଲି;
}

ସ୍ଥିର ଶୂନ୍ୟ
sshsk_free_enroll_response(ସଂରଚନା sk_enroll_response *r)
{
	ଯଦି (r == ଖାଲି)
		ଫେରନ୍ତୁ;
	freezero(r->ଚାବି_handle, r->ଚାବି_handle_len);
	freezero(r->public_ଚାବି, r->public_ଚାବି_len);
	freezero(r->signature, r->signature_len);
	freezero(r->attestation_cert, r->attestation_cert_len);
	freezero(r->authdata, r->authdata_len);
	freezero(r, ଆକାର(*r));
}

ସ୍ଥିର ଶୂନ୍ୟ
sshsk_free_sign_response(ସଂରଚନା sk_sign_response *r)
{
	ଯଦି (r == ଖାଲି)
		ଫେରନ୍ତୁ;
	freezero(r->sig_r, r->sig_r_len);
	freezero(r->sig_s, r->sig_s_len);
	freezero(r, ଆକାର(*r));
}

#ifdef WITH_OPENSSL
/* Assemble key from response */
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshsk_ecdsa_assemble(ସଂରଚନା sk_enroll_response *resp, ସଂରଚନା sshkey **keyp)
{
	ସଂରଚନା sshkey *ଚାବି = ଖାଲି;
	ସଂରଚନା sshbuf *b = ଖାଲି;
	EC_ଚାବି *ecdsa = ଖାଲି;
	EC_POINT *q = ଖାଲି;
	ଅଚଳ EC_GROUP *g = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	*keyp = ଖାଲି;
	ଯଦି ((ଚାବି = sshkey_new(ଚାବି_ECDSA_SK)) == ଖାଲି) {
		error_f("sshkey_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		ଯାଅ out;
	}
	ଚାବି->ecdsa_nid = NID_X9_62_prime256v1;
	ଯଦି ((ecdsa = EC_ଚାବି_new_by_curve_name(ଚାବି->ecdsa_nid)) == ଖାଲି ||
	    (g = EC_ଚାବି_get0_group(ecdsa)) == ଖାଲି ||
	    (q = EC_POINT_new(g)) == ଖାଲି ||
	    (b = sshbuf_new()) == ଖାଲି) {
		error_f("allocation failed");
		r = SSH_ERR_ALLOC_FAIL;
		ଯାଅ out;
	}
	ଯଦି ((r = sshbuf_put_string(b,
	    resp->public_ଚାବି, resp->public_ଚାବି_len)) != 0) {
		error_fr(r, "sshbuf_put_string");
		ଯାଅ out;
	}
	ଯଦି ((r = sshbuf_get_ec(b, q, g)) != 0) {
		error_fr(r, "parse");
		r = SSH_ERR_INVALID_FORMAT;
		ଯାଅ out;
	}
	ଯଦି (sshkey_ec_validate_public(g, q) != 0) {
		error("Authenticator returned invalid ECDSA key");
		r = SSH_ERR_ଚାବି_INVALID_EC_ମୂଲ୍ୟ;
		ଯାଅ out;
	}
	ଯଦି (EC_ଚାବି_set_public_ଚାବି(ecdsa, q) != 1) {
		/* XXX assume it is a allocation error */
		error_f("allocation failed");
		r = SSH_ERR_ALLOC_FAIL;
		ଯାଅ out;
	}
	ଯଦି ((ଚାବି->pkey = EVP_PKEY_new()) == ଖାଲି) {
		error_f("allocation failed");
		r = SSH_ERR_ALLOC_FAIL;
		ଯାଅ out;
	}
	ଯଦି (EVP_PKEY_set1_EC_ଚାବି(ଚାବି->pkey, ecdsa) != 1) {
		error_f("Assigning EC_KEY failed");
		r = SSH_ERR_LIBCRYPTO_ERROR;
		ଯାଅ out;
	}
	/* success */
	*keyp = ଚାବି;
	ଚାବି = ଖାଲି; /* transferred */
	r = 0;
 out:
	sshkey_free(ଚାବି);
	sshbuf_free(b);
	EC_ଚାବି_free(ecdsa);
	EC_POINT_free(q);
	ଫେରନ୍ତୁ r;
}
#endif /* WITH_OPENSSL */

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshsk_ed25519_assemble(ସଂରଚନା sk_enroll_response *resp, ସଂରଚନା sshkey **keyp)
{
	ସଂରଚନା sshkey *ଚାବି = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	*keyp = ଖାଲି;
	ଯଦି (resp->public_ଚାବି_len != ED25519_PK_SZ) {
		error_f("invalid size: %zu", resp->public_ଚାବି_len);
		r = SSH_ERR_INVALID_FORMAT;
		ଯାଅ out;
	}
	ଯଦି ((ଚାବି = sshkey_new(ଚାବି_ED25519_SK)) == ଖାଲି) {
		error_f("sshkey_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		ଯାଅ out;
	}
	ଯଦି ((ଚାବି->ed25519_pk = malloc(ED25519_PK_SZ)) == ଖାଲି) {
		error_f("malloc failed");
		r = SSH_ERR_ALLOC_FAIL;
		ଯାଅ out;
	}
	memcpy(ଚାବି->ed25519_pk, resp->public_ଚାବି, ED25519_PK_SZ);
	/* success */
	*keyp = ଚାବି;
	ଚାବି = ଖାଲି; /* transferred */
	r = 0;
 out:
	sshkey_free(ଚାବି);
	ଫେରନ୍ତୁ r;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshsk_ଚାବି_from_response(ପୂର୍ଣ୍ଣସଂଖ୍ୟା alg, ଅଚଳ ଅକ୍ଷର *application, uint8_t flags,
    ସଂରଚନା sk_enroll_response *resp, ସଂରଚନା sshkey **keyp)
{
	ସଂରଚନା sshkey *ଚାବି = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r = SSH_ERR_INTERNAL_ERROR;

	*keyp = ଖାଲି;

	/* Check response validity */
	ଯଦି (resp->public_ଚାବି == ଖାଲି || resp->ଚାବି_handle == ଖାଲି) {
		error_f("sk_enroll response invalid");
		r = SSH_ERR_INVALID_FORMAT;
		ଯାଅ out;
	}
	ବାଛ (alg) {
#ifdef WITH_OPENSSL
	ସ୍ଥିତି SSH_SK_ECDSA:
		ଯଦି ((r = sshsk_ecdsa_assemble(resp, &ଚାବି)) != 0)
			ଯାଅ out;
		ଭାଙ୍ଗ;
#endif /* WITH_OPENSSL */
	ସ୍ଥିତି SSH_SK_ED25519:
		ଯଦି ((r = sshsk_ed25519_assemble(resp, &ଚାବି)) != 0)
			ଯାଅ out;
		ଭାଙ୍ଗ;
	ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
		error_f("unsupported algorithm %d", alg);
		r = SSH_ERR_INVALID_ARGUMENT;
		ଯାଅ out;
	}
	ଚାବି->sk_flags = flags;
	ଯଦି ((ଚାବି->sk_ଚାବି_handle = sshbuf_new()) == ଖାଲି ||
	    (ଚାବି->sk_reserved = sshbuf_new()) == ଖାଲି) {
		error_f("allocation failed");
		r = SSH_ERR_ALLOC_FAIL;
		ଯାଅ out;
	}
	ଯଦି ((ଚାବି->sk_application = strdup(application)) == ଖାଲି) {
		error_f("strdup application failed");
		r = SSH_ERR_ALLOC_FAIL;
		ଯାଅ out;
	}
	ଯଦି ((r = sshbuf_put(ଚାବି->sk_ଚାବି_handle, resp->ଚାବି_handle,
	    resp->ଚାବି_handle_len)) != 0) {
		error_fr(r, "put key handle");
		ଯାଅ out;
	}
	/* success */
	r = 0;
	*keyp = ଚାବି;
	ଚାବି = ଖାଲି;
 out:
	sshkey_free(ଚାବି);
	ଫେରନ୍ତୁ r;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
skerr_to_ssherr(ପୂର୍ଣ୍ଣସଂଖ୍ୟା skerr)
{
	ବାଛ (skerr) {
	ସ୍ଥିତି SSH_SK_ERR_UNSUPPORTED:
		ଫେରନ୍ତୁ SSH_ERR_FEATURE_UNSUPPORTED;
	ସ୍ଥିତି SSH_SK_ERR_PIN_REQUIRED:
		ଫେରନ୍ତୁ SSH_ERR_ଚାବି_WRONG_PASSPHRASE;
	ସ୍ଥିତି SSH_SK_ERR_DEVICE_NOT_FOUND:
		ଫେରନ୍ତୁ SSH_ERR_DEVICE_NOT_FOUND;
	ସ୍ଥିତି SSH_SK_ERR_CREDENTIAL_EXISTS:
		ଫେରନ୍ତୁ SSH_ERR_ଚାବି_BAD_PERMISSIONS;
	ସ୍ଥିତି SSH_SK_ERR_GENERAL:
	ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
		ଫେରନ୍ତୁ SSH_ERR_INVALID_FORMAT;
	}
}

ସ୍ଥିର ଶୂନ୍ୟ
sshsk_free_options(ସଂରଚନା sk_option **opts)
{
	size_t i;

	ଯଦି (opts == ଖାଲି)
		ଫେରନ୍ତୁ;
	ପାଇଁ (i = 0; opts[i] != ଖାଲି; i++) {
		ମୁକ୍ତ(opts[i]->name);
		ମୁକ୍ତ(opts[i]->ମୂଲ୍ୟ);
		ମୁକ୍ତ(opts[i]);
	}
	ମୁକ୍ତ(opts);
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshsk_add_option(ସଂରଚନା sk_option ***optsp, size_t *noptsp,
    ଅଚଳ ଅକ୍ଷର *name, ଅଚଳ ଅକ୍ଷର *ମୂଲ୍ୟ, uint8_t required)
{
	ସଂରଚନା sk_option **opts = *optsp;
	size_t nopts = *noptsp;

	ଯଦି ((opts = recallocarray(opts, nopts, nopts + 2, /* extra for NULL */
	    ଆକାର(*opts))) == ଖାଲି) {
		error_f("array alloc failed");
		ଫେରନ୍ତୁ SSH_ERR_ALLOC_FAIL;
	}
	*optsp = opts;
	*noptsp = nopts + 1;
	ଯଦି ((opts[nopts] = calloc(1, ଆକାର(**opts))) == ଖାଲି) {
		error_f("alloc failed");
		ଫେରନ୍ତୁ SSH_ERR_ALLOC_FAIL;
	}
	ଯଦି ((opts[nopts]->name = strdup(name)) == ଖାଲି ||
	    (opts[nopts]->ମୂଲ୍ୟ = strdup(ମୂଲ୍ୟ)) == ଖାଲି) {
		error_f("alloc failed");
		ଫେରନ୍ତୁ SSH_ERR_ALLOC_FAIL;
	}
	opts[nopts]->required = required;
	ଫେରନ୍ତୁ 0;
}

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
make_options(ଅଚଳ ଅକ୍ଷର *device, ଅଚଳ ଅକ୍ଷର *user_id,
    ସଂରଚନା sk_option ***optsp)
{
	ସଂରଚନା sk_option **opts = ଖାଲି;
	size_t nopts = 0;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, ret = SSH_ERR_INTERNAL_ERROR;

	ଯଦି (device != ଖାଲି &&
	    (r = sshsk_add_option(&opts, &nopts, "device", device, 0)) != 0) {
		ret = r;
		ଯାଅ out;
	}
	ଯଦି (user_id != ଖାଲି &&
	    (r = sshsk_add_option(&opts, &nopts, "user", user_id, 0)) != 0) {
		ret = r;
		ଯାଅ out;
	}
	/* success */
	*optsp = opts;
	opts = ଖାଲି;
	nopts = 0;
	ret = 0;
 out:
	sshsk_free_options(opts);
	ଫେରନ୍ତୁ ret;
}


ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
fill_attestation_blob(ଅଚଳ ସଂରଚନା sk_enroll_response *resp,
    ସଂରଚନା sshbuf *attest)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

	ଯଦି (attest == ଖାଲି)
		ଫେରନ୍ତୁ 0; /* nothing to do */
	ଯଦି ((r = sshbuf_put_cstring(attest, "ssh-sk-attest-v01")) != 0 ||
	    (r = sshbuf_put_string(attest,
	    resp->attestation_cert, resp->attestation_cert_len)) != 0 ||
	    (r = sshbuf_put_string(attest,
	    resp->signature, resp->signature_len)) != 0 ||
	    (r = sshbuf_put_string(attest,
	    resp->authdata, resp->authdata_len)) != 0 ||
	    (r = sshbuf_put_u32(attest, 0)) != 0 || /* resvd flags */
	    (r = sshbuf_put_string(attest, ଖାଲି, 0)) != 0 /* resvd */) {
		error_fr(r, "compose");
		ଫେରନ୍ତୁ r;
	}
	/* success */
	ଫେରନ୍ତୁ 0;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshsk_enroll(ପୂର୍ଣ୍ଣସଂଖ୍ୟା type, ଅଚଳ ଅକ୍ଷର *provider_path, ଅଚଳ ଅକ୍ଷର *device,
    ଅଚଳ ଅକ୍ଷର *application, ଅଚଳ ଅକ୍ଷର *userid, uint8_t flags,
    ଅଚଳ ଅକ୍ଷର *pin, ସଂରଚନା sshbuf *challenge_buf,
    ସଂରଚନା sshkey **keyp, ସଂରଚନା sshbuf *attest)
{
	ସଂରଚନା sshsk_provider *skp = ଖାଲି;
	ସଂରଚନା sshkey *ଚାବି = ଖାଲି;
	u_char randchall[32];
	ଅଚଳ u_char *challenge;
	size_t challenge_len;
	ସଂରଚନା sk_enroll_response *resp = ଖାଲି;
	ସଂରଚନା sk_option **opts = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r = SSH_ERR_INTERNAL_ERROR;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା alg;

	debug_f("provider \"%s\", device \"%s\", application \"%s\", "
	    "userid \"%s\", flags 0x%02x, challenge len %zu%s",
	    provider_path, device, application, userid, flags,
	    challenge_buf == ଖାଲି ? 0 : sshbuf_len(challenge_buf),
	    (pin != ଖାଲି && *pin != '\0') ? " with-pin" : "");

	*keyp = ଖାଲି;
	ଯଦି (attest)
		sshbuf_reset(attest);

	ଯଦି ((r = make_options(device, userid, &opts)) != 0)
		ଯାଅ out;

	ବାଛ (type) {
#ifdef WITH_OPENSSL
	ସ୍ଥିତି ଚାବି_ECDSA_SK:
		alg = SSH_SK_ECDSA;
		ଭାଙ୍ଗ;
#endif /* WITH_OPENSSL */
	ସ୍ଥିତି ଚାବି_ED25519_SK:
		alg = SSH_SK_ED25519;
		ଭାଙ୍ଗ;
	ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
		error_f("unsupported key type");
		r = SSH_ERR_INVALID_ARGUMENT;
		ଯାଅ out;
	}
	ଯଦି (provider_path == ଖାଲି) {
		error_f("missing provider");
		r = SSH_ERR_INVALID_ARGUMENT;
		ଯାଅ out;
	}
	ଯଦି (application == ଖାଲି || *application == '\0') {
		error_f("missing application");
		r = SSH_ERR_INVALID_ARGUMENT;
		ଯାଅ out;
	}
	ଯଦି (challenge_buf == ଖାଲି) {
		debug_f("using random challenge");
		arc4random_buf(randchall, ଆକାର(randchall));
		challenge = randchall;
		challenge_len = ଆକାର(randchall);
	} ଅନ୍ୟଥା ଯଦି (sshbuf_len(challenge_buf) == 0) {
		error("Missing enrollment challenge");
		r = SSH_ERR_INVALID_ARGUMENT;
		ଯାଅ out;
	} ଅନ୍ୟଥା {
		challenge = sshbuf_ptr(challenge_buf);
		challenge_len = sshbuf_len(challenge_buf);
		debug3_f("using explicit challenge len=%zd", challenge_len);
	}
	ଯଦି ((skp = sshsk_open(provider_path)) == ଖାଲି) {
		r = SSH_ERR_INVALID_FORMAT; /* XXX sshsk_open return code? */
		ଯାଅ out;
	}
	/* XXX validate flags? */
	/* enroll key */
	ଯଦି ((r = skp->sk_enroll(alg, challenge, challenge_len, application,
	    flags, pin, opts, &resp)) != 0) {
		debug_f("provider \"%s\" failure %d", provider_path, r);
		r = skerr_to_ssherr(r);
		ଯାଅ out;
	}

	ଯଦି ((r = sshsk_ଚାବି_from_response(alg, application, resp->flags,
	    resp, &ଚାବି)) != 0)
		ଯାଅ out;

	/* Optionally fill in the attestation information */
	ଯଦି ((r = fill_attestation_blob(resp, attest)) != 0)
		ଯାଅ out;

	/* success */
	*keyp = ଚାବି;
	ଚାବି = ଖାଲି; /* transferred */
	r = 0;
 out:
	sshsk_free_options(opts);
	sshsk_free(skp);
	sshkey_free(ଚାବି);
	sshsk_free_enroll_response(resp);
	explicit_bzero(randchall, ଆକାର(randchall));
	ଫେରନ୍ତୁ r;
}

#ifdef WITH_OPENSSL
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshsk_ecdsa_sig(ସଂରଚନା sk_sign_response *resp, ସଂରଚନା sshbuf *sig)
{
	ସଂରଚନା sshbuf *inner_sig = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r = SSH_ERR_INTERNAL_ERROR;

	/* Check response validity */
	ଯଦି (resp->sig_r == ଖାଲି || resp->sig_s == ଖାଲି) {
		error_f("sk_sign response invalid");
		r = SSH_ERR_INVALID_FORMAT;
		ଯାଅ out;
	}
	ଯଦି ((inner_sig = sshbuf_new()) == ଖାଲି) {
		r = SSH_ERR_ALLOC_FAIL;
		ଯାଅ out;
	}
	/* Prepare and append inner signature object */
	ଯଦି ((r = sshbuf_put_bignum2_bytes(inner_sig,
	    resp->sig_r, resp->sig_r_len)) != 0 ||
	    (r = sshbuf_put_bignum2_bytes(inner_sig,
	    resp->sig_s, resp->sig_s_len)) != 0) {
		error_fr(r, "compose inner");
		ଯାଅ out;
	}
	ଯଦି ((r = sshbuf_put_stringb(sig, inner_sig)) != 0 ||
	    (r = sshbuf_put_u8(sig, resp->flags)) != 0 ||
	    (r = sshbuf_put_u32(sig, resp->counter)) != 0) {
		error_fr(r, "compose");
		ଯାଅ out;
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
	ଫେରନ୍ତୁ r;
}
#endif /* WITH_OPENSSL */

ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshsk_ed25519_sig(ସଂରଚନା sk_sign_response *resp, ସଂରଚନା sshbuf *sig)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r = SSH_ERR_INTERNAL_ERROR;

	/* Check response validity */
	ଯଦି (resp->sig_r == ଖାଲି) {
		error_f("sk_sign response invalid");
		r = SSH_ERR_INVALID_FORMAT;
		ଯାଅ out;
	}
	ଯଦି ((r = sshbuf_put_string(sig,
	    resp->sig_r, resp->sig_r_len)) != 0 ||
	    (r = sshbuf_put_u8(sig, resp->flags)) != 0 ||
	    (r = sshbuf_put_u32(sig, resp->counter)) != 0) {
		error_fr(r, "compose");
		ଯାଅ out;
	}
#ifdef DEBUG_SK
	fprintf(stderr, "%s: sig_r:\n", __func__);
	sshbuf_dump_data(resp->sig_r, resp->sig_r_len, stderr);
#endif
	r = 0;
 out:
	ଫେରନ୍ତୁ r;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshsk_sign(ଅଚଳ ଅକ୍ଷର *provider_path, ସଂରଚନା sshkey *ଚାବି,
    u_char **sigp, size_t *lenp, ଅଚଳ u_char *data, size_t datalen,
    u_int compat, ଅଚଳ ଅକ୍ଷର *pin)
{
	ସଂରଚନା sshsk_provider *skp = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r = SSH_ERR_INTERNAL_ERROR;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା type, alg;
	ସଂରଚନା sk_sign_response *resp = ଖାଲି;
	ସଂରଚନା sshbuf *inner_sig = ଖାଲି, *sig = ଖାଲି;
	ସଂରଚନା sk_option **opts = ଖାଲି;

	debug_f("provider \"%s\", key %s, flags 0x%02x%s",
	    provider_path, sshkey_type(ଚାବି), ଚାବି->sk_flags,
	    (pin != ଖାଲି && *pin != '\0') ? " with-pin" : "");

	ଯଦି (sigp != ଖାଲି)
		*sigp = ଖାଲି;
	ଯଦି (lenp != ଖାଲି)
		*lenp = 0;
	type = sshkey_type_plain(ଚାବି->type);
	ବାଛ (type) {
#ifdef WITH_OPENSSL
	ସ୍ଥିତି ଚାବି_ECDSA_SK:
		alg = SSH_SK_ECDSA;
		ଭାଙ୍ଗ;
#endif /* WITH_OPENSSL */
	ସ୍ଥିତି ଚାବି_ED25519_SK:
		alg = SSH_SK_ED25519;
		ଭାଙ୍ଗ;
	ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
		ଫେରନ୍ତୁ SSH_ERR_INVALID_ARGUMENT;
	}
	ଯଦି (provider_path == ଖାଲି ||
	    ଚାବି->sk_ଚାବି_handle == ଖାଲି ||
	    ଚାବି->sk_application == ଖାଲି || *ଚାବି->sk_application == '\0') {
		r = SSH_ERR_INVALID_ARGUMENT;
		ଯାଅ out;
	}
	ଯଦି ((skp = sshsk_open(provider_path)) == ଖାଲି) {
		r = SSH_ERR_INVALID_FORMAT; /* XXX sshsk_open return code? */
		ଯାଅ out;
	}
#ifdef DEBUG_SK
	fprintf(stderr, "%s: sk_flags = 0x%02x, sk_application = \"%s\"\n",
	    __func__, ଚାବି->sk_flags, ଚାବି->sk_application);
	fprintf(stderr, "%s: sk_key_handle:\n", __func__);
	sshbuf_dump(ଚାବି->sk_ଚାବି_handle, stderr);
#endif
	ଯଦି ((r = skp->sk_sign(alg, data, datalen, ଚାବି->sk_application,
	    sshbuf_ptr(ଚାବି->sk_ଚାବି_handle), sshbuf_len(ଚାବି->sk_ଚାବି_handle),
	    ଚାବି->sk_flags, pin, opts, &resp)) != 0) {
		debug_f("sk_sign failed with code %d", r);
		r = skerr_to_ssherr(r);
		ଯାଅ out;
	}
	/* Assemble signature */
	ଯଦି ((sig = sshbuf_new()) == ଖାଲି) {
		r = SSH_ERR_ALLOC_FAIL;
		ଯାଅ out;
	}
	ଯଦି ((r = sshbuf_put_cstring(sig, sshkey_ssh_name_plain(ଚାବି))) != 0) {
		error_fr(r, "compose outer");
		ଯାଅ out;
	}
	ବାଛ (type) {
#ifdef WITH_OPENSSL
	ସ୍ଥିତି ଚାବି_ECDSA_SK:
		ଯଦି ((r = sshsk_ecdsa_sig(resp, sig)) != 0)
			ଯାଅ out;
		ଭାଙ୍ଗ;
#endif /* WITH_OPENSSL */
	ସ୍ଥିତି ଚାବି_ED25519_SK:
		ଯଦି ((r = sshsk_ed25519_sig(resp, sig)) != 0)
			ଯାଅ out;
		ଭାଙ୍ଗ;
	}
#ifdef DEBUG_SK
	fprintf(stderr, "%s: sig_flags = 0x%02x, sig_counter = %u\n",
	    __func__, resp->flags, resp->counter);
	fprintf(stderr, "%s: data to sign:\n", __func__);
	sshbuf_dump_data(data, datalen, stderr);
	fprintf(stderr, "%s: sigbuf:\n", __func__);
	sshbuf_dump(sig, stderr);
#endif
	ଯଦି (sigp != ଖାଲି) {
		ଯଦି ((*sigp = malloc(sshbuf_len(sig))) == ଖାଲି) {
			r = SSH_ERR_ALLOC_FAIL;
			ଯାଅ out;
		}
		memcpy(*sigp, sshbuf_ptr(sig), sshbuf_len(sig));
	}
	ଯଦି (lenp != ଖାଲି)
		*lenp = sshbuf_len(sig);
	/* success */
	r = 0;
 out:
	sshsk_free_options(opts);
	sshsk_free(skp);
	sshsk_free_sign_response(resp);
	sshbuf_free(sig);
	sshbuf_free(inner_sig);
	ଫେରନ୍ତୁ r;
}

ସ୍ଥିର ଶୂନ୍ୟ
sshsk_free_sk_resident_ଚାବିଗୁଡ଼ିକ(ସଂରଚନା sk_resident_ଚାବି **rks, size_t nrks)
{
	size_t i;

	ଯଦି (nrks == 0 || rks == ଖାଲି)
		ଫେରନ୍ତୁ;
	ପାଇଁ (i = 0; i < nrks; i++) {
		ମୁକ୍ତ(rks[i]->application);
		freezero(rks[i]->user_id, rks[i]->user_id_len);
		freezero(rks[i]->ଚାବି.ଚାବି_handle, rks[i]->ଚାବି.ଚାବି_handle_len);
		freezero(rks[i]->ଚାବି.public_ଚାବି, rks[i]->ଚାବି.public_ଚାବି_len);
		freezero(rks[i]->ଚାବି.signature, rks[i]->ଚାବି.signature_len);
		freezero(rks[i]->ଚାବି.attestation_cert,
		    rks[i]->ଚାବି.attestation_cert_len);
		freezero(rks[i], ଆକାର(**rks));
	}
	ମୁକ୍ତ(rks);
}

ସ୍ଥିର ଶୂନ୍ୟ
sshsk_free_resident_ଚାବି(ସଂରଚନା sshsk_resident_ଚାବି *srk)
{
	ଯଦି (srk == ଖାଲି)
		ଫେରନ୍ତୁ;
	sshkey_free(srk->ଚାବି);
	freezero(srk->user_id, srk->user_id_len);
	ମୁକ୍ତ(srk);
}


ଶୂନ୍ୟ
sshsk_free_resident_ଚାବିଗୁଡ଼ିକ(ସଂରଚନା sshsk_resident_ଚାବି **srks, size_t nsrks)
{
	size_t i;

	ଯଦି (srks == ଖାଲି || nsrks == 0)
		ଫେରନ୍ତୁ;

	ପାଇଁ (i = 0; i < nsrks; i++)
		sshsk_free_resident_ଚାବି(srks[i]);
	ମୁକ୍ତ(srks);
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshsk_load_resident(ଅଚଳ ଅକ୍ଷର *provider_path, ଅଚଳ ଅକ୍ଷର *device,
    ଅଚଳ ଅକ୍ଷର *pin, u_int flags, ସଂରଚନା sshsk_resident_ଚାବି ***srksp,
    size_t *nsrksp)
{
	ସଂରଚନା sshsk_provider *skp = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r = SSH_ERR_INTERNAL_ERROR;
	ସଂରଚନା sk_resident_ଚାବି **rks = ଖାଲି;
	size_t i, nrks = 0, nsrks = 0;
	ସଂରଚନା sshkey *ଚାବି = ଖାଲି;
	ସଂରଚନା sshsk_resident_ଚାବି *srk = ଖାଲି, **srks = ଖାଲି, **tmp;
	uint8_t sk_flags;
	ସଂରଚନା sk_option **opts = ଖାଲି;

	debug_f("provider \"%s\"%s", provider_path,
	    (pin != ଖାଲି && *pin != '\0') ? ", have-pin": "");

	ଯଦି (srksp == ଖାଲି || nsrksp == ଖାଲି)
		ଫେରନ୍ତୁ SSH_ERR_INVALID_ARGUMENT;
	*srksp = ଖାଲି;
	*nsrksp = 0;

	ଯଦି ((r = make_options(device, ଖାଲି, &opts)) != 0)
		ଯାଅ out;
	ଯଦି ((skp = sshsk_open(provider_path)) == ଖାଲି) {
		r = SSH_ERR_INVALID_FORMAT; /* XXX sshsk_open return code? */
		ଯାଅ out;
	}
	ଯଦି ((r = skp->sk_load_resident_ଚାବିଗୁଡ଼ିକ(pin, opts, &rks, &nrks)) != 0) {
		error("Provider \"%s\" returned failure %d", provider_path, r);
		r = skerr_to_ssherr(r);
		ଯାଅ out;
	}
	ପାଇଁ (i = 0; i < nrks; i++) {
		debug3_f("rk %zu: slot %zu, alg %d, app \"%s\", uidlen %zu",
		    i, rks[i]->slot, rks[i]->alg, rks[i]->application,
		    rks[i]->user_id_len);
		/* XXX need better filter here */
		ଯଦି (strncmp(rks[i]->application, "ssh:", 4) != 0)
			ଜାରି;
		ବାଛ (rks[i]->alg) {
		ସ୍ଥିତି SSH_SK_ECDSA:
		ସ୍ଥିତି SSH_SK_ED25519:
			ଭାଙ୍ଗ;
		ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
			ଜାରି;
		}
		sk_flags = SSH_SK_USER_PRESENCE_REQD|SSH_SK_RESIDENT_ଚାବି;
		ଯଦି ((rks[i]->flags & SSH_SK_USER_VERIFICATION_REQD))
			sk_flags |= SSH_SK_USER_VERIFICATION_REQD;
		ଯଦି ((r = sshsk_ଚାବି_from_response(rks[i]->alg,
		    rks[i]->application, sk_flags, &rks[i]->ଚାବି, &ଚାବି)) != 0)
			ଯାଅ out;
		ଯଦି ((srk = calloc(1, ଆକାର(*srk))) == ଖାଲି) {
			error_f("calloc failed");
			r = SSH_ERR_ALLOC_FAIL;
			ଯାଅ out;
		}
		srk->ଚାବି = ଚାବି;
		ଚାବି = ଖାଲି; /* transferred */
		ଯଦି ((srk->user_id = calloc(1, rks[i]->user_id_len)) == ଖାଲି) {
			error_f("calloc failed");
			r = SSH_ERR_ALLOC_FAIL;
			ଯାଅ out;
		}
		memcpy(srk->user_id, rks[i]->user_id, rks[i]->user_id_len);
		srk->user_id_len = rks[i]->user_id_len;
		ଯଦି ((tmp = recallocarray(srks, nsrks, nsrks + 1,
		    ଆକାର(*tmp))) == ଖାଲି) {
			error_f("recallocarray failed");
			r = SSH_ERR_ALLOC_FAIL;
			ଯାଅ out;
		}
		srks = tmp;
		srks[nsrks++] = srk;
		srk = ଖାଲି;
		/* XXX synthesise comment */
	}
	/* success */
	*srksp = srks;
	*nsrksp = nsrks;
	srks = ଖାଲି;
	nsrks = 0;
	r = 0;
 out:
	sshsk_free_options(opts);
	sshsk_free(skp);
	sshsk_free_sk_resident_ଚାବିଗୁଡ଼ିକ(rks, nrks);
	sshkey_free(ଚାବି);
	sshsk_free_resident_ଚାବି(srk);
	sshsk_free_resident_ଚାବିଗୁଡ଼ିକ(srks, nsrks);
	ଫେରନ୍ତୁ r;
}

#endif /* ENABLE_SK */
