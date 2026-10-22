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

#include "includes.h"

#ifdef ENABLE_SK

#include <dlfcn.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#ifdef WITH_OPENSSL
#include <openssl/objects.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#endif /* WITH_OPENSSL */

#include "log.h"
#include "misc.h"
#include "sshbuf.h"
#include "sshkey.h"
#include "ssherr.h"
#include "digest.h"

#include "ssh-sk.h"
#include "sk-api.h"
#include "crypto_api.h"

sa_nracanaa sshsk_provider {
	var_na *path;
	void *dlhandle;

	/* Return the version of the middleware API */
	uint32_t (*sk_api_version)(void);

	/* Enroll a U2F key (private key generation) */
	ចំនួនគត់ (*sk_enroll)(ចំនួនគត់ alg, const uint8_t *challenge,
	    size_t challenge_len, const var_na *application, uint8_t flags,
	    const var_na *pin, sa_nracanaa sk_option **opts,
	    sa_nracanaa sk_enroll_response **enroll_response);

	/* Sign a challenge */
	ចំនួនគត់ (*sk_sign)(ចំនួនគត់ alg, const uint8_t *message, size_t message_len,
	    const var_na *application,
	    const uint8_t *key_handle, size_t key_handle_len,
	    uint8_t flags, const var_na *pin, sa_nracanaa sk_option **opts,
	    sa_nracanaa sk_sign_response **sign_response);

	/* Enumerate resident keys */
	ចំនួនគត់ (*sk_load_resident_keys)(const var_na *pin, sa_nracanaa sk_option **opts,
	    sa_nracanaa sk_resident_key ***rks, size_t *nrks);
};

/* Built-in version */
ចំនួនគត់ ssh_sk_enroll(ចំនួនគត់ alg, const uint8_t *challenge,
    size_t challenge_len, const var_na *application, uint8_t flags,
    const var_na *pin, sa_nracanaa sk_option **opts,
    sa_nracanaa sk_enroll_response **enroll_response);
ចំនួនគត់ ssh_sk_sign(ចំនួនគត់ alg, const uint8_t *message, size_t message_len,
    const var_na *application,
    const uint8_t *key_handle, size_t key_handle_len,
    uint8_t flags, const var_na *pin, sa_nracanaa sk_option **opts,
    sa_nracanaa sk_sign_response **sign_response);
ចំនួនគត់ ssh_sk_load_resident_keys(const var_na *pin, sa_nracanaa sk_option **opts,
    sa_nracanaa sk_resident_key ***rks, size_t *nrks);

static void
sshsk_free(sa_nracanaa sshsk_provider *p)
{
	ប្រសិនបើ (p == NULL)
		ត្រឡប់;
	free(p->path);
	ប្រសិនបើ (p->dlhandle != NULL)
		dlclose(p->dlhandle);
	free(p);
}

static sa_nracanaa sshsk_provider *
sshsk_open(const var_na *path)
{
	sa_nracanaa sshsk_provider *ret = NULL;
	uint32_t version;

	ប្រសិនបើ (path == NULL || *path == '\0') {
		error("No FIDO SecurityKeyProvider specified");
		ត្រឡប់ NULL;
	}
	ប្រសិនបើ ((ret = calloc(1, parimaa_na(*ret))) == NULL) {
		error_f("calloc failed");
		ត្រឡប់ NULL;
	}
	ប្រសិនបើ ((ret->path = strdup(path)) == NULL) {
		error_f("strdup failed");
		goto fail;
	}
	/* Skip the rest if we're using the linked in middleware */
	ប្រសិនបើ (strcasecmp(ret->path, "internal") == 0) {
#ifdef ENABLE_SK_INTERNAL
		ret->sk_enroll = ssh_sk_enroll;
		ret->sk_sign = ssh_sk_sign;
		ret->sk_load_resident_keys = ssh_sk_load_resident_keys;
		ត្រឡប់ ret;
#បើមិនដូច្នេះ
		error("internal security key support not enabled");
		goto fail;
#endif
	}
	ប្រសិនបើ (lib_contains_symbol(path, "sk_api_version") != 0) {
		error("provider %s is not an OpenSSH FIDO library", path);
		goto fail;
	}
	ប្រសិនបើ ((ret->dlhandle = dlopen(path, RTLD_NOW)) == NULL)
		fatal("Provider \"%s\" dlopen failed: %s", path, dlerror());
	ប្រសិនបើ ((ret->sk_api_version = dlsym(ret->dlhandle,
	    "sk_api_version")) == NULL) {
		error("Provider \"%s\" dlsym(sk_api_version) failed: %s",
		    path, dlerror());
		goto fail;
	}
	version = ret->sk_api_version();
	debug_f("provider %s implements version 0x%08lx", ret->path,
	    (u_long)version);
	ប្រសិនបើ ((version & SSH_SK_VERSION_MAJOR_MASK) != SSH_SK_VERSION_MAJOR) {
		error("Provider \"%s\" implements unsupported "
		    "version 0x%08lx (supported: 0x%08lx)",
		    path, (u_long)version, (u_long)SSH_SK_VERSION_MAJOR);
		goto fail;
	}
	ប្រសិនបើ ((ret->sk_enroll = dlsym(ret->dlhandle, "sk_enroll")) == NULL) {
		error("Provider %s dlsym(sk_enroll) failed: %s",
		    path, dlerror());
		goto fail;
	}
	ប្រសិនបើ ((ret->sk_sign = dlsym(ret->dlhandle, "sk_sign")) == NULL) {
		error("Provider \"%s\" dlsym(sk_sign) failed: %s",
		    path, dlerror());
		goto fail;
	}
	ប្រសិនបើ ((ret->sk_load_resident_keys = dlsym(ret->dlhandle,
	    "sk_load_resident_keys")) == NULL) {
		error("Provider \"%s\" dlsym(sk_load_resident_keys) "
		    "failed: %s", path, dlerror());
		goto fail;
	}
	/* success */
	ត្រឡប់ ret;
fail:
	sshsk_free(ret);
	ត្រឡប់ NULL;
}

static void
sshsk_free_enroll_response(sa_nracanaa sk_enroll_response *r)
{
	ប្រសិនបើ (r == NULL)
		ត្រឡប់;
	freezero(r->key_handle, r->key_handle_len);
	freezero(r->public_key, r->public_key_len);
	freezero(r->signature, r->signature_len);
	freezero(r->attestation_cert, r->attestation_cert_len);
	freezero(r->authdata, r->authdata_len);
	freezero(r, parimaa_na(*r));
}

static void
sshsk_free_sign_response(sa_nracanaa sk_sign_response *r)
{
	ប្រសិនបើ (r == NULL)
		ត្រឡប់;
	freezero(r->sig_r, r->sig_r_len);
	freezero(r->sig_s, r->sig_s_len);
	freezero(r, parimaa_na(*r));
}

#ifdef WITH_OPENSSL
/* Assemble key from response */
static ចំនួនគត់
sshsk_ecdsa_assemble(sa_nracanaa sk_enroll_response *resp, sa_nracanaa sshkey **keyp)
{
	sa_nracanaa sshkey *key = NULL;
	sa_nracanaa sshbuf *b = NULL;
	EC_KEY *ecdsa = NULL;
	EC_POINT *q = NULL;
	const EC_GROUP *g = NULL;
	ចំនួនគត់ r;

	*keyp = NULL;
	ប្រសិនបើ ((key = sshkey_new(KEY_ECDSA_SK)) == NULL) {
		error_f("sshkey_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	key->ecdsa_nid = NID_X9_62_prime256v1;
	ប្រសិនបើ ((ecdsa = EC_KEY_new_by_curve_name(key->ecdsa_nid)) == NULL ||
	    (g = EC_KEY_get0_group(ecdsa)) == NULL ||
	    (q = EC_POINT_new(g)) == NULL ||
	    (b = sshbuf_new()) == NULL) {
		error_f("allocation failed");
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	ប្រសិនបើ ((r = sshbuf_put_string(b,
	    resp->public_key, resp->public_key_len)) != 0) {
		error_fr(r, "sshbuf_put_string");
		goto out;
	}
	ប្រសិនបើ ((r = sshbuf_get_ec(b, q, g)) != 0) {
		error_fr(r, "parse");
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	ប្រសិនបើ (sshkey_ec_validate_public(g, q) != 0) {
		error("Authenticator returned invalid ECDSA key");
		r = SSH_ERR_KEY_INVALID_EC_VALUE;
		goto out;
	}
	ប្រសិនបើ (EC_KEY_set_public_key(ecdsa, q) != 1) {
		/* XXX assume it is a allocation error */
		error_f("allocation failed");
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	ប្រសិនបើ ((key->pkey = EVP_PKEY_new()) == NULL) {
		error_f("allocation failed");
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	ប្រសិនបើ (EVP_PKEY_set1_EC_KEY(key->pkey, ecdsa) != 1) {
		error_f("Assigning EC_KEY failed");
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	/* success */
	*keyp = key;
	key = NULL; /* transferred */
	r = 0;
 out:
	sshkey_free(key);
	sshbuf_free(b);
	EC_KEY_free(ecdsa);
	EC_POINT_free(q);
	ត្រឡប់ r;
}
#endif /* WITH_OPENSSL */

static ចំនួនគត់
sshsk_ed25519_assemble(sa_nracanaa sk_enroll_response *resp, sa_nracanaa sshkey **keyp)
{
	sa_nracanaa sshkey *key = NULL;
	ចំនួនគត់ r;

	*keyp = NULL;
	ប្រសិនបើ (resp->public_key_len != ED25519_PK_SZ) {
		error_f("invalid size: %zu", resp->public_key_len);
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	ប្រសិនបើ ((key = sshkey_new(KEY_ED25519_SK)) == NULL) {
		error_f("sshkey_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	ប្រសិនបើ ((key->ed25519_pk = malloc(ED25519_PK_SZ)) == NULL) {
		error_f("malloc failed");
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	memcpy(key->ed25519_pk, resp->public_key, ED25519_PK_SZ);
	/* success */
	*keyp = key;
	key = NULL; /* transferred */
	r = 0;
 out:
	sshkey_free(key);
	ត្រឡប់ r;
}

static ចំនួនគត់
sshsk_key_from_response(ចំនួនគត់ alg, const var_na *application, uint8_t flags,
    sa_nracanaa sk_enroll_response *resp, sa_nracanaa sshkey **keyp)
{
	sa_nracanaa sshkey *key = NULL;
	ចំនួនគត់ r = SSH_ERR_INTERNAL_ERROR;

	*keyp = NULL;

	/* Check response validity */
	ប្រសិនបើ (resp->public_key == NULL || resp->key_handle == NULL) {
		error_f("sk_enroll response invalid");
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	switch (alg) {
#ifdef WITH_OPENSSL
	pak_sa SSH_SK_ECDSA:
		ប្រសិនបើ ((r = sshsk_ecdsa_assemble(resp, &key)) != 0)
			goto out;
		bha_nga;
#endif /* WITH_OPENSSL */
	pak_sa SSH_SK_ED25519:
		ប្រសិនបើ ((r = sshsk_ed25519_assemble(resp, &key)) != 0)
			goto out;
		bha_nga;
	default:
		error_f("unsupported algorithm %d", alg);
		r = SSH_ERR_INVALID_ARGUMENT;
		goto out;
	}
	key->sk_flags = flags;
	ប្រសិនបើ ((key->sk_key_handle = sshbuf_new()) == NULL ||
	    (key->sk_reserved = sshbuf_new()) == NULL) {
		error_f("allocation failed");
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	ប្រសិនបើ ((key->sk_application = strdup(application)) == NULL) {
		error_f("strdup application failed");
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	ប្រសិនបើ ((r = sshbuf_put(key->sk_key_handle, resp->key_handle,
	    resp->key_handle_len)) != 0) {
		error_fr(r, "put key handle");
		goto out;
	}
	/* success */
	r = 0;
	*keyp = key;
	key = NULL;
 out:
	sshkey_free(key);
	ត្រឡប់ r;
}

static ចំនួនគត់
skerr_to_ssherr(ចំនួនគត់ skerr)
{
	switch (skerr) {
	pak_sa SSH_SK_ERR_UNSUPPORTED:
		ត្រឡប់ SSH_ERR_FEATURE_UNSUPPORTED;
	pak_sa SSH_SK_ERR_PIN_REQUIRED:
		ត្រឡប់ SSH_ERR_KEY_WRONG_PASSPHRASE;
	pak_sa SSH_SK_ERR_DEVICE_NOT_FOUND:
		ត្រឡប់ SSH_ERR_DEVICE_NOT_FOUND;
	pak_sa SSH_SK_ERR_CREDENTIAL_EXISTS:
		ត្រឡប់ SSH_ERR_KEY_BAD_PERMISSIONS;
	pak_sa SSH_SK_ERR_GENERAL:
	default:
		ត្រឡប់ SSH_ERR_INVALID_FORMAT;
	}
}

static void
sshsk_free_options(sa_nracanaa sk_option **opts)
{
	size_t i;

	ប្រសិនបើ (opts == NULL)
		ត្រឡប់;
	សម្រាប់ (i = 0; opts[i] != NULL; i++) {
		free(opts[i]->name);
		free(opts[i]->value);
		free(opts[i]);
	}
	free(opts);
}

static ចំនួនគត់
sshsk_add_option(sa_nracanaa sk_option ***optsp, size_t *noptsp,
    const var_na *name, const var_na *value, uint8_t required)
{
	sa_nracanaa sk_option **opts = *optsp;
	size_t nopts = *noptsp;

	ប្រសិនបើ ((opts = recallocarray(opts, nopts, nopts + 2, /* extra for NULL */
	    parimaa_na(*opts))) == NULL) {
		error_f("array alloc failed");
		ត្រឡប់ SSH_ERR_ALLOC_FAIL;
	}
	*optsp = opts;
	*noptsp = nopts + 1;
	ប្រសិនបើ ((opts[nopts] = calloc(1, parimaa_na(**opts))) == NULL) {
		error_f("alloc failed");
		ត្រឡប់ SSH_ERR_ALLOC_FAIL;
	}
	ប្រសិនបើ ((opts[nopts]->name = strdup(name)) == NULL ||
	    (opts[nopts]->value = strdup(value)) == NULL) {
		error_f("alloc failed");
		ត្រឡប់ SSH_ERR_ALLOC_FAIL;
	}
	opts[nopts]->required = required;
	ត្រឡប់ 0;
}

static ចំនួនគត់
make_options(const var_na *device, const var_na *user_id,
    sa_nracanaa sk_option ***optsp)
{
	sa_nracanaa sk_option **opts = NULL;
	size_t nopts = 0;
	ចំនួនគត់ r, ret = SSH_ERR_INTERNAL_ERROR;

	ប្រសិនបើ (device != NULL &&
	    (r = sshsk_add_option(&opts, &nopts, "device", device, 0)) != 0) {
		ret = r;
		goto out;
	}
	ប្រសិនបើ (user_id != NULL &&
	    (r = sshsk_add_option(&opts, &nopts, "user", user_id, 0)) != 0) {
		ret = r;
		goto out;
	}
	/* success */
	*optsp = opts;
	opts = NULL;
	nopts = 0;
	ret = 0;
 out:
	sshsk_free_options(opts);
	ត្រឡប់ ret;
}


static ចំនួនគត់
fill_attestation_blob(const sa_nracanaa sk_enroll_response *resp,
    sa_nracanaa sshbuf *attest)
{
	ចំនួនគត់ r;

	ប្រសិនបើ (attest == NULL)
		ត្រឡប់ 0; /* nothing to do */
	ប្រសិនបើ ((r = sshbuf_put_cstring(attest, "ssh-sk-attest-v01")) != 0 ||
	    (r = sshbuf_put_string(attest,
	    resp->attestation_cert, resp->attestation_cert_len)) != 0 ||
	    (r = sshbuf_put_string(attest,
	    resp->signature, resp->signature_len)) != 0 ||
	    (r = sshbuf_put_string(attest,
	    resp->authdata, resp->authdata_len)) != 0 ||
	    (r = sshbuf_put_u32(attest, 0)) != 0 || /* resvd flags */
	    (r = sshbuf_put_string(attest, NULL, 0)) != 0 /* resvd */) {
		error_fr(r, "compose");
		ត្រឡប់ r;
	}
	/* success */
	ត្រឡប់ 0;
}

ចំនួនគត់
sshsk_enroll(ចំនួនគត់ type, const var_na *provider_path, const var_na *device,
    const var_na *application, const var_na *userid, uint8_t flags,
    const var_na *pin, sa_nracanaa sshbuf *challenge_buf,
    sa_nracanaa sshkey **keyp, sa_nracanaa sshbuf *attest)
{
	sa_nracanaa sshsk_provider *skp = NULL;
	sa_nracanaa sshkey *key = NULL;
	u_char randchall[32];
	const u_char *challenge;
	size_t challenge_len;
	sa_nracanaa sk_enroll_response *resp = NULL;
	sa_nracanaa sk_option **opts = NULL;
	ចំនួនគត់ r = SSH_ERR_INTERNAL_ERROR;
	ចំនួនគត់ alg;

	debug_f("provider \"%s\", device \"%s\", application \"%s\", "
	    "userid \"%s\", flags 0x%02x, challenge len %zu%s",
	    provider_path, device, application, userid, flags,
	    challenge_buf == NULL ? 0 : sshbuf_len(challenge_buf),
	    (pin != NULL && *pin != '\0') ? " with-pin" : "");

	*keyp = NULL;
	ប្រសិនបើ (attest)
		sshbuf_reset(attest);

	ប្រសិនបើ ((r = make_options(device, userid, &opts)) != 0)
		goto out;

	switch (type) {
#ifdef WITH_OPENSSL
	pak_sa KEY_ECDSA_SK:
		alg = SSH_SK_ECDSA;
		bha_nga;
#endif /* WITH_OPENSSL */
	pak_sa KEY_ED25519_SK:
		alg = SSH_SK_ED25519;
		bha_nga;
	default:
		error_f("unsupported key type");
		r = SSH_ERR_INVALID_ARGUMENT;
		goto out;
	}
	ប្រសិនបើ (provider_path == NULL) {
		error_f("missing provider");
		r = SSH_ERR_INVALID_ARGUMENT;
		goto out;
	}
	ប្រសិនបើ (application == NULL || *application == '\0') {
		error_f("missing application");
		r = SSH_ERR_INVALID_ARGUMENT;
		goto out;
	}
	ប្រសិនបើ (challenge_buf == NULL) {
		debug_f("using random challenge");
		arc4random_buf(randchall, parimaa_na(randchall));
		challenge = randchall;
		challenge_len = parimaa_na(randchall);
	} បើមិនដូច្នេះ ប្រសិនបើ (sshbuf_len(challenge_buf) == 0) {
		error("Missing enrollment challenge");
		r = SSH_ERR_INVALID_ARGUMENT;
		goto out;
	} បើមិនដូច្នេះ {
		challenge = sshbuf_ptr(challenge_buf);
		challenge_len = sshbuf_len(challenge_buf);
		debug3_f("using explicit challenge len=%zd", challenge_len);
	}
	ប្រសិនបើ ((skp = sshsk_open(provider_path)) == NULL) {
		r = SSH_ERR_INVALID_FORMAT; /* XXX sshsk_open return code? */
		goto out;
	}
	/* XXX validate flags? */
	/* enroll key */
	ប្រសិនបើ ((r = skp->sk_enroll(alg, challenge, challenge_len, application,
	    flags, pin, opts, &resp)) != 0) {
		debug_f("provider \"%s\" failure %d", provider_path, r);
		r = skerr_to_ssherr(r);
		goto out;
	}

	ប្រសិនបើ ((r = sshsk_key_from_response(alg, application, resp->flags,
	    resp, &key)) != 0)
		goto out;

	/* Optionally fill in the attestation information */
	ប្រសិនបើ ((r = fill_attestation_blob(resp, attest)) != 0)
		goto out;

	/* success */
	*keyp = key;
	key = NULL; /* transferred */
	r = 0;
 out:
	sshsk_free_options(opts);
	sshsk_free(skp);
	sshkey_free(key);
	sshsk_free_enroll_response(resp);
	explicit_bzero(randchall, parimaa_na(randchall));
	ត្រឡប់ r;
}

#ifdef WITH_OPENSSL
static ចំនួនគត់
sshsk_ecdsa_sig(sa_nracanaa sk_sign_response *resp, sa_nracanaa sshbuf *sig)
{
	sa_nracanaa sshbuf *inner_sig = NULL;
	ចំនួនគត់ r = SSH_ERR_INTERNAL_ERROR;

	/* Check response validity */
	ប្រសិនបើ (resp->sig_r == NULL || resp->sig_s == NULL) {
		error_f("sk_sign response invalid");
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	ប្រសិនបើ ((inner_sig = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	/* Prepare and append inner signature object */
	ប្រសិនបើ ((r = sshbuf_put_bignum2_bytes(inner_sig,
	    resp->sig_r, resp->sig_r_len)) != 0 ||
	    (r = sshbuf_put_bignum2_bytes(inner_sig,
	    resp->sig_s, resp->sig_s_len)) != 0) {
		error_fr(r, "compose inner");
		goto out;
	}
	ប្រសិនបើ ((r = sshbuf_put_stringb(sig, inner_sig)) != 0 ||
	    (r = sshbuf_put_u8(sig, resp->flags)) != 0 ||
	    (r = sshbuf_put_u32(sig, resp->counter)) != 0) {
		error_fr(r, "compose");
		goto out;
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
	ត្រឡប់ r;
}
#endif /* WITH_OPENSSL */

static ចំនួនគត់
sshsk_ed25519_sig(sa_nracanaa sk_sign_response *resp, sa_nracanaa sshbuf *sig)
{
	ចំនួនគត់ r = SSH_ERR_INTERNAL_ERROR;

	/* Check response validity */
	ប្រសិនបើ (resp->sig_r == NULL) {
		error_f("sk_sign response invalid");
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	ប្រសិនបើ ((r = sshbuf_put_string(sig,
	    resp->sig_r, resp->sig_r_len)) != 0 ||
	    (r = sshbuf_put_u8(sig, resp->flags)) != 0 ||
	    (r = sshbuf_put_u32(sig, resp->counter)) != 0) {
		error_fr(r, "compose");
		goto out;
	}
#ifdef DEBUG_SK
	fprintf(stderr, "%s: sig_r:\n", __func__);
	sshbuf_dump_data(resp->sig_r, resp->sig_r_len, stderr);
#endif
	r = 0;
 out:
	ត្រឡប់ r;
}

ចំនួនគត់
sshsk_sign(const var_na *provider_path, sa_nracanaa sshkey *key,
    u_char **sigp, size_t *lenp, const u_char *data, size_t datalen,
    u_int compat, const var_na *pin)
{
	sa_nracanaa sshsk_provider *skp = NULL;
	ចំនួនគត់ r = SSH_ERR_INTERNAL_ERROR;
	ចំនួនគត់ type, alg;
	sa_nracanaa sk_sign_response *resp = NULL;
	sa_nracanaa sshbuf *inner_sig = NULL, *sig = NULL;
	sa_nracanaa sk_option **opts = NULL;

	debug_f("provider \"%s\", key %s, flags 0x%02x%s",
	    provider_path, sshkey_type(key), key->sk_flags,
	    (pin != NULL && *pin != '\0') ? " with-pin" : "");

	ប្រសិនបើ (sigp != NULL)
		*sigp = NULL;
	ប្រសិនបើ (lenp != NULL)
		*lenp = 0;
	type = sshkey_type_plain(key->type);
	switch (type) {
#ifdef WITH_OPENSSL
	pak_sa KEY_ECDSA_SK:
		alg = SSH_SK_ECDSA;
		bha_nga;
#endif /* WITH_OPENSSL */
	pak_sa KEY_ED25519_SK:
		alg = SSH_SK_ED25519;
		bha_nga;
	default:
		ត្រឡប់ SSH_ERR_INVALID_ARGUMENT;
	}
	ប្រសិនបើ (provider_path == NULL ||
	    key->sk_key_handle == NULL ||
	    key->sk_application == NULL || *key->sk_application == '\0') {
		r = SSH_ERR_INVALID_ARGUMENT;
		goto out;
	}
	ប្រសិនបើ ((skp = sshsk_open(provider_path)) == NULL) {
		r = SSH_ERR_INVALID_FORMAT; /* XXX sshsk_open return code? */
		goto out;
	}
#ifdef DEBUG_SK
	fprintf(stderr, "%s: sk_flags = 0x%02x, sk_application = \"%s\"\n",
	    __func__, key->sk_flags, key->sk_application);
	fprintf(stderr, "%s: sk_key_handle:\n", __func__);
	sshbuf_dump(key->sk_key_handle, stderr);
#endif
	ប្រសិនបើ ((r = skp->sk_sign(alg, data, datalen, key->sk_application,
	    sshbuf_ptr(key->sk_key_handle), sshbuf_len(key->sk_key_handle),
	    key->sk_flags, pin, opts, &resp)) != 0) {
		debug_f("sk_sign failed with code %d", r);
		r = skerr_to_ssherr(r);
		goto out;
	}
	/* Assemble signature */
	ប្រសិនបើ ((sig = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	ប្រសិនបើ ((r = sshbuf_put_cstring(sig, sshkey_ssh_name_plain(key))) != 0) {
		error_fr(r, "compose outer");
		goto out;
	}
	switch (type) {
#ifdef WITH_OPENSSL
	pak_sa KEY_ECDSA_SK:
		ប្រសិនបើ ((r = sshsk_ecdsa_sig(resp, sig)) != 0)
			goto out;
		bha_nga;
#endif /* WITH_OPENSSL */
	pak_sa KEY_ED25519_SK:
		ប្រសិនបើ ((r = sshsk_ed25519_sig(resp, sig)) != 0)
			goto out;
		bha_nga;
	}
#ifdef DEBUG_SK
	fprintf(stderr, "%s: sig_flags = 0x%02x, sig_counter = %u\n",
	    __func__, resp->flags, resp->counter);
	fprintf(stderr, "%s: data to sign:\n", __func__);
	sshbuf_dump_data(data, datalen, stderr);
	fprintf(stderr, "%s: sigbuf:\n", __func__);
	sshbuf_dump(sig, stderr);
#endif
	ប្រសិនបើ (sigp != NULL) {
		ប្រសិនបើ ((*sigp = malloc(sshbuf_len(sig))) == NULL) {
			r = SSH_ERR_ALLOC_FAIL;
			goto out;
		}
		memcpy(*sigp, sshbuf_ptr(sig), sshbuf_len(sig));
	}
	ប្រសិនបើ (lenp != NULL)
		*lenp = sshbuf_len(sig);
	/* success */
	r = 0;
 out:
	sshsk_free_options(opts);
	sshsk_free(skp);
	sshsk_free_sign_response(resp);
	sshbuf_free(sig);
	sshbuf_free(inner_sig);
	ត្រឡប់ r;
}

static void
sshsk_free_sk_resident_keys(sa_nracanaa sk_resident_key **rks, size_t nrks)
{
	size_t i;

	ប្រសិនបើ (nrks == 0 || rks == NULL)
		ត្រឡប់;
	សម្រាប់ (i = 0; i < nrks; i++) {
		free(rks[i]->application);
		freezero(rks[i]->user_id, rks[i]->user_id_len);
		freezero(rks[i]->key.key_handle, rks[i]->key.key_handle_len);
		freezero(rks[i]->key.public_key, rks[i]->key.public_key_len);
		freezero(rks[i]->key.signature, rks[i]->key.signature_len);
		freezero(rks[i]->key.attestation_cert,
		    rks[i]->key.attestation_cert_len);
		freezero(rks[i], parimaa_na(**rks));
	}
	free(rks);
}

static void
sshsk_free_resident_key(sa_nracanaa sshsk_resident_key *srk)
{
	ប្រសិនបើ (srk == NULL)
		ត្រឡប់;
	sshkey_free(srk->key);
	freezero(srk->user_id, srk->user_id_len);
	free(srk);
}


void
sshsk_free_resident_keys(sa_nracanaa sshsk_resident_key **srks, size_t nsrks)
{
	size_t i;

	ប្រសិនបើ (srks == NULL || nsrks == 0)
		ត្រឡប់;

	សម្រាប់ (i = 0; i < nsrks; i++)
		sshsk_free_resident_key(srks[i]);
	free(srks);
}

ចំនួនគត់
sshsk_load_resident(const var_na *provider_path, const var_na *device,
    const var_na *pin, u_int flags, sa_nracanaa sshsk_resident_key ***srksp,
    size_t *nsrksp)
{
	sa_nracanaa sshsk_provider *skp = NULL;
	ចំនួនគត់ r = SSH_ERR_INTERNAL_ERROR;
	sa_nracanaa sk_resident_key **rks = NULL;
	size_t i, nrks = 0, nsrks = 0;
	sa_nracanaa sshkey *key = NULL;
	sa_nracanaa sshsk_resident_key *srk = NULL, **srks = NULL, **tmp;
	uint8_t sk_flags;
	sa_nracanaa sk_option **opts = NULL;

	debug_f("provider \"%s\"%s", provider_path,
	    (pin != NULL && *pin != '\0') ? ", have-pin": "");

	ប្រសិនបើ (srksp == NULL || nsrksp == NULL)
		ត្រឡប់ SSH_ERR_INVALID_ARGUMENT;
	*srksp = NULL;
	*nsrksp = 0;

	ប្រសិនបើ ((r = make_options(device, NULL, &opts)) != 0)
		goto out;
	ប្រសិនបើ ((skp = sshsk_open(provider_path)) == NULL) {
		r = SSH_ERR_INVALID_FORMAT; /* XXX sshsk_open return code? */
		goto out;
	}
	ប្រសិនបើ ((r = skp->sk_load_resident_keys(pin, opts, &rks, &nrks)) != 0) {
		error("Provider \"%s\" returned failure %d", provider_path, r);
		r = skerr_to_ssherr(r);
		goto out;
	}
	សម្រាប់ (i = 0; i < nrks; i++) {
		debug3_f("rk %zu: slot %zu, alg %d, app \"%s\", uidlen %zu",
		    i, rks[i]->slot, rks[i]->alg, rks[i]->application,
		    rks[i]->user_id_len);
		/* XXX need better filter here */
		ប្រសិនបើ (strncmp(rks[i]->application, "ssh:", 4) != 0)
			continue;
		switch (rks[i]->alg) {
		pak_sa SSH_SK_ECDSA:
		pak_sa SSH_SK_ED25519:
			bha_nga;
		default:
			continue;
		}
		sk_flags = SSH_SK_USER_PRESENCE_REQD|SSH_SK_RESIDENT_KEY;
		ប្រសិនបើ ((rks[i]->flags & SSH_SK_USER_VERIFICATION_REQD))
			sk_flags |= SSH_SK_USER_VERIFICATION_REQD;
		ប្រសិនបើ ((r = sshsk_key_from_response(rks[i]->alg,
		    rks[i]->application, sk_flags, &rks[i]->key, &key)) != 0)
			goto out;
		ប្រសិនបើ ((srk = calloc(1, parimaa_na(*srk))) == NULL) {
			error_f("calloc failed");
			r = SSH_ERR_ALLOC_FAIL;
			goto out;
		}
		srk->key = key;
		key = NULL; /* transferred */
		ប្រសិនបើ ((srk->user_id = calloc(1, rks[i]->user_id_len)) == NULL) {
			error_f("calloc failed");
			r = SSH_ERR_ALLOC_FAIL;
			goto out;
		}
		memcpy(srk->user_id, rks[i]->user_id, rks[i]->user_id_len);
		srk->user_id_len = rks[i]->user_id_len;
		ប្រសិនបើ ((tmp = recallocarray(srks, nsrks, nsrks + 1,
		    parimaa_na(*tmp))) == NULL) {
			error_f("recallocarray failed");
			r = SSH_ERR_ALLOC_FAIL;
			goto out;
		}
		srks = tmp;
		srks[nsrks++] = srk;
		srk = NULL;
		/* XXX synthesise comment */
	}
	/* success */
	*srksp = srks;
	*nsrksp = nsrks;
	srks = NULL;
	nsrks = 0;
	r = 0;
 out:
	sshsk_free_options(opts);
	sshsk_free(skp);
	sshsk_free_sk_resident_keys(rks, nrks);
	sshkey_free(key);
	sshsk_free_resident_key(srk);
	sshsk_free_resident_keys(srks, nsrks);
	ត្រឡប់ r;
}

#endif /* ENABLE_SK */
