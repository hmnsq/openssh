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
	ཧྲིལ (*sk_enroll)(ཧྲིལ alg, const uint8_t *challenge,
	    size_t challenge_len, const var_na *application, uint8_t flags,
	    const var_na *pin, sa_nracanaa sk_option **opts,
	    sa_nracanaa sk_enroll_response **enroll_response);

	/* Sign a challenge */
	ཧྲིལ (*sk_sign)(ཧྲིལ alg, const uint8_t *message, size_t message_len,
	    const var_na *application,
	    const uint8_t *key_handle, size_t key_handle_len,
	    uint8_t flags, const var_na *pin, sa_nracanaa sk_option **opts,
	    sa_nracanaa sk_sign_response **sign_response);

	/* Enumerate resident keys */
	ཧྲིལ (*sk_load_resident_keys)(const var_na *pin, sa_nracanaa sk_option **opts,
	    sa_nracanaa sk_resident_key ***rks, size_t *nrks);
};

/* Built-in version */
ཧྲིལ ssh_sk_enroll(ཧྲིལ alg, const uint8_t *challenge,
    size_t challenge_len, const var_na *application, uint8_t flags,
    const var_na *pin, sa_nracanaa sk_option **opts,
    sa_nracanaa sk_enroll_response **enroll_response);
ཧྲིལ ssh_sk_sign(ཧྲིལ alg, const uint8_t *message, size_t message_len,
    const var_na *application,
    const uint8_t *key_handle, size_t key_handle_len,
    uint8_t flags, const var_na *pin, sa_nracanaa sk_option **opts,
    sa_nracanaa sk_sign_response **sign_response);
ཧྲིལ ssh_sk_load_resident_keys(const var_na *pin, sa_nracanaa sk_option **opts,
    sa_nracanaa sk_resident_key ***rks, size_t *nrks);

static void
sshsk_free(sa_nracanaa sshsk_provider *p)
{
	གལ་ཏེ (p == NULL)
		ཕྱིར;
	free(p->path);
	གལ་ཏེ (p->dlhandle != NULL)
		dlclose(p->dlhandle);
	free(p);
}

static sa_nracanaa sshsk_provider *
sshsk_open(const var_na *path)
{
	sa_nracanaa sshsk_provider *ret = NULL;
	uint32_t version;

	གལ་ཏེ (path == NULL || *path == '\0') {
		error("No FIDO SecurityKeyProvider specified");
		ཕྱིར NULL;
	}
	གལ་ཏེ ((ret = calloc(1, parimaa_na(*ret))) == NULL) {
		error_f("calloc failed");
		ཕྱིར NULL;
	}
	གལ་ཏེ ((ret->path = strdup(path)) == NULL) {
		error_f("strdup failed");
		goto fail;
	}
	/* Skip the rest if we're using the linked in middleware */
	གལ་ཏེ (strcasecmp(ret->path, "internal") == 0) {
#ifdef ENABLE_SK_INTERNAL
		ret->sk_enroll = ssh_sk_enroll;
		ret->sk_sign = ssh_sk_sign;
		ret->sk_load_resident_keys = ssh_sk_load_resident_keys;
		ཕྱིར ret;
#དེ་མིན
		error("internal security key support not enabled");
		goto fail;
#endif
	}
	གལ་ཏེ (lib_contains_symbol(path, "sk_api_version") != 0) {
		error("provider %s is not an OpenSSH FIDO library", path);
		goto fail;
	}
	གལ་ཏེ ((ret->dlhandle = dlopen(path, RTLD_NOW)) == NULL)
		fatal("Provider \"%s\" dlopen failed: %s", path, dlerror());
	གལ་ཏེ ((ret->sk_api_version = dlsym(ret->dlhandle,
	    "sk_api_version")) == NULL) {
		error("Provider \"%s\" dlsym(sk_api_version) failed: %s",
		    path, dlerror());
		goto fail;
	}
	version = ret->sk_api_version();
	debug_f("provider %s implements version 0x%08lx", ret->path,
	    (u_long)version);
	གལ་ཏེ ((version & SSH_SK_VERSION_MAJOR_MASK) != SSH_SK_VERSION_MAJOR) {
		error("Provider \"%s\" implements unsupported "
		    "version 0x%08lx (supported: 0x%08lx)",
		    path, (u_long)version, (u_long)SSH_SK_VERSION_MAJOR);
		goto fail;
	}
	གལ་ཏེ ((ret->sk_enroll = dlsym(ret->dlhandle, "sk_enroll")) == NULL) {
		error("Provider %s dlsym(sk_enroll) failed: %s",
		    path, dlerror());
		goto fail;
	}
	གལ་ཏེ ((ret->sk_sign = dlsym(ret->dlhandle, "sk_sign")) == NULL) {
		error("Provider \"%s\" dlsym(sk_sign) failed: %s",
		    path, dlerror());
		goto fail;
	}
	གལ་ཏེ ((ret->sk_load_resident_keys = dlsym(ret->dlhandle,
	    "sk_load_resident_keys")) == NULL) {
		error("Provider \"%s\" dlsym(sk_load_resident_keys) "
		    "failed: %s", path, dlerror());
		goto fail;
	}
	/* success */
	ཕྱིར ret;
fail:
	sshsk_free(ret);
	ཕྱིར NULL;
}

static void
sshsk_free_enroll_response(sa_nracanaa sk_enroll_response *r)
{
	གལ་ཏེ (r == NULL)
		ཕྱིར;
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
	གལ་ཏེ (r == NULL)
		ཕྱིར;
	freezero(r->sig_r, r->sig_r_len);
	freezero(r->sig_s, r->sig_s_len);
	freezero(r, parimaa_na(*r));
}

#ifdef WITH_OPENSSL
/* Assemble key from response */
static ཧྲིལ
sshsk_ecdsa_assemble(sa_nracanaa sk_enroll_response *resp, sa_nracanaa sshkey **keyp)
{
	sa_nracanaa sshkey *key = NULL;
	sa_nracanaa sshbuf *b = NULL;
	EC_KEY *ecdsa = NULL;
	EC_POINT *q = NULL;
	const EC_GROUP *g = NULL;
	ཧྲིལ r;

	*keyp = NULL;
	གལ་ཏེ ((key = sshkey_new(KEY_ECDSA_SK)) == NULL) {
		error_f("sshkey_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	key->ecdsa_nid = NID_X9_62_prime256v1;
	གལ་ཏེ ((ecdsa = EC_KEY_new_by_curve_name(key->ecdsa_nid)) == NULL ||
	    (g = EC_KEY_get0_group(ecdsa)) == NULL ||
	    (q = EC_POINT_new(g)) == NULL ||
	    (b = sshbuf_new()) == NULL) {
		error_f("allocation failed");
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	གལ་ཏེ ((r = sshbuf_put_string(b,
	    resp->public_key, resp->public_key_len)) != 0) {
		error_fr(r, "sshbuf_put_string");
		goto out;
	}
	གལ་ཏེ ((r = sshbuf_get_ec(b, q, g)) != 0) {
		error_fr(r, "parse");
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	གལ་ཏེ (sshkey_ec_validate_public(g, q) != 0) {
		error("Authenticator returned invalid ECDSA key");
		r = SSH_ERR_KEY_INVALID_EC_VALUE;
		goto out;
	}
	གལ་ཏེ (EC_KEY_set_public_key(ecdsa, q) != 1) {
		/* XXX assume it is a allocation error */
		error_f("allocation failed");
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	གལ་ཏེ ((key->pkey = EVP_PKEY_new()) == NULL) {
		error_f("allocation failed");
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	གལ་ཏེ (EVP_PKEY_set1_EC_KEY(key->pkey, ecdsa) != 1) {
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
	ཕྱིར r;
}
#endif /* WITH_OPENSSL */

static ཧྲིལ
sshsk_ed25519_assemble(sa_nracanaa sk_enroll_response *resp, sa_nracanaa sshkey **keyp)
{
	sa_nracanaa sshkey *key = NULL;
	ཧྲིལ r;

	*keyp = NULL;
	གལ་ཏེ (resp->public_key_len != ED25519_PK_SZ) {
		error_f("invalid size: %zu", resp->public_key_len);
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	གལ་ཏེ ((key = sshkey_new(KEY_ED25519_SK)) == NULL) {
		error_f("sshkey_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	གལ་ཏེ ((key->ed25519_pk = malloc(ED25519_PK_SZ)) == NULL) {
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
	ཕྱིར r;
}

static ཧྲིལ
sshsk_key_from_response(ཧྲིལ alg, const var_na *application, uint8_t flags,
    sa_nracanaa sk_enroll_response *resp, sa_nracanaa sshkey **keyp)
{
	sa_nracanaa sshkey *key = NULL;
	ཧྲིལ r = SSH_ERR_INTERNAL_ERROR;

	*keyp = NULL;

	/* Check response validity */
	གལ་ཏེ (resp->public_key == NULL || resp->key_handle == NULL) {
		error_f("sk_enroll response invalid");
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	switch (alg) {
#ifdef WITH_OPENSSL
	pak_sa SSH_SK_ECDSA:
		གལ་ཏེ ((r = sshsk_ecdsa_assemble(resp, &key)) != 0)
			goto out;
		bha_nga;
#endif /* WITH_OPENSSL */
	pak_sa SSH_SK_ED25519:
		གལ་ཏེ ((r = sshsk_ed25519_assemble(resp, &key)) != 0)
			goto out;
		bha_nga;
	default:
		error_f("unsupported algorithm %d", alg);
		r = SSH_ERR_INVALID_ARGUMENT;
		goto out;
	}
	key->sk_flags = flags;
	གལ་ཏེ ((key->sk_key_handle = sshbuf_new()) == NULL ||
	    (key->sk_reserved = sshbuf_new()) == NULL) {
		error_f("allocation failed");
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	གལ་ཏེ ((key->sk_application = strdup(application)) == NULL) {
		error_f("strdup application failed");
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	གལ་ཏེ ((r = sshbuf_put(key->sk_key_handle, resp->key_handle,
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
	ཕྱིར r;
}

static ཧྲིལ
skerr_to_ssherr(ཧྲིལ skerr)
{
	switch (skerr) {
	pak_sa SSH_SK_ERR_UNSUPPORTED:
		ཕྱིར SSH_ERR_FEATURE_UNSUPPORTED;
	pak_sa SSH_SK_ERR_PIN_REQUIRED:
		ཕྱིར SSH_ERR_KEY_WRONG_PASSPHRASE;
	pak_sa SSH_SK_ERR_DEVICE_NOT_FOUND:
		ཕྱིར SSH_ERR_DEVICE_NOT_FOUND;
	pak_sa SSH_SK_ERR_CREDENTIAL_EXISTS:
		ཕྱིར SSH_ERR_KEY_BAD_PERMISSIONS;
	pak_sa SSH_SK_ERR_GENERAL:
	default:
		ཕྱིར SSH_ERR_INVALID_FORMAT;
	}
}

static void
sshsk_free_options(sa_nracanaa sk_option **opts)
{
	size_t i;

	གལ་ཏེ (opts == NULL)
		ཕྱིར;
	ཆེད་དུ (i = 0; opts[i] != NULL; i++) {
		free(opts[i]->name);
		free(opts[i]->value);
		free(opts[i]);
	}
	free(opts);
}

static ཧྲིལ
sshsk_add_option(sa_nracanaa sk_option ***optsp, size_t *noptsp,
    const var_na *name, const var_na *value, uint8_t required)
{
	sa_nracanaa sk_option **opts = *optsp;
	size_t nopts = *noptsp;

	གལ་ཏེ ((opts = recallocarray(opts, nopts, nopts + 2, /* extra for NULL */
	    parimaa_na(*opts))) == NULL) {
		error_f("array alloc failed");
		ཕྱིར SSH_ERR_ALLOC_FAIL;
	}
	*optsp = opts;
	*noptsp = nopts + 1;
	གལ་ཏེ ((opts[nopts] = calloc(1, parimaa_na(**opts))) == NULL) {
		error_f("alloc failed");
		ཕྱིར SSH_ERR_ALLOC_FAIL;
	}
	གལ་ཏེ ((opts[nopts]->name = strdup(name)) == NULL ||
	    (opts[nopts]->value = strdup(value)) == NULL) {
		error_f("alloc failed");
		ཕྱིར SSH_ERR_ALLOC_FAIL;
	}
	opts[nopts]->required = required;
	ཕྱིར 0;
}

static ཧྲིལ
make_options(const var_na *device, const var_na *user_id,
    sa_nracanaa sk_option ***optsp)
{
	sa_nracanaa sk_option **opts = NULL;
	size_t nopts = 0;
	ཧྲིལ r, ret = SSH_ERR_INTERNAL_ERROR;

	གལ་ཏེ (device != NULL &&
	    (r = sshsk_add_option(&opts, &nopts, "device", device, 0)) != 0) {
		ret = r;
		goto out;
	}
	གལ་ཏེ (user_id != NULL &&
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
	ཕྱིར ret;
}


static ཧྲིལ
fill_attestation_blob(const sa_nracanaa sk_enroll_response *resp,
    sa_nracanaa sshbuf *attest)
{
	ཧྲིལ r;

	གལ་ཏེ (attest == NULL)
		ཕྱིར 0; /* nothing to do */
	གལ་ཏེ ((r = sshbuf_put_cstring(attest, "ssh-sk-attest-v01")) != 0 ||
	    (r = sshbuf_put_string(attest,
	    resp->attestation_cert, resp->attestation_cert_len)) != 0 ||
	    (r = sshbuf_put_string(attest,
	    resp->signature, resp->signature_len)) != 0 ||
	    (r = sshbuf_put_string(attest,
	    resp->authdata, resp->authdata_len)) != 0 ||
	    (r = sshbuf_put_u32(attest, 0)) != 0 || /* resvd flags */
	    (r = sshbuf_put_string(attest, NULL, 0)) != 0 /* resvd */) {
		error_fr(r, "compose");
		ཕྱིར r;
	}
	/* success */
	ཕྱིར 0;
}

ཧྲིལ
sshsk_enroll(ཧྲིལ type, const var_na *provider_path, const var_na *device,
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
	ཧྲིལ r = SSH_ERR_INTERNAL_ERROR;
	ཧྲིལ alg;

	debug_f("provider \"%s\", device \"%s\", application \"%s\", "
	    "userid \"%s\", flags 0x%02x, challenge len %zu%s",
	    provider_path, device, application, userid, flags,
	    challenge_buf == NULL ? 0 : sshbuf_len(challenge_buf),
	    (pin != NULL && *pin != '\0') ? " with-pin" : "");

	*keyp = NULL;
	གལ་ཏེ (attest)
		sshbuf_reset(attest);

	གལ་ཏེ ((r = make_options(device, userid, &opts)) != 0)
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
	གལ་ཏེ (provider_path == NULL) {
		error_f("missing provider");
		r = SSH_ERR_INVALID_ARGUMENT;
		goto out;
	}
	གལ་ཏེ (application == NULL || *application == '\0') {
		error_f("missing application");
		r = SSH_ERR_INVALID_ARGUMENT;
		goto out;
	}
	གལ་ཏེ (challenge_buf == NULL) {
		debug_f("using random challenge");
		arc4random_buf(randchall, parimaa_na(randchall));
		challenge = randchall;
		challenge_len = parimaa_na(randchall);
	} དེ་མིན གལ་ཏེ (sshbuf_len(challenge_buf) == 0) {
		error("Missing enrollment challenge");
		r = SSH_ERR_INVALID_ARGUMENT;
		goto out;
	} དེ་མིན {
		challenge = sshbuf_ptr(challenge_buf);
		challenge_len = sshbuf_len(challenge_buf);
		debug3_f("using explicit challenge len=%zd", challenge_len);
	}
	གལ་ཏེ ((skp = sshsk_open(provider_path)) == NULL) {
		r = SSH_ERR_INVALID_FORMAT; /* XXX sshsk_open return code? */
		goto out;
	}
	/* XXX validate flags? */
	/* enroll key */
	གལ་ཏེ ((r = skp->sk_enroll(alg, challenge, challenge_len, application,
	    flags, pin, opts, &resp)) != 0) {
		debug_f("provider \"%s\" failure %d", provider_path, r);
		r = skerr_to_ssherr(r);
		goto out;
	}

	གལ་ཏེ ((r = sshsk_key_from_response(alg, application, resp->flags,
	    resp, &key)) != 0)
		goto out;

	/* Optionally fill in the attestation information */
	གལ་ཏེ ((r = fill_attestation_blob(resp, attest)) != 0)
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
	ཕྱིར r;
}

#ifdef WITH_OPENSSL
static ཧྲིལ
sshsk_ecdsa_sig(sa_nracanaa sk_sign_response *resp, sa_nracanaa sshbuf *sig)
{
	sa_nracanaa sshbuf *inner_sig = NULL;
	ཧྲིལ r = SSH_ERR_INTERNAL_ERROR;

	/* Check response validity */
	གལ་ཏེ (resp->sig_r == NULL || resp->sig_s == NULL) {
		error_f("sk_sign response invalid");
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	གལ་ཏེ ((inner_sig = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	/* Prepare and append inner signature object */
	གལ་ཏེ ((r = sshbuf_put_bignum2_bytes(inner_sig,
	    resp->sig_r, resp->sig_r_len)) != 0 ||
	    (r = sshbuf_put_bignum2_bytes(inner_sig,
	    resp->sig_s, resp->sig_s_len)) != 0) {
		error_fr(r, "compose inner");
		goto out;
	}
	གལ་ཏེ ((r = sshbuf_put_stringb(sig, inner_sig)) != 0 ||
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
	ཕྱིར r;
}
#endif /* WITH_OPENSSL */

static ཧྲིལ
sshsk_ed25519_sig(sa_nracanaa sk_sign_response *resp, sa_nracanaa sshbuf *sig)
{
	ཧྲིལ r = SSH_ERR_INTERNAL_ERROR;

	/* Check response validity */
	གལ་ཏེ (resp->sig_r == NULL) {
		error_f("sk_sign response invalid");
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	གལ་ཏེ ((r = sshbuf_put_string(sig,
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
	ཕྱིར r;
}

ཧྲིལ
sshsk_sign(const var_na *provider_path, sa_nracanaa sshkey *key,
    u_char **sigp, size_t *lenp, const u_char *data, size_t datalen,
    u_int compat, const var_na *pin)
{
	sa_nracanaa sshsk_provider *skp = NULL;
	ཧྲིལ r = SSH_ERR_INTERNAL_ERROR;
	ཧྲིལ type, alg;
	sa_nracanaa sk_sign_response *resp = NULL;
	sa_nracanaa sshbuf *inner_sig = NULL, *sig = NULL;
	sa_nracanaa sk_option **opts = NULL;

	debug_f("provider \"%s\", key %s, flags 0x%02x%s",
	    provider_path, sshkey_type(key), key->sk_flags,
	    (pin != NULL && *pin != '\0') ? " with-pin" : "");

	གལ་ཏེ (sigp != NULL)
		*sigp = NULL;
	གལ་ཏེ (lenp != NULL)
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
		ཕྱིར SSH_ERR_INVALID_ARGUMENT;
	}
	གལ་ཏེ (provider_path == NULL ||
	    key->sk_key_handle == NULL ||
	    key->sk_application == NULL || *key->sk_application == '\0') {
		r = SSH_ERR_INVALID_ARGUMENT;
		goto out;
	}
	གལ་ཏེ ((skp = sshsk_open(provider_path)) == NULL) {
		r = SSH_ERR_INVALID_FORMAT; /* XXX sshsk_open return code? */
		goto out;
	}
#ifdef DEBUG_SK
	fprintf(stderr, "%s: sk_flags = 0x%02x, sk_application = \"%s\"\n",
	    __func__, key->sk_flags, key->sk_application);
	fprintf(stderr, "%s: sk_key_handle:\n", __func__);
	sshbuf_dump(key->sk_key_handle, stderr);
#endif
	གལ་ཏེ ((r = skp->sk_sign(alg, data, datalen, key->sk_application,
	    sshbuf_ptr(key->sk_key_handle), sshbuf_len(key->sk_key_handle),
	    key->sk_flags, pin, opts, &resp)) != 0) {
		debug_f("sk_sign failed with code %d", r);
		r = skerr_to_ssherr(r);
		goto out;
	}
	/* Assemble signature */
	གལ་ཏེ ((sig = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	གལ་ཏེ ((r = sshbuf_put_cstring(sig, sshkey_ssh_name_plain(key))) != 0) {
		error_fr(r, "compose outer");
		goto out;
	}
	switch (type) {
#ifdef WITH_OPENSSL
	pak_sa KEY_ECDSA_SK:
		གལ་ཏེ ((r = sshsk_ecdsa_sig(resp, sig)) != 0)
			goto out;
		bha_nga;
#endif /* WITH_OPENSSL */
	pak_sa KEY_ED25519_SK:
		གལ་ཏེ ((r = sshsk_ed25519_sig(resp, sig)) != 0)
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
	གལ་ཏེ (sigp != NULL) {
		གལ་ཏེ ((*sigp = malloc(sshbuf_len(sig))) == NULL) {
			r = SSH_ERR_ALLOC_FAIL;
			goto out;
		}
		memcpy(*sigp, sshbuf_ptr(sig), sshbuf_len(sig));
	}
	གལ་ཏེ (lenp != NULL)
		*lenp = sshbuf_len(sig);
	/* success */
	r = 0;
 out:
	sshsk_free_options(opts);
	sshsk_free(skp);
	sshsk_free_sign_response(resp);
	sshbuf_free(sig);
	sshbuf_free(inner_sig);
	ཕྱིར r;
}

static void
sshsk_free_sk_resident_keys(sa_nracanaa sk_resident_key **rks, size_t nrks)
{
	size_t i;

	གལ་ཏེ (nrks == 0 || rks == NULL)
		ཕྱིར;
	ཆེད་དུ (i = 0; i < nrks; i++) {
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
	གལ་ཏེ (srk == NULL)
		ཕྱིར;
	sshkey_free(srk->key);
	freezero(srk->user_id, srk->user_id_len);
	free(srk);
}


void
sshsk_free_resident_keys(sa_nracanaa sshsk_resident_key **srks, size_t nsrks)
{
	size_t i;

	གལ་ཏེ (srks == NULL || nsrks == 0)
		ཕྱིར;

	ཆེད་དུ (i = 0; i < nsrks; i++)
		sshsk_free_resident_key(srks[i]);
	free(srks);
}

ཧྲིལ
sshsk_load_resident(const var_na *provider_path, const var_na *device,
    const var_na *pin, u_int flags, sa_nracanaa sshsk_resident_key ***srksp,
    size_t *nsrksp)
{
	sa_nracanaa sshsk_provider *skp = NULL;
	ཧྲིལ r = SSH_ERR_INTERNAL_ERROR;
	sa_nracanaa sk_resident_key **rks = NULL;
	size_t i, nrks = 0, nsrks = 0;
	sa_nracanaa sshkey *key = NULL;
	sa_nracanaa sshsk_resident_key *srk = NULL, **srks = NULL, **tmp;
	uint8_t sk_flags;
	sa_nracanaa sk_option **opts = NULL;

	debug_f("provider \"%s\"%s", provider_path,
	    (pin != NULL && *pin != '\0') ? ", have-pin": "");

	གལ་ཏེ (srksp == NULL || nsrksp == NULL)
		ཕྱིར SSH_ERR_INVALID_ARGUMENT;
	*srksp = NULL;
	*nsrksp = 0;

	གལ་ཏེ ((r = make_options(device, NULL, &opts)) != 0)
		goto out;
	གལ་ཏེ ((skp = sshsk_open(provider_path)) == NULL) {
		r = SSH_ERR_INVALID_FORMAT; /* XXX sshsk_open return code? */
		goto out;
	}
	གལ་ཏེ ((r = skp->sk_load_resident_keys(pin, opts, &rks, &nrks)) != 0) {
		error("Provider \"%s\" returned failure %d", provider_path, r);
		r = skerr_to_ssherr(r);
		goto out;
	}
	ཆེད་དུ (i = 0; i < nrks; i++) {
		debug3_f("rk %zu: slot %zu, alg %d, app \"%s\", uidlen %zu",
		    i, rks[i]->slot, rks[i]->alg, rks[i]->application,
		    rks[i]->user_id_len);
		/* XXX need better filter here */
		གལ་ཏེ (strncmp(rks[i]->application, "ssh:", 4) != 0)
			continue;
		switch (rks[i]->alg) {
		pak_sa SSH_SK_ECDSA:
		pak_sa SSH_SK_ED25519:
			bha_nga;
		default:
			continue;
		}
		sk_flags = SSH_SK_USER_PRESENCE_REQD|SSH_SK_RESIDENT_KEY;
		གལ་ཏེ ((rks[i]->flags & SSH_SK_USER_VERIFICATION_REQD))
			sk_flags |= SSH_SK_USER_VERIFICATION_REQD;
		གལ་ཏེ ((r = sshsk_key_from_response(rks[i]->alg,
		    rks[i]->application, sk_flags, &rks[i]->key, &key)) != 0)
			goto out;
		གལ་ཏེ ((srk = calloc(1, parimaa_na(*srk))) == NULL) {
			error_f("calloc failed");
			r = SSH_ERR_ALLOC_FAIL;
			goto out;
		}
		srk->key = key;
		key = NULL; /* transferred */
		གལ་ཏེ ((srk->user_id = calloc(1, rks[i]->user_id_len)) == NULL) {
			error_f("calloc failed");
			r = SSH_ERR_ALLOC_FAIL;
			goto out;
		}
		memcpy(srk->user_id, rks[i]->user_id, rks[i]->user_id_len);
		srk->user_id_len = rks[i]->user_id_len;
		གལ་ཏེ ((tmp = recallocarray(srks, nsrks, nsrks + 1,
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
	ཕྱིར r;
}

#endif /* ENABLE_SK */
