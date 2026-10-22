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

#ಅನ್ತರ್ಭಾವ "includes.h"

#ifdef ENABLE_SK

#ಅನ್ತರ್ಭಾವ <dlfcn.h>
#ಅನ್ತರ್ಭಾವ <stddef.h>
#ಅನ್ತರ್ಭಾವ <stdint.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>

#ifdef WITH_OPENSSL
#ಅನ್ತರ್ಭಾವ <openssl/objects.h>
#ಅನ್ತರ್ಭಾವ <openssl/ec.h>
#ಅನ್ತರ್ಭಾವ <openssl/evp.h>
#endif /* WITH_OPENSSL */

#ಅನ್ತರ್ಭಾವ "log.h"
#ಅನ್ತರ್ಭಾವ "misc.h"
#ಅನ್ತರ್ಭಾವ "sshbuf.h"
#ಅನ್ತರ್ಭಾವ "sshkey.h"
#ಅನ್ತರ್ಭಾವ "ssherr.h"
#ಅನ್ತರ್ಭಾವ "digest.h"

#ಅನ್ತರ್ಭಾವ "ssh-sk.h"
#ಅನ್ತರ್ಭಾವ "sk-api.h"
#ಅನ್ತರ್ಭಾವ "crypto_api.h"

ಸಂರಚನಾ sshsk_provider {
	ವರ್ಣ *path;
	ಶೂನ್ಯ *dlhandle;

	/* Return the version of the middleware API */
	uint32_t (*sk_api_version)(ಶೂನ್ಯ);

	/* Enroll a U2F key (private key generation) */
	ಪೂರ್ಣಾಙ್ಕ (*sk_enroll)(ಪೂರ್ಣಾಙ್ಕ alg, ಧ್ರುವ uint8_t *challenge,
	    size_t challenge_len, ಧ್ರುವ ವರ್ಣ *application, uint8_t flags,
	    ಧ್ರುವ ವರ್ಣ *pin, ಸಂರಚನಾ sk_option **opts,
	    ಸಂರಚನಾ sk_enroll_response **enroll_response);

	/* Sign a challenge */
	ಪೂರ್ಣಾಙ್ಕ (*sk_sign)(ಪೂರ್ಣಾಙ್ಕ alg, ಧ್ರುವ uint8_t *message, size_t message_len,
	    ಧ್ರುವ ವರ್ಣ *application,
	    ಧ್ರುವ uint8_t *ಕೀಲಿ_handle, size_t ಕೀಲಿ_handle_len,
	    uint8_t flags, ಧ್ರುವ ವರ್ಣ *pin, ಸಂರಚನಾ sk_option **opts,
	    ಸಂರಚನಾ sk_sign_response **sign_response);

	/* Enumerate resident keys */
	ಪೂರ್ಣಾಙ್ಕ (*sk_load_resident_ಕೀಲಿಗಳು)(ಧ್ರುವ ವರ್ಣ *pin, ಸಂರಚನಾ sk_option **opts,
	    ಸಂರಚನಾ sk_resident_ಕೀಲಿ ***rks, size_t *nrks);
};

/* Built-in version */
ಪೂರ್ಣಾಙ್ಕ ssh_sk_enroll(ಪೂರ್ಣಾಙ್ಕ alg, ಧ್ರುವ uint8_t *challenge,
    size_t challenge_len, ಧ್ರುವ ವರ್ಣ *application, uint8_t flags,
    ಧ್ರುವ ವರ್ಣ *pin, ಸಂರಚನಾ sk_option **opts,
    ಸಂರಚನಾ sk_enroll_response **enroll_response);
ಪೂರ್ಣಾಙ್ಕ ssh_sk_sign(ಪೂರ್ಣಾಙ್ಕ alg, ಧ್ರುವ uint8_t *message, size_t message_len,
    ಧ್ರುವ ವರ್ಣ *application,
    ಧ್ರುವ uint8_t *ಕೀಲಿ_handle, size_t ಕೀಲಿ_handle_len,
    uint8_t flags, ಧ್ರುವ ವರ್ಣ *pin, ಸಂರಚನಾ sk_option **opts,
    ಸಂರಚನಾ sk_sign_response **sign_response);
ಪೂರ್ಣಾಙ್ಕ ssh_sk_load_resident_ಕೀಲಿಗಳು(ಧ್ರುವ ವರ್ಣ *pin, ಸಂರಚನಾ sk_option **opts,
    ಸಂರಚನಾ sk_resident_ಕೀಲಿ ***rks, size_t *nrks);

ಸ್ಥಿರ ಶೂನ್ಯ
sshsk_free(ಸಂರಚನಾ sshsk_provider *p)
{
	ಯದಿ (p == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ;
	ಮುಕ್ತ(p->path);
	ಯದಿ (p->dlhandle != ರಿಕ್ತ)
		dlclose(p->dlhandle);
	ಮುಕ್ತ(p);
}

ಸ್ಥಿರ ಸಂರಚನಾ sshsk_provider *
sshsk_open(ಧ್ರುವ ವರ್ಣ *path)
{
	ಸಂರಚನಾ sshsk_provider *ret = ರಿಕ್ತ;
	uint32_t version;

	ಯದಿ (path == ರಿಕ್ತ || *path == '\0') {
		error("No FIDO SecurityKeyProvider specified");
		ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
	}
	ಯದಿ ((ret = calloc(1, ಪರಿಮಾಣ(*ret))) == ರಿಕ್ತ) {
		error_f("calloc failed");
		ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
	}
	ಯದಿ ((ret->path = strdup(path)) == ರಿಕ್ತ) {
		error_f("strdup failed");
		ಗಚ್ಛ fail;
	}
	/* Skip the rest if we're using the linked in middleware */
	ಯದಿ (strcasecmp(ret->path, "internal") == 0) {
#ifdef ENABLE_SK_INTERNAL
		ret->sk_enroll = ssh_sk_enroll;
		ret->sk_sign = ssh_sk_sign;
		ret->sk_load_resident_ಕೀಲಿಗಳು = ssh_sk_load_resident_ಕೀಲಿಗಳು;
		ಪ್ರತ್ಯಾಗಮ ret;
#ಅನ್ಯಥಾ
		error("internal security key support not enabled");
		ಗಚ್ಛ fail;
#endif
	}
	ಯದಿ (lib_contains_ಚಿಹ್ನೆ(path, "sk_api_version") != 0) {
		error("provider %s is not an OpenSSH FIDO library", path);
		ಗಚ್ಛ fail;
	}
	ಯದಿ ((ret->dlhandle = dlopen(path, RTLD_NOW)) == ರಿಕ್ತ)
		fatal("Provider \"%s\" dlopen failed: %s", path, dlerror());
	ಯದಿ ((ret->sk_api_version = dlsym(ret->dlhandle,
	    "sk_api_version")) == ರಿಕ್ತ) {
		error("Provider \"%s\" dlsym(sk_api_version) failed: %s",
		    path, dlerror());
		ಗಚ್ಛ fail;
	}
	version = ret->sk_api_version();
	debug_f("provider %s implements version 0x%08lx", ret->path,
	    (u_long)version);
	ಯದಿ ((version & SSH_SK_VERSION_MAJOR_MASK) != SSH_SK_VERSION_MAJOR) {
		error("Provider \"%s\" implements unsupported "
		    "version 0x%08lx (supported: 0x%08lx)",
		    path, (u_long)version, (u_long)SSH_SK_VERSION_MAJOR);
		ಗಚ್ಛ fail;
	}
	ಯದಿ ((ret->sk_enroll = dlsym(ret->dlhandle, "sk_enroll")) == ರಿಕ್ತ) {
		error("Provider %s dlsym(sk_enroll) failed: %s",
		    path, dlerror());
		ಗಚ್ಛ fail;
	}
	ಯದಿ ((ret->sk_sign = dlsym(ret->dlhandle, "sk_sign")) == ರಿಕ್ತ) {
		error("Provider \"%s\" dlsym(sk_sign) failed: %s",
		    path, dlerror());
		ಗಚ್ಛ fail;
	}
	ಯದಿ ((ret->sk_load_resident_ಕೀಲಿಗಳು = dlsym(ret->dlhandle,
	    "sk_load_resident_keys")) == ರಿಕ್ತ) {
		error("Provider \"%s\" dlsym(sk_load_resident_keys) "
		    "failed: %s", path, dlerror());
		ಗಚ್ಛ fail;
	}
	/* success */
	ಪ್ರತ್ಯಾಗಮ ret;
fail:
	sshsk_free(ret);
	ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
}

ಸ್ಥಿರ ಶೂನ್ಯ
sshsk_free_enroll_response(ಸಂರಚನಾ sk_enroll_response *r)
{
	ಯದಿ (r == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ;
	freezero(r->ಕೀಲಿ_handle, r->ಕೀಲಿ_handle_len);
	freezero(r->public_ಕೀಲಿ, r->public_ಕೀಲಿ_len);
	freezero(r->signature, r->signature_len);
	freezero(r->attestation_cert, r->attestation_cert_len);
	freezero(r->authdata, r->authdata_len);
	freezero(r, ಪರಿಮಾಣ(*r));
}

ಸ್ಥಿರ ಶೂನ್ಯ
sshsk_free_sign_response(ಸಂರಚನಾ sk_sign_response *r)
{
	ಯದಿ (r == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ;
	freezero(r->sig_r, r->sig_r_len);
	freezero(r->sig_s, r->sig_s_len);
	freezero(r, ಪರಿಮಾಣ(*r));
}

#ifdef WITH_OPENSSL
/* Assemble key from response */
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
sshsk_ecdsa_assemble(ಸಂರಚನಾ sk_enroll_response *resp, ಸಂರಚನಾ sshkey **keyp)
{
	ಸಂರಚನಾ sshkey *ಕೀಲಿ = ರಿಕ್ತ;
	ಸಂರಚನಾ sshbuf *b = ರಿಕ್ತ;
	EC_ಕೀಲಿ *ecdsa = ರಿಕ್ತ;
	EC_POINT *q = ರಿಕ್ತ;
	ಧ್ರುವ EC_GROUP *g = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ r;

	*keyp = ರಿಕ್ತ;
	ಯದಿ ((ಕೀಲಿ = sshkey_new(ಕೀಲಿ_ECDSA_SK)) == ರಿಕ್ತ) {
		error_f("sshkey_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		ಗಚ್ಛ out;
	}
	ಕೀಲಿ->ecdsa_nid = NID_X9_62_prime256v1;
	ಯದಿ ((ecdsa = EC_ಕೀಲಿ_new_by_curve_name(ಕೀಲಿ->ecdsa_nid)) == ರಿಕ್ತ ||
	    (g = EC_ಕೀಲಿ_get0_group(ecdsa)) == ರಿಕ್ತ ||
	    (q = EC_POINT_new(g)) == ರಿಕ್ತ ||
	    (b = sshbuf_new()) == ರಿಕ್ತ) {
		error_f("allocation failed");
		r = SSH_ERR_ALLOC_FAIL;
		ಗಚ್ಛ out;
	}
	ಯದಿ ((r = sshbuf_put_string(b,
	    resp->public_ಕೀಲಿ, resp->public_ಕೀಲಿ_len)) != 0) {
		error_fr(r, "sshbuf_put_string");
		ಗಚ್ಛ out;
	}
	ಯದಿ ((r = sshbuf_get_ec(b, q, g)) != 0) {
		error_fr(r, "parse");
		r = SSH_ERR_INVALID_FORMAT;
		ಗಚ್ಛ out;
	}
	ಯದಿ (sshkey_ec_validate_public(g, q) != 0) {
		error("Authenticator returned invalid ECDSA key");
		r = SSH_ERR_ಕೀಲಿ_INVALID_EC_ಮೌಲ್ಯ;
		ಗಚ್ಛ out;
	}
	ಯದಿ (EC_ಕೀಲಿ_set_public_ಕೀಲಿ(ecdsa, q) != 1) {
		/* XXX assume it is a allocation error */
		error_f("allocation failed");
		r = SSH_ERR_ALLOC_FAIL;
		ಗಚ್ಛ out;
	}
	ಯದಿ ((ಕೀಲಿ->pkey = EVP_PKEY_new()) == ರಿಕ್ತ) {
		error_f("allocation failed");
		r = SSH_ERR_ALLOC_FAIL;
		ಗಚ್ಛ out;
	}
	ಯದಿ (EVP_PKEY_set1_EC_ಕೀಲಿ(ಕೀಲಿ->pkey, ecdsa) != 1) {
		error_f("Assigning EC_KEY failed");
		r = SSH_ERR_LIBCRYPTO_ERROR;
		ಗಚ್ಛ out;
	}
	/* success */
	*keyp = ಕೀಲಿ;
	ಕೀಲಿ = ರಿಕ್ತ; /* transferred */
	r = 0;
 out:
	sshkey_free(ಕೀಲಿ);
	sshbuf_free(b);
	EC_ಕೀಲಿ_free(ecdsa);
	EC_POINT_free(q);
	ಪ್ರತ್ಯಾಗಮ r;
}
#endif /* WITH_OPENSSL */

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
sshsk_ed25519_assemble(ಸಂರಚನಾ sk_enroll_response *resp, ಸಂರಚನಾ sshkey **keyp)
{
	ಸಂರಚನಾ sshkey *ಕೀಲಿ = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ r;

	*keyp = ರಿಕ್ತ;
	ಯದಿ (resp->public_ಕೀಲಿ_len != ED25519_PK_SZ) {
		error_f("invalid size: %zu", resp->public_ಕೀಲಿ_len);
		r = SSH_ERR_INVALID_FORMAT;
		ಗಚ್ಛ out;
	}
	ಯದಿ ((ಕೀಲಿ = sshkey_new(ಕೀಲಿ_ED25519_SK)) == ರಿಕ್ತ) {
		error_f("sshkey_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		ಗಚ್ಛ out;
	}
	ಯದಿ ((ಕೀಲಿ->ed25519_pk = malloc(ED25519_PK_SZ)) == ರಿಕ್ತ) {
		error_f("malloc failed");
		r = SSH_ERR_ALLOC_FAIL;
		ಗಚ್ಛ out;
	}
	memcpy(ಕೀಲಿ->ed25519_pk, resp->public_ಕೀಲಿ, ED25519_PK_SZ);
	/* success */
	*keyp = ಕೀಲಿ;
	ಕೀಲಿ = ರಿಕ್ತ; /* transferred */
	r = 0;
 out:
	sshkey_free(ಕೀಲಿ);
	ಪ್ರತ್ಯಾಗಮ r;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
sshsk_ಕೀಲಿ_from_response(ಪೂರ್ಣಾಙ್ಕ alg, ಧ್ರುವ ವರ್ಣ *application, uint8_t flags,
    ಸಂರಚನಾ sk_enroll_response *resp, ಸಂರಚನಾ sshkey **keyp)
{
	ಸಂರಚನಾ sshkey *ಕೀಲಿ = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ r = SSH_ERR_INTERNAL_ERROR;

	*keyp = ರಿಕ್ತ;

	/* Check response validity */
	ಯದಿ (resp->public_ಕೀಲಿ == ರಿಕ್ತ || resp->ಕೀಲಿ_handle == ರಿಕ್ತ) {
		error_f("sk_enroll response invalid");
		r = SSH_ERR_INVALID_FORMAT;
		ಗಚ್ಛ out;
	}
	ವಿಕಲ್ಪ (alg) {
#ifdef WITH_OPENSSL
	ಪಕ್ಷ SSH_SK_ECDSA:
		ಯದಿ ((r = sshsk_ecdsa_assemble(resp, &ಕೀಲಿ)) != 0)
			ಗಚ್ಛ out;
		ಭಙ್ಗ;
#endif /* WITH_OPENSSL */
	ಪಕ್ಷ SSH_SK_ED25519:
		ಯದಿ ((r = sshsk_ed25519_assemble(resp, &ಕೀಲಿ)) != 0)
			ಗಚ್ಛ out;
		ಭಙ್ಗ;
	ಸ್ವಭಾವ:
		error_f("unsupported algorithm %d", alg);
		r = SSH_ERR_INVALID_ARGUMENT;
		ಗಚ್ಛ out;
	}
	ಕೀಲಿ->sk_flags = flags;
	ಯದಿ ((ಕೀಲಿ->sk_ಕೀಲಿ_handle = sshbuf_new()) == ರಿಕ್ತ ||
	    (ಕೀಲಿ->sk_reserved = sshbuf_new()) == ರಿಕ್ತ) {
		error_f("allocation failed");
		r = SSH_ERR_ALLOC_FAIL;
		ಗಚ್ಛ out;
	}
	ಯದಿ ((ಕೀಲಿ->sk_application = strdup(application)) == ರಿಕ್ತ) {
		error_f("strdup application failed");
		r = SSH_ERR_ALLOC_FAIL;
		ಗಚ್ಛ out;
	}
	ಯದಿ ((r = sshbuf_put(ಕೀಲಿ->sk_ಕೀಲಿ_handle, resp->ಕೀಲಿ_handle,
	    resp->ಕೀಲಿ_handle_len)) != 0) {
		error_fr(r, "put key handle");
		ಗಚ್ಛ out;
	}
	/* success */
	r = 0;
	*keyp = ಕೀಲಿ;
	ಕೀಲಿ = ರಿಕ್ತ;
 out:
	sshkey_free(ಕೀಲಿ);
	ಪ್ರತ್ಯಾಗಮ r;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
skerr_to_ssherr(ಪೂರ್ಣಾಙ್ಕ skerr)
{
	ವಿಕಲ್ಪ (skerr) {
	ಪಕ್ಷ SSH_SK_ERR_UNSUPPORTED:
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_FEATURE_UNSUPPORTED;
	ಪಕ್ಷ SSH_SK_ERR_PIN_REQUIRED:
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_ಕೀಲಿ_WRONG_PASSPHRASE;
	ಪಕ್ಷ SSH_SK_ERR_DEVICE_NOT_FOUND:
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_DEVICE_NOT_FOUND;
	ಪಕ್ಷ SSH_SK_ERR_CREDENTIAL_EXISTS:
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_ಕೀಲಿ_BAD_PERMISSIONS;
	ಪಕ್ಷ SSH_SK_ERR_GENERAL:
	ಸ್ವಭಾವ:
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INVALID_FORMAT;
	}
}

ಸ್ಥಿರ ಶೂನ್ಯ
sshsk_free_options(ಸಂರಚನಾ sk_option **opts)
{
	size_t i;

	ಯದಿ (opts == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ;
	ಪ್ರತಿ (i = 0; opts[i] != ರಿಕ್ತ; i++) {
		ಮುಕ್ತ(opts[i]->name);
		ಮುಕ್ತ(opts[i]->ಮೌಲ್ಯ);
		ಮುಕ್ತ(opts[i]);
	}
	ಮುಕ್ತ(opts);
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
sshsk_add_option(ಸಂರಚನಾ sk_option ***optsp, size_t *noptsp,
    ಧ್ರುವ ವರ್ಣ *name, ಧ್ರುವ ವರ್ಣ *ಮೌಲ್ಯ, uint8_t required)
{
	ಸಂರಚನಾ sk_option **opts = *optsp;
	size_t nopts = *noptsp;

	ಯದಿ ((opts = recallocarray(opts, nopts, nopts + 2, /* extra for NULL */
	    ಪರಿಮಾಣ(*opts))) == ರಿಕ್ತ) {
		error_f("array alloc failed");
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_ALLOC_FAIL;
	}
	*optsp = opts;
	*noptsp = nopts + 1;
	ಯದಿ ((opts[nopts] = calloc(1, ಪರಿಮಾಣ(**opts))) == ರಿಕ್ತ) {
		error_f("alloc failed");
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_ALLOC_FAIL;
	}
	ಯದಿ ((opts[nopts]->name = strdup(name)) == ರಿಕ್ತ ||
	    (opts[nopts]->ಮೌಲ್ಯ = strdup(ಮೌಲ್ಯ)) == ರಿಕ್ತ) {
		error_f("alloc failed");
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_ALLOC_FAIL;
	}
	opts[nopts]->required = required;
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
make_options(ಧ್ರುವ ವರ್ಣ *device, ಧ್ರುವ ವರ್ಣ *user_id,
    ಸಂರಚನಾ sk_option ***optsp)
{
	ಸಂರಚನಾ sk_option **opts = ರಿಕ್ತ;
	size_t nopts = 0;
	ಪೂರ್ಣಾಙ್ಕ r, ret = SSH_ERR_INTERNAL_ERROR;

	ಯದಿ (device != ರಿಕ್ತ &&
	    (r = sshsk_add_option(&opts, &nopts, "device", device, 0)) != 0) {
		ret = r;
		ಗಚ್ಛ out;
	}
	ಯದಿ (user_id != ರಿಕ್ತ &&
	    (r = sshsk_add_option(&opts, &nopts, "user", user_id, 0)) != 0) {
		ret = r;
		ಗಚ್ಛ out;
	}
	/* success */
	*optsp = opts;
	opts = ರಿಕ್ತ;
	nopts = 0;
	ret = 0;
 out:
	sshsk_free_options(opts);
	ಪ್ರತ್ಯಾಗಮ ret;
}


ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
fill_attestation_blob(ಧ್ರುವ ಸಂರಚನಾ sk_enroll_response *resp,
    ಸಂರಚನಾ sshbuf *attest)
{
	ಪೂರ್ಣಾಙ್ಕ r;

	ಯದಿ (attest == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ 0; /* nothing to do */
	ಯದಿ ((r = sshbuf_put_cstring(attest, "ssh-sk-attest-v01")) != 0 ||
	    (r = sshbuf_put_string(attest,
	    resp->attestation_cert, resp->attestation_cert_len)) != 0 ||
	    (r = sshbuf_put_string(attest,
	    resp->signature, resp->signature_len)) != 0 ||
	    (r = sshbuf_put_string(attest,
	    resp->authdata, resp->authdata_len)) != 0 ||
	    (r = sshbuf_put_u32(attest, 0)) != 0 || /* resvd flags */
	    (r = sshbuf_put_string(attest, ರಿಕ್ತ, 0)) != 0 /* resvd */) {
		error_fr(r, "compose");
		ಪ್ರತ್ಯಾಗಮ r;
	}
	/* success */
	ಪ್ರತ್ಯಾಗಮ 0;
}

ಪೂರ್ಣಾಙ್ಕ
sshsk_enroll(ಪೂರ್ಣಾಙ್ಕ type, ಧ್ರುವ ವರ್ಣ *provider_path, ಧ್ರುವ ವರ್ಣ *device,
    ಧ್ರುವ ವರ್ಣ *application, ಧ್ರುವ ವರ್ಣ *userid, uint8_t flags,
    ಧ್ರುವ ವರ್ಣ *pin, ಸಂರಚನಾ sshbuf *challenge_buf,
    ಸಂರಚನಾ sshkey **keyp, ಸಂರಚನಾ sshbuf *attest)
{
	ಸಂರಚನಾ sshsk_provider *skp = ರಿಕ್ತ;
	ಸಂರಚನಾ sshkey *ಕೀಲಿ = ರಿಕ್ತ;
	u_char randchall[32];
	ಧ್ರುವ u_char *challenge;
	size_t challenge_len;
	ಸಂರಚನಾ sk_enroll_response *resp = ರಿಕ್ತ;
	ಸಂರಚನಾ sk_option **opts = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ r = SSH_ERR_INTERNAL_ERROR;
	ಪೂರ್ಣಾಙ್ಕ alg;

	debug_f("provider \"%s\", device \"%s\", application \"%s\", "
	    "userid \"%s\", flags 0x%02x, challenge len %zu%s",
	    provider_path, device, application, userid, flags,
	    challenge_buf == ರಿಕ್ತ ? 0 : sshbuf_len(challenge_buf),
	    (pin != ರಿಕ್ತ && *pin != '\0') ? " with-pin" : "");

	*keyp = ರಿಕ್ತ;
	ಯದಿ (attest)
		sshbuf_reset(attest);

	ಯದಿ ((r = make_options(device, userid, &opts)) != 0)
		ಗಚ್ಛ out;

	ವಿಕಲ್ಪ (type) {
#ifdef WITH_OPENSSL
	ಪಕ್ಷ ಕೀಲಿ_ECDSA_SK:
		alg = SSH_SK_ECDSA;
		ಭಙ್ಗ;
#endif /* WITH_OPENSSL */
	ಪಕ್ಷ ಕೀಲಿ_ED25519_SK:
		alg = SSH_SK_ED25519;
		ಭಙ್ಗ;
	ಸ್ವಭಾವ:
		error_f("unsupported key type");
		r = SSH_ERR_INVALID_ARGUMENT;
		ಗಚ್ಛ out;
	}
	ಯದಿ (provider_path == ರಿಕ್ತ) {
		error_f("missing provider");
		r = SSH_ERR_INVALID_ARGUMENT;
		ಗಚ್ಛ out;
	}
	ಯದಿ (application == ರಿಕ್ತ || *application == '\0') {
		error_f("missing application");
		r = SSH_ERR_INVALID_ARGUMENT;
		ಗಚ್ಛ out;
	}
	ಯದಿ (challenge_buf == ರಿಕ್ತ) {
		debug_f("using random challenge");
		arc4random_buf(randchall, ಪರಿಮಾಣ(randchall));
		challenge = randchall;
		challenge_len = ಪರಿಮಾಣ(randchall);
	} ಅನ್ಯಥಾ ಯದಿ (sshbuf_len(challenge_buf) == 0) {
		error("Missing enrollment challenge");
		r = SSH_ERR_INVALID_ARGUMENT;
		ಗಚ್ಛ out;
	} ಅನ್ಯಥಾ {
		challenge = sshbuf_ptr(challenge_buf);
		challenge_len = sshbuf_len(challenge_buf);
		debug3_f("using explicit challenge len=%zd", challenge_len);
	}
	ಯದಿ ((skp = sshsk_open(provider_path)) == ರಿಕ್ತ) {
		r = SSH_ERR_INVALID_FORMAT; /* XXX sshsk_open return code? */
		ಗಚ್ಛ out;
	}
	/* XXX validate flags? */
	/* enroll key */
	ಯದಿ ((r = skp->sk_enroll(alg, challenge, challenge_len, application,
	    flags, pin, opts, &resp)) != 0) {
		debug_f("provider \"%s\" failure %d", provider_path, r);
		r = skerr_to_ssherr(r);
		ಗಚ್ಛ out;
	}

	ಯದಿ ((r = sshsk_ಕೀಲಿ_from_response(alg, application, resp->flags,
	    resp, &ಕೀಲಿ)) != 0)
		ಗಚ್ಛ out;

	/* Optionally fill in the attestation information */
	ಯದಿ ((r = fill_attestation_blob(resp, attest)) != 0)
		ಗಚ್ಛ out;

	/* success */
	*keyp = ಕೀಲಿ;
	ಕೀಲಿ = ರಿಕ್ತ; /* transferred */
	r = 0;
 out:
	sshsk_free_options(opts);
	sshsk_free(skp);
	sshkey_free(ಕೀಲಿ);
	sshsk_free_enroll_response(resp);
	explicit_bzero(randchall, ಪರಿಮಾಣ(randchall));
	ಪ್ರತ್ಯಾಗಮ r;
}

#ifdef WITH_OPENSSL
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
sshsk_ecdsa_sig(ಸಂರಚನಾ sk_sign_response *resp, ಸಂರಚನಾ sshbuf *sig)
{
	ಸಂರಚನಾ sshbuf *inner_sig = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ r = SSH_ERR_INTERNAL_ERROR;

	/* Check response validity */
	ಯದಿ (resp->sig_r == ರಿಕ್ತ || resp->sig_s == ರಿಕ್ತ) {
		error_f("sk_sign response invalid");
		r = SSH_ERR_INVALID_FORMAT;
		ಗಚ್ಛ out;
	}
	ಯದಿ ((inner_sig = sshbuf_new()) == ರಿಕ್ತ) {
		r = SSH_ERR_ALLOC_FAIL;
		ಗಚ್ಛ out;
	}
	/* Prepare and append inner signature object */
	ಯದಿ ((r = sshbuf_put_bignum2_bytes(inner_sig,
	    resp->sig_r, resp->sig_r_len)) != 0 ||
	    (r = sshbuf_put_bignum2_bytes(inner_sig,
	    resp->sig_s, resp->sig_s_len)) != 0) {
		error_fr(r, "compose inner");
		ಗಚ್ಛ out;
	}
	ಯದಿ ((r = sshbuf_put_stringb(sig, inner_sig)) != 0 ||
	    (r = sshbuf_put_u8(sig, resp->flags)) != 0 ||
	    (r = sshbuf_put_u32(sig, resp->counter)) != 0) {
		error_fr(r, "compose");
		ಗಚ್ಛ out;
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
	ಪ್ರತ್ಯಾಗಮ r;
}
#endif /* WITH_OPENSSL */

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
sshsk_ed25519_sig(ಸಂರಚನಾ sk_sign_response *resp, ಸಂರಚನಾ sshbuf *sig)
{
	ಪೂರ್ಣಾಙ್ಕ r = SSH_ERR_INTERNAL_ERROR;

	/* Check response validity */
	ಯದಿ (resp->sig_r == ರಿಕ್ತ) {
		error_f("sk_sign response invalid");
		r = SSH_ERR_INVALID_FORMAT;
		ಗಚ್ಛ out;
	}
	ಯದಿ ((r = sshbuf_put_string(sig,
	    resp->sig_r, resp->sig_r_len)) != 0 ||
	    (r = sshbuf_put_u8(sig, resp->flags)) != 0 ||
	    (r = sshbuf_put_u32(sig, resp->counter)) != 0) {
		error_fr(r, "compose");
		ಗಚ್ಛ out;
	}
#ifdef DEBUG_SK
	fprintf(stderr, "%s: sig_r:\n", __func__);
	sshbuf_dump_data(resp->sig_r, resp->sig_r_len, stderr);
#endif
	r = 0;
 out:
	ಪ್ರತ್ಯಾಗಮ r;
}

ಪೂರ್ಣಾಙ್ಕ
sshsk_sign(ಧ್ರುವ ವರ್ಣ *provider_path, ಸಂರಚನಾ sshkey *ಕೀಲಿ,
    u_char **sigp, size_t *lenp, ಧ್ರುವ u_char *data, size_t datalen,
    u_int compat, ಧ್ರುವ ವರ್ಣ *pin)
{
	ಸಂರಚನಾ sshsk_provider *skp = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ r = SSH_ERR_INTERNAL_ERROR;
	ಪೂರ್ಣಾಙ್ಕ type, alg;
	ಸಂರಚನಾ sk_sign_response *resp = ರಿಕ್ತ;
	ಸಂರಚನಾ sshbuf *inner_sig = ರಿಕ್ತ, *sig = ರಿಕ್ತ;
	ಸಂರಚನಾ sk_option **opts = ರಿಕ್ತ;

	debug_f("provider \"%s\", key %s, flags 0x%02x%s",
	    provider_path, sshkey_type(ಕೀಲಿ), ಕೀಲಿ->sk_flags,
	    (pin != ರಿಕ್ತ && *pin != '\0') ? " with-pin" : "");

	ಯದಿ (sigp != ರಿಕ್ತ)
		*sigp = ರಿಕ್ತ;
	ಯದಿ (lenp != ರಿಕ್ತ)
		*lenp = 0;
	type = sshkey_type_plain(ಕೀಲಿ->type);
	ವಿಕಲ್ಪ (type) {
#ifdef WITH_OPENSSL
	ಪಕ್ಷ ಕೀಲಿ_ECDSA_SK:
		alg = SSH_SK_ECDSA;
		ಭಙ್ಗ;
#endif /* WITH_OPENSSL */
	ಪಕ್ಷ ಕೀಲಿ_ED25519_SK:
		alg = SSH_SK_ED25519;
		ಭಙ್ಗ;
	ಸ್ವಭಾವ:
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INVALID_ARGUMENT;
	}
	ಯದಿ (provider_path == ರಿಕ್ತ ||
	    ಕೀಲಿ->sk_ಕೀಲಿ_handle == ರಿಕ್ತ ||
	    ಕೀಲಿ->sk_application == ರಿಕ್ತ || *ಕೀಲಿ->sk_application == '\0') {
		r = SSH_ERR_INVALID_ARGUMENT;
		ಗಚ್ಛ out;
	}
	ಯದಿ ((skp = sshsk_open(provider_path)) == ರಿಕ್ತ) {
		r = SSH_ERR_INVALID_FORMAT; /* XXX sshsk_open return code? */
		ಗಚ್ಛ out;
	}
#ifdef DEBUG_SK
	fprintf(stderr, "%s: sk_flags = 0x%02x, sk_application = \"%s\"\n",
	    __func__, ಕೀಲಿ->sk_flags, ಕೀಲಿ->sk_application);
	fprintf(stderr, "%s: sk_key_handle:\n", __func__);
	sshbuf_dump(ಕೀಲಿ->sk_ಕೀಲಿ_handle, stderr);
#endif
	ಯದಿ ((r = skp->sk_sign(alg, data, datalen, ಕೀಲಿ->sk_application,
	    sshbuf_ptr(ಕೀಲಿ->sk_ಕೀಲಿ_handle), sshbuf_len(ಕೀಲಿ->sk_ಕೀಲಿ_handle),
	    ಕೀಲಿ->sk_flags, pin, opts, &resp)) != 0) {
		debug_f("sk_sign failed with code %d", r);
		r = skerr_to_ssherr(r);
		ಗಚ್ಛ out;
	}
	/* Assemble signature */
	ಯದಿ ((sig = sshbuf_new()) == ರಿಕ್ತ) {
		r = SSH_ERR_ALLOC_FAIL;
		ಗಚ್ಛ out;
	}
	ಯದಿ ((r = sshbuf_put_cstring(sig, sshkey_ssh_name_plain(ಕೀಲಿ))) != 0) {
		error_fr(r, "compose outer");
		ಗಚ್ಛ out;
	}
	ವಿಕಲ್ಪ (type) {
#ifdef WITH_OPENSSL
	ಪಕ್ಷ ಕೀಲಿ_ECDSA_SK:
		ಯದಿ ((r = sshsk_ecdsa_sig(resp, sig)) != 0)
			ಗಚ್ಛ out;
		ಭಙ್ಗ;
#endif /* WITH_OPENSSL */
	ಪಕ್ಷ ಕೀಲಿ_ED25519_SK:
		ಯದಿ ((r = sshsk_ed25519_sig(resp, sig)) != 0)
			ಗಚ್ಛ out;
		ಭಙ್ಗ;
	}
#ifdef DEBUG_SK
	fprintf(stderr, "%s: sig_flags = 0x%02x, sig_counter = %u\n",
	    __func__, resp->flags, resp->counter);
	fprintf(stderr, "%s: data to sign:\n", __func__);
	sshbuf_dump_data(data, datalen, stderr);
	fprintf(stderr, "%s: sigbuf:\n", __func__);
	sshbuf_dump(sig, stderr);
#endif
	ಯದಿ (sigp != ರಿಕ್ತ) {
		ಯದಿ ((*sigp = malloc(sshbuf_len(sig))) == ರಿಕ್ತ) {
			r = SSH_ERR_ALLOC_FAIL;
			ಗಚ್ಛ out;
		}
		memcpy(*sigp, sshbuf_ptr(sig), sshbuf_len(sig));
	}
	ಯದಿ (lenp != ರಿಕ್ತ)
		*lenp = sshbuf_len(sig);
	/* success */
	r = 0;
 out:
	sshsk_free_options(opts);
	sshsk_free(skp);
	sshsk_free_sign_response(resp);
	sshbuf_free(sig);
	sshbuf_free(inner_sig);
	ಪ್ರತ್ಯಾಗಮ r;
}

ಸ್ಥಿರ ಶೂನ್ಯ
sshsk_free_sk_resident_ಕೀಲಿಗಳು(ಸಂರಚನಾ sk_resident_ಕೀಲಿ **rks, size_t nrks)
{
	size_t i;

	ಯದಿ (nrks == 0 || rks == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ;
	ಪ್ರತಿ (i = 0; i < nrks; i++) {
		ಮುಕ್ತ(rks[i]->application);
		freezero(rks[i]->user_id, rks[i]->user_id_len);
		freezero(rks[i]->ಕೀಲಿ.ಕೀಲಿ_handle, rks[i]->ಕೀಲಿ.ಕೀಲಿ_handle_len);
		freezero(rks[i]->ಕೀಲಿ.public_ಕೀಲಿ, rks[i]->ಕೀಲಿ.public_ಕೀಲಿ_len);
		freezero(rks[i]->ಕೀಲಿ.signature, rks[i]->ಕೀಲಿ.signature_len);
		freezero(rks[i]->ಕೀಲಿ.attestation_cert,
		    rks[i]->ಕೀಲಿ.attestation_cert_len);
		freezero(rks[i], ಪರಿಮಾಣ(**rks));
	}
	ಮುಕ್ತ(rks);
}

ಸ್ಥಿರ ಶೂನ್ಯ
sshsk_free_resident_ಕೀಲಿ(ಸಂರಚನಾ sshsk_resident_ಕೀಲಿ *srk)
{
	ಯದಿ (srk == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ;
	sshkey_free(srk->ಕೀಲಿ);
	freezero(srk->user_id, srk->user_id_len);
	ಮುಕ್ತ(srk);
}


ಶೂನ್ಯ
sshsk_free_resident_ಕೀಲಿಗಳು(ಸಂರಚನಾ sshsk_resident_ಕೀಲಿ **srks, size_t nsrks)
{
	size_t i;

	ಯದಿ (srks == ರಿಕ್ತ || nsrks == 0)
		ಪ್ರತ್ಯಾಗಮ;

	ಪ್ರತಿ (i = 0; i < nsrks; i++)
		sshsk_free_resident_ಕೀಲಿ(srks[i]);
	ಮುಕ್ತ(srks);
}

ಪೂರ್ಣಾಙ್ಕ
sshsk_load_resident(ಧ್ರುವ ವರ್ಣ *provider_path, ಧ್ರುವ ವರ್ಣ *device,
    ಧ್ರುವ ವರ್ಣ *pin, u_int flags, ಸಂರಚನಾ sshsk_resident_ಕೀಲಿ ***srksp,
    size_t *nsrksp)
{
	ಸಂರಚನಾ sshsk_provider *skp = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ r = SSH_ERR_INTERNAL_ERROR;
	ಸಂರಚನಾ sk_resident_ಕೀಲಿ **rks = ರಿಕ್ತ;
	size_t i, nrks = 0, nsrks = 0;
	ಸಂರಚನಾ sshkey *ಕೀಲಿ = ರಿಕ್ತ;
	ಸಂರಚನಾ sshsk_resident_ಕೀಲಿ *srk = ರಿಕ್ತ, **srks = ರಿಕ್ತ, **tmp;
	uint8_t sk_flags;
	ಸಂರಚನಾ sk_option **opts = ರಿಕ್ತ;

	debug_f("provider \"%s\"%s", provider_path,
	    (pin != ರಿಕ್ತ && *pin != '\0') ? ", have-pin": "");

	ಯದಿ (srksp == ರಿಕ್ತ || nsrksp == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ SSH_ERR_INVALID_ARGUMENT;
	*srksp = ರಿಕ್ತ;
	*nsrksp = 0;

	ಯದಿ ((r = make_options(device, ರಿಕ್ತ, &opts)) != 0)
		ಗಚ್ಛ out;
	ಯದಿ ((skp = sshsk_open(provider_path)) == ರಿಕ್ತ) {
		r = SSH_ERR_INVALID_FORMAT; /* XXX sshsk_open return code? */
		ಗಚ್ಛ out;
	}
	ಯದಿ ((r = skp->sk_load_resident_ಕೀಲಿಗಳು(pin, opts, &rks, &nrks)) != 0) {
		error("Provider \"%s\" returned failure %d", provider_path, r);
		r = skerr_to_ssherr(r);
		ಗಚ್ಛ out;
	}
	ಪ್ರತಿ (i = 0; i < nrks; i++) {
		debug3_f("rk %zu: slot %zu, alg %d, app \"%s\", uidlen %zu",
		    i, rks[i]->slot, rks[i]->alg, rks[i]->application,
		    rks[i]->user_id_len);
		/* XXX need better filter here */
		ಯದಿ (strncmp(rks[i]->application, "ssh:", 4) != 0)
			ಅನುವರ್ತ;
		ವಿಕಲ್ಪ (rks[i]->alg) {
		ಪಕ್ಷ SSH_SK_ECDSA:
		ಪಕ್ಷ SSH_SK_ED25519:
			ಭಙ್ಗ;
		ಸ್ವಭಾವ:
			ಅನುವರ್ತ;
		}
		sk_flags = SSH_SK_USER_PRESENCE_REQD|SSH_SK_RESIDENT_ಕೀಲಿ;
		ಯದಿ ((rks[i]->flags & SSH_SK_USER_VERIFICATION_REQD))
			sk_flags |= SSH_SK_USER_VERIFICATION_REQD;
		ಯದಿ ((r = sshsk_ಕೀಲಿ_from_response(rks[i]->alg,
		    rks[i]->application, sk_flags, &rks[i]->ಕೀಲಿ, &ಕೀಲಿ)) != 0)
			ಗಚ್ಛ out;
		ಯದಿ ((srk = calloc(1, ಪರಿಮಾಣ(*srk))) == ರಿಕ್ತ) {
			error_f("calloc failed");
			r = SSH_ERR_ALLOC_FAIL;
			ಗಚ್ಛ out;
		}
		srk->ಕೀಲಿ = ಕೀಲಿ;
		ಕೀಲಿ = ರಿಕ್ತ; /* transferred */
		ಯದಿ ((srk->user_id = calloc(1, rks[i]->user_id_len)) == ರಿಕ್ತ) {
			error_f("calloc failed");
			r = SSH_ERR_ALLOC_FAIL;
			ಗಚ್ಛ out;
		}
		memcpy(srk->user_id, rks[i]->user_id, rks[i]->user_id_len);
		srk->user_id_len = rks[i]->user_id_len;
		ಯದಿ ((tmp = recallocarray(srks, nsrks, nsrks + 1,
		    ಪರಿಮಾಣ(*tmp))) == ರಿಕ್ತ) {
			error_f("recallocarray failed");
			r = SSH_ERR_ALLOC_FAIL;
			ಗಚ್ಛ out;
		}
		srks = tmp;
		srks[nsrks++] = srk;
		srk = ರಿಕ್ತ;
		/* XXX synthesise comment */
	}
	/* success */
	*srksp = srks;
	*nsrksp = nsrks;
	srks = ರಿಕ್ತ;
	nsrks = 0;
	r = 0;
 out:
	sshsk_free_options(opts);
	sshsk_free(skp);
	sshsk_free_sk_resident_ಕೀಲಿಗಳು(rks, nrks);
	sshkey_free(ಕೀಲಿ);
	sshsk_free_resident_ಕೀಲಿ(srk);
	sshsk_free_resident_ಕೀಲಿಗಳು(srks, nsrks);
	ಪ್ರತ್ಯಾಗಮ r;
}

#endif /* ENABLE_SK */
