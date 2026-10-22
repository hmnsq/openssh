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

#അന്തര്ഭാവ "includes.h"

#ifdef ENABLE_SK

#അന്തര്ഭാവ <dlfcn.h>
#അന്തര്ഭാവ <stddef.h>
#അന്തര്ഭാവ <stdint.h>
#അന്തര്ഭാവ <string.h>
#അന്തര്ഭാവ <stdio.h>

#ifdef WITH_OPENSSL
#അന്തര്ഭാവ <openssl/objects.h>
#അന്തര്ഭാവ <openssl/ec.h>
#അന്തര്ഭാവ <openssl/evp.h>
#endif /* WITH_OPENSSL */

#അന്തര്ഭാവ "log.h"
#അന്തര്ഭാവ "misc.h"
#അന്തര്ഭാവ "sshbuf.h"
#അന്തര്ഭാവ "sshkey.h"
#അന്തര്ഭാവ "ssherr.h"
#അന്തര്ഭാവ "digest.h"

#അന്തര്ഭാവ "ssh-sk.h"
#അന്തര്ഭാവ "sk-api.h"
#അന്തര്ഭാവ "crypto_api.h"

ഘടന sshsk_provider {
	അക്ഷരം *path;
	ശൂന്യം *dlhandle;

	/* Return the version of the middleware API */
	uint32_t (*sk_api_version)(ശൂന്യം);

	/* Enroll a U2F key (private key generation) */
	പൂർണ്ണസംഖ്യ (*sk_enroll)(പൂർണ്ണസംഖ്യ alg, സ്ഥിരം uint8_t *challenge,
	    size_t challenge_len, സ്ഥിരം അക്ഷരം *application, uint8_t flags,
	    സ്ഥിരം അക്ഷരം *pin, ഘടന sk_option **opts,
	    ഘടന sk_enroll_response **enroll_response);

	/* Sign a challenge */
	പൂർണ്ണസംഖ്യ (*sk_sign)(പൂർണ്ണസംഖ്യ alg, സ്ഥിരം uint8_t *message, size_t message_len,
	    സ്ഥിരം അക്ഷരം *application,
	    സ്ഥിരം uint8_t *താക്കോൽ_handle, size_t താക്കോൽ_handle_len,
	    uint8_t flags, സ്ഥിരം അക്ഷരം *pin, ഘടന sk_option **opts,
	    ഘടന sk_sign_response **sign_response);

	/* Enumerate resident keys */
	പൂർണ്ണസംഖ്യ (*sk_load_resident_താക്കോലുകൾ)(സ്ഥിരം അക്ഷരം *pin, ഘടന sk_option **opts,
	    ഘടന sk_resident_താക്കോൽ ***rks, size_t *nrks);
};

/* Built-in version */
പൂർണ്ണസംഖ്യ ssh_sk_enroll(പൂർണ്ണസംഖ്യ alg, സ്ഥിരം uint8_t *challenge,
    size_t challenge_len, സ്ഥിരം അക്ഷരം *application, uint8_t flags,
    സ്ഥിരം അക്ഷരം *pin, ഘടന sk_option **opts,
    ഘടന sk_enroll_response **enroll_response);
പൂർണ്ണസംഖ്യ ssh_sk_sign(പൂർണ്ണസംഖ്യ alg, സ്ഥിരം uint8_t *message, size_t message_len,
    സ്ഥിരം അക്ഷരം *application,
    സ്ഥിരം uint8_t *താക്കോൽ_handle, size_t താക്കോൽ_handle_len,
    uint8_t flags, സ്ഥിരം അക്ഷരം *pin, ഘടന sk_option **opts,
    ഘടന sk_sign_response **sign_response);
പൂർണ്ണസംഖ്യ ssh_sk_load_resident_താക്കോലുകൾ(സ്ഥിരം അക്ഷരം *pin, ഘടന sk_option **opts,
    ഘടന sk_resident_താക്കോൽ ***rks, size_t *nrks);

സ്ഥിതം ശൂന്യം
sshsk_free(ഘടന sshsk_provider *p)
{
	എങ്കിൽ (p == ശൂന്യ)
		തിരികെ;
	സ്വതന്ത്രം(p->path);
	എങ്കിൽ (p->dlhandle != ശൂന്യ)
		dlclose(p->dlhandle);
	സ്വതന്ത്രം(p);
}

സ്ഥിതം ഘടന sshsk_provider *
sshsk_open(സ്ഥിരം അക്ഷരം *path)
{
	ഘടന sshsk_provider *ret = ശൂന്യ;
	uint32_t version;

	എങ്കിൽ (path == ശൂന്യ || *path == '\0') {
		error("No FIDO SecurityKeyProvider specified");
		തിരികെ ശൂന്യ;
	}
	എങ്കിൽ ((ret = calloc(1, വലുപ്പം(*ret))) == ശൂന്യ) {
		error_f("calloc failed");
		തിരികെ ശൂന്യ;
	}
	എങ്കിൽ ((ret->path = strdup(path)) == ശൂന്യ) {
		error_f("strdup failed");
		പോകുക fail;
	}
	/* Skip the rest if we're using the linked in middleware */
	എങ്കിൽ (strcasecmp(ret->path, "internal") == 0) {
#ifdef ENABLE_SK_INTERNAL
		ret->sk_enroll = ssh_sk_enroll;
		ret->sk_sign = ssh_sk_sign;
		ret->sk_load_resident_താക്കോലുകൾ = ssh_sk_load_resident_താക്കോലുകൾ;
		തിരികെ ret;
#അല്ലെങ്കിൽ
		error("internal security key support not enabled");
		പോകുക fail;
#endif
	}
	എങ്കിൽ (lib_contains_ചിഹ്നം(path, "sk_api_version") != 0) {
		error("provider %s is not an OpenSSH FIDO library", path);
		പോകുക fail;
	}
	എങ്കിൽ ((ret->dlhandle = dlopen(path, RTLD_NOW)) == ശൂന്യ)
		fatal("Provider \"%s\" dlopen failed: %s", path, dlerror());
	എങ്കിൽ ((ret->sk_api_version = dlsym(ret->dlhandle,
	    "sk_api_version")) == ശൂന്യ) {
		error("Provider \"%s\" dlsym(sk_api_version) failed: %s",
		    path, dlerror());
		പോകുക fail;
	}
	version = ret->sk_api_version();
	debug_f("provider %s implements version 0x%08lx", ret->path,
	    (u_long)version);
	എങ്കിൽ ((version & SSH_SK_VERSION_MAJOR_MASK) != SSH_SK_VERSION_MAJOR) {
		error("Provider \"%s\" implements unsupported "
		    "version 0x%08lx (supported: 0x%08lx)",
		    path, (u_long)version, (u_long)SSH_SK_VERSION_MAJOR);
		പോകുക fail;
	}
	എങ്കിൽ ((ret->sk_enroll = dlsym(ret->dlhandle, "sk_enroll")) == ശൂന്യ) {
		error("Provider %s dlsym(sk_enroll) failed: %s",
		    path, dlerror());
		പോകുക fail;
	}
	എങ്കിൽ ((ret->sk_sign = dlsym(ret->dlhandle, "sk_sign")) == ശൂന്യ) {
		error("Provider \"%s\" dlsym(sk_sign) failed: %s",
		    path, dlerror());
		പോകുക fail;
	}
	എങ്കിൽ ((ret->sk_load_resident_താക്കോലുകൾ = dlsym(ret->dlhandle,
	    "sk_load_resident_keys")) == ശൂന്യ) {
		error("Provider \"%s\" dlsym(sk_load_resident_keys) "
		    "failed: %s", path, dlerror());
		പോകുക fail;
	}
	/* success */
	തിരികെ ret;
fail:
	sshsk_free(ret);
	തിരികെ ശൂന്യ;
}

സ്ഥിതം ശൂന്യം
sshsk_free_enroll_response(ഘടന sk_enroll_response *r)
{
	എങ്കിൽ (r == ശൂന്യ)
		തിരികെ;
	freezero(r->താക്കോൽ_handle, r->താക്കോൽ_handle_len);
	freezero(r->public_താക്കോൽ, r->public_താക്കോൽ_len);
	freezero(r->signature, r->signature_len);
	freezero(r->attestation_cert, r->attestation_cert_len);
	freezero(r->authdata, r->authdata_len);
	freezero(r, വലുപ്പം(*r));
}

സ്ഥിതം ശൂന്യം
sshsk_free_sign_response(ഘടന sk_sign_response *r)
{
	എങ്കിൽ (r == ശൂന്യ)
		തിരികെ;
	freezero(r->sig_r, r->sig_r_len);
	freezero(r->sig_s, r->sig_s_len);
	freezero(r, വലുപ്പം(*r));
}

#ifdef WITH_OPENSSL
/* Assemble key from response */
സ്ഥിതം പൂർണ്ണസംഖ്യ
sshsk_ecdsa_assemble(ഘടന sk_enroll_response *resp, ഘടന sshkey **keyp)
{
	ഘടന sshkey *താക്കോൽ = ശൂന്യ;
	ഘടന sshbuf *b = ശൂന്യ;
	EC_താക്കോൽ *ecdsa = ശൂന്യ;
	EC_POINT *q = ശൂന്യ;
	സ്ഥിരം EC_GROUP *g = ശൂന്യ;
	പൂർണ്ണസംഖ്യ r;

	*keyp = ശൂന്യ;
	എങ്കിൽ ((താക്കോൽ = sshkey_new(താക്കോൽ_ECDSA_SK)) == ശൂന്യ) {
		error_f("sshkey_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		പോകുക out;
	}
	താക്കോൽ->ecdsa_nid = NID_X9_62_prime256v1;
	എങ്കിൽ ((ecdsa = EC_താക്കോൽ_new_by_curve_name(താക്കോൽ->ecdsa_nid)) == ശൂന്യ ||
	    (g = EC_താക്കോൽ_get0_group(ecdsa)) == ശൂന്യ ||
	    (q = EC_POINT_new(g)) == ശൂന്യ ||
	    (b = sshbuf_new()) == ശൂന്യ) {
		error_f("allocation failed");
		r = SSH_ERR_ALLOC_FAIL;
		പോകുക out;
	}
	എങ്കിൽ ((r = sshbuf_put_string(b,
	    resp->public_താക്കോൽ, resp->public_താക്കോൽ_len)) != 0) {
		error_fr(r, "sshbuf_put_string");
		പോകുക out;
	}
	എങ്കിൽ ((r = sshbuf_get_ec(b, q, g)) != 0) {
		error_fr(r, "parse");
		r = SSH_ERR_INVALID_FORMAT;
		പോകുക out;
	}
	എങ്കിൽ (sshkey_ec_validate_public(g, q) != 0) {
		error("Authenticator returned invalid ECDSA key");
		r = SSH_ERR_താക്കോൽ_INVALID_EC_മൂല്യം;
		പോകുക out;
	}
	എങ്കിൽ (EC_താക്കോൽ_set_public_താക്കോൽ(ecdsa, q) != 1) {
		/* XXX assume it is a allocation error */
		error_f("allocation failed");
		r = SSH_ERR_ALLOC_FAIL;
		പോകുക out;
	}
	എങ്കിൽ ((താക്കോൽ->pkey = EVP_PKEY_new()) == ശൂന്യ) {
		error_f("allocation failed");
		r = SSH_ERR_ALLOC_FAIL;
		പോകുക out;
	}
	എങ്കിൽ (EVP_PKEY_set1_EC_താക്കോൽ(താക്കോൽ->pkey, ecdsa) != 1) {
		error_f("Assigning EC_KEY failed");
		r = SSH_ERR_LIBCRYPTO_ERROR;
		പോകുക out;
	}
	/* success */
	*keyp = താക്കോൽ;
	താക്കോൽ = ശൂന്യ; /* transferred */
	r = 0;
 out:
	sshkey_free(താക്കോൽ);
	sshbuf_free(b);
	EC_താക്കോൽ_free(ecdsa);
	EC_POINT_free(q);
	തിരികെ r;
}
#endif /* WITH_OPENSSL */

സ്ഥിതം പൂർണ്ണസംഖ്യ
sshsk_ed25519_assemble(ഘടന sk_enroll_response *resp, ഘടന sshkey **keyp)
{
	ഘടന sshkey *താക്കോൽ = ശൂന്യ;
	പൂർണ്ണസംഖ്യ r;

	*keyp = ശൂന്യ;
	എങ്കിൽ (resp->public_താക്കോൽ_len != ED25519_PK_SZ) {
		error_f("invalid size: %zu", resp->public_താക്കോൽ_len);
		r = SSH_ERR_INVALID_FORMAT;
		പോകുക out;
	}
	എങ്കിൽ ((താക്കോൽ = sshkey_new(താക്കോൽ_ED25519_SK)) == ശൂന്യ) {
		error_f("sshkey_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		പോകുക out;
	}
	എങ്കിൽ ((താക്കോൽ->ed25519_pk = malloc(ED25519_PK_SZ)) == ശൂന്യ) {
		error_f("malloc failed");
		r = SSH_ERR_ALLOC_FAIL;
		പോകുക out;
	}
	memcpy(താക്കോൽ->ed25519_pk, resp->public_താക്കോൽ, ED25519_PK_SZ);
	/* success */
	*keyp = താക്കോൽ;
	താക്കോൽ = ശൂന്യ; /* transferred */
	r = 0;
 out:
	sshkey_free(താക്കോൽ);
	തിരികെ r;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
sshsk_താക്കോൽ_from_response(പൂർണ്ണസംഖ്യ alg, സ്ഥിരം അക്ഷരം *application, uint8_t flags,
    ഘടന sk_enroll_response *resp, ഘടന sshkey **keyp)
{
	ഘടന sshkey *താക്കോൽ = ശൂന്യ;
	പൂർണ്ണസംഖ്യ r = SSH_ERR_INTERNAL_ERROR;

	*keyp = ശൂന്യ;

	/* Check response validity */
	എങ്കിൽ (resp->public_താക്കോൽ == ശൂന്യ || resp->താക്കോൽ_handle == ശൂന്യ) {
		error_f("sk_enroll response invalid");
		r = SSH_ERR_INVALID_FORMAT;
		പോകുക out;
	}
	തിരഞ്ഞെടുപ്പ് (alg) {
#ifdef WITH_OPENSSL
	അവസ്ഥ SSH_SK_ECDSA:
		എങ്കിൽ ((r = sshsk_ecdsa_assemble(resp, &താക്കോൽ)) != 0)
			പോകുക out;
		നിർത്തുക;
#endif /* WITH_OPENSSL */
	അവസ്ഥ SSH_SK_ED25519:
		എങ്കിൽ ((r = sshsk_ed25519_assemble(resp, &താക്കോൽ)) != 0)
			പോകുക out;
		നിർത്തുക;
	സ്ഥിരസ്ഥിതി:
		error_f("unsupported algorithm %d", alg);
		r = SSH_ERR_INVALID_ARGUMENT;
		പോകുക out;
	}
	താക്കോൽ->sk_flags = flags;
	എങ്കിൽ ((താക്കോൽ->sk_താക്കോൽ_handle = sshbuf_new()) == ശൂന്യ ||
	    (താക്കോൽ->sk_reserved = sshbuf_new()) == ശൂന്യ) {
		error_f("allocation failed");
		r = SSH_ERR_ALLOC_FAIL;
		പോകുക out;
	}
	എങ്കിൽ ((താക്കോൽ->sk_application = strdup(application)) == ശൂന്യ) {
		error_f("strdup application failed");
		r = SSH_ERR_ALLOC_FAIL;
		പോകുക out;
	}
	എങ്കിൽ ((r = sshbuf_put(താക്കോൽ->sk_താക്കോൽ_handle, resp->താക്കോൽ_handle,
	    resp->താക്കോൽ_handle_len)) != 0) {
		error_fr(r, "put key handle");
		പോകുക out;
	}
	/* success */
	r = 0;
	*keyp = താക്കോൽ;
	താക്കോൽ = ശൂന്യ;
 out:
	sshkey_free(താക്കോൽ);
	തിരികെ r;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
skerr_to_ssherr(പൂർണ്ണസംഖ്യ skerr)
{
	തിരഞ്ഞെടുപ്പ് (skerr) {
	അവസ്ഥ SSH_SK_ERR_UNSUPPORTED:
		തിരികെ SSH_ERR_FEATURE_UNSUPPORTED;
	അവസ്ഥ SSH_SK_ERR_PIN_REQUIRED:
		തിരികെ SSH_ERR_താക്കോൽ_WRONG_PASSPHRASE;
	അവസ്ഥ SSH_SK_ERR_DEVICE_NOT_FOUND:
		തിരികെ SSH_ERR_DEVICE_NOT_FOUND;
	അവസ്ഥ SSH_SK_ERR_CREDENTIAL_EXISTS:
		തിരികെ SSH_ERR_താക്കോൽ_BAD_PERMISSIONS;
	അവസ്ഥ SSH_SK_ERR_GENERAL:
	സ്ഥിരസ്ഥിതി:
		തിരികെ SSH_ERR_INVALID_FORMAT;
	}
}

സ്ഥിതം ശൂന്യം
sshsk_free_options(ഘടന sk_option **opts)
{
	size_t i;

	എങ്കിൽ (opts == ശൂന്യ)
		തിരികെ;
	വേണ്ടി (i = 0; opts[i] != ശൂന്യ; i++) {
		സ്വതന്ത്രം(opts[i]->name);
		സ്വതന്ത്രം(opts[i]->മൂല്യം);
		സ്വതന്ത്രം(opts[i]);
	}
	സ്വതന്ത്രം(opts);
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
sshsk_add_option(ഘടന sk_option ***optsp, size_t *noptsp,
    സ്ഥിരം അക്ഷരം *name, സ്ഥിരം അക്ഷരം *മൂല്യം, uint8_t required)
{
	ഘടന sk_option **opts = *optsp;
	size_t nopts = *noptsp;

	എങ്കിൽ ((opts = recallocarray(opts, nopts, nopts + 2, /* extra for NULL */
	    വലുപ്പം(*opts))) == ശൂന്യ) {
		error_f("array alloc failed");
		തിരികെ SSH_ERR_ALLOC_FAIL;
	}
	*optsp = opts;
	*noptsp = nopts + 1;
	എങ്കിൽ ((opts[nopts] = calloc(1, വലുപ്പം(**opts))) == ശൂന്യ) {
		error_f("alloc failed");
		തിരികെ SSH_ERR_ALLOC_FAIL;
	}
	എങ്കിൽ ((opts[nopts]->name = strdup(name)) == ശൂന്യ ||
	    (opts[nopts]->മൂല്യം = strdup(മൂല്യം)) == ശൂന്യ) {
		error_f("alloc failed");
		തിരികെ SSH_ERR_ALLOC_FAIL;
	}
	opts[nopts]->required = required;
	തിരികെ 0;
}

സ്ഥിതം പൂർണ്ണസംഖ്യ
make_options(സ്ഥിരം അക്ഷരം *device, സ്ഥിരം അക്ഷരം *user_id,
    ഘടന sk_option ***optsp)
{
	ഘടന sk_option **opts = ശൂന്യ;
	size_t nopts = 0;
	പൂർണ്ണസംഖ്യ r, ret = SSH_ERR_INTERNAL_ERROR;

	എങ്കിൽ (device != ശൂന്യ &&
	    (r = sshsk_add_option(&opts, &nopts, "device", device, 0)) != 0) {
		ret = r;
		പോകുക out;
	}
	എങ്കിൽ (user_id != ശൂന്യ &&
	    (r = sshsk_add_option(&opts, &nopts, "user", user_id, 0)) != 0) {
		ret = r;
		പോകുക out;
	}
	/* success */
	*optsp = opts;
	opts = ശൂന്യ;
	nopts = 0;
	ret = 0;
 out:
	sshsk_free_options(opts);
	തിരികെ ret;
}


സ്ഥിതം പൂർണ്ണസംഖ്യ
fill_attestation_blob(സ്ഥിരം ഘടന sk_enroll_response *resp,
    ഘടന sshbuf *attest)
{
	പൂർണ്ണസംഖ്യ r;

	എങ്കിൽ (attest == ശൂന്യ)
		തിരികെ 0; /* nothing to do */
	എങ്കിൽ ((r = sshbuf_put_cstring(attest, "ssh-sk-attest-v01")) != 0 ||
	    (r = sshbuf_put_string(attest,
	    resp->attestation_cert, resp->attestation_cert_len)) != 0 ||
	    (r = sshbuf_put_string(attest,
	    resp->signature, resp->signature_len)) != 0 ||
	    (r = sshbuf_put_string(attest,
	    resp->authdata, resp->authdata_len)) != 0 ||
	    (r = sshbuf_put_u32(attest, 0)) != 0 || /* resvd flags */
	    (r = sshbuf_put_string(attest, ശൂന്യ, 0)) != 0 /* resvd */) {
		error_fr(r, "compose");
		തിരികെ r;
	}
	/* success */
	തിരികെ 0;
}

പൂർണ്ണസംഖ്യ
sshsk_enroll(പൂർണ്ണസംഖ്യ type, സ്ഥിരം അക്ഷരം *provider_path, സ്ഥിരം അക്ഷരം *device,
    സ്ഥിരം അക്ഷരം *application, സ്ഥിരം അക്ഷരം *userid, uint8_t flags,
    സ്ഥിരം അക്ഷരം *pin, ഘടന sshbuf *challenge_buf,
    ഘടന sshkey **keyp, ഘടന sshbuf *attest)
{
	ഘടന sshsk_provider *skp = ശൂന്യ;
	ഘടന sshkey *താക്കോൽ = ശൂന്യ;
	u_char randchall[32];
	സ്ഥിരം u_char *challenge;
	size_t challenge_len;
	ഘടന sk_enroll_response *resp = ശൂന്യ;
	ഘടന sk_option **opts = ശൂന്യ;
	പൂർണ്ണസംഖ്യ r = SSH_ERR_INTERNAL_ERROR;
	പൂർണ്ണസംഖ്യ alg;

	debug_f("provider \"%s\", device \"%s\", application \"%s\", "
	    "userid \"%s\", flags 0x%02x, challenge len %zu%s",
	    provider_path, device, application, userid, flags,
	    challenge_buf == ശൂന്യ ? 0 : sshbuf_len(challenge_buf),
	    (pin != ശൂന്യ && *pin != '\0') ? " with-pin" : "");

	*keyp = ശൂന്യ;
	എങ്കിൽ (attest)
		sshbuf_reset(attest);

	എങ്കിൽ ((r = make_options(device, userid, &opts)) != 0)
		പോകുക out;

	തിരഞ്ഞെടുപ്പ് (type) {
#ifdef WITH_OPENSSL
	അവസ്ഥ താക്കോൽ_ECDSA_SK:
		alg = SSH_SK_ECDSA;
		നിർത്തുക;
#endif /* WITH_OPENSSL */
	അവസ്ഥ താക്കോൽ_ED25519_SK:
		alg = SSH_SK_ED25519;
		നിർത്തുക;
	സ്ഥിരസ്ഥിതി:
		error_f("unsupported key type");
		r = SSH_ERR_INVALID_ARGUMENT;
		പോകുക out;
	}
	എങ്കിൽ (provider_path == ശൂന്യ) {
		error_f("missing provider");
		r = SSH_ERR_INVALID_ARGUMENT;
		പോകുക out;
	}
	എങ്കിൽ (application == ശൂന്യ || *application == '\0') {
		error_f("missing application");
		r = SSH_ERR_INVALID_ARGUMENT;
		പോകുക out;
	}
	എങ്കിൽ (challenge_buf == ശൂന്യ) {
		debug_f("using random challenge");
		arc4random_buf(randchall, വലുപ്പം(randchall));
		challenge = randchall;
		challenge_len = വലുപ്പം(randchall);
	} അല്ലെങ്കിൽ എങ്കിൽ (sshbuf_len(challenge_buf) == 0) {
		error("Missing enrollment challenge");
		r = SSH_ERR_INVALID_ARGUMENT;
		പോകുക out;
	} അല്ലെങ്കിൽ {
		challenge = sshbuf_ptr(challenge_buf);
		challenge_len = sshbuf_len(challenge_buf);
		debug3_f("using explicit challenge len=%zd", challenge_len);
	}
	എങ്കിൽ ((skp = sshsk_open(provider_path)) == ശൂന്യ) {
		r = SSH_ERR_INVALID_FORMAT; /* XXX sshsk_open return code? */
		പോകുക out;
	}
	/* XXX validate flags? */
	/* enroll key */
	എങ്കിൽ ((r = skp->sk_enroll(alg, challenge, challenge_len, application,
	    flags, pin, opts, &resp)) != 0) {
		debug_f("provider \"%s\" failure %d", provider_path, r);
		r = skerr_to_ssherr(r);
		പോകുക out;
	}

	എങ്കിൽ ((r = sshsk_താക്കോൽ_from_response(alg, application, resp->flags,
	    resp, &താക്കോൽ)) != 0)
		പോകുക out;

	/* Optionally fill in the attestation information */
	എങ്കിൽ ((r = fill_attestation_blob(resp, attest)) != 0)
		പോകുക out;

	/* success */
	*keyp = താക്കോൽ;
	താക്കോൽ = ശൂന്യ; /* transferred */
	r = 0;
 out:
	sshsk_free_options(opts);
	sshsk_free(skp);
	sshkey_free(താക്കോൽ);
	sshsk_free_enroll_response(resp);
	explicit_bzero(randchall, വലുപ്പം(randchall));
	തിരികെ r;
}

#ifdef WITH_OPENSSL
സ്ഥിതം പൂർണ്ണസംഖ്യ
sshsk_ecdsa_sig(ഘടന sk_sign_response *resp, ഘടന sshbuf *sig)
{
	ഘടന sshbuf *inner_sig = ശൂന്യ;
	പൂർണ്ണസംഖ്യ r = SSH_ERR_INTERNAL_ERROR;

	/* Check response validity */
	എങ്കിൽ (resp->sig_r == ശൂന്യ || resp->sig_s == ശൂന്യ) {
		error_f("sk_sign response invalid");
		r = SSH_ERR_INVALID_FORMAT;
		പോകുക out;
	}
	എങ്കിൽ ((inner_sig = sshbuf_new()) == ശൂന്യ) {
		r = SSH_ERR_ALLOC_FAIL;
		പോകുക out;
	}
	/* Prepare and append inner signature object */
	എങ്കിൽ ((r = sshbuf_put_bignum2_bytes(inner_sig,
	    resp->sig_r, resp->sig_r_len)) != 0 ||
	    (r = sshbuf_put_bignum2_bytes(inner_sig,
	    resp->sig_s, resp->sig_s_len)) != 0) {
		error_fr(r, "compose inner");
		പോകുക out;
	}
	എങ്കിൽ ((r = sshbuf_put_stringb(sig, inner_sig)) != 0 ||
	    (r = sshbuf_put_u8(sig, resp->flags)) != 0 ||
	    (r = sshbuf_put_u32(sig, resp->counter)) != 0) {
		error_fr(r, "compose");
		പോകുക out;
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
	തിരികെ r;
}
#endif /* WITH_OPENSSL */

സ്ഥിതം പൂർണ്ണസംഖ്യ
sshsk_ed25519_sig(ഘടന sk_sign_response *resp, ഘടന sshbuf *sig)
{
	പൂർണ്ണസംഖ്യ r = SSH_ERR_INTERNAL_ERROR;

	/* Check response validity */
	എങ്കിൽ (resp->sig_r == ശൂന്യ) {
		error_f("sk_sign response invalid");
		r = SSH_ERR_INVALID_FORMAT;
		പോകുക out;
	}
	എങ്കിൽ ((r = sshbuf_put_string(sig,
	    resp->sig_r, resp->sig_r_len)) != 0 ||
	    (r = sshbuf_put_u8(sig, resp->flags)) != 0 ||
	    (r = sshbuf_put_u32(sig, resp->counter)) != 0) {
		error_fr(r, "compose");
		പോകുക out;
	}
#ifdef DEBUG_SK
	fprintf(stderr, "%s: sig_r:\n", __func__);
	sshbuf_dump_data(resp->sig_r, resp->sig_r_len, stderr);
#endif
	r = 0;
 out:
	തിരികെ r;
}

പൂർണ്ണസംഖ്യ
sshsk_sign(സ്ഥിരം അക്ഷരം *provider_path, ഘടന sshkey *താക്കോൽ,
    u_char **sigp, size_t *lenp, സ്ഥിരം u_char *data, size_t datalen,
    u_int compat, സ്ഥിരം അക്ഷരം *pin)
{
	ഘടന sshsk_provider *skp = ശൂന്യ;
	പൂർണ്ണസംഖ്യ r = SSH_ERR_INTERNAL_ERROR;
	പൂർണ്ണസംഖ്യ type, alg;
	ഘടന sk_sign_response *resp = ശൂന്യ;
	ഘടന sshbuf *inner_sig = ശൂന്യ, *sig = ശൂന്യ;
	ഘടന sk_option **opts = ശൂന്യ;

	debug_f("provider \"%s\", key %s, flags 0x%02x%s",
	    provider_path, sshkey_type(താക്കോൽ), താക്കോൽ->sk_flags,
	    (pin != ശൂന്യ && *pin != '\0') ? " with-pin" : "");

	എങ്കിൽ (sigp != ശൂന്യ)
		*sigp = ശൂന്യ;
	എങ്കിൽ (lenp != ശൂന്യ)
		*lenp = 0;
	type = sshkey_type_plain(താക്കോൽ->type);
	തിരഞ്ഞെടുപ്പ് (type) {
#ifdef WITH_OPENSSL
	അവസ്ഥ താക്കോൽ_ECDSA_SK:
		alg = SSH_SK_ECDSA;
		നിർത്തുക;
#endif /* WITH_OPENSSL */
	അവസ്ഥ താക്കോൽ_ED25519_SK:
		alg = SSH_SK_ED25519;
		നിർത്തുക;
	സ്ഥിരസ്ഥിതി:
		തിരികെ SSH_ERR_INVALID_ARGUMENT;
	}
	എങ്കിൽ (provider_path == ശൂന്യ ||
	    താക്കോൽ->sk_താക്കോൽ_handle == ശൂന്യ ||
	    താക്കോൽ->sk_application == ശൂന്യ || *താക്കോൽ->sk_application == '\0') {
		r = SSH_ERR_INVALID_ARGUMENT;
		പോകുക out;
	}
	എങ്കിൽ ((skp = sshsk_open(provider_path)) == ശൂന്യ) {
		r = SSH_ERR_INVALID_FORMAT; /* XXX sshsk_open return code? */
		പോകുക out;
	}
#ifdef DEBUG_SK
	fprintf(stderr, "%s: sk_flags = 0x%02x, sk_application = \"%s\"\n",
	    __func__, താക്കോൽ->sk_flags, താക്കോൽ->sk_application);
	fprintf(stderr, "%s: sk_key_handle:\n", __func__);
	sshbuf_dump(താക്കോൽ->sk_താക്കോൽ_handle, stderr);
#endif
	എങ്കിൽ ((r = skp->sk_sign(alg, data, datalen, താക്കോൽ->sk_application,
	    sshbuf_ptr(താക്കോൽ->sk_താക്കോൽ_handle), sshbuf_len(താക്കോൽ->sk_താക്കോൽ_handle),
	    താക്കോൽ->sk_flags, pin, opts, &resp)) != 0) {
		debug_f("sk_sign failed with code %d", r);
		r = skerr_to_ssherr(r);
		പോകുക out;
	}
	/* Assemble signature */
	എങ്കിൽ ((sig = sshbuf_new()) == ശൂന്യ) {
		r = SSH_ERR_ALLOC_FAIL;
		പോകുക out;
	}
	എങ്കിൽ ((r = sshbuf_put_cstring(sig, sshkey_ssh_name_plain(താക്കോൽ))) != 0) {
		error_fr(r, "compose outer");
		പോകുക out;
	}
	തിരഞ്ഞെടുപ്പ് (type) {
#ifdef WITH_OPENSSL
	അവസ്ഥ താക്കോൽ_ECDSA_SK:
		എങ്കിൽ ((r = sshsk_ecdsa_sig(resp, sig)) != 0)
			പോകുക out;
		നിർത്തുക;
#endif /* WITH_OPENSSL */
	അവസ്ഥ താക്കോൽ_ED25519_SK:
		എങ്കിൽ ((r = sshsk_ed25519_sig(resp, sig)) != 0)
			പോകുക out;
		നിർത്തുക;
	}
#ifdef DEBUG_SK
	fprintf(stderr, "%s: sig_flags = 0x%02x, sig_counter = %u\n",
	    __func__, resp->flags, resp->counter);
	fprintf(stderr, "%s: data to sign:\n", __func__);
	sshbuf_dump_data(data, datalen, stderr);
	fprintf(stderr, "%s: sigbuf:\n", __func__);
	sshbuf_dump(sig, stderr);
#endif
	എങ്കിൽ (sigp != ശൂന്യ) {
		എങ്കിൽ ((*sigp = malloc(sshbuf_len(sig))) == ശൂന്യ) {
			r = SSH_ERR_ALLOC_FAIL;
			പോകുക out;
		}
		memcpy(*sigp, sshbuf_ptr(sig), sshbuf_len(sig));
	}
	എങ്കിൽ (lenp != ശൂന്യ)
		*lenp = sshbuf_len(sig);
	/* success */
	r = 0;
 out:
	sshsk_free_options(opts);
	sshsk_free(skp);
	sshsk_free_sign_response(resp);
	sshbuf_free(sig);
	sshbuf_free(inner_sig);
	തിരികെ r;
}

സ്ഥിതം ശൂന്യം
sshsk_free_sk_resident_താക്കോലുകൾ(ഘടന sk_resident_താക്കോൽ **rks, size_t nrks)
{
	size_t i;

	എങ്കിൽ (nrks == 0 || rks == ശൂന്യ)
		തിരികെ;
	വേണ്ടി (i = 0; i < nrks; i++) {
		സ്വതന്ത്രം(rks[i]->application);
		freezero(rks[i]->user_id, rks[i]->user_id_len);
		freezero(rks[i]->താക്കോൽ.താക്കോൽ_handle, rks[i]->താക്കോൽ.താക്കോൽ_handle_len);
		freezero(rks[i]->താക്കോൽ.public_താക്കോൽ, rks[i]->താക്കോൽ.public_താക്കോൽ_len);
		freezero(rks[i]->താക്കോൽ.signature, rks[i]->താക്കോൽ.signature_len);
		freezero(rks[i]->താക്കോൽ.attestation_cert,
		    rks[i]->താക്കോൽ.attestation_cert_len);
		freezero(rks[i], വലുപ്പം(**rks));
	}
	സ്വതന്ത്രം(rks);
}

സ്ഥിതം ശൂന്യം
sshsk_free_resident_താക്കോൽ(ഘടന sshsk_resident_താക്കോൽ *srk)
{
	എങ്കിൽ (srk == ശൂന്യ)
		തിരികെ;
	sshkey_free(srk->താക്കോൽ);
	freezero(srk->user_id, srk->user_id_len);
	സ്വതന്ത്രം(srk);
}


ശൂന്യം
sshsk_free_resident_താക്കോലുകൾ(ഘടന sshsk_resident_താക്കോൽ **srks, size_t nsrks)
{
	size_t i;

	എങ്കിൽ (srks == ശൂന്യ || nsrks == 0)
		തിരികെ;

	വേണ്ടി (i = 0; i < nsrks; i++)
		sshsk_free_resident_താക്കോൽ(srks[i]);
	സ്വതന്ത്രം(srks);
}

പൂർണ്ണസംഖ്യ
sshsk_load_resident(സ്ഥിരം അക്ഷരം *provider_path, സ്ഥിരം അക്ഷരം *device,
    സ്ഥിരം അക്ഷരം *pin, u_int flags, ഘടന sshsk_resident_താക്കോൽ ***srksp,
    size_t *nsrksp)
{
	ഘടന sshsk_provider *skp = ശൂന്യ;
	പൂർണ്ണസംഖ്യ r = SSH_ERR_INTERNAL_ERROR;
	ഘടന sk_resident_താക്കോൽ **rks = ശൂന്യ;
	size_t i, nrks = 0, nsrks = 0;
	ഘടന sshkey *താക്കോൽ = ശൂന്യ;
	ഘടന sshsk_resident_താക്കോൽ *srk = ശൂന്യ, **srks = ശൂന്യ, **tmp;
	uint8_t sk_flags;
	ഘടന sk_option **opts = ശൂന്യ;

	debug_f("provider \"%s\"%s", provider_path,
	    (pin != ശൂന്യ && *pin != '\0') ? ", have-pin": "");

	എങ്കിൽ (srksp == ശൂന്യ || nsrksp == ശൂന്യ)
		തിരികെ SSH_ERR_INVALID_ARGUMENT;
	*srksp = ശൂന്യ;
	*nsrksp = 0;

	എങ്കിൽ ((r = make_options(device, ശൂന്യ, &opts)) != 0)
		പോകുക out;
	എങ്കിൽ ((skp = sshsk_open(provider_path)) == ശൂന്യ) {
		r = SSH_ERR_INVALID_FORMAT; /* XXX sshsk_open return code? */
		പോകുക out;
	}
	എങ്കിൽ ((r = skp->sk_load_resident_താക്കോലുകൾ(pin, opts, &rks, &nrks)) != 0) {
		error("Provider \"%s\" returned failure %d", provider_path, r);
		r = skerr_to_ssherr(r);
		പോകുക out;
	}
	വേണ്ടി (i = 0; i < nrks; i++) {
		debug3_f("rk %zu: slot %zu, alg %d, app \"%s\", uidlen %zu",
		    i, rks[i]->slot, rks[i]->alg, rks[i]->application,
		    rks[i]->user_id_len);
		/* XXX need better filter here */
		എങ്കിൽ (strncmp(rks[i]->application, "ssh:", 4) != 0)
			തുടരുക;
		തിരഞ്ഞെടുപ്പ് (rks[i]->alg) {
		അവസ്ഥ SSH_SK_ECDSA:
		അവസ്ഥ SSH_SK_ED25519:
			നിർത്തുക;
		സ്ഥിരസ്ഥിതി:
			തുടരുക;
		}
		sk_flags = SSH_SK_USER_PRESENCE_REQD|SSH_SK_RESIDENT_താക്കോൽ;
		എങ്കിൽ ((rks[i]->flags & SSH_SK_USER_VERIFICATION_REQD))
			sk_flags |= SSH_SK_USER_VERIFICATION_REQD;
		എങ്കിൽ ((r = sshsk_താക്കോൽ_from_response(rks[i]->alg,
		    rks[i]->application, sk_flags, &rks[i]->താക്കോൽ, &താക്കോൽ)) != 0)
			പോകുക out;
		എങ്കിൽ ((srk = calloc(1, വലുപ്പം(*srk))) == ശൂന്യ) {
			error_f("calloc failed");
			r = SSH_ERR_ALLOC_FAIL;
			പോകുക out;
		}
		srk->താക്കോൽ = താക്കോൽ;
		താക്കോൽ = ശൂന്യ; /* transferred */
		എങ്കിൽ ((srk->user_id = calloc(1, rks[i]->user_id_len)) == ശൂന്യ) {
			error_f("calloc failed");
			r = SSH_ERR_ALLOC_FAIL;
			പോകുക out;
		}
		memcpy(srk->user_id, rks[i]->user_id, rks[i]->user_id_len);
		srk->user_id_len = rks[i]->user_id_len;
		എങ്കിൽ ((tmp = recallocarray(srks, nsrks, nsrks + 1,
		    വലുപ്പം(*tmp))) == ശൂന്യ) {
			error_f("recallocarray failed");
			r = SSH_ERR_ALLOC_FAIL;
			പോകുക out;
		}
		srks = tmp;
		srks[nsrks++] = srk;
		srk = ശൂന്യ;
		/* XXX synthesise comment */
	}
	/* success */
	*srksp = srks;
	*nsrksp = nsrks;
	srks = ശൂന്യ;
	nsrks = 0;
	r = 0;
 out:
	sshsk_free_options(opts);
	sshsk_free(skp);
	sshsk_free_sk_resident_താക്കോലുകൾ(rks, nrks);
	sshkey_free(താക്കോൽ);
	sshsk_free_resident_താക്കോൽ(srk);
	sshsk_free_resident_താക്കോലുകൾ(srks, nsrks);
	തിരികെ r;
}

#endif /* ENABLE_SK */
