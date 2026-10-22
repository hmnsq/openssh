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

#અન્તર્ભાવ "includes.h"

#ifdef ENABLE_SK

#અન્તર્ભાવ <dlfcn.h>
#અન્તર્ભાવ <stddef.h>
#અન્તર્ભાવ <stdint.h>
#અન્તર્ભાવ <string.h>
#અન્તર્ભાવ <stdio.h>

#ifdef WITH_OPENSSL
#અન્તર્ભાવ <openssl/objects.h>
#અન્તર્ભાવ <openssl/ec.h>
#અન્તર્ભાવ <openssl/evp.h>
#endif /* WITH_OPENSSL */

#અન્તર્ભાવ "log.h"
#અન્તર્ભાવ "misc.h"
#અન્તર્ભાવ "sshbuf.h"
#અન્તર્ભાવ "sshkey.h"
#અન્તર્ભાવ "ssherr.h"
#અન્તર્ભાવ "digest.h"

#અન્તર્ભાવ "ssh-sk.h"
#અન્તર્ભાવ "sk-api.h"
#અન્તર્ભાવ "crypto_api.h"

સંરચના sshsk_provider {
	અક્ષર *path;
	શૂન્ય *dlhandle;

	/* Return the version of the middleware API */
	uint32_t (*sk_api_version)(શૂન્ય);

	/* Enroll a U2F key (private key generation) */
	પૂર્ણાંક (*sk_enroll)(પૂર્ણાંક alg, અચલ uint8_t *challenge,
	    size_t challenge_len, અચલ અક્ષર *application, uint8_t flags,
	    અચલ અક્ષર *pin, સંરચના sk_option **opts,
	    સંરચના sk_enroll_response **enroll_response);

	/* Sign a challenge */
	પૂર્ણાંક (*sk_sign)(પૂર્ણાંક alg, અચલ uint8_t *message, size_t message_len,
	    અચલ અક્ષર *application,
	    અચલ uint8_t *ચાવી_handle, size_t ચાવી_handle_len,
	    uint8_t flags, અચલ અક્ષર *pin, સંરચના sk_option **opts,
	    સંરચના sk_sign_response **sign_response);

	/* Enumerate resident keys */
	પૂર્ણાંક (*sk_load_resident_ચાવીઓ)(અચલ અક્ષર *pin, સંરચના sk_option **opts,
	    સંરચના sk_resident_ચાવી ***rks, size_t *nrks);
};

/* Built-in version */
પૂર્ણાંક ssh_sk_enroll(પૂર્ણાંક alg, અચલ uint8_t *challenge,
    size_t challenge_len, અચલ અક્ષર *application, uint8_t flags,
    અચલ અક્ષર *pin, સંરચના sk_option **opts,
    સંરચના sk_enroll_response **enroll_response);
પૂર્ણાંક ssh_sk_sign(પૂર્ણાંક alg, અચલ uint8_t *message, size_t message_len,
    અચલ અક્ષર *application,
    અચલ uint8_t *ચાવી_handle, size_t ચાવી_handle_len,
    uint8_t flags, અચલ અક્ષર *pin, સંરચના sk_option **opts,
    સંરચના sk_sign_response **sign_response);
પૂર્ણાંક ssh_sk_load_resident_ચાવીઓ(અચલ અક્ષર *pin, સંરચના sk_option **opts,
    સંરચના sk_resident_ચાવી ***rks, size_t *nrks);

સ્થિર શૂન્ય
sshsk_free(સંરચના sshsk_provider *p)
{
	જો (p == ખાલી)
		પાછા;
	મુક્ત(p->path);
	જો (p->dlhandle != ખાલી)
		dlclose(p->dlhandle);
	મુક્ત(p);
}

સ્થિર સંરચના sshsk_provider *
sshsk_open(અચલ અક્ષર *path)
{
	સંરચના sshsk_provider *ret = ખાલી;
	uint32_t version;

	જો (path == ખાલી || *path == '\0') {
		error("No FIDO SecurityKeyProvider specified");
		પાછા ખાલી;
	}
	જો ((ret = calloc(1, કદ(*ret))) == ખાલી) {
		error_f("calloc failed");
		પાછા ખાલી;
	}
	જો ((ret->path = strdup(path)) == ખાલી) {
		error_f("strdup failed");
		જાઓ fail;
	}
	/* Skip the rest if we're using the linked in middleware */
	જો (strcasecmp(ret->path, "internal") == 0) {
#ifdef ENABLE_SK_INTERNAL
		ret->sk_enroll = ssh_sk_enroll;
		ret->sk_sign = ssh_sk_sign;
		ret->sk_load_resident_ચાવીઓ = ssh_sk_load_resident_ચાવીઓ;
		પાછા ret;
#નહીંતર
		error("internal security key support not enabled");
		જાઓ fail;
#endif
	}
	જો (lib_contains_પ્રતીક(path, "sk_api_version") != 0) {
		error("provider %s is not an OpenSSH FIDO library", path);
		જાઓ fail;
	}
	જો ((ret->dlhandle = dlopen(path, RTLD_NOW)) == ખાલી)
		fatal("Provider \"%s\" dlopen failed: %s", path, dlerror());
	જો ((ret->sk_api_version = dlsym(ret->dlhandle,
	    "sk_api_version")) == ખાલી) {
		error("Provider \"%s\" dlsym(sk_api_version) failed: %s",
		    path, dlerror());
		જાઓ fail;
	}
	version = ret->sk_api_version();
	debug_f("provider %s implements version 0x%08lx", ret->path,
	    (u_long)version);
	જો ((version & SSH_SK_VERSION_MAJOR_MASK) != SSH_SK_VERSION_MAJOR) {
		error("Provider \"%s\" implements unsupported "
		    "version 0x%08lx (supported: 0x%08lx)",
		    path, (u_long)version, (u_long)SSH_SK_VERSION_MAJOR);
		જાઓ fail;
	}
	જો ((ret->sk_enroll = dlsym(ret->dlhandle, "sk_enroll")) == ખાલી) {
		error("Provider %s dlsym(sk_enroll) failed: %s",
		    path, dlerror());
		જાઓ fail;
	}
	જો ((ret->sk_sign = dlsym(ret->dlhandle, "sk_sign")) == ખાલી) {
		error("Provider \"%s\" dlsym(sk_sign) failed: %s",
		    path, dlerror());
		જાઓ fail;
	}
	જો ((ret->sk_load_resident_ચાવીઓ = dlsym(ret->dlhandle,
	    "sk_load_resident_keys")) == ખાલી) {
		error("Provider \"%s\" dlsym(sk_load_resident_keys) "
		    "failed: %s", path, dlerror());
		જાઓ fail;
	}
	/* success */
	પાછા ret;
fail:
	sshsk_free(ret);
	પાછા ખાલી;
}

સ્થિર શૂન્ય
sshsk_free_enroll_response(સંરચના sk_enroll_response *r)
{
	જો (r == ખાલી)
		પાછા;
	freezero(r->ચાવી_handle, r->ચાવી_handle_len);
	freezero(r->public_ચાવી, r->public_ચાવી_len);
	freezero(r->signature, r->signature_len);
	freezero(r->attestation_cert, r->attestation_cert_len);
	freezero(r->authdata, r->authdata_len);
	freezero(r, કદ(*r));
}

સ્થિર શૂન્ય
sshsk_free_sign_response(સંરચના sk_sign_response *r)
{
	જો (r == ખાલી)
		પાછા;
	freezero(r->sig_r, r->sig_r_len);
	freezero(r->sig_s, r->sig_s_len);
	freezero(r, કદ(*r));
}

#ifdef WITH_OPENSSL
/* Assemble key from response */
સ્થિર પૂર્ણાંક
sshsk_ecdsa_assemble(સંરચના sk_enroll_response *resp, સંરચના sshkey **keyp)
{
	સંરચના sshkey *ચાવી = ખાલી;
	સંરચના sshbuf *b = ખાલી;
	EC_ચાવી *ecdsa = ખાલી;
	EC_POINT *q = ખાલી;
	અચલ EC_GROUP *g = ખાલી;
	પૂર્ણાંક r;

	*keyp = ખાલી;
	જો ((ચાવી = sshkey_new(ચાવી_ECDSA_SK)) == ખાલી) {
		error_f("sshkey_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		જાઓ out;
	}
	ચાવી->ecdsa_nid = NID_X9_62_prime256v1;
	જો ((ecdsa = EC_ચાવી_new_by_curve_name(ચાવી->ecdsa_nid)) == ખાલી ||
	    (g = EC_ચાવી_get0_group(ecdsa)) == ખાલી ||
	    (q = EC_POINT_new(g)) == ખાલી ||
	    (b = sshbuf_new()) == ખાલી) {
		error_f("allocation failed");
		r = SSH_ERR_ALLOC_FAIL;
		જાઓ out;
	}
	જો ((r = sshbuf_put_string(b,
	    resp->public_ચાવી, resp->public_ચાવી_len)) != 0) {
		error_fr(r, "sshbuf_put_string");
		જાઓ out;
	}
	જો ((r = sshbuf_get_ec(b, q, g)) != 0) {
		error_fr(r, "parse");
		r = SSH_ERR_INVALID_FORMAT;
		જાઓ out;
	}
	જો (sshkey_ec_validate_public(g, q) != 0) {
		error("Authenticator returned invalid ECDSA key");
		r = SSH_ERR_ચાવી_INVALID_EC_કિંમત;
		જાઓ out;
	}
	જો (EC_ચાવી_set_public_ચાવી(ecdsa, q) != 1) {
		/* XXX assume it is a allocation error */
		error_f("allocation failed");
		r = SSH_ERR_ALLOC_FAIL;
		જાઓ out;
	}
	જો ((ચાવી->pkey = EVP_PKEY_new()) == ખાલી) {
		error_f("allocation failed");
		r = SSH_ERR_ALLOC_FAIL;
		જાઓ out;
	}
	જો (EVP_PKEY_set1_EC_ચાવી(ચાવી->pkey, ecdsa) != 1) {
		error_f("Assigning EC_KEY failed");
		r = SSH_ERR_LIBCRYPTO_ERROR;
		જાઓ out;
	}
	/* success */
	*keyp = ચાવી;
	ચાવી = ખાલી; /* transferred */
	r = 0;
 out:
	sshkey_free(ચાવી);
	sshbuf_free(b);
	EC_ચાવી_free(ecdsa);
	EC_POINT_free(q);
	પાછા r;
}
#endif /* WITH_OPENSSL */

સ્થિર પૂર્ણાંક
sshsk_ed25519_assemble(સંરચના sk_enroll_response *resp, સંરચના sshkey **keyp)
{
	સંરચના sshkey *ચાવી = ખાલી;
	પૂર્ણાંક r;

	*keyp = ખાલી;
	જો (resp->public_ચાવી_len != ED25519_PK_SZ) {
		error_f("invalid size: %zu", resp->public_ચાવી_len);
		r = SSH_ERR_INVALID_FORMAT;
		જાઓ out;
	}
	જો ((ચાવી = sshkey_new(ચાવી_ED25519_SK)) == ખાલી) {
		error_f("sshkey_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		જાઓ out;
	}
	જો ((ચાવી->ed25519_pk = malloc(ED25519_PK_SZ)) == ખાલી) {
		error_f("malloc failed");
		r = SSH_ERR_ALLOC_FAIL;
		જાઓ out;
	}
	memcpy(ચાવી->ed25519_pk, resp->public_ચાવી, ED25519_PK_SZ);
	/* success */
	*keyp = ચાવી;
	ચાવી = ખાલી; /* transferred */
	r = 0;
 out:
	sshkey_free(ચાવી);
	પાછા r;
}

સ્થિર પૂર્ણાંક
sshsk_ચાવી_from_response(પૂર્ણાંક alg, અચલ અક્ષર *application, uint8_t flags,
    સંરચના sk_enroll_response *resp, સંરચના sshkey **keyp)
{
	સંરચના sshkey *ચાવી = ખાલી;
	પૂર્ણાંક r = SSH_ERR_INTERNAL_ERROR;

	*keyp = ખાલી;

	/* Check response validity */
	જો (resp->public_ચાવી == ખાલી || resp->ચાવી_handle == ખાલી) {
		error_f("sk_enroll response invalid");
		r = SSH_ERR_INVALID_FORMAT;
		જાઓ out;
	}
	પસંદગી (alg) {
#ifdef WITH_OPENSSL
	સ્થિતિ SSH_SK_ECDSA:
		જો ((r = sshsk_ecdsa_assemble(resp, &ચાવી)) != 0)
			જાઓ out;
		તોડો;
#endif /* WITH_OPENSSL */
	સ્થિતિ SSH_SK_ED25519:
		જો ((r = sshsk_ed25519_assemble(resp, &ચાવી)) != 0)
			જાઓ out;
		તોડો;
	મૂળભૂત:
		error_f("unsupported algorithm %d", alg);
		r = SSH_ERR_INVALID_ARGUMENT;
		જાઓ out;
	}
	ચાવી->sk_flags = flags;
	જો ((ચાવી->sk_ચાવી_handle = sshbuf_new()) == ખાલી ||
	    (ચાવી->sk_reserved = sshbuf_new()) == ખાલી) {
		error_f("allocation failed");
		r = SSH_ERR_ALLOC_FAIL;
		જાઓ out;
	}
	જો ((ચાવી->sk_application = strdup(application)) == ખાલી) {
		error_f("strdup application failed");
		r = SSH_ERR_ALLOC_FAIL;
		જાઓ out;
	}
	જો ((r = sshbuf_put(ચાવી->sk_ચાવી_handle, resp->ચાવી_handle,
	    resp->ચાવી_handle_len)) != 0) {
		error_fr(r, "put key handle");
		જાઓ out;
	}
	/* success */
	r = 0;
	*keyp = ચાવી;
	ચાવી = ખાલી;
 out:
	sshkey_free(ચાવી);
	પાછા r;
}

સ્થિર પૂર્ણાંક
skerr_to_ssherr(પૂર્ણાંક skerr)
{
	પસંદગી (skerr) {
	સ્થિતિ SSH_SK_ERR_UNSUPPORTED:
		પાછા SSH_ERR_FEATURE_UNSUPPORTED;
	સ્થિતિ SSH_SK_ERR_PIN_REQUIRED:
		પાછા SSH_ERR_ચાવી_WRONG_PASSPHRASE;
	સ્થિતિ SSH_SK_ERR_DEVICE_NOT_FOUND:
		પાછા SSH_ERR_DEVICE_NOT_FOUND;
	સ્થિતિ SSH_SK_ERR_CREDENTIAL_EXISTS:
		પાછા SSH_ERR_ચાવી_BAD_PERMISSIONS;
	સ્થિતિ SSH_SK_ERR_GENERAL:
	મૂળભૂત:
		પાછા SSH_ERR_INVALID_FORMAT;
	}
}

સ્થિર શૂન્ય
sshsk_free_options(સંરચના sk_option **opts)
{
	size_t i;

	જો (opts == ખાલી)
		પાછા;
	માટે (i = 0; opts[i] != ખાલી; i++) {
		મુક્ત(opts[i]->name);
		મુક્ત(opts[i]->કિંમત);
		મુક્ત(opts[i]);
	}
	મુક્ત(opts);
}

સ્થિર પૂર્ણાંક
sshsk_add_option(સંરચના sk_option ***optsp, size_t *noptsp,
    અચલ અક્ષર *name, અચલ અક્ષર *કિંમત, uint8_t required)
{
	સંરચના sk_option **opts = *optsp;
	size_t nopts = *noptsp;

	જો ((opts = recallocarray(opts, nopts, nopts + 2, /* extra for NULL */
	    કદ(*opts))) == ખાલી) {
		error_f("array alloc failed");
		પાછા SSH_ERR_ALLOC_FAIL;
	}
	*optsp = opts;
	*noptsp = nopts + 1;
	જો ((opts[nopts] = calloc(1, કદ(**opts))) == ખાલી) {
		error_f("alloc failed");
		પાછા SSH_ERR_ALLOC_FAIL;
	}
	જો ((opts[nopts]->name = strdup(name)) == ખાલી ||
	    (opts[nopts]->કિંમત = strdup(કિંમત)) == ખાલી) {
		error_f("alloc failed");
		પાછા SSH_ERR_ALLOC_FAIL;
	}
	opts[nopts]->required = required;
	પાછા 0;
}

સ્થિર પૂર્ણાંક
make_options(અચલ અક્ષર *device, અચલ અક્ષર *user_id,
    સંરચના sk_option ***optsp)
{
	સંરચના sk_option **opts = ખાલી;
	size_t nopts = 0;
	પૂર્ણાંક r, ret = SSH_ERR_INTERNAL_ERROR;

	જો (device != ખાલી &&
	    (r = sshsk_add_option(&opts, &nopts, "device", device, 0)) != 0) {
		ret = r;
		જાઓ out;
	}
	જો (user_id != ખાલી &&
	    (r = sshsk_add_option(&opts, &nopts, "user", user_id, 0)) != 0) {
		ret = r;
		જાઓ out;
	}
	/* success */
	*optsp = opts;
	opts = ખાલી;
	nopts = 0;
	ret = 0;
 out:
	sshsk_free_options(opts);
	પાછા ret;
}


સ્થિર પૂર્ણાંક
fill_attestation_blob(અચલ સંરચના sk_enroll_response *resp,
    સંરચના sshbuf *attest)
{
	પૂર્ણાંક r;

	જો (attest == ખાલી)
		પાછા 0; /* nothing to do */
	જો ((r = sshbuf_put_cstring(attest, "ssh-sk-attest-v01")) != 0 ||
	    (r = sshbuf_put_string(attest,
	    resp->attestation_cert, resp->attestation_cert_len)) != 0 ||
	    (r = sshbuf_put_string(attest,
	    resp->signature, resp->signature_len)) != 0 ||
	    (r = sshbuf_put_string(attest,
	    resp->authdata, resp->authdata_len)) != 0 ||
	    (r = sshbuf_put_u32(attest, 0)) != 0 || /* resvd flags */
	    (r = sshbuf_put_string(attest, ખાલી, 0)) != 0 /* resvd */) {
		error_fr(r, "compose");
		પાછા r;
	}
	/* success */
	પાછા 0;
}

પૂર્ણાંક
sshsk_enroll(પૂર્ણાંક type, અચલ અક્ષર *provider_path, અચલ અક્ષર *device,
    અચલ અક્ષર *application, અચલ અક્ષર *userid, uint8_t flags,
    અચલ અક્ષર *pin, સંરચના sshbuf *challenge_buf,
    સંરચના sshkey **keyp, સંરચના sshbuf *attest)
{
	સંરચના sshsk_provider *skp = ખાલી;
	સંરચના sshkey *ચાવી = ખાલી;
	u_char randchall[32];
	અચલ u_char *challenge;
	size_t challenge_len;
	સંરચના sk_enroll_response *resp = ખાલી;
	સંરચના sk_option **opts = ખાલી;
	પૂર્ણાંક r = SSH_ERR_INTERNAL_ERROR;
	પૂર્ણાંક alg;

	debug_f("provider \"%s\", device \"%s\", application \"%s\", "
	    "userid \"%s\", flags 0x%02x, challenge len %zu%s",
	    provider_path, device, application, userid, flags,
	    challenge_buf == ખાલી ? 0 : sshbuf_len(challenge_buf),
	    (pin != ખાલી && *pin != '\0') ? " with-pin" : "");

	*keyp = ખાલી;
	જો (attest)
		sshbuf_reset(attest);

	જો ((r = make_options(device, userid, &opts)) != 0)
		જાઓ out;

	પસંદગી (type) {
#ifdef WITH_OPENSSL
	સ્થિતિ ચાવી_ECDSA_SK:
		alg = SSH_SK_ECDSA;
		તોડો;
#endif /* WITH_OPENSSL */
	સ્થિતિ ચાવી_ED25519_SK:
		alg = SSH_SK_ED25519;
		તોડો;
	મૂળભૂત:
		error_f("unsupported key type");
		r = SSH_ERR_INVALID_ARGUMENT;
		જાઓ out;
	}
	જો (provider_path == ખાલી) {
		error_f("missing provider");
		r = SSH_ERR_INVALID_ARGUMENT;
		જાઓ out;
	}
	જો (application == ખાલી || *application == '\0') {
		error_f("missing application");
		r = SSH_ERR_INVALID_ARGUMENT;
		જાઓ out;
	}
	જો (challenge_buf == ખાલી) {
		debug_f("using random challenge");
		arc4random_buf(randchall, કદ(randchall));
		challenge = randchall;
		challenge_len = કદ(randchall);
	} નહીંતર જો (sshbuf_len(challenge_buf) == 0) {
		error("Missing enrollment challenge");
		r = SSH_ERR_INVALID_ARGUMENT;
		જાઓ out;
	} નહીંતર {
		challenge = sshbuf_ptr(challenge_buf);
		challenge_len = sshbuf_len(challenge_buf);
		debug3_f("using explicit challenge len=%zd", challenge_len);
	}
	જો ((skp = sshsk_open(provider_path)) == ખાલી) {
		r = SSH_ERR_INVALID_FORMAT; /* XXX sshsk_open return code? */
		જાઓ out;
	}
	/* XXX validate flags? */
	/* enroll key */
	જો ((r = skp->sk_enroll(alg, challenge, challenge_len, application,
	    flags, pin, opts, &resp)) != 0) {
		debug_f("provider \"%s\" failure %d", provider_path, r);
		r = skerr_to_ssherr(r);
		જાઓ out;
	}

	જો ((r = sshsk_ચાવી_from_response(alg, application, resp->flags,
	    resp, &ચાવી)) != 0)
		જાઓ out;

	/* Optionally fill in the attestation information */
	જો ((r = fill_attestation_blob(resp, attest)) != 0)
		જાઓ out;

	/* success */
	*keyp = ચાવી;
	ચાવી = ખાલી; /* transferred */
	r = 0;
 out:
	sshsk_free_options(opts);
	sshsk_free(skp);
	sshkey_free(ચાવી);
	sshsk_free_enroll_response(resp);
	explicit_bzero(randchall, કદ(randchall));
	પાછા r;
}

#ifdef WITH_OPENSSL
સ્થિર પૂર્ણાંક
sshsk_ecdsa_sig(સંરચના sk_sign_response *resp, સંરચના sshbuf *sig)
{
	સંરચના sshbuf *inner_sig = ખાલી;
	પૂર્ણાંક r = SSH_ERR_INTERNAL_ERROR;

	/* Check response validity */
	જો (resp->sig_r == ખાલી || resp->sig_s == ખાલી) {
		error_f("sk_sign response invalid");
		r = SSH_ERR_INVALID_FORMAT;
		જાઓ out;
	}
	જો ((inner_sig = sshbuf_new()) == ખાલી) {
		r = SSH_ERR_ALLOC_FAIL;
		જાઓ out;
	}
	/* Prepare and append inner signature object */
	જો ((r = sshbuf_put_bignum2_bytes(inner_sig,
	    resp->sig_r, resp->sig_r_len)) != 0 ||
	    (r = sshbuf_put_bignum2_bytes(inner_sig,
	    resp->sig_s, resp->sig_s_len)) != 0) {
		error_fr(r, "compose inner");
		જાઓ out;
	}
	જો ((r = sshbuf_put_stringb(sig, inner_sig)) != 0 ||
	    (r = sshbuf_put_u8(sig, resp->flags)) != 0 ||
	    (r = sshbuf_put_u32(sig, resp->counter)) != 0) {
		error_fr(r, "compose");
		જાઓ out;
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
	પાછા r;
}
#endif /* WITH_OPENSSL */

સ્થિર પૂર્ણાંક
sshsk_ed25519_sig(સંરચના sk_sign_response *resp, સંરચના sshbuf *sig)
{
	પૂર્ણાંક r = SSH_ERR_INTERNAL_ERROR;

	/* Check response validity */
	જો (resp->sig_r == ખાલી) {
		error_f("sk_sign response invalid");
		r = SSH_ERR_INVALID_FORMAT;
		જાઓ out;
	}
	જો ((r = sshbuf_put_string(sig,
	    resp->sig_r, resp->sig_r_len)) != 0 ||
	    (r = sshbuf_put_u8(sig, resp->flags)) != 0 ||
	    (r = sshbuf_put_u32(sig, resp->counter)) != 0) {
		error_fr(r, "compose");
		જાઓ out;
	}
#ifdef DEBUG_SK
	fprintf(stderr, "%s: sig_r:\n", __func__);
	sshbuf_dump_data(resp->sig_r, resp->sig_r_len, stderr);
#endif
	r = 0;
 out:
	પાછા r;
}

પૂર્ણાંક
sshsk_sign(અચલ અક્ષર *provider_path, સંરચના sshkey *ચાવી,
    u_char **sigp, size_t *lenp, અચલ u_char *data, size_t datalen,
    u_int compat, અચલ અક્ષર *pin)
{
	સંરચના sshsk_provider *skp = ખાલી;
	પૂર્ણાંક r = SSH_ERR_INTERNAL_ERROR;
	પૂર્ણાંક type, alg;
	સંરચના sk_sign_response *resp = ખાલી;
	સંરચના sshbuf *inner_sig = ખાલી, *sig = ખાલી;
	સંરચના sk_option **opts = ખાલી;

	debug_f("provider \"%s\", key %s, flags 0x%02x%s",
	    provider_path, sshkey_type(ચાવી), ચાવી->sk_flags,
	    (pin != ખાલી && *pin != '\0') ? " with-pin" : "");

	જો (sigp != ખાલી)
		*sigp = ખાલી;
	જો (lenp != ખાલી)
		*lenp = 0;
	type = sshkey_type_plain(ચાવી->type);
	પસંદગી (type) {
#ifdef WITH_OPENSSL
	સ્થિતિ ચાવી_ECDSA_SK:
		alg = SSH_SK_ECDSA;
		તોડો;
#endif /* WITH_OPENSSL */
	સ્થિતિ ચાવી_ED25519_SK:
		alg = SSH_SK_ED25519;
		તોડો;
	મૂળભૂત:
		પાછા SSH_ERR_INVALID_ARGUMENT;
	}
	જો (provider_path == ખાલી ||
	    ચાવી->sk_ચાવી_handle == ખાલી ||
	    ચાવી->sk_application == ખાલી || *ચાવી->sk_application == '\0') {
		r = SSH_ERR_INVALID_ARGUMENT;
		જાઓ out;
	}
	જો ((skp = sshsk_open(provider_path)) == ખાલી) {
		r = SSH_ERR_INVALID_FORMAT; /* XXX sshsk_open return code? */
		જાઓ out;
	}
#ifdef DEBUG_SK
	fprintf(stderr, "%s: sk_flags = 0x%02x, sk_application = \"%s\"\n",
	    __func__, ચાવી->sk_flags, ચાવી->sk_application);
	fprintf(stderr, "%s: sk_key_handle:\n", __func__);
	sshbuf_dump(ચાવી->sk_ચાવી_handle, stderr);
#endif
	જો ((r = skp->sk_sign(alg, data, datalen, ચાવી->sk_application,
	    sshbuf_ptr(ચાવી->sk_ચાવી_handle), sshbuf_len(ચાવી->sk_ચાવી_handle),
	    ચાવી->sk_flags, pin, opts, &resp)) != 0) {
		debug_f("sk_sign failed with code %d", r);
		r = skerr_to_ssherr(r);
		જાઓ out;
	}
	/* Assemble signature */
	જો ((sig = sshbuf_new()) == ખાલી) {
		r = SSH_ERR_ALLOC_FAIL;
		જાઓ out;
	}
	જો ((r = sshbuf_put_cstring(sig, sshkey_ssh_name_plain(ચાવી))) != 0) {
		error_fr(r, "compose outer");
		જાઓ out;
	}
	પસંદગી (type) {
#ifdef WITH_OPENSSL
	સ્થિતિ ચાવી_ECDSA_SK:
		જો ((r = sshsk_ecdsa_sig(resp, sig)) != 0)
			જાઓ out;
		તોડો;
#endif /* WITH_OPENSSL */
	સ્થિતિ ચાવી_ED25519_SK:
		જો ((r = sshsk_ed25519_sig(resp, sig)) != 0)
			જાઓ out;
		તોડો;
	}
#ifdef DEBUG_SK
	fprintf(stderr, "%s: sig_flags = 0x%02x, sig_counter = %u\n",
	    __func__, resp->flags, resp->counter);
	fprintf(stderr, "%s: data to sign:\n", __func__);
	sshbuf_dump_data(data, datalen, stderr);
	fprintf(stderr, "%s: sigbuf:\n", __func__);
	sshbuf_dump(sig, stderr);
#endif
	જો (sigp != ખાલી) {
		જો ((*sigp = malloc(sshbuf_len(sig))) == ખાલી) {
			r = SSH_ERR_ALLOC_FAIL;
			જાઓ out;
		}
		memcpy(*sigp, sshbuf_ptr(sig), sshbuf_len(sig));
	}
	જો (lenp != ખાલી)
		*lenp = sshbuf_len(sig);
	/* success */
	r = 0;
 out:
	sshsk_free_options(opts);
	sshsk_free(skp);
	sshsk_free_sign_response(resp);
	sshbuf_free(sig);
	sshbuf_free(inner_sig);
	પાછા r;
}

સ્થિર શૂન્ય
sshsk_free_sk_resident_ચાવીઓ(સંરચના sk_resident_ચાવી **rks, size_t nrks)
{
	size_t i;

	જો (nrks == 0 || rks == ખાલી)
		પાછા;
	માટે (i = 0; i < nrks; i++) {
		મુક્ત(rks[i]->application);
		freezero(rks[i]->user_id, rks[i]->user_id_len);
		freezero(rks[i]->ચાવી.ચાવી_handle, rks[i]->ચાવી.ચાવી_handle_len);
		freezero(rks[i]->ચાવી.public_ચાવી, rks[i]->ચાવી.public_ચાવી_len);
		freezero(rks[i]->ચાવી.signature, rks[i]->ચાવી.signature_len);
		freezero(rks[i]->ચાવી.attestation_cert,
		    rks[i]->ચાવી.attestation_cert_len);
		freezero(rks[i], કદ(**rks));
	}
	મુક્ત(rks);
}

સ્થિર શૂન્ય
sshsk_free_resident_ચાવી(સંરચના sshsk_resident_ચાવી *srk)
{
	જો (srk == ખાલી)
		પાછા;
	sshkey_free(srk->ચાવી);
	freezero(srk->user_id, srk->user_id_len);
	મુક્ત(srk);
}


શૂન્ય
sshsk_free_resident_ચાવીઓ(સંરચના sshsk_resident_ચાવી **srks, size_t nsrks)
{
	size_t i;

	જો (srks == ખાલી || nsrks == 0)
		પાછા;

	માટે (i = 0; i < nsrks; i++)
		sshsk_free_resident_ચાવી(srks[i]);
	મુક્ત(srks);
}

પૂર્ણાંક
sshsk_load_resident(અચલ અક્ષર *provider_path, અચલ અક્ષર *device,
    અચલ અક્ષર *pin, u_int flags, સંરચના sshsk_resident_ચાવી ***srksp,
    size_t *nsrksp)
{
	સંરચના sshsk_provider *skp = ખાલી;
	પૂર્ણાંક r = SSH_ERR_INTERNAL_ERROR;
	સંરચના sk_resident_ચાવી **rks = ખાલી;
	size_t i, nrks = 0, nsrks = 0;
	સંરચના sshkey *ચાવી = ખાલી;
	સંરચના sshsk_resident_ચાવી *srk = ખાલી, **srks = ખાલી, **tmp;
	uint8_t sk_flags;
	સંરચના sk_option **opts = ખાલી;

	debug_f("provider \"%s\"%s", provider_path,
	    (pin != ખાલી && *pin != '\0') ? ", have-pin": "");

	જો (srksp == ખાલી || nsrksp == ખાલી)
		પાછા SSH_ERR_INVALID_ARGUMENT;
	*srksp = ખાલી;
	*nsrksp = 0;

	જો ((r = make_options(device, ખાલી, &opts)) != 0)
		જાઓ out;
	જો ((skp = sshsk_open(provider_path)) == ખાલી) {
		r = SSH_ERR_INVALID_FORMAT; /* XXX sshsk_open return code? */
		જાઓ out;
	}
	જો ((r = skp->sk_load_resident_ચાવીઓ(pin, opts, &rks, &nrks)) != 0) {
		error("Provider \"%s\" returned failure %d", provider_path, r);
		r = skerr_to_ssherr(r);
		જાઓ out;
	}
	માટે (i = 0; i < nrks; i++) {
		debug3_f("rk %zu: slot %zu, alg %d, app \"%s\", uidlen %zu",
		    i, rks[i]->slot, rks[i]->alg, rks[i]->application,
		    rks[i]->user_id_len);
		/* XXX need better filter here */
		જો (strncmp(rks[i]->application, "ssh:", 4) != 0)
			ચાલુ;
		પસંદગી (rks[i]->alg) {
		સ્થિતિ SSH_SK_ECDSA:
		સ્થિતિ SSH_SK_ED25519:
			તોડો;
		મૂળભૂત:
			ચાલુ;
		}
		sk_flags = SSH_SK_USER_PRESENCE_REQD|SSH_SK_RESIDENT_ચાવી;
		જો ((rks[i]->flags & SSH_SK_USER_VERIFICATION_REQD))
			sk_flags |= SSH_SK_USER_VERIFICATION_REQD;
		જો ((r = sshsk_ચાવી_from_response(rks[i]->alg,
		    rks[i]->application, sk_flags, &rks[i]->ચાવી, &ચાવી)) != 0)
			જાઓ out;
		જો ((srk = calloc(1, કદ(*srk))) == ખાલી) {
			error_f("calloc failed");
			r = SSH_ERR_ALLOC_FAIL;
			જાઓ out;
		}
		srk->ચાવી = ચાવી;
		ચાવી = ખાલી; /* transferred */
		જો ((srk->user_id = calloc(1, rks[i]->user_id_len)) == ખાલી) {
			error_f("calloc failed");
			r = SSH_ERR_ALLOC_FAIL;
			જાઓ out;
		}
		memcpy(srk->user_id, rks[i]->user_id, rks[i]->user_id_len);
		srk->user_id_len = rks[i]->user_id_len;
		જો ((tmp = recallocarray(srks, nsrks, nsrks + 1,
		    કદ(*tmp))) == ખાલી) {
			error_f("recallocarray failed");
			r = SSH_ERR_ALLOC_FAIL;
			જાઓ out;
		}
		srks = tmp;
		srks[nsrks++] = srk;
		srk = ખાલી;
		/* XXX synthesise comment */
	}
	/* success */
	*srksp = srks;
	*nsrksp = nsrks;
	srks = ખાલી;
	nsrks = 0;
	r = 0;
 out:
	sshsk_free_options(opts);
	sshsk_free(skp);
	sshsk_free_sk_resident_ચાવીઓ(rks, nrks);
	sshkey_free(ચાવી);
	sshsk_free_resident_ચાવી(srk);
	sshsk_free_resident_ચાવીઓ(srks, nsrks);
	પાછા r;
}

#endif /* ENABLE_SK */
