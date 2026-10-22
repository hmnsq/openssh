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

#அந்தர்பாவ "includes.h"

#ifdef ENABLE_SK

#அந்தர்பாவ <dlfcn.h>
#அந்தர்பாவ <stddef.h>
#அந்தர்பாவ <stdint.h>
#அந்தர்பாவ <string.h>
#அந்தர்பாவ <stdio.h>

#ifdef WITH_OPENSSL
#அந்தர்பாவ <openssl/objects.h>
#அந்தர்பாவ <openssl/ec.h>
#அந்தர்பாவ <openssl/evp.h>
#endif /* WITH_OPENSSL */

#அந்தர்பாவ "log.h"
#அந்தர்பாவ "misc.h"
#அந்தர்பாவ "sshbuf.h"
#அந்தர்பாவ "sshkey.h"
#அந்தர்பாவ "ssherr.h"
#அந்தர்பாவ "digest.h"

#அந்தர்பாவ "ssh-sk.h"
#அந்தர்பாவ "sk-api.h"
#அந்தர்பாவ "crypto_api.h"

கட்டமைப்பு sshsk_provider {
	எழுத்து *path;
	வெறுமை *dlhandle;

	/* Return the version of the middleware API */
	uint32_t (*sk_api_version)(வெறுமை);

	/* Enroll a U2F key (private key generation) */
	முழு (*sk_enroll)(முழு alg, மாறிலி uint8_t *challenge,
	    size_t challenge_len, மாறிலி எழுத்து *application, uint8_t flags,
	    மாறிலி எழுத்து *pin, கட்டமைப்பு sk_option **opts,
	    கட்டமைப்பு sk_enroll_response **enroll_response);

	/* Sign a challenge */
	முழு (*sk_sign)(முழு alg, மாறிலி uint8_t *message, size_t message_len,
	    மாறிலி எழுத்து *application,
	    மாறிலி uint8_t *சாவி_handle, size_t சாவி_handle_len,
	    uint8_t flags, மாறிலி எழுத்து *pin, கட்டமைப்பு sk_option **opts,
	    கட்டமைப்பு sk_sign_response **sign_response);

	/* Enumerate resident keys */
	முழு (*sk_load_resident_சாவிகள்)(மாறிலி எழுத்து *pin, கட்டமைப்பு sk_option **opts,
	    கட்டமைப்பு sk_resident_சாவி ***rks, size_t *nrks);
};

/* Built-in version */
முழு ssh_sk_enroll(முழு alg, மாறிலி uint8_t *challenge,
    size_t challenge_len, மாறிலி எழுத்து *application, uint8_t flags,
    மாறிலி எழுத்து *pin, கட்டமைப்பு sk_option **opts,
    கட்டமைப்பு sk_enroll_response **enroll_response);
முழு ssh_sk_sign(முழு alg, மாறிலி uint8_t *message, size_t message_len,
    மாறிலி எழுத்து *application,
    மாறிலி uint8_t *சாவி_handle, size_t சாவி_handle_len,
    uint8_t flags, மாறிலி எழுத்து *pin, கட்டமைப்பு sk_option **opts,
    கட்டமைப்பு sk_sign_response **sign_response);
முழு ssh_sk_load_resident_சாவிகள்(மாறிலி எழுத்து *pin, கட்டமைப்பு sk_option **opts,
    கட்டமைப்பு sk_resident_சாவி ***rks, size_t *nrks);

நிலையான வெறுமை
sshsk_free(கட்டமைப்பு sshsk_provider *p)
{
	எனில் (p == வெற்று)
		திரும்பு;
	விடுவி(p->path);
	எனில் (p->dlhandle != வெற்று)
		dlclose(p->dlhandle);
	விடுவி(p);
}

நிலையான கட்டமைப்பு sshsk_provider *
sshsk_open(மாறிலி எழுத்து *path)
{
	கட்டமைப்பு sshsk_provider *ret = வெற்று;
	uint32_t version;

	எனில் (path == வெற்று || *path == '\0') {
		error("No FIDO SecurityKeyProvider specified");
		திரும்பு வெற்று;
	}
	எனில் ((ret = calloc(1, அளவு(*ret))) == வெற்று) {
		error_f("calloc failed");
		திரும்பு வெற்று;
	}
	எனில் ((ret->path = strdup(path)) == வெற்று) {
		error_f("strdup failed");
		செல் fail;
	}
	/* Skip the rest if we're using the linked in middleware */
	எனில் (strcasecmp(ret->path, "internal") == 0) {
#ifdef ENABLE_SK_INTERNAL
		ret->sk_enroll = ssh_sk_enroll;
		ret->sk_sign = ssh_sk_sign;
		ret->sk_load_resident_சாவிகள் = ssh_sk_load_resident_சாவிகள்;
		திரும்பு ret;
#இல்லையெனில்
		error("internal security key support not enabled");
		செல் fail;
#endif
	}
	எனில் (lib_contains_குறியீடு(path, "sk_api_version") != 0) {
		error("provider %s is not an OpenSSH FIDO library", path);
		செல் fail;
	}
	எனில் ((ret->dlhandle = dlopen(path, RTLD_NOW)) == வெற்று)
		fatal("Provider \"%s\" dlopen failed: %s", path, dlerror());
	எனில் ((ret->sk_api_version = dlsym(ret->dlhandle,
	    "sk_api_version")) == வெற்று) {
		error("Provider \"%s\" dlsym(sk_api_version) failed: %s",
		    path, dlerror());
		செல் fail;
	}
	version = ret->sk_api_version();
	debug_f("provider %s implements version 0x%08lx", ret->path,
	    (u_long)version);
	எனில் ((version & SSH_SK_VERSION_MAJOR_MASK) != SSH_SK_VERSION_MAJOR) {
		error("Provider \"%s\" implements unsupported "
		    "version 0x%08lx (supported: 0x%08lx)",
		    path, (u_long)version, (u_long)SSH_SK_VERSION_MAJOR);
		செல் fail;
	}
	எனில் ((ret->sk_enroll = dlsym(ret->dlhandle, "sk_enroll")) == வெற்று) {
		error("Provider %s dlsym(sk_enroll) failed: %s",
		    path, dlerror());
		செல் fail;
	}
	எனில் ((ret->sk_sign = dlsym(ret->dlhandle, "sk_sign")) == வெற்று) {
		error("Provider \"%s\" dlsym(sk_sign) failed: %s",
		    path, dlerror());
		செல் fail;
	}
	எனில் ((ret->sk_load_resident_சாவிகள் = dlsym(ret->dlhandle,
	    "sk_load_resident_keys")) == வெற்று) {
		error("Provider \"%s\" dlsym(sk_load_resident_keys) "
		    "failed: %s", path, dlerror());
		செல் fail;
	}
	/* success */
	திரும்பு ret;
fail:
	sshsk_free(ret);
	திரும்பு வெற்று;
}

நிலையான வெறுமை
sshsk_free_enroll_response(கட்டமைப்பு sk_enroll_response *r)
{
	எனில் (r == வெற்று)
		திரும்பு;
	freezero(r->சாவி_handle, r->சாவி_handle_len);
	freezero(r->public_சாவி, r->public_சாவி_len);
	freezero(r->signature, r->signature_len);
	freezero(r->attestation_cert, r->attestation_cert_len);
	freezero(r->authdata, r->authdata_len);
	freezero(r, அளவு(*r));
}

நிலையான வெறுமை
sshsk_free_sign_response(கட்டமைப்பு sk_sign_response *r)
{
	எனில் (r == வெற்று)
		திரும்பு;
	freezero(r->sig_r, r->sig_r_len);
	freezero(r->sig_s, r->sig_s_len);
	freezero(r, அளவு(*r));
}

#ifdef WITH_OPENSSL
/* Assemble key from response */
நிலையான முழு
sshsk_ecdsa_assemble(கட்டமைப்பு sk_enroll_response *resp, கட்டமைப்பு sshkey **keyp)
{
	கட்டமைப்பு sshkey *சாவி = வெற்று;
	கட்டமைப்பு sshbuf *b = வெற்று;
	EC_சாவி *ecdsa = வெற்று;
	EC_POINT *q = வெற்று;
	மாறிலி EC_GROUP *g = வெற்று;
	முழு r;

	*keyp = வெற்று;
	எனில் ((சாவி = sshkey_new(சாவி_ECDSA_SK)) == வெற்று) {
		error_f("sshkey_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		செல் out;
	}
	சாவி->ecdsa_nid = NID_X9_62_prime256v1;
	எனில் ((ecdsa = EC_சாவி_new_by_curve_name(சாவி->ecdsa_nid)) == வெற்று ||
	    (g = EC_சாவி_get0_group(ecdsa)) == வெற்று ||
	    (q = EC_POINT_new(g)) == வெற்று ||
	    (b = sshbuf_new()) == வெற்று) {
		error_f("allocation failed");
		r = SSH_ERR_ALLOC_FAIL;
		செல் out;
	}
	எனில் ((r = sshbuf_put_string(b,
	    resp->public_சாவி, resp->public_சாவி_len)) != 0) {
		error_fr(r, "sshbuf_put_string");
		செல் out;
	}
	எனில் ((r = sshbuf_get_ec(b, q, g)) != 0) {
		error_fr(r, "parse");
		r = SSH_ERR_INVALID_FORMAT;
		செல் out;
	}
	எனில் (sshkey_ec_validate_public(g, q) != 0) {
		error("Authenticator returned invalid ECDSA key");
		r = SSH_ERR_சாவி_INVALID_EC_மதிப்பு;
		செல் out;
	}
	எனில் (EC_சாவி_set_public_சாவி(ecdsa, q) != 1) {
		/* XXX assume it is a allocation error */
		error_f("allocation failed");
		r = SSH_ERR_ALLOC_FAIL;
		செல் out;
	}
	எனில் ((சாவி->pkey = EVP_PKEY_new()) == வெற்று) {
		error_f("allocation failed");
		r = SSH_ERR_ALLOC_FAIL;
		செல் out;
	}
	எனில் (EVP_PKEY_set1_EC_சாவி(சாவி->pkey, ecdsa) != 1) {
		error_f("Assigning EC_KEY failed");
		r = SSH_ERR_LIBCRYPTO_ERROR;
		செல் out;
	}
	/* success */
	*keyp = சாவி;
	சாவி = வெற்று; /* transferred */
	r = 0;
 out:
	sshkey_free(சாவி);
	sshbuf_free(b);
	EC_சாவி_free(ecdsa);
	EC_POINT_free(q);
	திரும்பு r;
}
#endif /* WITH_OPENSSL */

நிலையான முழு
sshsk_ed25519_assemble(கட்டமைப்பு sk_enroll_response *resp, கட்டமைப்பு sshkey **keyp)
{
	கட்டமைப்பு sshkey *சாவி = வெற்று;
	முழு r;

	*keyp = வெற்று;
	எனில் (resp->public_சாவி_len != ED25519_PK_SZ) {
		error_f("invalid size: %zu", resp->public_சாவி_len);
		r = SSH_ERR_INVALID_FORMAT;
		செல் out;
	}
	எனில் ((சாவி = sshkey_new(சாவி_ED25519_SK)) == வெற்று) {
		error_f("sshkey_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		செல் out;
	}
	எனில் ((சாவி->ed25519_pk = malloc(ED25519_PK_SZ)) == வெற்று) {
		error_f("malloc failed");
		r = SSH_ERR_ALLOC_FAIL;
		செல் out;
	}
	memcpy(சாவி->ed25519_pk, resp->public_சாவி, ED25519_PK_SZ);
	/* success */
	*keyp = சாவி;
	சாவி = வெற்று; /* transferred */
	r = 0;
 out:
	sshkey_free(சாவி);
	திரும்பு r;
}

நிலையான முழு
sshsk_சாவி_from_response(முழு alg, மாறிலி எழுத்து *application, uint8_t flags,
    கட்டமைப்பு sk_enroll_response *resp, கட்டமைப்பு sshkey **keyp)
{
	கட்டமைப்பு sshkey *சாவி = வெற்று;
	முழு r = SSH_ERR_INTERNAL_ERROR;

	*keyp = வெற்று;

	/* Check response validity */
	எனில் (resp->public_சாவி == வெற்று || resp->சாவி_handle == வெற்று) {
		error_f("sk_enroll response invalid");
		r = SSH_ERR_INVALID_FORMAT;
		செல் out;
	}
	தேர்வு (alg) {
#ifdef WITH_OPENSSL
	நிலை SSH_SK_ECDSA:
		எனில் ((r = sshsk_ecdsa_assemble(resp, &சாவி)) != 0)
			செல் out;
		நிறுத்து;
#endif /* WITH_OPENSSL */
	நிலை SSH_SK_ED25519:
		எனில் ((r = sshsk_ed25519_assemble(resp, &சாவி)) != 0)
			செல் out;
		நிறுத்து;
	இயல்பு:
		error_f("unsupported algorithm %d", alg);
		r = SSH_ERR_INVALID_ARGUMENT;
		செல் out;
	}
	சாவி->sk_flags = flags;
	எனில் ((சாவி->sk_சாவி_handle = sshbuf_new()) == வெற்று ||
	    (சாவி->sk_reserved = sshbuf_new()) == வெற்று) {
		error_f("allocation failed");
		r = SSH_ERR_ALLOC_FAIL;
		செல் out;
	}
	எனில் ((சாவி->sk_application = strdup(application)) == வெற்று) {
		error_f("strdup application failed");
		r = SSH_ERR_ALLOC_FAIL;
		செல் out;
	}
	எனில் ((r = sshbuf_put(சாவி->sk_சாவி_handle, resp->சாவி_handle,
	    resp->சாவி_handle_len)) != 0) {
		error_fr(r, "put key handle");
		செல் out;
	}
	/* success */
	r = 0;
	*keyp = சாவி;
	சாவி = வெற்று;
 out:
	sshkey_free(சாவி);
	திரும்பு r;
}

நிலையான முழு
skerr_to_ssherr(முழு skerr)
{
	தேர்வு (skerr) {
	நிலை SSH_SK_ERR_UNSUPPORTED:
		திரும்பு SSH_ERR_FEATURE_UNSUPPORTED;
	நிலை SSH_SK_ERR_PIN_REQUIRED:
		திரும்பு SSH_ERR_சாவி_WRONG_PASSPHRASE;
	நிலை SSH_SK_ERR_DEVICE_NOT_FOUND:
		திரும்பு SSH_ERR_DEVICE_NOT_FOUND;
	நிலை SSH_SK_ERR_CREDENTIAL_EXISTS:
		திரும்பு SSH_ERR_சாவி_BAD_PERMISSIONS;
	நிலை SSH_SK_ERR_GENERAL:
	இயல்பு:
		திரும்பு SSH_ERR_INVALID_FORMAT;
	}
}

நிலையான வெறுமை
sshsk_free_options(கட்டமைப்பு sk_option **opts)
{
	size_t i;

	எனில் (opts == வெற்று)
		திரும்பு;
	க்கு (i = 0; opts[i] != வெற்று; i++) {
		விடுவி(opts[i]->name);
		விடுவி(opts[i]->மதிப்பு);
		விடுவி(opts[i]);
	}
	விடுவி(opts);
}

நிலையான முழு
sshsk_add_option(கட்டமைப்பு sk_option ***optsp, size_t *noptsp,
    மாறிலி எழுத்து *name, மாறிலி எழுத்து *மதிப்பு, uint8_t required)
{
	கட்டமைப்பு sk_option **opts = *optsp;
	size_t nopts = *noptsp;

	எனில் ((opts = recallocarray(opts, nopts, nopts + 2, /* extra for NULL */
	    அளவு(*opts))) == வெற்று) {
		error_f("array alloc failed");
		திரும்பு SSH_ERR_ALLOC_FAIL;
	}
	*optsp = opts;
	*noptsp = nopts + 1;
	எனில் ((opts[nopts] = calloc(1, அளவு(**opts))) == வெற்று) {
		error_f("alloc failed");
		திரும்பு SSH_ERR_ALLOC_FAIL;
	}
	எனில் ((opts[nopts]->name = strdup(name)) == வெற்று ||
	    (opts[nopts]->மதிப்பு = strdup(மதிப்பு)) == வெற்று) {
		error_f("alloc failed");
		திரும்பு SSH_ERR_ALLOC_FAIL;
	}
	opts[nopts]->required = required;
	திரும்பு 0;
}

நிலையான முழு
make_options(மாறிலி எழுத்து *device, மாறிலி எழுத்து *user_id,
    கட்டமைப்பு sk_option ***optsp)
{
	கட்டமைப்பு sk_option **opts = வெற்று;
	size_t nopts = 0;
	முழு r, ret = SSH_ERR_INTERNAL_ERROR;

	எனில் (device != வெற்று &&
	    (r = sshsk_add_option(&opts, &nopts, "device", device, 0)) != 0) {
		ret = r;
		செல் out;
	}
	எனில் (user_id != வெற்று &&
	    (r = sshsk_add_option(&opts, &nopts, "user", user_id, 0)) != 0) {
		ret = r;
		செல் out;
	}
	/* success */
	*optsp = opts;
	opts = வெற்று;
	nopts = 0;
	ret = 0;
 out:
	sshsk_free_options(opts);
	திரும்பு ret;
}


நிலையான முழு
fill_attestation_blob(மாறிலி கட்டமைப்பு sk_enroll_response *resp,
    கட்டமைப்பு sshbuf *attest)
{
	முழு r;

	எனில் (attest == வெற்று)
		திரும்பு 0; /* nothing to do */
	எனில் ((r = sshbuf_put_cstring(attest, "ssh-sk-attest-v01")) != 0 ||
	    (r = sshbuf_put_string(attest,
	    resp->attestation_cert, resp->attestation_cert_len)) != 0 ||
	    (r = sshbuf_put_string(attest,
	    resp->signature, resp->signature_len)) != 0 ||
	    (r = sshbuf_put_string(attest,
	    resp->authdata, resp->authdata_len)) != 0 ||
	    (r = sshbuf_put_u32(attest, 0)) != 0 || /* resvd flags */
	    (r = sshbuf_put_string(attest, வெற்று, 0)) != 0 /* resvd */) {
		error_fr(r, "compose");
		திரும்பு r;
	}
	/* success */
	திரும்பு 0;
}

முழு
sshsk_enroll(முழு type, மாறிலி எழுத்து *provider_path, மாறிலி எழுத்து *device,
    மாறிலி எழுத்து *application, மாறிலி எழுத்து *userid, uint8_t flags,
    மாறிலி எழுத்து *pin, கட்டமைப்பு sshbuf *challenge_buf,
    கட்டமைப்பு sshkey **keyp, கட்டமைப்பு sshbuf *attest)
{
	கட்டமைப்பு sshsk_provider *skp = வெற்று;
	கட்டமைப்பு sshkey *சாவி = வெற்று;
	u_char randchall[32];
	மாறிலி u_char *challenge;
	size_t challenge_len;
	கட்டமைப்பு sk_enroll_response *resp = வெற்று;
	கட்டமைப்பு sk_option **opts = வெற்று;
	முழு r = SSH_ERR_INTERNAL_ERROR;
	முழு alg;

	debug_f("provider \"%s\", device \"%s\", application \"%s\", "
	    "userid \"%s\", flags 0x%02x, challenge len %zu%s",
	    provider_path, device, application, userid, flags,
	    challenge_buf == வெற்று ? 0 : sshbuf_len(challenge_buf),
	    (pin != வெற்று && *pin != '\0') ? " with-pin" : "");

	*keyp = வெற்று;
	எனில் (attest)
		sshbuf_reset(attest);

	எனில் ((r = make_options(device, userid, &opts)) != 0)
		செல் out;

	தேர்வு (type) {
#ifdef WITH_OPENSSL
	நிலை சாவி_ECDSA_SK:
		alg = SSH_SK_ECDSA;
		நிறுத்து;
#endif /* WITH_OPENSSL */
	நிலை சாவி_ED25519_SK:
		alg = SSH_SK_ED25519;
		நிறுத்து;
	இயல்பு:
		error_f("unsupported key type");
		r = SSH_ERR_INVALID_ARGUMENT;
		செல் out;
	}
	எனில் (provider_path == வெற்று) {
		error_f("missing provider");
		r = SSH_ERR_INVALID_ARGUMENT;
		செல் out;
	}
	எனில் (application == வெற்று || *application == '\0') {
		error_f("missing application");
		r = SSH_ERR_INVALID_ARGUMENT;
		செல் out;
	}
	எனில் (challenge_buf == வெற்று) {
		debug_f("using random challenge");
		arc4random_buf(randchall, அளவு(randchall));
		challenge = randchall;
		challenge_len = அளவு(randchall);
	} இல்லையெனில் எனில் (sshbuf_len(challenge_buf) == 0) {
		error("Missing enrollment challenge");
		r = SSH_ERR_INVALID_ARGUMENT;
		செல் out;
	} இல்லையெனில் {
		challenge = sshbuf_ptr(challenge_buf);
		challenge_len = sshbuf_len(challenge_buf);
		debug3_f("using explicit challenge len=%zd", challenge_len);
	}
	எனில் ((skp = sshsk_open(provider_path)) == வெற்று) {
		r = SSH_ERR_INVALID_FORMAT; /* XXX sshsk_open return code? */
		செல் out;
	}
	/* XXX validate flags? */
	/* enroll key */
	எனில் ((r = skp->sk_enroll(alg, challenge, challenge_len, application,
	    flags, pin, opts, &resp)) != 0) {
		debug_f("provider \"%s\" failure %d", provider_path, r);
		r = skerr_to_ssherr(r);
		செல் out;
	}

	எனில் ((r = sshsk_சாவி_from_response(alg, application, resp->flags,
	    resp, &சாவி)) != 0)
		செல் out;

	/* Optionally fill in the attestation information */
	எனில் ((r = fill_attestation_blob(resp, attest)) != 0)
		செல் out;

	/* success */
	*keyp = சாவி;
	சாவி = வெற்று; /* transferred */
	r = 0;
 out:
	sshsk_free_options(opts);
	sshsk_free(skp);
	sshkey_free(சாவி);
	sshsk_free_enroll_response(resp);
	explicit_bzero(randchall, அளவு(randchall));
	திரும்பு r;
}

#ifdef WITH_OPENSSL
நிலையான முழு
sshsk_ecdsa_sig(கட்டமைப்பு sk_sign_response *resp, கட்டமைப்பு sshbuf *sig)
{
	கட்டமைப்பு sshbuf *inner_sig = வெற்று;
	முழு r = SSH_ERR_INTERNAL_ERROR;

	/* Check response validity */
	எனில் (resp->sig_r == வெற்று || resp->sig_s == வெற்று) {
		error_f("sk_sign response invalid");
		r = SSH_ERR_INVALID_FORMAT;
		செல் out;
	}
	எனில் ((inner_sig = sshbuf_new()) == வெற்று) {
		r = SSH_ERR_ALLOC_FAIL;
		செல் out;
	}
	/* Prepare and append inner signature object */
	எனில் ((r = sshbuf_put_bignum2_bytes(inner_sig,
	    resp->sig_r, resp->sig_r_len)) != 0 ||
	    (r = sshbuf_put_bignum2_bytes(inner_sig,
	    resp->sig_s, resp->sig_s_len)) != 0) {
		error_fr(r, "compose inner");
		செல் out;
	}
	எனில் ((r = sshbuf_put_stringb(sig, inner_sig)) != 0 ||
	    (r = sshbuf_put_u8(sig, resp->flags)) != 0 ||
	    (r = sshbuf_put_u32(sig, resp->counter)) != 0) {
		error_fr(r, "compose");
		செல் out;
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
	திரும்பு r;
}
#endif /* WITH_OPENSSL */

நிலையான முழு
sshsk_ed25519_sig(கட்டமைப்பு sk_sign_response *resp, கட்டமைப்பு sshbuf *sig)
{
	முழு r = SSH_ERR_INTERNAL_ERROR;

	/* Check response validity */
	எனில் (resp->sig_r == வெற்று) {
		error_f("sk_sign response invalid");
		r = SSH_ERR_INVALID_FORMAT;
		செல் out;
	}
	எனில் ((r = sshbuf_put_string(sig,
	    resp->sig_r, resp->sig_r_len)) != 0 ||
	    (r = sshbuf_put_u8(sig, resp->flags)) != 0 ||
	    (r = sshbuf_put_u32(sig, resp->counter)) != 0) {
		error_fr(r, "compose");
		செல் out;
	}
#ifdef DEBUG_SK
	fprintf(stderr, "%s: sig_r:\n", __func__);
	sshbuf_dump_data(resp->sig_r, resp->sig_r_len, stderr);
#endif
	r = 0;
 out:
	திரும்பு r;
}

முழு
sshsk_sign(மாறிலி எழுத்து *provider_path, கட்டமைப்பு sshkey *சாவி,
    u_char **sigp, size_t *lenp, மாறிலி u_char *data, size_t datalen,
    u_int compat, மாறிலி எழுத்து *pin)
{
	கட்டமைப்பு sshsk_provider *skp = வெற்று;
	முழு r = SSH_ERR_INTERNAL_ERROR;
	முழு type, alg;
	கட்டமைப்பு sk_sign_response *resp = வெற்று;
	கட்டமைப்பு sshbuf *inner_sig = வெற்று, *sig = வெற்று;
	கட்டமைப்பு sk_option **opts = வெற்று;

	debug_f("provider \"%s\", key %s, flags 0x%02x%s",
	    provider_path, sshkey_type(சாவி), சாவி->sk_flags,
	    (pin != வெற்று && *pin != '\0') ? " with-pin" : "");

	எனில் (sigp != வெற்று)
		*sigp = வெற்று;
	எனில் (lenp != வெற்று)
		*lenp = 0;
	type = sshkey_type_plain(சாவி->type);
	தேர்வு (type) {
#ifdef WITH_OPENSSL
	நிலை சாவி_ECDSA_SK:
		alg = SSH_SK_ECDSA;
		நிறுத்து;
#endif /* WITH_OPENSSL */
	நிலை சாவி_ED25519_SK:
		alg = SSH_SK_ED25519;
		நிறுத்து;
	இயல்பு:
		திரும்பு SSH_ERR_INVALID_ARGUMENT;
	}
	எனில் (provider_path == வெற்று ||
	    சாவி->sk_சாவி_handle == வெற்று ||
	    சாவி->sk_application == வெற்று || *சாவி->sk_application == '\0') {
		r = SSH_ERR_INVALID_ARGUMENT;
		செல் out;
	}
	எனில் ((skp = sshsk_open(provider_path)) == வெற்று) {
		r = SSH_ERR_INVALID_FORMAT; /* XXX sshsk_open return code? */
		செல் out;
	}
#ifdef DEBUG_SK
	fprintf(stderr, "%s: sk_flags = 0x%02x, sk_application = \"%s\"\n",
	    __func__, சாவி->sk_flags, சாவி->sk_application);
	fprintf(stderr, "%s: sk_key_handle:\n", __func__);
	sshbuf_dump(சாவி->sk_சாவி_handle, stderr);
#endif
	எனில் ((r = skp->sk_sign(alg, data, datalen, சாவி->sk_application,
	    sshbuf_ptr(சாவி->sk_சாவி_handle), sshbuf_len(சாவி->sk_சாவி_handle),
	    சாவி->sk_flags, pin, opts, &resp)) != 0) {
		debug_f("sk_sign failed with code %d", r);
		r = skerr_to_ssherr(r);
		செல் out;
	}
	/* Assemble signature */
	எனில் ((sig = sshbuf_new()) == வெற்று) {
		r = SSH_ERR_ALLOC_FAIL;
		செல் out;
	}
	எனில் ((r = sshbuf_put_cstring(sig, sshkey_ssh_name_plain(சாவி))) != 0) {
		error_fr(r, "compose outer");
		செல் out;
	}
	தேர்வு (type) {
#ifdef WITH_OPENSSL
	நிலை சாவி_ECDSA_SK:
		எனில் ((r = sshsk_ecdsa_sig(resp, sig)) != 0)
			செல் out;
		நிறுத்து;
#endif /* WITH_OPENSSL */
	நிலை சாவி_ED25519_SK:
		எனில் ((r = sshsk_ed25519_sig(resp, sig)) != 0)
			செல் out;
		நிறுத்து;
	}
#ifdef DEBUG_SK
	fprintf(stderr, "%s: sig_flags = 0x%02x, sig_counter = %u\n",
	    __func__, resp->flags, resp->counter);
	fprintf(stderr, "%s: data to sign:\n", __func__);
	sshbuf_dump_data(data, datalen, stderr);
	fprintf(stderr, "%s: sigbuf:\n", __func__);
	sshbuf_dump(sig, stderr);
#endif
	எனில் (sigp != வெற்று) {
		எனில் ((*sigp = malloc(sshbuf_len(sig))) == வெற்று) {
			r = SSH_ERR_ALLOC_FAIL;
			செல் out;
		}
		memcpy(*sigp, sshbuf_ptr(sig), sshbuf_len(sig));
	}
	எனில் (lenp != வெற்று)
		*lenp = sshbuf_len(sig);
	/* success */
	r = 0;
 out:
	sshsk_free_options(opts);
	sshsk_free(skp);
	sshsk_free_sign_response(resp);
	sshbuf_free(sig);
	sshbuf_free(inner_sig);
	திரும்பு r;
}

நிலையான வெறுமை
sshsk_free_sk_resident_சாவிகள்(கட்டமைப்பு sk_resident_சாவி **rks, size_t nrks)
{
	size_t i;

	எனில் (nrks == 0 || rks == வெற்று)
		திரும்பு;
	க்கு (i = 0; i < nrks; i++) {
		விடுவி(rks[i]->application);
		freezero(rks[i]->user_id, rks[i]->user_id_len);
		freezero(rks[i]->சாவி.சாவி_handle, rks[i]->சாவி.சாவி_handle_len);
		freezero(rks[i]->சாவி.public_சாவி, rks[i]->சாவி.public_சாவி_len);
		freezero(rks[i]->சாவி.signature, rks[i]->சாவி.signature_len);
		freezero(rks[i]->சாவி.attestation_cert,
		    rks[i]->சாவி.attestation_cert_len);
		freezero(rks[i], அளவு(**rks));
	}
	விடுவி(rks);
}

நிலையான வெறுமை
sshsk_free_resident_சாவி(கட்டமைப்பு sshsk_resident_சாவி *srk)
{
	எனில் (srk == வெற்று)
		திரும்பு;
	sshkey_free(srk->சாவி);
	freezero(srk->user_id, srk->user_id_len);
	விடுவி(srk);
}


வெறுமை
sshsk_free_resident_சாவிகள்(கட்டமைப்பு sshsk_resident_சாவி **srks, size_t nsrks)
{
	size_t i;

	எனில் (srks == வெற்று || nsrks == 0)
		திரும்பு;

	க்கு (i = 0; i < nsrks; i++)
		sshsk_free_resident_சாவி(srks[i]);
	விடுவி(srks);
}

முழு
sshsk_load_resident(மாறிலி எழுத்து *provider_path, மாறிலி எழுத்து *device,
    மாறிலி எழுத்து *pin, u_int flags, கட்டமைப்பு sshsk_resident_சாவி ***srksp,
    size_t *nsrksp)
{
	கட்டமைப்பு sshsk_provider *skp = வெற்று;
	முழு r = SSH_ERR_INTERNAL_ERROR;
	கட்டமைப்பு sk_resident_சாவி **rks = வெற்று;
	size_t i, nrks = 0, nsrks = 0;
	கட்டமைப்பு sshkey *சாவி = வெற்று;
	கட்டமைப்பு sshsk_resident_சாவி *srk = வெற்று, **srks = வெற்று, **tmp;
	uint8_t sk_flags;
	கட்டமைப்பு sk_option **opts = வெற்று;

	debug_f("provider \"%s\"%s", provider_path,
	    (pin != வெற்று && *pin != '\0') ? ", have-pin": "");

	எனில் (srksp == வெற்று || nsrksp == வெற்று)
		திரும்பு SSH_ERR_INVALID_ARGUMENT;
	*srksp = வெற்று;
	*nsrksp = 0;

	எனில் ((r = make_options(device, வெற்று, &opts)) != 0)
		செல் out;
	எனில் ((skp = sshsk_open(provider_path)) == வெற்று) {
		r = SSH_ERR_INVALID_FORMAT; /* XXX sshsk_open return code? */
		செல் out;
	}
	எனில் ((r = skp->sk_load_resident_சாவிகள்(pin, opts, &rks, &nrks)) != 0) {
		error("Provider \"%s\" returned failure %d", provider_path, r);
		r = skerr_to_ssherr(r);
		செல் out;
	}
	க்கு (i = 0; i < nrks; i++) {
		debug3_f("rk %zu: slot %zu, alg %d, app \"%s\", uidlen %zu",
		    i, rks[i]->slot, rks[i]->alg, rks[i]->application,
		    rks[i]->user_id_len);
		/* XXX need better filter here */
		எனில் (strncmp(rks[i]->application, "ssh:", 4) != 0)
			தொடர்;
		தேர்வு (rks[i]->alg) {
		நிலை SSH_SK_ECDSA:
		நிலை SSH_SK_ED25519:
			நிறுத்து;
		இயல்பு:
			தொடர்;
		}
		sk_flags = SSH_SK_USER_PRESENCE_REQD|SSH_SK_RESIDENT_சாவி;
		எனில் ((rks[i]->flags & SSH_SK_USER_VERIFICATION_REQD))
			sk_flags |= SSH_SK_USER_VERIFICATION_REQD;
		எனில் ((r = sshsk_சாவி_from_response(rks[i]->alg,
		    rks[i]->application, sk_flags, &rks[i]->சாவி, &சாவி)) != 0)
			செல் out;
		எனில் ((srk = calloc(1, அளவு(*srk))) == வெற்று) {
			error_f("calloc failed");
			r = SSH_ERR_ALLOC_FAIL;
			செல் out;
		}
		srk->சாவி = சாவி;
		சாவி = வெற்று; /* transferred */
		எனில் ((srk->user_id = calloc(1, rks[i]->user_id_len)) == வெற்று) {
			error_f("calloc failed");
			r = SSH_ERR_ALLOC_FAIL;
			செல் out;
		}
		memcpy(srk->user_id, rks[i]->user_id, rks[i]->user_id_len);
		srk->user_id_len = rks[i]->user_id_len;
		எனில் ((tmp = recallocarray(srks, nsrks, nsrks + 1,
		    அளவு(*tmp))) == வெற்று) {
			error_f("recallocarray failed");
			r = SSH_ERR_ALLOC_FAIL;
			செல் out;
		}
		srks = tmp;
		srks[nsrks++] = srk;
		srk = வெற்று;
		/* XXX synthesise comment */
	}
	/* success */
	*srksp = srks;
	*nsrksp = nsrks;
	srks = வெற்று;
	nsrks = 0;
	r = 0;
 out:
	sshsk_free_options(opts);
	sshsk_free(skp);
	sshsk_free_sk_resident_சாவிகள்(rks, nrks);
	sshkey_free(சாவி);
	sshsk_free_resident_சாவி(srk);
	sshsk_free_resident_சாவிகள்(srks, nsrks);
	திரும்பு r;
}

#endif /* ENABLE_SK */
