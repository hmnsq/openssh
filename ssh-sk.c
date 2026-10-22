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

#ضمن "includes.h"

#ifdef ENABLE_SK

#ضمن <dlfcn.h>
#ضمن <stddef.h>
#ضمن <stdint.h>
#ضمن <string.h>
#ضمن <stdio.h>

#ifdef WITH_OPENSSL
#ضمن <openssl/objects.h>
#ضمن <openssl/ec.h>
#ضمن <openssl/evp.h>
#endif /* WITH_OPENSSL */

#ضمن "log.h"
#ضمن "misc.h"
#ضمن "sshbuf.h"
#ضمن "sshkey.h"
#ضمن "ssherr.h"
#ضمن "digest.h"

#ضمن "ssh-sk.h"
#ضمن "sk-api.h"
#ضمن "crypto_api.h"

بنية sshsk_provider {
	حرف *path;
	فراغ *dlhandle;

	/* Return the version of the middleware API */
	uint32_t (*sk_api_version)(فراغ);

	/* Enroll a U2F key (private key generation) */
	صحيح (*sk_enroll)(صحيح alg, ثابت uint8_t *challenge,
	    size_t challenge_len, ثابت حرف *application, uint8_t flags,
	    ثابت حرف *pin, بنية sk_option **opts,
	    بنية sk_enroll_response **enroll_response);

	/* Sign a challenge */
	صحيح (*sk_sign)(صحيح alg, ثابت uint8_t *message, size_t message_len,
	    ثابت حرف *application,
	    ثابت uint8_t *key_handle, size_t key_handle_len,
	    uint8_t flags, ثابت حرف *pin, بنية sk_option **opts,
	    بنية sk_sign_response **sign_response);

	/* Enumerate resident keys */
	صحيح (*sk_load_resident_keys)(ثابت حرف *pin, بنية sk_option **opts,
	    بنية sk_resident_key ***rks, size_t *nrks);
};

/* Built-in version */
صحيح ssh_sk_enroll(صحيح alg, ثابت uint8_t *challenge,
    size_t challenge_len, ثابت حرف *application, uint8_t flags,
    ثابت حرف *pin, بنية sk_option **opts,
    بنية sk_enroll_response **enroll_response);
صحيح ssh_sk_sign(صحيح alg, ثابت uint8_t *message, size_t message_len,
    ثابت حرف *application,
    ثابت uint8_t *key_handle, size_t key_handle_len,
    uint8_t flags, ثابت حرف *pin, بنية sk_option **opts,
    بنية sk_sign_response **sign_response);
صحيح ssh_sk_load_resident_keys(ثابت حرف *pin, بنية sk_option **opts,
    بنية sk_resident_key ***rks, size_t *nrks);

ساكن فراغ
sshsk_free(بنية sshsk_provider *p)
{
	אם (p == عدم)
		החזר;
	حرر(p->path);
	אם (p->dlhandle != عدم)
		dlclose(p->dlhandle);
	حرر(p);
}

ساكن بنية sshsk_provider *
sshsk_open(ثابت حرف *path)
{
	بنية sshsk_provider *ret = عدم;
	uint32_t version;

	אם (path == عدم || *path == '\0') {
		error("No FIDO SecurityKeyProvider specified");
		החזר عدم;
	}
	אם ((ret = calloc(1, حجم(*ret))) == عدم) {
		error_f("calloc failed");
		החזר عدم;
	}
	אם ((ret->path = strdup(path)) == عدم) {
		error_f("strdup failed");
		اذهب fail;
	}
	/* Skip the rest if we're using the linked in middleware */
	אם (strcasecmp(ret->path, "internal") == 0) {
#ifdef ENABLE_SK_INTERNAL
		ret->sk_enroll = ssh_sk_enroll;
		ret->sk_sign = ssh_sk_sign;
		ret->sk_load_resident_keys = ssh_sk_load_resident_keys;
		החזר ret;
#אחרת
		error("internal security key support not enabled");
		اذهب fail;
#endif
	}
	אם (lib_contains_symbol(path, "sk_api_version") != 0) {
		error("provider %s is not an OpenSSH FIDO library", path);
		اذهب fail;
	}
	אם ((ret->dlhandle = dlopen(path, RTLD_NOW)) == عدم)
		fatal("Provider \"%s\" dlopen failed: %s", path, dlerror());
	אם ((ret->sk_api_version = dlsym(ret->dlhandle,
	    "sk_api_version")) == عدم) {
		error("Provider \"%s\" dlsym(sk_api_version) failed: %s",
		    path, dlerror());
		اذهب fail;
	}
	version = ret->sk_api_version();
	debug_f("provider %s implements version 0x%08lx", ret->path,
	    (u_long)version);
	אם ((version & SSH_SK_VERSION_MAJOR_MASK) != SSH_SK_VERSION_MAJOR) {
		error("Provider \"%s\" implements unsupported "
		    "version 0x%08lx (supported: 0x%08lx)",
		    path, (u_long)version, (u_long)SSH_SK_VERSION_MAJOR);
		اذهب fail;
	}
	אם ((ret->sk_enroll = dlsym(ret->dlhandle, "sk_enroll")) == عدم) {
		error("Provider %s dlsym(sk_enroll) failed: %s",
		    path, dlerror());
		اذهب fail;
	}
	אם ((ret->sk_sign = dlsym(ret->dlhandle, "sk_sign")) == عدم) {
		error("Provider \"%s\" dlsym(sk_sign) failed: %s",
		    path, dlerror());
		اذهب fail;
	}
	אם ((ret->sk_load_resident_keys = dlsym(ret->dlhandle,
	    "sk_load_resident_keys")) == عدم) {
		error("Provider \"%s\" dlsym(sk_load_resident_keys) "
		    "failed: %s", path, dlerror());
		اذهب fail;
	}
	/* success */
	החזר ret;
fail:
	sshsk_free(ret);
	החזר عدم;
}

ساكن فراغ
sshsk_free_enroll_response(بنية sk_enroll_response *r)
{
	אם (r == عدم)
		החזר;
	freezero(r->key_handle, r->key_handle_len);
	freezero(r->public_key, r->public_key_len);
	freezero(r->signature, r->signature_len);
	freezero(r->attestation_cert, r->attestation_cert_len);
	freezero(r->authdata, r->authdata_len);
	freezero(r, حجم(*r));
}

ساكن فراغ
sshsk_free_sign_response(بنية sk_sign_response *r)
{
	אם (r == عدم)
		החזר;
	freezero(r->sig_r, r->sig_r_len);
	freezero(r->sig_s, r->sig_s_len);
	freezero(r, حجم(*r));
}

#ifdef WITH_OPENSSL
/* Assemble key from response */
ساكن صحيح
sshsk_ecdsa_assemble(بنية sk_enroll_response *resp, بنية sshkey **keyp)
{
	بنية sshkey *key = عدم;
	بنية sshbuf *b = عدم;
	EC_KEY *ecdsa = عدم;
	EC_POINT *q = عدم;
	ثابت EC_GROUP *g = عدم;
	صحيح r;

	*keyp = عدم;
	אם ((key = sshkey_new(KEY_ECDSA_SK)) == عدم) {
		error_f("sshkey_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		اذهب out;
	}
	key->ecdsa_nid = NID_X9_62_prime256v1;
	אם ((ecdsa = EC_KEY_new_by_curve_name(key->ecdsa_nid)) == عدم ||
	    (g = EC_KEY_get0_group(ecdsa)) == عدم ||
	    (q = EC_POINT_new(g)) == عدم ||
	    (b = sshbuf_new()) == عدم) {
		error_f("allocation failed");
		r = SSH_ERR_ALLOC_FAIL;
		اذهب out;
	}
	אם ((r = sshbuf_put_string(b,
	    resp->public_key, resp->public_key_len)) != 0) {
		error_fr(r, "sshbuf_put_string");
		اذهب out;
	}
	אם ((r = sshbuf_get_ec(b, q, g)) != 0) {
		error_fr(r, "parse");
		r = SSH_ERR_INVALID_FORMAT;
		اذهب out;
	}
	אם (sshkey_ec_validate_public(g, q) != 0) {
		error("Authenticator returned invalid ECDSA key");
		r = SSH_ERR_KEY_INVALID_EC_VALUE;
		اذهب out;
	}
	אם (EC_KEY_set_public_key(ecdsa, q) != 1) {
		/* XXX assume it is a allocation error */
		error_f("allocation failed");
		r = SSH_ERR_ALLOC_FAIL;
		اذهب out;
	}
	אם ((key->pkey = EVP_PKEY_new()) == عدم) {
		error_f("allocation failed");
		r = SSH_ERR_ALLOC_FAIL;
		اذهب out;
	}
	אם (EVP_PKEY_set1_EC_KEY(key->pkey, ecdsa) != 1) {
		error_f("Assigning EC_KEY failed");
		r = SSH_ERR_LIBCRYPTO_ERROR;
		اذهب out;
	}
	/* success */
	*keyp = key;
	key = عدم; /* transferred */
	r = 0;
 out:
	sshkey_free(key);
	sshbuf_free(b);
	EC_KEY_free(ecdsa);
	EC_POINT_free(q);
	החזר r;
}
#endif /* WITH_OPENSSL */

ساكن صحيح
sshsk_ed25519_assemble(بنية sk_enroll_response *resp, بنية sshkey **keyp)
{
	بنية sshkey *key = عدم;
	صحيح r;

	*keyp = عدم;
	אם (resp->public_key_len != ED25519_PK_SZ) {
		error_f("invalid size: %zu", resp->public_key_len);
		r = SSH_ERR_INVALID_FORMAT;
		اذهب out;
	}
	אם ((key = sshkey_new(KEY_ED25519_SK)) == عدم) {
		error_f("sshkey_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		اذهب out;
	}
	אם ((key->ed25519_pk = malloc(ED25519_PK_SZ)) == عدم) {
		error_f("malloc failed");
		r = SSH_ERR_ALLOC_FAIL;
		اذهب out;
	}
	memcpy(key->ed25519_pk, resp->public_key, ED25519_PK_SZ);
	/* success */
	*keyp = key;
	key = عدم; /* transferred */
	r = 0;
 out:
	sshkey_free(key);
	החזר r;
}

ساكن صحيح
sshsk_key_from_response(صحيح alg, ثابت حرف *application, uint8_t flags,
    بنية sk_enroll_response *resp, بنية sshkey **keyp)
{
	بنية sshkey *key = عدم;
	صحيح r = SSH_ERR_INTERNAL_ERROR;

	*keyp = عدم;

	/* Check response validity */
	אם (resp->public_key == عدم || resp->key_handle == عدم) {
		error_f("sk_enroll response invalid");
		r = SSH_ERR_INVALID_FORMAT;
		اذهب out;
	}
	بدل (alg) {
#ifdef WITH_OPENSSL
	حالة SSH_SK_ECDSA:
		אם ((r = sshsk_ecdsa_assemble(resp, &key)) != 0)
			اذهب out;
		اكسر;
#endif /* WITH_OPENSSL */
	حالة SSH_SK_ED25519:
		אם ((r = sshsk_ed25519_assemble(resp, &key)) != 0)
			اذهب out;
		اكسر;
	افتراضي:
		error_f("unsupported algorithm %d", alg);
		r = SSH_ERR_INVALID_ARGUMENT;
		اذهب out;
	}
	key->sk_flags = flags;
	אם ((key->sk_key_handle = sshbuf_new()) == عدم ||
	    (key->sk_reserved = sshbuf_new()) == عدم) {
		error_f("allocation failed");
		r = SSH_ERR_ALLOC_FAIL;
		اذهب out;
	}
	אם ((key->sk_application = strdup(application)) == عدم) {
		error_f("strdup application failed");
		r = SSH_ERR_ALLOC_FAIL;
		اذهب out;
	}
	אם ((r = sshbuf_put(key->sk_key_handle, resp->key_handle,
	    resp->key_handle_len)) != 0) {
		error_fr(r, "put key handle");
		اذهب out;
	}
	/* success */
	r = 0;
	*keyp = key;
	key = عدم;
 out:
	sshkey_free(key);
	החזר r;
}

ساكن صحيح
skerr_to_ssherr(صحيح skerr)
{
	بدل (skerr) {
	حالة SSH_SK_ERR_UNSUPPORTED:
		החזר SSH_ERR_FEATURE_UNSUPPORTED;
	حالة SSH_SK_ERR_PIN_REQUIRED:
		החזר SSH_ERR_KEY_WRONG_PASSPHRASE;
	حالة SSH_SK_ERR_DEVICE_NOT_FOUND:
		החזר SSH_ERR_DEVICE_NOT_FOUND;
	حالة SSH_SK_ERR_CREDENTIAL_EXISTS:
		החזר SSH_ERR_KEY_BAD_PERMISSIONS;
	حالة SSH_SK_ERR_GENERAL:
	افتراضي:
		החזר SSH_ERR_INVALID_FORMAT;
	}
}

ساكن فراغ
sshsk_free_options(بنية sk_option **opts)
{
	size_t i;

	אם (opts == عدم)
		החזר;
	עבור (i = 0; opts[i] != عدم; i++) {
		حرر(opts[i]->name);
		حرر(opts[i]->value);
		حرر(opts[i]);
	}
	حرر(opts);
}

ساكن صحيح
sshsk_add_option(بنية sk_option ***optsp, size_t *noptsp,
    ثابت حرف *name, ثابت حرف *value, uint8_t required)
{
	بنية sk_option **opts = *optsp;
	size_t nopts = *noptsp;

	אם ((opts = recallocarray(opts, nopts, nopts + 2, /* extra for NULL */
	    حجم(*opts))) == عدم) {
		error_f("array alloc failed");
		החזר SSH_ERR_ALLOC_FAIL;
	}
	*optsp = opts;
	*noptsp = nopts + 1;
	אם ((opts[nopts] = calloc(1, حجم(**opts))) == عدم) {
		error_f("alloc failed");
		החזר SSH_ERR_ALLOC_FAIL;
	}
	אם ((opts[nopts]->name = strdup(name)) == عدم ||
	    (opts[nopts]->value = strdup(value)) == عدم) {
		error_f("alloc failed");
		החזר SSH_ERR_ALLOC_FAIL;
	}
	opts[nopts]->required = required;
	החזר 0;
}

ساكن صحيح
make_options(ثابت حرف *device, ثابت حرف *user_id,
    بنية sk_option ***optsp)
{
	بنية sk_option **opts = عدم;
	size_t nopts = 0;
	صحيح r, ret = SSH_ERR_INTERNAL_ERROR;

	אם (device != عدم &&
	    (r = sshsk_add_option(&opts, &nopts, "device", device, 0)) != 0) {
		ret = r;
		اذهب out;
	}
	אם (user_id != عدم &&
	    (r = sshsk_add_option(&opts, &nopts, "user", user_id, 0)) != 0) {
		ret = r;
		اذهب out;
	}
	/* success */
	*optsp = opts;
	opts = عدم;
	nopts = 0;
	ret = 0;
 out:
	sshsk_free_options(opts);
	החזר ret;
}


ساكن صحيح
fill_attestation_blob(ثابت بنية sk_enroll_response *resp,
    بنية sshbuf *attest)
{
	صحيح r;

	אם (attest == عدم)
		החזר 0; /* nothing to do */
	אם ((r = sshbuf_put_cstring(attest, "ssh-sk-attest-v01")) != 0 ||
	    (r = sshbuf_put_string(attest,
	    resp->attestation_cert, resp->attestation_cert_len)) != 0 ||
	    (r = sshbuf_put_string(attest,
	    resp->signature, resp->signature_len)) != 0 ||
	    (r = sshbuf_put_string(attest,
	    resp->authdata, resp->authdata_len)) != 0 ||
	    (r = sshbuf_put_u32(attest, 0)) != 0 || /* resvd flags */
	    (r = sshbuf_put_string(attest, عدم, 0)) != 0 /* resvd */) {
		error_fr(r, "compose");
		החזר r;
	}
	/* success */
	החזר 0;
}

صحيح
sshsk_enroll(صحيح type, ثابت حرف *provider_path, ثابت حرف *device,
    ثابت حرف *application, ثابت حرف *userid, uint8_t flags,
    ثابت حرف *pin, بنية sshbuf *challenge_buf,
    بنية sshkey **keyp, بنية sshbuf *attest)
{
	بنية sshsk_provider *skp = عدم;
	بنية sshkey *key = عدم;
	u_char randchall[32];
	ثابت u_char *challenge;
	size_t challenge_len;
	بنية sk_enroll_response *resp = عدم;
	بنية sk_option **opts = عدم;
	صحيح r = SSH_ERR_INTERNAL_ERROR;
	صحيح alg;

	debug_f("provider \"%s\", device \"%s\", application \"%s\", "
	    "userid \"%s\", flags 0x%02x, challenge len %zu%s",
	    provider_path, device, application, userid, flags,
	    challenge_buf == عدم ? 0 : sshbuf_len(challenge_buf),
	    (pin != عدم && *pin != '\0') ? " with-pin" : "");

	*keyp = عدم;
	אם (attest)
		sshbuf_reset(attest);

	אם ((r = make_options(device, userid, &opts)) != 0)
		اذهب out;

	بدل (type) {
#ifdef WITH_OPENSSL
	حالة KEY_ECDSA_SK:
		alg = SSH_SK_ECDSA;
		اكسر;
#endif /* WITH_OPENSSL */
	حالة KEY_ED25519_SK:
		alg = SSH_SK_ED25519;
		اكسر;
	افتراضي:
		error_f("unsupported key type");
		r = SSH_ERR_INVALID_ARGUMENT;
		اذهب out;
	}
	אם (provider_path == عدم) {
		error_f("missing provider");
		r = SSH_ERR_INVALID_ARGUMENT;
		اذهب out;
	}
	אם (application == عدم || *application == '\0') {
		error_f("missing application");
		r = SSH_ERR_INVALID_ARGUMENT;
		اذهب out;
	}
	אם (challenge_buf == عدم) {
		debug_f("using random challenge");
		arc4random_buf(randchall, حجم(randchall));
		challenge = randchall;
		challenge_len = حجم(randchall);
	} אחרת אם (sshbuf_len(challenge_buf) == 0) {
		error("Missing enrollment challenge");
		r = SSH_ERR_INVALID_ARGUMENT;
		اذهب out;
	} אחרת {
		challenge = sshbuf_ptr(challenge_buf);
		challenge_len = sshbuf_len(challenge_buf);
		debug3_f("using explicit challenge len=%zd", challenge_len);
	}
	אם ((skp = sshsk_open(provider_path)) == عدم) {
		r = SSH_ERR_INVALID_FORMAT; /* XXX sshsk_open return code? */
		اذهب out;
	}
	/* XXX validate flags? */
	/* enroll key */
	אם ((r = skp->sk_enroll(alg, challenge, challenge_len, application,
	    flags, pin, opts, &resp)) != 0) {
		debug_f("provider \"%s\" failure %d", provider_path, r);
		r = skerr_to_ssherr(r);
		اذهب out;
	}

	אם ((r = sshsk_key_from_response(alg, application, resp->flags,
	    resp, &key)) != 0)
		اذهب out;

	/* Optionally fill in the attestation information */
	אם ((r = fill_attestation_blob(resp, attest)) != 0)
		اذهب out;

	/* success */
	*keyp = key;
	key = عدم; /* transferred */
	r = 0;
 out:
	sshsk_free_options(opts);
	sshsk_free(skp);
	sshkey_free(key);
	sshsk_free_enroll_response(resp);
	explicit_bzero(randchall, حجم(randchall));
	החזר r;
}

#ifdef WITH_OPENSSL
ساكن صحيح
sshsk_ecdsa_sig(بنية sk_sign_response *resp, بنية sshbuf *sig)
{
	بنية sshbuf *inner_sig = عدم;
	صحيح r = SSH_ERR_INTERNAL_ERROR;

	/* Check response validity */
	אם (resp->sig_r == عدم || resp->sig_s == عدم) {
		error_f("sk_sign response invalid");
		r = SSH_ERR_INVALID_FORMAT;
		اذهب out;
	}
	אם ((inner_sig = sshbuf_new()) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب out;
	}
	/* Prepare and append inner signature object */
	אם ((r = sshbuf_put_bignum2_bytes(inner_sig,
	    resp->sig_r, resp->sig_r_len)) != 0 ||
	    (r = sshbuf_put_bignum2_bytes(inner_sig,
	    resp->sig_s, resp->sig_s_len)) != 0) {
		error_fr(r, "compose inner");
		اذهب out;
	}
	אם ((r = sshbuf_put_stringb(sig, inner_sig)) != 0 ||
	    (r = sshbuf_put_u8(sig, resp->flags)) != 0 ||
	    (r = sshbuf_put_u32(sig, resp->counter)) != 0) {
		error_fr(r, "compose");
		اذهب out;
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
	החזר r;
}
#endif /* WITH_OPENSSL */

ساكن صحيح
sshsk_ed25519_sig(بنية sk_sign_response *resp, بنية sshbuf *sig)
{
	صحيح r = SSH_ERR_INTERNAL_ERROR;

	/* Check response validity */
	אם (resp->sig_r == عدم) {
		error_f("sk_sign response invalid");
		r = SSH_ERR_INVALID_FORMAT;
		اذهب out;
	}
	אם ((r = sshbuf_put_string(sig,
	    resp->sig_r, resp->sig_r_len)) != 0 ||
	    (r = sshbuf_put_u8(sig, resp->flags)) != 0 ||
	    (r = sshbuf_put_u32(sig, resp->counter)) != 0) {
		error_fr(r, "compose");
		اذهب out;
	}
#ifdef DEBUG_SK
	fprintf(stderr, "%s: sig_r:\n", __func__);
	sshbuf_dump_data(resp->sig_r, resp->sig_r_len, stderr);
#endif
	r = 0;
 out:
	החזר r;
}

صحيح
sshsk_sign(ثابت حرف *provider_path, بنية sshkey *key,
    u_char **sigp, size_t *lenp, ثابت u_char *data, size_t datalen,
    u_int compat, ثابت حرف *pin)
{
	بنية sshsk_provider *skp = عدم;
	صحيح r = SSH_ERR_INTERNAL_ERROR;
	صحيح type, alg;
	بنية sk_sign_response *resp = عدم;
	بنية sshbuf *inner_sig = عدم, *sig = عدم;
	بنية sk_option **opts = عدم;

	debug_f("provider \"%s\", key %s, flags 0x%02x%s",
	    provider_path, sshkey_type(key), key->sk_flags,
	    (pin != عدم && *pin != '\0') ? " with-pin" : "");

	אם (sigp != عدم)
		*sigp = عدم;
	אם (lenp != عدم)
		*lenp = 0;
	type = sshkey_type_plain(key->type);
	بدل (type) {
#ifdef WITH_OPENSSL
	حالة KEY_ECDSA_SK:
		alg = SSH_SK_ECDSA;
		اكسر;
#endif /* WITH_OPENSSL */
	حالة KEY_ED25519_SK:
		alg = SSH_SK_ED25519;
		اكسر;
	افتراضي:
		החזר SSH_ERR_INVALID_ARGUMENT;
	}
	אם (provider_path == عدم ||
	    key->sk_key_handle == عدم ||
	    key->sk_application == عدم || *key->sk_application == '\0') {
		r = SSH_ERR_INVALID_ARGUMENT;
		اذهب out;
	}
	אם ((skp = sshsk_open(provider_path)) == عدم) {
		r = SSH_ERR_INVALID_FORMAT; /* XXX sshsk_open return code? */
		اذهب out;
	}
#ifdef DEBUG_SK
	fprintf(stderr, "%s: sk_flags = 0x%02x, sk_application = \"%s\"\n",
	    __func__, key->sk_flags, key->sk_application);
	fprintf(stderr, "%s: sk_key_handle:\n", __func__);
	sshbuf_dump(key->sk_key_handle, stderr);
#endif
	אם ((r = skp->sk_sign(alg, data, datalen, key->sk_application,
	    sshbuf_ptr(key->sk_key_handle), sshbuf_len(key->sk_key_handle),
	    key->sk_flags, pin, opts, &resp)) != 0) {
		debug_f("sk_sign failed with code %d", r);
		r = skerr_to_ssherr(r);
		اذهب out;
	}
	/* Assemble signature */
	אם ((sig = sshbuf_new()) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب out;
	}
	אם ((r = sshbuf_put_cstring(sig, sshkey_ssh_name_plain(key))) != 0) {
		error_fr(r, "compose outer");
		اذهب out;
	}
	بدل (type) {
#ifdef WITH_OPENSSL
	حالة KEY_ECDSA_SK:
		אם ((r = sshsk_ecdsa_sig(resp, sig)) != 0)
			اذهب out;
		اكسر;
#endif /* WITH_OPENSSL */
	حالة KEY_ED25519_SK:
		אם ((r = sshsk_ed25519_sig(resp, sig)) != 0)
			اذهب out;
		اكسر;
	}
#ifdef DEBUG_SK
	fprintf(stderr, "%s: sig_flags = 0x%02x, sig_counter = %u\n",
	    __func__, resp->flags, resp->counter);
	fprintf(stderr, "%s: data to sign:\n", __func__);
	sshbuf_dump_data(data, datalen, stderr);
	fprintf(stderr, "%s: sigbuf:\n", __func__);
	sshbuf_dump(sig, stderr);
#endif
	אם (sigp != عدم) {
		אם ((*sigp = malloc(sshbuf_len(sig))) == عدم) {
			r = SSH_ERR_ALLOC_FAIL;
			اذهب out;
		}
		memcpy(*sigp, sshbuf_ptr(sig), sshbuf_len(sig));
	}
	אם (lenp != عدم)
		*lenp = sshbuf_len(sig);
	/* success */
	r = 0;
 out:
	sshsk_free_options(opts);
	sshsk_free(skp);
	sshsk_free_sign_response(resp);
	sshbuf_free(sig);
	sshbuf_free(inner_sig);
	החזר r;
}

ساكن فراغ
sshsk_free_sk_resident_keys(بنية sk_resident_key **rks, size_t nrks)
{
	size_t i;

	אם (nrks == 0 || rks == عدم)
		החזר;
	עבור (i = 0; i < nrks; i++) {
		حرر(rks[i]->application);
		freezero(rks[i]->user_id, rks[i]->user_id_len);
		freezero(rks[i]->key.key_handle, rks[i]->key.key_handle_len);
		freezero(rks[i]->key.public_key, rks[i]->key.public_key_len);
		freezero(rks[i]->key.signature, rks[i]->key.signature_len);
		freezero(rks[i]->key.attestation_cert,
		    rks[i]->key.attestation_cert_len);
		freezero(rks[i], حجم(**rks));
	}
	حرر(rks);
}

ساكن فراغ
sshsk_free_resident_key(بنية sshsk_resident_key *srk)
{
	אם (srk == عدم)
		החזר;
	sshkey_free(srk->key);
	freezero(srk->user_id, srk->user_id_len);
	حرر(srk);
}


فراغ
sshsk_free_resident_keys(بنية sshsk_resident_key **srks, size_t nsrks)
{
	size_t i;

	אם (srks == عدم || nsrks == 0)
		החזר;

	עבור (i = 0; i < nsrks; i++)
		sshsk_free_resident_key(srks[i]);
	حرر(srks);
}

صحيح
sshsk_load_resident(ثابت حرف *provider_path, ثابت حرف *device,
    ثابت حرف *pin, u_int flags, بنية sshsk_resident_key ***srksp,
    size_t *nsrksp)
{
	بنية sshsk_provider *skp = عدم;
	صحيح r = SSH_ERR_INTERNAL_ERROR;
	بنية sk_resident_key **rks = عدم;
	size_t i, nrks = 0, nsrks = 0;
	بنية sshkey *key = عدم;
	بنية sshsk_resident_key *srk = عدم, **srks = عدم, **tmp;
	uint8_t sk_flags;
	بنية sk_option **opts = عدم;

	debug_f("provider \"%s\"%s", provider_path,
	    (pin != عدم && *pin != '\0') ? ", have-pin": "");

	אם (srksp == عدم || nsrksp == عدم)
		החזר SSH_ERR_INVALID_ARGUMENT;
	*srksp = عدم;
	*nsrksp = 0;

	אם ((r = make_options(device, عدم, &opts)) != 0)
		اذهب out;
	אם ((skp = sshsk_open(provider_path)) == عدم) {
		r = SSH_ERR_INVALID_FORMAT; /* XXX sshsk_open return code? */
		اذهب out;
	}
	אם ((r = skp->sk_load_resident_keys(pin, opts, &rks, &nrks)) != 0) {
		error("Provider \"%s\" returned failure %d", provider_path, r);
		r = skerr_to_ssherr(r);
		اذهب out;
	}
	עבור (i = 0; i < nrks; i++) {
		debug3_f("rk %zu: slot %zu, alg %d, app \"%s\", uidlen %zu",
		    i, rks[i]->slot, rks[i]->alg, rks[i]->application,
		    rks[i]->user_id_len);
		/* XXX need better filter here */
		אם (strncmp(rks[i]->application, "ssh:", 4) != 0)
			استمر;
		بدل (rks[i]->alg) {
		حالة SSH_SK_ECDSA:
		حالة SSH_SK_ED25519:
			اكسر;
		افتراضي:
			استمر;
		}
		sk_flags = SSH_SK_USER_PRESENCE_REQD|SSH_SK_RESIDENT_KEY;
		אם ((rks[i]->flags & SSH_SK_USER_VERIFICATION_REQD))
			sk_flags |= SSH_SK_USER_VERIFICATION_REQD;
		אם ((r = sshsk_key_from_response(rks[i]->alg,
		    rks[i]->application, sk_flags, &rks[i]->key, &key)) != 0)
			اذهب out;
		אם ((srk = calloc(1, حجم(*srk))) == عدم) {
			error_f("calloc failed");
			r = SSH_ERR_ALLOC_FAIL;
			اذهب out;
		}
		srk->key = key;
		key = عدم; /* transferred */
		אם ((srk->user_id = calloc(1, rks[i]->user_id_len)) == عدم) {
			error_f("calloc failed");
			r = SSH_ERR_ALLOC_FAIL;
			اذهب out;
		}
		memcpy(srk->user_id, rks[i]->user_id, rks[i]->user_id_len);
		srk->user_id_len = rks[i]->user_id_len;
		אם ((tmp = recallocarray(srks, nsrks, nsrks + 1,
		    حجم(*tmp))) == عدم) {
			error_f("recallocarray failed");
			r = SSH_ERR_ALLOC_FAIL;
			اذهب out;
		}
		srks = tmp;
		srks[nsrks++] = srk;
		srk = عدم;
		/* XXX synthesise comment */
	}
	/* success */
	*srksp = srks;
	*nsrksp = nsrks;
	srks = عدم;
	nsrks = 0;
	r = 0;
 out:
	sshsk_free_options(opts);
	sshsk_free(skp);
	sshsk_free_sk_resident_keys(rks, nrks);
	sshkey_free(key);
	sshsk_free_resident_key(srk);
	sshsk_free_resident_keys(srks, nsrks);
	החזר r;
}

#endif /* ENABLE_SK */
