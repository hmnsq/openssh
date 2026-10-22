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
	    ثابت uint8_t *مبودي_handle, size_t مبودي_handle_len,
	    uint8_t flags, ثابت حرف *pin, بنية sk_option **opts,
	    بنية sk_sign_response **sign_response);

	/* Enumerate resident keys */
	صحيح (*sk_load_resident_مبوداي)(ثابت حرف *pin, بنية sk_option **opts,
	    بنية sk_resident_مبودي ***rks, size_t *nrks);
};

/* Built-in version */
صحيح ssh_sk_enroll(صحيح alg, ثابت uint8_t *challenge,
    size_t challenge_len, ثابت حرف *application, uint8_t flags,
    ثابت حرف *pin, بنية sk_option **opts,
    بنية sk_enroll_response **enroll_response);
صحيح ssh_sk_sign(صحيح alg, ثابت uint8_t *message, size_t message_len,
    ثابت حرف *application,
    ثابت uint8_t *مبودي_handle, size_t مبودي_handle_len,
    uint8_t flags, ثابت حرف *pin, بنية sk_option **opts,
    بنية sk_sign_response **sign_response);
صحيح ssh_sk_load_resident_مبوداي(ثابت حرف *pin, بنية sk_option **opts,
    بنية sk_resident_مبودي ***rks, size_t *nrks);

ساكن فراغ
sshsk_free(بنية sshsk_provider *p)
{
	إذا (p == عدم)
		أرجع;
	حرر(p->path);
	إذا (p->dlhandle != عدم)
		dlclose(p->dlhandle);
	حرر(p);
}

ساكن بنية sshsk_provider *
sshsk_open(ثابت حرف *path)
{
	بنية sshsk_provider *ret = عدم;
	uint32_t version;

	إذا (path == عدم || *path == '\0') {
		error("No FIDO SecurityKeyProvider specified");
		أرجع عدم;
	}
	إذا ((ret = calloc(1, حجم(*ret))) == عدم) {
		error_f("calloc failed");
		أرجع عدم;
	}
	إذا ((ret->path = strdup(path)) == عدم) {
		error_f("strdup failed");
		اذهب fail;
	}
	/* Skip the rest if we're using the linked in middleware */
	إذا (strcasecmp(ret->path, "internal") == 0) {
#ifdef ENABLE_SK_INTERNAL
		ret->sk_enroll = ssh_sk_enroll;
		ret->sk_sign = ssh_sk_sign;
		ret->sk_load_resident_مبوداي = ssh_sk_load_resident_مبوداي;
		أرجع ret;
#وإلا
		error("internal security key support not enabled");
		اذهب fail;
#endif
	}
	إذا (lib_contains_علام(path, "sk_api_version") != 0) {
		error("provider %s is not an OpenSSH FIDO library", path);
		اذهب fail;
	}
	إذا ((ret->dlhandle = dlopen(path, RTLD_NOW)) == عدم)
		fatal("Provider \"%s\" dlopen failed: %s", path, dlerror());
	إذا ((ret->sk_api_version = dlsym(ret->dlhandle,
	    "sk_api_version")) == عدم) {
		error("Provider \"%s\" dlsym(sk_api_version) failed: %s",
		    path, dlerror());
		اذهب fail;
	}
	version = ret->sk_api_version();
	debug_f("provider %s implements version 0x%08lx", ret->path,
	    (u_long)version);
	إذا ((version & SSH_SK_VERSION_MAJOR_MASK) != SSH_SK_VERSION_MAJOR) {
		error("Provider \"%s\" implements unsupported "
		    "version 0x%08lx (supported: 0x%08lx)",
		    path, (u_long)version, (u_long)SSH_SK_VERSION_MAJOR);
		اذهب fail;
	}
	إذا ((ret->sk_enroll = dlsym(ret->dlhandle, "sk_enroll")) == عدم) {
		error("Provider %s dlsym(sk_enroll) failed: %s",
		    path, dlerror());
		اذهب fail;
	}
	إذا ((ret->sk_sign = dlsym(ret->dlhandle, "sk_sign")) == عدم) {
		error("Provider \"%s\" dlsym(sk_sign) failed: %s",
		    path, dlerror());
		اذهب fail;
	}
	إذا ((ret->sk_load_resident_مبوداي = dlsym(ret->dlhandle,
	    "sk_load_resident_keys")) == عدم) {
		error("Provider \"%s\" dlsym(sk_load_resident_keys) "
		    "failed: %s", path, dlerror());
		اذهب fail;
	}
	/* success */
	أرجع ret;
fail:
	sshsk_free(ret);
	أرجع عدم;
}

ساكن فراغ
sshsk_free_enroll_response(بنية sk_enroll_response *r)
{
	إذا (r == عدم)
		أرجع;
	freezero(r->مبودي_handle, r->مبودي_handle_len);
	freezero(r->public_مبودي, r->public_مبودي_len);
	freezero(r->signature, r->signature_len);
	freezero(r->attestation_cert, r->attestation_cert_len);
	freezero(r->authdata, r->authdata_len);
	freezero(r, حجم(*r));
}

ساكن فراغ
sshsk_free_sign_response(بنية sk_sign_response *r)
{
	إذا (r == عدم)
		أرجع;
	freezero(r->sig_r, r->sig_r_len);
	freezero(r->sig_s, r->sig_s_len);
	freezero(r, حجم(*r));
}

#ifdef WITH_OPENSSL
/* Assemble key from response */
ساكن صحيح
sshsk_ecdsa_assemble(بنية sk_enroll_response *resp, بنية sshkey **keyp)
{
	بنية sshkey *مبودي = عدم;
	بنية sshbuf *b = عدم;
	EC_مبودي *ecdsa = عدم;
	EC_POINT *q = عدم;
	ثابت EC_GROUP *g = عدم;
	صحيح r;

	*keyp = عدم;
	إذا ((مبودي = sshkey_new(مبودي_ECDSA_SK)) == عدم) {
		error_f("sshkey_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		اذهب out;
	}
	مبودي->ecdsa_nid = NID_X9_62_prime256v1;
	إذا ((ecdsa = EC_مبودي_new_by_curve_name(مبودي->ecdsa_nid)) == عدم ||
	    (g = EC_مبودي_get0_group(ecdsa)) == عدم ||
	    (q = EC_POINT_new(g)) == عدم ||
	    (b = sshbuf_new()) == عدم) {
		error_f("allocation failed");
		r = SSH_ERR_ALLOC_FAIL;
		اذهب out;
	}
	إذا ((r = sshbuf_put_string(b,
	    resp->public_مبودي, resp->public_مبودي_len)) != 0) {
		error_fr(r, "sshbuf_put_string");
		اذهب out;
	}
	إذا ((r = sshbuf_get_ec(b, q, g)) != 0) {
		error_fr(r, "parse");
		r = SSH_ERR_INVALID_FORMAT;
		اذهب out;
	}
	إذا (sshkey_ec_validate_public(g, q) != 0) {
		error("Authenticator returned invalid ECDSA key");
		r = SSH_ERR_مبودي_INVALID_EC_درج;
		اذهب out;
	}
	إذا (EC_مبودي_set_public_مبودي(ecdsa, q) != 1) {
		/* XXX assume it is a allocation error */
		error_f("allocation failed");
		r = SSH_ERR_ALLOC_FAIL;
		اذهب out;
	}
	إذا ((مبودي->pkey = EVP_PKEY_new()) == عدم) {
		error_f("allocation failed");
		r = SSH_ERR_ALLOC_FAIL;
		اذهب out;
	}
	إذا (EVP_PKEY_set1_EC_مبودي(مبودي->pkey, ecdsa) != 1) {
		error_f("Assigning EC_KEY failed");
		r = SSH_ERR_LIBCRYPTO_ERROR;
		اذهب out;
	}
	/* success */
	*keyp = مبودي;
	مبودي = عدم; /* transferred */
	r = 0;
 out:
	sshkey_free(مبودي);
	sshbuf_free(b);
	EC_مبودي_free(ecdsa);
	EC_POINT_free(q);
	أرجع r;
}
#endif /* WITH_OPENSSL */

ساكن صحيح
sshsk_ed25519_assemble(بنية sk_enroll_response *resp, بنية sshkey **keyp)
{
	بنية sshkey *مبودي = عدم;
	صحيح r;

	*keyp = عدم;
	إذا (resp->public_مبودي_len != ED25519_PK_SZ) {
		error_f("invalid size: %zu", resp->public_مبودي_len);
		r = SSH_ERR_INVALID_FORMAT;
		اذهب out;
	}
	إذا ((مبودي = sshkey_new(مبودي_ED25519_SK)) == عدم) {
		error_f("sshkey_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		اذهب out;
	}
	إذا ((مبودي->ed25519_pk = malloc(ED25519_PK_SZ)) == عدم) {
		error_f("malloc failed");
		r = SSH_ERR_ALLOC_FAIL;
		اذهب out;
	}
	memcpy(مبودي->ed25519_pk, resp->public_مبودي, ED25519_PK_SZ);
	/* success */
	*keyp = مبودي;
	مبودي = عدم; /* transferred */
	r = 0;
 out:
	sshkey_free(مبودي);
	أرجع r;
}

ساكن صحيح
sshsk_مبودي_from_response(صحيح alg, ثابت حرف *application, uint8_t flags,
    بنية sk_enroll_response *resp, بنية sshkey **keyp)
{
	بنية sshkey *مبودي = عدم;
	صحيح r = SSH_ERR_INTERNAL_ERROR;

	*keyp = عدم;

	/* Check response validity */
	إذا (resp->public_مبودي == عدم || resp->مبودي_handle == عدم) {
		error_f("sk_enroll response invalid");
		r = SSH_ERR_INVALID_FORMAT;
		اذهب out;
	}
	بدل (alg) {
#ifdef WITH_OPENSSL
	حالة SSH_SK_ECDSA:
		إذا ((r = sshsk_ecdsa_assemble(resp, &مبودي)) != 0)
			اذهب out;
		اكسر;
#endif /* WITH_OPENSSL */
	حالة SSH_SK_ED25519:
		إذا ((r = sshsk_ed25519_assemble(resp, &مبودي)) != 0)
			اذهب out;
		اكسر;
	افتراضي:
		error_f("unsupported algorithm %d", alg);
		r = SSH_ERR_INVALID_ARGUMENT;
		اذهب out;
	}
	مبودي->sk_flags = flags;
	إذا ((مبودي->sk_مبودي_handle = sshbuf_new()) == عدم ||
	    (مبودي->sk_reserved = sshbuf_new()) == عدم) {
		error_f("allocation failed");
		r = SSH_ERR_ALLOC_FAIL;
		اذهب out;
	}
	إذا ((مبودي->sk_application = strdup(application)) == عدم) {
		error_f("strdup application failed");
		r = SSH_ERR_ALLOC_FAIL;
		اذهب out;
	}
	إذا ((r = sshbuf_put(مبودي->sk_مبودي_handle, resp->مبودي_handle,
	    resp->مبودي_handle_len)) != 0) {
		error_fr(r, "put key handle");
		اذهب out;
	}
	/* success */
	r = 0;
	*keyp = مبودي;
	مبودي = عدم;
 out:
	sshkey_free(مبودي);
	أرجع r;
}

ساكن صحيح
skerr_to_ssherr(صحيح skerr)
{
	بدل (skerr) {
	حالة SSH_SK_ERR_UNSUPPORTED:
		أرجع SSH_ERR_FEATURE_UNSUPPORTED;
	حالة SSH_SK_ERR_PIN_REQUIRED:
		أرجع SSH_ERR_مبودي_WRONG_PASSPHRASE;
	حالة SSH_SK_ERR_DEVICE_NOT_FOUND:
		أرجع SSH_ERR_DEVICE_NOT_FOUND;
	حالة SSH_SK_ERR_CREDENTIAL_EXISTS:
		أرجع SSH_ERR_مبودي_BAD_PERMISSIONS;
	حالة SSH_SK_ERR_GENERAL:
	افتراضي:
		أرجع SSH_ERR_INVALID_FORMAT;
	}
}

ساكن فراغ
sshsk_free_options(بنية sk_option **opts)
{
	size_t i;

	إذا (opts == عدم)
		أرجع;
	لكل (i = 0; opts[i] != عدم; i++) {
		حرر(opts[i]->name);
		حرر(opts[i]->درج);
		حرر(opts[i]);
	}
	حرر(opts);
}

ساكن صحيح
sshsk_add_option(بنية sk_option ***optsp, size_t *noptsp,
    ثابت حرف *name, ثابت حرف *درج, uint8_t required)
{
	بنية sk_option **opts = *optsp;
	size_t nopts = *noptsp;

	إذا ((opts = recallocarray(opts, nopts, nopts + 2, /* extra for NULL */
	    حجم(*opts))) == عدم) {
		error_f("array alloc failed");
		أرجع SSH_ERR_ALLOC_FAIL;
	}
	*optsp = opts;
	*noptsp = nopts + 1;
	إذا ((opts[nopts] = calloc(1, حجم(**opts))) == عدم) {
		error_f("alloc failed");
		أرجع SSH_ERR_ALLOC_FAIL;
	}
	إذا ((opts[nopts]->name = strdup(name)) == عدم ||
	    (opts[nopts]->درج = strdup(درج)) == عدم) {
		error_f("alloc failed");
		أرجع SSH_ERR_ALLOC_FAIL;
	}
	opts[nopts]->required = required;
	أرجع 0;
}

ساكن صحيح
make_options(ثابت حرف *device, ثابت حرف *user_id,
    بنية sk_option ***optsp)
{
	بنية sk_option **opts = عدم;
	size_t nopts = 0;
	صحيح r, ret = SSH_ERR_INTERNAL_ERROR;

	إذا (device != عدم &&
	    (r = sshsk_add_option(&opts, &nopts, "device", device, 0)) != 0) {
		ret = r;
		اذهب out;
	}
	إذا (user_id != عدم &&
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
	أرجع ret;
}


ساكن صحيح
fill_attestation_blob(ثابت بنية sk_enroll_response *resp,
    بنية sshbuf *attest)
{
	صحيح r;

	إذا (attest == عدم)
		أرجع 0; /* nothing to do */
	إذا ((r = sshbuf_put_cstring(attest, "ssh-sk-attest-v01")) != 0 ||
	    (r = sshbuf_put_string(attest,
	    resp->attestation_cert, resp->attestation_cert_len)) != 0 ||
	    (r = sshbuf_put_string(attest,
	    resp->signature, resp->signature_len)) != 0 ||
	    (r = sshbuf_put_string(attest,
	    resp->authdata, resp->authdata_len)) != 0 ||
	    (r = sshbuf_put_u32(attest, 0)) != 0 || /* resvd flags */
	    (r = sshbuf_put_string(attest, عدم, 0)) != 0 /* resvd */) {
		error_fr(r, "compose");
		أرجع r;
	}
	/* success */
	أرجع 0;
}

صحيح
sshsk_enroll(صحيح type, ثابت حرف *provider_path, ثابت حرف *device,
    ثابت حرف *application, ثابت حرف *userid, uint8_t flags,
    ثابت حرف *pin, بنية sshbuf *challenge_buf,
    بنية sshkey **keyp, بنية sshbuf *attest)
{
	بنية sshsk_provider *skp = عدم;
	بنية sshkey *مبودي = عدم;
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
	إذا (attest)
		sshbuf_reset(attest);

	إذا ((r = make_options(device, userid, &opts)) != 0)
		اذهب out;

	بدل (type) {
#ifdef WITH_OPENSSL
	حالة مبودي_ECDSA_SK:
		alg = SSH_SK_ECDSA;
		اكسر;
#endif /* WITH_OPENSSL */
	حالة مبودي_ED25519_SK:
		alg = SSH_SK_ED25519;
		اكسر;
	افتراضي:
		error_f("unsupported key type");
		r = SSH_ERR_INVALID_ARGUMENT;
		اذهب out;
	}
	إذا (provider_path == عدم) {
		error_f("missing provider");
		r = SSH_ERR_INVALID_ARGUMENT;
		اذهب out;
	}
	إذا (application == عدم || *application == '\0') {
		error_f("missing application");
		r = SSH_ERR_INVALID_ARGUMENT;
		اذهب out;
	}
	إذا (challenge_buf == عدم) {
		debug_f("using random challenge");
		arc4random_buf(randchall, حجم(randchall));
		challenge = randchall;
		challenge_len = حجم(randchall);
	} وإلا إذا (sshbuf_len(challenge_buf) == 0) {
		error("Missing enrollment challenge");
		r = SSH_ERR_INVALID_ARGUMENT;
		اذهب out;
	} وإلا {
		challenge = sshbuf_ptr(challenge_buf);
		challenge_len = sshbuf_len(challenge_buf);
		debug3_f("using explicit challenge len=%zd", challenge_len);
	}
	إذا ((skp = sshsk_open(provider_path)) == عدم) {
		r = SSH_ERR_INVALID_FORMAT; /* XXX sshsk_open return code? */
		اذهب out;
	}
	/* XXX validate flags? */
	/* enroll key */
	إذا ((r = skp->sk_enroll(alg, challenge, challenge_len, application,
	    flags, pin, opts, &resp)) != 0) {
		debug_f("provider \"%s\" failure %d", provider_path, r);
		r = skerr_to_ssherr(r);
		اذهب out;
	}

	إذا ((r = sshsk_مبودي_from_response(alg, application, resp->flags,
	    resp, &مبودي)) != 0)
		اذهب out;

	/* Optionally fill in the attestation information */
	إذا ((r = fill_attestation_blob(resp, attest)) != 0)
		اذهب out;

	/* success */
	*keyp = مبودي;
	مبودي = عدم; /* transferred */
	r = 0;
 out:
	sshsk_free_options(opts);
	sshsk_free(skp);
	sshkey_free(مبودي);
	sshsk_free_enroll_response(resp);
	explicit_bzero(randchall, حجم(randchall));
	أرجع r;
}

#ifdef WITH_OPENSSL
ساكن صحيح
sshsk_ecdsa_sig(بنية sk_sign_response *resp, بنية sshbuf *sig)
{
	بنية sshbuf *inner_sig = عدم;
	صحيح r = SSH_ERR_INTERNAL_ERROR;

	/* Check response validity */
	إذا (resp->sig_r == عدم || resp->sig_s == عدم) {
		error_f("sk_sign response invalid");
		r = SSH_ERR_INVALID_FORMAT;
		اذهب out;
	}
	إذا ((inner_sig = sshbuf_new()) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب out;
	}
	/* Prepare and append inner signature object */
	إذا ((r = sshbuf_put_bignum2_bytes(inner_sig,
	    resp->sig_r, resp->sig_r_len)) != 0 ||
	    (r = sshbuf_put_bignum2_bytes(inner_sig,
	    resp->sig_s, resp->sig_s_len)) != 0) {
		error_fr(r, "compose inner");
		اذهب out;
	}
	إذا ((r = sshbuf_put_stringb(sig, inner_sig)) != 0 ||
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
	أرجع r;
}
#endif /* WITH_OPENSSL */

ساكن صحيح
sshsk_ed25519_sig(بنية sk_sign_response *resp, بنية sshbuf *sig)
{
	صحيح r = SSH_ERR_INTERNAL_ERROR;

	/* Check response validity */
	إذا (resp->sig_r == عدم) {
		error_f("sk_sign response invalid");
		r = SSH_ERR_INVALID_FORMAT;
		اذهب out;
	}
	إذا ((r = sshbuf_put_string(sig,
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
	أرجع r;
}

صحيح
sshsk_sign(ثابت حرف *provider_path, بنية sshkey *مبودي,
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
	    provider_path, sshkey_type(مبودي), مبودي->sk_flags,
	    (pin != عدم && *pin != '\0') ? " with-pin" : "");

	إذا (sigp != عدم)
		*sigp = عدم;
	إذا (lenp != عدم)
		*lenp = 0;
	type = sshkey_type_plain(مبودي->type);
	بدل (type) {
#ifdef WITH_OPENSSL
	حالة مبودي_ECDSA_SK:
		alg = SSH_SK_ECDSA;
		اكسر;
#endif /* WITH_OPENSSL */
	حالة مبودي_ED25519_SK:
		alg = SSH_SK_ED25519;
		اكسر;
	افتراضي:
		أرجع SSH_ERR_INVALID_ARGUMENT;
	}
	إذا (provider_path == عدم ||
	    مبودي->sk_مبودي_handle == عدم ||
	    مبودي->sk_application == عدم || *مبودي->sk_application == '\0') {
		r = SSH_ERR_INVALID_ARGUMENT;
		اذهب out;
	}
	إذا ((skp = sshsk_open(provider_path)) == عدم) {
		r = SSH_ERR_INVALID_FORMAT; /* XXX sshsk_open return code? */
		اذهب out;
	}
#ifdef DEBUG_SK
	fprintf(stderr, "%s: sk_flags = 0x%02x, sk_application = \"%s\"\n",
	    __func__, مبودي->sk_flags, مبودي->sk_application);
	fprintf(stderr, "%s: sk_key_handle:\n", __func__);
	sshbuf_dump(مبودي->sk_مبودي_handle, stderr);
#endif
	إذا ((r = skp->sk_sign(alg, data, datalen, مبودي->sk_application,
	    sshbuf_ptr(مبودي->sk_مبودي_handle), sshbuf_len(مبودي->sk_مبودي_handle),
	    مبودي->sk_flags, pin, opts, &resp)) != 0) {
		debug_f("sk_sign failed with code %d", r);
		r = skerr_to_ssherr(r);
		اذهب out;
	}
	/* Assemble signature */
	إذا ((sig = sshbuf_new()) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب out;
	}
	إذا ((r = sshbuf_put_cstring(sig, sshkey_ssh_name_plain(مبودي))) != 0) {
		error_fr(r, "compose outer");
		اذهب out;
	}
	بدل (type) {
#ifdef WITH_OPENSSL
	حالة مبودي_ECDSA_SK:
		إذا ((r = sshsk_ecdsa_sig(resp, sig)) != 0)
			اذهب out;
		اكسر;
#endif /* WITH_OPENSSL */
	حالة مبودي_ED25519_SK:
		إذا ((r = sshsk_ed25519_sig(resp, sig)) != 0)
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
	إذا (sigp != عدم) {
		إذا ((*sigp = malloc(sshbuf_len(sig))) == عدم) {
			r = SSH_ERR_ALLOC_FAIL;
			اذهب out;
		}
		memcpy(*sigp, sshbuf_ptr(sig), sshbuf_len(sig));
	}
	إذا (lenp != عدم)
		*lenp = sshbuf_len(sig);
	/* success */
	r = 0;
 out:
	sshsk_free_options(opts);
	sshsk_free(skp);
	sshsk_free_sign_response(resp);
	sshbuf_free(sig);
	sshbuf_free(inner_sig);
	أرجع r;
}

ساكن فراغ
sshsk_free_sk_resident_مبوداي(بنية sk_resident_مبودي **rks, size_t nrks)
{
	size_t i;

	إذا (nrks == 0 || rks == عدم)
		أرجع;
	لكل (i = 0; i < nrks; i++) {
		حرر(rks[i]->application);
		freezero(rks[i]->user_id, rks[i]->user_id_len);
		freezero(rks[i]->مبودي.مبودي_handle, rks[i]->مبودي.مبودي_handle_len);
		freezero(rks[i]->مبودي.public_مبودي, rks[i]->مبودي.public_مبودي_len);
		freezero(rks[i]->مبودي.signature, rks[i]->مبودي.signature_len);
		freezero(rks[i]->مبودي.attestation_cert,
		    rks[i]->مبودي.attestation_cert_len);
		freezero(rks[i], حجم(**rks));
	}
	حرر(rks);
}

ساكن فراغ
sshsk_free_resident_مبودي(بنية sshsk_resident_مبودي *srk)
{
	إذا (srk == عدم)
		أرجع;
	sshkey_free(srk->مبودي);
	freezero(srk->user_id, srk->user_id_len);
	حرر(srk);
}


فراغ
sshsk_free_resident_مبوداي(بنية sshsk_resident_مبودي **srks, size_t nsrks)
{
	size_t i;

	إذا (srks == عدم || nsrks == 0)
		أرجع;

	لكل (i = 0; i < nsrks; i++)
		sshsk_free_resident_مبودي(srks[i]);
	حرر(srks);
}

صحيح
sshsk_load_resident(ثابت حرف *provider_path, ثابت حرف *device,
    ثابت حرف *pin, u_int flags, بنية sshsk_resident_مبودي ***srksp,
    size_t *nsrksp)
{
	بنية sshsk_provider *skp = عدم;
	صحيح r = SSH_ERR_INTERNAL_ERROR;
	بنية sk_resident_مبودي **rks = عدم;
	size_t i, nrks = 0, nsrks = 0;
	بنية sshkey *مبودي = عدم;
	بنية sshsk_resident_مبودي *srk = عدم, **srks = عدم, **tmp;
	uint8_t sk_flags;
	بنية sk_option **opts = عدم;

	debug_f("provider \"%s\"%s", provider_path,
	    (pin != عدم && *pin != '\0') ? ", have-pin": "");

	إذا (srksp == عدم || nsrksp == عدم)
		أرجع SSH_ERR_INVALID_ARGUMENT;
	*srksp = عدم;
	*nsrksp = 0;

	إذا ((r = make_options(device, عدم, &opts)) != 0)
		اذهب out;
	إذا ((skp = sshsk_open(provider_path)) == عدم) {
		r = SSH_ERR_INVALID_FORMAT; /* XXX sshsk_open return code? */
		اذهب out;
	}
	إذا ((r = skp->sk_load_resident_مبوداي(pin, opts, &rks, &nrks)) != 0) {
		error("Provider \"%s\" returned failure %d", provider_path, r);
		r = skerr_to_ssherr(r);
		اذهب out;
	}
	لكل (i = 0; i < nrks; i++) {
		debug3_f("rk %zu: slot %zu, alg %d, app \"%s\", uidlen %zu",
		    i, rks[i]->slot, rks[i]->alg, rks[i]->application,
		    rks[i]->user_id_len);
		/* XXX need better filter here */
		إذا (strncmp(rks[i]->application, "ssh:", 4) != 0)
			استمر;
		بدل (rks[i]->alg) {
		حالة SSH_SK_ECDSA:
		حالة SSH_SK_ED25519:
			اكسر;
		افتراضي:
			استمر;
		}
		sk_flags = SSH_SK_USER_PRESENCE_REQD|SSH_SK_RESIDENT_مبودي;
		إذا ((rks[i]->flags & SSH_SK_USER_VERIFICATION_REQD))
			sk_flags |= SSH_SK_USER_VERIFICATION_REQD;
		إذا ((r = sshsk_مبودي_from_response(rks[i]->alg,
		    rks[i]->application, sk_flags, &rks[i]->مبودي, &مبودي)) != 0)
			اذهب out;
		إذا ((srk = calloc(1, حجم(*srk))) == عدم) {
			error_f("calloc failed");
			r = SSH_ERR_ALLOC_FAIL;
			اذهب out;
		}
		srk->مبودي = مبودي;
		مبودي = عدم; /* transferred */
		إذا ((srk->user_id = calloc(1, rks[i]->user_id_len)) == عدم) {
			error_f("calloc failed");
			r = SSH_ERR_ALLOC_FAIL;
			اذهب out;
		}
		memcpy(srk->user_id, rks[i]->user_id, rks[i]->user_id_len);
		srk->user_id_len = rks[i]->user_id_len;
		إذا ((tmp = recallocarray(srks, nsrks, nsrks + 1,
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
	sshsk_free_sk_resident_مبوداي(rks, nrks);
	sshkey_free(مبودي);
	sshsk_free_resident_مبودي(srk);
	sshsk_free_resident_مبوداي(srks, nsrks);
	أرجع r;
}

#endif /* ENABLE_SK */
