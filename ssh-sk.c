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

#شامل "includes.h"

#ifdef ENABLE_SK

#شامل <dlfcn.h>
#شامل <stddef.h>
#شامل <stdint.h>
#شامل <string.h>
#شامل <stdio.h>

#ifdef WITH_OPENSSL
#شامل <openssl/objects.h>
#شامل <openssl/ec.h>
#شامل <openssl/evp.h>
#endif /* WITH_OPENSSL */

#شامل "log.h"
#شامل "misc.h"
#شامل "sshbuf.h"
#شامل "sshkey.h"
#شامل "ssherr.h"
#شامل "digest.h"

#شامل "ssh-sk.h"
#شامل "sk-api.h"
#شامل "crypto_api.h"

ساختار sshsk_provider {
	نویسه *path;
	تهی *dlhandle;

	/* Return the version of the middleware API */
	uint32_t (*sk_api_version)(تهی);

	/* Enroll a U2F key (private key generation) */
	صحیح (*sk_enroll)(صحیح alg, ثابت uint8_t *challenge,
	    size_t challenge_len, ثابت نویسه *application, uint8_t flags,
	    ثابت نویسه *pin, ساختار sk_option **opts,
	    ساختار sk_enroll_response **enroll_response);

	/* Sign a challenge */
	صحیح (*sk_sign)(صحیح alg, ثابت uint8_t *message, size_t message_len,
	    ثابت نویسه *application,
	    ثابت uint8_t *کلید_handle, size_t کلید_handle_len,
	    uint8_t flags, ثابت نویسه *pin, ساختار sk_option **opts,
	    ساختار sk_sign_response **sign_response);

	/* Enumerate resident keys */
	صحیح (*sk_load_resident_کلیدها)(ثابت نویسه *pin, ساختار sk_option **opts,
	    ساختار sk_resident_کلید ***rks, size_t *nrks);
};

/* Built-in version */
صحیح ssh_sk_enroll(صحیح alg, ثابت uint8_t *challenge,
    size_t challenge_len, ثابت نویسه *application, uint8_t flags,
    ثابت نویسه *pin, ساختار sk_option **opts,
    ساختار sk_enroll_response **enroll_response);
صحیح ssh_sk_sign(صحیح alg, ثابت uint8_t *message, size_t message_len,
    ثابت نویسه *application,
    ثابت uint8_t *کلید_handle, size_t کلید_handle_len,
    uint8_t flags, ثابت نویسه *pin, ساختار sk_option **opts,
    ساختار sk_sign_response **sign_response);
صحیح ssh_sk_load_resident_کلیدها(ثابت نویسه *pin, ساختار sk_option **opts,
    ساختار sk_resident_کلید ***rks, size_t *nrks);

ایستا تهی
sshsk_free(ساختار sshsk_provider *p)
{
	اگر (p == پوچ)
		بازگشت;
	آزاد(p->path);
	اگر (p->dlhandle != پوچ)
		dlclose(p->dlhandle);
	آزاد(p);
}

ایستا ساختار sshsk_provider *
sshsk_open(ثابت نویسه *path)
{
	ساختار sshsk_provider *ret = پوچ;
	uint32_t version;

	اگر (path == پوچ || *path == '\0') {
		error("No FIDO SecurityKeyProvider specified");
		بازگشت پوچ;
	}
	اگر ((ret = calloc(1, اندازه(*ret))) == پوچ) {
		error_f("calloc failed");
		بازگشت پوچ;
	}
	اگر ((ret->path = strdup(path)) == پوچ) {
		error_f("strdup failed");
		برو fail;
	}
	/* Skip the rest if we're using the linked in middleware */
	اگر (strcasecmp(ret->path, "internal") == 0) {
#ifdef ENABLE_SK_INTERNAL
		ret->sk_enroll = ssh_sk_enroll;
		ret->sk_sign = ssh_sk_sign;
		ret->sk_load_resident_کلیدها = ssh_sk_load_resident_کلیدها;
		بازگشت ret;
#وگرنه
		error("internal security key support not enabled");
		برو fail;
#endif
	}
	اگر (lib_contains_نماد(path, "sk_api_version") != 0) {
		error("provider %s is not an OpenSSH FIDO library", path);
		برو fail;
	}
	اگر ((ret->dlhandle = dlopen(path, RTLD_NOW)) == پوچ)
		fatal("Provider \"%s\" dlopen failed: %s", path, dlerror());
	اگر ((ret->sk_api_version = dlsym(ret->dlhandle,
	    "sk_api_version")) == پوچ) {
		error("Provider \"%s\" dlsym(sk_api_version) failed: %s",
		    path, dlerror());
		برو fail;
	}
	version = ret->sk_api_version();
	debug_f("provider %s implements version 0x%08lx", ret->path,
	    (u_long)version);
	اگر ((version & SSH_SK_VERSION_MAJOR_MASK) != SSH_SK_VERSION_MAJOR) {
		error("Provider \"%s\" implements unsupported "
		    "version 0x%08lx (supported: 0x%08lx)",
		    path, (u_long)version, (u_long)SSH_SK_VERSION_MAJOR);
		برو fail;
	}
	اگر ((ret->sk_enroll = dlsym(ret->dlhandle, "sk_enroll")) == پوچ) {
		error("Provider %s dlsym(sk_enroll) failed: %s",
		    path, dlerror());
		برو fail;
	}
	اگر ((ret->sk_sign = dlsym(ret->dlhandle, "sk_sign")) == پوچ) {
		error("Provider \"%s\" dlsym(sk_sign) failed: %s",
		    path, dlerror());
		برو fail;
	}
	اگر ((ret->sk_load_resident_کلیدها = dlsym(ret->dlhandle,
	    "sk_load_resident_keys")) == پوچ) {
		error("Provider \"%s\" dlsym(sk_load_resident_keys) "
		    "failed: %s", path, dlerror());
		برو fail;
	}
	/* success */
	بازگشت ret;
fail:
	sshsk_free(ret);
	بازگشت پوچ;
}

ایستا تهی
sshsk_free_enroll_response(ساختار sk_enroll_response *r)
{
	اگر (r == پوچ)
		بازگشت;
	freezero(r->کلید_handle, r->کلید_handle_len);
	freezero(r->public_کلید, r->public_کلید_len);
	freezero(r->signature, r->signature_len);
	freezero(r->attestation_cert, r->attestation_cert_len);
	freezero(r->authdata, r->authdata_len);
	freezero(r, اندازه(*r));
}

ایستا تهی
sshsk_free_sign_response(ساختار sk_sign_response *r)
{
	اگر (r == پوچ)
		بازگشت;
	freezero(r->sig_r, r->sig_r_len);
	freezero(r->sig_s, r->sig_s_len);
	freezero(r, اندازه(*r));
}

#ifdef WITH_OPENSSL
/* Assemble key from response */
ایستا صحیح
sshsk_ecdsa_assemble(ساختار sk_enroll_response *resp, ساختار sshkey **keyp)
{
	ساختار sshkey *کلید = پوچ;
	ساختار sshbuf *b = پوچ;
	EC_کلید *ecdsa = پوچ;
	EC_POINT *q = پوچ;
	ثابت EC_GROUP *g = پوچ;
	صحیح r;

	*keyp = پوچ;
	اگر ((کلید = sshkey_new(کلید_ECDSA_SK)) == پوچ) {
		error_f("sshkey_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		برو out;
	}
	کلید->ecdsa_nid = NID_X9_62_prime256v1;
	اگر ((ecdsa = EC_کلید_new_by_curve_name(کلید->ecdsa_nid)) == پوچ ||
	    (g = EC_کلید_get0_group(ecdsa)) == پوچ ||
	    (q = EC_POINT_new(g)) == پوچ ||
	    (b = sshbuf_new()) == پوچ) {
		error_f("allocation failed");
		r = SSH_ERR_ALLOC_FAIL;
		برو out;
	}
	اگر ((r = sshbuf_put_string(b,
	    resp->public_کلید, resp->public_کلید_len)) != 0) {
		error_fr(r, "sshbuf_put_string");
		برو out;
	}
	اگر ((r = sshbuf_get_ec(b, q, g)) != 0) {
		error_fr(r, "parse");
		r = SSH_ERR_INVALID_FORMAT;
		برو out;
	}
	اگر (sshkey_ec_validate_public(g, q) != 0) {
		error("Authenticator returned invalid ECDSA key");
		r = SSH_ERR_کلید_INVALID_EC_مقدار;
		برو out;
	}
	اگر (EC_کلید_set_public_کلید(ecdsa, q) != 1) {
		/* XXX assume it is a allocation error */
		error_f("allocation failed");
		r = SSH_ERR_ALLOC_FAIL;
		برو out;
	}
	اگر ((کلید->pkey = EVP_PKEY_new()) == پوچ) {
		error_f("allocation failed");
		r = SSH_ERR_ALLOC_FAIL;
		برو out;
	}
	اگر (EVP_PKEY_set1_EC_کلید(کلید->pkey, ecdsa) != 1) {
		error_f("Assigning EC_KEY failed");
		r = SSH_ERR_LIBCRYPTO_ERROR;
		برو out;
	}
	/* success */
	*keyp = کلید;
	کلید = پوچ; /* transferred */
	r = 0;
 out:
	sshkey_free(کلید);
	sshbuf_free(b);
	EC_کلید_free(ecdsa);
	EC_POINT_free(q);
	بازگشت r;
}
#endif /* WITH_OPENSSL */

ایستا صحیح
sshsk_ed25519_assemble(ساختار sk_enroll_response *resp, ساختار sshkey **keyp)
{
	ساختار sshkey *کلید = پوچ;
	صحیح r;

	*keyp = پوچ;
	اگر (resp->public_کلید_len != ED25519_PK_SZ) {
		error_f("invalid size: %zu", resp->public_کلید_len);
		r = SSH_ERR_INVALID_FORMAT;
		برو out;
	}
	اگر ((کلید = sshkey_new(کلید_ED25519_SK)) == پوچ) {
		error_f("sshkey_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		برو out;
	}
	اگر ((کلید->ed25519_pk = malloc(ED25519_PK_SZ)) == پوچ) {
		error_f("malloc failed");
		r = SSH_ERR_ALLOC_FAIL;
		برو out;
	}
	memcpy(کلید->ed25519_pk, resp->public_کلید, ED25519_PK_SZ);
	/* success */
	*keyp = کلید;
	کلید = پوچ; /* transferred */
	r = 0;
 out:
	sshkey_free(کلید);
	بازگشت r;
}

ایستا صحیح
sshsk_کلید_from_response(صحیح alg, ثابت نویسه *application, uint8_t flags,
    ساختار sk_enroll_response *resp, ساختار sshkey **keyp)
{
	ساختار sshkey *کلید = پوچ;
	صحیح r = SSH_ERR_INTERNAL_ERROR;

	*keyp = پوچ;

	/* Check response validity */
	اگر (resp->public_کلید == پوچ || resp->کلید_handle == پوچ) {
		error_f("sk_enroll response invalid");
		r = SSH_ERR_INVALID_FORMAT;
		برو out;
	}
	انتخاب (alg) {
#ifdef WITH_OPENSSL
	حالت SSH_SK_ECDSA:
		اگر ((r = sshsk_ecdsa_assemble(resp, &کلید)) != 0)
			برو out;
		بشکن;
#endif /* WITH_OPENSSL */
	حالت SSH_SK_ED25519:
		اگر ((r = sshsk_ed25519_assemble(resp, &کلید)) != 0)
			برو out;
		بشکن;
	پیشفرض:
		error_f("unsupported algorithm %d", alg);
		r = SSH_ERR_INVALID_ARGUMENT;
		برو out;
	}
	کلید->sk_flags = flags;
	اگر ((کلید->sk_کلید_handle = sshbuf_new()) == پوچ ||
	    (کلید->sk_reserved = sshbuf_new()) == پوچ) {
		error_f("allocation failed");
		r = SSH_ERR_ALLOC_FAIL;
		برو out;
	}
	اگر ((کلید->sk_application = strdup(application)) == پوچ) {
		error_f("strdup application failed");
		r = SSH_ERR_ALLOC_FAIL;
		برو out;
	}
	اگر ((r = sshbuf_put(کلید->sk_کلید_handle, resp->کلید_handle,
	    resp->کلید_handle_len)) != 0) {
		error_fr(r, "put key handle");
		برو out;
	}
	/* success */
	r = 0;
	*keyp = کلید;
	کلید = پوچ;
 out:
	sshkey_free(کلید);
	بازگشت r;
}

ایستا صحیح
skerr_to_ssherr(صحیح skerr)
{
	انتخاب (skerr) {
	حالت SSH_SK_ERR_UNSUPPORTED:
		بازگشت SSH_ERR_FEATURE_UNSUPPORTED;
	حالت SSH_SK_ERR_PIN_REQUIRED:
		بازگشت SSH_ERR_کلید_WRONG_PASSPHRASE;
	حالت SSH_SK_ERR_DEVICE_NOT_FOUND:
		بازگشت SSH_ERR_DEVICE_NOT_FOUND;
	حالت SSH_SK_ERR_CREDENTIAL_EXISTS:
		بازگشت SSH_ERR_کلید_BAD_PERMISSIONS;
	حالت SSH_SK_ERR_GENERAL:
	پیشفرض:
		بازگشت SSH_ERR_INVALID_FORMAT;
	}
}

ایستا تهی
sshsk_free_options(ساختار sk_option **opts)
{
	size_t i;

	اگر (opts == پوچ)
		بازگشت;
	برای (i = 0; opts[i] != پوچ; i++) {
		آزاد(opts[i]->name);
		آزاد(opts[i]->مقدار);
		آزاد(opts[i]);
	}
	آزاد(opts);
}

ایستا صحیح
sshsk_add_option(ساختار sk_option ***optsp, size_t *noptsp,
    ثابت نویسه *name, ثابت نویسه *مقدار, uint8_t required)
{
	ساختار sk_option **opts = *optsp;
	size_t nopts = *noptsp;

	اگر ((opts = recallocarray(opts, nopts, nopts + 2, /* extra for NULL */
	    اندازه(*opts))) == پوچ) {
		error_f("array alloc failed");
		بازگشت SSH_ERR_ALLOC_FAIL;
	}
	*optsp = opts;
	*noptsp = nopts + 1;
	اگر ((opts[nopts] = calloc(1, اندازه(**opts))) == پوچ) {
		error_f("alloc failed");
		بازگشت SSH_ERR_ALLOC_FAIL;
	}
	اگر ((opts[nopts]->name = strdup(name)) == پوچ ||
	    (opts[nopts]->مقدار = strdup(مقدار)) == پوچ) {
		error_f("alloc failed");
		بازگشت SSH_ERR_ALLOC_FAIL;
	}
	opts[nopts]->required = required;
	بازگشت 0;
}

ایستا صحیح
make_options(ثابت نویسه *device, ثابت نویسه *user_id,
    ساختار sk_option ***optsp)
{
	ساختار sk_option **opts = پوچ;
	size_t nopts = 0;
	صحیح r, ret = SSH_ERR_INTERNAL_ERROR;

	اگر (device != پوچ &&
	    (r = sshsk_add_option(&opts, &nopts, "device", device, 0)) != 0) {
		ret = r;
		برو out;
	}
	اگر (user_id != پوچ &&
	    (r = sshsk_add_option(&opts, &nopts, "user", user_id, 0)) != 0) {
		ret = r;
		برو out;
	}
	/* success */
	*optsp = opts;
	opts = پوچ;
	nopts = 0;
	ret = 0;
 out:
	sshsk_free_options(opts);
	بازگشت ret;
}


ایستا صحیح
fill_attestation_blob(ثابت ساختار sk_enroll_response *resp,
    ساختار sshbuf *attest)
{
	صحیح r;

	اگر (attest == پوچ)
		بازگشت 0; /* nothing to do */
	اگر ((r = sshbuf_put_cstring(attest, "ssh-sk-attest-v01")) != 0 ||
	    (r = sshbuf_put_string(attest,
	    resp->attestation_cert, resp->attestation_cert_len)) != 0 ||
	    (r = sshbuf_put_string(attest,
	    resp->signature, resp->signature_len)) != 0 ||
	    (r = sshbuf_put_string(attest,
	    resp->authdata, resp->authdata_len)) != 0 ||
	    (r = sshbuf_put_u32(attest, 0)) != 0 || /* resvd flags */
	    (r = sshbuf_put_string(attest, پوچ, 0)) != 0 /* resvd */) {
		error_fr(r, "compose");
		بازگشت r;
	}
	/* success */
	بازگشت 0;
}

صحیح
sshsk_enroll(صحیح type, ثابت نویسه *provider_path, ثابت نویسه *device,
    ثابت نویسه *application, ثابت نویسه *userid, uint8_t flags,
    ثابت نویسه *pin, ساختار sshbuf *challenge_buf,
    ساختار sshkey **keyp, ساختار sshbuf *attest)
{
	ساختار sshsk_provider *skp = پوچ;
	ساختار sshkey *کلید = پوچ;
	u_char randchall[32];
	ثابت u_char *challenge;
	size_t challenge_len;
	ساختار sk_enroll_response *resp = پوچ;
	ساختار sk_option **opts = پوچ;
	صحیح r = SSH_ERR_INTERNAL_ERROR;
	صحیح alg;

	debug_f("provider \"%s\", device \"%s\", application \"%s\", "
	    "userid \"%s\", flags 0x%02x, challenge len %zu%s",
	    provider_path, device, application, userid, flags,
	    challenge_buf == پوچ ? 0 : sshbuf_len(challenge_buf),
	    (pin != پوچ && *pin != '\0') ? " with-pin" : "");

	*keyp = پوچ;
	اگر (attest)
		sshbuf_reset(attest);

	اگر ((r = make_options(device, userid, &opts)) != 0)
		برو out;

	انتخاب (type) {
#ifdef WITH_OPENSSL
	حالت کلید_ECDSA_SK:
		alg = SSH_SK_ECDSA;
		بشکن;
#endif /* WITH_OPENSSL */
	حالت کلید_ED25519_SK:
		alg = SSH_SK_ED25519;
		بشکن;
	پیشفرض:
		error_f("unsupported key type");
		r = SSH_ERR_INVALID_ARGUMENT;
		برو out;
	}
	اگر (provider_path == پوچ) {
		error_f("missing provider");
		r = SSH_ERR_INVALID_ARGUMENT;
		برو out;
	}
	اگر (application == پوچ || *application == '\0') {
		error_f("missing application");
		r = SSH_ERR_INVALID_ARGUMENT;
		برو out;
	}
	اگر (challenge_buf == پوچ) {
		debug_f("using random challenge");
		arc4random_buf(randchall, اندازه(randchall));
		challenge = randchall;
		challenge_len = اندازه(randchall);
	} وگرنه اگر (sshbuf_len(challenge_buf) == 0) {
		error("Missing enrollment challenge");
		r = SSH_ERR_INVALID_ARGUMENT;
		برو out;
	} وگرنه {
		challenge = sshbuf_ptr(challenge_buf);
		challenge_len = sshbuf_len(challenge_buf);
		debug3_f("using explicit challenge len=%zd", challenge_len);
	}
	اگر ((skp = sshsk_open(provider_path)) == پوچ) {
		r = SSH_ERR_INVALID_FORMAT; /* XXX sshsk_open return code? */
		برو out;
	}
	/* XXX validate flags? */
	/* enroll key */
	اگر ((r = skp->sk_enroll(alg, challenge, challenge_len, application,
	    flags, pin, opts, &resp)) != 0) {
		debug_f("provider \"%s\" failure %d", provider_path, r);
		r = skerr_to_ssherr(r);
		برو out;
	}

	اگر ((r = sshsk_کلید_from_response(alg, application, resp->flags,
	    resp, &کلید)) != 0)
		برو out;

	/* Optionally fill in the attestation information */
	اگر ((r = fill_attestation_blob(resp, attest)) != 0)
		برو out;

	/* success */
	*keyp = کلید;
	کلید = پوچ; /* transferred */
	r = 0;
 out:
	sshsk_free_options(opts);
	sshsk_free(skp);
	sshkey_free(کلید);
	sshsk_free_enroll_response(resp);
	explicit_bzero(randchall, اندازه(randchall));
	بازگشت r;
}

#ifdef WITH_OPENSSL
ایستا صحیح
sshsk_ecdsa_sig(ساختار sk_sign_response *resp, ساختار sshbuf *sig)
{
	ساختار sshbuf *inner_sig = پوچ;
	صحیح r = SSH_ERR_INTERNAL_ERROR;

	/* Check response validity */
	اگر (resp->sig_r == پوچ || resp->sig_s == پوچ) {
		error_f("sk_sign response invalid");
		r = SSH_ERR_INVALID_FORMAT;
		برو out;
	}
	اگر ((inner_sig = sshbuf_new()) == پوچ) {
		r = SSH_ERR_ALLOC_FAIL;
		برو out;
	}
	/* Prepare and append inner signature object */
	اگر ((r = sshbuf_put_bignum2_bytes(inner_sig,
	    resp->sig_r, resp->sig_r_len)) != 0 ||
	    (r = sshbuf_put_bignum2_bytes(inner_sig,
	    resp->sig_s, resp->sig_s_len)) != 0) {
		error_fr(r, "compose inner");
		برو out;
	}
	اگر ((r = sshbuf_put_stringb(sig, inner_sig)) != 0 ||
	    (r = sshbuf_put_u8(sig, resp->flags)) != 0 ||
	    (r = sshbuf_put_u32(sig, resp->counter)) != 0) {
		error_fr(r, "compose");
		برو out;
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
	بازگشت r;
}
#endif /* WITH_OPENSSL */

ایستا صحیح
sshsk_ed25519_sig(ساختار sk_sign_response *resp, ساختار sshbuf *sig)
{
	صحیح r = SSH_ERR_INTERNAL_ERROR;

	/* Check response validity */
	اگر (resp->sig_r == پوچ) {
		error_f("sk_sign response invalid");
		r = SSH_ERR_INVALID_FORMAT;
		برو out;
	}
	اگر ((r = sshbuf_put_string(sig,
	    resp->sig_r, resp->sig_r_len)) != 0 ||
	    (r = sshbuf_put_u8(sig, resp->flags)) != 0 ||
	    (r = sshbuf_put_u32(sig, resp->counter)) != 0) {
		error_fr(r, "compose");
		برو out;
	}
#ifdef DEBUG_SK
	fprintf(stderr, "%s: sig_r:\n", __func__);
	sshbuf_dump_data(resp->sig_r, resp->sig_r_len, stderr);
#endif
	r = 0;
 out:
	بازگشت r;
}

صحیح
sshsk_sign(ثابت نویسه *provider_path, ساختار sshkey *کلید,
    u_char **sigp, size_t *lenp, ثابت u_char *data, size_t datalen,
    u_int compat, ثابت نویسه *pin)
{
	ساختار sshsk_provider *skp = پوچ;
	صحیح r = SSH_ERR_INTERNAL_ERROR;
	صحیح type, alg;
	ساختار sk_sign_response *resp = پوچ;
	ساختار sshbuf *inner_sig = پوچ, *sig = پوچ;
	ساختار sk_option **opts = پوچ;

	debug_f("provider \"%s\", key %s, flags 0x%02x%s",
	    provider_path, sshkey_type(کلید), کلید->sk_flags,
	    (pin != پوچ && *pin != '\0') ? " with-pin" : "");

	اگر (sigp != پوچ)
		*sigp = پوچ;
	اگر (lenp != پوچ)
		*lenp = 0;
	type = sshkey_type_plain(کلید->type);
	انتخاب (type) {
#ifdef WITH_OPENSSL
	حالت کلید_ECDSA_SK:
		alg = SSH_SK_ECDSA;
		بشکن;
#endif /* WITH_OPENSSL */
	حالت کلید_ED25519_SK:
		alg = SSH_SK_ED25519;
		بشکن;
	پیشفرض:
		بازگشت SSH_ERR_INVALID_ARGUMENT;
	}
	اگر (provider_path == پوچ ||
	    کلید->sk_کلید_handle == پوچ ||
	    کلید->sk_application == پوچ || *کلید->sk_application == '\0') {
		r = SSH_ERR_INVALID_ARGUMENT;
		برو out;
	}
	اگر ((skp = sshsk_open(provider_path)) == پوچ) {
		r = SSH_ERR_INVALID_FORMAT; /* XXX sshsk_open return code? */
		برو out;
	}
#ifdef DEBUG_SK
	fprintf(stderr, "%s: sk_flags = 0x%02x, sk_application = \"%s\"\n",
	    __func__, کلید->sk_flags, کلید->sk_application);
	fprintf(stderr, "%s: sk_key_handle:\n", __func__);
	sshbuf_dump(کلید->sk_کلید_handle, stderr);
#endif
	اگر ((r = skp->sk_sign(alg, data, datalen, کلید->sk_application,
	    sshbuf_ptr(کلید->sk_کلید_handle), sshbuf_len(کلید->sk_کلید_handle),
	    کلید->sk_flags, pin, opts, &resp)) != 0) {
		debug_f("sk_sign failed with code %d", r);
		r = skerr_to_ssherr(r);
		برو out;
	}
	/* Assemble signature */
	اگر ((sig = sshbuf_new()) == پوچ) {
		r = SSH_ERR_ALLOC_FAIL;
		برو out;
	}
	اگر ((r = sshbuf_put_cstring(sig, sshkey_ssh_name_plain(کلید))) != 0) {
		error_fr(r, "compose outer");
		برو out;
	}
	انتخاب (type) {
#ifdef WITH_OPENSSL
	حالت کلید_ECDSA_SK:
		اگر ((r = sshsk_ecdsa_sig(resp, sig)) != 0)
			برو out;
		بشکن;
#endif /* WITH_OPENSSL */
	حالت کلید_ED25519_SK:
		اگر ((r = sshsk_ed25519_sig(resp, sig)) != 0)
			برو out;
		بشکن;
	}
#ifdef DEBUG_SK
	fprintf(stderr, "%s: sig_flags = 0x%02x, sig_counter = %u\n",
	    __func__, resp->flags, resp->counter);
	fprintf(stderr, "%s: data to sign:\n", __func__);
	sshbuf_dump_data(data, datalen, stderr);
	fprintf(stderr, "%s: sigbuf:\n", __func__);
	sshbuf_dump(sig, stderr);
#endif
	اگر (sigp != پوچ) {
		اگر ((*sigp = malloc(sshbuf_len(sig))) == پوچ) {
			r = SSH_ERR_ALLOC_FAIL;
			برو out;
		}
		memcpy(*sigp, sshbuf_ptr(sig), sshbuf_len(sig));
	}
	اگر (lenp != پوچ)
		*lenp = sshbuf_len(sig);
	/* success */
	r = 0;
 out:
	sshsk_free_options(opts);
	sshsk_free(skp);
	sshsk_free_sign_response(resp);
	sshbuf_free(sig);
	sshbuf_free(inner_sig);
	بازگشت r;
}

ایستا تهی
sshsk_free_sk_resident_کلیدها(ساختار sk_resident_کلید **rks, size_t nrks)
{
	size_t i;

	اگر (nrks == 0 || rks == پوچ)
		بازگشت;
	برای (i = 0; i < nrks; i++) {
		آزاد(rks[i]->application);
		freezero(rks[i]->user_id, rks[i]->user_id_len);
		freezero(rks[i]->کلید.کلید_handle, rks[i]->کلید.کلید_handle_len);
		freezero(rks[i]->کلید.public_کلید, rks[i]->کلید.public_کلید_len);
		freezero(rks[i]->کلید.signature, rks[i]->کلید.signature_len);
		freezero(rks[i]->کلید.attestation_cert,
		    rks[i]->کلید.attestation_cert_len);
		freezero(rks[i], اندازه(**rks));
	}
	آزاد(rks);
}

ایستا تهی
sshsk_free_resident_کلید(ساختار sshsk_resident_کلید *srk)
{
	اگر (srk == پوچ)
		بازگشت;
	sshkey_free(srk->کلید);
	freezero(srk->user_id, srk->user_id_len);
	آزاد(srk);
}


تهی
sshsk_free_resident_کلیدها(ساختار sshsk_resident_کلید **srks, size_t nsrks)
{
	size_t i;

	اگر (srks == پوچ || nsrks == 0)
		بازگشت;

	برای (i = 0; i < nsrks; i++)
		sshsk_free_resident_کلید(srks[i]);
	آزاد(srks);
}

صحیح
sshsk_load_resident(ثابت نویسه *provider_path, ثابت نویسه *device,
    ثابت نویسه *pin, u_int flags, ساختار sshsk_resident_کلید ***srksp,
    size_t *nsrksp)
{
	ساختار sshsk_provider *skp = پوچ;
	صحیح r = SSH_ERR_INTERNAL_ERROR;
	ساختار sk_resident_کلید **rks = پوچ;
	size_t i, nrks = 0, nsrks = 0;
	ساختار sshkey *کلید = پوچ;
	ساختار sshsk_resident_کلید *srk = پوچ, **srks = پوچ, **tmp;
	uint8_t sk_flags;
	ساختار sk_option **opts = پوچ;

	debug_f("provider \"%s\"%s", provider_path,
	    (pin != پوچ && *pin != '\0') ? ", have-pin": "");

	اگر (srksp == پوچ || nsrksp == پوچ)
		بازگشت SSH_ERR_INVALID_ARGUMENT;
	*srksp = پوچ;
	*nsrksp = 0;

	اگر ((r = make_options(device, پوچ, &opts)) != 0)
		برو out;
	اگر ((skp = sshsk_open(provider_path)) == پوچ) {
		r = SSH_ERR_INVALID_FORMAT; /* XXX sshsk_open return code? */
		برو out;
	}
	اگر ((r = skp->sk_load_resident_کلیدها(pin, opts, &rks, &nrks)) != 0) {
		error("Provider \"%s\" returned failure %d", provider_path, r);
		r = skerr_to_ssherr(r);
		برو out;
	}
	برای (i = 0; i < nrks; i++) {
		debug3_f("rk %zu: slot %zu, alg %d, app \"%s\", uidlen %zu",
		    i, rks[i]->slot, rks[i]->alg, rks[i]->application,
		    rks[i]->user_id_len);
		/* XXX need better filter here */
		اگر (strncmp(rks[i]->application, "ssh:", 4) != 0)
			ادامه;
		انتخاب (rks[i]->alg) {
		حالت SSH_SK_ECDSA:
		حالت SSH_SK_ED25519:
			بشکن;
		پیشفرض:
			ادامه;
		}
		sk_flags = SSH_SK_USER_PRESENCE_REQD|SSH_SK_RESIDENT_کلید;
		اگر ((rks[i]->flags & SSH_SK_USER_VERIFICATION_REQD))
			sk_flags |= SSH_SK_USER_VERIFICATION_REQD;
		اگر ((r = sshsk_کلید_from_response(rks[i]->alg,
		    rks[i]->application, sk_flags, &rks[i]->کلید, &کلید)) != 0)
			برو out;
		اگر ((srk = calloc(1, اندازه(*srk))) == پوچ) {
			error_f("calloc failed");
			r = SSH_ERR_ALLOC_FAIL;
			برو out;
		}
		srk->کلید = کلید;
		کلید = پوچ; /* transferred */
		اگر ((srk->user_id = calloc(1, rks[i]->user_id_len)) == پوچ) {
			error_f("calloc failed");
			r = SSH_ERR_ALLOC_FAIL;
			برو out;
		}
		memcpy(srk->user_id, rks[i]->user_id, rks[i]->user_id_len);
		srk->user_id_len = rks[i]->user_id_len;
		اگر ((tmp = recallocarray(srks, nsrks, nsrks + 1,
		    اندازه(*tmp))) == پوچ) {
			error_f("recallocarray failed");
			r = SSH_ERR_ALLOC_FAIL;
			برو out;
		}
		srks = tmp;
		srks[nsrks++] = srk;
		srk = پوچ;
		/* XXX synthesise comment */
	}
	/* success */
	*srksp = srks;
	*nsrksp = nsrks;
	srks = پوچ;
	nsrks = 0;
	r = 0;
 out:
	sshsk_free_options(opts);
	sshsk_free(skp);
	sshsk_free_sk_resident_کلیدها(rks, nrks);
	sshkey_free(کلید);
	sshsk_free_resident_کلید(srk);
	sshsk_free_resident_کلیدها(srks, nsrks);
	بازگشت r;
}

#endif /* ENABLE_SK */
