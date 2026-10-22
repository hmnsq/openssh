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

#অন্তর্ভাব "includes.h"

#ifdef ENABLE_SK

#অন্তর্ভাব <dlfcn.h>
#অন্তর্ভাব <stddef.h>
#অন্তর্ভাব <stdint.h>
#অন্তর্ভাব <string.h>
#অন্তর্ভাব <stdio.h>

#ifdef WITH_OPENSSL
#অন্তর্ভাব <openssl/objects.h>
#অন্তর্ভাব <openssl/ec.h>
#অন্তর্ভাব <openssl/evp.h>
#endif /* WITH_OPENSSL */

#অন্তর্ভাব "log.h"
#অন্তর্ভাব "misc.h"
#অন্তর্ভাব "sshbuf.h"
#অন্তর্ভাব "sshkey.h"
#অন্তর্ভাব "ssherr.h"
#অন্তর্ভাব "digest.h"

#অন্তর্ভাব "ssh-sk.h"
#অন্তর্ভাব "sk-api.h"
#অন্তর্ভাব "crypto_api.h"

কাঠামো sshsk_provider {
	অক্ষর *path;
	শূন্য *dlhandle;

	/* Return the version of the middleware API */
	uint32_t (*sk_api_version)(শূন্য);

	/* Enroll a U2F key (private key generation) */
	পূর্ণসংখ্যা (*sk_enroll)(পূর্ণসংখ্যা alg, ধ্রুবক uint8_t *challenge,
	    আকার_t challenge_len, ধ্রুবক অক্ষর *application, uint8_t flags,
	    ধ্রুবক অক্ষর *pin, কাঠামো sk_option **opts,
	    কাঠামো sk_enroll_response **enroll_response);

	/* Sign a challenge */
	পূর্ণসংখ্যা (*sk_sign)(পূর্ণসংখ্যা alg, ধ্রুবক uint8_t *message, আকার_t message_len,
	    ধ্রুবক অক্ষর *application,
	    ধ্রুবক uint8_t *চাবি_handle, আকার_t চাবি_handle_len,
	    uint8_t flags, ধ্রুবক অক্ষর *pin, কাঠামো sk_option **opts,
	    কাঠামো sk_sign_response **sign_response);

	/* Enumerate resident keys */
	পূর্ণসংখ্যা (*sk_load_resident_চাবিগুলি)(ধ্রুবক অক্ষর *pin, কাঠামো sk_option **opts,
	    কাঠামো sk_resident_চাবি ***rks, আকার_t *nrks);
};

/* Built-in version */
পূর্ণসংখ্যা ssh_sk_enroll(পূর্ণসংখ্যা alg, ধ্রুবক uint8_t *challenge,
    আকার_t challenge_len, ধ্রুবক অক্ষর *application, uint8_t flags,
    ধ্রুবক অক্ষর *pin, কাঠামো sk_option **opts,
    কাঠামো sk_enroll_response **enroll_response);
পূর্ণসংখ্যা ssh_sk_sign(পূর্ণসংখ্যা alg, ধ্রুবক uint8_t *message, আকার_t message_len,
    ধ্রুবক অক্ষর *application,
    ধ্রুবক uint8_t *চাবি_handle, আকার_t চাবি_handle_len,
    uint8_t flags, ধ্রুবক অক্ষর *pin, কাঠামো sk_option **opts,
    কাঠামো sk_sign_response **sign_response);
পূর্ণসংখ্যা ssh_sk_load_resident_চাবিগুলি(ধ্রুবক অক্ষর *pin, কাঠামো sk_option **opts,
    কাঠামো sk_resident_চাবি ***rks, আকার_t *nrks);

স্থির শূন্য
sshsk_free(কাঠামো sshsk_provider *p)
{
	যদি (p == ফাঁকা)
		ফেরত;
	মুক্ত(p->path);
	যদি (p->dlhandle != ফাঁকা)
		dlclose(p->dlhandle);
	মুক্ত(p);
}

স্থির কাঠামো sshsk_provider *
sshsk_open(ধ্রুবক অক্ষর *path)
{
	কাঠামো sshsk_provider *ret = ফাঁকা;
	uint32_t version;

	যদি (path == ফাঁকা || *path == '\0') {
		error("No FIDO SecurityKeyProvider specified");
		ফেরত ফাঁকা;
	}
	যদি ((ret = calloc(1, আকার(*ret))) == ফাঁকা) {
		error_f("calloc failed");
		ফেরত ফাঁকা;
	}
	যদি ((ret->path = strdup(path)) == ফাঁকা) {
		error_f("strdup failed");
		যাও fail;
	}
	/* Skip the rest if we're using the linked in middleware */
	যদি (strcasecmp(ret->path, "internal") == 0) {
#ifdef ENABLE_SK_INTERNAL
		ret->sk_enroll = ssh_sk_enroll;
		ret->sk_sign = ssh_sk_sign;
		ret->sk_load_resident_চাবিগুলি = ssh_sk_load_resident_চাবিগুলি;
		ফেরত ret;
#অন্যথা
		error("internal security key support not enabled");
		যাও fail;
#endif
	}
	যদি (lib_contains_প্রতীক(path, "sk_api_version") != 0) {
		error("provider %s is not an OpenSSH FIDO library", path);
		যাও fail;
	}
	যদি ((ret->dlhandle = dlopen(path, RTLD_NOW)) == ফাঁকা)
		fatal("Provider \"%s\" dlopen failed: %s", path, dlerror());
	যদি ((ret->sk_api_version = dlsym(ret->dlhandle,
	    "sk_api_version")) == ফাঁকা) {
		error("Provider \"%s\" dlsym(sk_api_version) failed: %s",
		    path, dlerror());
		যাও fail;
	}
	version = ret->sk_api_version();
	debug_f("provider %s implements version 0x%08lx", ret->path,
	    (u_long)version);
	যদি ((version & SSH_SK_VERSION_MAJOR_MASK) != SSH_SK_VERSION_MAJOR) {
		error("Provider \"%s\" implements unsupported "
		    "version 0x%08lx (supported: 0x%08lx)",
		    path, (u_long)version, (u_long)SSH_SK_VERSION_MAJOR);
		যাও fail;
	}
	যদি ((ret->sk_enroll = dlsym(ret->dlhandle, "sk_enroll")) == ফাঁকা) {
		error("Provider %s dlsym(sk_enroll) failed: %s",
		    path, dlerror());
		যাও fail;
	}
	যদি ((ret->sk_sign = dlsym(ret->dlhandle, "sk_sign")) == ফাঁকা) {
		error("Provider \"%s\" dlsym(sk_sign) failed: %s",
		    path, dlerror());
		যাও fail;
	}
	যদি ((ret->sk_load_resident_চাবিগুলি = dlsym(ret->dlhandle,
	    "sk_load_resident_keys")) == ফাঁকা) {
		error("Provider \"%s\" dlsym(sk_load_resident_keys) "
		    "failed: %s", path, dlerror());
		যাও fail;
	}
	/* success */
	ফেরত ret;
fail:
	sshsk_free(ret);
	ফেরত ফাঁকা;
}

স্থির শূন্য
sshsk_free_enroll_response(কাঠামো sk_enroll_response *r)
{
	যদি (r == ফাঁকা)
		ফেরত;
	freezero(r->চাবি_handle, r->চাবি_handle_len);
	freezero(r->public_চাবি, r->public_চাবি_len);
	freezero(r->signature, r->signature_len);
	freezero(r->attestation_cert, r->attestation_cert_len);
	freezero(r->authdata, r->authdata_len);
	freezero(r, আকার(*r));
}

স্থির শূন্য
sshsk_free_sign_response(কাঠামো sk_sign_response *r)
{
	যদি (r == ফাঁকা)
		ফেরত;
	freezero(r->sig_r, r->sig_r_len);
	freezero(r->sig_s, r->sig_s_len);
	freezero(r, আকার(*r));
}

#ifdef WITH_OPENSSL
/* Assemble key from response */
স্থির পূর্ণসংখ্যা
sshsk_ecdsa_assemble(কাঠামো sk_enroll_response *resp, কাঠামো sshkey **keyp)
{
	কাঠামো sshkey *চাবি = ফাঁকা;
	কাঠামো sshbuf *b = ফাঁকা;
	EC_চাবি *ecdsa = ফাঁকা;
	EC_POINT *q = ফাঁকা;
	ধ্রুবক EC_GROUP *g = ফাঁকা;
	পূর্ণসংখ্যা r;

	*keyp = ফাঁকা;
	যদি ((চাবি = sshkey_new(চাবি_ECDSA_SK)) == ফাঁকা) {
		error_f("sshkey_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		যাও out;
	}
	চাবি->ecdsa_nid = NID_X9_62_prime256v1;
	যদি ((ecdsa = EC_চাবি_new_by_curve_name(চাবি->ecdsa_nid)) == ফাঁকা ||
	    (g = EC_চাবি_get0_group(ecdsa)) == ফাঁকা ||
	    (q = EC_POINT_new(g)) == ফাঁকা ||
	    (b = sshbuf_new()) == ফাঁকা) {
		error_f("allocation failed");
		r = SSH_ERR_ALLOC_FAIL;
		যাও out;
	}
	যদি ((r = sshbuf_put_string(b,
	    resp->public_চাবি, resp->public_চাবি_len)) != 0) {
		error_fr(r, "sshbuf_put_string");
		যাও out;
	}
	যদি ((r = sshbuf_get_ec(b, q, g)) != 0) {
		error_fr(r, "parse");
		r = SSH_ERR_INVALID_FORMAT;
		যাও out;
	}
	যদি (sshkey_ec_validate_public(g, q) != 0) {
		error("Authenticator returned invalid ECDSA key");
		r = SSH_ERR_চাবি_INVALID_EC_মান;
		যাও out;
	}
	যদি (EC_চাবি_set_public_চাবি(ecdsa, q) != 1) {
		/* XXX assume it is a allocation error */
		error_f("allocation failed");
		r = SSH_ERR_ALLOC_FAIL;
		যাও out;
	}
	যদি ((চাবি->pkey = EVP_PKEY_new()) == ফাঁকা) {
		error_f("allocation failed");
		r = SSH_ERR_ALLOC_FAIL;
		যাও out;
	}
	যদি (EVP_PKEY_set1_EC_চাবি(চাবি->pkey, ecdsa) != 1) {
		error_f("Assigning EC_KEY failed");
		r = SSH_ERR_LIBCRYPTO_ERROR;
		যাও out;
	}
	/* success */
	*keyp = চাবি;
	চাবি = ফাঁকা; /* transferred */
	r = 0;
 out:
	sshkey_free(চাবি);
	sshbuf_free(b);
	EC_চাবি_free(ecdsa);
	EC_POINT_free(q);
	ফেরত r;
}
#endif /* WITH_OPENSSL */

স্থির পূর্ণসংখ্যা
sshsk_ed25519_assemble(কাঠামো sk_enroll_response *resp, কাঠামো sshkey **keyp)
{
	কাঠামো sshkey *চাবি = ফাঁকা;
	পূর্ণসংখ্যা r;

	*keyp = ফাঁকা;
	যদি (resp->public_চাবি_len != ED25519_PK_SZ) {
		error_f("invalid size: %zu", resp->public_চাবি_len);
		r = SSH_ERR_INVALID_FORMAT;
		যাও out;
	}
	যদি ((চাবি = sshkey_new(চাবি_ED25519_SK)) == ফাঁকা) {
		error_f("sshkey_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		যাও out;
	}
	যদি ((চাবি->ed25519_pk = malloc(ED25519_PK_SZ)) == ফাঁকা) {
		error_f("malloc failed");
		r = SSH_ERR_ALLOC_FAIL;
		যাও out;
	}
	memcpy(চাবি->ed25519_pk, resp->public_চাবি, ED25519_PK_SZ);
	/* success */
	*keyp = চাবি;
	চাবি = ফাঁকা; /* transferred */
	r = 0;
 out:
	sshkey_free(চাবি);
	ফেরত r;
}

স্থির পূর্ণসংখ্যা
sshsk_চাবি_from_response(পূর্ণসংখ্যা alg, ধ্রুবক অক্ষর *application, uint8_t flags,
    কাঠামো sk_enroll_response *resp, কাঠামো sshkey **keyp)
{
	কাঠামো sshkey *চাবি = ফাঁকা;
	পূর্ণসংখ্যা r = SSH_ERR_INTERNAL_ERROR;

	*keyp = ফাঁকা;

	/* Check response validity */
	যদি (resp->public_চাবি == ফাঁকা || resp->চাবি_handle == ফাঁকা) {
		error_f("sk_enroll response invalid");
		r = SSH_ERR_INVALID_FORMAT;
		যাও out;
	}
	নির্বাচন (alg) {
#ifdef WITH_OPENSSL
	ক্ষেত্র SSH_SK_ECDSA:
		যদি ((r = sshsk_ecdsa_assemble(resp, &চাবি)) != 0)
			যাও out;
		বিরতি;
#endif /* WITH_OPENSSL */
	ক্ষেত্র SSH_SK_ED25519:
		যদি ((r = sshsk_ed25519_assemble(resp, &চাবি)) != 0)
			যাও out;
		বিরতি;
	পূর্বনির্ধারিত:
		error_f("unsupported algorithm %d", alg);
		r = SSH_ERR_INVALID_ARGUMENT;
		যাও out;
	}
	চাবি->sk_flags = flags;
	যদি ((চাবি->sk_চাবি_handle = sshbuf_new()) == ফাঁকা ||
	    (চাবি->sk_reserved = sshbuf_new()) == ফাঁকা) {
		error_f("allocation failed");
		r = SSH_ERR_ALLOC_FAIL;
		যাও out;
	}
	যদি ((চাবি->sk_application = strdup(application)) == ফাঁকা) {
		error_f("strdup application failed");
		r = SSH_ERR_ALLOC_FAIL;
		যাও out;
	}
	যদি ((r = sshbuf_put(চাবি->sk_চাবি_handle, resp->চাবি_handle,
	    resp->চাবি_handle_len)) != 0) {
		error_fr(r, "put key handle");
		যাও out;
	}
	/* success */
	r = 0;
	*keyp = চাবি;
	চাবি = ফাঁকা;
 out:
	sshkey_free(চাবি);
	ফেরত r;
}

স্থির পূর্ণসংখ্যা
skerr_to_ssherr(পূর্ণসংখ্যা skerr)
{
	নির্বাচন (skerr) {
	ক্ষেত্র SSH_SK_ERR_UNSUPPORTED:
		ফেরত SSH_ERR_FEATURE_UNSUPPORTED;
	ক্ষেত্র SSH_SK_ERR_PIN_REQUIRED:
		ফেরত SSH_ERR_চাবি_WRONG_PASSPHRASE;
	ক্ষেত্র SSH_SK_ERR_DEVICE_NOT_FOUND:
		ফেরত SSH_ERR_DEVICE_NOT_FOUND;
	ক্ষেত্র SSH_SK_ERR_CREDENTIAL_EXISTS:
		ফেরত SSH_ERR_চাবি_BAD_PERMISSIONS;
	ক্ষেত্র SSH_SK_ERR_GENERAL:
	পূর্বনির্ধারিত:
		ফেরত SSH_ERR_INVALID_FORMAT;
	}
}

স্থির শূন্য
sshsk_free_options(কাঠামো sk_option **opts)
{
	আকার_t i;

	যদি (opts == ফাঁকা)
		ফেরত;
	জন্য (i = 0; opts[i] != ফাঁকা; i++) {
		মুক্ত(opts[i]->name);
		মুক্ত(opts[i]->মান);
		মুক্ত(opts[i]);
	}
	মুক্ত(opts);
}

স্থির পূর্ণসংখ্যা
sshsk_add_option(কাঠামো sk_option ***optsp, আকার_t *noptsp,
    ধ্রুবক অক্ষর *name, ধ্রুবক অক্ষর *মান, uint8_t required)
{
	কাঠামো sk_option **opts = *optsp;
	আকার_t nopts = *noptsp;

	যদি ((opts = recallocarray(opts, nopts, nopts + 2, /* extra for NULL */
	    আকার(*opts))) == ফাঁকা) {
		error_f("array alloc failed");
		ফেরত SSH_ERR_ALLOC_FAIL;
	}
	*optsp = opts;
	*noptsp = nopts + 1;
	যদি ((opts[nopts] = calloc(1, আকার(**opts))) == ফাঁকা) {
		error_f("alloc failed");
		ফেরত SSH_ERR_ALLOC_FAIL;
	}
	যদি ((opts[nopts]->name = strdup(name)) == ফাঁকা ||
	    (opts[nopts]->মান = strdup(মান)) == ফাঁকা) {
		error_f("alloc failed");
		ফেরত SSH_ERR_ALLOC_FAIL;
	}
	opts[nopts]->required = required;
	ফেরত 0;
}

স্থির পূর্ণসংখ্যা
make_options(ধ্রুবক অক্ষর *device, ধ্রুবক অক্ষর *user_id,
    কাঠামো sk_option ***optsp)
{
	কাঠামো sk_option **opts = ফাঁকা;
	আকার_t nopts = 0;
	পূর্ণসংখ্যা r, ret = SSH_ERR_INTERNAL_ERROR;

	যদি (device != ফাঁকা &&
	    (r = sshsk_add_option(&opts, &nopts, "device", device, 0)) != 0) {
		ret = r;
		যাও out;
	}
	যদি (user_id != ফাঁকা &&
	    (r = sshsk_add_option(&opts, &nopts, "user", user_id, 0)) != 0) {
		ret = r;
		যাও out;
	}
	/* success */
	*optsp = opts;
	opts = ফাঁকা;
	nopts = 0;
	ret = 0;
 out:
	sshsk_free_options(opts);
	ফেরত ret;
}


স্থির পূর্ণসংখ্যা
fill_attestation_blob(ধ্রুবক কাঠামো sk_enroll_response *resp,
    কাঠামো sshbuf *attest)
{
	পূর্ণসংখ্যা r;

	যদি (attest == ফাঁকা)
		ফেরত 0; /* nothing to do */
	যদি ((r = sshbuf_put_cstring(attest, "ssh-sk-attest-v01")) != 0 ||
	    (r = sshbuf_put_string(attest,
	    resp->attestation_cert, resp->attestation_cert_len)) != 0 ||
	    (r = sshbuf_put_string(attest,
	    resp->signature, resp->signature_len)) != 0 ||
	    (r = sshbuf_put_string(attest,
	    resp->authdata, resp->authdata_len)) != 0 ||
	    (r = sshbuf_put_u32(attest, 0)) != 0 || /* resvd flags */
	    (r = sshbuf_put_string(attest, ফাঁকা, 0)) != 0 /* resvd */) {
		error_fr(r, "compose");
		ফেরত r;
	}
	/* success */
	ফেরত 0;
}

পূর্ণসংখ্যা
sshsk_enroll(পূর্ণসংখ্যা type, ধ্রুবক অক্ষর *provider_path, ধ্রুবক অক্ষর *device,
    ধ্রুবক অক্ষর *application, ধ্রুবক অক্ষর *userid, uint8_t flags,
    ধ্রুবক অক্ষর *pin, কাঠামো sshbuf *challenge_buf,
    কাঠামো sshkey **keyp, কাঠামো sshbuf *attest)
{
	কাঠামো sshsk_provider *skp = ফাঁকা;
	কাঠামো sshkey *চাবি = ফাঁকা;
	u_char randchall[32];
	ধ্রুবক u_char *challenge;
	আকার_t challenge_len;
	কাঠামো sk_enroll_response *resp = ফাঁকা;
	কাঠামো sk_option **opts = ফাঁকা;
	পূর্ণসংখ্যা r = SSH_ERR_INTERNAL_ERROR;
	পূর্ণসংখ্যা alg;

	debug_f("provider \"%s\", device \"%s\", application \"%s\", "
	    "userid \"%s\", flags 0x%02x, challenge len %zu%s",
	    provider_path, device, application, userid, flags,
	    challenge_buf == ফাঁকা ? 0 : sshbuf_len(challenge_buf),
	    (pin != ফাঁকা && *pin != '\0') ? " with-pin" : "");

	*keyp = ফাঁকা;
	যদি (attest)
		sshbuf_reset(attest);

	যদি ((r = make_options(device, userid, &opts)) != 0)
		যাও out;

	নির্বাচন (type) {
#ifdef WITH_OPENSSL
	ক্ষেত্র চাবি_ECDSA_SK:
		alg = SSH_SK_ECDSA;
		বিরতি;
#endif /* WITH_OPENSSL */
	ক্ষেত্র চাবি_ED25519_SK:
		alg = SSH_SK_ED25519;
		বিরতি;
	পূর্বনির্ধারিত:
		error_f("unsupported key type");
		r = SSH_ERR_INVALID_ARGUMENT;
		যাও out;
	}
	যদি (provider_path == ফাঁকা) {
		error_f("missing provider");
		r = SSH_ERR_INVALID_ARGUMENT;
		যাও out;
	}
	যদি (application == ফাঁকা || *application == '\0') {
		error_f("missing application");
		r = SSH_ERR_INVALID_ARGUMENT;
		যাও out;
	}
	যদি (challenge_buf == ফাঁকা) {
		debug_f("using random challenge");
		arc4random_buf(randchall, আকার(randchall));
		challenge = randchall;
		challenge_len = আকার(randchall);
	} অন্যথা যদি (sshbuf_len(challenge_buf) == 0) {
		error("Missing enrollment challenge");
		r = SSH_ERR_INVALID_ARGUMENT;
		যাও out;
	} অন্যথা {
		challenge = sshbuf_ptr(challenge_buf);
		challenge_len = sshbuf_len(challenge_buf);
		debug3_f("using explicit challenge len=%zd", challenge_len);
	}
	যদি ((skp = sshsk_open(provider_path)) == ফাঁকা) {
		r = SSH_ERR_INVALID_FORMAT; /* XXX sshsk_open return code? */
		যাও out;
	}
	/* XXX validate flags? */
	/* enroll key */
	যদি ((r = skp->sk_enroll(alg, challenge, challenge_len, application,
	    flags, pin, opts, &resp)) != 0) {
		debug_f("provider \"%s\" failure %d", provider_path, r);
		r = skerr_to_ssherr(r);
		যাও out;
	}

	যদি ((r = sshsk_চাবি_from_response(alg, application, resp->flags,
	    resp, &চাবি)) != 0)
		যাও out;

	/* Optionally fill in the attestation information */
	যদি ((r = fill_attestation_blob(resp, attest)) != 0)
		যাও out;

	/* success */
	*keyp = চাবি;
	চাবি = ফাঁকা; /* transferred */
	r = 0;
 out:
	sshsk_free_options(opts);
	sshsk_free(skp);
	sshkey_free(চাবি);
	sshsk_free_enroll_response(resp);
	explicit_bzero(randchall, আকার(randchall));
	ফেরত r;
}

#ifdef WITH_OPENSSL
স্থির পূর্ণসংখ্যা
sshsk_ecdsa_sig(কাঠামো sk_sign_response *resp, কাঠামো sshbuf *sig)
{
	কাঠামো sshbuf *inner_sig = ফাঁকা;
	পূর্ণসংখ্যা r = SSH_ERR_INTERNAL_ERROR;

	/* Check response validity */
	যদি (resp->sig_r == ফাঁকা || resp->sig_s == ফাঁকা) {
		error_f("sk_sign response invalid");
		r = SSH_ERR_INVALID_FORMAT;
		যাও out;
	}
	যদি ((inner_sig = sshbuf_new()) == ফাঁকা) {
		r = SSH_ERR_ALLOC_FAIL;
		যাও out;
	}
	/* Prepare and append inner signature object */
	যদি ((r = sshbuf_put_bignum2_bytes(inner_sig,
	    resp->sig_r, resp->sig_r_len)) != 0 ||
	    (r = sshbuf_put_bignum2_bytes(inner_sig,
	    resp->sig_s, resp->sig_s_len)) != 0) {
		error_fr(r, "compose inner");
		যাও out;
	}
	যদি ((r = sshbuf_put_stringb(sig, inner_sig)) != 0 ||
	    (r = sshbuf_put_u8(sig, resp->flags)) != 0 ||
	    (r = sshbuf_put_u32(sig, resp->গণক)) != 0) {
		error_fr(r, "compose");
		যাও out;
	}
#ifdef DEBUG_SK
	fprintf(stderr, "%s: sig_r:\n", __func__);
	sshbuf_dump_তথ্য(resp->sig_r, resp->sig_r_len, stderr);
	fprintf(stderr, "%s: sig_s:\n", __func__);
	sshbuf_dump_তথ্য(resp->sig_s, resp->sig_s_len, stderr);
	fprintf(stderr, "%s: inner:\n", __func__);
	sshbuf_dump(inner_sig, stderr);
#endif
	r = 0;
 out:
	sshbuf_free(inner_sig);
	ফেরত r;
}
#endif /* WITH_OPENSSL */

স্থির পূর্ণসংখ্যা
sshsk_ed25519_sig(কাঠামো sk_sign_response *resp, কাঠামো sshbuf *sig)
{
	পূর্ণসংখ্যা r = SSH_ERR_INTERNAL_ERROR;

	/* Check response validity */
	যদি (resp->sig_r == ফাঁকা) {
		error_f("sk_sign response invalid");
		r = SSH_ERR_INVALID_FORMAT;
		যাও out;
	}
	যদি ((r = sshbuf_put_string(sig,
	    resp->sig_r, resp->sig_r_len)) != 0 ||
	    (r = sshbuf_put_u8(sig, resp->flags)) != 0 ||
	    (r = sshbuf_put_u32(sig, resp->গণক)) != 0) {
		error_fr(r, "compose");
		যাও out;
	}
#ifdef DEBUG_SK
	fprintf(stderr, "%s: sig_r:\n", __func__);
	sshbuf_dump_তথ্য(resp->sig_r, resp->sig_r_len, stderr);
#endif
	r = 0;
 out:
	ফেরত r;
}

পূর্ণসংখ্যা
sshsk_sign(ধ্রুবক অক্ষর *provider_path, কাঠামো sshkey *চাবি,
    u_char **sigp, আকার_t *lenp, ধ্রুবক u_char *তথ্য, আকার_t datalen,
    u_int compat, ধ্রুবক অক্ষর *pin)
{
	কাঠামো sshsk_provider *skp = ফাঁকা;
	পূর্ণসংখ্যা r = SSH_ERR_INTERNAL_ERROR;
	পূর্ণসংখ্যা type, alg;
	কাঠামো sk_sign_response *resp = ফাঁকা;
	কাঠামো sshbuf *inner_sig = ফাঁকা, *sig = ফাঁকা;
	কাঠামো sk_option **opts = ফাঁকা;

	debug_f("provider \"%s\", key %s, flags 0x%02x%s",
	    provider_path, sshkey_type(চাবি), চাবি->sk_flags,
	    (pin != ফাঁকা && *pin != '\0') ? " with-pin" : "");

	যদি (sigp != ফাঁকা)
		*sigp = ফাঁকা;
	যদি (lenp != ফাঁকা)
		*lenp = 0;
	type = sshkey_type_plain(চাবি->type);
	নির্বাচন (type) {
#ifdef WITH_OPENSSL
	ক্ষেত্র চাবি_ECDSA_SK:
		alg = SSH_SK_ECDSA;
		বিরতি;
#endif /* WITH_OPENSSL */
	ক্ষেত্র চাবি_ED25519_SK:
		alg = SSH_SK_ED25519;
		বিরতি;
	পূর্বনির্ধারিত:
		ফেরত SSH_ERR_INVALID_ARGUMENT;
	}
	যদি (provider_path == ফাঁকা ||
	    চাবি->sk_চাবি_handle == ফাঁকা ||
	    চাবি->sk_application == ফাঁকা || *চাবি->sk_application == '\0') {
		r = SSH_ERR_INVALID_ARGUMENT;
		যাও out;
	}
	যদি ((skp = sshsk_open(provider_path)) == ফাঁকা) {
		r = SSH_ERR_INVALID_FORMAT; /* XXX sshsk_open return code? */
		যাও out;
	}
#ifdef DEBUG_SK
	fprintf(stderr, "%s: sk_flags = 0x%02x, sk_application = \"%s\"\n",
	    __func__, চাবি->sk_flags, চাবি->sk_application);
	fprintf(stderr, "%s: sk_key_handle:\n", __func__);
	sshbuf_dump(চাবি->sk_চাবি_handle, stderr);
#endif
	যদি ((r = skp->sk_sign(alg, তথ্য, datalen, চাবি->sk_application,
	    sshbuf_ptr(চাবি->sk_চাবি_handle), sshbuf_len(চাবি->sk_চাবি_handle),
	    চাবি->sk_flags, pin, opts, &resp)) != 0) {
		debug_f("sk_sign failed with code %d", r);
		r = skerr_to_ssherr(r);
		যাও out;
	}
	/* Assemble signature */
	যদি ((sig = sshbuf_new()) == ফাঁকা) {
		r = SSH_ERR_ALLOC_FAIL;
		যাও out;
	}
	যদি ((r = sshbuf_put_cstring(sig, sshkey_ssh_name_plain(চাবি))) != 0) {
		error_fr(r, "compose outer");
		যাও out;
	}
	নির্বাচন (type) {
#ifdef WITH_OPENSSL
	ক্ষেত্র চাবি_ECDSA_SK:
		যদি ((r = sshsk_ecdsa_sig(resp, sig)) != 0)
			যাও out;
		বিরতি;
#endif /* WITH_OPENSSL */
	ক্ষেত্র চাবি_ED25519_SK:
		যদি ((r = sshsk_ed25519_sig(resp, sig)) != 0)
			যাও out;
		বিরতি;
	}
#ifdef DEBUG_SK
	fprintf(stderr, "%s: sig_flags = 0x%02x, sig_counter = %u\n",
	    __func__, resp->flags, resp->গণক);
	fprintf(stderr, "%s: data to sign:\n", __func__);
	sshbuf_dump_তথ্য(তথ্য, datalen, stderr);
	fprintf(stderr, "%s: sigbuf:\n", __func__);
	sshbuf_dump(sig, stderr);
#endif
	যদি (sigp != ফাঁকা) {
		যদি ((*sigp = malloc(sshbuf_len(sig))) == ফাঁকা) {
			r = SSH_ERR_ALLOC_FAIL;
			যাও out;
		}
		memcpy(*sigp, sshbuf_ptr(sig), sshbuf_len(sig));
	}
	যদি (lenp != ফাঁকা)
		*lenp = sshbuf_len(sig);
	/* success */
	r = 0;
 out:
	sshsk_free_options(opts);
	sshsk_free(skp);
	sshsk_free_sign_response(resp);
	sshbuf_free(sig);
	sshbuf_free(inner_sig);
	ফেরত r;
}

স্থির শূন্য
sshsk_free_sk_resident_চাবিগুলি(কাঠামো sk_resident_চাবি **rks, আকার_t nrks)
{
	আকার_t i;

	যদি (nrks == 0 || rks == ফাঁকা)
		ফেরত;
	জন্য (i = 0; i < nrks; i++) {
		মুক্ত(rks[i]->application);
		freezero(rks[i]->user_id, rks[i]->user_id_len);
		freezero(rks[i]->চাবি.চাবি_handle, rks[i]->চাবি.চাবি_handle_len);
		freezero(rks[i]->চাবি.public_চাবি, rks[i]->চাবি.public_চাবি_len);
		freezero(rks[i]->চাবি.signature, rks[i]->চাবি.signature_len);
		freezero(rks[i]->চাবি.attestation_cert,
		    rks[i]->চাবি.attestation_cert_len);
		freezero(rks[i], আকার(**rks));
	}
	মুক্ত(rks);
}

স্থির শূন্য
sshsk_free_resident_চাবি(কাঠামো sshsk_resident_চাবি *srk)
{
	যদি (srk == ফাঁকা)
		ফেরত;
	sshkey_free(srk->চাবি);
	freezero(srk->user_id, srk->user_id_len);
	মুক্ত(srk);
}


শূন্য
sshsk_free_resident_চাবিগুলি(কাঠামো sshsk_resident_চাবি **srks, আকার_t nsrks)
{
	আকার_t i;

	যদি (srks == ফাঁকা || nsrks == 0)
		ফেরত;

	জন্য (i = 0; i < nsrks; i++)
		sshsk_free_resident_চাবি(srks[i]);
	মুক্ত(srks);
}

পূর্ণসংখ্যা
sshsk_load_resident(ধ্রুবক অক্ষর *provider_path, ধ্রুবক অক্ষর *device,
    ধ্রুবক অক্ষর *pin, u_int flags, কাঠামো sshsk_resident_চাবি ***srksp,
    আকার_t *nsrksp)
{
	কাঠামো sshsk_provider *skp = ফাঁকা;
	পূর্ণসংখ্যা r = SSH_ERR_INTERNAL_ERROR;
	কাঠামো sk_resident_চাবি **rks = ফাঁকা;
	আকার_t i, nrks = 0, nsrks = 0;
	কাঠামো sshkey *চাবি = ফাঁকা;
	কাঠামো sshsk_resident_চাবি *srk = ফাঁকা, **srks = ফাঁকা, **tmp;
	uint8_t sk_flags;
	কাঠামো sk_option **opts = ফাঁকা;

	debug_f("provider \"%s\"%s", provider_path,
	    (pin != ফাঁকা && *pin != '\0') ? ", have-pin": "");

	যদি (srksp == ফাঁকা || nsrksp == ফাঁকা)
		ফেরত SSH_ERR_INVALID_ARGUMENT;
	*srksp = ফাঁকা;
	*nsrksp = 0;

	যদি ((r = make_options(device, ফাঁকা, &opts)) != 0)
		যাও out;
	যদি ((skp = sshsk_open(provider_path)) == ফাঁকা) {
		r = SSH_ERR_INVALID_FORMAT; /* XXX sshsk_open return code? */
		যাও out;
	}
	যদি ((r = skp->sk_load_resident_চাবিগুলি(pin, opts, &rks, &nrks)) != 0) {
		error("Provider \"%s\" returned failure %d", provider_path, r);
		r = skerr_to_ssherr(r);
		যাও out;
	}
	জন্য (i = 0; i < nrks; i++) {
		debug3_f("rk %zu: slot %zu, alg %d, app \"%s\", uidlen %zu",
		    i, rks[i]->slot, rks[i]->alg, rks[i]->application,
		    rks[i]->user_id_len);
		/* XXX need better filter here */
		যদি (strncmp(rks[i]->application, "ssh:", 4) != 0)
			চালু;
		নির্বাচন (rks[i]->alg) {
		ক্ষেত্র SSH_SK_ECDSA:
		ক্ষেত্র SSH_SK_ED25519:
			বিরতি;
		পূর্বনির্ধারিত:
			চালু;
		}
		sk_flags = SSH_SK_USER_PRESENCE_REQD|SSH_SK_RESIDENT_চাবি;
		যদি ((rks[i]->flags & SSH_SK_USER_VERIFICATION_REQD))
			sk_flags |= SSH_SK_USER_VERIFICATION_REQD;
		যদি ((r = sshsk_চাবি_from_response(rks[i]->alg,
		    rks[i]->application, sk_flags, &rks[i]->চাবি, &চাবি)) != 0)
			যাও out;
		যদি ((srk = calloc(1, আকার(*srk))) == ফাঁকা) {
			error_f("calloc failed");
			r = SSH_ERR_ALLOC_FAIL;
			যাও out;
		}
		srk->চাবি = চাবি;
		চাবি = ফাঁকা; /* transferred */
		যদি ((srk->user_id = calloc(1, rks[i]->user_id_len)) == ফাঁকা) {
			error_f("calloc failed");
			r = SSH_ERR_ALLOC_FAIL;
			যাও out;
		}
		memcpy(srk->user_id, rks[i]->user_id, rks[i]->user_id_len);
		srk->user_id_len = rks[i]->user_id_len;
		যদি ((tmp = recallocarray(srks, nsrks, nsrks + 1,
		    আকার(*tmp))) == ফাঁকা) {
			error_f("recallocarray failed");
			r = SSH_ERR_ALLOC_FAIL;
			যাও out;
		}
		srks = tmp;
		srks[nsrks++] = srk;
		srk = ফাঁকা;
		/* XXX synthesise comment */
	}
	/* success */
	*srksp = srks;
	*nsrksp = nsrks;
	srks = ফাঁকা;
	nsrks = 0;
	r = 0;
 out:
	sshsk_free_options(opts);
	sshsk_free(skp);
	sshsk_free_sk_resident_চাবিগুলি(rks, nrks);
	sshkey_free(চাবি);
	sshsk_free_resident_চাবি(srk);
	sshsk_free_resident_চাবিগুলি(srks, nsrks);
	ফেরত r;
}

#endif /* ENABLE_SK */
