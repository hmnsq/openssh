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

সংরচনা sshsk_provider {
	বর্ণ *path;
	শূন্য *dlhandle;

	/* Return the version of the middleware API */
	uint32_t (*sk_api_version)(শূন্য);

	/* Enroll a U2F key (private key generation) */
	পূর্ণাঙ্ক (*sk_enroll)(পূর্ণাঙ্ক alg, ধ্রুব uint8_t *challenge,
	    size_t challenge_len, ধ্রুব বর্ণ *application, uint8_t flags,
	    ধ্রুব বর্ণ *pin, সংরচনা sk_option **opts,
	    সংরচনা sk_enroll_response **enroll_response);

	/* Sign a challenge */
	পূর্ণাঙ্ক (*sk_sign)(পূর্ণাঙ্ক alg, ধ্রুব uint8_t *message, size_t message_len,
	    ধ্রুব বর্ণ *application,
	    ধ্রুব uint8_t *চাবি_handle, size_t চাবি_handle_len,
	    uint8_t flags, ধ্রুব বর্ণ *pin, সংরচনা sk_option **opts,
	    সংরচনা sk_sign_response **sign_response);

	/* Enumerate resident keys */
	পূর্ণাঙ্ক (*sk_load_resident_চাবিগুলি)(ধ্রুব বর্ণ *pin, সংরচনা sk_option **opts,
	    সংরচনা sk_resident_চাবি ***rks, size_t *nrks);
};

/* Built-in version */
পূর্ণাঙ্ক ssh_sk_enroll(পূর্ণাঙ্ক alg, ধ্রুব uint8_t *challenge,
    size_t challenge_len, ধ্রুব বর্ণ *application, uint8_t flags,
    ধ্রুব বর্ণ *pin, সংরচনা sk_option **opts,
    সংরচনা sk_enroll_response **enroll_response);
পূর্ণাঙ্ক ssh_sk_sign(পূর্ণাঙ্ক alg, ধ্রুব uint8_t *message, size_t message_len,
    ধ্রুব বর্ণ *application,
    ধ্রুব uint8_t *চাবি_handle, size_t চাবি_handle_len,
    uint8_t flags, ধ্রুব বর্ণ *pin, সংরচনা sk_option **opts,
    সংরচনা sk_sign_response **sign_response);
পূর্ণাঙ্ক ssh_sk_load_resident_চাবিগুলি(ধ্রুব বর্ণ *pin, সংরচনা sk_option **opts,
    সংরচনা sk_resident_চাবি ***rks, size_t *nrks);

স্থির শূন্য
sshsk_free(সংরচনা sshsk_provider *p)
{
	যদি (p == রিক্ত)
		প্রত্যাগম;
	মুক্ত(p->path);
	যদি (p->dlhandle != রিক্ত)
		dlclose(p->dlhandle);
	মুক্ত(p);
}

স্থির সংরচনা sshsk_provider *
sshsk_open(ধ্রুব বর্ণ *path)
{
	সংরচনা sshsk_provider *ret = রিক্ত;
	uint32_t version;

	যদি (path == রিক্ত || *path == '\0') {
		error("No FIDO SecurityKeyProvider specified");
		প্রত্যাগম রিক্ত;
	}
	যদি ((ret = calloc(1, পরিমাণ(*ret))) == রিক্ত) {
		error_f("calloc failed");
		প্রত্যাগম রিক্ত;
	}
	যদি ((ret->path = strdup(path)) == রিক্ত) {
		error_f("strdup failed");
		গচ্ছ fail;
	}
	/* Skip the rest if we're using the linked in middleware */
	যদি (strcasecmp(ret->path, "internal") == 0) {
#ifdef ENABLE_SK_INTERNAL
		ret->sk_enroll = ssh_sk_enroll;
		ret->sk_sign = ssh_sk_sign;
		ret->sk_load_resident_চাবিগুলি = ssh_sk_load_resident_চাবিগুলি;
		প্রত্যাগম ret;
#অন্যথা
		error("internal security key support not enabled");
		গচ্ছ fail;
#endif
	}
	যদি (lib_contains_প্রতীক(path, "sk_api_version") != 0) {
		error("provider %s is not an OpenSSH FIDO library", path);
		গচ্ছ fail;
	}
	যদি ((ret->dlhandle = dlopen(path, RTLD_NOW)) == রিক্ত)
		fatal("Provider \"%s\" dlopen failed: %s", path, dlerror());
	যদি ((ret->sk_api_version = dlsym(ret->dlhandle,
	    "sk_api_version")) == রিক্ত) {
		error("Provider \"%s\" dlsym(sk_api_version) failed: %s",
		    path, dlerror());
		গচ্ছ fail;
	}
	version = ret->sk_api_version();
	debug_f("provider %s implements version 0x%08lx", ret->path,
	    (u_long)version);
	যদি ((version & SSH_SK_VERSION_MAJOR_MASK) != SSH_SK_VERSION_MAJOR) {
		error("Provider \"%s\" implements unsupported "
		    "version 0x%08lx (supported: 0x%08lx)",
		    path, (u_long)version, (u_long)SSH_SK_VERSION_MAJOR);
		গচ্ছ fail;
	}
	যদি ((ret->sk_enroll = dlsym(ret->dlhandle, "sk_enroll")) == রিক্ত) {
		error("Provider %s dlsym(sk_enroll) failed: %s",
		    path, dlerror());
		গচ্ছ fail;
	}
	যদি ((ret->sk_sign = dlsym(ret->dlhandle, "sk_sign")) == রিক্ত) {
		error("Provider \"%s\" dlsym(sk_sign) failed: %s",
		    path, dlerror());
		গচ্ছ fail;
	}
	যদি ((ret->sk_load_resident_চাবিগুলি = dlsym(ret->dlhandle,
	    "sk_load_resident_keys")) == রিক্ত) {
		error("Provider \"%s\" dlsym(sk_load_resident_keys) "
		    "failed: %s", path, dlerror());
		গচ্ছ fail;
	}
	/* success */
	প্রত্যাগম ret;
fail:
	sshsk_free(ret);
	প্রত্যাগম রিক্ত;
}

স্থির শূন্য
sshsk_free_enroll_response(সংরচনা sk_enroll_response *r)
{
	যদি (r == রিক্ত)
		প্রত্যাগম;
	freezero(r->চাবি_handle, r->চাবি_handle_len);
	freezero(r->public_চাবি, r->public_চাবি_len);
	freezero(r->signature, r->signature_len);
	freezero(r->attestation_cert, r->attestation_cert_len);
	freezero(r->authdata, r->authdata_len);
	freezero(r, পরিমাণ(*r));
}

স্থির শূন্য
sshsk_free_sign_response(সংরচনা sk_sign_response *r)
{
	যদি (r == রিক্ত)
		প্রত্যাগম;
	freezero(r->sig_r, r->sig_r_len);
	freezero(r->sig_s, r->sig_s_len);
	freezero(r, পরিমাণ(*r));
}

#ifdef WITH_OPENSSL
/* Assemble key from response */
স্থির পূর্ণাঙ্ক
sshsk_ecdsa_assemble(সংরচনা sk_enroll_response *resp, সংরচনা sshkey **keyp)
{
	সংরচনা sshkey *চাবি = রিক্ত;
	সংরচনা sshbuf *b = রিক্ত;
	EC_চাবি *ecdsa = রিক্ত;
	EC_POINT *q = রিক্ত;
	ধ্রুব EC_GROUP *g = রিক্ত;
	পূর্ণাঙ্ক r;

	*keyp = রিক্ত;
	যদি ((চাবি = sshkey_new(চাবি_ECDSA_SK)) == রিক্ত) {
		error_f("sshkey_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		গচ্ছ out;
	}
	চাবি->ecdsa_nid = NID_X9_62_prime256v1;
	যদি ((ecdsa = EC_চাবি_new_by_curve_name(চাবি->ecdsa_nid)) == রিক্ত ||
	    (g = EC_চাবি_get0_group(ecdsa)) == রিক্ত ||
	    (q = EC_POINT_new(g)) == রিক্ত ||
	    (b = sshbuf_new()) == রিক্ত) {
		error_f("allocation failed");
		r = SSH_ERR_ALLOC_FAIL;
		গচ্ছ out;
	}
	যদি ((r = sshbuf_put_string(b,
	    resp->public_চাবি, resp->public_চাবি_len)) != 0) {
		error_fr(r, "sshbuf_put_string");
		গচ্ছ out;
	}
	যদি ((r = sshbuf_get_ec(b, q, g)) != 0) {
		error_fr(r, "parse");
		r = SSH_ERR_INVALID_FORMAT;
		গচ্ছ out;
	}
	যদি (sshkey_ec_validate_public(g, q) != 0) {
		error("Authenticator returned invalid ECDSA key");
		r = SSH_ERR_চাবি_INVALID_EC_মান;
		গচ্ছ out;
	}
	যদি (EC_চাবি_set_public_চাবি(ecdsa, q) != 1) {
		/* XXX assume it is a allocation error */
		error_f("allocation failed");
		r = SSH_ERR_ALLOC_FAIL;
		গচ্ছ out;
	}
	যদি ((চাবি->pkey = EVP_PKEY_new()) == রিক্ত) {
		error_f("allocation failed");
		r = SSH_ERR_ALLOC_FAIL;
		গচ্ছ out;
	}
	যদি (EVP_PKEY_set1_EC_চাবি(চাবি->pkey, ecdsa) != 1) {
		error_f("Assigning EC_KEY failed");
		r = SSH_ERR_LIBCRYPTO_ERROR;
		গচ্ছ out;
	}
	/* success */
	*keyp = চাবি;
	চাবি = রিক্ত; /* transferred */
	r = 0;
 out:
	sshkey_free(চাবি);
	sshbuf_free(b);
	EC_চাবি_free(ecdsa);
	EC_POINT_free(q);
	প্রত্যাগম r;
}
#endif /* WITH_OPENSSL */

স্থির পূর্ণাঙ্ক
sshsk_ed25519_assemble(সংরচনা sk_enroll_response *resp, সংরচনা sshkey **keyp)
{
	সংরচনা sshkey *চাবি = রিক্ত;
	পূর্ণাঙ্ক r;

	*keyp = রিক্ত;
	যদি (resp->public_চাবি_len != ED25519_PK_SZ) {
		error_f("invalid size: %zu", resp->public_চাবি_len);
		r = SSH_ERR_INVALID_FORMAT;
		গচ্ছ out;
	}
	যদি ((চাবি = sshkey_new(চাবি_ED25519_SK)) == রিক্ত) {
		error_f("sshkey_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		গচ্ছ out;
	}
	যদি ((চাবি->ed25519_pk = malloc(ED25519_PK_SZ)) == রিক্ত) {
		error_f("malloc failed");
		r = SSH_ERR_ALLOC_FAIL;
		গচ্ছ out;
	}
	memcpy(চাবি->ed25519_pk, resp->public_চাবি, ED25519_PK_SZ);
	/* success */
	*keyp = চাবি;
	চাবি = রিক্ত; /* transferred */
	r = 0;
 out:
	sshkey_free(চাবি);
	প্রত্যাগম r;
}

স্থির পূর্ণাঙ্ক
sshsk_চাবি_from_response(পূর্ণাঙ্ক alg, ধ্রুব বর্ণ *application, uint8_t flags,
    সংরচনা sk_enroll_response *resp, সংরচনা sshkey **keyp)
{
	সংরচনা sshkey *চাবি = রিক্ত;
	পূর্ণাঙ্ক r = SSH_ERR_INTERNAL_ERROR;

	*keyp = রিক্ত;

	/* Check response validity */
	যদি (resp->public_চাবি == রিক্ত || resp->চাবি_handle == রিক্ত) {
		error_f("sk_enroll response invalid");
		r = SSH_ERR_INVALID_FORMAT;
		গচ্ছ out;
	}
	বিকল্প (alg) {
#ifdef WITH_OPENSSL
	পক্ষ SSH_SK_ECDSA:
		যদি ((r = sshsk_ecdsa_assemble(resp, &চাবি)) != 0)
			গচ্ছ out;
		ভঙ্গ;
#endif /* WITH_OPENSSL */
	পক্ষ SSH_SK_ED25519:
		যদি ((r = sshsk_ed25519_assemble(resp, &চাবি)) != 0)
			গচ্ছ out;
		ভঙ্গ;
	স্বভাব:
		error_f("unsupported algorithm %d", alg);
		r = SSH_ERR_INVALID_ARGUMENT;
		গচ্ছ out;
	}
	চাবি->sk_flags = flags;
	যদি ((চাবি->sk_চাবি_handle = sshbuf_new()) == রিক্ত ||
	    (চাবি->sk_reserved = sshbuf_new()) == রিক্ত) {
		error_f("allocation failed");
		r = SSH_ERR_ALLOC_FAIL;
		গচ্ছ out;
	}
	যদি ((চাবি->sk_application = strdup(application)) == রিক্ত) {
		error_f("strdup application failed");
		r = SSH_ERR_ALLOC_FAIL;
		গচ্ছ out;
	}
	যদি ((r = sshbuf_put(চাবি->sk_চাবি_handle, resp->চাবি_handle,
	    resp->চাবি_handle_len)) != 0) {
		error_fr(r, "put key handle");
		গচ্ছ out;
	}
	/* success */
	r = 0;
	*keyp = চাবি;
	চাবি = রিক্ত;
 out:
	sshkey_free(চাবি);
	প্রত্যাগম r;
}

স্থির পূর্ণাঙ্ক
skerr_to_ssherr(পূর্ণাঙ্ক skerr)
{
	বিকল্প (skerr) {
	পক্ষ SSH_SK_ERR_UNSUPPORTED:
		প্রত্যাগম SSH_ERR_FEATURE_UNSUPPORTED;
	পক্ষ SSH_SK_ERR_PIN_REQUIRED:
		প্রত্যাগম SSH_ERR_চাবি_WRONG_PASSPHRASE;
	পক্ষ SSH_SK_ERR_DEVICE_NOT_FOUND:
		প্রত্যাগম SSH_ERR_DEVICE_NOT_FOUND;
	পক্ষ SSH_SK_ERR_CREDENTIAL_EXISTS:
		প্রত্যাগম SSH_ERR_চাবি_BAD_PERMISSIONS;
	পক্ষ SSH_SK_ERR_GENERAL:
	স্বভাব:
		প্রত্যাগম SSH_ERR_INVALID_FORMAT;
	}
}

স্থির শূন্য
sshsk_free_options(সংরচনা sk_option **opts)
{
	size_t i;

	যদি (opts == রিক্ত)
		প্রত্যাগম;
	প্রতি (i = 0; opts[i] != রিক্ত; i++) {
		মুক্ত(opts[i]->name);
		মুক্ত(opts[i]->মান);
		মুক্ত(opts[i]);
	}
	মুক্ত(opts);
}

স্থির পূর্ণাঙ্ক
sshsk_add_option(সংরচনা sk_option ***optsp, size_t *noptsp,
    ধ্রুব বর্ণ *name, ধ্রুব বর্ণ *মান, uint8_t required)
{
	সংরচনা sk_option **opts = *optsp;
	size_t nopts = *noptsp;

	যদি ((opts = recallocarray(opts, nopts, nopts + 2, /* extra for NULL */
	    পরিমাণ(*opts))) == রিক্ত) {
		error_f("array alloc failed");
		প্রত্যাগম SSH_ERR_ALLOC_FAIL;
	}
	*optsp = opts;
	*noptsp = nopts + 1;
	যদি ((opts[nopts] = calloc(1, পরিমাণ(**opts))) == রিক্ত) {
		error_f("alloc failed");
		প্রত্যাগম SSH_ERR_ALLOC_FAIL;
	}
	যদি ((opts[nopts]->name = strdup(name)) == রিক্ত ||
	    (opts[nopts]->মান = strdup(মান)) == রিক্ত) {
		error_f("alloc failed");
		প্রত্যাগম SSH_ERR_ALLOC_FAIL;
	}
	opts[nopts]->required = required;
	প্রত্যাগম 0;
}

স্থির পূর্ণাঙ্ক
make_options(ধ্রুব বর্ণ *device, ধ্রুব বর্ণ *user_id,
    সংরচনা sk_option ***optsp)
{
	সংরচনা sk_option **opts = রিক্ত;
	size_t nopts = 0;
	পূর্ণাঙ্ক r, ret = SSH_ERR_INTERNAL_ERROR;

	যদি (device != রিক্ত &&
	    (r = sshsk_add_option(&opts, &nopts, "device", device, 0)) != 0) {
		ret = r;
		গচ্ছ out;
	}
	যদি (user_id != রিক্ত &&
	    (r = sshsk_add_option(&opts, &nopts, "user", user_id, 0)) != 0) {
		ret = r;
		গচ্ছ out;
	}
	/* success */
	*optsp = opts;
	opts = রিক্ত;
	nopts = 0;
	ret = 0;
 out:
	sshsk_free_options(opts);
	প্রত্যাগম ret;
}


স্থির পূর্ণাঙ্ক
fill_attestation_blob(ধ্রুব সংরচনা sk_enroll_response *resp,
    সংরচনা sshbuf *attest)
{
	পূর্ণাঙ্ক r;

	যদি (attest == রিক্ত)
		প্রত্যাগম 0; /* nothing to do */
	যদি ((r = sshbuf_put_cstring(attest, "ssh-sk-attest-v01")) != 0 ||
	    (r = sshbuf_put_string(attest,
	    resp->attestation_cert, resp->attestation_cert_len)) != 0 ||
	    (r = sshbuf_put_string(attest,
	    resp->signature, resp->signature_len)) != 0 ||
	    (r = sshbuf_put_string(attest,
	    resp->authdata, resp->authdata_len)) != 0 ||
	    (r = sshbuf_put_u32(attest, 0)) != 0 || /* resvd flags */
	    (r = sshbuf_put_string(attest, রিক্ত, 0)) != 0 /* resvd */) {
		error_fr(r, "compose");
		প্রত্যাগম r;
	}
	/* success */
	প্রত্যাগম 0;
}

পূর্ণাঙ্ক
sshsk_enroll(পূর্ণাঙ্ক type, ধ্রুব বর্ণ *provider_path, ধ্রুব বর্ণ *device,
    ধ্রুব বর্ণ *application, ধ্রুব বর্ণ *userid, uint8_t flags,
    ধ্রুব বর্ণ *pin, সংরচনা sshbuf *challenge_buf,
    সংরচনা sshkey **keyp, সংরচনা sshbuf *attest)
{
	সংরচনা sshsk_provider *skp = রিক্ত;
	সংরচনা sshkey *চাবি = রিক্ত;
	u_char randchall[32];
	ধ্রুব u_char *challenge;
	size_t challenge_len;
	সংরচনা sk_enroll_response *resp = রিক্ত;
	সংরচনা sk_option **opts = রিক্ত;
	পূর্ণাঙ্ক r = SSH_ERR_INTERNAL_ERROR;
	পূর্ণাঙ্ক alg;

	debug_f("provider \"%s\", device \"%s\", application \"%s\", "
	    "userid \"%s\", flags 0x%02x, challenge len %zu%s",
	    provider_path, device, application, userid, flags,
	    challenge_buf == রিক্ত ? 0 : sshbuf_len(challenge_buf),
	    (pin != রিক্ত && *pin != '\0') ? " with-pin" : "");

	*keyp = রিক্ত;
	যদি (attest)
		sshbuf_reset(attest);

	যদি ((r = make_options(device, userid, &opts)) != 0)
		গচ্ছ out;

	বিকল্প (type) {
#ifdef WITH_OPENSSL
	পক্ষ চাবি_ECDSA_SK:
		alg = SSH_SK_ECDSA;
		ভঙ্গ;
#endif /* WITH_OPENSSL */
	পক্ষ চাবি_ED25519_SK:
		alg = SSH_SK_ED25519;
		ভঙ্গ;
	স্বভাব:
		error_f("unsupported key type");
		r = SSH_ERR_INVALID_ARGUMENT;
		গচ্ছ out;
	}
	যদি (provider_path == রিক্ত) {
		error_f("missing provider");
		r = SSH_ERR_INVALID_ARGUMENT;
		গচ্ছ out;
	}
	যদি (application == রিক্ত || *application == '\0') {
		error_f("missing application");
		r = SSH_ERR_INVALID_ARGUMENT;
		গচ্ছ out;
	}
	যদি (challenge_buf == রিক্ত) {
		debug_f("using random challenge");
		arc4random_buf(randchall, পরিমাণ(randchall));
		challenge = randchall;
		challenge_len = পরিমাণ(randchall);
	} অন্যথা যদি (sshbuf_len(challenge_buf) == 0) {
		error("Missing enrollment challenge");
		r = SSH_ERR_INVALID_ARGUMENT;
		গচ্ছ out;
	} অন্যথা {
		challenge = sshbuf_ptr(challenge_buf);
		challenge_len = sshbuf_len(challenge_buf);
		debug3_f("using explicit challenge len=%zd", challenge_len);
	}
	যদি ((skp = sshsk_open(provider_path)) == রিক্ত) {
		r = SSH_ERR_INVALID_FORMAT; /* XXX sshsk_open return code? */
		গচ্ছ out;
	}
	/* XXX validate flags? */
	/* enroll key */
	যদি ((r = skp->sk_enroll(alg, challenge, challenge_len, application,
	    flags, pin, opts, &resp)) != 0) {
		debug_f("provider \"%s\" failure %d", provider_path, r);
		r = skerr_to_ssherr(r);
		গচ্ছ out;
	}

	যদি ((r = sshsk_চাবি_from_response(alg, application, resp->flags,
	    resp, &চাবি)) != 0)
		গচ্ছ out;

	/* Optionally fill in the attestation information */
	যদি ((r = fill_attestation_blob(resp, attest)) != 0)
		গচ্ছ out;

	/* success */
	*keyp = চাবি;
	চাবি = রিক্ত; /* transferred */
	r = 0;
 out:
	sshsk_free_options(opts);
	sshsk_free(skp);
	sshkey_free(চাবি);
	sshsk_free_enroll_response(resp);
	explicit_bzero(randchall, পরিমাণ(randchall));
	প্রত্যাগম r;
}

#ifdef WITH_OPENSSL
স্থির পূর্ণাঙ্ক
sshsk_ecdsa_sig(সংরচনা sk_sign_response *resp, সংরচনা sshbuf *sig)
{
	সংরচনা sshbuf *inner_sig = রিক্ত;
	পূর্ণাঙ্ক r = SSH_ERR_INTERNAL_ERROR;

	/* Check response validity */
	যদি (resp->sig_r == রিক্ত || resp->sig_s == রিক্ত) {
		error_f("sk_sign response invalid");
		r = SSH_ERR_INVALID_FORMAT;
		গচ্ছ out;
	}
	যদি ((inner_sig = sshbuf_new()) == রিক্ত) {
		r = SSH_ERR_ALLOC_FAIL;
		গচ্ছ out;
	}
	/* Prepare and append inner signature object */
	যদি ((r = sshbuf_put_bignum2_bytes(inner_sig,
	    resp->sig_r, resp->sig_r_len)) != 0 ||
	    (r = sshbuf_put_bignum2_bytes(inner_sig,
	    resp->sig_s, resp->sig_s_len)) != 0) {
		error_fr(r, "compose inner");
		গচ্ছ out;
	}
	যদি ((r = sshbuf_put_stringb(sig, inner_sig)) != 0 ||
	    (r = sshbuf_put_u8(sig, resp->flags)) != 0 ||
	    (r = sshbuf_put_u32(sig, resp->counter)) != 0) {
		error_fr(r, "compose");
		গচ্ছ out;
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
	প্রত্যাগম r;
}
#endif /* WITH_OPENSSL */

স্থির পূর্ণাঙ্ক
sshsk_ed25519_sig(সংরচনা sk_sign_response *resp, সংরচনা sshbuf *sig)
{
	পূর্ণাঙ্ক r = SSH_ERR_INTERNAL_ERROR;

	/* Check response validity */
	যদি (resp->sig_r == রিক্ত) {
		error_f("sk_sign response invalid");
		r = SSH_ERR_INVALID_FORMAT;
		গচ্ছ out;
	}
	যদি ((r = sshbuf_put_string(sig,
	    resp->sig_r, resp->sig_r_len)) != 0 ||
	    (r = sshbuf_put_u8(sig, resp->flags)) != 0 ||
	    (r = sshbuf_put_u32(sig, resp->counter)) != 0) {
		error_fr(r, "compose");
		গচ্ছ out;
	}
#ifdef DEBUG_SK
	fprintf(stderr, "%s: sig_r:\n", __func__);
	sshbuf_dump_data(resp->sig_r, resp->sig_r_len, stderr);
#endif
	r = 0;
 out:
	প্রত্যাগম r;
}

পূর্ণাঙ্ক
sshsk_sign(ধ্রুব বর্ণ *provider_path, সংরচনা sshkey *চাবি,
    u_char **sigp, size_t *lenp, ধ্রুব u_char *data, size_t datalen,
    u_int compat, ধ্রুব বর্ণ *pin)
{
	সংরচনা sshsk_provider *skp = রিক্ত;
	পূর্ণাঙ্ক r = SSH_ERR_INTERNAL_ERROR;
	পূর্ণাঙ্ক type, alg;
	সংরচনা sk_sign_response *resp = রিক্ত;
	সংরচনা sshbuf *inner_sig = রিক্ত, *sig = রিক্ত;
	সংরচনা sk_option **opts = রিক্ত;

	debug_f("provider \"%s\", key %s, flags 0x%02x%s",
	    provider_path, sshkey_type(চাবি), চাবি->sk_flags,
	    (pin != রিক্ত && *pin != '\0') ? " with-pin" : "");

	যদি (sigp != রিক্ত)
		*sigp = রিক্ত;
	যদি (lenp != রিক্ত)
		*lenp = 0;
	type = sshkey_type_plain(চাবি->type);
	বিকল্প (type) {
#ifdef WITH_OPENSSL
	পক্ষ চাবি_ECDSA_SK:
		alg = SSH_SK_ECDSA;
		ভঙ্গ;
#endif /* WITH_OPENSSL */
	পক্ষ চাবি_ED25519_SK:
		alg = SSH_SK_ED25519;
		ভঙ্গ;
	স্বভাব:
		প্রত্যাগম SSH_ERR_INVALID_ARGUMENT;
	}
	যদি (provider_path == রিক্ত ||
	    চাবি->sk_চাবি_handle == রিক্ত ||
	    চাবি->sk_application == রিক্ত || *চাবি->sk_application == '\0') {
		r = SSH_ERR_INVALID_ARGUMENT;
		গচ্ছ out;
	}
	যদি ((skp = sshsk_open(provider_path)) == রিক্ত) {
		r = SSH_ERR_INVALID_FORMAT; /* XXX sshsk_open return code? */
		গচ্ছ out;
	}
#ifdef DEBUG_SK
	fprintf(stderr, "%s: sk_flags = 0x%02x, sk_application = \"%s\"\n",
	    __func__, চাবি->sk_flags, চাবি->sk_application);
	fprintf(stderr, "%s: sk_key_handle:\n", __func__);
	sshbuf_dump(চাবি->sk_চাবি_handle, stderr);
#endif
	যদি ((r = skp->sk_sign(alg, data, datalen, চাবি->sk_application,
	    sshbuf_ptr(চাবি->sk_চাবি_handle), sshbuf_len(চাবি->sk_চাবি_handle),
	    চাবি->sk_flags, pin, opts, &resp)) != 0) {
		debug_f("sk_sign failed with code %d", r);
		r = skerr_to_ssherr(r);
		গচ্ছ out;
	}
	/* Assemble signature */
	যদি ((sig = sshbuf_new()) == রিক্ত) {
		r = SSH_ERR_ALLOC_FAIL;
		গচ্ছ out;
	}
	যদি ((r = sshbuf_put_cstring(sig, sshkey_ssh_name_plain(চাবি))) != 0) {
		error_fr(r, "compose outer");
		গচ্ছ out;
	}
	বিকল্প (type) {
#ifdef WITH_OPENSSL
	পক্ষ চাবি_ECDSA_SK:
		যদি ((r = sshsk_ecdsa_sig(resp, sig)) != 0)
			গচ্ছ out;
		ভঙ্গ;
#endif /* WITH_OPENSSL */
	পক্ষ চাবি_ED25519_SK:
		যদি ((r = sshsk_ed25519_sig(resp, sig)) != 0)
			গচ্ছ out;
		ভঙ্গ;
	}
#ifdef DEBUG_SK
	fprintf(stderr, "%s: sig_flags = 0x%02x, sig_counter = %u\n",
	    __func__, resp->flags, resp->counter);
	fprintf(stderr, "%s: data to sign:\n", __func__);
	sshbuf_dump_data(data, datalen, stderr);
	fprintf(stderr, "%s: sigbuf:\n", __func__);
	sshbuf_dump(sig, stderr);
#endif
	যদি (sigp != রিক্ত) {
		যদি ((*sigp = malloc(sshbuf_len(sig))) == রিক্ত) {
			r = SSH_ERR_ALLOC_FAIL;
			গচ্ছ out;
		}
		memcpy(*sigp, sshbuf_ptr(sig), sshbuf_len(sig));
	}
	যদি (lenp != রিক্ত)
		*lenp = sshbuf_len(sig);
	/* success */
	r = 0;
 out:
	sshsk_free_options(opts);
	sshsk_free(skp);
	sshsk_free_sign_response(resp);
	sshbuf_free(sig);
	sshbuf_free(inner_sig);
	প্রত্যাগম r;
}

স্থির শূন্য
sshsk_free_sk_resident_চাবিগুলি(সংরচনা sk_resident_চাবি **rks, size_t nrks)
{
	size_t i;

	যদি (nrks == 0 || rks == রিক্ত)
		প্রত্যাগম;
	প্রতি (i = 0; i < nrks; i++) {
		মুক্ত(rks[i]->application);
		freezero(rks[i]->user_id, rks[i]->user_id_len);
		freezero(rks[i]->চাবি.চাবি_handle, rks[i]->চাবি.চাবি_handle_len);
		freezero(rks[i]->চাবি.public_চাবি, rks[i]->চাবি.public_চাবি_len);
		freezero(rks[i]->চাবি.signature, rks[i]->চাবি.signature_len);
		freezero(rks[i]->চাবি.attestation_cert,
		    rks[i]->চাবি.attestation_cert_len);
		freezero(rks[i], পরিমাণ(**rks));
	}
	মুক্ত(rks);
}

স্থির শূন্য
sshsk_free_resident_চাবি(সংরচনা sshsk_resident_চাবি *srk)
{
	যদি (srk == রিক্ত)
		প্রত্যাগম;
	sshkey_free(srk->চাবি);
	freezero(srk->user_id, srk->user_id_len);
	মুক্ত(srk);
}


শূন্য
sshsk_free_resident_চাবিগুলি(সংরচনা sshsk_resident_চাবি **srks, size_t nsrks)
{
	size_t i;

	যদি (srks == রিক্ত || nsrks == 0)
		প্রত্যাগম;

	প্রতি (i = 0; i < nsrks; i++)
		sshsk_free_resident_চাবি(srks[i]);
	মুক্ত(srks);
}

পূর্ণাঙ্ক
sshsk_load_resident(ধ্রুব বর্ণ *provider_path, ধ্রুব বর্ণ *device,
    ধ্রুব বর্ণ *pin, u_int flags, সংরচনা sshsk_resident_চাবি ***srksp,
    size_t *nsrksp)
{
	সংরচনা sshsk_provider *skp = রিক্ত;
	পূর্ণাঙ্ক r = SSH_ERR_INTERNAL_ERROR;
	সংরচনা sk_resident_চাবি **rks = রিক্ত;
	size_t i, nrks = 0, nsrks = 0;
	সংরচনা sshkey *চাবি = রিক্ত;
	সংরচনা sshsk_resident_চাবি *srk = রিক্ত, **srks = রিক্ত, **tmp;
	uint8_t sk_flags;
	সংরচনা sk_option **opts = রিক্ত;

	debug_f("provider \"%s\"%s", provider_path,
	    (pin != রিক্ত && *pin != '\0') ? ", have-pin": "");

	যদি (srksp == রিক্ত || nsrksp == রিক্ত)
		প্রত্যাগম SSH_ERR_INVALID_ARGUMENT;
	*srksp = রিক্ত;
	*nsrksp = 0;

	যদি ((r = make_options(device, রিক্ত, &opts)) != 0)
		গচ্ছ out;
	যদি ((skp = sshsk_open(provider_path)) == রিক্ত) {
		r = SSH_ERR_INVALID_FORMAT; /* XXX sshsk_open return code? */
		গচ্ছ out;
	}
	যদি ((r = skp->sk_load_resident_চাবিগুলি(pin, opts, &rks, &nrks)) != 0) {
		error("Provider \"%s\" returned failure %d", provider_path, r);
		r = skerr_to_ssherr(r);
		গচ্ছ out;
	}
	প্রতি (i = 0; i < nrks; i++) {
		debug3_f("rk %zu: slot %zu, alg %d, app \"%s\", uidlen %zu",
		    i, rks[i]->slot, rks[i]->alg, rks[i]->application,
		    rks[i]->user_id_len);
		/* XXX need better filter here */
		যদি (strncmp(rks[i]->application, "ssh:", 4) != 0)
			অনুবর্ত;
		বিকল্প (rks[i]->alg) {
		পক্ষ SSH_SK_ECDSA:
		পক্ষ SSH_SK_ED25519:
			ভঙ্গ;
		স্বভাব:
			অনুবর্ত;
		}
		sk_flags = SSH_SK_USER_PRESENCE_REQD|SSH_SK_RESIDENT_চাবি;
		যদি ((rks[i]->flags & SSH_SK_USER_VERIFICATION_REQD))
			sk_flags |= SSH_SK_USER_VERIFICATION_REQD;
		যদি ((r = sshsk_চাবি_from_response(rks[i]->alg,
		    rks[i]->application, sk_flags, &rks[i]->চাবি, &চাবি)) != 0)
			গচ্ছ out;
		যদি ((srk = calloc(1, পরিমাণ(*srk))) == রিক্ত) {
			error_f("calloc failed");
			r = SSH_ERR_ALLOC_FAIL;
			গচ্ছ out;
		}
		srk->চাবি = চাবি;
		চাবি = রিক্ত; /* transferred */
		যদি ((srk->user_id = calloc(1, rks[i]->user_id_len)) == রিক্ত) {
			error_f("calloc failed");
			r = SSH_ERR_ALLOC_FAIL;
			গচ্ছ out;
		}
		memcpy(srk->user_id, rks[i]->user_id, rks[i]->user_id_len);
		srk->user_id_len = rks[i]->user_id_len;
		যদি ((tmp = recallocarray(srks, nsrks, nsrks + 1,
		    পরিমাণ(*tmp))) == রিক্ত) {
			error_f("recallocarray failed");
			r = SSH_ERR_ALLOC_FAIL;
			গচ্ছ out;
		}
		srks = tmp;
		srks[nsrks++] = srk;
		srk = রিক্ত;
		/* XXX synthesise comment */
	}
	/* success */
	*srksp = srks;
	*nsrksp = nsrks;
	srks = রিক্ত;
	nsrks = 0;
	r = 0;
 out:
	sshsk_free_options(opts);
	sshsk_free(skp);
	sshsk_free_sk_resident_চাবিগুলি(rks, nrks);
	sshkey_free(চাবি);
	sshsk_free_resident_চাবি(srk);
	sshsk_free_resident_চাবিগুলি(srks, nsrks);
	প্রত্যাগম r;
}

#endif /* ENABLE_SK */
