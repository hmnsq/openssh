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

#جے_تعریف_شدہ ENABLE_SK

#ضمن <dlfcn.h>
#ضمن <stddef.h>
#ضمن <stdint.h>
#ضمن <string.h>
#ضمن <stdio.h>

#جے_تعریف_شدہ WITH_OPENSSL
#ضمن <openssl/objects.h>
#ضمن <openssl/ec.h>
#ضمن <openssl/evp.h>
#جے_انت /* WITH_OPENSSL */

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
	حرف *رستہ;
	فراغ *dlhandle;

	/* Return the version of the middleware API */
	uint32_t (*sk_api_نسخہ)(فراغ);

	/* Enroll a U2F key (private key generation) */
	صحيح (*sk_enroll)(صحيح alg, ثابت uint8_t *challenge,
	    ناپ_t challenge_len, ثابت حرف *application, uint8_t flags,
	    ثابت حرف *pin, بنية sk_option **opts,
	    بنية sk_enroll_response **enroll_response);

	/* Sign a challenge */
	صحيح (*sk_sign)(صحيح alg, ثابت uint8_t *سنیہا, ناپ_t سنیہا_len,
	    ثابت حرف *application,
	    ثابت uint8_t *کلید_handle, ناپ_t کلید_handle_len,
	    uint8_t flags, ثابت حرف *pin, بنية sk_option **opts,
	    بنية sk_sign_response **sign_response);

	/* Enumerate resident keys */
	صحيح (*sk_لدو_resident_کلیدیں)(ثابت حرف *pin, بنية sk_option **opts,
	    بنية sk_resident_کلید ***rks, ناپ_t *nrks);
};

/* Built-in version */
صحيح ssh_sk_enroll(صحيح alg, ثابت uint8_t *challenge,
    ناپ_t challenge_len, ثابت حرف *application, uint8_t flags,
    ثابت حرف *pin, بنية sk_option **opts,
    بنية sk_enroll_response **enroll_response);
صحيح ssh_sk_sign(صحيح alg, ثابت uint8_t *سنیہا, ناپ_t سنیہا_len,
    ثابت حرف *application,
    ثابت uint8_t *کلید_handle, ناپ_t کلید_handle_len,
    uint8_t flags, ثابت حرف *pin, بنية sk_option **opts,
    بنية sk_sign_response **sign_response);
صحيح ssh_sk_لدو_resident_کلیدیں(ثابت حرف *pin, بنية sk_option **opts,
    بنية sk_resident_کلید ***rks, ناپ_t *nrks);

ساكن فراغ
sshsk_free(بنية sshsk_provider *p)
{
	إذا (p == عدم)
		أرجع;
	حرر(p->رستہ);
	إذا (p->dlhandle != عدم)
		dlclose(p->dlhandle);
	حرر(p);
}

ساكن بنية sshsk_provider *
sshsk_open(ثابت حرف *رستہ)
{
	بنية sshsk_provider *ret = عدم;
	uint32_t نسخہ;

	إذا (رستہ == عدم || *رستہ == '\0') {
		error("No FIDO SecurityKeyProvider specified");
		أرجع عدم;
	}
	إذا ((ret = صفر_حافظہ_دیو(1, حجم(*ret))) == عدم) {
		error_f("calloc failed");
		أرجع عدم;
	}
	إذا ((ret->رستہ = strdup(رستہ)) == عدم) {
		error_f("strdup failed");
		اذهب fail;
	}
	/* Skip the rest if we're using the linked in middleware */
	إذا (strcasecmp(ret->رستہ, "internal") == 0) {
#جے_تعریف_شدہ ENABLE_SK_اندرونی
		ret->sk_enroll = ssh_sk_enroll;
		ret->sk_sign = ssh_sk_sign;
		ret->sk_لدو_resident_کلیدیں = ssh_sk_لدو_resident_کلیدیں;
		أرجع ret;
#وإلا
		error("internal security key support not enabled");
		اذهب fail;
#جے_انت
	}
	إذا (lib_شامل_اے_علامت(رستہ, "sk_api_version") != 0) {
		error("provider %s is not an OpenSSH FIDO library", رستہ);
		اذهب fail;
	}
	إذا ((ret->dlhandle = dlopen(رستہ, RTLD_NOW)) == عدم)
		fatal("Provider \"%s\" dlopen failed: %s", رستہ, dlerror());
	إذا ((ret->sk_api_نسخہ = dlsym(ret->dlhandle,
	    "sk_api_version")) == عدم) {
		error("Provider \"%s\" dlsym(sk_api_version) failed: %s",
		    رستہ, dlerror());
		اذهب fail;
	}
	نسخہ = ret->sk_api_نسخہ();
	debug_f("provider %s implements version 0x%08lx", ret->رستہ,
	    (u_long)نسخہ);
	إذا ((نسخہ & SSH_SK_نسخہ_MAJOR_نقاب) != SSH_SK_نسخہ_MAJOR) {
		error("Provider \"%s\" implements unsupported "
		    "version 0x%08lx (supported: 0x%08lx)",
		    رستہ, (u_long)نسخہ, (u_long)SSH_SK_نسخہ_MAJOR);
		اذهب fail;
	}
	إذا ((ret->sk_enroll = dlsym(ret->dlhandle, "sk_enroll")) == عدم) {
		error("Provider %s dlsym(sk_enroll) failed: %s",
		    رستہ, dlerror());
		اذهب fail;
	}
	إذا ((ret->sk_sign = dlsym(ret->dlhandle, "sk_sign")) == عدم) {
		error("Provider \"%s\" dlsym(sk_sign) failed: %s",
		    رستہ, dlerror());
		اذهب fail;
	}
	إذا ((ret->sk_لدو_resident_کلیدیں = dlsym(ret->dlhandle,
	    "sk_load_resident_keys")) == عدم) {
		error("Provider \"%s\" dlsym(sk_load_resident_keys) "
		    "failed: %s", رستہ, dlerror());
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
	freezero(r->کلید_handle, r->کلید_handle_len);
	freezero(r->عوامی_کلید, r->عوامی_کلید_len);
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

#جے_تعریف_شدہ WITH_OPENSSL
/* Assemble key from response */
ساكن صحيح
sshsk_ecdsa_assemble(بنية sk_enroll_response *resp, بنية sshkey **keyp)
{
	بنية sshkey *کلید = عدم;
	بنية sshbuf *b = عدم;
	EC_کلید *ecdsa = عدم;
	EC_نقطہ *q = عدم;
	ثابت EC_گروہ *g = عدم;
	صحيح r;

	*keyp = عدم;
	إذا ((کلید = sshkey_new(کلید_ECDSA_SK)) == عدم) {
		error_f("sshkey_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		اذهب باہرلا;
	}
	کلید->ecdsa_nid = NID_X9_62_prime256v1;
	إذا ((ecdsa = EC_کلید_new_by_ونگ_name(کلید->ecdsa_nid)) == عدم ||
	    (g = EC_کلید_get0_گروہ(ecdsa)) == عدم ||
	    (q = EC_نقطہ_new(g)) == عدم ||
	    (b = sshbuf_new()) == عدم) {
		error_f("allocation failed");
		r = SSH_ERR_ALLOC_FAIL;
		اذهب باہرلا;
	}
	إذا ((r = sshbuf_put_string(b,
	    resp->عوامی_کلید, resp->عوامی_کلید_len)) != 0) {
		error_fr(r, "sshbuf_put_string");
		اذهب باہرلا;
	}
	إذا ((r = sshbuf_get_ec(b, q, g)) != 0) {
		error_fr(r, "parse");
		r = SSH_ERR_INVALID_FORMAT;
		اذهب باہرلا;
	}
	إذا (sshkey_ec_validate_عوامی(g, q) != 0) {
		error("Authenticator returned invalid ECDSA key");
		r = SSH_ERR_کلید_INVALID_EC_قدر;
		اذهب باہرلا;
	}
	إذا (EC_کلید_سیٹ_عوامی_کلید(ecdsa, q) != 1) {
		/* XXX assume it is a allocation error */
		error_f("allocation failed");
		r = SSH_ERR_ALLOC_FAIL;
		اذهب باہرلا;
	}
	إذا ((کلید->pkey = EVP_PKEY_new()) == عدم) {
		error_f("allocation failed");
		r = SSH_ERR_ALLOC_FAIL;
		اذهب باہرلا;
	}
	إذا (EVP_PKEY_set1_EC_کلید(کلید->pkey, ecdsa) != 1) {
		error_f("Assigning EC_KEY failed");
		r = SSH_ERR_LIBCRYPTO_ERROR;
		اذهب باہرلا;
	}
	/* success */
	*keyp = کلید;
	کلید = عدم; /* transferred */
	r = 0;
 باہرلا:
	sshkey_free(کلید);
	sshbuf_free(b);
	EC_کلید_free(ecdsa);
	EC_نقطہ_free(q);
	أرجع r;
}
#جے_انت /* WITH_OPENSSL */

ساكن صحيح
sshsk_ed25519_assemble(بنية sk_enroll_response *resp, بنية sshkey **keyp)
{
	بنية sshkey *کلید = عدم;
	صحيح r;

	*keyp = عدم;
	إذا (resp->عوامی_کلید_len != ED25519_PK_SZ) {
		error_f("invalid size: %zu", resp->عوامی_کلید_len);
		r = SSH_ERR_INVALID_FORMAT;
		اذهب باہرلا;
	}
	إذا ((کلید = sshkey_new(کلید_ED25519_SK)) == عدم) {
		error_f("sshkey_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		اذهب باہرلا;
	}
	إذا ((کلید->ed25519_pk = حافظہ_دیو(ED25519_PK_SZ)) == عدم) {
		error_f("malloc failed");
		r = SSH_ERR_ALLOC_FAIL;
		اذهب باہرلا;
	}
	حافظہ_نقل(کلید->ed25519_pk, resp->عوامی_کلید, ED25519_PK_SZ);
	/* success */
	*keyp = کلید;
	کلید = عدم; /* transferred */
	r = 0;
 باہرلا:
	sshkey_free(کلید);
	أرجع r;
}

ساكن صحيح
sshsk_کلید_from_response(صحيح alg, ثابت حرف *application, uint8_t flags,
    بنية sk_enroll_response *resp, بنية sshkey **keyp)
{
	بنية sshkey *کلید = عدم;
	صحيح r = SSH_ERR_اندرونی_ERROR;

	*keyp = عدم;

	/* Check response validity */
	إذا (resp->عوامی_کلید == عدم || resp->کلید_handle == عدم) {
		error_f("sk_enroll response invalid");
		r = SSH_ERR_INVALID_FORMAT;
		اذهب باہرلا;
	}
	بدل (alg) {
#جے_تعریف_شدہ WITH_OPENSSL
	حالة SSH_SK_ECDSA:
		إذا ((r = sshsk_ecdsa_assemble(resp, &کلید)) != 0)
			اذهب باہرلا;
		اكسر;
#جے_انت /* WITH_OPENSSL */
	حالة SSH_SK_ED25519:
		إذا ((r = sshsk_ed25519_assemble(resp, &کلید)) != 0)
			اذهب باہرلا;
		اكسر;
	افتراضي:
		error_f("unsupported algorithm %d", alg);
		r = SSH_ERR_INVALID_دلیل;
		اذهب باہرلا;
	}
	کلید->sk_flags = flags;
	إذا ((کلید->sk_کلید_handle = sshbuf_new()) == عدم ||
	    (کلید->sk_reserved = sshbuf_new()) == عدم) {
		error_f("allocation failed");
		r = SSH_ERR_ALLOC_FAIL;
		اذهب باہرلا;
	}
	إذا ((کلید->sk_application = strdup(application)) == عدم) {
		error_f("strdup application failed");
		r = SSH_ERR_ALLOC_FAIL;
		اذهب باہرلا;
	}
	إذا ((r = sshbuf_put(کلید->sk_کلید_handle, resp->کلید_handle,
	    resp->کلید_handle_len)) != 0) {
		error_fr(r, "put key handle");
		اذهب باہرلا;
	}
	/* success */
	r = 0;
	*keyp = کلید;
	کلید = عدم;
 باہرلا:
	sshkey_free(کلید);
	أرجع r;
}

ساكن صحيح
skerr_منزل_ssherr(صحيح skerr)
{
	بدل (skerr) {
	حالة SSH_SK_ERR_UNSUPPORTED:
		أرجع SSH_ERR_FEATURE_UNSUPPORTED;
	حالة SSH_SK_ERR_PIN_REQUIRED:
		أرجع SSH_ERR_کلید_WRONG_PASSPHRASE;
	حالة SSH_SK_ERR_DEVICE_NOT_لبھیا:
		أرجع SSH_ERR_DEVICE_NOT_لبھیا;
	حالة SSH_SK_ERR_CREDENTIAL_EXISTS:
		أرجع SSH_ERR_کلید_BAD_PERMISSIONS;
	حالة SSH_SK_ERR_GENERAL:
	افتراضي:
		أرجع SSH_ERR_INVALID_FORMAT;
	}
}

ساكن فراغ
sshsk_free_options(بنية sk_option **opts)
{
	ناپ_t i;

	إذا (opts == عدم)
		أرجع;
	لكل (i = 0; opts[i] != عدم; i++) {
		حرر(opts[i]->name);
		حرر(opts[i]->قدر);
		حرر(opts[i]);
	}
	حرر(opts);
}

ساكن صحيح
sshsk_جوڑو_option(بنية sk_option ***optsp, ناپ_t *noptsp,
    ثابت حرف *name, ثابت حرف *قدر, uint8_t required)
{
	بنية sk_option **opts = *optsp;
	ناپ_t nopts = *noptsp;

	إذا ((opts = recallocarray(opts, nopts, nopts + 2, /* extra for NULL */
	    حجم(*opts))) == عدم) {
		error_f("array alloc failed");
		أرجع SSH_ERR_ALLOC_FAIL;
	}
	*optsp = opts;
	*noptsp = nopts + 1;
	إذا ((opts[nopts] = صفر_حافظہ_دیو(1, حجم(**opts))) == عدم) {
		error_f("alloc failed");
		أرجع SSH_ERR_ALLOC_FAIL;
	}
	إذا ((opts[nopts]->name = strdup(name)) == عدم ||
	    (opts[nopts]->قدر = strdup(قدر)) == عدم) {
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
	ناپ_t nopts = 0;
	صحيح r, ret = SSH_ERR_اندرونی_ERROR;

	إذا (device != عدم &&
	    (r = sshsk_جوڑو_option(&opts, &nopts, "device", device, 0)) != 0) {
		ret = r;
		اذهب باہرلا;
	}
	إذا (user_id != عدم &&
	    (r = sshsk_جوڑو_option(&opts, &nopts, "user", user_id, 0)) != 0) {
		ret = r;
		اذهب باہرلا;
	}
	/* success */
	*optsp = opts;
	opts = عدم;
	nopts = 0;
	ret = 0;
 باہرلا:
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
sshsk_enroll(صحيح type, ثابت حرف *provider_رستہ, ثابت حرف *device,
    ثابت حرف *application, ثابت حرف *userid, uint8_t flags,
    ثابت حرف *pin, بنية sshbuf *challenge_buf,
    بنية sshkey **keyp, بنية sshbuf *attest)
{
	بنية sshsk_provider *skp = عدم;
	بنية sshkey *کلید = عدم;
	u_char randchall[32];
	ثابت u_char *challenge;
	ناپ_t challenge_len;
	بنية sk_enroll_response *resp = عدم;
	بنية sk_option **opts = عدم;
	صحيح r = SSH_ERR_اندرونی_ERROR;
	صحيح alg;

	debug_f("provider \"%s\", device \"%s\", application \"%s\", "
	    "userid \"%s\", flags 0x%02x, challenge len %zu%s",
	    provider_رستہ, device, application, userid, flags,
	    challenge_buf == عدم ? 0 : sshbuf_len(challenge_buf),
	    (pin != عدم && *pin != '\0') ? " with-pin" : "");

	*keyp = عدم;
	إذا (attest)
		sshbuf_reset(attest);

	إذا ((r = make_options(device, userid, &opts)) != 0)
		اذهب باہرلا;

	بدل (type) {
#جے_تعریف_شدہ WITH_OPENSSL
	حالة کلید_ECDSA_SK:
		alg = SSH_SK_ECDSA;
		اكسر;
#جے_انت /* WITH_OPENSSL */
	حالة کلید_ED25519_SK:
		alg = SSH_SK_ED25519;
		اكسر;
	افتراضي:
		error_f("unsupported key type");
		r = SSH_ERR_INVALID_دلیل;
		اذهب باہرلا;
	}
	إذا (provider_رستہ == عدم) {
		error_f("missing provider");
		r = SSH_ERR_INVALID_دلیل;
		اذهب باہرلا;
	}
	إذا (application == عدم || *application == '\0') {
		error_f("missing application");
		r = SSH_ERR_INVALID_دلیل;
		اذهب باہرلا;
	}
	إذا (challenge_buf == عدم) {
		debug_f("using random challenge");
		arc4random_buf(randchall, حجم(randchall));
		challenge = randchall;
		challenge_len = حجم(randchall);
	} وإلا إذا (sshbuf_len(challenge_buf) == 0) {
		error("Missing enrollment challenge");
		r = SSH_ERR_INVALID_دلیل;
		اذهب باہرلا;
	} وإلا {
		challenge = sshbuf_ptr(challenge_buf);
		challenge_len = sshbuf_len(challenge_buf);
		debug3_f("using explicit challenge len=%zd", challenge_len);
	}
	إذا ((skp = sshsk_open(provider_رستہ)) == عدم) {
		r = SSH_ERR_INVALID_FORMAT; /* XXX sshsk_open return code? */
		اذهب باہرلا;
	}
	/* XXX validate flags? */
	/* enroll key */
	إذا ((r = skp->sk_enroll(alg, challenge, challenge_len, application,
	    flags, pin, opts, &resp)) != 0) {
		debug_f("provider \"%s\" failure %d", provider_رستہ, r);
		r = skerr_منزل_ssherr(r);
		اذهب باہرلا;
	}

	إذا ((r = sshsk_کلید_from_response(alg, application, resp->flags,
	    resp, &کلید)) != 0)
		اذهب باہرلا;

	/* Optionally fill in the attestation information */
	إذا ((r = fill_attestation_blob(resp, attest)) != 0)
		اذهب باہرلا;

	/* success */
	*keyp = کلید;
	کلید = عدم; /* transferred */
	r = 0;
 باہرلا:
	sshsk_free_options(opts);
	sshsk_free(skp);
	sshkey_free(کلید);
	sshsk_free_enroll_response(resp);
	explicit_bzero(randchall, حجم(randchall));
	أرجع r;
}

#جے_تعریف_شدہ WITH_OPENSSL
ساكن صحيح
sshsk_ecdsa_sig(بنية sk_sign_response *resp, بنية sshbuf *sig)
{
	بنية sshbuf *inner_sig = عدم;
	صحيح r = SSH_ERR_اندرونی_ERROR;

	/* Check response validity */
	إذا (resp->sig_r == عدم || resp->sig_s == عدم) {
		error_f("sk_sign response invalid");
		r = SSH_ERR_INVALID_FORMAT;
		اذهب باہرلا;
	}
	إذا ((inner_sig = sshbuf_new()) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب باہرلا;
	}
	/* Prepare and append inner signature object */
	إذا ((r = sshbuf_put_bignum2_بائٹاں(inner_sig,
	    resp->sig_r, resp->sig_r_len)) != 0 ||
	    (r = sshbuf_put_bignum2_بائٹاں(inner_sig,
	    resp->sig_s, resp->sig_s_len)) != 0) {
		error_fr(r, "compose inner");
		اذهب باہرلا;
	}
	إذا ((r = sshbuf_put_stringb(sig, inner_sig)) != 0 ||
	    (r = sshbuf_put_u8(sig, resp->flags)) != 0 ||
	    (r = sshbuf_put_u32(sig, resp->counter)) != 0) {
		error_fr(r, "compose");
		اذهب باہرلا;
	}
#جے_تعریف_شدہ DEBUG_SK
	fprintf(stderr, "%s: sig_r:\n", __func__);
	sshbuf_dump_انکڑے(resp->sig_r, resp->sig_r_len, stderr);
	fprintf(stderr, "%s: sig_s:\n", __func__);
	sshbuf_dump_انکڑے(resp->sig_s, resp->sig_s_len, stderr);
	fprintf(stderr, "%s: inner:\n", __func__);
	sshbuf_dump(inner_sig, stderr);
#جے_انت
	r = 0;
 باہرلا:
	sshbuf_free(inner_sig);
	أرجع r;
}
#جے_انت /* WITH_OPENSSL */

ساكن صحيح
sshsk_ed25519_sig(بنية sk_sign_response *resp, بنية sshbuf *sig)
{
	صحيح r = SSH_ERR_اندرونی_ERROR;

	/* Check response validity */
	إذا (resp->sig_r == عدم) {
		error_f("sk_sign response invalid");
		r = SSH_ERR_INVALID_FORMAT;
		اذهب باہرلا;
	}
	إذا ((r = sshbuf_put_string(sig,
	    resp->sig_r, resp->sig_r_len)) != 0 ||
	    (r = sshbuf_put_u8(sig, resp->flags)) != 0 ||
	    (r = sshbuf_put_u32(sig, resp->counter)) != 0) {
		error_fr(r, "compose");
		اذهب باہرلا;
	}
#جے_تعریف_شدہ DEBUG_SK
	fprintf(stderr, "%s: sig_r:\n", __func__);
	sshbuf_dump_انکڑے(resp->sig_r, resp->sig_r_len, stderr);
#جے_انت
	r = 0;
 باہرلا:
	أرجع r;
}

صحيح
sshsk_sign(ثابت حرف *provider_رستہ, بنية sshkey *کلید,
    u_char **sigp, ناپ_t *lenp, ثابت u_char *انکڑے, ناپ_t datalen,
    u_int compat, ثابت حرف *pin)
{
	بنية sshsk_provider *skp = عدم;
	صحيح r = SSH_ERR_اندرونی_ERROR;
	صحيح type, alg;
	بنية sk_sign_response *resp = عدم;
	بنية sshbuf *inner_sig = عدم, *sig = عدم;
	بنية sk_option **opts = عدم;

	debug_f("provider \"%s\", key %s, flags 0x%02x%s",
	    provider_رستہ, sshkey_type(کلید), کلید->sk_flags,
	    (pin != عدم && *pin != '\0') ? " with-pin" : "");

	إذا (sigp != عدم)
		*sigp = عدم;
	إذا (lenp != عدم)
		*lenp = 0;
	type = sshkey_type_plain(کلید->type);
	بدل (type) {
#جے_تعریف_شدہ WITH_OPENSSL
	حالة کلید_ECDSA_SK:
		alg = SSH_SK_ECDSA;
		اكسر;
#جے_انت /* WITH_OPENSSL */
	حالة کلید_ED25519_SK:
		alg = SSH_SK_ED25519;
		اكسر;
	افتراضي:
		أرجع SSH_ERR_INVALID_دلیل;
	}
	إذا (provider_رستہ == عدم ||
	    کلید->sk_کلید_handle == عدم ||
	    کلید->sk_application == عدم || *کلید->sk_application == '\0') {
		r = SSH_ERR_INVALID_دلیل;
		اذهب باہرلا;
	}
	إذا ((skp = sshsk_open(provider_رستہ)) == عدم) {
		r = SSH_ERR_INVALID_FORMAT; /* XXX sshsk_open return code? */
		اذهب باہرلا;
	}
#جے_تعریف_شدہ DEBUG_SK
	fprintf(stderr, "%s: sk_flags = 0x%02x, sk_application = \"%s\"\n",
	    __func__, کلید->sk_flags, کلید->sk_application);
	fprintf(stderr, "%s: sk_key_handle:\n", __func__);
	sshbuf_dump(کلید->sk_کلید_handle, stderr);
#جے_انت
	إذا ((r = skp->sk_sign(alg, انکڑے, datalen, کلید->sk_application,
	    sshbuf_ptr(کلید->sk_کلید_handle), sshbuf_len(کلید->sk_کلید_handle),
	    کلید->sk_flags, pin, opts, &resp)) != 0) {
		debug_f("sk_sign failed with code %d", r);
		r = skerr_منزل_ssherr(r);
		اذهب باہرلا;
	}
	/* Assemble signature */
	إذا ((sig = sshbuf_new()) == عدم) {
		r = SSH_ERR_ALLOC_FAIL;
		اذهب باہرلا;
	}
	إذا ((r = sshbuf_put_cstring(sig, sshkey_ssh_name_plain(کلید))) != 0) {
		error_fr(r, "compose outer");
		اذهب باہرلا;
	}
	بدل (type) {
#جے_تعریف_شدہ WITH_OPENSSL
	حالة کلید_ECDSA_SK:
		إذا ((r = sshsk_ecdsa_sig(resp, sig)) != 0)
			اذهب باہرلا;
		اكسر;
#جے_انت /* WITH_OPENSSL */
	حالة کلید_ED25519_SK:
		إذا ((r = sshsk_ed25519_sig(resp, sig)) != 0)
			اذهب باہرلا;
		اكسر;
	}
#جے_تعریف_شدہ DEBUG_SK
	fprintf(stderr, "%s: sig_flags = 0x%02x, sig_counter = %u\n",
	    __func__, resp->flags, resp->counter);
	fprintf(stderr, "%s: data to sign:\n", __func__);
	sshbuf_dump_انکڑے(انکڑے, datalen, stderr);
	fprintf(stderr, "%s: sigbuf:\n", __func__);
	sshbuf_dump(sig, stderr);
#جے_انت
	إذا (sigp != عدم) {
		إذا ((*sigp = حافظہ_دیو(sshbuf_len(sig))) == عدم) {
			r = SSH_ERR_ALLOC_FAIL;
			اذهب باہرلا;
		}
		حافظہ_نقل(*sigp, sshbuf_ptr(sig), sshbuf_len(sig));
	}
	إذا (lenp != عدم)
		*lenp = sshbuf_len(sig);
	/* success */
	r = 0;
 باہرلا:
	sshsk_free_options(opts);
	sshsk_free(skp);
	sshsk_free_sign_response(resp);
	sshbuf_free(sig);
	sshbuf_free(inner_sig);
	أرجع r;
}

ساكن فراغ
sshsk_free_sk_resident_کلیدیں(بنية sk_resident_کلید **rks, ناپ_t nrks)
{
	ناپ_t i;

	إذا (nrks == 0 || rks == عدم)
		أرجع;
	لكل (i = 0; i < nrks; i++) {
		حرر(rks[i]->application);
		freezero(rks[i]->user_id, rks[i]->user_id_len);
		freezero(rks[i]->کلید.کلید_handle, rks[i]->کلید.کلید_handle_len);
		freezero(rks[i]->کلید.عوامی_کلید, rks[i]->کلید.عوامی_کلید_len);
		freezero(rks[i]->کلید.signature, rks[i]->کلید.signature_len);
		freezero(rks[i]->کلید.attestation_cert,
		    rks[i]->کلید.attestation_cert_len);
		freezero(rks[i], حجم(**rks));
	}
	حرر(rks);
}

ساكن فراغ
sshsk_free_resident_کلید(بنية sshsk_resident_کلید *srk)
{
	إذا (srk == عدم)
		أرجع;
	sshkey_free(srk->کلید);
	freezero(srk->user_id, srk->user_id_len);
	حرر(srk);
}


فراغ
sshsk_free_resident_کلیدیں(بنية sshsk_resident_کلید **srks, ناپ_t nsrks)
{
	ناپ_t i;

	إذا (srks == عدم || nsrks == 0)
		أرجع;

	لكل (i = 0; i < nsrks; i++)
		sshsk_free_resident_کلید(srks[i]);
	حرر(srks);
}

صحيح
sshsk_لدو_resident(ثابت حرف *provider_رستہ, ثابت حرف *device,
    ثابت حرف *pin, u_int flags, بنية sshsk_resident_کلید ***srksp,
    ناپ_t *nsrksp)
{
	بنية sshsk_provider *skp = عدم;
	صحيح r = SSH_ERR_اندرونی_ERROR;
	بنية sk_resident_کلید **rks = عدم;
	ناپ_t i, nrks = 0, nsrks = 0;
	بنية sshkey *کلید = عدم;
	بنية sshsk_resident_کلید *srk = عدم, **srks = عدم, **tmp;
	uint8_t sk_flags;
	بنية sk_option **opts = عدم;

	debug_f("provider \"%s\"%s", provider_رستہ,
	    (pin != عدم && *pin != '\0') ? ", have-pin": "");

	إذا (srksp == عدم || nsrksp == عدم)
		أرجع SSH_ERR_INVALID_دلیل;
	*srksp = عدم;
	*nsrksp = 0;

	إذا ((r = make_options(device, عدم, &opts)) != 0)
		اذهب باہرلا;
	إذا ((skp = sshsk_open(provider_رستہ)) == عدم) {
		r = SSH_ERR_INVALID_FORMAT; /* XXX sshsk_open return code? */
		اذهب باہرلا;
	}
	إذا ((r = skp->sk_لدو_resident_کلیدیں(pin, opts, &rks, &nrks)) != 0) {
		error("Provider \"%s\" returned failure %d", provider_رستہ, r);
		r = skerr_منزل_ssherr(r);
		اذهب باہرلا;
	}
	لكل (i = 0; i < nrks; i++) {
		debug3_f("rk %zu: slot %zu, alg %d, app \"%s\", uidlen %zu",
		    i, rks[i]->تھاں, rks[i]->alg, rks[i]->application,
		    rks[i]->user_id_len);
		/* XXX need better filter here */
		إذا (لڑی_مقابلہ(rks[i]->application, "ssh:", 4) != 0)
			استمر;
		بدل (rks[i]->alg) {
		حالة SSH_SK_ECDSA:
		حالة SSH_SK_ED25519:
			اكسر;
		افتراضي:
			استمر;
		}
		sk_flags = SSH_SK_USER_PRESENCE_REQD|SSH_SK_RESIDENT_کلید;
		إذا ((rks[i]->flags & SSH_SK_USER_VERIFICATION_REQD))
			sk_flags |= SSH_SK_USER_VERIFICATION_REQD;
		إذا ((r = sshsk_کلید_from_response(rks[i]->alg,
		    rks[i]->application, sk_flags, &rks[i]->کلید, &کلید)) != 0)
			اذهب باہرلا;
		إذا ((srk = صفر_حافظہ_دیو(1, حجم(*srk))) == عدم) {
			error_f("calloc failed");
			r = SSH_ERR_ALLOC_FAIL;
			اذهب باہرلا;
		}
		srk->کلید = کلید;
		کلید = عدم; /* transferred */
		إذا ((srk->user_id = صفر_حافظہ_دیو(1, rks[i]->user_id_len)) == عدم) {
			error_f("calloc failed");
			r = SSH_ERR_ALLOC_FAIL;
			اذهب باہرلا;
		}
		حافظہ_نقل(srk->user_id, rks[i]->user_id, rks[i]->user_id_len);
		srk->user_id_len = rks[i]->user_id_len;
		إذا ((tmp = recallocarray(srks, nsrks, nsrks + 1,
		    حجم(*tmp))) == عدم) {
			error_f("recallocarray failed");
			r = SSH_ERR_ALLOC_FAIL;
			اذهب باہرلا;
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
 باہرلا:
	sshsk_free_options(opts);
	sshsk_free(skp);
	sshsk_free_sk_resident_کلیدیں(rks, nrks);
	sshkey_free(کلید);
	sshsk_free_resident_کلید(srk);
	sshsk_free_resident_کلیدیں(srks, nsrks);
	أرجع r;
}

#جے_انت /* ENABLE_SK */
