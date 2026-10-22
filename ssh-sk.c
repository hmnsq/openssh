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

#اگر_تعریف_شدہ ENABLE_SK

#شامل <dlfcn.h>
#شامل <stddef.h>
#شامل <stdint.h>
#شامل <string.h>
#شامل <stdio.h>

#اگر_تعریف_شدہ WITH_OPENSSL
#شامل <openssl/objects.h>
#شامل <openssl/ec.h>
#شامل <openssl/evp.h>
#اگر_ختم /* WITH_OPENSSL */

#شامل "log.h"
#شامل "misc.h"
#شامل "sshbuf.h"
#شامل "sshkey.h"
#شامل "ssherr.h"
#شامل "digest.h"

#شامل "ssh-sk.h"
#شامل "sk-api.h"
#شامل "crypto_api.h"

ساخت sshsk_provider {
	حرف *راستہ;
	خالی *dlhandle;

	/* Return the version of the middleware API */
	uint32_t (*sk_api_نسخہ)(خالی);

	/* Enroll a U2F key (private key generation) */
	صحیح (*sk_enroll)(صحیح alg, ثابت uint8_t *challenge,
	    سائز_t challenge_len, ثابت حرف *application, uint8_t flags,
	    ثابت حرف *pin, ساخت sk_option **opts,
	    ساخت sk_enroll_response **enroll_response);

	/* Sign a challenge */
	صحیح (*sk_sign)(صحیح alg, ثابت uint8_t *پیغام_2, سائز_t پیغام_len_2,
	    ثابت حرف *application,
	    ثابت uint8_t *کلید_handle, سائز_t کلید_handle_len,
	    uint8_t flags, ثابت حرف *pin, ساخت sk_option **opts,
	    ساخت sk_sign_response **sign_response);

	/* Enumerate resident keys */
	صحیح (*sk_بھرو_resident_کلیدیں)(ثابت حرف *pin, ساخت sk_option **opts,
	    ساخت sk_resident_کلید ***rks, سائز_t *nrks);
};

/* Built-in version */
صحیح ssh_sk_enroll(صحیح alg, ثابت uint8_t *challenge,
    سائز_t challenge_len, ثابت حرف *application, uint8_t flags,
    ثابت حرف *pin, ساخت sk_option **opts,
    ساخت sk_enroll_response **enroll_response);
صحیح ssh_sk_sign(صحیح alg, ثابت uint8_t *پیغام_2, سائز_t پیغام_len_2,
    ثابت حرف *application,
    ثابت uint8_t *کلید_handle, سائز_t کلید_handle_len,
    uint8_t flags, ثابت حرف *pin, ساخت sk_option **opts,
    ساخت sk_sign_response **sign_response);
صحیح ssh_sk_بھرو_resident_کلیدیں(ثابت حرف *pin, ساخت sk_option **opts,
    ساخت sk_resident_کلید ***rks, سائز_t *nrks);

ساکن خالی
sshsk_free(ساخت sshsk_provider *p)
{
	اگر (p == تہی)
		واپس;
	آزاد(p->راستہ);
	اگر (p->dlhandle != تہی)
		dlclose(p->dlhandle);
	آزاد(p);
}

ساکن ساخت sshsk_provider *
sshsk_open(ثابت حرف *راستہ)
{
	ساخت sshsk_provider *ret = تہی;
	uint32_t نسخہ;

	اگر (راستہ == تہی || *راستہ == '\0') {
		error("No FIDO SecurityKeyProvider specified");
		واپس تہی;
	}
	اگر ((ret = صفر_حافظہ_دو(1, حجم(*ret))) == تہی) {
		error_f("calloc failed");
		واپس تہی;
	}
	اگر ((ret->راستہ = strdup(راستہ)) == تہی) {
		error_f("strdup failed");
		جاؤ fail;
	}
	/* Skip the rest if we're using the linked in middleware */
	اگر (strcasecmp(ret->راستہ, "internal") == 0) {
#اگر_تعریف_شدہ ENABLE_SK_اندرونی
		ret->sk_enroll = ssh_sk_enroll;
		ret->sk_sign = ssh_sk_sign;
		ret->sk_بھرو_resident_کلیدیں = ssh_sk_بھرو_resident_کلیدیں;
		واپس ret;
#ورنہ
		error("internal security key support not enabled");
		جاؤ fail;
#اگر_ختم
	}
	اگر (lib_شامل_ہے_علامت(راستہ, "sk_api_version") != 0) {
		error("provider %s is not an OpenSSH FIDO library", راستہ);
		جاؤ fail;
	}
	اگر ((ret->dlhandle = dlopen(راستہ, RTLD_NOW)) == تہی)
		fatal("Provider \"%s\" dlopen failed: %s", راستہ, dlerror());
	اگر ((ret->sk_api_نسخہ = dlsym(ret->dlhandle,
	    "sk_api_version")) == تہی) {
		error("Provider \"%s\" dlsym(sk_api_version) failed: %s",
		    راستہ, dlerror());
		جاؤ fail;
	}
	نسخہ = ret->sk_api_نسخہ();
	debug_f("provider %s implements version 0x%08lx", ret->راستہ,
	    (u_long)نسخہ);
	اگر ((نسخہ & SSH_SK_نسخہ_MAJOR_نقاب) != SSH_SK_نسخہ_MAJOR) {
		error("Provider \"%s\" implements unsupported "
		    "version 0x%08lx (supported: 0x%08lx)",
		    راستہ, (u_long)نسخہ, (u_long)SSH_SK_نسخہ_MAJOR);
		جاؤ fail;
	}
	اگر ((ret->sk_enroll = dlsym(ret->dlhandle, "sk_enroll")) == تہی) {
		error("Provider %s dlsym(sk_enroll) failed: %s",
		    راستہ, dlerror());
		جاؤ fail;
	}
	اگر ((ret->sk_sign = dlsym(ret->dlhandle, "sk_sign")) == تہی) {
		error("Provider \"%s\" dlsym(sk_sign) failed: %s",
		    راستہ, dlerror());
		جاؤ fail;
	}
	اگر ((ret->sk_بھرو_resident_کلیدیں = dlsym(ret->dlhandle,
	    "sk_load_resident_keys")) == تہی) {
		error("Provider \"%s\" dlsym(sk_load_resident_keys) "
		    "failed: %s", راستہ, dlerror());
		جاؤ fail;
	}
	/* success */
	واپس ret;
fail:
	sshsk_free(ret);
	واپس تہی;
}

ساکن خالی
sshsk_free_enroll_response(ساخت sk_enroll_response *r)
{
	اگر (r == تہی)
		واپس;
	freezero(r->کلید_handle, r->کلید_handle_len);
	freezero(r->عوامی_کلید, r->عوامی_کلید_len);
	freezero(r->signature, r->signature_len);
	freezero(r->attestation_cert, r->attestation_cert_len);
	freezero(r->authdata, r->authdata_len);
	freezero(r, حجم(*r));
}

ساکن خالی
sshsk_free_sign_response(ساخت sk_sign_response *r)
{
	اگر (r == تہی)
		واپس;
	freezero(r->sig_r, r->sig_r_len);
	freezero(r->sig_s, r->sig_s_len);
	freezero(r, حجم(*r));
}

#اگر_تعریف_شدہ WITH_OPENSSL
/* Assemble key from response */
ساکن صحیح
sshsk_ecdsa_assemble(ساخت sk_enroll_response *resp, ساخت sshkey **keyp)
{
	ساخت sshkey *کلید = تہی;
	ساخت sshbuf *b = تہی;
	EC_کلید *ecdsa = تہی;
	EC_نقطہ *q = تہی;
	ثابت EC_گروہ *g = تہی;
	صحیح r;

	*keyp = تہی;
	اگر ((کلید = sshkey_new(کلید_ECDSA_SK)) == تہی) {
		error_f("sshkey_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		جاؤ برآمد;
	}
	کلید->ecdsa_nid = NID_X9_62_prime256v1;
	اگر ((ecdsa = EC_کلید_new_by_خم_name(کلید->ecdsa_nid)) == تہی ||
	    (g = EC_کلید_get0_گروہ(ecdsa)) == تہی ||
	    (q = EC_نقطہ_new(g)) == تہی ||
	    (b = sshbuf_new()) == تہی) {
		error_f("allocation failed");
		r = SSH_ERR_ALLOC_FAIL;
		جاؤ برآمد;
	}
	اگر ((r = sshbuf_put_string(b,
	    resp->عوامی_کلید, resp->عوامی_کلید_len)) != 0) {
		error_fr(r, "sshbuf_put_string");
		جاؤ برآمد;
	}
	اگر ((r = sshbuf_get_ec(b, q, g)) != 0) {
		error_fr(r, "parse");
		r = SSH_ERR_INVALID_FORMAT;
		جاؤ برآمد;
	}
	اگر (sshkey_ec_validate_عوامی(g, q) != 0) {
		error("Authenticator returned invalid ECDSA key");
		r = SSH_ERR_کلید_INVALID_EC_قدر;
		جاؤ برآمد;
	}
	اگر (EC_کلید_سیٹ_عوامی_کلید(ecdsa, q) != 1) {
		/* XXX assume it is a allocation error */
		error_f("allocation failed");
		r = SSH_ERR_ALLOC_FAIL;
		جاؤ برآمد;
	}
	اگر ((کلید->pkey = EVP_PKEY_new()) == تہی) {
		error_f("allocation failed");
		r = SSH_ERR_ALLOC_FAIL;
		جاؤ برآمد;
	}
	اگر (EVP_PKEY_set1_EC_کلید(کلید->pkey, ecdsa) != 1) {
		error_f("Assigning EC_KEY failed");
		r = SSH_ERR_LIBCRYPTO_ERROR;
		جاؤ برآمد;
	}
	/* success */
	*keyp = کلید;
	کلید = تہی; /* transferred */
	r = 0;
 برآمد:
	sshkey_free(کلید);
	sshbuf_free(b);
	EC_کلید_free(ecdsa);
	EC_نقطہ_free(q);
	واپس r;
}
#اگر_ختم /* WITH_OPENSSL */

ساکن صحیح
sshsk_ed25519_assemble(ساخت sk_enroll_response *resp, ساخت sshkey **keyp)
{
	ساخت sshkey *کلید = تہی;
	صحیح r;

	*keyp = تہی;
	اگر (resp->عوامی_کلید_len != ED25519_PK_SZ) {
		error_f("invalid size: %zu", resp->عوامی_کلید_len);
		r = SSH_ERR_INVALID_FORMAT;
		جاؤ برآمد;
	}
	اگر ((کلید = sshkey_new(کلید_ED25519_SK)) == تہی) {
		error_f("sshkey_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		جاؤ برآمد;
	}
	اگر ((کلید->ed25519_pk = حافظہ_دو(ED25519_PK_SZ)) == تہی) {
		error_f("malloc failed");
		r = SSH_ERR_ALLOC_FAIL;
		جاؤ برآمد;
	}
	حافظہ_نقل(کلید->ed25519_pk, resp->عوامی_کلید, ED25519_PK_SZ);
	/* success */
	*keyp = کلید;
	کلید = تہی; /* transferred */
	r = 0;
 برآمد:
	sshkey_free(کلید);
	واپس r;
}

ساکن صحیح
sshsk_کلید_from_response(صحیح alg, ثابت حرف *application, uint8_t flags,
    ساخت sk_enroll_response *resp, ساخت sshkey **keyp)
{
	ساخت sshkey *کلید = تہی;
	صحیح r = SSH_ERR_اندرونی_ERROR;

	*keyp = تہی;

	/* Check response validity */
	اگر (resp->عوامی_کلید == تہی || resp->کلید_handle == تہی) {
		error_f("sk_enroll response invalid");
		r = SSH_ERR_INVALID_FORMAT;
		جاؤ برآمد;
	}
	انتخاب (alg) {
#اگر_تعریف_شدہ WITH_OPENSSL
	حالت SSH_SK_ECDSA:
		اگر ((r = sshsk_ecdsa_assemble(resp, &کلید)) != 0)
			جاؤ برآمد;
		توڑو;
#اگر_ختم /* WITH_OPENSSL */
	حالت SSH_SK_ED25519:
		اگر ((r = sshsk_ed25519_assemble(resp, &کلید)) != 0)
			جاؤ برآمد;
		توڑو;
	طےشدہ:
		error_f("unsupported algorithm %d", alg);
		r = SSH_ERR_INVALID_دلیل;
		جاؤ برآمد;
	}
	کلید->sk_flags = flags;
	اگر ((کلید->sk_کلید_handle = sshbuf_new()) == تہی ||
	    (کلید->sk_reserved = sshbuf_new()) == تہی) {
		error_f("allocation failed");
		r = SSH_ERR_ALLOC_FAIL;
		جاؤ برآمد;
	}
	اگر ((کلید->sk_application = strdup(application)) == تہی) {
		error_f("strdup application failed");
		r = SSH_ERR_ALLOC_FAIL;
		جاؤ برآمد;
	}
	اگر ((r = sshbuf_put(کلید->sk_کلید_handle, resp->کلید_handle,
	    resp->کلید_handle_len)) != 0) {
		error_fr(r, "put key handle");
		جاؤ برآمد;
	}
	/* success */
	r = 0;
	*keyp = کلید;
	کلید = تہی;
 برآمد:
	sshkey_free(کلید);
	واپس r;
}

ساکن صحیح
skerr_مقصد_ssherr(صحیح skerr)
{
	انتخاب (skerr) {
	حالت SSH_SK_ERR_UNSUPPORTED:
		واپس SSH_ERR_FEATURE_UNSUPPORTED;
	حالت SSH_SK_ERR_PIN_REQUIRED:
		واپس SSH_ERR_کلید_WRONG_PASSPHRASE;
	حالت SSH_SK_ERR_DEVICE_NOT_ملا:
		واپس SSH_ERR_DEVICE_NOT_ملا;
	حالت SSH_SK_ERR_CREDENTIAL_EXISTS:
		واپس SSH_ERR_کلید_BAD_PERMISSIONS;
	حالت SSH_SK_ERR_GENERAL:
	طےشدہ:
		واپس SSH_ERR_INVALID_FORMAT;
	}
}

ساکن خالی
sshsk_free_options(ساخت sk_option **opts)
{
	سائز_t i;

	اگر (opts == تہی)
		واپس;
	برائے (i = 0; opts[i] != تہی; i++) {
		آزاد(opts[i]->name);
		آزاد(opts[i]->قدر);
		آزاد(opts[i]);
	}
	آزاد(opts);
}

ساکن صحیح
sshsk_جوڑو_option(ساخت sk_option ***optsp, سائز_t *noptsp,
    ثابت حرف *name, ثابت حرف *قدر, uint8_t required)
{
	ساخت sk_option **opts = *optsp;
	سائز_t nopts = *noptsp;

	اگر ((opts = recallocarray(opts, nopts, nopts + 2, /* extra for NULL */
	    حجم(*opts))) == تہی) {
		error_f("array alloc failed");
		واپس SSH_ERR_ALLOC_FAIL;
	}
	*optsp = opts;
	*noptsp = nopts + 1;
	اگر ((opts[nopts] = صفر_حافظہ_دو(1, حجم(**opts))) == تہی) {
		error_f("alloc failed");
		واپس SSH_ERR_ALLOC_FAIL;
	}
	اگر ((opts[nopts]->name = strdup(name)) == تہی ||
	    (opts[nopts]->قدر = strdup(قدر)) == تہی) {
		error_f("alloc failed");
		واپس SSH_ERR_ALLOC_FAIL;
	}
	opts[nopts]->required = required;
	واپس 0;
}

ساکن صحیح
make_options(ثابت حرف *device, ثابت حرف *user_id,
    ساخت sk_option ***optsp)
{
	ساخت sk_option **opts = تہی;
	سائز_t nopts = 0;
	صحیح r, ret = SSH_ERR_اندرونی_ERROR;

	اگر (device != تہی &&
	    (r = sshsk_جوڑو_option(&opts, &nopts, "device", device, 0)) != 0) {
		ret = r;
		جاؤ برآمد;
	}
	اگر (user_id != تہی &&
	    (r = sshsk_جوڑو_option(&opts, &nopts, "user", user_id, 0)) != 0) {
		ret = r;
		جاؤ برآمد;
	}
	/* success */
	*optsp = opts;
	opts = تہی;
	nopts = 0;
	ret = 0;
 برآمد:
	sshsk_free_options(opts);
	واپس ret;
}


ساکن صحیح
fill_attestation_blob(ثابت ساخت sk_enroll_response *resp,
    ساخت sshbuf *attest)
{
	صحیح r;

	اگر (attest == تہی)
		واپس 0; /* nothing to do */
	اگر ((r = sshbuf_put_cstring(attest, "ssh-sk-attest-v01")) != 0 ||
	    (r = sshbuf_put_string(attest,
	    resp->attestation_cert, resp->attestation_cert_len)) != 0 ||
	    (r = sshbuf_put_string(attest,
	    resp->signature, resp->signature_len)) != 0 ||
	    (r = sshbuf_put_string(attest,
	    resp->authdata, resp->authdata_len)) != 0 ||
	    (r = sshbuf_put_u32(attest, 0)) != 0 || /* resvd flags */
	    (r = sshbuf_put_string(attest, تہی, 0)) != 0 /* resvd */) {
		error_fr(r, "compose");
		واپس r;
	}
	/* success */
	واپس 0;
}

صحیح
sshsk_enroll(صحیح type, ثابت حرف *provider_راستہ, ثابت حرف *device,
    ثابت حرف *application, ثابت حرف *userid, uint8_t flags,
    ثابت حرف *pin, ساخت sshbuf *challenge_buf,
    ساخت sshkey **keyp, ساخت sshbuf *attest)
{
	ساخت sshsk_provider *skp = تہی;
	ساخت sshkey *کلید = تہی;
	u_char randchall[32];
	ثابت u_char *challenge;
	سائز_t challenge_len;
	ساخت sk_enroll_response *resp = تہی;
	ساخت sk_option **opts = تہی;
	صحیح r = SSH_ERR_اندرونی_ERROR;
	صحیح alg;

	debug_f("provider \"%s\", device \"%s\", application \"%s\", "
	    "userid \"%s\", flags 0x%02x, challenge len %zu%s",
	    provider_راستہ, device, application, userid, flags,
	    challenge_buf == تہی ? 0 : sshbuf_len(challenge_buf),
	    (pin != تہی && *pin != '\0') ? " with-pin" : "");

	*keyp = تہی;
	اگر (attest)
		sshbuf_reset(attest);

	اگر ((r = make_options(device, userid, &opts)) != 0)
		جاؤ برآمد;

	انتخاب (type) {
#اگر_تعریف_شدہ WITH_OPENSSL
	حالت کلید_ECDSA_SK:
		alg = SSH_SK_ECDSA;
		توڑو;
#اگر_ختم /* WITH_OPENSSL */
	حالت کلید_ED25519_SK:
		alg = SSH_SK_ED25519;
		توڑو;
	طےشدہ:
		error_f("unsupported key type");
		r = SSH_ERR_INVALID_دلیل;
		جاؤ برآمد;
	}
	اگر (provider_راستہ == تہی) {
		error_f("missing provider");
		r = SSH_ERR_INVALID_دلیل;
		جاؤ برآمد;
	}
	اگر (application == تہی || *application == '\0') {
		error_f("missing application");
		r = SSH_ERR_INVALID_دلیل;
		جاؤ برآمد;
	}
	اگر (challenge_buf == تہی) {
		debug_f("using random challenge");
		arc4random_buf(randchall, حجم(randchall));
		challenge = randchall;
		challenge_len = حجم(randchall);
	} ورنہ اگر (sshbuf_len(challenge_buf) == 0) {
		error("Missing enrollment challenge");
		r = SSH_ERR_INVALID_دلیل;
		جاؤ برآمد;
	} ورنہ {
		challenge = sshbuf_ptr(challenge_buf);
		challenge_len = sshbuf_len(challenge_buf);
		debug3_f("using explicit challenge len=%zd", challenge_len);
	}
	اگر ((skp = sshsk_open(provider_راستہ)) == تہی) {
		r = SSH_ERR_INVALID_FORMAT; /* XXX sshsk_open return code? */
		جاؤ برآمد;
	}
	/* XXX validate flags? */
	/* enroll key */
	اگر ((r = skp->sk_enroll(alg, challenge, challenge_len, application,
	    flags, pin, opts, &resp)) != 0) {
		debug_f("provider \"%s\" failure %d", provider_راستہ, r);
		r = skerr_مقصد_ssherr(r);
		جاؤ برآمد;
	}

	اگر ((r = sshsk_کلید_from_response(alg, application, resp->flags,
	    resp, &کلید)) != 0)
		جاؤ برآمد;

	/* Optionally fill in the attestation information */
	اگر ((r = fill_attestation_blob(resp, attest)) != 0)
		جاؤ برآمد;

	/* success */
	*keyp = کلید;
	کلید = تہی; /* transferred */
	r = 0;
 برآمد:
	sshsk_free_options(opts);
	sshsk_free(skp);
	sshkey_free(کلید);
	sshsk_free_enroll_response(resp);
	explicit_bzero(randchall, حجم(randchall));
	واپس r;
}

#اگر_تعریف_شدہ WITH_OPENSSL
ساکن صحیح
sshsk_ecdsa_sig(ساخت sk_sign_response *resp, ساخت sshbuf *sig)
{
	ساخت sshbuf *inner_sig = تہی;
	صحیح r = SSH_ERR_اندرونی_ERROR;

	/* Check response validity */
	اگر (resp->sig_r == تہی || resp->sig_s == تہی) {
		error_f("sk_sign response invalid");
		r = SSH_ERR_INVALID_FORMAT;
		جاؤ برآمد;
	}
	اگر ((inner_sig = sshbuf_new()) == تہی) {
		r = SSH_ERR_ALLOC_FAIL;
		جاؤ برآمد;
	}
	/* Prepare and append inner signature object */
	اگر ((r = sshbuf_put_bignum2_بائٹیں(inner_sig,
	    resp->sig_r, resp->sig_r_len)) != 0 ||
	    (r = sshbuf_put_bignum2_بائٹیں(inner_sig,
	    resp->sig_s, resp->sig_s_len)) != 0) {
		error_fr(r, "compose inner");
		جاؤ برآمد;
	}
	اگر ((r = sshbuf_put_stringb(sig, inner_sig)) != 0 ||
	    (r = sshbuf_put_u8(sig, resp->flags)) != 0 ||
	    (r = sshbuf_put_u32(sig, resp->شمار_2)) != 0) {
		error_fr(r, "compose");
		جاؤ برآمد;
	}
#اگر_تعریف_شدہ DEBUG_SK
	fprintf(stderr, "%s: sig_r:\n", __func__);
	sshbuf_dump_ڈیٹا(resp->sig_r, resp->sig_r_len, stderr);
	fprintf(stderr, "%s: sig_s:\n", __func__);
	sshbuf_dump_ڈیٹا(resp->sig_s, resp->sig_s_len, stderr);
	fprintf(stderr, "%s: inner:\n", __func__);
	sshbuf_dump(inner_sig, stderr);
#اگر_ختم
	r = 0;
 برآمد:
	sshbuf_free(inner_sig);
	واپس r;
}
#اگر_ختم /* WITH_OPENSSL */

ساکن صحیح
sshsk_ed25519_sig(ساخت sk_sign_response *resp, ساخت sshbuf *sig)
{
	صحیح r = SSH_ERR_اندرونی_ERROR;

	/* Check response validity */
	اگر (resp->sig_r == تہی) {
		error_f("sk_sign response invalid");
		r = SSH_ERR_INVALID_FORMAT;
		جاؤ برآمد;
	}
	اگر ((r = sshbuf_put_string(sig,
	    resp->sig_r, resp->sig_r_len)) != 0 ||
	    (r = sshbuf_put_u8(sig, resp->flags)) != 0 ||
	    (r = sshbuf_put_u32(sig, resp->شمار_2)) != 0) {
		error_fr(r, "compose");
		جاؤ برآمد;
	}
#اگر_تعریف_شدہ DEBUG_SK
	fprintf(stderr, "%s: sig_r:\n", __func__);
	sshbuf_dump_ڈیٹا(resp->sig_r, resp->sig_r_len, stderr);
#اگر_ختم
	r = 0;
 برآمد:
	واپس r;
}

صحیح
sshsk_sign(ثابت حرف *provider_راستہ, ساخت sshkey *کلید,
    u_char **sigp, سائز_t *lenp, ثابت u_char *ڈیٹا, سائز_t datalen,
    u_int compat, ثابت حرف *pin)
{
	ساخت sshsk_provider *skp = تہی;
	صحیح r = SSH_ERR_اندرونی_ERROR;
	صحیح type, alg;
	ساخت sk_sign_response *resp = تہی;
	ساخت sshbuf *inner_sig = تہی, *sig = تہی;
	ساخت sk_option **opts = تہی;

	debug_f("provider \"%s\", key %s, flags 0x%02x%s",
	    provider_راستہ, sshkey_type(کلید), کلید->sk_flags,
	    (pin != تہی && *pin != '\0') ? " with-pin" : "");

	اگر (sigp != تہی)
		*sigp = تہی;
	اگر (lenp != تہی)
		*lenp = 0;
	type = sshkey_type_plain(کلید->type);
	انتخاب (type) {
#اگر_تعریف_شدہ WITH_OPENSSL
	حالت کلید_ECDSA_SK:
		alg = SSH_SK_ECDSA;
		توڑو;
#اگر_ختم /* WITH_OPENSSL */
	حالت کلید_ED25519_SK:
		alg = SSH_SK_ED25519;
		توڑو;
	طےشدہ:
		واپس SSH_ERR_INVALID_دلیل;
	}
	اگر (provider_راستہ == تہی ||
	    کلید->sk_کلید_handle == تہی ||
	    کلید->sk_application == تہی || *کلید->sk_application == '\0') {
		r = SSH_ERR_INVALID_دلیل;
		جاؤ برآمد;
	}
	اگر ((skp = sshsk_open(provider_راستہ)) == تہی) {
		r = SSH_ERR_INVALID_FORMAT; /* XXX sshsk_open return code? */
		جاؤ برآمد;
	}
#اگر_تعریف_شدہ DEBUG_SK
	fprintf(stderr, "%s: sk_flags = 0x%02x, sk_application = \"%s\"\n",
	    __func__, کلید->sk_flags, کلید->sk_application);
	fprintf(stderr, "%s: sk_key_handle:\n", __func__);
	sshbuf_dump(کلید->sk_کلید_handle, stderr);
#اگر_ختم
	اگر ((r = skp->sk_sign(alg, ڈیٹا, datalen, کلید->sk_application,
	    sshbuf_ptr(کلید->sk_کلید_handle), sshbuf_len(کلید->sk_کلید_handle),
	    کلید->sk_flags, pin, opts, &resp)) != 0) {
		debug_f("sk_sign failed with code %d", r);
		r = skerr_مقصد_ssherr(r);
		جاؤ برآمد;
	}
	/* Assemble signature */
	اگر ((sig = sshbuf_new()) == تہی) {
		r = SSH_ERR_ALLOC_FAIL;
		جاؤ برآمد;
	}
	اگر ((r = sshbuf_put_cstring(sig, sshkey_ssh_name_plain(کلید))) != 0) {
		error_fr(r, "compose outer");
		جاؤ برآمد;
	}
	انتخاب (type) {
#اگر_تعریف_شدہ WITH_OPENSSL
	حالت کلید_ECDSA_SK:
		اگر ((r = sshsk_ecdsa_sig(resp, sig)) != 0)
			جاؤ برآمد;
		توڑو;
#اگر_ختم /* WITH_OPENSSL */
	حالت کلید_ED25519_SK:
		اگر ((r = sshsk_ed25519_sig(resp, sig)) != 0)
			جاؤ برآمد;
		توڑو;
	}
#اگر_تعریف_شدہ DEBUG_SK
	fprintf(stderr, "%s: sig_flags = 0x%02x, sig_counter = %u\n",
	    __func__, resp->flags, resp->شمار_2);
	fprintf(stderr, "%s: data to sign:\n", __func__);
	sshbuf_dump_ڈیٹا(ڈیٹا, datalen, stderr);
	fprintf(stderr, "%s: sigbuf:\n", __func__);
	sshbuf_dump(sig, stderr);
#اگر_ختم
	اگر (sigp != تہی) {
		اگر ((*sigp = حافظہ_دو(sshbuf_len(sig))) == تہی) {
			r = SSH_ERR_ALLOC_FAIL;
			جاؤ برآمد;
		}
		حافظہ_نقل(*sigp, sshbuf_ptr(sig), sshbuf_len(sig));
	}
	اگر (lenp != تہی)
		*lenp = sshbuf_len(sig);
	/* success */
	r = 0;
 برآمد:
	sshsk_free_options(opts);
	sshsk_free(skp);
	sshsk_free_sign_response(resp);
	sshbuf_free(sig);
	sshbuf_free(inner_sig);
	واپس r;
}

ساکن خالی
sshsk_free_sk_resident_کلیدیں(ساخت sk_resident_کلید **rks, سائز_t nrks)
{
	سائز_t i;

	اگر (nrks == 0 || rks == تہی)
		واپس;
	برائے (i = 0; i < nrks; i++) {
		آزاد(rks[i]->application);
		freezero(rks[i]->user_id, rks[i]->user_id_len);
		freezero(rks[i]->کلید.کلید_handle, rks[i]->کلید.کلید_handle_len);
		freezero(rks[i]->کلید.عوامی_کلید, rks[i]->کلید.عوامی_کلید_len);
		freezero(rks[i]->کلید.signature, rks[i]->کلید.signature_len);
		freezero(rks[i]->کلید.attestation_cert,
		    rks[i]->کلید.attestation_cert_len);
		freezero(rks[i], حجم(**rks));
	}
	آزاد(rks);
}

ساکن خالی
sshsk_free_resident_کلید(ساخت sshsk_resident_کلید *srk)
{
	اگر (srk == تہی)
		واپس;
	sshkey_free(srk->کلید);
	freezero(srk->user_id, srk->user_id_len);
	آزاد(srk);
}


خالی
sshsk_free_resident_کلیدیں(ساخت sshsk_resident_کلید **srks, سائز_t nsrks)
{
	سائز_t i;

	اگر (srks == تہی || nsrks == 0)
		واپس;

	برائے (i = 0; i < nsrks; i++)
		sshsk_free_resident_کلید(srks[i]);
	آزاد(srks);
}

صحیح
sshsk_بھرو_resident(ثابت حرف *provider_راستہ, ثابت حرف *device,
    ثابت حرف *pin, u_int flags, ساخت sshsk_resident_کلید ***srksp,
    سائز_t *nsrksp)
{
	ساخت sshsk_provider *skp = تہی;
	صحیح r = SSH_ERR_اندرونی_ERROR;
	ساخت sk_resident_کلید **rks = تہی;
	سائز_t i, nrks = 0, nsrks = 0;
	ساخت sshkey *کلید = تہی;
	ساخت sshsk_resident_کلید *srk = تہی, **srks = تہی, **tmp;
	uint8_t sk_flags;
	ساخت sk_option **opts = تہی;

	debug_f("provider \"%s\"%s", provider_راستہ,
	    (pin != تہی && *pin != '\0') ? ", have-pin": "");

	اگر (srksp == تہی || nsrksp == تہی)
		واپس SSH_ERR_INVALID_دلیل;
	*srksp = تہی;
	*nsrksp = 0;

	اگر ((r = make_options(device, تہی, &opts)) != 0)
		جاؤ برآمد;
	اگر ((skp = sshsk_open(provider_راستہ)) == تہی) {
		r = SSH_ERR_INVALID_FORMAT; /* XXX sshsk_open return code? */
		جاؤ برآمد;
	}
	اگر ((r = skp->sk_بھرو_resident_کلیدیں(pin, opts, &rks, &nrks)) != 0) {
		error("Provider \"%s\" returned failure %d", provider_راستہ, r);
		r = skerr_مقصد_ssherr(r);
		جاؤ برآمد;
	}
	برائے (i = 0; i < nrks; i++) {
		debug3_f("rk %zu: slot %zu, alg %d, app \"%s\", uidlen %zu",
		    i, rks[i]->خانہ, rks[i]->alg, rks[i]->application,
		    rks[i]->user_id_len);
		/* XXX need better filter here */
		اگر (لڑی_موازنہ(rks[i]->application, "ssh:", 4) != 0)
			جاری;
		انتخاب (rks[i]->alg) {
		حالت SSH_SK_ECDSA:
		حالت SSH_SK_ED25519:
			توڑو;
		طےشدہ:
			جاری;
		}
		sk_flags = SSH_SK_USER_PRESENCE_REQD|SSH_SK_RESIDENT_کلید;
		اگر ((rks[i]->flags & SSH_SK_USER_VERIFICATION_REQD))
			sk_flags |= SSH_SK_USER_VERIFICATION_REQD;
		اگر ((r = sshsk_کلید_from_response(rks[i]->alg,
		    rks[i]->application, sk_flags, &rks[i]->کلید, &کلید)) != 0)
			جاؤ برآمد;
		اگر ((srk = صفر_حافظہ_دو(1, حجم(*srk))) == تہی) {
			error_f("calloc failed");
			r = SSH_ERR_ALLOC_FAIL;
			جاؤ برآمد;
		}
		srk->کلید = کلید;
		کلید = تہی; /* transferred */
		اگر ((srk->user_id = صفر_حافظہ_دو(1, rks[i]->user_id_len)) == تہی) {
			error_f("calloc failed");
			r = SSH_ERR_ALLOC_FAIL;
			جاؤ برآمد;
		}
		حافظہ_نقل(srk->user_id, rks[i]->user_id, rks[i]->user_id_len);
		srk->user_id_len = rks[i]->user_id_len;
		اگر ((tmp = recallocarray(srks, nsrks, nsrks + 1,
		    حجم(*tmp))) == تہی) {
			error_f("recallocarray failed");
			r = SSH_ERR_ALLOC_FAIL;
			جاؤ برآمد;
		}
		srks = tmp;
		srks[nsrks++] = srk;
		srk = تہی;
		/* XXX synthesise comment */
	}
	/* success */
	*srksp = srks;
	*nsrksp = nsrks;
	srks = تہی;
	nsrks = 0;
	r = 0;
 برآمد:
	sshsk_free_options(opts);
	sshsk_free(skp);
	sshsk_free_sk_resident_کلیدیں(rks, nrks);
	sshkey_free(کلید);
	sshsk_free_resident_کلید(srk);
	sshsk_free_resident_کلیدیں(srks, nsrks);
	واپس r;
}

#اگر_ختم /* ENABLE_SK */
