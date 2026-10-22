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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ ENABLE_SK

#ਅਨ੍ਤਰ੍ਭਾਵ <dlfcn.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stddef.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdint.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
#ਅਨ੍ਤਰ੍ਭਾਵ <openssl/objects.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <openssl/ec.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <openssl/evp.h>
#ਜੇ_ਅੰਤ /* WITH_OPENSSL */

#ਅਨ੍ਤਰ੍ਭਾਵ "log.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "misc.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshbuf.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshkey.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssherr.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "digest.h"

#ਅਨ੍ਤਰ੍ਭਾਵ "ssh-sk.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sk-api.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "crypto_api.h"

ਬਣਤਰ sshsk_provider {
	ਅੱਖਰ *ਰਸਤਾ;
	ਖਾਲੀ *dlhandle;

	/* Return the version of the middleware API */
	uint32_t (*sk_api_ਸੰਸਕਰਣ)(ਖਾਲੀ);

	/* Enroll a U2F key (private key generation) */
	ਪੂਰਨ (*sk_enroll)(ਪੂਰਨ alg, ਅਚਲ uint8_t *challenge,
	    ਮਾਪ_t challenge_len, ਅਚਲ ਅੱਖਰ *application, uint8_t flags,
	    ਅਚਲ ਅੱਖਰ *pin, ਬਣਤਰ sk_option **opts,
	    ਬਣਤਰ sk_enroll_response **enroll_response);

	/* Sign a challenge */
	ਪੂਰਨ (*sk_sign)(ਪੂਰਨ alg, ਅਚਲ uint8_t *ਸੁਨੇਹਾ_2, ਮਾਪ_t ਸੁਨੇਹਾ_len_2,
	    ਅਚਲ ਅੱਖਰ *application,
	    ਅਚਲ uint8_t *ਕੁੰਜੀ_handle, ਮਾਪ_t ਕੁੰਜੀ_handle_len,
	    uint8_t flags, ਅਚਲ ਅੱਖਰ *pin, ਬਣਤਰ sk_option **opts,
	    ਬਣਤਰ sk_sign_response **sign_response);

	/* Enumerate resident keys */
	ਪੂਰਨ (*sk_ਲੱਦੋ_resident_ਕੁੰਜੀਆਂ)(ਅਚਲ ਅੱਖਰ *pin, ਬਣਤਰ sk_option **opts,
	    ਬਣਤਰ sk_resident_ਕੁੰਜੀ ***rks, ਮਾਪ_t *nrks);
};

/* Built-in version */
ਪੂਰਨ ssh_sk_enroll(ਪੂਰਨ alg, ਅਚਲ uint8_t *challenge,
    ਮਾਪ_t challenge_len, ਅਚਲ ਅੱਖਰ *application, uint8_t flags,
    ਅਚਲ ਅੱਖਰ *pin, ਬਣਤਰ sk_option **opts,
    ਬਣਤਰ sk_enroll_response **enroll_response);
ਪੂਰਨ ssh_sk_sign(ਪੂਰਨ alg, ਅਚਲ uint8_t *ਸੁਨੇਹਾ_2, ਮਾਪ_t ਸੁਨੇਹਾ_len_2,
    ਅਚਲ ਅੱਖਰ *application,
    ਅਚਲ uint8_t *ਕੁੰਜੀ_handle, ਮਾਪ_t ਕੁੰਜੀ_handle_len,
    uint8_t flags, ਅਚਲ ਅੱਖਰ *pin, ਬਣਤਰ sk_option **opts,
    ਬਣਤਰ sk_sign_response **sign_response);
ਪੂਰਨ ssh_sk_ਲੱਦੋ_resident_ਕੁੰਜੀਆਂ(ਅਚਲ ਅੱਖਰ *pin, ਬਣਤਰ sk_option **opts,
    ਬਣਤਰ sk_resident_ਕੁੰਜੀ ***rks, ਮਾਪ_t *nrks);

ਸਥਿਰ ਖਾਲੀ
sshsk_free(ਬਣਤਰ sshsk_provider *p)
{
	ਜੇ (p == ਨਿਰਾ)
		ਵਾਪਸ;
	ਮੁਕਤ(p->ਰਸਤਾ);
	ਜੇ (p->dlhandle != ਨਿਰਾ)
		dlclose(p->dlhandle);
	ਮੁਕਤ(p);
}

ਸਥਿਰ ਬਣਤਰ sshsk_provider *
sshsk_open(ਅਚਲ ਅੱਖਰ *ਰਸਤਾ)
{
	ਬਣਤਰ sshsk_provider *ret = ਨਿਰਾ;
	uint32_t ਸੰਸਕਰਣ;

	ਜੇ (ਰਸਤਾ == ਨਿਰਾ || *ਰਸਤਾ == '\0') {
		error("No FIDO SecurityKeyProvider specified");
		ਵਾਪਸ ਨਿਰਾ;
	}
	ਜੇ ((ret = ਸਿਫਰ_ਸਮ੍ਰਿਤੀ_ਦਿਓ(1, ਆਕਾਰ(*ret))) == ਨਿਰਾ) {
		error_f("calloc failed");
		ਵਾਪਸ ਨਿਰਾ;
	}
	ਜੇ ((ret->ਰਸਤਾ = strdup(ਰਸਤਾ)) == ਨਿਰਾ) {
		error_f("strdup failed");
		ਜਾਓ fail;
	}
	/* Skip the rest if we're using the linked in middleware */
	ਜੇ (strcasecmp(ret->ਰਸਤਾ, "internal") == 0) {
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ ENABLE_SK_ਅੰਦਰੂਨੀ
		ret->sk_enroll = ssh_sk_enroll;
		ret->sk_sign = ssh_sk_sign;
		ret->sk_ਲੱਦੋ_resident_ਕੁੰਜੀਆਂ = ssh_sk_ਲੱਦੋ_resident_ਕੁੰਜੀਆਂ;
		ਵਾਪਸ ret;
#ਨਹੀਂਤਾਂ
		error("internal security key support not enabled");
		ਜਾਓ fail;
#ਜੇ_ਅੰਤ
	}
	ਜੇ (lib_ਸ਼ਾਮਲ_ਹੈ_ਚਿੰਨ੍ਹ(ਰਸਤਾ, "sk_api_version") != 0) {
		error("provider %s is not an OpenSSH FIDO library", ਰਸਤਾ);
		ਜਾਓ fail;
	}
	ਜੇ ((ret->dlhandle = dlopen(ਰਸਤਾ, RTLD_NOW)) == ਨਿਰਾ)
		fatal("Provider \"%s\" dlopen failed: %s", ਰਸਤਾ, dlerror());
	ਜੇ ((ret->sk_api_ਸੰਸਕਰਣ = dlsym(ret->dlhandle,
	    "sk_api_version")) == ਨਿਰਾ) {
		error("Provider \"%s\" dlsym(sk_api_version) failed: %s",
		    ਰਸਤਾ, dlerror());
		ਜਾਓ fail;
	}
	ਸੰਸਕਰਣ = ret->sk_api_ਸੰਸਕਰਣ();
	debug_f("provider %s implements version 0x%08lx", ret->ਰਸਤਾ,
	    (u_long)ਸੰਸਕਰਣ);
	ਜੇ ((ਸੰਸਕਰਣ & SSH_SK_ਸੰਸਕਰਣ_MAJOR_ਨਕਾਬ) != SSH_SK_ਸੰਸਕਰਣ_MAJOR) {
		error("Provider \"%s\" implements unsupported "
		    "version 0x%08lx (supported: 0x%08lx)",
		    ਰਸਤਾ, (u_long)ਸੰਸਕਰਣ, (u_long)SSH_SK_ਸੰਸਕਰਣ_MAJOR);
		ਜਾਓ fail;
	}
	ਜੇ ((ret->sk_enroll = dlsym(ret->dlhandle, "sk_enroll")) == ਨਿਰਾ) {
		error("Provider %s dlsym(sk_enroll) failed: %s",
		    ਰਸਤਾ, dlerror());
		ਜਾਓ fail;
	}
	ਜੇ ((ret->sk_sign = dlsym(ret->dlhandle, "sk_sign")) == ਨਿਰਾ) {
		error("Provider \"%s\" dlsym(sk_sign) failed: %s",
		    ਰਸਤਾ, dlerror());
		ਜਾਓ fail;
	}
	ਜੇ ((ret->sk_ਲੱਦੋ_resident_ਕੁੰਜੀਆਂ = dlsym(ret->dlhandle,
	    "sk_load_resident_keys")) == ਨਿਰਾ) {
		error("Provider \"%s\" dlsym(sk_load_resident_keys) "
		    "failed: %s", ਰਸਤਾ, dlerror());
		ਜਾਓ fail;
	}
	/* success */
	ਵਾਪਸ ret;
fail:
	sshsk_free(ret);
	ਵਾਪਸ ਨਿਰਾ;
}

ਸਥਿਰ ਖਾਲੀ
sshsk_free_enroll_response(ਬਣਤਰ sk_enroll_response *r)
{
	ਜੇ (r == ਨਿਰਾ)
		ਵਾਪਸ;
	freezero(r->ਕੁੰਜੀ_handle, r->ਕੁੰਜੀ_handle_len);
	freezero(r->ਜਨਤਕ_ਕੁੰਜੀ, r->ਜਨਤਕ_ਕੁੰਜੀ_len);
	freezero(r->signature, r->signature_len);
	freezero(r->attestation_cert, r->attestation_cert_len);
	freezero(r->authdata, r->authdata_len);
	freezero(r, ਆਕਾਰ(*r));
}

ਸਥਿਰ ਖਾਲੀ
sshsk_free_sign_response(ਬਣਤਰ sk_sign_response *r)
{
	ਜੇ (r == ਨਿਰਾ)
		ਵਾਪਸ;
	freezero(r->sig_r, r->sig_r_len);
	freezero(r->sig_s, r->sig_s_len);
	freezero(r, ਆਕਾਰ(*r));
}

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
/* Assemble key from response */
ਸਥਿਰ ਪੂਰਨ
sshsk_ecdsa_assemble(ਬਣਤਰ sk_enroll_response *resp, ਬਣਤਰ sshkey **keyp)
{
	ਬਣਤਰ sshkey *ਕੁੰਜੀ = ਨਿਰਾ;
	ਬਣਤਰ sshbuf *b = ਨਿਰਾ;
	EC_ਕੁੰਜੀ *ecdsa = ਨਿਰਾ;
	EC_ਬਿੰਦੂ *q = ਨਿਰਾ;
	ਅਚਲ EC_ਸਮੂਹ *g = ਨਿਰਾ;
	ਪੂਰਨ r;

	*keyp = ਨਿਰਾ;
	ਜੇ ((ਕੁੰਜੀ = sshkey_new(ਕੁੰਜੀ_ECDSA_SK)) == ਨਿਰਾ) {
		error_f("sshkey_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਕੁੰਜੀ->ecdsa_nid = NID_X9_62_prime256v1;
	ਜੇ ((ecdsa = EC_ਕੁੰਜੀ_new_by_ਵਕਰ_name(ਕੁੰਜੀ->ecdsa_nid)) == ਨਿਰਾ ||
	    (g = EC_ਕੁੰਜੀ_get0_ਸਮੂਹ(ecdsa)) == ਨਿਰਾ ||
	    (q = EC_ਬਿੰਦੂ_new(g)) == ਨਿਰਾ ||
	    (b = sshbuf_new()) == ਨਿਰਾ) {
		error_f("allocation failed");
		r = SSH_ERR_ALLOC_FAIL;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((r = sshbuf_put_string(b,
	    resp->ਜਨਤਕ_ਕੁੰਜੀ, resp->ਜਨਤਕ_ਕੁੰਜੀ_len)) != 0) {
		error_fr(r, "sshbuf_put_string");
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((r = sshbuf_get_ec(b, q, g)) != 0) {
		error_fr(r, "parse");
		r = SSH_ERR_INVALID_FORMAT;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ (sshkey_ec_validate_ਜਨਤਕ(g, q) != 0) {
		error("Authenticator returned invalid ECDSA key");
		r = SSH_ERR_ਕੁੰਜੀ_INVALID_EC_ਮੁੱਲ;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ (EC_ਕੁੰਜੀ_ਸੈੱਟ_ਜਨਤਕ_ਕੁੰਜੀ(ecdsa, q) != 1) {
		/* XXX assume it is a allocation error */
		error_f("allocation failed");
		r = SSH_ERR_ALLOC_FAIL;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((ਕੁੰਜੀ->pkey = EVP_PKEY_new()) == ਨਿਰਾ) {
		error_f("allocation failed");
		r = SSH_ERR_ALLOC_FAIL;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ (EVP_PKEY_set1_EC_ਕੁੰਜੀ(ਕੁੰਜੀ->pkey, ecdsa) != 1) {
		error_f("Assigning EC_KEY failed");
		r = SSH_ERR_LIBCRYPTO_ERROR;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	/* success */
	*keyp = ਕੁੰਜੀ;
	ਕੁੰਜੀ = ਨਿਰਾ; /* transferred */
	r = 0;
 ਬਾਹਰਲਾ:
	sshkey_free(ਕੁੰਜੀ);
	sshbuf_free(b);
	EC_ਕੁੰਜੀ_free(ecdsa);
	EC_ਬਿੰਦੂ_free(q);
	ਵਾਪਸ r;
}
#ਜੇ_ਅੰਤ /* WITH_OPENSSL */

ਸਥਿਰ ਪੂਰਨ
sshsk_ed25519_assemble(ਬਣਤਰ sk_enroll_response *resp, ਬਣਤਰ sshkey **keyp)
{
	ਬਣਤਰ sshkey *ਕੁੰਜੀ = ਨਿਰਾ;
	ਪੂਰਨ r;

	*keyp = ਨਿਰਾ;
	ਜੇ (resp->ਜਨਤਕ_ਕੁੰਜੀ_len != ED25519_PK_SZ) {
		error_f("invalid size: %zu", resp->ਜਨਤਕ_ਕੁੰਜੀ_len);
		r = SSH_ERR_INVALID_FORMAT;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((ਕੁੰਜੀ = sshkey_new(ਕੁੰਜੀ_ED25519_SK)) == ਨਿਰਾ) {
		error_f("sshkey_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((ਕੁੰਜੀ->ed25519_pk = ਸਮ੍ਰਿਤੀ_ਦਿਓ(ED25519_PK_SZ)) == ਨਿਰਾ) {
		error_f("malloc failed");
		r = SSH_ERR_ALLOC_FAIL;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਸਮ੍ਰਿਤੀ_ਨਕਲ(ਕੁੰਜੀ->ed25519_pk, resp->ਜਨਤਕ_ਕੁੰਜੀ, ED25519_PK_SZ);
	/* success */
	*keyp = ਕੁੰਜੀ;
	ਕੁੰਜੀ = ਨਿਰਾ; /* transferred */
	r = 0;
 ਬਾਹਰਲਾ:
	sshkey_free(ਕੁੰਜੀ);
	ਵਾਪਸ r;
}

ਸਥਿਰ ਪੂਰਨ
sshsk_ਕੁੰਜੀ_from_response(ਪੂਰਨ alg, ਅਚਲ ਅੱਖਰ *application, uint8_t flags,
    ਬਣਤਰ sk_enroll_response *resp, ਬਣਤਰ sshkey **keyp)
{
	ਬਣਤਰ sshkey *ਕੁੰਜੀ = ਨਿਰਾ;
	ਪੂਰਨ r = SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;

	*keyp = ਨਿਰਾ;

	/* Check response validity */
	ਜੇ (resp->ਜਨਤਕ_ਕੁੰਜੀ == ਨਿਰਾ || resp->ਕੁੰਜੀ_handle == ਨਿਰਾ) {
		error_f("sk_enroll response invalid");
		r = SSH_ERR_INVALID_FORMAT;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਚੋਣ (alg) {
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
	ਹਾਲਤ SSH_SK_ECDSA:
		ਜੇ ((r = sshsk_ecdsa_assemble(resp, &ਕੁੰਜੀ)) != 0)
			ਜਾਓ ਬਾਹਰਲਾ;
		ਰੋਕੋ;
#ਜੇ_ਅੰਤ /* WITH_OPENSSL */
	ਹਾਲਤ SSH_SK_ED25519:
		ਜੇ ((r = sshsk_ed25519_assemble(resp, &ਕੁੰਜੀ)) != 0)
			ਜਾਓ ਬਾਹਰਲਾ;
		ਰੋਕੋ;
	ਮੂਲ:
		error_f("unsupported algorithm %d", alg);
		r = SSH_ERR_INVALID_ਦਲੀਲ;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਕੁੰਜੀ->sk_flags = flags;
	ਜੇ ((ਕੁੰਜੀ->sk_ਕੁੰਜੀ_handle = sshbuf_new()) == ਨਿਰਾ ||
	    (ਕੁੰਜੀ->sk_reserved = sshbuf_new()) == ਨਿਰਾ) {
		error_f("allocation failed");
		r = SSH_ERR_ALLOC_FAIL;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((ਕੁੰਜੀ->sk_application = strdup(application)) == ਨਿਰਾ) {
		error_f("strdup application failed");
		r = SSH_ERR_ALLOC_FAIL;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((r = sshbuf_put(ਕੁੰਜੀ->sk_ਕੁੰਜੀ_handle, resp->ਕੁੰਜੀ_handle,
	    resp->ਕੁੰਜੀ_handle_len)) != 0) {
		error_fr(r, "put key handle");
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	/* success */
	r = 0;
	*keyp = ਕੁੰਜੀ;
	ਕੁੰਜੀ = ਨਿਰਾ;
 ਬਾਹਰਲਾ:
	sshkey_free(ਕੁੰਜੀ);
	ਵਾਪਸ r;
}

ਸਥਿਰ ਪੂਰਨ
skerr_ਮੰਜ਼ਿਲ_ssherr(ਪੂਰਨ skerr)
{
	ਚੋਣ (skerr) {
	ਹਾਲਤ SSH_SK_ERR_UNSUPPORTED:
		ਵਾਪਸ SSH_ERR_FEATURE_UNSUPPORTED;
	ਹਾਲਤ SSH_SK_ERR_PIN_REQUIRED:
		ਵਾਪਸ SSH_ERR_ਕੁੰਜੀ_WRONG_PASSPHRASE;
	ਹਾਲਤ SSH_SK_ERR_DEVICE_NOT_ਮਿਲਿਆ:
		ਵਾਪਸ SSH_ERR_DEVICE_NOT_ਮਿਲਿਆ;
	ਹਾਲਤ SSH_SK_ERR_CREDENTIAL_EXISTS:
		ਵਾਪਸ SSH_ERR_ਕੁੰਜੀ_BAD_PERMISSIONS;
	ਹਾਲਤ SSH_SK_ERR_GENERAL:
	ਮੂਲ:
		ਵਾਪਸ SSH_ERR_INVALID_FORMAT;
	}
}

ਸਥਿਰ ਖਾਲੀ
sshsk_free_options(ਬਣਤਰ sk_option **opts)
{
	ਮਾਪ_t i;

	ਜੇ (opts == ਨਿਰਾ)
		ਵਾਪਸ;
	ਲਈ (i = 0; opts[i] != ਨਿਰਾ; i++) {
		ਮੁਕਤ(opts[i]->name);
		ਮੁਕਤ(opts[i]->ਮੁੱਲ);
		ਮੁਕਤ(opts[i]);
	}
	ਮੁਕਤ(opts);
}

ਸਥਿਰ ਪੂਰਨ
sshsk_ਜੋੜੋ_option(ਬਣਤਰ sk_option ***optsp, ਮਾਪ_t *noptsp,
    ਅਚਲ ਅੱਖਰ *name, ਅਚਲ ਅੱਖਰ *ਮੁੱਲ, uint8_t required)
{
	ਬਣਤਰ sk_option **opts = *optsp;
	ਮਾਪ_t nopts = *noptsp;

	ਜੇ ((opts = recallocarray(opts, nopts, nopts + 2, /* extra for NULL */
	    ਆਕਾਰ(*opts))) == ਨਿਰਾ) {
		error_f("array alloc failed");
		ਵਾਪਸ SSH_ERR_ALLOC_FAIL;
	}
	*optsp = opts;
	*noptsp = nopts + 1;
	ਜੇ ((opts[nopts] = ਸਿਫਰ_ਸਮ੍ਰਿਤੀ_ਦਿਓ(1, ਆਕਾਰ(**opts))) == ਨਿਰਾ) {
		error_f("alloc failed");
		ਵਾਪਸ SSH_ERR_ALLOC_FAIL;
	}
	ਜੇ ((opts[nopts]->name = strdup(name)) == ਨਿਰਾ ||
	    (opts[nopts]->ਮੁੱਲ = strdup(ਮੁੱਲ)) == ਨਿਰਾ) {
		error_f("alloc failed");
		ਵਾਪਸ SSH_ERR_ALLOC_FAIL;
	}
	opts[nopts]->required = required;
	ਵਾਪਸ 0;
}

ਸਥਿਰ ਪੂਰਨ
make_options(ਅਚਲ ਅੱਖਰ *device, ਅਚਲ ਅੱਖਰ *user_id,
    ਬਣਤਰ sk_option ***optsp)
{
	ਬਣਤਰ sk_option **opts = ਨਿਰਾ;
	ਮਾਪ_t nopts = 0;
	ਪੂਰਨ r, ret = SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;

	ਜੇ (device != ਨਿਰਾ &&
	    (r = sshsk_ਜੋੜੋ_option(&opts, &nopts, "device", device, 0)) != 0) {
		ret = r;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ (user_id != ਨਿਰਾ &&
	    (r = sshsk_ਜੋੜੋ_option(&opts, &nopts, "user", user_id, 0)) != 0) {
		ret = r;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	/* success */
	*optsp = opts;
	opts = ਨਿਰਾ;
	nopts = 0;
	ret = 0;
 ਬਾਹਰਲਾ:
	sshsk_free_options(opts);
	ਵਾਪਸ ret;
}


ਸਥਿਰ ਪੂਰਨ
fill_attestation_blob(ਅਚਲ ਬਣਤਰ sk_enroll_response *resp,
    ਬਣਤਰ sshbuf *attest)
{
	ਪੂਰਨ r;

	ਜੇ (attest == ਨਿਰਾ)
		ਵਾਪਸ 0; /* nothing to do */
	ਜੇ ((r = sshbuf_put_cstring(attest, "ssh-sk-attest-v01")) != 0 ||
	    (r = sshbuf_put_string(attest,
	    resp->attestation_cert, resp->attestation_cert_len)) != 0 ||
	    (r = sshbuf_put_string(attest,
	    resp->signature, resp->signature_len)) != 0 ||
	    (r = sshbuf_put_string(attest,
	    resp->authdata, resp->authdata_len)) != 0 ||
	    (r = sshbuf_put_u32(attest, 0)) != 0 || /* resvd flags */
	    (r = sshbuf_put_string(attest, ਨਿਰਾ, 0)) != 0 /* resvd */) {
		error_fr(r, "compose");
		ਵਾਪਸ r;
	}
	/* success */
	ਵਾਪਸ 0;
}

ਪੂਰਨ
sshsk_enroll(ਪੂਰਨ type, ਅਚਲ ਅੱਖਰ *provider_ਰਸਤਾ, ਅਚਲ ਅੱਖਰ *device,
    ਅਚਲ ਅੱਖਰ *application, ਅਚਲ ਅੱਖਰ *userid, uint8_t flags,
    ਅਚਲ ਅੱਖਰ *pin, ਬਣਤਰ sshbuf *challenge_buf,
    ਬਣਤਰ sshkey **keyp, ਬਣਤਰ sshbuf *attest)
{
	ਬਣਤਰ sshsk_provider *skp = ਨਿਰਾ;
	ਬਣਤਰ sshkey *ਕੁੰਜੀ = ਨਿਰਾ;
	u_char randchall[32];
	ਅਚਲ u_char *challenge;
	ਮਾਪ_t challenge_len;
	ਬਣਤਰ sk_enroll_response *resp = ਨਿਰਾ;
	ਬਣਤਰ sk_option **opts = ਨਿਰਾ;
	ਪੂਰਨ r = SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;
	ਪੂਰਨ alg;

	debug_f("provider \"%s\", device \"%s\", application \"%s\", "
	    "userid \"%s\", flags 0x%02x, challenge len %zu%s",
	    provider_ਰਸਤਾ, device, application, userid, flags,
	    challenge_buf == ਨਿਰਾ ? 0 : sshbuf_len(challenge_buf),
	    (pin != ਨਿਰਾ && *pin != '\0') ? " with-pin" : "");

	*keyp = ਨਿਰਾ;
	ਜੇ (attest)
		sshbuf_reset(attest);

	ਜੇ ((r = make_options(device, userid, &opts)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;

	ਚੋਣ (type) {
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
	ਹਾਲਤ ਕੁੰਜੀ_ECDSA_SK:
		alg = SSH_SK_ECDSA;
		ਰੋਕੋ;
#ਜੇ_ਅੰਤ /* WITH_OPENSSL */
	ਹਾਲਤ ਕੁੰਜੀ_ED25519_SK:
		alg = SSH_SK_ED25519;
		ਰੋਕੋ;
	ਮੂਲ:
		error_f("unsupported key type");
		r = SSH_ERR_INVALID_ਦਲੀਲ;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ (provider_ਰਸਤਾ == ਨਿਰਾ) {
		error_f("missing provider");
		r = SSH_ERR_INVALID_ਦਲੀਲ;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ (application == ਨਿਰਾ || *application == '\0') {
		error_f("missing application");
		r = SSH_ERR_INVALID_ਦਲੀਲ;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ (challenge_buf == ਨਿਰਾ) {
		debug_f("using random challenge");
		arc4random_buf(randchall, ਆਕਾਰ(randchall));
		challenge = randchall;
		challenge_len = ਆਕਾਰ(randchall);
	} ਨਹੀਂਤਾਂ ਜੇ (sshbuf_len(challenge_buf) == 0) {
		error("Missing enrollment challenge");
		r = SSH_ERR_INVALID_ਦਲੀਲ;
		ਜਾਓ ਬਾਹਰਲਾ;
	} ਨਹੀਂਤਾਂ {
		challenge = sshbuf_ptr(challenge_buf);
		challenge_len = sshbuf_len(challenge_buf);
		debug3_f("using explicit challenge len=%zd", challenge_len);
	}
	ਜੇ ((skp = sshsk_open(provider_ਰਸਤਾ)) == ਨਿਰਾ) {
		r = SSH_ERR_INVALID_FORMAT; /* XXX sshsk_open return code? */
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	/* XXX validate flags? */
	/* enroll key */
	ਜੇ ((r = skp->sk_enroll(alg, challenge, challenge_len, application,
	    flags, pin, opts, &resp)) != 0) {
		debug_f("provider \"%s\" failure %d", provider_ਰਸਤਾ, r);
		r = skerr_ਮੰਜ਼ਿਲ_ssherr(r);
		ਜਾਓ ਬਾਹਰਲਾ;
	}

	ਜੇ ((r = sshsk_ਕੁੰਜੀ_from_response(alg, application, resp->flags,
	    resp, &ਕੁੰਜੀ)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;

	/* Optionally fill in the attestation information */
	ਜੇ ((r = fill_attestation_blob(resp, attest)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;

	/* success */
	*keyp = ਕੁੰਜੀ;
	ਕੁੰਜੀ = ਨਿਰਾ; /* transferred */
	r = 0;
 ਬਾਹਰਲਾ:
	sshsk_free_options(opts);
	sshsk_free(skp);
	sshkey_free(ਕੁੰਜੀ);
	sshsk_free_enroll_response(resp);
	explicit_bzero(randchall, ਆਕਾਰ(randchall));
	ਵਾਪਸ r;
}

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
ਸਥਿਰ ਪੂਰਨ
sshsk_ecdsa_sig(ਬਣਤਰ sk_sign_response *resp, ਬਣਤਰ sshbuf *sig)
{
	ਬਣਤਰ sshbuf *inner_sig = ਨਿਰਾ;
	ਪੂਰਨ r = SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;

	/* Check response validity */
	ਜੇ (resp->sig_r == ਨਿਰਾ || resp->sig_s == ਨਿਰਾ) {
		error_f("sk_sign response invalid");
		r = SSH_ERR_INVALID_FORMAT;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((inner_sig = sshbuf_new()) == ਨਿਰਾ) {
		r = SSH_ERR_ALLOC_FAIL;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	/* Prepare and append inner signature object */
	ਜੇ ((r = sshbuf_put_bignum2_ਬਾਈਟਾਂ(inner_sig,
	    resp->sig_r, resp->sig_r_len)) != 0 ||
	    (r = sshbuf_put_bignum2_ਬਾਈਟਾਂ(inner_sig,
	    resp->sig_s, resp->sig_s_len)) != 0) {
		error_fr(r, "compose inner");
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((r = sshbuf_put_stringb(sig, inner_sig)) != 0 ||
	    (r = sshbuf_put_u8(sig, resp->flags)) != 0 ||
	    (r = sshbuf_put_u32(sig, resp->counter)) != 0) {
		error_fr(r, "compose");
		ਜਾਓ ਬਾਹਰਲਾ;
	}
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ DEBUG_SK
	fprintf(stderr, "%s: sig_r:\n", __func__);
	sshbuf_dump_ਅੰਕੜੇ(resp->sig_r, resp->sig_r_len, stderr);
	fprintf(stderr, "%s: sig_s:\n", __func__);
	sshbuf_dump_ਅੰਕੜੇ(resp->sig_s, resp->sig_s_len, stderr);
	fprintf(stderr, "%s: inner:\n", __func__);
	sshbuf_dump(inner_sig, stderr);
#ਜੇ_ਅੰਤ
	r = 0;
 ਬਾਹਰਲਾ:
	sshbuf_free(inner_sig);
	ਵਾਪਸ r;
}
#ਜੇ_ਅੰਤ /* WITH_OPENSSL */

ਸਥਿਰ ਪੂਰਨ
sshsk_ed25519_sig(ਬਣਤਰ sk_sign_response *resp, ਬਣਤਰ sshbuf *sig)
{
	ਪੂਰਨ r = SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;

	/* Check response validity */
	ਜੇ (resp->sig_r == ਨਿਰਾ) {
		error_f("sk_sign response invalid");
		r = SSH_ERR_INVALID_FORMAT;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((r = sshbuf_put_string(sig,
	    resp->sig_r, resp->sig_r_len)) != 0 ||
	    (r = sshbuf_put_u8(sig, resp->flags)) != 0 ||
	    (r = sshbuf_put_u32(sig, resp->counter)) != 0) {
		error_fr(r, "compose");
		ਜਾਓ ਬਾਹਰਲਾ;
	}
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ DEBUG_SK
	fprintf(stderr, "%s: sig_r:\n", __func__);
	sshbuf_dump_ਅੰਕੜੇ(resp->sig_r, resp->sig_r_len, stderr);
#ਜੇ_ਅੰਤ
	r = 0;
 ਬਾਹਰਲਾ:
	ਵਾਪਸ r;
}

ਪੂਰਨ
sshsk_sign(ਅਚਲ ਅੱਖਰ *provider_ਰਸਤਾ, ਬਣਤਰ sshkey *ਕੁੰਜੀ,
    u_char **sigp, ਮਾਪ_t *lenp, ਅਚਲ u_char *ਅੰਕੜੇ, ਮਾਪ_t datalen,
    u_int compat, ਅਚਲ ਅੱਖਰ *pin)
{
	ਬਣਤਰ sshsk_provider *skp = ਨਿਰਾ;
	ਪੂਰਨ r = SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;
	ਪੂਰਨ type, alg;
	ਬਣਤਰ sk_sign_response *resp = ਨਿਰਾ;
	ਬਣਤਰ sshbuf *inner_sig = ਨਿਰਾ, *sig = ਨਿਰਾ;
	ਬਣਤਰ sk_option **opts = ਨਿਰਾ;

	debug_f("provider \"%s\", key %s, flags 0x%02x%s",
	    provider_ਰਸਤਾ, sshkey_type(ਕੁੰਜੀ), ਕੁੰਜੀ->sk_flags,
	    (pin != ਨਿਰਾ && *pin != '\0') ? " with-pin" : "");

	ਜੇ (sigp != ਨਿਰਾ)
		*sigp = ਨਿਰਾ;
	ਜੇ (lenp != ਨਿਰਾ)
		*lenp = 0;
	type = sshkey_type_plain(ਕੁੰਜੀ->type);
	ਚੋਣ (type) {
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
	ਹਾਲਤ ਕੁੰਜੀ_ECDSA_SK:
		alg = SSH_SK_ECDSA;
		ਰੋਕੋ;
#ਜੇ_ਅੰਤ /* WITH_OPENSSL */
	ਹਾਲਤ ਕੁੰਜੀ_ED25519_SK:
		alg = SSH_SK_ED25519;
		ਰੋਕੋ;
	ਮੂਲ:
		ਵਾਪਸ SSH_ERR_INVALID_ਦਲੀਲ;
	}
	ਜੇ (provider_ਰਸਤਾ == ਨਿਰਾ ||
	    ਕੁੰਜੀ->sk_ਕੁੰਜੀ_handle == ਨਿਰਾ ||
	    ਕੁੰਜੀ->sk_application == ਨਿਰਾ || *ਕੁੰਜੀ->sk_application == '\0') {
		r = SSH_ERR_INVALID_ਦਲੀਲ;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((skp = sshsk_open(provider_ਰਸਤਾ)) == ਨਿਰਾ) {
		r = SSH_ERR_INVALID_FORMAT; /* XXX sshsk_open return code? */
		ਜਾਓ ਬਾਹਰਲਾ;
	}
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ DEBUG_SK
	fprintf(stderr, "%s: sk_flags = 0x%02x, sk_application = \"%s\"\n",
	    __func__, ਕੁੰਜੀ->sk_flags, ਕੁੰਜੀ->sk_application);
	fprintf(stderr, "%s: sk_key_handle:\n", __func__);
	sshbuf_dump(ਕੁੰਜੀ->sk_ਕੁੰਜੀ_handle, stderr);
#ਜੇ_ਅੰਤ
	ਜੇ ((r = skp->sk_sign(alg, ਅੰਕੜੇ, datalen, ਕੁੰਜੀ->sk_application,
	    sshbuf_ptr(ਕੁੰਜੀ->sk_ਕੁੰਜੀ_handle), sshbuf_len(ਕੁੰਜੀ->sk_ਕੁੰਜੀ_handle),
	    ਕੁੰਜੀ->sk_flags, pin, opts, &resp)) != 0) {
		debug_f("sk_sign failed with code %d", r);
		r = skerr_ਮੰਜ਼ਿਲ_ssherr(r);
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	/* Assemble signature */
	ਜੇ ((sig = sshbuf_new()) == ਨਿਰਾ) {
		r = SSH_ERR_ALLOC_FAIL;
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((r = sshbuf_put_cstring(sig, sshkey_ssh_name_plain(ਕੁੰਜੀ))) != 0) {
		error_fr(r, "compose outer");
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਚੋਣ (type) {
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL
	ਹਾਲਤ ਕੁੰਜੀ_ECDSA_SK:
		ਜੇ ((r = sshsk_ecdsa_sig(resp, sig)) != 0)
			ਜਾਓ ਬਾਹਰਲਾ;
		ਰੋਕੋ;
#ਜੇ_ਅੰਤ /* WITH_OPENSSL */
	ਹਾਲਤ ਕੁੰਜੀ_ED25519_SK:
		ਜੇ ((r = sshsk_ed25519_sig(resp, sig)) != 0)
			ਜਾਓ ਬਾਹਰਲਾ;
		ਰੋਕੋ;
	}
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ DEBUG_SK
	fprintf(stderr, "%s: sig_flags = 0x%02x, sig_counter = %u\n",
	    __func__, resp->flags, resp->counter);
	fprintf(stderr, "%s: data to sign:\n", __func__);
	sshbuf_dump_ਅੰਕੜੇ(ਅੰਕੜੇ, datalen, stderr);
	fprintf(stderr, "%s: sigbuf:\n", __func__);
	sshbuf_dump(sig, stderr);
#ਜੇ_ਅੰਤ
	ਜੇ (sigp != ਨਿਰਾ) {
		ਜੇ ((*sigp = ਸਮ੍ਰਿਤੀ_ਦਿਓ(sshbuf_len(sig))) == ਨਿਰਾ) {
			r = SSH_ERR_ALLOC_FAIL;
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		ਸਮ੍ਰਿਤੀ_ਨਕਲ(*sigp, sshbuf_ptr(sig), sshbuf_len(sig));
	}
	ਜੇ (lenp != ਨਿਰਾ)
		*lenp = sshbuf_len(sig);
	/* success */
	r = 0;
 ਬਾਹਰਲਾ:
	sshsk_free_options(opts);
	sshsk_free(skp);
	sshsk_free_sign_response(resp);
	sshbuf_free(sig);
	sshbuf_free(inner_sig);
	ਵਾਪਸ r;
}

ਸਥਿਰ ਖਾਲੀ
sshsk_free_sk_resident_ਕੁੰਜੀਆਂ(ਬਣਤਰ sk_resident_ਕੁੰਜੀ **rks, ਮਾਪ_t nrks)
{
	ਮਾਪ_t i;

	ਜੇ (nrks == 0 || rks == ਨਿਰਾ)
		ਵਾਪਸ;
	ਲਈ (i = 0; i < nrks; i++) {
		ਮੁਕਤ(rks[i]->application);
		freezero(rks[i]->user_id, rks[i]->user_id_len);
		freezero(rks[i]->ਕੁੰਜੀ.ਕੁੰਜੀ_handle, rks[i]->ਕੁੰਜੀ.ਕੁੰਜੀ_handle_len);
		freezero(rks[i]->ਕੁੰਜੀ.ਜਨਤਕ_ਕੁੰਜੀ, rks[i]->ਕੁੰਜੀ.ਜਨਤਕ_ਕੁੰਜੀ_len);
		freezero(rks[i]->ਕੁੰਜੀ.signature, rks[i]->ਕੁੰਜੀ.signature_len);
		freezero(rks[i]->ਕੁੰਜੀ.attestation_cert,
		    rks[i]->ਕੁੰਜੀ.attestation_cert_len);
		freezero(rks[i], ਆਕਾਰ(**rks));
	}
	ਮੁਕਤ(rks);
}

ਸਥਿਰ ਖਾਲੀ
sshsk_free_resident_ਕੁੰਜੀ(ਬਣਤਰ sshsk_resident_ਕੁੰਜੀ *srk)
{
	ਜੇ (srk == ਨਿਰਾ)
		ਵਾਪਸ;
	sshkey_free(srk->ਕੁੰਜੀ);
	freezero(srk->user_id, srk->user_id_len);
	ਮੁਕਤ(srk);
}


ਖਾਲੀ
sshsk_free_resident_ਕੁੰਜੀਆਂ(ਬਣਤਰ sshsk_resident_ਕੁੰਜੀ **srks, ਮਾਪ_t nsrks)
{
	ਮਾਪ_t i;

	ਜੇ (srks == ਨਿਰਾ || nsrks == 0)
		ਵਾਪਸ;

	ਲਈ (i = 0; i < nsrks; i++)
		sshsk_free_resident_ਕੁੰਜੀ(srks[i]);
	ਮੁਕਤ(srks);
}

ਪੂਰਨ
sshsk_ਲੱਦੋ_resident(ਅਚਲ ਅੱਖਰ *provider_ਰਸਤਾ, ਅਚਲ ਅੱਖਰ *device,
    ਅਚਲ ਅੱਖਰ *pin, u_int flags, ਬਣਤਰ sshsk_resident_ਕੁੰਜੀ ***srksp,
    ਮਾਪ_t *nsrksp)
{
	ਬਣਤਰ sshsk_provider *skp = ਨਿਰਾ;
	ਪੂਰਨ r = SSH_ERR_ਅੰਦਰੂਨੀ_ERROR;
	ਬਣਤਰ sk_resident_ਕੁੰਜੀ **rks = ਨਿਰਾ;
	ਮਾਪ_t i, nrks = 0, nsrks = 0;
	ਬਣਤਰ sshkey *ਕੁੰਜੀ = ਨਿਰਾ;
	ਬਣਤਰ sshsk_resident_ਕੁੰਜੀ *srk = ਨਿਰਾ, **srks = ਨਿਰਾ, **tmp;
	uint8_t sk_flags;
	ਬਣਤਰ sk_option **opts = ਨਿਰਾ;

	debug_f("provider \"%s\"%s", provider_ਰਸਤਾ,
	    (pin != ਨਿਰਾ && *pin != '\0') ? ", have-pin": "");

	ਜੇ (srksp == ਨਿਰਾ || nsrksp == ਨਿਰਾ)
		ਵਾਪਸ SSH_ERR_INVALID_ਦਲੀਲ;
	*srksp = ਨਿਰਾ;
	*nsrksp = 0;

	ਜੇ ((r = make_options(device, ਨਿਰਾ, &opts)) != 0)
		ਜਾਓ ਬਾਹਰਲਾ;
	ਜੇ ((skp = sshsk_open(provider_ਰਸਤਾ)) == ਨਿਰਾ) {
		r = SSH_ERR_INVALID_FORMAT; /* XXX sshsk_open return code? */
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((r = skp->sk_ਲੱਦੋ_resident_ਕੁੰਜੀਆਂ(pin, opts, &rks, &nrks)) != 0) {
		error("Provider \"%s\" returned failure %d", provider_ਰਸਤਾ, r);
		r = skerr_ਮੰਜ਼ਿਲ_ssherr(r);
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਲਈ (i = 0; i < nrks; i++) {
		debug3_f("rk %zu: slot %zu, alg %d, app \"%s\", uidlen %zu",
		    i, rks[i]->ਥਾਂ, rks[i]->alg, rks[i]->application,
		    rks[i]->user_id_len);
		/* XXX need better filter here */
		ਜੇ (ਲੜੀ_ਤੁਲਨਾ(rks[i]->application, "ssh:", 4) != 0)
			ਜਾਰੀ;
		ਚੋਣ (rks[i]->alg) {
		ਹਾਲਤ SSH_SK_ECDSA:
		ਹਾਲਤ SSH_SK_ED25519:
			ਰੋਕੋ;
		ਮੂਲ:
			ਜਾਰੀ;
		}
		sk_flags = SSH_SK_USER_PRESENCE_REQD|SSH_SK_RESIDENT_ਕੁੰਜੀ;
		ਜੇ ((rks[i]->flags & SSH_SK_USER_VERIFICATION_REQD))
			sk_flags |= SSH_SK_USER_VERIFICATION_REQD;
		ਜੇ ((r = sshsk_ਕੁੰਜੀ_from_response(rks[i]->alg,
		    rks[i]->application, sk_flags, &rks[i]->ਕੁੰਜੀ, &ਕੁੰਜੀ)) != 0)
			ਜਾਓ ਬਾਹਰਲਾ;
		ਜੇ ((srk = ਸਿਫਰ_ਸਮ੍ਰਿਤੀ_ਦਿਓ(1, ਆਕਾਰ(*srk))) == ਨਿਰਾ) {
			error_f("calloc failed");
			r = SSH_ERR_ALLOC_FAIL;
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		srk->ਕੁੰਜੀ = ਕੁੰਜੀ;
		ਕੁੰਜੀ = ਨਿਰਾ; /* transferred */
		ਜੇ ((srk->user_id = ਸਿਫਰ_ਸਮ੍ਰਿਤੀ_ਦਿਓ(1, rks[i]->user_id_len)) == ਨਿਰਾ) {
			error_f("calloc failed");
			r = SSH_ERR_ALLOC_FAIL;
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		ਸਮ੍ਰਿਤੀ_ਨਕਲ(srk->user_id, rks[i]->user_id, rks[i]->user_id_len);
		srk->user_id_len = rks[i]->user_id_len;
		ਜੇ ((tmp = recallocarray(srks, nsrks, nsrks + 1,
		    ਆਕਾਰ(*tmp))) == ਨਿਰਾ) {
			error_f("recallocarray failed");
			r = SSH_ERR_ALLOC_FAIL;
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		srks = tmp;
		srks[nsrks++] = srk;
		srk = ਨਿਰਾ;
		/* XXX synthesise comment */
	}
	/* success */
	*srksp = srks;
	*nsrksp = nsrks;
	srks = ਨਿਰਾ;
	nsrks = 0;
	r = 0;
 ਬਾਹਰਲਾ:
	sshsk_free_options(opts);
	sshsk_free(skp);
	sshsk_free_sk_resident_ਕੁੰਜੀਆਂ(rks, nrks);
	sshkey_free(ਕੁੰਜੀ);
	sshsk_free_resident_ਕੁੰਜੀ(srk);
	sshsk_free_resident_ਕੁੰਜੀਆਂ(srks, nsrks);
	ਵਾਪਸ r;
}

#ਜੇ_ਅੰਤ /* ENABLE_SK */
