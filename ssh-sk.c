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

#ಅನ್ತರ್ಭಾವ "includes.h"

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ ENABLE_SK

#ಅನ್ತರ್ಭಾವ <dlfcn.h>
#ಅನ್ತರ್ಭಾವ <stddef.h>
#ಅನ್ತರ್ಭಾವ <stdint.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL
#ಅನ್ತರ್ಭಾವ <openssl/objects.h>
#ಅನ್ತರ್ಭಾವ <openssl/ec.h>
#ಅನ್ತರ್ಭಾವ <openssl/evp.h>
#ಆದರೆ_ಅಂತ್ಯ /* WITH_OPENSSL */

#ಅನ್ತರ್ಭಾವ "log.h"
#ಅನ್ತರ್ಭಾವ "misc.h"
#ಅನ್ತರ್ಭಾವ "sshbuf.h"
#ಅನ್ತರ್ಭಾವ "sshkey.h"
#ಅನ್ತರ್ಭಾವ "ssherr.h"
#ಅನ್ತರ್ಭಾವ "digest.h"

#ಅನ್ತರ್ಭಾವ "ssh-sk.h"
#ಅನ್ತರ್ಭಾವ "sk-api.h"
#ಅನ್ತರ್ಭಾವ "crypto_api.h"

ರಚನೆ sshsk_provider {
	ಅಕ್ಷರ *ಮಾರ್ಗ;
	ಶೂನ್ಯ *dlhandle;

	/* Return the version of the middleware API */
	uint32_t (*sk_api_ಆವೃತ್ತಿ)(ಶೂನ್ಯ);

	/* Enroll a U2F key (private key generation) */
	ಪೂರ್ಣಾಂಕ (*sk_enroll)(ಪೂರ್ಣಾಂಕ alg, ಸ್ಥಿರಾಂಕ uint8_t *challenge,
	    ಗಾತ್ರ_t challenge_len, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *application, uint8_t flags,
	    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *pin, ರಚನೆ sk_option **opts,
	    ರಚನೆ sk_enroll_response **enroll_response);

	/* Sign a challenge */
	ಪೂರ್ಣಾಂಕ (*sk_sign)(ಪೂರ್ಣಾಂಕ alg, ಸ್ಥಿರಾಂಕ uint8_t *ಸಂದೇಶ_2, ಗಾತ್ರ_t ಸಂದೇಶ_len_2,
	    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *application,
	    ಸ್ಥಿರಾಂಕ uint8_t *ಕೀಲಿ_handle, ಗಾತ್ರ_t ಕೀಲಿ_handle_len,
	    uint8_t flags, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *pin, ರಚನೆ sk_option **opts,
	    ರಚನೆ sk_sign_response **sign_response);

	/* Enumerate resident keys */
	ಪೂರ್ಣಾಂಕ (*sk_ತುಂಬು_resident_ಕೀಲಿಗಳು)(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *pin, ರಚನೆ sk_option **opts,
	    ರಚನೆ sk_resident_ಕೀಲಿ ***rks, ಗಾತ್ರ_t *nrks);
};

/* Built-in version */
ಪೂರ್ಣಾಂಕ ssh_sk_enroll(ಪೂರ್ಣಾಂಕ alg, ಸ್ಥಿರಾಂಕ uint8_t *challenge,
    ಗಾತ್ರ_t challenge_len, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *application, uint8_t flags,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *pin, ರಚನೆ sk_option **opts,
    ರಚನೆ sk_enroll_response **enroll_response);
ಪೂರ್ಣಾಂಕ ssh_sk_sign(ಪೂರ್ಣಾಂಕ alg, ಸ್ಥಿರಾಂಕ uint8_t *ಸಂದೇಶ_2, ಗಾತ್ರ_t ಸಂದೇಶ_len_2,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *application,
    ಸ್ಥಿರಾಂಕ uint8_t *ಕೀಲಿ_handle, ಗಾತ್ರ_t ಕೀಲಿ_handle_len,
    uint8_t flags, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *pin, ರಚನೆ sk_option **opts,
    ರಚನೆ sk_sign_response **sign_response);
ಪೂರ್ಣಾಂಕ ssh_sk_ತುಂಬು_resident_ಕೀಲಿಗಳು(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *pin, ರಚನೆ sk_option **opts,
    ರಚನೆ sk_resident_ಕೀಲಿ ***rks, ಗಾತ್ರ_t *nrks);

ಸ್ಥಿರ ಶೂನ್ಯ
sshsk_free(ರಚನೆ sshsk_provider *p)
{
	ಆದರೆ (p == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ;
	ಬಿಡುಗಡೆ(p->ಮಾರ್ಗ);
	ಆದರೆ (p->dlhandle != ಖಾಲಿ)
		dlclose(p->dlhandle);
	ಬಿಡುಗಡೆ(p);
}

ಸ್ಥಿರ ರಚನೆ sshsk_provider *
sshsk_open(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಮಾರ್ಗ)
{
	ರಚನೆ sshsk_provider *ret = ಖಾಲಿ;
	uint32_t ಆವೃತ್ತಿ;

	ಆದರೆ (ಮಾರ್ಗ == ಖಾಲಿ || *ಮಾರ್ಗ == '\0') {
		error("No FIDO SecurityKeyProvider specified");
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;
	}
	ಆದರೆ ((ret = ಸೊನ್ನೆ_ಸ್ಮರಣೆ_ಕೊಡು(1, ಗಾತ್ರ(*ret))) == ಖಾಲಿ) {
		error_f("calloc failed");
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;
	}
	ಆದರೆ ((ret->ಮಾರ್ಗ = strdup(ಮಾರ್ಗ)) == ಖಾಲಿ) {
		error_f("strdup failed");
		ಹೋಗು fail;
	}
	/* Skip the rest if we're using the linked in middleware */
	ಆದರೆ (strcasecmp(ret->ಮಾರ್ಗ, "internal") == 0) {
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ ENABLE_SK_ಆಂತರಿಕ
		ret->sk_enroll = ssh_sk_enroll;
		ret->sk_sign = ssh_sk_sign;
		ret->sk_ತುಂಬು_resident_ಕೀಲಿಗಳು = ssh_sk_ತುಂಬು_resident_ಕೀಲಿಗಳು;
		ಹಿಂತಿರುಗಿ ret;
#ಇಲ್ಲದಿದ್ದರೆ
		error("internal security key support not enabled");
		ಹೋಗು fail;
#ಆದರೆ_ಅಂತ್ಯ
	}
	ಆದರೆ (lib_ಒಳಗೊಂಡಿದೆ_ಚಿಹ್ನೆ(ಮಾರ್ಗ, "sk_api_version") != 0) {
		error("provider %s is not an OpenSSH FIDO library", ಮಾರ್ಗ);
		ಹೋಗು fail;
	}
	ಆದರೆ ((ret->dlhandle = dlopen(ಮಾರ್ಗ, RTLD_NOW)) == ಖಾಲಿ)
		fatal("Provider \"%s\" dlopen failed: %s", ಮಾರ್ಗ, dlerror());
	ಆದರೆ ((ret->sk_api_ಆವೃತ್ತಿ = dlsym(ret->dlhandle,
	    "sk_api_version")) == ಖಾಲಿ) {
		error("Provider \"%s\" dlsym(sk_api_version) failed: %s",
		    ಮಾರ್ಗ, dlerror());
		ಹೋಗು fail;
	}
	ಆವೃತ್ತಿ = ret->sk_api_ಆವೃತ್ತಿ();
	debug_f("provider %s implements version 0x%08lx", ret->ಮಾರ್ಗ,
	    (u_long)ಆವೃತ್ತಿ);
	ಆದರೆ ((ಆವೃತ್ತಿ & SSH_SK_ಆವೃತ್ತಿ_MAJOR_ಮುಖವಾಡ) != SSH_SK_ಆವೃತ್ತಿ_MAJOR) {
		error("Provider \"%s\" implements unsupported "
		    "version 0x%08lx (supported: 0x%08lx)",
		    ಮಾರ್ಗ, (u_long)ಆವೃತ್ತಿ, (u_long)SSH_SK_ಆವೃತ್ತಿ_MAJOR);
		ಹೋಗು fail;
	}
	ಆದರೆ ((ret->sk_enroll = dlsym(ret->dlhandle, "sk_enroll")) == ಖಾಲಿ) {
		error("Provider %s dlsym(sk_enroll) failed: %s",
		    ಮಾರ್ಗ, dlerror());
		ಹೋಗು fail;
	}
	ಆದರೆ ((ret->sk_sign = dlsym(ret->dlhandle, "sk_sign")) == ಖಾಲಿ) {
		error("Provider \"%s\" dlsym(sk_sign) failed: %s",
		    ಮಾರ್ಗ, dlerror());
		ಹೋಗು fail;
	}
	ಆದರೆ ((ret->sk_ತುಂಬು_resident_ಕೀಲಿಗಳು = dlsym(ret->dlhandle,
	    "sk_load_resident_keys")) == ಖಾಲಿ) {
		error("Provider \"%s\" dlsym(sk_load_resident_keys) "
		    "failed: %s", ಮಾರ್ಗ, dlerror());
		ಹೋಗು fail;
	}
	/* success */
	ಹಿಂತಿರುಗಿ ret;
fail:
	sshsk_free(ret);
	ಹಿಂತಿರುಗಿ ಖಾಲಿ;
}

ಸ್ಥಿರ ಶೂನ್ಯ
sshsk_free_enroll_response(ರಚನೆ sk_enroll_response *r)
{
	ಆದರೆ (r == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ;
	freezero(r->ಕೀಲಿ_handle, r->ಕೀಲಿ_handle_len);
	freezero(r->ಬಹಿರಂಗ_ಕೀಲಿ, r->ಬಹಿರಂಗ_ಕೀಲಿ_len);
	freezero(r->signature, r->signature_len);
	freezero(r->attestation_cert, r->attestation_cert_len);
	freezero(r->authdata, r->authdata_len);
	freezero(r, ಗಾತ್ರ(*r));
}

ಸ್ಥಿರ ಶೂನ್ಯ
sshsk_free_sign_response(ರಚನೆ sk_sign_response *r)
{
	ಆದರೆ (r == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ;
	freezero(r->sig_r, r->sig_r_len);
	freezero(r->sig_s, r->sig_s_len);
	freezero(r, ಗಾತ್ರ(*r));
}

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL
/* Assemble key from response */
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
sshsk_ecdsa_assemble(ರಚನೆ sk_enroll_response *resp, ರಚನೆ sshkey **keyp)
{
	ರಚನೆ sshkey *ಕೀಲಿ = ಖಾಲಿ;
	ರಚನೆ sshbuf *b = ಖಾಲಿ;
	EC_ಕೀಲಿ *ecdsa = ಖಾಲಿ;
	EC_ಬಿಂದು *q = ಖಾಲಿ;
	ಸ್ಥಿರಾಂಕ EC_ಗುಂಪು *g = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ r;

	*keyp = ಖಾಲಿ;
	ಆದರೆ ((ಕೀಲಿ = sshkey_new(ಕೀಲಿ_ECDSA_SK)) == ಖಾಲಿ) {
		error_f("sshkey_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಕೀಲಿ->ecdsa_nid = NID_X9_62_prime256v1;
	ಆದರೆ ((ecdsa = EC_ಕೀಲಿ_new_by_ವಕ್ರ_name(ಕೀಲಿ->ecdsa_nid)) == ಖಾಲಿ ||
	    (g = EC_ಕೀಲಿ_get0_ಗುಂಪು(ecdsa)) == ಖಾಲಿ ||
	    (q = EC_ಬಿಂದು_new(g)) == ಖಾಲಿ ||
	    (b = sshbuf_new()) == ಖಾಲಿ) {
		error_f("allocation failed");
		r = SSH_ERR_ALLOC_FAIL;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((r = sshbuf_put_string(b,
	    resp->ಬಹಿರಂಗ_ಕೀಲಿ, resp->ಬಹಿರಂಗ_ಕೀಲಿ_len)) != 0) {
		error_fr(r, "sshbuf_put_string");
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((r = sshbuf_get_ec(b, q, g)) != 0) {
		error_fr(r, "parse");
		r = SSH_ERR_INVALID_FORMAT;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ (sshkey_ec_validate_ಬಹಿರಂಗ(g, q) != 0) {
		error("Authenticator returned invalid ECDSA key");
		r = SSH_ERR_ಕೀಲಿ_INVALID_EC_ಮೌಲ್ಯ;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ (EC_ಕೀಲಿ_ಗಣ_ಬಹಿರಂಗ_ಕೀಲಿ(ecdsa, q) != 1) {
		/* XXX assume it is a allocation error */
		error_f("allocation failed");
		r = SSH_ERR_ALLOC_FAIL;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((ಕೀಲಿ->pkey = EVP_PKEY_new()) == ಖಾಲಿ) {
		error_f("allocation failed");
		r = SSH_ERR_ALLOC_FAIL;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ (EVP_PKEY_set1_EC_ಕೀಲಿ(ಕೀಲಿ->pkey, ecdsa) != 1) {
		error_f("Assigning EC_KEY failed");
		r = SSH_ERR_LIBCRYPTO_ERROR;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	/* success */
	*keyp = ಕೀಲಿ;
	ಕೀಲಿ = ಖಾಲಿ; /* transferred */
	r = 0;
 ಹೊರಹೋಗು:
	sshkey_free(ಕೀಲಿ);
	sshbuf_free(b);
	EC_ಕೀಲಿ_free(ecdsa);
	EC_ಬಿಂದು_free(q);
	ಹಿಂತಿರುಗಿ r;
}
#ಆದರೆ_ಅಂತ್ಯ /* WITH_OPENSSL */

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
sshsk_ed25519_assemble(ರಚನೆ sk_enroll_response *resp, ರಚನೆ sshkey **keyp)
{
	ರಚನೆ sshkey *ಕೀಲಿ = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ r;

	*keyp = ಖಾಲಿ;
	ಆದರೆ (resp->ಬಹಿರಂಗ_ಕೀಲಿ_len != ED25519_PK_SZ) {
		error_f("invalid size: %zu", resp->ಬಹಿರಂಗ_ಕೀಲಿ_len);
		r = SSH_ERR_INVALID_FORMAT;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((ಕೀಲಿ = sshkey_new(ಕೀಲಿ_ED25519_SK)) == ಖಾಲಿ) {
		error_f("sshkey_new failed");
		r = SSH_ERR_ALLOC_FAIL;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((ಕೀಲಿ->ed25519_pk = ಸ್ಮರಣೆ_ಕೊಡು(ED25519_PK_SZ)) == ಖಾಲಿ) {
		error_f("malloc failed");
		r = SSH_ERR_ALLOC_FAIL;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಸ್ಮರಣೆ_ನಕಲು(ಕೀಲಿ->ed25519_pk, resp->ಬಹಿರಂಗ_ಕೀಲಿ, ED25519_PK_SZ);
	/* success */
	*keyp = ಕೀಲಿ;
	ಕೀಲಿ = ಖಾಲಿ; /* transferred */
	r = 0;
 ಹೊರಹೋಗು:
	sshkey_free(ಕೀಲಿ);
	ಹಿಂತಿರುಗಿ r;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
sshsk_ಕೀಲಿ_from_response(ಪೂರ್ಣಾಂಕ alg, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *application, uint8_t flags,
    ರಚನೆ sk_enroll_response *resp, ರಚನೆ sshkey **keyp)
{
	ರಚನೆ sshkey *ಕೀಲಿ = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ r = SSH_ERR_ಆಂತರಿಕ_ERROR;

	*keyp = ಖಾಲಿ;

	/* Check response validity */
	ಆದರೆ (resp->ಬಹಿರಂಗ_ಕೀಲಿ == ಖಾಲಿ || resp->ಕೀಲಿ_handle == ಖಾಲಿ) {
		error_f("sk_enroll response invalid");
		r = SSH_ERR_INVALID_FORMAT;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆಯ್ಕೆ (alg) {
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL
	ಸ್ಥಿತಿ SSH_SK_ECDSA:
		ಆದರೆ ((r = sshsk_ecdsa_assemble(resp, &ಕೀಲಿ)) != 0)
			ಹೋಗು ಹೊರಹೋಗು;
		ನಿಲ್ಲಿಸು;
#ಆದರೆ_ಅಂತ್ಯ /* WITH_OPENSSL */
	ಸ್ಥಿತಿ SSH_SK_ED25519:
		ಆದರೆ ((r = sshsk_ed25519_assemble(resp, &ಕೀಲಿ)) != 0)
			ಹೋಗು ಹೊರಹೋಗು;
		ನಿಲ್ಲಿಸು;
	ಪೂರ್ವನಿಯೋಜಿತ:
		error_f("unsupported algorithm %d", alg);
		r = SSH_ERR_INVALID_ವಾದ;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಕೀಲಿ->sk_flags = flags;
	ಆದರೆ ((ಕೀಲಿ->sk_ಕೀಲಿ_handle = sshbuf_new()) == ಖಾಲಿ ||
	    (ಕೀಲಿ->sk_reserved = sshbuf_new()) == ಖಾಲಿ) {
		error_f("allocation failed");
		r = SSH_ERR_ALLOC_FAIL;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((ಕೀಲಿ->sk_application = strdup(application)) == ಖಾಲಿ) {
		error_f("strdup application failed");
		r = SSH_ERR_ALLOC_FAIL;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((r = sshbuf_put(ಕೀಲಿ->sk_ಕೀಲಿ_handle, resp->ಕೀಲಿ_handle,
	    resp->ಕೀಲಿ_handle_len)) != 0) {
		error_fr(r, "put key handle");
		ಹೋಗು ಹೊರಹೋಗು;
	}
	/* success */
	r = 0;
	*keyp = ಕೀಲಿ;
	ಕೀಲಿ = ಖಾಲಿ;
 ಹೊರಹೋಗು:
	sshkey_free(ಕೀಲಿ);
	ಹಿಂತಿರುಗಿ r;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
skerr_ಗಮ್ಯ_ssherr(ಪೂರ್ಣಾಂಕ skerr)
{
	ಆಯ್ಕೆ (skerr) {
	ಸ್ಥಿತಿ SSH_SK_ERR_UNSUPPORTED:
		ಹಿಂತಿರುಗಿ SSH_ERR_FEATURE_UNSUPPORTED;
	ಸ್ಥಿತಿ SSH_SK_ERR_PIN_REQUIRED:
		ಹಿಂತಿರುಗಿ SSH_ERR_ಕೀಲಿ_WRONG_PASSPHRASE;
	ಸ್ಥಿತಿ SSH_SK_ERR_DEVICE_NOT_ಸಿಕ್ಕಿತು:
		ಹಿಂತಿರುಗಿ SSH_ERR_DEVICE_NOT_ಸಿಕ್ಕಿತು;
	ಸ್ಥಿತಿ SSH_SK_ERR_CREDENTIAL_EXISTS:
		ಹಿಂತಿರುಗಿ SSH_ERR_ಕೀಲಿ_BAD_PERMISSIONS;
	ಸ್ಥಿತಿ SSH_SK_ERR_GENERAL:
	ಪೂರ್ವನಿಯೋಜಿತ:
		ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_FORMAT;
	}
}

ಸ್ಥಿರ ಶೂನ್ಯ
sshsk_free_options(ರಚನೆ sk_option **opts)
{
	ಗಾತ್ರ_t i;

	ಆದರೆ (opts == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ;
	ಗಾಗಿ (i = 0; opts[i] != ಖಾಲಿ; i++) {
		ಬಿಡುಗಡೆ(opts[i]->name);
		ಬಿಡುಗಡೆ(opts[i]->ಮೌಲ್ಯ);
		ಬಿಡುಗಡೆ(opts[i]);
	}
	ಬಿಡುಗಡೆ(opts);
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
sshsk_ಕೂಡಿಸು_option(ರಚನೆ sk_option ***optsp, ಗಾತ್ರ_t *noptsp,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *name, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಮೌಲ್ಯ, uint8_t required)
{
	ರಚನೆ sk_option **opts = *optsp;
	ಗಾತ್ರ_t nopts = *noptsp;

	ಆದರೆ ((opts = recallocarray(opts, nopts, nopts + 2, /* extra for NULL */
	    ಗಾತ್ರ(*opts))) == ಖಾಲಿ) {
		error_f("array alloc failed");
		ಹಿಂತಿರುಗಿ SSH_ERR_ALLOC_FAIL;
	}
	*optsp = opts;
	*noptsp = nopts + 1;
	ಆದರೆ ((opts[nopts] = ಸೊನ್ನೆ_ಸ್ಮರಣೆ_ಕೊಡು(1, ಗಾತ್ರ(**opts))) == ಖಾಲಿ) {
		error_f("alloc failed");
		ಹಿಂತಿರುಗಿ SSH_ERR_ALLOC_FAIL;
	}
	ಆದರೆ ((opts[nopts]->name = strdup(name)) == ಖಾಲಿ ||
	    (opts[nopts]->ಮೌಲ್ಯ = strdup(ಮೌಲ್ಯ)) == ಖಾಲಿ) {
		error_f("alloc failed");
		ಹಿಂತಿರುಗಿ SSH_ERR_ALLOC_FAIL;
	}
	opts[nopts]->required = required;
	ಹಿಂತಿರುಗಿ 0;
}

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
make_options(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *device, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *user_id,
    ರಚನೆ sk_option ***optsp)
{
	ರಚನೆ sk_option **opts = ಖಾಲಿ;
	ಗಾತ್ರ_t nopts = 0;
	ಪೂರ್ಣಾಂಕ r, ret = SSH_ERR_ಆಂತರಿಕ_ERROR;

	ಆದರೆ (device != ಖಾಲಿ &&
	    (r = sshsk_ಕೂಡಿಸು_option(&opts, &nopts, "device", device, 0)) != 0) {
		ret = r;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ (user_id != ಖಾಲಿ &&
	    (r = sshsk_ಕೂಡಿಸು_option(&opts, &nopts, "user", user_id, 0)) != 0) {
		ret = r;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	/* success */
	*optsp = opts;
	opts = ಖಾಲಿ;
	nopts = 0;
	ret = 0;
 ಹೊರಹೋಗು:
	sshsk_free_options(opts);
	ಹಿಂತಿರುಗಿ ret;
}


ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
fill_attestation_blob(ಸ್ಥಿರಾಂಕ ರಚನೆ sk_enroll_response *resp,
    ರಚನೆ sshbuf *attest)
{
	ಪೂರ್ಣಾಂಕ r;

	ಆದರೆ (attest == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ 0; /* nothing to do */
	ಆದರೆ ((r = sshbuf_put_cstring(attest, "ssh-sk-attest-v01")) != 0 ||
	    (r = sshbuf_put_string(attest,
	    resp->attestation_cert, resp->attestation_cert_len)) != 0 ||
	    (r = sshbuf_put_string(attest,
	    resp->signature, resp->signature_len)) != 0 ||
	    (r = sshbuf_put_string(attest,
	    resp->authdata, resp->authdata_len)) != 0 ||
	    (r = sshbuf_put_u32(attest, 0)) != 0 || /* resvd flags */
	    (r = sshbuf_put_string(attest, ಖಾಲಿ, 0)) != 0 /* resvd */) {
		error_fr(r, "compose");
		ಹಿಂತಿರುಗಿ r;
	}
	/* success */
	ಹಿಂತಿರುಗಿ 0;
}

ಪೂರ್ಣಾಂಕ
sshsk_enroll(ಪೂರ್ಣಾಂಕ type, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *provider_ಮಾರ್ಗ, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *device,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *application, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *userid, uint8_t flags,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *pin, ರಚನೆ sshbuf *challenge_buf,
    ರಚನೆ sshkey **keyp, ರಚನೆ sshbuf *attest)
{
	ರಚನೆ sshsk_provider *skp = ಖಾಲಿ;
	ರಚನೆ sshkey *ಕೀಲಿ = ಖಾಲಿ;
	u_char randchall[32];
	ಸ್ಥಿರಾಂಕ u_char *challenge;
	ಗಾತ್ರ_t challenge_len;
	ರಚನೆ sk_enroll_response *resp = ಖಾಲಿ;
	ರಚನೆ sk_option **opts = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ r = SSH_ERR_ಆಂತರಿಕ_ERROR;
	ಪೂರ್ಣಾಂಕ alg;

	debug_f("provider \"%s\", device \"%s\", application \"%s\", "
	    "userid \"%s\", flags 0x%02x, challenge len %zu%s",
	    provider_ಮಾರ್ಗ, device, application, userid, flags,
	    challenge_buf == ಖಾಲಿ ? 0 : sshbuf_len(challenge_buf),
	    (pin != ಖಾಲಿ && *pin != '\0') ? " with-pin" : "");

	*keyp = ಖಾಲಿ;
	ಆದರೆ (attest)
		sshbuf_reset(attest);

	ಆದರೆ ((r = make_options(device, userid, &opts)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;

	ಆಯ್ಕೆ (type) {
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL
	ಸ್ಥಿತಿ ಕೀಲಿ_ECDSA_SK:
		alg = SSH_SK_ECDSA;
		ನಿಲ್ಲಿಸು;
#ಆದರೆ_ಅಂತ್ಯ /* WITH_OPENSSL */
	ಸ್ಥಿತಿ ಕೀಲಿ_ED25519_SK:
		alg = SSH_SK_ED25519;
		ನಿಲ್ಲಿಸು;
	ಪೂರ್ವನಿಯೋಜಿತ:
		error_f("unsupported key type");
		r = SSH_ERR_INVALID_ವಾದ;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ (provider_ಮಾರ್ಗ == ಖಾಲಿ) {
		error_f("missing provider");
		r = SSH_ERR_INVALID_ವಾದ;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ (application == ಖಾಲಿ || *application == '\0') {
		error_f("missing application");
		r = SSH_ERR_INVALID_ವಾದ;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ (challenge_buf == ಖಾಲಿ) {
		debug_f("using random challenge");
		arc4random_buf(randchall, ಗಾತ್ರ(randchall));
		challenge = randchall;
		challenge_len = ಗಾತ್ರ(randchall);
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (sshbuf_len(challenge_buf) == 0) {
		error("Missing enrollment challenge");
		r = SSH_ERR_INVALID_ವಾದ;
		ಹೋಗು ಹೊರಹೋಗು;
	} ಇಲ್ಲದಿದ್ದರೆ {
		challenge = sshbuf_ptr(challenge_buf);
		challenge_len = sshbuf_len(challenge_buf);
		debug3_f("using explicit challenge len=%zd", challenge_len);
	}
	ಆದರೆ ((skp = sshsk_open(provider_ಮಾರ್ಗ)) == ಖಾಲಿ) {
		r = SSH_ERR_INVALID_FORMAT; /* XXX sshsk_open return code? */
		ಹೋಗು ಹೊರಹೋಗು;
	}
	/* XXX validate flags? */
	/* enroll key */
	ಆದರೆ ((r = skp->sk_enroll(alg, challenge, challenge_len, application,
	    flags, pin, opts, &resp)) != 0) {
		debug_f("provider \"%s\" failure %d", provider_ಮಾರ್ಗ, r);
		r = skerr_ಗಮ್ಯ_ssherr(r);
		ಹೋಗು ಹೊರಹೋಗು;
	}

	ಆದರೆ ((r = sshsk_ಕೀಲಿ_from_response(alg, application, resp->flags,
	    resp, &ಕೀಲಿ)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;

	/* Optionally fill in the attestation information */
	ಆದರೆ ((r = fill_attestation_blob(resp, attest)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;

	/* success */
	*keyp = ಕೀಲಿ;
	ಕೀಲಿ = ಖಾಲಿ; /* transferred */
	r = 0;
 ಹೊರಹೋಗು:
	sshsk_free_options(opts);
	sshsk_free(skp);
	sshkey_free(ಕೀಲಿ);
	sshsk_free_enroll_response(resp);
	explicit_bzero(randchall, ಗಾತ್ರ(randchall));
	ಹಿಂತಿರುಗಿ r;
}

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
sshsk_ecdsa_sig(ರಚನೆ sk_sign_response *resp, ರಚನೆ sshbuf *sig)
{
	ರಚನೆ sshbuf *inner_sig = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ r = SSH_ERR_ಆಂತರಿಕ_ERROR;

	/* Check response validity */
	ಆದರೆ (resp->sig_r == ಖಾಲಿ || resp->sig_s == ಖಾಲಿ) {
		error_f("sk_sign response invalid");
		r = SSH_ERR_INVALID_FORMAT;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((inner_sig = sshbuf_new()) == ಖಾಲಿ) {
		r = SSH_ERR_ALLOC_FAIL;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	/* Prepare and append inner signature object */
	ಆದರೆ ((r = sshbuf_put_bignum2_ಬೈಟುಗಳು(inner_sig,
	    resp->sig_r, resp->sig_r_len)) != 0 ||
	    (r = sshbuf_put_bignum2_ಬೈಟುಗಳು(inner_sig,
	    resp->sig_s, resp->sig_s_len)) != 0) {
		error_fr(r, "compose inner");
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((r = sshbuf_put_stringb(sig, inner_sig)) != 0 ||
	    (r = sshbuf_put_u8(sig, resp->flags)) != 0 ||
	    (r = sshbuf_put_u32(sig, resp->counter)) != 0) {
		error_fr(r, "compose");
		ಹೋಗು ಹೊರಹೋಗು;
	}
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ DEBUG_SK
	fprintf(stderr, "%s: sig_r:\n", __func__);
	sshbuf_dump_ದತ್ತಾಂಶ(resp->sig_r, resp->sig_r_len, stderr);
	fprintf(stderr, "%s: sig_s:\n", __func__);
	sshbuf_dump_ದತ್ತಾಂಶ(resp->sig_s, resp->sig_s_len, stderr);
	fprintf(stderr, "%s: inner:\n", __func__);
	sshbuf_dump(inner_sig, stderr);
#ಆದರೆ_ಅಂತ್ಯ
	r = 0;
 ಹೊರಹೋಗು:
	sshbuf_free(inner_sig);
	ಹಿಂತಿರುಗಿ r;
}
#ಆದರೆ_ಅಂತ್ಯ /* WITH_OPENSSL */

ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
sshsk_ed25519_sig(ರಚನೆ sk_sign_response *resp, ರಚನೆ sshbuf *sig)
{
	ಪೂರ್ಣಾಂಕ r = SSH_ERR_ಆಂತರಿಕ_ERROR;

	/* Check response validity */
	ಆದರೆ (resp->sig_r == ಖಾಲಿ) {
		error_f("sk_sign response invalid");
		r = SSH_ERR_INVALID_FORMAT;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((r = sshbuf_put_string(sig,
	    resp->sig_r, resp->sig_r_len)) != 0 ||
	    (r = sshbuf_put_u8(sig, resp->flags)) != 0 ||
	    (r = sshbuf_put_u32(sig, resp->counter)) != 0) {
		error_fr(r, "compose");
		ಹೋಗು ಹೊರಹೋಗು;
	}
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ DEBUG_SK
	fprintf(stderr, "%s: sig_r:\n", __func__);
	sshbuf_dump_ದತ್ತಾಂಶ(resp->sig_r, resp->sig_r_len, stderr);
#ಆದರೆ_ಅಂತ್ಯ
	r = 0;
 ಹೊರಹೋಗು:
	ಹಿಂತಿರುಗಿ r;
}

ಪೂರ್ಣಾಂಕ
sshsk_sign(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *provider_ಮಾರ್ಗ, ರಚನೆ sshkey *ಕೀಲಿ,
    u_char **sigp, ಗಾತ್ರ_t *lenp, ಸ್ಥಿರಾಂಕ u_char *ದತ್ತಾಂಶ, ಗಾತ್ರ_t datalen,
    u_int compat, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *pin)
{
	ರಚನೆ sshsk_provider *skp = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ r = SSH_ERR_ಆಂತರಿಕ_ERROR;
	ಪೂರ್ಣಾಂಕ type, alg;
	ರಚನೆ sk_sign_response *resp = ಖಾಲಿ;
	ರಚನೆ sshbuf *inner_sig = ಖಾಲಿ, *sig = ಖಾಲಿ;
	ರಚನೆ sk_option **opts = ಖಾಲಿ;

	debug_f("provider \"%s\", key %s, flags 0x%02x%s",
	    provider_ಮಾರ್ಗ, sshkey_type(ಕೀಲಿ), ಕೀಲಿ->sk_flags,
	    (pin != ಖಾಲಿ && *pin != '\0') ? " with-pin" : "");

	ಆದರೆ (sigp != ಖಾಲಿ)
		*sigp = ಖಾಲಿ;
	ಆದರೆ (lenp != ಖಾಲಿ)
		*lenp = 0;
	type = sshkey_type_plain(ಕೀಲಿ->type);
	ಆಯ್ಕೆ (type) {
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL
	ಸ್ಥಿತಿ ಕೀಲಿ_ECDSA_SK:
		alg = SSH_SK_ECDSA;
		ನಿಲ್ಲಿಸು;
#ಆದರೆ_ಅಂತ್ಯ /* WITH_OPENSSL */
	ಸ್ಥಿತಿ ಕೀಲಿ_ED25519_SK:
		alg = SSH_SK_ED25519;
		ನಿಲ್ಲಿಸು;
	ಪೂರ್ವನಿಯೋಜಿತ:
		ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_ವಾದ;
	}
	ಆದರೆ (provider_ಮಾರ್ಗ == ಖಾಲಿ ||
	    ಕೀಲಿ->sk_ಕೀಲಿ_handle == ಖಾಲಿ ||
	    ಕೀಲಿ->sk_application == ಖಾಲಿ || *ಕೀಲಿ->sk_application == '\0') {
		r = SSH_ERR_INVALID_ವಾದ;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((skp = sshsk_open(provider_ಮಾರ್ಗ)) == ಖಾಲಿ) {
		r = SSH_ERR_INVALID_FORMAT; /* XXX sshsk_open return code? */
		ಹೋಗು ಹೊರಹೋಗು;
	}
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ DEBUG_SK
	fprintf(stderr, "%s: sk_flags = 0x%02x, sk_application = \"%s\"\n",
	    __func__, ಕೀಲಿ->sk_flags, ಕೀಲಿ->sk_application);
	fprintf(stderr, "%s: sk_key_handle:\n", __func__);
	sshbuf_dump(ಕೀಲಿ->sk_ಕೀಲಿ_handle, stderr);
#ಆದರೆ_ಅಂತ್ಯ
	ಆದರೆ ((r = skp->sk_sign(alg, ದತ್ತಾಂಶ, datalen, ಕೀಲಿ->sk_application,
	    sshbuf_ptr(ಕೀಲಿ->sk_ಕೀಲಿ_handle), sshbuf_len(ಕೀಲಿ->sk_ಕೀಲಿ_handle),
	    ಕೀಲಿ->sk_flags, pin, opts, &resp)) != 0) {
		debug_f("sk_sign failed with code %d", r);
		r = skerr_ಗಮ್ಯ_ssherr(r);
		ಹೋಗು ಹೊರಹೋಗು;
	}
	/* Assemble signature */
	ಆದರೆ ((sig = sshbuf_new()) == ಖಾಲಿ) {
		r = SSH_ERR_ALLOC_FAIL;
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((r = sshbuf_put_cstring(sig, sshkey_ssh_name_plain(ಕೀಲಿ))) != 0) {
		error_fr(r, "compose outer");
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆಯ್ಕೆ (type) {
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_OPENSSL
	ಸ್ಥಿತಿ ಕೀಲಿ_ECDSA_SK:
		ಆದರೆ ((r = sshsk_ecdsa_sig(resp, sig)) != 0)
			ಹೋಗು ಹೊರಹೋಗು;
		ನಿಲ್ಲಿಸು;
#ಆದರೆ_ಅಂತ್ಯ /* WITH_OPENSSL */
	ಸ್ಥಿತಿ ಕೀಲಿ_ED25519_SK:
		ಆದರೆ ((r = sshsk_ed25519_sig(resp, sig)) != 0)
			ಹೋಗು ಹೊರಹೋಗು;
		ನಿಲ್ಲಿಸು;
	}
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ DEBUG_SK
	fprintf(stderr, "%s: sig_flags = 0x%02x, sig_counter = %u\n",
	    __func__, resp->flags, resp->counter);
	fprintf(stderr, "%s: data to sign:\n", __func__);
	sshbuf_dump_ದತ್ತಾಂಶ(ದತ್ತಾಂಶ, datalen, stderr);
	fprintf(stderr, "%s: sigbuf:\n", __func__);
	sshbuf_dump(sig, stderr);
#ಆದರೆ_ಅಂತ್ಯ
	ಆದರೆ (sigp != ಖಾಲಿ) {
		ಆದರೆ ((*sigp = ಸ್ಮರಣೆ_ಕೊಡು(sshbuf_len(sig))) == ಖಾಲಿ) {
			r = SSH_ERR_ALLOC_FAIL;
			ಹೋಗು ಹೊರಹೋಗು;
		}
		ಸ್ಮರಣೆ_ನಕಲು(*sigp, sshbuf_ptr(sig), sshbuf_len(sig));
	}
	ಆದರೆ (lenp != ಖಾಲಿ)
		*lenp = sshbuf_len(sig);
	/* success */
	r = 0;
 ಹೊರಹೋಗು:
	sshsk_free_options(opts);
	sshsk_free(skp);
	sshsk_free_sign_response(resp);
	sshbuf_free(sig);
	sshbuf_free(inner_sig);
	ಹಿಂತಿರುಗಿ r;
}

ಸ್ಥಿರ ಶೂನ್ಯ
sshsk_free_sk_resident_ಕೀಲಿಗಳು(ರಚನೆ sk_resident_ಕೀಲಿ **rks, ಗಾತ್ರ_t nrks)
{
	ಗಾತ್ರ_t i;

	ಆದರೆ (nrks == 0 || rks == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ;
	ಗಾಗಿ (i = 0; i < nrks; i++) {
		ಬಿಡುಗಡೆ(rks[i]->application);
		freezero(rks[i]->user_id, rks[i]->user_id_len);
		freezero(rks[i]->ಕೀಲಿ.ಕೀಲಿ_handle, rks[i]->ಕೀಲಿ.ಕೀಲಿ_handle_len);
		freezero(rks[i]->ಕೀಲಿ.ಬಹಿರಂಗ_ಕೀಲಿ, rks[i]->ಕೀಲಿ.ಬಹಿರಂಗ_ಕೀಲಿ_len);
		freezero(rks[i]->ಕೀಲಿ.signature, rks[i]->ಕೀಲಿ.signature_len);
		freezero(rks[i]->ಕೀಲಿ.attestation_cert,
		    rks[i]->ಕೀಲಿ.attestation_cert_len);
		freezero(rks[i], ಗಾತ್ರ(**rks));
	}
	ಬಿಡುಗಡೆ(rks);
}

ಸ್ಥಿರ ಶೂನ್ಯ
sshsk_free_resident_ಕೀಲಿ(ರಚನೆ sshsk_resident_ಕೀಲಿ *srk)
{
	ಆದರೆ (srk == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ;
	sshkey_free(srk->ಕೀಲಿ);
	freezero(srk->user_id, srk->user_id_len);
	ಬಿಡುಗಡೆ(srk);
}


ಶೂನ್ಯ
sshsk_free_resident_ಕೀಲಿಗಳು(ರಚನೆ sshsk_resident_ಕೀಲಿ **srks, ಗಾತ್ರ_t nsrks)
{
	ಗಾತ್ರ_t i;

	ಆದರೆ (srks == ಖಾಲಿ || nsrks == 0)
		ಹಿಂತಿರುಗಿ;

	ಗಾಗಿ (i = 0; i < nsrks; i++)
		sshsk_free_resident_ಕೀಲಿ(srks[i]);
	ಬಿಡುಗಡೆ(srks);
}

ಪೂರ್ಣಾಂಕ
sshsk_ತುಂಬು_resident(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *provider_ಮಾರ್ಗ, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *device,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *pin, u_int flags, ರಚನೆ sshsk_resident_ಕೀಲಿ ***srksp,
    ಗಾತ್ರ_t *nsrksp)
{
	ರಚನೆ sshsk_provider *skp = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ r = SSH_ERR_ಆಂತರಿಕ_ERROR;
	ರಚನೆ sk_resident_ಕೀಲಿ **rks = ಖಾಲಿ;
	ಗಾತ್ರ_t i, nrks = 0, nsrks = 0;
	ರಚನೆ sshkey *ಕೀಲಿ = ಖಾಲಿ;
	ರಚನೆ sshsk_resident_ಕೀಲಿ *srk = ಖಾಲಿ, **srks = ಖಾಲಿ, **tmp;
	uint8_t sk_flags;
	ರಚನೆ sk_option **opts = ಖಾಲಿ;

	debug_f("provider \"%s\"%s", provider_ಮಾರ್ಗ,
	    (pin != ಖಾಲಿ && *pin != '\0') ? ", have-pin": "");

	ಆದರೆ (srksp == ಖಾಲಿ || nsrksp == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ SSH_ERR_INVALID_ವಾದ;
	*srksp = ಖಾಲಿ;
	*nsrksp = 0;

	ಆದರೆ ((r = make_options(device, ಖಾಲಿ, &opts)) != 0)
		ಹೋಗು ಹೊರಹೋಗು;
	ಆದರೆ ((skp = sshsk_open(provider_ಮಾರ್ಗ)) == ಖಾಲಿ) {
		r = SSH_ERR_INVALID_FORMAT; /* XXX sshsk_open return code? */
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((r = skp->sk_ತುಂಬು_resident_ಕೀಲಿಗಳು(pin, opts, &rks, &nrks)) != 0) {
		error("Provider \"%s\" returned failure %d", provider_ಮಾರ್ಗ, r);
		r = skerr_ಗಮ್ಯ_ssherr(r);
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಗಾಗಿ (i = 0; i < nrks; i++) {
		debug3_f("rk %zu: slot %zu, alg %d, app \"%s\", uidlen %zu",
		    i, rks[i]->ಸ್ಥಾನ, rks[i]->alg, rks[i]->application,
		    rks[i]->user_id_len);
		/* XXX need better filter here */
		ಆದರೆ (ಅಕ್ಷರಸರಣಿ_ಹೋಲಿಕೆ(rks[i]->application, "ssh:", 4) != 0)
			ಮುಂದುವರಿ;
		ಆಯ್ಕೆ (rks[i]->alg) {
		ಸ್ಥಿತಿ SSH_SK_ECDSA:
		ಸ್ಥಿತಿ SSH_SK_ED25519:
			ನಿಲ್ಲಿಸು;
		ಪೂರ್ವನಿಯೋಜಿತ:
			ಮುಂದುವರಿ;
		}
		sk_flags = SSH_SK_USER_PRESENCE_REQD|SSH_SK_RESIDENT_ಕೀಲಿ;
		ಆದರೆ ((rks[i]->flags & SSH_SK_USER_VERIFICATION_REQD))
			sk_flags |= SSH_SK_USER_VERIFICATION_REQD;
		ಆದರೆ ((r = sshsk_ಕೀಲಿ_from_response(rks[i]->alg,
		    rks[i]->application, sk_flags, &rks[i]->ಕೀಲಿ, &ಕೀಲಿ)) != 0)
			ಹೋಗು ಹೊರಹೋಗು;
		ಆದರೆ ((srk = ಸೊನ್ನೆ_ಸ್ಮರಣೆ_ಕೊಡು(1, ಗಾತ್ರ(*srk))) == ಖಾಲಿ) {
			error_f("calloc failed");
			r = SSH_ERR_ALLOC_FAIL;
			ಹೋಗು ಹೊರಹೋಗು;
		}
		srk->ಕೀಲಿ = ಕೀಲಿ;
		ಕೀಲಿ = ಖಾಲಿ; /* transferred */
		ಆದರೆ ((srk->user_id = ಸೊನ್ನೆ_ಸ್ಮರಣೆ_ಕೊಡು(1, rks[i]->user_id_len)) == ಖಾಲಿ) {
			error_f("calloc failed");
			r = SSH_ERR_ALLOC_FAIL;
			ಹೋಗು ಹೊರಹೋಗು;
		}
		ಸ್ಮರಣೆ_ನಕಲು(srk->user_id, rks[i]->user_id, rks[i]->user_id_len);
		srk->user_id_len = rks[i]->user_id_len;
		ಆದರೆ ((tmp = recallocarray(srks, nsrks, nsrks + 1,
		    ಗಾತ್ರ(*tmp))) == ಖಾಲಿ) {
			error_f("recallocarray failed");
			r = SSH_ERR_ALLOC_FAIL;
			ಹೋಗು ಹೊರಹೋಗು;
		}
		srks = tmp;
		srks[nsrks++] = srk;
		srk = ಖಾಲಿ;
		/* XXX synthesise comment */
	}
	/* success */
	*srksp = srks;
	*nsrksp = nsrks;
	srks = ಖಾಲಿ;
	nsrks = 0;
	r = 0;
 ಹೊರಹೋಗು:
	sshsk_free_options(opts);
	sshsk_free(skp);
	sshsk_free_sk_resident_ಕೀಲಿಗಳು(rks, nrks);
	sshkey_free(ಕೀಲಿ);
	sshsk_free_resident_ಕೀಲಿ(srk);
	sshsk_free_resident_ಕೀಲಿಗಳು(srks, nsrks);
	ಹಿಂತಿರುಗಿ r;
}

#ಆದರೆ_ಅಂತ್ಯ /* ENABLE_SK */
