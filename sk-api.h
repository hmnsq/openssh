/* $OpenBSD: sk-api.h,v 1.15 2022/07/20 03:29:14 djm Exp $ */
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

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ _SK_API_H
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ _SK_API_H 1

#ਅਨ੍ਤਰ੍ਭਾਵ <stddef.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdint.h>

/* Flags */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_SK_USER_PRESENCE_REQD	0x01
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_SK_USER_VERIFICATION_REQD	0x04
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_SK_FORCE_OPERATION		0x10
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_SK_RESIDENT_ਕੁੰਜੀ		0x20

/* Algs */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_SK_ECDSA			0x00
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_SK_ED25519			0x01

/* Error codes */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_SK_ERR_GENERAL		-1
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_SK_ERR_UNSUPPORTED		-2
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_SK_ERR_PIN_REQUIRED		-3
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_SK_ERR_DEVICE_NOT_ਮਿਲਿਆ	-4
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_SK_ERR_CREDENTIAL_EXISTS	-5

ਬਣਤਰ sk_enroll_response {
	uint8_t flags;
	uint8_t *ਜਨਤਕ_ਕੁੰਜੀ;
	ਮਾਪ_t ਜਨਤਕ_ਕੁੰਜੀ_len;
	uint8_t *ਕੁੰਜੀ_handle;
	ਮਾਪ_t ਕੁੰਜੀ_handle_len;
	uint8_t *signature;
	ਮਾਪ_t signature_len;
	uint8_t *attestation_cert;
	ਮਾਪ_t attestation_cert_len;
	uint8_t *authdata;
	ਮਾਪ_t authdata_len;
};

ਬਣਤਰ sk_sign_response {
	uint8_t flags;
	uint32_t counter;
	uint8_t *sig_r;
	ਮਾਪ_t sig_r_len;
	uint8_t *sig_s;
	ਮਾਪ_t sig_s_len;
};

ਬਣਤਰ sk_resident_ਕੁੰਜੀ {
	uint32_t alg;
	ਮਾਪ_t ਥਾਂ;
	ਅੱਖਰ *application;
	ਬਣਤਰ sk_enroll_response ਕੁੰਜੀ;
	uint8_t flags;
	uint8_t *user_id;
	ਮਾਪ_t user_id_len;
};

ਬਣਤਰ sk_option {
	ਅੱਖਰ *name;
	ਅੱਖਰ *ਮੁੱਲ;
	uint8_t required;
};

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_SK_ਸੰਸਕਰਣ_MAJOR		0x000a0000 /* current API version */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_SK_ਸੰਸਕਰਣ_MAJOR_ਨਕਾਬ	0xffff0000

/* Return the version of the middleware API */
uint32_t sk_api_ਸੰਸਕਰਣ(ਖਾਲੀ);

/* Enroll a U2F key (private key generation) */
ਪੂਰਨ sk_enroll(uint32_t alg, ਅਚਲ uint8_t *challenge, ਮਾਪ_t challenge_len,
    ਅਚਲ ਅੱਖਰ *application, uint8_t flags, ਅਚਲ ਅੱਖਰ *pin,
    ਬਣਤਰ sk_option **options, ਬਣਤਰ sk_enroll_response **enroll_response);

/* Sign a challenge */
ਪੂਰਨ sk_sign(uint32_t alg, ਅਚਲ uint8_t *ਅੰਕੜੇ, ਮਾਪ_t ਅੰਕੜੇ_len,
    ਅਚਲ ਅੱਖਰ *application, ਅਚਲ uint8_t *ਕੁੰਜੀ_handle, ਮਾਪ_t ਕੁੰਜੀ_handle_len,
    uint8_t flags, ਅਚਲ ਅੱਖਰ *pin, ਬਣਤਰ sk_option **options,
    ਬਣਤਰ sk_sign_response **sign_response);

/* Enumerate all resident keys */
ਪੂਰਨ sk_ਲੱਦੋ_resident_ਕੁੰਜੀਆਂ(ਅਚਲ ਅੱਖਰ *pin, ਬਣਤਰ sk_option **options,
    ਬਣਤਰ sk_resident_ਕੁੰਜੀ ***rks, ਮਾਪ_t *nrks);

#ਜੇ_ਅੰਤ /* _SK_API_H */
