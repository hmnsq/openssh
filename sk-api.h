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

#ifndef _SK_API_H
#define _SK_API_H 1

#अन्तर्भाव <stddef.h>
#अन्तर्भाव <stdint.h>

/* Flags */
#define SSH_SK_USER_PRESENCE_REQD	0x01
#define SSH_SK_USER_VERIFICATION_REQD	0x04
#define SSH_SK_FORCE_OPERATION		0x10
#define SSH_SK_RESIDENT_किल्ली		0x20

/* Algs */
#define SSH_SK_ECDSA			0x00
#define SSH_SK_ED25519			0x01

/* Error codes */
#define SSH_SK_ERR_GENERAL		-1
#define SSH_SK_ERR_UNSUPPORTED		-2
#define SSH_SK_ERR_PIN_REQUIRED		-3
#define SSH_SK_ERR_DEVICE_NOT_FOUND	-4
#define SSH_SK_ERR_CREDENTIAL_EXISTS	-5

संरचना sk_enroll_response {
	uint8_t flags;
	uint8_t *public_किल्ली;
	माप_प्रकार public_किल्ली_len;
	uint8_t *किल्ली_handle;
	माप_प्रकार किल्ली_handle_len;
	uint8_t *signature;
	माप_प्रकार signature_len;
	uint8_t *attestation_cert;
	माप_प्रकार attestation_cert_len;
	uint8_t *authdata;
	माप_प्रकार authdata_len;
};

संरचना sk_sign_response {
	uint8_t flags;
	uint32_t counter;
	uint8_t *sig_r;
	माप_प्रकार sig_r_len;
	uint8_t *sig_s;
	माप_प्रकार sig_s_len;
};

संरचना sk_resident_किल्ली {
	uint32_t alg;
	माप_प्रकार slot;
	अक्षर *application;
	संरचना sk_enroll_response किल्ली;
	uint8_t flags;
	uint8_t *user_id;
	माप_प्रकार user_id_len;
};

संरचना sk_option {
	अक्षर *name;
	अक्षर *मूल्य;
	uint8_t required;
};

#define SSH_SK_VERSION_MAJOR		0x000a0000 /* current API version */
#define SSH_SK_VERSION_MAJOR_MASK	0xffff0000

/* Return the version of the middleware API */
uint32_t sk_api_version(शून्य);

/* Enroll a U2F key (private key generation) */
पूर्णांक sk_enroll(uint32_t alg, स्थिरांक uint8_t *challenge, माप_प्रकार challenge_len,
    स्थिरांक अक्षर *application, uint8_t flags, स्थिरांक अक्षर *pin,
    संरचना sk_option **options, संरचना sk_enroll_response **enroll_response);

/* Sign a challenge */
पूर्णांक sk_sign(uint32_t alg, स्थिरांक uint8_t *data, माप_प्रकार data_len,
    स्थिरांक अक्षर *application, स्थिरांक uint8_t *किल्ली_handle, माप_प्रकार किल्ली_handle_len,
    uint8_t flags, स्थिरांक अक्षर *pin, संरचना sk_option **options,
    संरचना sk_sign_response **sign_response);

/* Enumerate all resident keys */
पूर्णांक sk_load_resident_किल्ल्या(स्थिरांक अक्षर *pin, संरचना sk_option **options,
    संरचना sk_resident_किल्ली ***rks, माप_प्रकार *nrks);

#endif /* _SK_API_H */
