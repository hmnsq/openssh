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

#अगर_अघोषित _SK_API_H
#घोषणा _SK_API_H 1

#समावेश <stddef.h>
#समावेश <stdint.h>

/* Flags */
#घोषणा SSH_SK_USER_PRESENCE_REQD	0x01
#घोषणा SSH_SK_USER_VERIFICATION_REQD	0x04
#घोषणा SSH_SK_FORCE_OPERATION		0x10
#घोषणा SSH_SK_RESIDENT_कुंजी		0x20

/* Algs */
#घोषणा SSH_SK_ECDSA			0x00
#घोषणा SSH_SK_ED25519			0x01

/* Error codes */
#घोषणा SSH_SK_ERR_GENERAL		-1
#घोषणा SSH_SK_ERR_UNSUPPORTED		-2
#घोषणा SSH_SK_ERR_PIN_REQUIRED		-3
#घोषणा SSH_SK_ERR_DEVICE_NOT_FOUND	-4
#घोषणा SSH_SK_ERR_CREDENTIAL_EXISTS	-5

काष्ठा sk_enroll_response {
	uint8_t flags;
	uint8_t *public_कुंजी;
	माप_प्रकार public_कुंजी_len;
	uint8_t *कुंजी_handle;
	माप_प्रकार कुंजी_handle_len;
	uint8_t *signature;
	माप_प्रकार signature_len;
	uint8_t *attestation_cert;
	माप_प्रकार attestation_cert_len;
	uint8_t *authdata;
	माप_प्रकार authdata_len;
};

काष्ठा sk_sign_response {
	uint8_t flags;
	uint32_t गणक;
	uint8_t *sig_r;
	माप_प्रकार sig_r_len;
	uint8_t *sig_s;
	माप_प्रकार sig_s_len;
};

काष्ठा sk_resident_कुंजी {
	uint32_t alg;
	माप_प्रकार slot;
	अक्षर *application;
	काष्ठा sk_enroll_response कुंजी;
	uint8_t flags;
	uint8_t *user_id;
	माप_प्रकार user_id_len;
};

काष्ठा sk_option {
	अक्षर *name;
	अक्षर *मूल्य;
	uint8_t required;
};

#घोषणा SSH_SK_VERSION_MAJOR		0x000a0000 /* current API version */
#घोषणा SSH_SK_VERSION_MAJOR_MASK	0xffff0000

/* Return the version of the middleware API */
uint32_t sk_api_version(व्योम);

/* Enroll a U2F key (private key generation) */
पूर्णांक sk_enroll(uint32_t alg, स्थिर uint8_t *challenge, माप_प्रकार challenge_len,
    स्थिर अक्षर *application, uint8_t flags, स्थिर अक्षर *pin,
    काष्ठा sk_option **options, काष्ठा sk_enroll_response **enroll_response);

/* Sign a challenge */
पूर्णांक sk_sign(uint32_t alg, स्थिर uint8_t *तथ्य, माप_प्रकार तथ्य_len,
    स्थिर अक्षर *application, स्थिर uint8_t *कुंजी_handle, माप_प्रकार कुंजी_handle_len,
    uint8_t flags, स्थिर अक्षर *pin, काष्ठा sk_option **options,
    काष्ठा sk_sign_response **sign_response);

/* Enumerate all resident keys */
पूर्णांक sk_load_resident_कुंजियाँ(स्थिर अक्षर *pin, काष्ठा sk_option **options,
    काष्ठा sk_resident_कुंजी ***rks, माप_प्रकार *nrks);

#पूर्ण_अगर /* _SK_API_H */
