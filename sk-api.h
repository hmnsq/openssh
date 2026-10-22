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

#यदि_अपरिभाषितम् _SK_API_H
#परिभाषय _SK_API_H 1

#अन्तर्भाव <stddef.h>
#अन्तर्भाव <stdint.h>

/* Flags */
#परिभाषय SSH_SK_USER_PRESENCE_REQD	0x01
#परिभाषय SSH_SK_USER_VERIFICATION_REQD	0x04
#परिभाषय SSH_SK_FORCE_OPERATION		0x10
#परिभाषय SSH_SK_RESIDENT_कुञ्चिका		0x20

/* Algs */
#परिभाषय SSH_SK_ECDSA			0x00
#परिभाषय SSH_SK_ED25519			0x01

/* Error codes */
#परिभाषय SSH_SK_ERR_GENERAL		-1
#परिभाषय SSH_SK_ERR_UNSUPPORTED		-2
#परिभाषय SSH_SK_ERR_PIN_REQUIRED		-3
#परिभाषय SSH_SK_ERR_DEVICE_NOT_प्राप्तम्	-4
#परिभाषय SSH_SK_ERR_CREDENTIAL_EXISTS	-5

संरचना sk_enroll_response {
	uint8_t flags;
	uint8_t *लौकिकम्_कुञ्चिका;
	आकार_t लौकिकम्_कुञ्चिका_len;
	uint8_t *कुञ्चिका_handle;
	आकार_t कुञ्चिका_handle_len;
	uint8_t *signature;
	आकार_t signature_len;
	uint8_t *attestation_cert;
	आकार_t attestation_cert_len;
	uint8_t *authdata;
	आकार_t authdata_len;
};

संरचना sk_sign_response {
	uint8_t flags;
	uint32_t गणक;
	uint8_t *sig_r;
	आकार_t sig_r_len;
	uint8_t *sig_s;
	आकार_t sig_s_len;
};

संरचना sk_resident_कुञ्चिका {
	uint32_t alg;
	आकार_t slot;
	वर्ण *application;
	संरचना sk_enroll_response कुञ्चिका;
	uint8_t flags;
	uint8_t *user_id;
	आकार_t user_id_len;
};

संरचना sk_option {
	वर्ण *name;
	वर्ण *मानम्;
	uint8_t required;
};

#परिभाषय SSH_SK_संस्करणम्_MAJOR		0x000a0000 /* current API version */
#परिभाषय SSH_SK_संस्करणम्_MAJOR_आवरणम्	0xffff0000

/* Return the version of the middleware API */
uint32_t sk_api_संस्करणम्(शून्य);

/* Enroll a U2F key (private key generation) */
पूर्णाङ्क sk_enroll(uint32_t alg, ध्रुव uint8_t *challenge, आकार_t challenge_len,
    ध्रुव वर्ण *application, uint8_t flags, ध्रुव वर्ण *pin,
    संरचना sk_option **options, संरचना sk_enroll_response **enroll_response);

/* Sign a challenge */
पूर्णाङ्क sk_sign(uint32_t alg, ध्रुव uint8_t *दत्त, आकार_t दत्त_len,
    ध्रुव वर्ण *application, ध्रुव uint8_t *कुञ्चिका_handle, आकार_t कुञ्चिका_handle_len,
    uint8_t flags, ध्रुव वर्ण *pin, संरचना sk_option **options,
    संरचना sk_sign_response **sign_response);

/* Enumerate all resident keys */
पूर्णाङ्क sk_आरोपय_resident_कुञ्चिकाः(ध्रुव वर्ण *pin, संरचना sk_option **options,
    संरचना sk_resident_कुञ्चिका ***rks, आकार_t *nrks);

#यदि_अन्तः /* _SK_API_H */
