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

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ _SK_API_H
#ವ್ಯಾಖ್ಯಾನಿಸು _SK_API_H 1

#ಅನ್ತರ್ಭಾವ <stddef.h>
#ಅನ್ತರ್ಭಾವ <stdint.h>

/* Flags */
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_SK_USER_PRESENCE_REQD	0x01
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_SK_USER_VERIFICATION_REQD	0x04
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_SK_FORCE_OPERATION		0x10
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_SK_RESIDENT_ಕೀಲಿ		0x20

/* Algs */
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_SK_ECDSA			0x00
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_SK_ED25519			0x01

/* Error codes */
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_SK_ERR_GENERAL		-1
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_SK_ERR_UNSUPPORTED		-2
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_SK_ERR_PIN_REQUIRED		-3
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_SK_ERR_DEVICE_NOT_ಸಿಕ್ಕಿತು	-4
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_SK_ERR_CREDENTIAL_EXISTS	-5

ರಚನೆ sk_enroll_response {
	uint8_t flags;
	uint8_t *ಬಹಿರಂಗ_ಕೀಲಿ;
	ಗಾತ್ರ_t ಬಹಿರಂಗ_ಕೀಲಿ_len;
	uint8_t *ಕೀಲಿ_handle;
	ಗಾತ್ರ_t ಕೀಲಿ_handle_len;
	uint8_t *signature;
	ಗಾತ್ರ_t signature_len;
	uint8_t *attestation_cert;
	ಗಾತ್ರ_t attestation_cert_len;
	uint8_t *authdata;
	ಗಾತ್ರ_t authdata_len;
};

ರಚನೆ sk_sign_response {
	uint8_t flags;
	uint32_t counter;
	uint8_t *sig_r;
	ಗಾತ್ರ_t sig_r_len;
	uint8_t *sig_s;
	ಗಾತ್ರ_t sig_s_len;
};

ರಚನೆ sk_resident_ಕೀಲಿ {
	uint32_t alg;
	ಗಾತ್ರ_t ಸ್ಥಾನ;
	ಅಕ್ಷರ *application;
	ರಚನೆ sk_enroll_response ಕೀಲಿ;
	uint8_t flags;
	uint8_t *user_id;
	ಗಾತ್ರ_t user_id_len;
};

ರಚನೆ sk_option {
	ಅಕ್ಷರ *name;
	ಅಕ್ಷರ *ಮೌಲ್ಯ;
	uint8_t required;
};

#ವ್ಯಾಖ್ಯಾನಿಸು SSH_SK_ಆವೃತ್ತಿ_MAJOR		0x000a0000 /* current API version */
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_SK_ಆವೃತ್ತಿ_MAJOR_ಮುಖವಾಡ	0xffff0000

/* Return the version of the middleware API */
uint32_t sk_api_ಆವೃತ್ತಿ(ಶೂನ್ಯ);

/* Enroll a U2F key (private key generation) */
ಪೂರ್ಣಾಂಕ sk_enroll(uint32_t alg, ಸ್ಥಿರಾಂಕ uint8_t *challenge, ಗಾತ್ರ_t challenge_len,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *application, uint8_t flags, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *pin,
    ರಚನೆ sk_option **options, ರಚನೆ sk_enroll_response **enroll_response);

/* Sign a challenge */
ಪೂರ್ಣಾಂಕ sk_sign(uint32_t alg, ಸ್ಥಿರಾಂಕ uint8_t *ದತ್ತಾಂಶ, ಗಾತ್ರ_t ದತ್ತಾಂಶ_len,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *application, ಸ್ಥಿರಾಂಕ uint8_t *ಕೀಲಿ_handle, ಗಾತ್ರ_t ಕೀಲಿ_handle_len,
    uint8_t flags, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *pin, ರಚನೆ sk_option **options,
    ರಚನೆ sk_sign_response **sign_response);

/* Enumerate all resident keys */
ಪೂರ್ಣಾಂಕ sk_ತುಂಬು_resident_ಕೀಲಿಗಳು(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *pin, ರಚನೆ sk_option **options,
    ರಚನೆ sk_resident_ಕೀಲಿ ***rks, ಗಾತ್ರ_t *nrks);

#ಆದರೆ_ಅಂತ್ಯ /* _SK_API_H */
