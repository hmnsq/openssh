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

#جيڪڏهن_وصف_نه_ٿيل _SK_API_H
#وصف_ڪريو _SK_API_H 1

#ضمن <stddef.h>
#ضمن <stdint.h>

/* Flags */
#وصف_ڪريو SSH_SK_USER_PRESENCE_REQD	0x01
#وصف_ڪريو SSH_SK_USER_VERIFICATION_REQD	0x04
#وصف_ڪريو SSH_SK_FORCE_OPERATION		0x10
#وصف_ڪريو SSH_SK_RESIDENT_ڪنجي		0x20

/* Algs */
#وصف_ڪريو SSH_SK_ECDSA			0x00
#وصف_ڪريو SSH_SK_ED25519			0x01

/* Error codes */
#وصف_ڪريو SSH_SK_ERR_GENERAL		-1
#وصف_ڪريو SSH_SK_ERR_UNSUPPORTED		-2
#وصف_ڪريو SSH_SK_ERR_PIN_REQUIRED		-3
#وصف_ڪريو SSH_SK_ERR_DEVICE_NOT_مليو	-4
#وصف_ڪريو SSH_SK_ERR_CREDENTIAL_EXISTS	-5

بنية sk_enroll_response {
	uint8_t flags;
	uint8_t *عوامي_ڪنجي;
	سائيز_t عوامي_ڪنجي_len;
	uint8_t *ڪنجي_handle;
	سائيز_t ڪنجي_handle_len;
	uint8_t *signature;
	سائيز_t signature_len;
	uint8_t *attestation_cert;
	سائيز_t attestation_cert_len;
	uint8_t *authdata;
	سائيز_t authdata_len;
};

بنية sk_sign_response {
	uint8_t flags;
	uint32_t counter;
	uint8_t *sig_r;
	سائيز_t sig_r_len;
	uint8_t *sig_s;
	سائيز_t sig_s_len;
};

بنية sk_resident_ڪنجي {
	uint32_t alg;
	سائيز_t جڳهه;
	حرف *application;
	بنية sk_enroll_response ڪنجي;
	uint8_t flags;
	uint8_t *user_id;
	سائيز_t user_id_len;
};

بنية sk_option {
	حرف *name;
	حرف *قدر;
	uint8_t required;
};

#وصف_ڪريو SSH_SK_نسخو_MAJOR		0x000a0000 /* current API version */
#وصف_ڪريو SSH_SK_نسخو_MAJOR_نقاب	0xffff0000

/* Return the version of the middleware API */
uint32_t sk_api_نسخو(فراغ);

/* Enroll a U2F key (private key generation) */
صحيح sk_enroll(uint32_t alg, ثابت uint8_t *challenge, سائيز_t challenge_len,
    ثابت حرف *application, uint8_t flags, ثابت حرف *pin,
    بنية sk_option **options, بنية sk_enroll_response **enroll_response);

/* Sign a challenge */
صحيح sk_sign(uint32_t alg, ثابت uint8_t *معلومات, سائيز_t معلومات_len,
    ثابت حرف *application, ثابت uint8_t *ڪنجي_handle, سائيز_t ڪنجي_handle_len,
    uint8_t flags, ثابت حرف *pin, بنية sk_option **options,
    بنية sk_sign_response **sign_response);

/* Enumerate all resident keys */
صحيح sk_ڀريو_resident_ڪنجيون(ثابت حرف *pin, بنية sk_option **options,
    بنية sk_resident_ڪنجي ***rks, سائيز_t *nrks);

#جيڪڏهن_پورو /* _SK_API_H */
