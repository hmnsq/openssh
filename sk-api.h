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

#اگر_تعریف_نشده _SK_API_H
#تعریف_کن _SK_API_H 1

#ضمن <stddef.h>
#ضمن <stdint.h>

/* Flags */
#تعریف_کن SSH_SK_USER_PRESENCE_REQD	0x01
#تعریف_کن SSH_SK_USER_VERIFICATION_REQD	0x04
#تعریف_کن SSH_SK_FORCE_OPERATION		0x10
#تعریف_کن SSH_SK_RESIDENT_کلید		0x20

/* Algs */
#تعریف_کن SSH_SK_ECDSA			0x00
#تعریف_کن SSH_SK_ED25519			0x01

/* Error codes */
#تعریف_کن SSH_SK_ERR_GENERAL		-1
#تعریف_کن SSH_SK_ERR_UNSUPPORTED		-2
#تعریف_کن SSH_SK_ERR_PIN_REQUIRED		-3
#تعریف_کن SSH_SK_ERR_DEVICE_NOT_یافت	-4
#تعریف_کن SSH_SK_ERR_CREDENTIAL_EXISTS	-5

بنية sk_enroll_response {
	uint8_t flags;
	uint8_t *عمومی_کلید;
	اندازه_t عمومی_کلید_len;
	uint8_t *کلید_handle;
	اندازه_t کلید_handle_len;
	uint8_t *signature;
	اندازه_t signature_len;
	uint8_t *attestation_cert;
	اندازه_t attestation_cert_len;
	uint8_t *authdata;
	اندازه_t authdata_len;
};

بنية sk_sign_response {
	uint8_t flags;
	uint32_t counter;
	uint8_t *sig_r;
	اندازه_t sig_r_len;
	uint8_t *sig_s;
	اندازه_t sig_s_len;
};

بنية sk_resident_کلید {
	uint32_t alg;
	اندازه_t جایگاه;
	حرف *application;
	بنية sk_enroll_response کلید;
	uint8_t flags;
	uint8_t *user_id;
	اندازه_t user_id_len;
};

بنية sk_option {
	حرف *name;
	حرف *مقدار;
	uint8_t required;
};

#تعریف_کن SSH_SK_نسخه_MAJOR		0x000a0000 /* current API version */
#تعریف_کن SSH_SK_نسخه_MAJOR_ماسک	0xffff0000

/* Return the version of the middleware API */
uint32_t sk_api_نسخه(فراغ);

/* Enroll a U2F key (private key generation) */
صحيح sk_enroll(uint32_t alg, ثابت uint8_t *challenge, اندازه_t challenge_len,
    ثابت حرف *application, uint8_t flags, ثابت حرف *pin,
    بنية sk_option **options, بنية sk_enroll_response **enroll_response);

/* Sign a challenge */
صحيح sk_sign(uint32_t alg, ثابت uint8_t *داده, اندازه_t داده_len,
    ثابت حرف *application, ثابت uint8_t *کلید_handle, اندازه_t کلید_handle_len,
    uint8_t flags, ثابت حرف *pin, بنية sk_option **options,
    بنية sk_sign_response **sign_response);

/* Enumerate all resident keys */
صحيح sk_بارگیری_resident_کلیدها(ثابت حرف *pin, بنية sk_option **options,
    بنية sk_resident_کلید ***rks, اندازه_t *nrks);

#پایان_اگر /* _SK_API_H */
