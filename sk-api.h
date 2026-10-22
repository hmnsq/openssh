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

#অন্তর্ভাব <stddef.h>
#অন্তর্ভাব <stdint.h>

/* Flags */
#define SSH_SK_USER_PRESENCE_REQD	0x01
#define SSH_SK_USER_VERIFICATION_REQD	0x04
#define SSH_SK_FORCE_OPERATION		0x10
#define SSH_SK_RESIDENT_চাবি		0x20

/* Algs */
#define SSH_SK_ECDSA			0x00
#define SSH_SK_ED25519			0x01

/* Error codes */
#define SSH_SK_ERR_GENERAL		-1
#define SSH_SK_ERR_UNSUPPORTED		-2
#define SSH_SK_ERR_PIN_REQUIRED		-3
#define SSH_SK_ERR_DEVICE_NOT_FOUND	-4
#define SSH_SK_ERR_CREDENTIAL_EXISTS	-5

কাঠামো sk_enroll_response {
	uint8_t flags;
	uint8_t *public_চাবি;
	আকার_t public_চাবি_len;
	uint8_t *চাবি_handle;
	আকার_t চাবি_handle_len;
	uint8_t *signature;
	আকার_t signature_len;
	uint8_t *attestation_cert;
	আকার_t attestation_cert_len;
	uint8_t *authdata;
	আকার_t authdata_len;
};

কাঠামো sk_sign_response {
	uint8_t flags;
	uint32_t গণক;
	uint8_t *sig_r;
	আকার_t sig_r_len;
	uint8_t *sig_s;
	আকার_t sig_s_len;
};

কাঠামো sk_resident_চাবি {
	uint32_t alg;
	আকার_t slot;
	অক্ষর *application;
	কাঠামো sk_enroll_response চাবি;
	uint8_t flags;
	uint8_t *user_id;
	আকার_t user_id_len;
};

কাঠামো sk_option {
	অক্ষর *name;
	অক্ষর *মান;
	uint8_t required;
};

#define SSH_SK_VERSION_MAJOR		0x000a0000 /* current API version */
#define SSH_SK_VERSION_MAJOR_MASK	0xffff0000

/* Return the version of the middleware API */
uint32_t sk_api_version(শূন্য);

/* Enroll a U2F key (private key generation) */
পূর্ণসংখ্যা sk_enroll(uint32_t alg, ধ্রুবক uint8_t *challenge, আকার_t challenge_len,
    ধ্রুবক অক্ষর *application, uint8_t flags, ধ্রুবক অক্ষর *pin,
    কাঠামো sk_option **options, কাঠামো sk_enroll_response **enroll_response);

/* Sign a challenge */
পূর্ণসংখ্যা sk_sign(uint32_t alg, ধ্রুবক uint8_t *তথ্য, আকার_t তথ্য_len,
    ধ্রুবক অক্ষর *application, ধ্রুবক uint8_t *চাবি_handle, আকার_t চাবি_handle_len,
    uint8_t flags, ধ্রুবক অক্ষর *pin, কাঠামো sk_option **options,
    কাঠামো sk_sign_response **sign_response);

/* Enumerate all resident keys */
পূর্ণসংখ্যা sk_load_resident_চাবিগুলি(ধ্রুবক অক্ষর *pin, কাঠামো sk_option **options,
    কাঠামো sk_resident_চাবি ***rks, আকার_t *nrks);

#endif /* _SK_API_H */
