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

#నిర్వచితం_కాకపోతే _SK_API_H
#నిర్వచించు _SK_API_H 1

#అన్తర్భావ <stddef.h>
#అన్తర్భావ <stdint.h>

/* Flags */
#నిర్వచించు SSH_SK_USER_PRESENCE_REQD	0x01
#నిర్వచించు SSH_SK_USER_VERIFICATION_REQD	0x04
#నిర్వచించు SSH_SK_FORCE_OPERATION		0x10
#నిర్వచించు SSH_SK_RESIDENT_కీలకం		0x20

/* Algs */
#నిర్వచించు SSH_SK_ECDSA			0x00
#నిర్వచించు SSH_SK_ED25519			0x01

/* Error codes */
#నిర్వచించు SSH_SK_ERR_GENERAL		-1
#నిర్వచించు SSH_SK_ERR_UNSUPPORTED		-2
#నిర్వచించు SSH_SK_ERR_PIN_REQUIRED		-3
#నిర్వచించు SSH_SK_ERR_DEVICE_NOT_దొరికింది	-4
#నిర్వచించు SSH_SK_ERR_CREDENTIAL_EXISTS	-5

నిర్మాణం sk_enroll_response {
	uint8_t flags;
	uint8_t *ప్రజా_కీలకం;
	కొలత_t ప్రజా_కీలకం_len;
	uint8_t *కీలకం_handle;
	కొలత_t కీలకం_handle_len;
	uint8_t *signature;
	కొలత_t signature_len;
	uint8_t *attestation_cert;
	కొలత_t attestation_cert_len;
	uint8_t *authdata;
	కొలత_t authdata_len;
};

నిర్మాణం sk_sign_response {
	uint8_t flags;
	uint32_t counter;
	uint8_t *sig_r;
	కొలత_t sig_r_len;
	uint8_t *sig_s;
	కొలత_t sig_s_len;
};

నిర్మాణం sk_resident_కీలకం {
	uint32_t alg;
	కొలత_t స్థానం;
	అక్షరం *application;
	నిర్మాణం sk_enroll_response కీలకం;
	uint8_t flags;
	uint8_t *user_id;
	కొలత_t user_id_len;
};

నిర్మాణం sk_option {
	అక్షరం *name;
	అక్షరం *విలువ;
	uint8_t required;
};

#నిర్వచించు SSH_SK_సంస్కరణ_MAJOR		0x000a0000 /* current API version */
#నిర్వచించు SSH_SK_సంస్కరణ_MAJOR_ముసుగు	0xffff0000

/* Return the version of the middleware API */
uint32_t sk_api_సంస్కరణ(శూన్య);

/* Enroll a U2F key (private key generation) */
పూర్ణాంకం sk_enroll(uint32_t alg, స్థిరరాశి uint8_t *challenge, కొలత_t challenge_len,
    స్థిరరాశి అక్షరం *application, uint8_t flags, స్థిరరాశి అక్షరం *pin,
    నిర్మాణం sk_option **options, నిర్మాణం sk_enroll_response **enroll_response);

/* Sign a challenge */
పూర్ణాంకం sk_sign(uint32_t alg, స్థిరరాశి uint8_t *దత్తాంశం, కొలత_t దత్తాంశం_len,
    స్థిరరాశి అక్షరం *application, స్థిరరాశి uint8_t *కీలకం_handle, కొలత_t కీలకం_handle_len,
    uint8_t flags, స్థిరరాశి అక్షరం *pin, నిర్మాణం sk_option **options,
    నిర్మాణం sk_sign_response **sign_response);

/* Enumerate all resident keys */
పూర్ణాంకం sk_ఎక్కించు_resident_కీలకాలు(స్థిరరాశి అక్షరం *pin, నిర్మాణం sk_option **options,
    నిర్మాణం sk_resident_కీలకం ***rks, కొలత_t *nrks);

#అయితే_ముగింపు /* _SK_API_H */
