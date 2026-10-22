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

#અન્તર્ભાવ <stddef.h>
#અન્તર્ભાવ <stdint.h>

/* Flags */
#define SSH_SK_USER_PRESENCE_REQD	0x01
#define SSH_SK_USER_VERIFICATION_REQD	0x04
#define SSH_SK_FORCE_OPERATION		0x10
#define SSH_SK_RESIDENT_ચાવી		0x20

/* Algs */
#define SSH_SK_ECDSA			0x00
#define SSH_SK_ED25519			0x01

/* Error codes */
#define SSH_SK_ERR_GENERAL		-1
#define SSH_SK_ERR_UNSUPPORTED		-2
#define SSH_SK_ERR_PIN_REQUIRED		-3
#define SSH_SK_ERR_DEVICE_NOT_FOUND	-4
#define SSH_SK_ERR_CREDENTIAL_EXISTS	-5

સંરચના sk_enroll_response {
	uint8_t flags;
	uint8_t *public_ચાવી;
	size_t public_ચાવી_len;
	uint8_t *ચાવી_handle;
	size_t ચાવી_handle_len;
	uint8_t *signature;
	size_t signature_len;
	uint8_t *attestation_cert;
	size_t attestation_cert_len;
	uint8_t *authdata;
	size_t authdata_len;
};

સંરચના sk_sign_response {
	uint8_t flags;
	uint32_t counter;
	uint8_t *sig_r;
	size_t sig_r_len;
	uint8_t *sig_s;
	size_t sig_s_len;
};

સંરચના sk_resident_ચાવી {
	uint32_t alg;
	size_t slot;
	અક્ષર *application;
	સંરચના sk_enroll_response ચાવી;
	uint8_t flags;
	uint8_t *user_id;
	size_t user_id_len;
};

સંરચના sk_option {
	અક્ષર *name;
	અક્ષર *કિંમત;
	uint8_t required;
};

#define SSH_SK_VERSION_MAJOR		0x000a0000 /* current API version */
#define SSH_SK_VERSION_MAJOR_MASK	0xffff0000

/* Return the version of the middleware API */
uint32_t sk_api_version(શૂન્ય);

/* Enroll a U2F key (private key generation) */
પૂર્ણાંક sk_enroll(uint32_t alg, અચલ uint8_t *challenge, size_t challenge_len,
    અચલ અક્ષર *application, uint8_t flags, અચલ અક્ષર *pin,
    સંરચના sk_option **options, સંરચના sk_enroll_response **enroll_response);

/* Sign a challenge */
પૂર્ણાંક sk_sign(uint32_t alg, અચલ uint8_t *data, size_t data_len,
    અચલ અક્ષર *application, અચલ uint8_t *ચાવી_handle, size_t ચાવી_handle_len,
    uint8_t flags, અચલ અક્ષર *pin, સંરચના sk_option **options,
    સંરચના sk_sign_response **sign_response);

/* Enumerate all resident keys */
પૂર્ણાંક sk_load_resident_ચાવીઓ(અચલ અક્ષર *pin, સંરચના sk_option **options,
    સંરચના sk_resident_ચાવી ***rks, size_t *nrks);

#endif /* _SK_API_H */
