/* $OpenBSD: ssh-sk.h,v 1.11 2021/10/28 02:54:18 djm Exp $ */
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

#ifndef _SSH_SK_H
#define _SSH_SK_H 1

সংরচনা sshbuf;
সংরচনা sshkey;
সংরচনা sk_option;

/* Version of protocol expected from ssh-sk-helper */
#define SSH_SK_HELPER_VERSION		5

/* ssh-sk-helper messages */
#define SSH_SK_HELPER_ERROR		0	/* Only valid H->C */
#define SSH_SK_HELPER_SIGN		1
#define SSH_SK_HELPER_ENROLL		2
#define SSH_SK_HELPER_LOAD_RESIDENT	3

সংরচনা sshsk_resident_চাবি {
	সংরচনা sshkey *চাবি;
	uint8_t *user_id;
	size_t user_id_len;
};

/*
 * Enroll (generate) a new security-key hosted private key of given type
 * via the specified provider middleware.
 * If challenge_buf is NULL then a random 256 bit challenge will be used.
 *
 * Returns 0 on success or a ssherr.h error code on failure.
 *
 * If successful and the attest_data buffer is not NULL then attestation
 * information is placed there.
 */
পূর্ণাঙ্ক sshsk_enroll(পূর্ণাঙ্ক type, ধ্রুব বর্ণ *provider_path, ধ্রুব বর্ণ *device,
    ধ্রুব বর্ণ *application, ধ্রুব বর্ণ *userid, uint8_t flags,
    ধ্রুব বর্ণ *pin, সংরচনা sshbuf *challenge_buf,
    সংরচনা sshkey **keyp, সংরচনা sshbuf *attest);

/*
 * Calculate an ECDSA_SK or ED25519_SK signature using the specified key
 * and provider middleware.
 *
 * Returns 0 on success or a ssherr.h error code on failure.
 */
পূর্ণাঙ্ক sshsk_sign(ধ্রুব বর্ণ *provider_path, সংরচনা sshkey *চাবি,
    u_char **sigp, size_t *lenp, ধ্রুব u_char *data, size_t datalen,
    u_int compat, ধ্রুব বর্ণ *pin);

/*
 * Enumerates and loads all SSH-compatible resident keys from a security
 * key.
 *
 * Returns 0 on success or a ssherr.h error code on failure.
 */
পূর্ণাঙ্ক sshsk_load_resident(ধ্রুব বর্ণ *provider_path, ধ্রুব বর্ণ *device,
    ধ্রুব বর্ণ *pin, u_int flags, সংরচনা sshsk_resident_চাবি ***srksp,
    size_t *nsrksp);

/* Free an array of sshsk_resident_key (as returned from sshsk_load_resident) */
শূন্য sshsk_free_resident_চাবিগুলি(সংরচনা sshsk_resident_চাবি **srks, size_t nsrks);

#endif /* _SSH_SK_H */

