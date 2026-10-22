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

#اگر_غیر_تعریف_شدہ _SSH_SK_H
#تعریف_کرو _SSH_SK_H 1

ساخت sshbuf;
ساخت sshkey;
ساخت sk_option;

/* Version of protocol expected from ssh-sk-helper */
#تعریف_کرو SSH_SK_HELPER_نسخہ		5

/* ssh-sk-helper messages */
#تعریف_کرو SSH_SK_HELPER_ERROR		0	/* Only valid H->C */
#تعریف_کرو SSH_SK_HELPER_SIGN		1
#تعریف_کرو SSH_SK_HELPER_ENROLL		2
#تعریف_کرو SSH_SK_HELPER_بھرو_RESIDENT	3

ساخت sshsk_resident_کلید {
	ساخت sshkey *کلید;
	uint8_t *user_id;
	سائز_t user_id_len;
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
صحیح sshsk_enroll(صحیح type, ثابت حرف *provider_راستہ, ثابت حرف *device,
    ثابت حرف *application, ثابت حرف *userid, uint8_t flags,
    ثابت حرف *pin, ساخت sshbuf *challenge_buf,
    ساخت sshkey **keyp, ساخت sshbuf *attest);

/*
 * Calculate an ECDSA_SK or ED25519_SK signature using the specified key
 * and provider middleware.
 *
 * Returns 0 on success or a ssherr.h error code on failure.
 */
صحیح sshsk_sign(ثابت حرف *provider_راستہ, ساخت sshkey *کلید,
    u_char **sigp, سائز_t *lenp, ثابت u_char *ڈیٹا, سائز_t datalen,
    u_int compat, ثابت حرف *pin);

/*
 * Enumerates and loads all SSH-compatible resident keys from a security
 * key.
 *
 * Returns 0 on success or a ssherr.h error code on failure.
 */
صحیح sshsk_بھرو_resident(ثابت حرف *provider_راستہ, ثابت حرف *device,
    ثابت حرف *pin, u_int flags, ساخت sshsk_resident_کلید ***srksp,
    سائز_t *nsrksp);

/* Free an array of sshsk_resident_key (as returned from sshsk_load_resident) */
خالی sshsk_free_resident_کلیدیں(ساخت sshsk_resident_کلید **srks, سائز_t nsrks);

#اگر_ختم /* _SSH_SK_H */

