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

#جيڪڏهن_وصف_نه_ٿيل _SSH_SK_H
#وصف_ڪريو _SSH_SK_H 1

بنية sshbuf;
بنية sshkey;
بنية sk_option;

/* Version of protocol expected from ssh-sk-helper */
#وصف_ڪريو SSH_SK_HELPER_نسخو		5

/* ssh-sk-helper messages */
#وصف_ڪريو SSH_SK_HELPER_ERROR		0	/* Only valid H->C */
#وصف_ڪريو SSH_SK_HELPER_SIGN		1
#وصف_ڪريو SSH_SK_HELPER_ENROLL		2
#وصف_ڪريو SSH_SK_HELPER_ڀريو_RESIDENT	3

بنية sshsk_resident_ڪنجي {
	بنية sshkey *ڪنجي;
	uint8_t *user_id;
	سائيز_t user_id_len;
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
صحيح sshsk_enroll(صحيح type, ثابت حرف *provider_رستو, ثابت حرف *device,
    ثابت حرف *application, ثابت حرف *userid, uint8_t flags,
    ثابت حرف *pin, بنية sshbuf *challenge_buf,
    بنية sshkey **keyp, بنية sshbuf *attest);

/*
 * Calculate an ECDSA_SK or ED25519_SK signature using the specified key
 * and provider middleware.
 *
 * Returns 0 on success or a ssherr.h error code on failure.
 */
صحيح sshsk_sign(ثابت حرف *provider_رستو, بنية sshkey *ڪنجي,
    u_char **sigp, سائيز_t *lenp, ثابت u_char *معلومات, سائيز_t datalen,
    u_int compat, ثابت حرف *pin);

/*
 * Enumerates and loads all SSH-compatible resident keys from a security
 * key.
 *
 * Returns 0 on success or a ssherr.h error code on failure.
 */
صحيح sshsk_ڀريو_resident(ثابت حرف *provider_رستو, ثابت حرف *device,
    ثابت حرف *pin, u_int flags, بنية sshsk_resident_ڪنجي ***srksp,
    سائيز_t *nsrksp);

/* Free an array of sshsk_resident_key (as returned from sshsk_load_resident) */
فراغ sshsk_free_resident_ڪنجيون(بنية sshsk_resident_ڪنجي **srks, سائيز_t nsrks);

#جيڪڏهن_پورو /* _SSH_SK_H */

