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

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ _SSH_SK_H
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ _SSH_SK_H 1

ਬਣਤਰ sshbuf;
ਬਣਤਰ sshkey;
ਬਣਤਰ sk_option;

/* Version of protocol expected from ssh-sk-helper */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_SK_HELPER_ਸੰਸਕਰਣ		5

/* ssh-sk-helper messages */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_SK_HELPER_ERROR		0	/* Only valid H->C */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_SK_HELPER_SIGN		1
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_SK_HELPER_ENROLL		2
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSH_SK_HELPER_ਲੱਦੋ_RESIDENT	3

ਬਣਤਰ sshsk_resident_ਕੁੰਜੀ {
	ਬਣਤਰ sshkey *ਕੁੰਜੀ;
	uint8_t *user_id;
	ਮਾਪ_t user_id_len;
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
ਪੂਰਨ sshsk_enroll(ਪੂਰਨ type, ਅਚਲ ਅੱਖਰ *provider_ਰਸਤਾ, ਅਚਲ ਅੱਖਰ *device,
    ਅਚਲ ਅੱਖਰ *application, ਅਚਲ ਅੱਖਰ *userid, uint8_t flags,
    ਅਚਲ ਅੱਖਰ *pin, ਬਣਤਰ sshbuf *challenge_buf,
    ਬਣਤਰ sshkey **keyp, ਬਣਤਰ sshbuf *attest);

/*
 * Calculate an ECDSA_SK or ED25519_SK signature using the specified key
 * and provider middleware.
 *
 * Returns 0 on success or a ssherr.h error code on failure.
 */
ਪੂਰਨ sshsk_sign(ਅਚਲ ਅੱਖਰ *provider_ਰਸਤਾ, ਬਣਤਰ sshkey *ਕੁੰਜੀ,
    u_char **sigp, ਮਾਪ_t *lenp, ਅਚਲ u_char *ਅੰਕੜੇ, ਮਾਪ_t datalen,
    u_int compat, ਅਚਲ ਅੱਖਰ *pin);

/*
 * Enumerates and loads all SSH-compatible resident keys from a security
 * key.
 *
 * Returns 0 on success or a ssherr.h error code on failure.
 */
ਪੂਰਨ sshsk_ਲੱਦੋ_resident(ਅਚਲ ਅੱਖਰ *provider_ਰਸਤਾ, ਅਚਲ ਅੱਖਰ *device,
    ਅਚਲ ਅੱਖਰ *pin, u_int flags, ਬਣਤਰ sshsk_resident_ਕੁੰਜੀ ***srksp,
    ਮਾਪ_t *nsrksp);

/* Free an array of sshsk_resident_key (as returned from sshsk_load_resident) */
ਖਾਲੀ sshsk_free_resident_ਕੁੰਜੀਆਂ(ਬਣਤਰ sshsk_resident_ਕੁੰਜੀ **srks, ਮਾਪ_t nsrks);

#ਜੇ_ਅੰਤ /* _SSH_SK_H */

