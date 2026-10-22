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

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ _SSH_SK_H
#ವ್ಯಾಖ್ಯಾನಿಸು _SSH_SK_H 1

ರಚನೆ sshbuf;
ರಚನೆ sshkey;
ರಚನೆ sk_option;

/* Version of protocol expected from ssh-sk-helper */
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_SK_HELPER_ಆವೃತ್ತಿ		5

/* ssh-sk-helper messages */
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_SK_HELPER_ERROR		0	/* Only valid H->C */
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_SK_HELPER_SIGN		1
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_SK_HELPER_ENROLL		2
#ವ್ಯಾಖ್ಯಾನಿಸು SSH_SK_HELPER_ತುಂಬು_RESIDENT	3

ರಚನೆ sshsk_resident_ಕೀಲಿ {
	ರಚನೆ sshkey *ಕೀಲಿ;
	uint8_t *user_id;
	ಗಾತ್ರ_t user_id_len;
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
ಪೂರ್ಣಾಂಕ sshsk_enroll(ಪೂರ್ಣಾಂಕ type, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *provider_ಮಾರ್ಗ, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *device,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *application, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *userid, uint8_t flags,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *pin, ರಚನೆ sshbuf *challenge_buf,
    ರಚನೆ sshkey **keyp, ರಚನೆ sshbuf *attest);

/*
 * Calculate an ECDSA_SK or ED25519_SK signature using the specified key
 * and provider middleware.
 *
 * Returns 0 on success or a ssherr.h error code on failure.
 */
ಪೂರ್ಣಾಂಕ sshsk_sign(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *provider_ಮಾರ್ಗ, ರಚನೆ sshkey *ಕೀಲಿ,
    u_char **sigp, ಗಾತ್ರ_t *lenp, ಸ್ಥಿರಾಂಕ u_char *ದತ್ತಾಂಶ, ಗಾತ್ರ_t datalen,
    u_int compat, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *pin);

/*
 * Enumerates and loads all SSH-compatible resident keys from a security
 * key.
 *
 * Returns 0 on success or a ssherr.h error code on failure.
 */
ಪೂರ್ಣಾಂಕ sshsk_ತುಂಬು_resident(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *provider_ಮಾರ್ಗ, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *device,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *pin, u_int flags, ರಚನೆ sshsk_resident_ಕೀಲಿ ***srksp,
    ಗಾತ್ರ_t *nsrksp);

/* Free an array of sshsk_resident_key (as returned from sshsk_load_resident) */
ಶೂನ್ಯ sshsk_free_resident_ಕೀಲಿಗಳು(ರಚನೆ sshsk_resident_ಕೀಲಿ **srks, ಗಾತ್ರ_t nsrks);

#ಆದರೆ_ಅಂತ್ಯ /* _SSH_SK_H */

