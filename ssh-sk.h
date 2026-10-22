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

#अगर_अघोषित _SSH_SK_H
#घोषणा _SSH_SK_H 1

काष्ठा sshbuf;
काष्ठा sshkey;
काष्ठा sk_option;

/* Version of protocol expected from ssh-sk-helper */
#घोषणा SSH_SK_HELPER_VERSION		5

/* ssh-sk-helper messages */
#घोषणा SSH_SK_HELPER_ERROR		0	/* Only valid H->C */
#घोषणा SSH_SK_HELPER_SIGN		1
#घोषणा SSH_SK_HELPER_ENROLL		2
#घोषणा SSH_SK_HELPER_LOAD_RESIDENT	3

काष्ठा sshsk_resident_कुंजी {
	काष्ठा sshkey *कुंजी;
	uint8_t *user_id;
	माप_प्रकार user_id_len;
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
पूर्णांक sshsk_enroll(पूर्णांक type, स्थिर अक्षर *provider_path, स्थिर अक्षर *device,
    स्थिर अक्षर *application, स्थिर अक्षर *userid, uint8_t flags,
    स्थिर अक्षर *pin, काष्ठा sshbuf *challenge_buf,
    काष्ठा sshkey **keyp, काष्ठा sshbuf *attest);

/*
 * Calculate an ECDSA_SK or ED25519_SK signature using the specified key
 * and provider middleware.
 *
 * Returns 0 on success or a ssherr.h error code on failure.
 */
पूर्णांक sshsk_sign(स्थिर अक्षर *provider_path, काष्ठा sshkey *कुंजी,
    u_char **sigp, माप_प्रकार *lenp, स्थिर u_char *तथ्य, माप_प्रकार datalen,
    u_int compat, स्थिर अक्षर *pin);

/*
 * Enumerates and loads all SSH-compatible resident keys from a security
 * key.
 *
 * Returns 0 on success or a ssherr.h error code on failure.
 */
पूर्णांक sshsk_load_resident(स्थिर अक्षर *provider_path, स्थिर अक्षर *device,
    स्थिर अक्षर *pin, u_int flags, काष्ठा sshsk_resident_कुंजी ***srksp,
    माप_प्रकार *nsrksp);

/* Free an array of sshsk_resident_key (as returned from sshsk_load_resident) */
व्योम sshsk_free_resident_कुंजियाँ(काष्ठा sshsk_resident_कुंजी **srks, माप_प्रकार nsrks);

#पूर्ण_अगर /* _SSH_SK_H */

