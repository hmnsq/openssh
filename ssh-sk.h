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

#నిర్వచితం_కాకపోతే _SSH_SK_H
#నిర్వచించు _SSH_SK_H 1

నిర్మాణం sshbuf;
నిర్మాణం sshkey;
నిర్మాణం sk_option;

/* Version of protocol expected from ssh-sk-helper */
#నిర్వచించు SSH_SK_HELPER_సంస్కరణ		5

/* ssh-sk-helper messages */
#నిర్వచించు SSH_SK_HELPER_ERROR		0	/* Only valid H->C */
#నిర్వచించు SSH_SK_HELPER_SIGN		1
#నిర్వచించు SSH_SK_HELPER_ENROLL		2
#నిర్వచించు SSH_SK_HELPER_ఎక్కించు_RESIDENT	3

నిర్మాణం sshsk_resident_కీలకం {
	నిర్మాణం sshkey *కీలకం;
	uint8_t *user_id;
	కొలత_t user_id_len;
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
పూర్ణాంకం sshsk_enroll(పూర్ణాంకం type, స్థిరరాశి అక్షరం *provider_మార్గం, స్థిరరాశి అక్షరం *device,
    స్థిరరాశి అక్షరం *application, స్థిరరాశి అక్షరం *userid, uint8_t flags,
    స్థిరరాశి అక్షరం *pin, నిర్మాణం sshbuf *challenge_buf,
    నిర్మాణం sshkey **keyp, నిర్మాణం sshbuf *attest);

/*
 * Calculate an ECDSA_SK or ED25519_SK signature using the specified key
 * and provider middleware.
 *
 * Returns 0 on success or a ssherr.h error code on failure.
 */
పూర్ణాంకం sshsk_sign(స్థిరరాశి అక్షరం *provider_మార్గం, నిర్మాణం sshkey *కీలకం,
    u_char **sigp, కొలత_t *lenp, స్థిరరాశి u_char *దత్తాంశం, కొలత_t datalen,
    u_int compat, స్థిరరాశి అక్షరం *pin);

/*
 * Enumerates and loads all SSH-compatible resident keys from a security
 * key.
 *
 * Returns 0 on success or a ssherr.h error code on failure.
 */
పూర్ణాంకం sshsk_ఎక్కించు_resident(స్థిరరాశి అక్షరం *provider_మార్గం, స్థిరరాశి అక్షరం *device,
    స్థిరరాశి అక్షరం *pin, u_int flags, నిర్మాణం sshsk_resident_కీలకం ***srksp,
    కొలత_t *nsrksp);

/* Free an array of sshsk_resident_key (as returned from sshsk_load_resident) */
శూన్య sshsk_free_resident_కీలకాలు(నిర్మాణం sshsk_resident_కీలకం **srks, కొలత_t nsrks);

#అయితే_ముగింపు /* _SSH_SK_H */

