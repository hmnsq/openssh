/* $OpenBSD: sshsig.h,v 1.11 2021/11/27 07:14:46 djm Exp $ */
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

#నిర్వచితం_కాకపోతే SSHSIG_H
#నిర్వచించు SSHSIG_H

నిర్మాణం sshbuf;
నిర్మాణం sshkey;
నిర్మాణం sshsigopt;
నిర్మాణం sshkey_sig_details;

రకనిర్వచనం పూర్ణాంకం sshsig_signer(నిర్మాణం sshkey *, u_char **, కొలత_t *,
    స్థిరరాశి u_char *, కొలత_t, స్థిరరాశి అక్షరం *, స్థిరరాశి అక్షరం *, స్థిరరాశి అక్షరం *,
    u_int, శూన్య *);

/* Buffer-oriented API */

/*
 * Creates a detached SSH signature for a given buffer.
 * Returns 0 on success or a negative SSH_ERR_* error code on failure.
 * out is populated with the detached signature, or NULL on failure.
 */
పూర్ణాంకం sshsig_signb(నిర్మాణం sshkey *కీలకం, స్థిరరాశి అక్షరం *hashalg,
    స్థిరరాశి అక్షరం *sk_provider, స్థిరరాశి అక్షరం *sk_pin, స్థిరరాశి నిర్మాణం sshbuf *సందేశం_2,
    స్థిరరాశి అక్షరం *sig_namespace, నిర్మాణం sshbuf **బహిర్గతం,
    sshsig_signer *signer, శూన్య *signer_ctx);

/*
 * Verifies that a detached signature is valid and optionally returns key
 * used to sign via argument.
 * Returns 0 on success or a negative SSH_ERR_* error code on failure.
 */
పూర్ణాంకం sshsig_verifyb(నిర్మాణం sshbuf *signature,
    స్థిరరాశి నిర్మాణం sshbuf *సందేశం_2, స్థిరరాశి అక్షరం *sig_namespace,
    నిర్మాణం sshkey **sign_keyp, నిర్మాణం sshkey_sig_details **sig_details);

/* File/FD-oriented API */

/*
 * Creates a detached SSH signature for a given file.
 * Returns 0 on success or a negative SSH_ERR_* error code on failure.
 * out is populated with the detached signature, or NULL on failure.
 */
పూర్ణాంకం sshsig_sign_fd(నిర్మాణం sshkey *కీలకం, స్థిరరాశి అక్షరం *hashalg,
    స్థిరరాశి అక్షరం *sk_provider, స్థిరరాశి అక్షరం *sk_pin,
    పూర్ణాంకం fd, స్థిరరాశి అక్షరం *sig_namespace,
    నిర్మాణం sshbuf **బహిర్గతం, sshsig_signer *signer, శూన్య *signer_ctx);

/*
 * Verifies that a detached signature over a file is valid and optionally
 * returns key used to sign via argument.
 * Returns 0 on success or a negative SSH_ERR_* error code on failure.
 */
పూర్ణాంకం sshsig_verify_fd(నిర్మాణం sshbuf *signature, పూర్ణాంకం fd,
    స్థిరరాశి అక్షరం *sig_namespace, నిర్మాణం sshkey **sign_keyp,
    నిర్మాణం sshkey_sig_details **sig_details);

/* Utility functions */

/*
 * Return a base64 encoded "ASCII armoured" version of a raw signature.
 */
పూర్ణాంకం sshsig_armor(స్థిరరాశి నిర్మాణం sshbuf *blob, నిర్మాణం sshbuf **బహిర్గతం);

/*
 * Decode a base64 encoded armoured signature to a raw signature.
 */
పూర్ణాంకం sshsig_dearmor(నిర్మాణం sshbuf *sig, నిర్మాణం sshbuf **బహిర్గతం);

/*
 * Checks whether a particular key/principal/namespace is permitted by
 * an allowed_keys file. Returns 0 on success.
 */
పూర్ణాంకం sshsig_check_allowed_కీలకాలు(స్థిరరాశి అక్షరం *మార్గం, స్థిరరాశి నిర్మాణం sshkey *sign_కీలకం,
    స్థిరరాశి అక్షరం *principal, స్థిరరాశి అక్షరం *ns, uint64_t verify_సమయం);

/* Parse zero or more allowed_keys signature options */
నిర్మాణం sshsigopt *sshsigopt_parse(స్థిరరాశి అక్షరం *opts,
    స్థిరరాశి అక్షరం *మార్గం, u_long linenum, స్థిరరాశి అక్షరం **errstrp);

/* Free signature options */
శూన్య sshsigopt_free(నిర్మాణం sshsigopt *opts);

/* Get public key from signature */
పూర్ణాంకం sshsig_get_pubkey(నిర్మాణం sshbuf *signature, నిర్మాణం sshkey **pubkey);

/* Find principal in allowed_keys file, given a sshkey. Returns
 * 0 on success.
 */
పూర్ణాంకం sshsig_కనుగొను_principals(స్థిరరాశి అక్షరం *మార్గం, స్థిరరాశి నిర్మాణం sshkey *sign_కీలకం,
    uint64_t verify_సమయం, అక్షరం **principal);

/* Find all principals in allowed_keys file matching *principal */
పూర్ణాంకం sshsig_సరిపోలిక_principals(స్థిరరాశి అక్షరం *మార్గం,
	స్థిరరాశి అక్షరం *principal, అక్షరం ***principalsp, కొలత_t *nprincipalsp);

#అయితే_ముగింపు /* SSHSIG_H */
