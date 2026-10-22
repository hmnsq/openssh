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

#ifndef SSHSIG_H
#define SSHSIG_H

ಸಂರಚನಾ sshbuf;
ಸಂರಚನಾ sshkey;
ಸಂರಚನಾ sshsigopt;
ಸಂರಚನಾ sshkey_sig_details;

ಪ್ರಕಾರನಿರ್ದೇಶ ಪೂರ್ಣಾಙ್ಕ sshsig_signer(ಸಂರಚನಾ sshkey *, u_char **, size_t *,
    ಧ್ರುವ u_char *, size_t, ಧ್ರುವ ವರ್ಣ *, ಧ್ರುವ ವರ್ಣ *, ಧ್ರುವ ವರ್ಣ *,
    u_int, ಶೂನ್ಯ *);

/* Buffer-oriented API */

/*
 * Creates a detached SSH signature for a given buffer.
 * Returns 0 on success or a negative SSH_ERR_* error code on failure.
 * out is populated with the detached signature, or NULL on failure.
 */
ಪೂರ್ಣಾಙ್ಕ sshsig_signb(ಸಂರಚನಾ sshkey *ಕೀಲಿ, ಧ್ರುವ ವರ್ಣ *hashalg,
    ಧ್ರುವ ವರ್ಣ *sk_provider, ಧ್ರುವ ವರ್ಣ *sk_pin, ಧ್ರುವ ಸಂರಚನಾ sshbuf *message,
    ಧ್ರುವ ವರ್ಣ *sig_namespace, ಸಂರಚನಾ sshbuf **out,
    sshsig_signer *signer, ಶೂನ್ಯ *signer_ctx);

/*
 * Verifies that a detached signature is valid and optionally returns key
 * used to sign via argument.
 * Returns 0 on success or a negative SSH_ERR_* error code on failure.
 */
ಪೂರ್ಣಾಙ್ಕ sshsig_verifyb(ಸಂರಚನಾ sshbuf *signature,
    ಧ್ರುವ ಸಂರಚನಾ sshbuf *message, ಧ್ರುವ ವರ್ಣ *sig_namespace,
    ಸಂರಚನಾ sshkey **sign_keyp, ಸಂರಚನಾ sshkey_sig_details **sig_details);

/* File/FD-oriented API */

/*
 * Creates a detached SSH signature for a given file.
 * Returns 0 on success or a negative SSH_ERR_* error code on failure.
 * out is populated with the detached signature, or NULL on failure.
 */
ಪೂರ್ಣಾಙ್ಕ sshsig_sign_fd(ಸಂರಚನಾ sshkey *ಕೀಲಿ, ಧ್ರುವ ವರ್ಣ *hashalg,
    ಧ್ರುವ ವರ್ಣ *sk_provider, ಧ್ರುವ ವರ್ಣ *sk_pin,
    ಪೂರ್ಣಾಙ್ಕ fd, ಧ್ರುವ ವರ್ಣ *sig_namespace,
    ಸಂರಚನಾ sshbuf **out, sshsig_signer *signer, ಶೂನ್ಯ *signer_ctx);

/*
 * Verifies that a detached signature over a file is valid and optionally
 * returns key used to sign via argument.
 * Returns 0 on success or a negative SSH_ERR_* error code on failure.
 */
ಪೂರ್ಣಾಙ್ಕ sshsig_verify_fd(ಸಂರಚನಾ sshbuf *signature, ಪೂರ್ಣಾಙ್ಕ fd,
    ಧ್ರುವ ವರ್ಣ *sig_namespace, ಸಂರಚನಾ sshkey **sign_keyp,
    ಸಂರಚನಾ sshkey_sig_details **sig_details);

/* Utility functions */

/*
 * Return a base64 encoded "ASCII armoured" version of a raw signature.
 */
ಪೂರ್ಣಾಙ್ಕ sshsig_armor(ಧ್ರುವ ಸಂರಚನಾ sshbuf *blob, ಸಂರಚನಾ sshbuf **out);

/*
 * Decode a base64 encoded armoured signature to a raw signature.
 */
ಪೂರ್ಣಾಙ್ಕ sshsig_dearmor(ಸಂರಚನಾ sshbuf *sig, ಸಂರಚನಾ sshbuf **out);

/*
 * Checks whether a particular key/principal/namespace is permitted by
 * an allowed_keys file. Returns 0 on success.
 */
ಪೂರ್ಣಾಙ್ಕ sshsig_check_allowed_ಕೀಲಿಗಳು(ಧ್ರುವ ವರ್ಣ *path, ಧ್ರುವ ಸಂರಚನಾ sshkey *sign_ಕೀಲಿ,
    ಧ್ರುವ ವರ್ಣ *principal, ಧ್ರುವ ವರ್ಣ *ns, uint64_t verify_time);

/* Parse zero or more allowed_keys signature options */
ಸಂರಚನಾ sshsigopt *sshsigopt_parse(ಧ್ರುವ ವರ್ಣ *opts,
    ಧ್ರುವ ವರ್ಣ *path, u_long linenum, ಧ್ರುವ ವರ್ಣ **errstrp);

/* Free signature options */
ಶೂನ್ಯ sshsigopt_free(ಸಂರಚನಾ sshsigopt *opts);

/* Get public key from signature */
ಪೂರ್ಣಾಙ್ಕ sshsig_get_pubkey(ಸಂರಚನಾ sshbuf *signature, ಸಂರಚನಾ sshkey **pubkey);

/* Find principal in allowed_keys file, given a sshkey. Returns
 * 0 on success.
 */
ಪೂರ್ಣಾಙ್ಕ sshsig_find_principals(ಧ್ರುವ ವರ್ಣ *path, ಧ್ರುವ ಸಂರಚನಾ sshkey *sign_ಕೀಲಿ,
    uint64_t verify_time, ವರ್ಣ **principal);

/* Find all principals in allowed_keys file matching *principal */
ಪೂರ್ಣಾಙ್ಕ sshsig_match_principals(ಧ್ರುವ ವರ್ಣ *path,
	ಧ್ರುವ ವರ್ಣ *principal, ವರ್ಣ ***principalsp, size_t *nprincipalsp);

#endif /* SSHSIG_H */
