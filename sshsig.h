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

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ SSHSIG_H
#ವ್ಯಾಖ್ಯಾನಿಸು SSHSIG_H

ರಚನೆ sshbuf;
ರಚನೆ sshkey;
ರಚನೆ sshsigopt;
ರಚನೆ sshkey_sig_details;

ಪ್ರಕಾರವ್ಯಾಖ್ಯೆ ಪೂರ್ಣಾಂಕ sshsig_signer(ರಚನೆ sshkey *, u_char **, ಗಾತ್ರ_t *,
    ಸ್ಥಿರಾಂಕ u_char *, ಗಾತ್ರ_t, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *,
    u_int, ಶೂನ್ಯ *);

/* Buffer-oriented API */

/*
 * Creates a detached SSH signature for a given buffer.
 * Returns 0 on success or a negative SSH_ERR_* error code on failure.
 * out is populated with the detached signature, or NULL on failure.
 */
ಪೂರ್ಣಾಂಕ sshsig_signb(ರಚನೆ sshkey *ಕೀಲಿ, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *hashalg,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *sk_provider, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *sk_pin, ಸ್ಥಿರಾಂಕ ರಚನೆ sshbuf *ಸಂದೇಶ_2,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *sig_namespace, ರಚನೆ sshbuf **ಹೊರಹೋಗು,
    sshsig_signer *signer, ಶೂನ್ಯ *signer_ctx);

/*
 * Verifies that a detached signature is valid and optionally returns key
 * used to sign via argument.
 * Returns 0 on success or a negative SSH_ERR_* error code on failure.
 */
ಪೂರ್ಣಾಂಕ sshsig_verifyb(ರಚನೆ sshbuf *signature,
    ಸ್ಥಿರಾಂಕ ರಚನೆ sshbuf *ಸಂದೇಶ_2, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *sig_namespace,
    ರಚನೆ sshkey **sign_keyp, ರಚನೆ sshkey_sig_details **sig_details);

/* File/FD-oriented API */

/*
 * Creates a detached SSH signature for a given file.
 * Returns 0 on success or a negative SSH_ERR_* error code on failure.
 * out is populated with the detached signature, or NULL on failure.
 */
ಪೂರ್ಣಾಂಕ sshsig_sign_fd(ರಚನೆ sshkey *ಕೀಲಿ, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *hashalg,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *sk_provider, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *sk_pin,
    ಪೂರ್ಣಾಂಕ fd, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *sig_namespace,
    ರಚನೆ sshbuf **ಹೊರಹೋಗು, sshsig_signer *signer, ಶೂನ್ಯ *signer_ctx);

/*
 * Verifies that a detached signature over a file is valid and optionally
 * returns key used to sign via argument.
 * Returns 0 on success or a negative SSH_ERR_* error code on failure.
 */
ಪೂರ್ಣಾಂಕ sshsig_verify_fd(ರಚನೆ sshbuf *signature, ಪೂರ್ಣಾಂಕ fd,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *sig_namespace, ರಚನೆ sshkey **sign_keyp,
    ರಚನೆ sshkey_sig_details **sig_details);

/* Utility functions */

/*
 * Return a base64 encoded "ASCII armoured" version of a raw signature.
 */
ಪೂರ್ಣಾಂಕ sshsig_armor(ಸ್ಥಿರಾಂಕ ರಚನೆ sshbuf *blob, ರಚನೆ sshbuf **ಹೊರಹೋಗು);

/*
 * Decode a base64 encoded armoured signature to a raw signature.
 */
ಪೂರ್ಣಾಂಕ sshsig_dearmor(ರಚನೆ sshbuf *sig, ರಚನೆ sshbuf **ಹೊರಹೋಗು);

/*
 * Checks whether a particular key/principal/namespace is permitted by
 * an allowed_keys file. Returns 0 on success.
 */
ಪೂರ್ಣಾಂಕ sshsig_check_allowed_ಕೀಲಿಗಳು(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಮಾರ್ಗ, ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *sign_ಕೀಲಿ,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *principal, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ns, uint64_t verify_ಸಮಯ);

/* Parse zero or more allowed_keys signature options */
ರಚನೆ sshsigopt *sshsigopt_parse(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *opts,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಮಾರ್ಗ, u_long linenum, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ **errstrp);

/* Free signature options */
ಶೂನ್ಯ sshsigopt_free(ರಚನೆ sshsigopt *opts);

/* Get public key from signature */
ಪೂರ್ಣಾಂಕ sshsig_get_pubkey(ರಚನೆ sshbuf *signature, ರಚನೆ sshkey **pubkey);

/* Find principal in allowed_keys file, given a sshkey. Returns
 * 0 on success.
 */
ಪೂರ್ಣಾಂಕ sshsig_ಕಂಡುಹಿಡಿ_principals(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಮಾರ್ಗ, ಸ್ಥಿರಾಂಕ ರಚನೆ sshkey *sign_ಕೀಲಿ,
    uint64_t verify_ಸಮಯ, ಅಕ್ಷರ **principal);

/* Find all principals in allowed_keys file matching *principal */
ಪೂರ್ಣಾಂಕ sshsig_ಹೊಂದಿಕೆ_principals(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಮಾರ್ಗ,
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *principal, ಅಕ್ಷರ ***principalsp, ಗಾತ್ರ_t *nprincipalsp);

#ಆದರೆ_ಅಂತ್ಯ /* SSHSIG_H */
