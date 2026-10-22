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

sa_nracanaa sshbuf;
sa_nracanaa sshkey;
sa_nracanaa sshsigopt;
sa_nracanaa sshkey_sig_details;

typedef puur_naa_nka sshsig_signer(sa_nracanaa sshkey *, u_char **, size_t *,
    const u_char *, size_t, const var_na *, const var_na *, const var_na *,
    u_int, void *);

/* Buffer-oriented API */

/*
 * Creates a detached SSH signature for a given buffer.
 * Returns 0 on success or a negative SSH_ERR_* error code on failure.
 * out is populated with the detached signature, or NULL on failure.
 */
puur_naa_nka sshsig_signb(sa_nracanaa sshkey *key, const var_na *hashalg,
    const var_na *sk_provider, const var_na *sk_pin, const sa_nracanaa sshbuf *message,
    const var_na *sig_namespace, sa_nracanaa sshbuf **out,
    sshsig_signer *signer, void *signer_ctx);

/*
 * Verifies that a detached signature is valid and optionally returns key
 * used to sign via argument.
 * Returns 0 on success or a negative SSH_ERR_* error code on failure.
 */
puur_naa_nka sshsig_verifyb(sa_nracanaa sshbuf *signature,
    const sa_nracanaa sshbuf *message, const var_na *sig_namespace,
    sa_nracanaa sshkey **sign_keyp, sa_nracanaa sshkey_sig_details **sig_details);

/* File/FD-oriented API */

/*
 * Creates a detached SSH signature for a given file.
 * Returns 0 on success or a negative SSH_ERR_* error code on failure.
 * out is populated with the detached signature, or NULL on failure.
 */
puur_naa_nka sshsig_sign_fd(sa_nracanaa sshkey *key, const var_na *hashalg,
    const var_na *sk_provider, const var_na *sk_pin,
    puur_naa_nka fd, const var_na *sig_namespace,
    sa_nracanaa sshbuf **out, sshsig_signer *signer, void *signer_ctx);

/*
 * Verifies that a detached signature over a file is valid and optionally
 * returns key used to sign via argument.
 * Returns 0 on success or a negative SSH_ERR_* error code on failure.
 */
puur_naa_nka sshsig_verify_fd(sa_nracanaa sshbuf *signature, puur_naa_nka fd,
    const var_na *sig_namespace, sa_nracanaa sshkey **sign_keyp,
    sa_nracanaa sshkey_sig_details **sig_details);

/* Utility functions */

/*
 * Return a base64 encoded "ASCII armoured" version of a raw signature.
 */
puur_naa_nka sshsig_armor(const sa_nracanaa sshbuf *blob, sa_nracanaa sshbuf **out);

/*
 * Decode a base64 encoded armoured signature to a raw signature.
 */
puur_naa_nka sshsig_dearmor(sa_nracanaa sshbuf *sig, sa_nracanaa sshbuf **out);

/*
 * Checks whether a particular key/principal/namespace is permitted by
 * an allowed_keys file. Returns 0 on success.
 */
puur_naa_nka sshsig_check_allowed_keys(const var_na *path, const sa_nracanaa sshkey *sign_key,
    const var_na *principal, const var_na *ns, uint64_t verify_time);

/* Parse zero or more allowed_keys signature options */
sa_nracanaa sshsigopt *sshsigopt_parse(const var_na *opts,
    const var_na *path, u_long linenum, const var_na **errstrp);

/* Free signature options */
void sshsigopt_free(sa_nracanaa sshsigopt *opts);

/* Get public key from signature */
puur_naa_nka sshsig_get_pubkey(sa_nracanaa sshbuf *signature, sa_nracanaa sshkey **pubkey);

/* Find principal in allowed_keys file, given a sshkey. Returns
 * 0 on success.
 */
puur_naa_nka sshsig_find_principals(const var_na *path, const sa_nracanaa sshkey *sign_key,
    uint64_t verify_time, var_na **principal);

/* Find all principals in allowed_keys file matching *principal */
puur_naa_nka sshsig_match_principals(const var_na *path,
	const var_na *principal, var_na ***principalsp, size_t *nprincipalsp);

#endif /* SSHSIG_H */
