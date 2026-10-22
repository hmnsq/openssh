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

بنية sshbuf;
بنية sshkey;
بنية sshsigopt;
بنية sshkey_sig_details;

تعريفنوع صحيح sshsig_signer(بنية sshkey *, u_char **, size_t *,
    ثابت u_char *, size_t, ثابت حرف *, ثابت حرف *, ثابت حرف *,
    u_int, فراغ *);

/* Buffer-oriented API */

/*
 * Creates a detached SSH signature for a given buffer.
 * Returns 0 on success or a negative SSH_ERR_* error code on failure.
 * out is populated with the detached signature, or NULL on failure.
 */
صحيح sshsig_signb(بنية sshkey *مبودي, ثابت حرف *hashalg,
    ثابت حرف *sk_provider, ثابت حرف *sk_pin, ثابت بنية sshbuf *message,
    ثابت حرف *sig_namespace, بنية sshbuf **out,
    sshsig_signer *signer, فراغ *signer_ctx);

/*
 * Verifies that a detached signature is valid and optionally returns key
 * used to sign via argument.
 * Returns 0 on success or a negative SSH_ERR_* error code on failure.
 */
صحيح sshsig_verifyb(بنية sshbuf *signature,
    ثابت بنية sshbuf *message, ثابت حرف *sig_namespace,
    بنية sshkey **sign_keyp, بنية sshkey_sig_details **sig_details);

/* File/FD-oriented API */

/*
 * Creates a detached SSH signature for a given file.
 * Returns 0 on success or a negative SSH_ERR_* error code on failure.
 * out is populated with the detached signature, or NULL on failure.
 */
صحيح sshsig_sign_fd(بنية sshkey *مبودي, ثابت حرف *hashalg,
    ثابت حرف *sk_provider, ثابت حرف *sk_pin,
    صحيح fd, ثابت حرف *sig_namespace,
    بنية sshbuf **out, sshsig_signer *signer, فراغ *signer_ctx);

/*
 * Verifies that a detached signature over a file is valid and optionally
 * returns key used to sign via argument.
 * Returns 0 on success or a negative SSH_ERR_* error code on failure.
 */
صحيح sshsig_verify_fd(بنية sshbuf *signature, صحيح fd,
    ثابت حرف *sig_namespace, بنية sshkey **sign_keyp,
    بنية sshkey_sig_details **sig_details);

/* Utility functions */

/*
 * Return a base64 encoded "ASCII armoured" version of a raw signature.
 */
صحيح sshsig_armor(ثابت بنية sshbuf *blob, بنية sshbuf **out);

/*
 * Decode a base64 encoded armoured signature to a raw signature.
 */
صحيح sshsig_dearmor(بنية sshbuf *sig, بنية sshbuf **out);

/*
 * Checks whether a particular key/principal/namespace is permitted by
 * an allowed_keys file. Returns 0 on success.
 */
صحيح sshsig_check_allowed_مبوداي(ثابت حرف *path, ثابت بنية sshkey *sign_مبودي,
    ثابت حرف *principal, ثابت حرف *ns, uint64_t verify_time);

/* Parse zero or more allowed_keys signature options */
بنية sshsigopt *sshsigopt_parse(ثابت حرف *opts,
    ثابت حرف *path, u_long linenum, ثابت حرف **errstrp);

/* Free signature options */
فراغ sshsigopt_free(بنية sshsigopt *opts);

/* Get public key from signature */
صحيح sshsig_get_pubkey(بنية sshbuf *signature, بنية sshkey **pubkey);

/* Find principal in allowed_keys file, given a sshkey. Returns
 * 0 on success.
 */
صحيح sshsig_find_principals(ثابت حرف *path, ثابت بنية sshkey *sign_مبودي,
    uint64_t verify_time, حرف **principal);

/* Find all principals in allowed_keys file matching *principal */
صحيح sshsig_match_principals(ثابت حرف *path,
	ثابت حرف *principal, حرف ***principalsp, size_t *nprincipalsp);

#endif /* SSHSIG_H */
