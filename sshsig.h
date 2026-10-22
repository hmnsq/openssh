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

সংরচনা sshbuf;
সংরচনা sshkey;
সংরচনা sshsigopt;
সংরচনা sshkey_sig_details;

প্রকারনির্দেশ পূর্ণাঙ্ক sshsig_signer(সংরচনা sshkey *, u_char **, size_t *,
    ধ্রুৱ u_char *, size_t, ধ্রুৱ ৱর্ণ *, ধ্রুৱ ৱর্ণ *, ধ্রুৱ ৱর্ণ *,
    u_int, শূন্য *);

/* Buffer-oriented API */

/*
 * Creates a detached SSH signature for a given buffer.
 * Returns 0 on success or a negative SSH_ERR_* error code on failure.
 * out is populated with the detached signature, or NULL on failure.
 */
পূর্ণাঙ্ক sshsig_signb(সংরচনা sshkey *চাবি, ধ্রুৱ ৱর্ণ *hashalg,
    ধ্রুৱ ৱর্ণ *sk_provider, ধ্রুৱ ৱর্ণ *sk_pin, ধ্রুৱ সংরচনা sshbuf *message,
    ধ্রুৱ ৱর্ণ *sig_namespace, সংরচনা sshbuf **out,
    sshsig_signer *signer, শূন্য *signer_ctx);

/*
 * Verifies that a detached signature is valid and optionally returns key
 * used to sign via argument.
 * Returns 0 on success or a negative SSH_ERR_* error code on failure.
 */
পূর্ণাঙ্ক sshsig_verifyb(সংরচনা sshbuf *signature,
    ধ্রুৱ সংরচনা sshbuf *message, ধ্রুৱ ৱর্ণ *sig_namespace,
    সংরচনা sshkey **sign_keyp, সংরচনা sshkey_sig_details **sig_details);

/* File/FD-oriented API */

/*
 * Creates a detached SSH signature for a given file.
 * Returns 0 on success or a negative SSH_ERR_* error code on failure.
 * out is populated with the detached signature, or NULL on failure.
 */
পূর্ণাঙ্ক sshsig_sign_fd(সংরচনা sshkey *চাবি, ধ্রুৱ ৱর্ণ *hashalg,
    ধ্রুৱ ৱর্ণ *sk_provider, ধ্রুৱ ৱর্ণ *sk_pin,
    পূর্ণাঙ্ক fd, ধ্রুৱ ৱর্ণ *sig_namespace,
    সংরচনা sshbuf **out, sshsig_signer *signer, শূন্য *signer_ctx);

/*
 * Verifies that a detached signature over a file is valid and optionally
 * returns key used to sign via argument.
 * Returns 0 on success or a negative SSH_ERR_* error code on failure.
 */
পূর্ণাঙ্ক sshsig_verify_fd(সংরচনা sshbuf *signature, পূর্ণাঙ্ক fd,
    ধ্রুৱ ৱর্ণ *sig_namespace, সংরচনা sshkey **sign_keyp,
    সংরচনা sshkey_sig_details **sig_details);

/* Utility functions */

/*
 * Return a base64 encoded "ASCII armoured" version of a raw signature.
 */
পূর্ণাঙ্ক sshsig_armor(ধ্রুৱ সংরচনা sshbuf *blob, সংরচনা sshbuf **out);

/*
 * Decode a base64 encoded armoured signature to a raw signature.
 */
পূর্ণাঙ্ক sshsig_dearmor(সংরচনা sshbuf *sig, সংরচনা sshbuf **out);

/*
 * Checks whether a particular key/principal/namespace is permitted by
 * an allowed_keys file. Returns 0 on success.
 */
পূর্ণাঙ্ক sshsig_check_allowed_চাবিগুলি(ধ্রুৱ ৱর্ণ *path, ধ্রুৱ সংরচনা sshkey *sign_চাবি,
    ধ্রুৱ ৱর্ণ *principal, ধ্রুৱ ৱর্ণ *ns, uint64_t verify_time);

/* Parse zero or more allowed_keys signature options */
সংরচনা sshsigopt *sshsigopt_parse(ধ্রুৱ ৱর্ণ *opts,
    ধ্রুৱ ৱর্ণ *path, u_long linenum, ধ্রুৱ ৱর্ণ **errstrp);

/* Free signature options */
শূন্য sshsigopt_free(সংরচনা sshsigopt *opts);

/* Get public key from signature */
পূর্ণাঙ্ক sshsig_get_pubkey(সংরচনা sshbuf *signature, সংরচনা sshkey **pubkey);

/* Find principal in allowed_keys file, given a sshkey. Returns
 * 0 on success.
 */
পূর্ণাঙ্ক sshsig_find_principals(ধ্রুৱ ৱর্ণ *path, ধ্রুৱ সংরচনা sshkey *sign_চাবি,
    uint64_t verify_time, ৱর্ণ **principal);

/* Find all principals in allowed_keys file matching *principal */
পূর্ণাঙ্ক sshsig_match_principals(ধ্রুৱ ৱর্ণ *path,
	ধ্রুৱ ৱর্ণ *principal, ৱর্ণ ***principalsp, size_t *nprincipalsp);

#endif /* SSHSIG_H */
