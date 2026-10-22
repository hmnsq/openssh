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

কাঠামো sshbuf;
কাঠামো sshkey;
কাঠামো sshsigopt;
কাঠামো sshkey_sig_details;

প্রকারলেখ পূর্ণসংখ্যা sshsig_signer(কাঠামো sshkey *, u_char **, আকার_t *,
    ধ্রুবক u_char *, আকার_t, ধ্রুবক অক্ষর *, ধ্রুবক অক্ষর *, ধ্রুবক অক্ষর *,
    u_int, শূন্য *);

/* Buffer-oriented API */

/*
 * Creates a detached SSH signature for a given buffer.
 * Returns 0 on success or a negative SSH_ERR_* error code on failure.
 * out is populated with the detached signature, or NULL on failure.
 */
পূর্ণসংখ্যা sshsig_signb(কাঠামো sshkey *চাবি, ধ্রুবক অক্ষর *hashalg,
    ধ্রুবক অক্ষর *sk_provider, ধ্রুবক অক্ষর *sk_pin, ধ্রুবক কাঠামো sshbuf *message,
    ধ্রুবক অক্ষর *sig_namespace, কাঠামো sshbuf **out,
    sshsig_signer *signer, শূন্য *signer_ctx);

/*
 * Verifies that a detached signature is valid and optionally returns key
 * used to sign via argument.
 * Returns 0 on success or a negative SSH_ERR_* error code on failure.
 */
পূর্ণসংখ্যা sshsig_verifyb(কাঠামো sshbuf *signature,
    ধ্রুবক কাঠামো sshbuf *message, ধ্রুবক অক্ষর *sig_namespace,
    কাঠামো sshkey **sign_keyp, কাঠামো sshkey_sig_details **sig_details);

/* File/FD-oriented API */

/*
 * Creates a detached SSH signature for a given file.
 * Returns 0 on success or a negative SSH_ERR_* error code on failure.
 * out is populated with the detached signature, or NULL on failure.
 */
পূর্ণসংখ্যা sshsig_sign_fd(কাঠামো sshkey *চাবি, ধ্রুবক অক্ষর *hashalg,
    ধ্রুবক অক্ষর *sk_provider, ধ্রুবক অক্ষর *sk_pin,
    পূর্ণসংখ্যা fd, ধ্রুবক অক্ষর *sig_namespace,
    কাঠামো sshbuf **out, sshsig_signer *signer, শূন্য *signer_ctx);

/*
 * Verifies that a detached signature over a file is valid and optionally
 * returns key used to sign via argument.
 * Returns 0 on success or a negative SSH_ERR_* error code on failure.
 */
পূর্ণসংখ্যা sshsig_verify_fd(কাঠামো sshbuf *signature, পূর্ণসংখ্যা fd,
    ধ্রুবক অক্ষর *sig_namespace, কাঠামো sshkey **sign_keyp,
    কাঠামো sshkey_sig_details **sig_details);

/* Utility functions */

/*
 * Return a base64 encoded "ASCII armoured" version of a raw signature.
 */
পূর্ণসংখ্যা sshsig_armor(ধ্রুবক কাঠামো sshbuf *blob, কাঠামো sshbuf **out);

/*
 * Decode a base64 encoded armoured signature to a raw signature.
 */
পূর্ণসংখ্যা sshsig_dearmor(কাঠামো sshbuf *sig, কাঠামো sshbuf **out);

/*
 * Checks whether a particular key/principal/namespace is permitted by
 * an allowed_keys file. Returns 0 on success.
 */
পূর্ণসংখ্যা sshsig_check_allowed_চাবিগুলি(ধ্রুবক অক্ষর *path, ধ্রুবক কাঠামো sshkey *sign_চাবি,
    ধ্রুবক অক্ষর *principal, ধ্রুবক অক্ষর *ns, uint64_t verify_time);

/* Parse zero or more allowed_keys signature options */
কাঠামো sshsigopt *sshsigopt_parse(ধ্রুবক অক্ষর *opts,
    ধ্রুবক অক্ষর *path, u_long linenum, ধ্রুবক অক্ষর **errstrp);

/* Free signature options */
শূন্য sshsigopt_free(কাঠামো sshsigopt *opts);

/* Get public key from signature */
পূর্ণসংখ্যা sshsig_get_pubkey(কাঠামো sshbuf *signature, কাঠামো sshkey **pubkey);

/* Find principal in allowed_keys file, given a sshkey. Returns
 * 0 on success.
 */
পূর্ণসংখ্যা sshsig_find_principals(ধ্রুবক অক্ষর *path, ধ্রুবক কাঠামো sshkey *sign_চাবি,
    uint64_t verify_time, অক্ষর **principal);

/* Find all principals in allowed_keys file matching *principal */
পূর্ণসংখ্যা sshsig_match_principals(ধ্রুবক অক্ষর *path,
	ধ্রুবক অক্ষর *principal, অক্ষর ***principalsp, আকার_t *nprincipalsp);

#endif /* SSHSIG_H */
