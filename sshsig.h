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

ساختار sshbuf;
ساختار sshkey;
ساختار sshsigopt;
ساختار sshkey_sig_details;

تعریفنوع صحیح sshsig_signer(ساختار sshkey *, u_char **, size_t *,
    ثابت u_char *, size_t, ثابت نویسه *, ثابت نویسه *, ثابت نویسه *,
    u_int, تهی *);

/* Buffer-oriented API */

/*
 * Creates a detached SSH signature for a given buffer.
 * Returns 0 on success or a negative SSH_ERR_* error code on failure.
 * out is populated with the detached signature, or NULL on failure.
 */
صحیح sshsig_signb(ساختار sshkey *کلید, ثابت نویسه *hashalg,
    ثابت نویسه *sk_provider, ثابت نویسه *sk_pin, ثابت ساختار sshbuf *message,
    ثابت نویسه *sig_namespace, ساختار sshbuf **out,
    sshsig_signer *signer, تهی *signer_ctx);

/*
 * Verifies that a detached signature is valid and optionally returns key
 * used to sign via argument.
 * Returns 0 on success or a negative SSH_ERR_* error code on failure.
 */
صحیح sshsig_verifyb(ساختار sshbuf *signature,
    ثابت ساختار sshbuf *message, ثابت نویسه *sig_namespace,
    ساختار sshkey **sign_keyp, ساختار sshkey_sig_details **sig_details);

/* File/FD-oriented API */

/*
 * Creates a detached SSH signature for a given file.
 * Returns 0 on success or a negative SSH_ERR_* error code on failure.
 * out is populated with the detached signature, or NULL on failure.
 */
صحیح sshsig_sign_fd(ساختار sshkey *کلید, ثابت نویسه *hashalg,
    ثابت نویسه *sk_provider, ثابت نویسه *sk_pin,
    صحیح fd, ثابت نویسه *sig_namespace,
    ساختار sshbuf **out, sshsig_signer *signer, تهی *signer_ctx);

/*
 * Verifies that a detached signature over a file is valid and optionally
 * returns key used to sign via argument.
 * Returns 0 on success or a negative SSH_ERR_* error code on failure.
 */
صحیح sshsig_verify_fd(ساختار sshbuf *signature, صحیح fd,
    ثابت نویسه *sig_namespace, ساختار sshkey **sign_keyp,
    ساختار sshkey_sig_details **sig_details);

/* Utility functions */

/*
 * Return a base64 encoded "ASCII armoured" version of a raw signature.
 */
صحیح sshsig_armor(ثابت ساختار sshbuf *blob, ساختار sshbuf **out);

/*
 * Decode a base64 encoded armoured signature to a raw signature.
 */
صحیح sshsig_dearmor(ساختار sshbuf *sig, ساختار sshbuf **out);

/*
 * Checks whether a particular key/principal/namespace is permitted by
 * an allowed_keys file. Returns 0 on success.
 */
صحیح sshsig_check_allowed_کلیدها(ثابت نویسه *path, ثابت ساختار sshkey *sign_کلید,
    ثابت نویسه *principal, ثابت نویسه *ns, uint64_t verify_time);

/* Parse zero or more allowed_keys signature options */
ساختار sshsigopt *sshsigopt_parse(ثابت نویسه *opts,
    ثابت نویسه *path, u_long linenum, ثابت نویسه **errstrp);

/* Free signature options */
تهی sshsigopt_free(ساختار sshsigopt *opts);

/* Get public key from signature */
صحیح sshsig_get_pubkey(ساختار sshbuf *signature, ساختار sshkey **pubkey);

/* Find principal in allowed_keys file, given a sshkey. Returns
 * 0 on success.
 */
صحیح sshsig_find_principals(ثابت نویسه *path, ثابت ساختار sshkey *sign_کلید,
    uint64_t verify_time, نویسه **principal);

/* Find all principals in allowed_keys file matching *principal */
صحیح sshsig_match_principals(ثابت نویسه *path,
	ثابت نویسه *principal, نویسه ***principalsp, size_t *nprincipalsp);

#endif /* SSHSIG_H */
