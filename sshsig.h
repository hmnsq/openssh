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

#اگر_تعریف_نشده SSHSIG_H
#تعریف_کن SSHSIG_H

بنية sshbuf;
بنية sshkey;
بنية sshsigopt;
بنية sshkey_sig_details;

تعريفنوع صحيح sshsig_signer(بنية sshkey *, u_char **, اندازه_t *,
    ثابت u_char *, اندازه_t, ثابت حرف *, ثابت حرف *, ثابت حرف *,
    u_int, فراغ *);

/* Buffer-oriented API */

/*
 * Creates a detached SSH signature for a given buffer.
 * Returns 0 on success or a negative SSH_ERR_* error code on failure.
 * out is populated with the detached signature, or NULL on failure.
 */
صحيح sshsig_signb(بنية sshkey *کلید, ثابت حرف *hashalg,
    ثابت حرف *sk_provider, ثابت حرف *sk_pin, ثابت بنية sshbuf *پیام_2,
    ثابت حرف *sig_namespace, بنية sshbuf **بیرون,
    sshsig_signer *signer, فراغ *signer_ctx);

/*
 * Verifies that a detached signature is valid and optionally returns key
 * used to sign via argument.
 * Returns 0 on success or a negative SSH_ERR_* error code on failure.
 */
صحيح sshsig_verifyb(بنية sshbuf *signature,
    ثابت بنية sshbuf *پیام_2, ثابت حرف *sig_namespace,
    بنية sshkey **sign_keyp, بنية sshkey_sig_details **sig_details);

/* File/FD-oriented API */

/*
 * Creates a detached SSH signature for a given file.
 * Returns 0 on success or a negative SSH_ERR_* error code on failure.
 * out is populated with the detached signature, or NULL on failure.
 */
صحيح sshsig_sign_fd(بنية sshkey *کلید, ثابت حرف *hashalg,
    ثابت حرف *sk_provider, ثابت حرف *sk_pin,
    صحيح fd, ثابت حرف *sig_namespace,
    بنية sshbuf **بیرون, sshsig_signer *signer, فراغ *signer_ctx);

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
صحيح sshsig_armor(ثابت بنية sshbuf *blob, بنية sshbuf **بیرون);

/*
 * Decode a base64 encoded armoured signature to a raw signature.
 */
صحيح sshsig_dearmor(بنية sshbuf *sig, بنية sshbuf **بیرون);

/*
 * Checks whether a particular key/principal/namespace is permitted by
 * an allowed_keys file. Returns 0 on success.
 */
صحيح sshsig_check_allowed_کلیدها(ثابت حرف *مسیر, ثابت بنية sshkey *sign_کلید,
    ثابت حرف *principal, ثابت حرف *ns, uint64_t verify_زمان);

/* Parse zero or more allowed_keys signature options */
بنية sshsigopt *sshsigopt_parse(ثابت حرف *opts,
    ثابت حرف *مسیر, u_long linenum, ثابت حرف **errstrp);

/* Free signature options */
فراغ sshsigopt_free(بنية sshsigopt *opts);

/* Get public key from signature */
صحيح sshsig_get_pubkey(بنية sshbuf *signature, بنية sshkey **pubkey);

/* Find principal in allowed_keys file, given a sshkey. Returns
 * 0 on success.
 */
صحيح sshsig_پیدا_کن_principals(ثابت حرف *مسیر, ثابت بنية sshkey *sign_کلید,
    uint64_t verify_زمان, حرف **principal);

/* Find all principals in allowed_keys file matching *principal */
صحيح sshsig_تطابق_principals(ثابت حرف *مسیر,
	ثابت حرف *principal, حرف ***principalsp, اندازه_t *nprincipalsp);

#پایان_اگر /* SSHSIG_H */
