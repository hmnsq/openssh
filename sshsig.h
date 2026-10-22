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

#اگر_غیر_تعریف_شدہ SSHSIG_H
#تعریف_کرو SSHSIG_H

ساخت sshbuf;
ساخت sshkey;
ساخت sshsigopt;
ساخت sshkey_sig_details;

قسمتعریف صحیح sshsig_signer(ساخت sshkey *, u_char **, سائز_t *,
    ثابت u_char *, سائز_t, ثابت حرف *, ثابت حرف *, ثابت حرف *,
    u_int, خالی *);

/* Buffer-oriented API */

/*
 * Creates a detached SSH signature for a given buffer.
 * Returns 0 on success or a negative SSH_ERR_* error code on failure.
 * out is populated with the detached signature, or NULL on failure.
 */
صحیح sshsig_signb(ساخت sshkey *کلید, ثابت حرف *hashalg,
    ثابت حرف *sk_provider, ثابت حرف *sk_pin, ثابت ساخت sshbuf *پیغام_2,
    ثابت حرف *sig_namespace, ساخت sshbuf **برآمد,
    sshsig_signer *signer, خالی *signer_ctx);

/*
 * Verifies that a detached signature is valid and optionally returns key
 * used to sign via argument.
 * Returns 0 on success or a negative SSH_ERR_* error code on failure.
 */
صحیح sshsig_verifyb(ساخت sshbuf *signature,
    ثابت ساخت sshbuf *پیغام_2, ثابت حرف *sig_namespace,
    ساخت sshkey **sign_keyp, ساخت sshkey_sig_details **sig_details);

/* File/FD-oriented API */

/*
 * Creates a detached SSH signature for a given file.
 * Returns 0 on success or a negative SSH_ERR_* error code on failure.
 * out is populated with the detached signature, or NULL on failure.
 */
صحیح sshsig_sign_fd(ساخت sshkey *کلید, ثابت حرف *hashalg,
    ثابت حرف *sk_provider, ثابت حرف *sk_pin,
    صحیح fd, ثابت حرف *sig_namespace,
    ساخت sshbuf **برآمد, sshsig_signer *signer, خالی *signer_ctx);

/*
 * Verifies that a detached signature over a file is valid and optionally
 * returns key used to sign via argument.
 * Returns 0 on success or a negative SSH_ERR_* error code on failure.
 */
صحیح sshsig_verify_fd(ساخت sshbuf *signature, صحیح fd,
    ثابت حرف *sig_namespace, ساخت sshkey **sign_keyp,
    ساخت sshkey_sig_details **sig_details);

/* Utility functions */

/*
 * Return a base64 encoded "ASCII armoured" version of a raw signature.
 */
صحیح sshsig_armor(ثابت ساخت sshbuf *blob, ساخت sshbuf **برآمد);

/*
 * Decode a base64 encoded armoured signature to a raw signature.
 */
صحیح sshsig_dearmor(ساخت sshbuf *sig, ساخت sshbuf **برآمد);

/*
 * Checks whether a particular key/principal/namespace is permitted by
 * an allowed_keys file. Returns 0 on success.
 */
صحیح sshsig_check_allowed_کلیدیں(ثابت حرف *راستہ, ثابت ساخت sshkey *sign_کلید,
    ثابت حرف *principal, ثابت حرف *ns, uint64_t verify_وقت);

/* Parse zero or more allowed_keys signature options */
ساخت sshsigopt *sshsigopt_parse(ثابت حرف *opts,
    ثابت حرف *راستہ, u_long linenum, ثابت حرف **errstrp);

/* Free signature options */
خالی sshsigopt_free(ساخت sshsigopt *opts);

/* Get public key from signature */
صحیح sshsig_get_pubkey(ساخت sshbuf *signature, ساخت sshkey **pubkey);

/* Find principal in allowed_keys file, given a sshkey. Returns
 * 0 on success.
 */
صحیح sshsig_ڈھونڈو_principals(ثابت حرف *راستہ, ثابت ساخت sshkey *sign_کلید,
    uint64_t verify_وقت, حرف **principal);

/* Find all principals in allowed_keys file matching *principal */
صحیح sshsig_مطابقت_principals(ثابت حرف *راستہ,
	ثابت حرف *principal, حرف ***principalsp, سائز_t *nprincipalsp);

#اگر_ختم /* SSHSIG_H */
