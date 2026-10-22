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

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ SSHSIG_H
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHSIG_H

ਬਣਤਰ sshbuf;
ਬਣਤਰ sshkey;
ਬਣਤਰ sshsigopt;
ਬਣਤਰ sshkey_sig_details;

ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਪੂਰਨ sshsig_signer(ਬਣਤਰ sshkey *, u_char **, ਮਾਪ_t *,
    ਅਚਲ u_char *, ਮਾਪ_t, ਅਚਲ ਅੱਖਰ *, ਅਚਲ ਅੱਖਰ *, ਅਚਲ ਅੱਖਰ *,
    u_int, ਖਾਲੀ *);

/* Buffer-oriented API */

/*
 * Creates a detached SSH signature for a given buffer.
 * Returns 0 on success or a negative SSH_ERR_* error code on failure.
 * out is populated with the detached signature, or NULL on failure.
 */
ਪੂਰਨ sshsig_signb(ਬਣਤਰ sshkey *ਕੁੰਜੀ, ਅਚਲ ਅੱਖਰ *hashalg,
    ਅਚਲ ਅੱਖਰ *sk_provider, ਅਚਲ ਅੱਖਰ *sk_pin, ਅਚਲ ਬਣਤਰ sshbuf *ਸੁਨੇਹਾ_2,
    ਅਚਲ ਅੱਖਰ *sig_namespace, ਬਣਤਰ sshbuf **ਬਾਹਰਲਾ,
    sshsig_signer *signer, ਖਾਲੀ *signer_ctx);

/*
 * Verifies that a detached signature is valid and optionally returns key
 * used to sign via argument.
 * Returns 0 on success or a negative SSH_ERR_* error code on failure.
 */
ਪੂਰਨ sshsig_verifyb(ਬਣਤਰ sshbuf *signature,
    ਅਚਲ ਬਣਤਰ sshbuf *ਸੁਨੇਹਾ_2, ਅਚਲ ਅੱਖਰ *sig_namespace,
    ਬਣਤਰ sshkey **sign_keyp, ਬਣਤਰ sshkey_sig_details **sig_details);

/* File/FD-oriented API */

/*
 * Creates a detached SSH signature for a given file.
 * Returns 0 on success or a negative SSH_ERR_* error code on failure.
 * out is populated with the detached signature, or NULL on failure.
 */
ਪੂਰਨ sshsig_sign_fd(ਬਣਤਰ sshkey *ਕੁੰਜੀ, ਅਚਲ ਅੱਖਰ *hashalg,
    ਅਚਲ ਅੱਖਰ *sk_provider, ਅਚਲ ਅੱਖਰ *sk_pin,
    ਪੂਰਨ fd, ਅਚਲ ਅੱਖਰ *sig_namespace,
    ਬਣਤਰ sshbuf **ਬਾਹਰਲਾ, sshsig_signer *signer, ਖਾਲੀ *signer_ctx);

/*
 * Verifies that a detached signature over a file is valid and optionally
 * returns key used to sign via argument.
 * Returns 0 on success or a negative SSH_ERR_* error code on failure.
 */
ਪੂਰਨ sshsig_verify_fd(ਬਣਤਰ sshbuf *signature, ਪੂਰਨ fd,
    ਅਚਲ ਅੱਖਰ *sig_namespace, ਬਣਤਰ sshkey **sign_keyp,
    ਬਣਤਰ sshkey_sig_details **sig_details);

/* Utility functions */

/*
 * Return a base64 encoded "ASCII armoured" version of a raw signature.
 */
ਪੂਰਨ sshsig_armor(ਅਚਲ ਬਣਤਰ sshbuf *blob, ਬਣਤਰ sshbuf **ਬਾਹਰਲਾ);

/*
 * Decode a base64 encoded armoured signature to a raw signature.
 */
ਪੂਰਨ sshsig_dearmor(ਬਣਤਰ sshbuf *sig, ਬਣਤਰ sshbuf **ਬਾਹਰਲਾ);

/*
 * Checks whether a particular key/principal/namespace is permitted by
 * an allowed_keys file. Returns 0 on success.
 */
ਪੂਰਨ sshsig_check_allowed_ਕੁੰਜੀਆਂ(ਅਚਲ ਅੱਖਰ *ਰਸਤਾ, ਅਚਲ ਬਣਤਰ sshkey *sign_ਕੁੰਜੀ,
    ਅਚਲ ਅੱਖਰ *principal, ਅਚਲ ਅੱਖਰ *ns, uint64_t verify_ਸਮਾਂ);

/* Parse zero or more allowed_keys signature options */
ਬਣਤਰ sshsigopt *sshsigopt_parse(ਅਚਲ ਅੱਖਰ *opts,
    ਅਚਲ ਅੱਖਰ *ਰਸਤਾ, u_long linenum, ਅਚਲ ਅੱਖਰ **errstrp);

/* Free signature options */
ਖਾਲੀ sshsigopt_free(ਬਣਤਰ sshsigopt *opts);

/* Get public key from signature */
ਪੂਰਨ sshsig_get_pubkey(ਬਣਤਰ sshbuf *signature, ਬਣਤਰ sshkey **pubkey);

/* Find principal in allowed_keys file, given a sshkey. Returns
 * 0 on success.
 */
ਪੂਰਨ sshsig_ਲੱਭੋ_principals(ਅਚਲ ਅੱਖਰ *ਰਸਤਾ, ਅਚਲ ਬਣਤਰ sshkey *sign_ਕੁੰਜੀ,
    uint64_t verify_ਸਮਾਂ, ਅੱਖਰ **principal);

/* Find all principals in allowed_keys file matching *principal */
ਪੂਰਨ sshsig_ਮੇਲ_principals(ਅਚਲ ਅੱਖਰ *ਰਸਤਾ,
	ਅਚਲ ਅੱਖਰ *principal, ਅੱਖਰ ***principalsp, ਮਾਪ_t *nprincipalsp);

#ਜੇ_ਅੰਤ /* SSHSIG_H */
