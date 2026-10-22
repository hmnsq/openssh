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

સંરચના sshbuf;
સંરચના sshkey;
સંરચના sshsigopt;
સંરચના sshkey_sig_details;

પ્રકારવ્યાખ્યા પૂર્ણાંક sshsig_signer(સંરચના sshkey *, u_char **, size_t *,
    અચલ u_char *, size_t, અચલ અક્ષર *, અચલ અક્ષર *, અચલ અક્ષર *,
    u_int, શૂન્ય *);

/* Buffer-oriented API */

/*
 * Creates a detached SSH signature for a given buffer.
 * Returns 0 on success or a negative SSH_ERR_* error code on failure.
 * out is populated with the detached signature, or NULL on failure.
 */
પૂર્ણાંક sshsig_signb(સંરચના sshkey *ચાવી, અચલ અક્ષર *hashalg,
    અચલ અક્ષર *sk_provider, અચલ અક્ષર *sk_pin, અચલ સંરચના sshbuf *message,
    અચલ અક્ષર *sig_namespace, સંરચના sshbuf **out,
    sshsig_signer *signer, શૂન્ય *signer_ctx);

/*
 * Verifies that a detached signature is valid and optionally returns key
 * used to sign via argument.
 * Returns 0 on success or a negative SSH_ERR_* error code on failure.
 */
પૂર્ણાંક sshsig_verifyb(સંરચના sshbuf *signature,
    અચલ સંરચના sshbuf *message, અચલ અક્ષર *sig_namespace,
    સંરચના sshkey **sign_keyp, સંરચના sshkey_sig_details **sig_details);

/* File/FD-oriented API */

/*
 * Creates a detached SSH signature for a given file.
 * Returns 0 on success or a negative SSH_ERR_* error code on failure.
 * out is populated with the detached signature, or NULL on failure.
 */
પૂર્ણાંક sshsig_sign_fd(સંરચના sshkey *ચાવી, અચલ અક્ષર *hashalg,
    અચલ અક્ષર *sk_provider, અચલ અક્ષર *sk_pin,
    પૂર્ણાંક fd, અચલ અક્ષર *sig_namespace,
    સંરચના sshbuf **out, sshsig_signer *signer, શૂન્ય *signer_ctx);

/*
 * Verifies that a detached signature over a file is valid and optionally
 * returns key used to sign via argument.
 * Returns 0 on success or a negative SSH_ERR_* error code on failure.
 */
પૂર્ણાંક sshsig_verify_fd(સંરચના sshbuf *signature, પૂર્ણાંક fd,
    અચલ અક્ષર *sig_namespace, સંરચના sshkey **sign_keyp,
    સંરચના sshkey_sig_details **sig_details);

/* Utility functions */

/*
 * Return a base64 encoded "ASCII armoured" version of a raw signature.
 */
પૂર્ણાંક sshsig_armor(અચલ સંરચના sshbuf *blob, સંરચના sshbuf **out);

/*
 * Decode a base64 encoded armoured signature to a raw signature.
 */
પૂર્ણાંક sshsig_dearmor(સંરચના sshbuf *sig, સંરચના sshbuf **out);

/*
 * Checks whether a particular key/principal/namespace is permitted by
 * an allowed_keys file. Returns 0 on success.
 */
પૂર્ણાંક sshsig_check_allowed_ચાવીઓ(અચલ અક્ષર *path, અચલ સંરચના sshkey *sign_ચાવી,
    અચલ અક્ષર *principal, અચલ અક્ષર *ns, uint64_t verify_time);

/* Parse zero or more allowed_keys signature options */
સંરચના sshsigopt *sshsigopt_parse(અચલ અક્ષર *opts,
    અચલ અક્ષર *path, u_long linenum, અચલ અક્ષર **errstrp);

/* Free signature options */
શૂન્ય sshsigopt_free(સંરચના sshsigopt *opts);

/* Get public key from signature */
પૂર્ણાંક sshsig_get_pubkey(સંરચના sshbuf *signature, સંરચના sshkey **pubkey);

/* Find principal in allowed_keys file, given a sshkey. Returns
 * 0 on success.
 */
પૂર્ણાંક sshsig_find_principals(અચલ અક્ષર *path, અચલ સંરચના sshkey *sign_ચાવી,
    uint64_t verify_time, અક્ષર **principal);

/* Find all principals in allowed_keys file matching *principal */
પૂર્ણાંક sshsig_match_principals(અચલ અક્ષર *path,
	અચલ અક્ષર *principal, અક્ષર ***principalsp, size_t *nprincipalsp);

#endif /* SSHSIG_H */
