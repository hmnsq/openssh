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

ഘടന sshbuf;
ഘടന sshkey;
ഘടന sshsigopt;
ഘടന sshkey_sig_details;

തരനിർവചനം പൂർണ്ണസംഖ്യ sshsig_signer(ഘടന sshkey *, u_char **, size_t *,
    സ്ഥിരം u_char *, size_t, സ്ഥിരം അക്ഷരം *, സ്ഥിരം അക്ഷരം *, സ്ഥിരം അക്ഷരം *,
    u_int, ശൂന്യം *);

/* Buffer-oriented API */

/*
 * Creates a detached SSH signature for a given buffer.
 * Returns 0 on success or a negative SSH_ERR_* error code on failure.
 * out is populated with the detached signature, or NULL on failure.
 */
പൂർണ്ണസംഖ്യ sshsig_signb(ഘടന sshkey *താക്കോൽ, സ്ഥിരം അക്ഷരം *hashalg,
    സ്ഥിരം അക്ഷരം *sk_provider, സ്ഥിരം അക്ഷരം *sk_pin, സ്ഥിരം ഘടന sshbuf *message,
    സ്ഥിരം അക്ഷരം *sig_namespace, ഘടന sshbuf **out,
    sshsig_signer *signer, ശൂന്യം *signer_ctx);

/*
 * Verifies that a detached signature is valid and optionally returns key
 * used to sign via argument.
 * Returns 0 on success or a negative SSH_ERR_* error code on failure.
 */
പൂർണ്ണസംഖ്യ sshsig_verifyb(ഘടന sshbuf *signature,
    സ്ഥിരം ഘടന sshbuf *message, സ്ഥിരം അക്ഷരം *sig_namespace,
    ഘടന sshkey **sign_keyp, ഘടന sshkey_sig_details **sig_details);

/* File/FD-oriented API */

/*
 * Creates a detached SSH signature for a given file.
 * Returns 0 on success or a negative SSH_ERR_* error code on failure.
 * out is populated with the detached signature, or NULL on failure.
 */
പൂർണ്ണസംഖ്യ sshsig_sign_fd(ഘടന sshkey *താക്കോൽ, സ്ഥിരം അക്ഷരം *hashalg,
    സ്ഥിരം അക്ഷരം *sk_provider, സ്ഥിരം അക്ഷരം *sk_pin,
    പൂർണ്ണസംഖ്യ fd, സ്ഥിരം അക്ഷരം *sig_namespace,
    ഘടന sshbuf **out, sshsig_signer *signer, ശൂന്യം *signer_ctx);

/*
 * Verifies that a detached signature over a file is valid and optionally
 * returns key used to sign via argument.
 * Returns 0 on success or a negative SSH_ERR_* error code on failure.
 */
പൂർണ്ണസംഖ്യ sshsig_verify_fd(ഘടന sshbuf *signature, പൂർണ്ണസംഖ്യ fd,
    സ്ഥിരം അക്ഷരം *sig_namespace, ഘടന sshkey **sign_keyp,
    ഘടന sshkey_sig_details **sig_details);

/* Utility functions */

/*
 * Return a base64 encoded "ASCII armoured" version of a raw signature.
 */
പൂർണ്ണസംഖ്യ sshsig_armor(സ്ഥിരം ഘടന sshbuf *blob, ഘടന sshbuf **out);

/*
 * Decode a base64 encoded armoured signature to a raw signature.
 */
പൂർണ്ണസംഖ്യ sshsig_dearmor(ഘടന sshbuf *sig, ഘടന sshbuf **out);

/*
 * Checks whether a particular key/principal/namespace is permitted by
 * an allowed_keys file. Returns 0 on success.
 */
പൂർണ്ണസംഖ്യ sshsig_check_allowed_താക്കോലുകൾ(സ്ഥിരം അക്ഷരം *path, സ്ഥിരം ഘടന sshkey *sign_താക്കോൽ,
    സ്ഥിരം അക്ഷരം *principal, സ്ഥിരം അക്ഷരം *ns, uint64_t verify_time);

/* Parse zero or more allowed_keys signature options */
ഘടന sshsigopt *sshsigopt_parse(സ്ഥിരം അക്ഷരം *opts,
    സ്ഥിരം അക്ഷരം *path, u_long linenum, സ്ഥിരം അക്ഷരം **errstrp);

/* Free signature options */
ശൂന്യം sshsigopt_free(ഘടന sshsigopt *opts);

/* Get public key from signature */
പൂർണ്ണസംഖ്യ sshsig_get_pubkey(ഘടന sshbuf *signature, ഘടന sshkey **pubkey);

/* Find principal in allowed_keys file, given a sshkey. Returns
 * 0 on success.
 */
പൂർണ്ണസംഖ്യ sshsig_find_principals(സ്ഥിരം അക്ഷരം *path, സ്ഥിരം ഘടന sshkey *sign_താക്കോൽ,
    uint64_t verify_time, അക്ഷരം **principal);

/* Find all principals in allowed_keys file matching *principal */
പൂർണ്ണസംഖ്യ sshsig_match_principals(സ്ഥിരം അക്ഷരം *path,
	സ്ഥിരം അക്ഷരം *principal, അക്ഷരം ***principalsp, size_t *nprincipalsp);

#endif /* SSHSIG_H */
