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

கட்டமைப்பு sshbuf;
கட்டமைப்பு sshkey;
கட்டமைப்பு sshsigopt;
கட்டமைப்பு sshkey_sig_details;

வகைவரை முழு sshsig_signer(கட்டமைப்பு sshkey *, u_char **, size_t *,
    மாறிலி u_char *, size_t, மாறிலி எழுத்து *, மாறிலி எழுத்து *, மாறிலி எழுத்து *,
    u_int, வெறுமை *);

/* Buffer-oriented API */

/*
 * Creates a detached SSH signature for a given buffer.
 * Returns 0 on success or a negative SSH_ERR_* error code on failure.
 * out is populated with the detached signature, or NULL on failure.
 */
முழு sshsig_signb(கட்டமைப்பு sshkey *சாவி, மாறிலி எழுத்து *hashalg,
    மாறிலி எழுத்து *sk_provider, மாறிலி எழுத்து *sk_pin, மாறிலி கட்டமைப்பு sshbuf *message,
    மாறிலி எழுத்து *sig_namespace, கட்டமைப்பு sshbuf **out,
    sshsig_signer *signer, வெறுமை *signer_ctx);

/*
 * Verifies that a detached signature is valid and optionally returns key
 * used to sign via argument.
 * Returns 0 on success or a negative SSH_ERR_* error code on failure.
 */
முழு sshsig_verifyb(கட்டமைப்பு sshbuf *signature,
    மாறிலி கட்டமைப்பு sshbuf *message, மாறிலி எழுத்து *sig_namespace,
    கட்டமைப்பு sshkey **sign_keyp, கட்டமைப்பு sshkey_sig_details **sig_details);

/* File/FD-oriented API */

/*
 * Creates a detached SSH signature for a given file.
 * Returns 0 on success or a negative SSH_ERR_* error code on failure.
 * out is populated with the detached signature, or NULL on failure.
 */
முழு sshsig_sign_fd(கட்டமைப்பு sshkey *சாவி, மாறிலி எழுத்து *hashalg,
    மாறிலி எழுத்து *sk_provider, மாறிலி எழுத்து *sk_pin,
    முழு fd, மாறிலி எழுத்து *sig_namespace,
    கட்டமைப்பு sshbuf **out, sshsig_signer *signer, வெறுமை *signer_ctx);

/*
 * Verifies that a detached signature over a file is valid and optionally
 * returns key used to sign via argument.
 * Returns 0 on success or a negative SSH_ERR_* error code on failure.
 */
முழு sshsig_verify_fd(கட்டமைப்பு sshbuf *signature, முழு fd,
    மாறிலி எழுத்து *sig_namespace, கட்டமைப்பு sshkey **sign_keyp,
    கட்டமைப்பு sshkey_sig_details **sig_details);

/* Utility functions */

/*
 * Return a base64 encoded "ASCII armoured" version of a raw signature.
 */
முழு sshsig_armor(மாறிலி கட்டமைப்பு sshbuf *blob, கட்டமைப்பு sshbuf **out);

/*
 * Decode a base64 encoded armoured signature to a raw signature.
 */
முழு sshsig_dearmor(கட்டமைப்பு sshbuf *sig, கட்டமைப்பு sshbuf **out);

/*
 * Checks whether a particular key/principal/namespace is permitted by
 * an allowed_keys file. Returns 0 on success.
 */
முழு sshsig_check_allowed_சாவிகள்(மாறிலி எழுத்து *path, மாறிலி கட்டமைப்பு sshkey *sign_சாவி,
    மாறிலி எழுத்து *principal, மாறிலி எழுத்து *ns, uint64_t verify_time);

/* Parse zero or more allowed_keys signature options */
கட்டமைப்பு sshsigopt *sshsigopt_parse(மாறிலி எழுத்து *opts,
    மாறிலி எழுத்து *path, u_long linenum, மாறிலி எழுத்து **errstrp);

/* Free signature options */
வெறுமை sshsigopt_free(கட்டமைப்பு sshsigopt *opts);

/* Get public key from signature */
முழு sshsig_get_pubkey(கட்டமைப்பு sshbuf *signature, கட்டமைப்பு sshkey **pubkey);

/* Find principal in allowed_keys file, given a sshkey. Returns
 * 0 on success.
 */
முழு sshsig_find_principals(மாறிலி எழுத்து *path, மாறிலி கட்டமைப்பு sshkey *sign_சாவி,
    uint64_t verify_time, எழுத்து **principal);

/* Find all principals in allowed_keys file matching *principal */
முழு sshsig_match_principals(மாறிலி எழுத்து *path,
	மாறிலி எழுத்து *principal, எழுத்து ***principalsp, size_t *nprincipalsp);

#endif /* SSHSIG_H */
