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

#अगर_अघोषित SSHSIG_H
#घोषणा SSHSIG_H

काष्ठा sshbuf;
काष्ठा sshkey;
काष्ठा sshsigopt;
काष्ठा sshkey_sig_details;

प्रकार पूर्णांक sshsig_signer(काष्ठा sshkey *, u_char **, माप_प्रकार *,
    स्थिर u_char *, माप_प्रकार, स्थिर अक्षर *, स्थिर अक्षर *, स्थिर अक्षर *,
    u_int, व्योम *);

/* Buffer-oriented API */

/*
 * Creates a detached SSH signature for a given buffer.
 * Returns 0 on success or a negative SSH_ERR_* error code on failure.
 * out is populated with the detached signature, or NULL on failure.
 */
पूर्णांक sshsig_signb(काष्ठा sshkey *कुंजी, स्थिर अक्षर *hashalg,
    स्थिर अक्षर *sk_provider, स्थिर अक्षर *sk_pin, स्थिर काष्ठा sshbuf *message,
    स्थिर अक्षर *sig_namespace, काष्ठा sshbuf **out,
    sshsig_signer *signer, व्योम *signer_ctx);

/*
 * Verifies that a detached signature is valid and optionally returns key
 * used to sign via argument.
 * Returns 0 on success or a negative SSH_ERR_* error code on failure.
 */
पूर्णांक sshsig_verifyb(काष्ठा sshbuf *signature,
    स्थिर काष्ठा sshbuf *message, स्थिर अक्षर *sig_namespace,
    काष्ठा sshkey **sign_keyp, काष्ठा sshkey_sig_details **sig_details);

/* File/FD-oriented API */

/*
 * Creates a detached SSH signature for a given file.
 * Returns 0 on success or a negative SSH_ERR_* error code on failure.
 * out is populated with the detached signature, or NULL on failure.
 */
पूर्णांक sshsig_sign_fd(काष्ठा sshkey *कुंजी, स्थिर अक्षर *hashalg,
    स्थिर अक्षर *sk_provider, स्थिर अक्षर *sk_pin,
    पूर्णांक fd, स्थिर अक्षर *sig_namespace,
    काष्ठा sshbuf **out, sshsig_signer *signer, व्योम *signer_ctx);

/*
 * Verifies that a detached signature over a file is valid and optionally
 * returns key used to sign via argument.
 * Returns 0 on success or a negative SSH_ERR_* error code on failure.
 */
पूर्णांक sshsig_verify_fd(काष्ठा sshbuf *signature, पूर्णांक fd,
    स्थिर अक्षर *sig_namespace, काष्ठा sshkey **sign_keyp,
    काष्ठा sshkey_sig_details **sig_details);

/* Utility functions */

/*
 * Return a base64 encoded "ASCII armoured" version of a raw signature.
 */
पूर्णांक sshsig_armor(स्थिर काष्ठा sshbuf *blob, काष्ठा sshbuf **out);

/*
 * Decode a base64 encoded armoured signature to a raw signature.
 */
पूर्णांक sshsig_dearmor(काष्ठा sshbuf *sig, काष्ठा sshbuf **out);

/*
 * Checks whether a particular key/principal/namespace is permitted by
 * an allowed_keys file. Returns 0 on success.
 */
पूर्णांक sshsig_check_allowed_कुंजियाँ(स्थिर अक्षर *path, स्थिर काष्ठा sshkey *sign_कुंजी,
    स्थिर अक्षर *principal, स्थिर अक्षर *ns, uint64_t verify_time);

/* Parse zero or more allowed_keys signature options */
काष्ठा sshsigopt *sshsigopt_parse(स्थिर अक्षर *opts,
    स्थिर अक्षर *path, u_long linenum, स्थिर अक्षर **errstrp);

/* Free signature options */
व्योम sshsigopt_free(काष्ठा sshsigopt *opts);

/* Get public key from signature */
पूर्णांक sshsig_get_pubkey(काष्ठा sshbuf *signature, काष्ठा sshkey **pubkey);

/* Find principal in allowed_keys file, given a sshkey. Returns
 * 0 on success.
 */
पूर्णांक sshsig_find_principals(स्थिर अक्षर *path, स्थिर काष्ठा sshkey *sign_कुंजी,
    uint64_t verify_time, अक्षर **principal);

/* Find all principals in allowed_keys file matching *principal */
पूर्णांक sshsig_match_principals(स्थिर अक्षर *path,
	स्थिर अक्षर *principal, अक्षर ***principalsp, माप_प्रकार *nprincipalsp);

#पूर्ण_अगर /* SSHSIG_H */
