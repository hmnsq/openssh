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

संरचना sshbuf;
संरचना sshkey;
संरचना sshsigopt;
संरचना sshkey_sig_details;

प्रकारव्याख्या पूर्णांक sshsig_signer(संरचना sshkey *, u_char **, माप_प्रकार *,
    स्थिरांक u_char *, माप_प्रकार, स्थिरांक अक्षर *, स्थिरांक अक्षर *, स्थिरांक अक्षर *,
    u_int, शून्य *);

/* Buffer-oriented API */

/*
 * Creates a detached SSH signature for a given buffer.
 * Returns 0 on success or a negative SSH_ERR_* error code on failure.
 * out is populated with the detached signature, or NULL on failure.
 */
पूर्णांक sshsig_signb(संरचना sshkey *किल्ली, स्थिरांक अक्षर *hashalg,
    स्थिरांक अक्षर *sk_provider, स्थिरांक अक्षर *sk_pin, स्थिरांक संरचना sshbuf *message,
    स्थिरांक अक्षर *sig_namespace, संरचना sshbuf **out,
    sshsig_signer *signer, शून्य *signer_ctx);

/*
 * Verifies that a detached signature is valid and optionally returns key
 * used to sign via argument.
 * Returns 0 on success or a negative SSH_ERR_* error code on failure.
 */
पूर्णांक sshsig_verifyb(संरचना sshbuf *signature,
    स्थिरांक संरचना sshbuf *message, स्थिरांक अक्षर *sig_namespace,
    संरचना sshkey **sign_keyp, संरचना sshkey_sig_details **sig_details);

/* File/FD-oriented API */

/*
 * Creates a detached SSH signature for a given file.
 * Returns 0 on success or a negative SSH_ERR_* error code on failure.
 * out is populated with the detached signature, or NULL on failure.
 */
पूर्णांक sshsig_sign_fd(संरचना sshkey *किल्ली, स्थिरांक अक्षर *hashalg,
    स्थिरांक अक्षर *sk_provider, स्थिरांक अक्षर *sk_pin,
    पूर्णांक fd, स्थिरांक अक्षर *sig_namespace,
    संरचना sshbuf **out, sshsig_signer *signer, शून्य *signer_ctx);

/*
 * Verifies that a detached signature over a file is valid and optionally
 * returns key used to sign via argument.
 * Returns 0 on success or a negative SSH_ERR_* error code on failure.
 */
पूर्णांक sshsig_verify_fd(संरचना sshbuf *signature, पूर्णांक fd,
    स्थिरांक अक्षर *sig_namespace, संरचना sshkey **sign_keyp,
    संरचना sshkey_sig_details **sig_details);

/* Utility functions */

/*
 * Return a base64 encoded "ASCII armoured" version of a raw signature.
 */
पूर्णांक sshsig_armor(स्थिरांक संरचना sshbuf *blob, संरचना sshbuf **out);

/*
 * Decode a base64 encoded armoured signature to a raw signature.
 */
पूर्णांक sshsig_dearmor(संरचना sshbuf *sig, संरचना sshbuf **out);

/*
 * Checks whether a particular key/principal/namespace is permitted by
 * an allowed_keys file. Returns 0 on success.
 */
पूर्णांक sshsig_check_allowed_किल्ल्या(स्थिरांक अक्षर *path, स्थिरांक संरचना sshkey *sign_किल्ली,
    स्थिरांक अक्षर *principal, स्थिरांक अक्षर *ns, uint64_t verify_time);

/* Parse zero or more allowed_keys signature options */
संरचना sshsigopt *sshsigopt_parse(स्थिरांक अक्षर *opts,
    स्थिरांक अक्षर *path, u_long linenum, स्थिरांक अक्षर **errstrp);

/* Free signature options */
शून्य sshsigopt_free(संरचना sshsigopt *opts);

/* Get public key from signature */
पूर्णांक sshsig_get_pubkey(संरचना sshbuf *signature, संरचना sshkey **pubkey);

/* Find principal in allowed_keys file, given a sshkey. Returns
 * 0 on success.
 */
पूर्णांक sshsig_find_principals(स्थिरांक अक्षर *path, स्थिरांक संरचना sshkey *sign_किल्ली,
    uint64_t verify_time, अक्षर **principal);

/* Find all principals in allowed_keys file matching *principal */
पूर्णांक sshsig_match_principals(स्थिरांक अक्षर *path,
	स्थिरांक अक्षर *principal, अक्षर ***principalsp, माप_प्रकार *nprincipalsp);

#endif /* SSHSIG_H */
