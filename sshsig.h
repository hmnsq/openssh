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

ସଂରଚନା sshbuf;
ସଂରଚନା sshkey;
ସଂରଚନା sshsigopt;
ସଂରଚନା sshkey_sig_details;

ପ୍ରକାରବ୍ୟାଖ୍ୟା ପୂର୍ଣ୍ଣସଂଖ୍ୟା sshsig_signer(ସଂରଚନା sshkey *, u_char **, size_t *,
    ଅଚଳ u_char *, size_t, ଅଚଳ ଅକ୍ଷର *, ଅଚଳ ଅକ୍ଷର *, ଅଚଳ ଅକ୍ଷର *,
    u_int, ଶୂନ୍ୟ *);

/* Buffer-oriented API */

/*
 * Creates a detached SSH signature for a given buffer.
 * Returns 0 on success or a negative SSH_ERR_* error code on failure.
 * out is populated with the detached signature, or NULL on failure.
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା sshsig_signb(ସଂରଚନା sshkey *ଚାବି, ଅଚଳ ଅକ୍ଷର *hashalg,
    ଅଚଳ ଅକ୍ଷର *sk_provider, ଅଚଳ ଅକ୍ଷର *sk_pin, ଅଚଳ ସଂରଚନା sshbuf *message,
    ଅଚଳ ଅକ୍ଷର *sig_namespace, ସଂରଚନା sshbuf **out,
    sshsig_signer *signer, ଶୂନ୍ୟ *signer_ctx);

/*
 * Verifies that a detached signature is valid and optionally returns key
 * used to sign via argument.
 * Returns 0 on success or a negative SSH_ERR_* error code on failure.
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା sshsig_verifyb(ସଂରଚନା sshbuf *signature,
    ଅଚଳ ସଂରଚନା sshbuf *message, ଅଚଳ ଅକ୍ଷର *sig_namespace,
    ସଂରଚନା sshkey **sign_keyp, ସଂରଚନା sshkey_sig_details **sig_details);

/* File/FD-oriented API */

/*
 * Creates a detached SSH signature for a given file.
 * Returns 0 on success or a negative SSH_ERR_* error code on failure.
 * out is populated with the detached signature, or NULL on failure.
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା sshsig_sign_fd(ସଂରଚନା sshkey *ଚାବି, ଅଚଳ ଅକ୍ଷର *hashalg,
    ଅଚଳ ଅକ୍ଷର *sk_provider, ଅଚଳ ଅକ୍ଷର *sk_pin,
    ପୂର୍ଣ୍ଣସଂଖ୍ୟା fd, ଅଚଳ ଅକ୍ଷର *sig_namespace,
    ସଂରଚନା sshbuf **out, sshsig_signer *signer, ଶୂନ୍ୟ *signer_ctx);

/*
 * Verifies that a detached signature over a file is valid and optionally
 * returns key used to sign via argument.
 * Returns 0 on success or a negative SSH_ERR_* error code on failure.
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା sshsig_verify_fd(ସଂରଚନା sshbuf *signature, ପୂର୍ଣ୍ଣସଂଖ୍ୟା fd,
    ଅଚଳ ଅକ୍ଷର *sig_namespace, ସଂରଚନା sshkey **sign_keyp,
    ସଂରଚନା sshkey_sig_details **sig_details);

/* Utility functions */

/*
 * Return a base64 encoded "ASCII armoured" version of a raw signature.
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା sshsig_armor(ଅଚଳ ସଂରଚନା sshbuf *blob, ସଂରଚନା sshbuf **out);

/*
 * Decode a base64 encoded armoured signature to a raw signature.
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା sshsig_dearmor(ସଂରଚନା sshbuf *sig, ସଂରଚନା sshbuf **out);

/*
 * Checks whether a particular key/principal/namespace is permitted by
 * an allowed_keys file. Returns 0 on success.
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା sshsig_check_allowed_ଚାବିଗୁଡ଼ିକ(ଅଚଳ ଅକ୍ଷର *path, ଅଚଳ ସଂରଚନା sshkey *sign_ଚାବି,
    ଅଚଳ ଅକ୍ଷର *principal, ଅଚଳ ଅକ୍ଷର *ns, uint64_t verify_time);

/* Parse zero or more allowed_keys signature options */
ସଂରଚନା sshsigopt *sshsigopt_parse(ଅଚଳ ଅକ୍ଷର *opts,
    ଅଚଳ ଅକ୍ଷର *path, u_long linenum, ଅଚଳ ଅକ୍ଷର **errstrp);

/* Free signature options */
ଶୂନ୍ୟ sshsigopt_free(ସଂରଚନା sshsigopt *opts);

/* Get public key from signature */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା sshsig_get_pubkey(ସଂରଚନା sshbuf *signature, ସଂରଚନା sshkey **pubkey);

/* Find principal in allowed_keys file, given a sshkey. Returns
 * 0 on success.
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା sshsig_find_principals(ଅଚଳ ଅକ୍ଷର *path, ଅଚଳ ସଂରଚନା sshkey *sign_ଚାବି,
    uint64_t verify_time, ଅକ୍ଷର **principal);

/* Find all principals in allowed_keys file matching *principal */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା sshsig_match_principals(ଅଚଳ ଅକ୍ଷର *path,
	ଅଚଳ ଅକ୍ଷର *principal, ଅକ୍ଷର ***principalsp, size_t *nprincipalsp);

#endif /* SSHSIG_H */
