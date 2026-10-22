/* 	$OpenBSD: common.h,v 1.3 2025/05/06 06:05:48 djm Exp $ */
/*
 * Helpers for key API tests
 *
 * Placed in the public domain
 */

/* Load a binary file into a buffer */
संरचना sshbuf *आरोपय_file(ध्रुव वर्ण *name);

/* Load a text file into a buffer */
संरचना sshbuf *आरोपय_text_file(ध्रुव वर्ण *name);

/* Load a bignum from a file */
BIGNUM *आरोपय_bignum(ध्रुव वर्ण *name);

/* Accessors for key components */
ध्रुव BIGNUM *rsa_n(संरचना sshkey *k);
ध्रुव BIGNUM *rsa_e(संरचना sshkey *k);
ध्रुव BIGNUM *rsa_p(संरचना sshkey *k);
ध्रुव BIGNUM *rsa_q(संरचना sshkey *k);

