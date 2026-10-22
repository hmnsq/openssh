/* 	$OpenBSD: common.h,v 1.3 2025/05/06 06:05:48 djm Exp $ */
/*
 * Helpers for key API tests
 *
 * Placed in the public domain
 */

/* Load a binary file into a buffer */
संरचना sshbuf *load_file(स्थिरांक अक्षर *name);

/* Load a text file into a buffer */
संरचना sshbuf *load_text_file(स्थिरांक अक्षर *name);

/* Load a bignum from a file */
BIGNUM *load_bignum(स्थिरांक अक्षर *name);

/* Accessors for key components */
स्थिरांक BIGNUM *rsa_n(संरचना sshkey *k);
स्थिरांक BIGNUM *rsa_e(संरचना sshkey *k);
स्थिरांक BIGNUM *rsa_p(संरचना sshkey *k);
स्थिरांक BIGNUM *rsa_q(संरचना sshkey *k);

