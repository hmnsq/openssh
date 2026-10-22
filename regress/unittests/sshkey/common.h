/* 	$OpenBSD: common.h,v 1.3 2025/05/06 06:05:48 djm Exp $ */
/*
 * Helpers for key API tests
 *
 * Placed in the public domain
 */

/* Load a binary file into a buffer */
संरचना sshbuf *load_file(अचर वर्ण *name);

/* Load a text file into a buffer */
संरचना sshbuf *load_text_file(अचर वर्ण *name);

/* Load a bignum from a file */
BIGNUM *load_bignum(अचर वर्ण *name);

/* Accessors for key components */
अचर BIGNUM *rsa_n(संरचना sshkey *k);
अचर BIGNUM *rsa_e(संरचना sshkey *k);
अचर BIGNUM *rsa_p(संरचना sshkey *k);
अचर BIGNUM *rsa_q(संरचना sshkey *k);

