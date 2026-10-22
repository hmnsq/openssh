/* 	$OpenBSD: common.h,v 1.3 2025/05/06 06:05:48 djm Exp $ */
/*
 * Helpers for key API tests
 *
 * Placed in the public domain
 */

/* Load a binary file into a buffer */
بنية sshbuf *load_file(ثابت حرف *name);

/* Load a text file into a buffer */
بنية sshbuf *load_text_file(ثابت حرف *name);

/* Load a bignum from a file */
BIGNUM *load_bignum(ثابت حرف *name);

/* Accessors for key components */
ثابت BIGNUM *rsa_n(بنية sshkey *k);
ثابت BIGNUM *rsa_e(بنية sshkey *k);
ثابت BIGNUM *rsa_p(بنية sshkey *k);
ثابت BIGNUM *rsa_q(بنية sshkey *k);

