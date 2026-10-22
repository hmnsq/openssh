/* 	$OpenBSD: common.h,v 1.3 2025/05/06 06:05:48 djm Exp $ */
/*
 * Helpers for key API tests
 *
 * Placed in the public domain
 */

/* Load a binary file into a buffer */
ساخت sshbuf *بھرو_file(ثابت حرف *name);

/* Load a text file into a buffer */
ساخت sshbuf *بھرو_متن_file(ثابت حرف *name);

/* Load a bignum from a file */
BIGNUM *بھرو_bignum(ثابت حرف *name);

/* Accessors for key components */
ثابت BIGNUM *rsa_n(ساخت sshkey *k);
ثابت BIGNUM *rsa_e(ساخت sshkey *k);
ثابت BIGNUM *rsa_p(ساخت sshkey *k);
ثابت BIGNUM *rsa_q(ساخت sshkey *k);

