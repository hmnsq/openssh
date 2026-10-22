/* 	$OpenBSD: common.h,v 1.3 2025/05/06 06:05:48 djm Exp $ */
/*
 * Helpers for key API tests
 *
 * Placed in the public domain
 */

/* Load a binary file into a buffer */
ساختار sshbuf *load_file(ثابت نویسه *name);

/* Load a text file into a buffer */
ساختار sshbuf *load_text_file(ثابت نویسه *name);

/* Load a bignum from a file */
BIGNUM *load_bignum(ثابت نویسه *name);

/* Accessors for key components */
ثابت BIGNUM *rsa_n(ساختار sshkey *k);
ثابت BIGNUM *rsa_e(ساختار sshkey *k);
ثابت BIGNUM *rsa_p(ساختار sshkey *k);
ثابت BIGNUM *rsa_q(ساختار sshkey *k);

