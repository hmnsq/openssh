/* 	$OpenBSD: common.h,v 1.3 2025/05/06 06:05:48 djm Exp $ */
/*
 * Helpers for key API tests
 *
 * Placed in the public domain
 */

/* Load a binary file into a buffer */
काष्ठा sshbuf *load_file(स्थिर अक्षर *name);

/* Load a text file into a buffer */
काष्ठा sshbuf *load_text_file(स्थिर अक्षर *name);

/* Load a bignum from a file */
BIGNUM *load_bignum(स्थिर अक्षर *name);

/* Accessors for key components */
स्थिर BIGNUM *rsa_n(काष्ठा sshkey *k);
स्थिर BIGNUM *rsa_e(काष्ठा sshkey *k);
स्थिर BIGNUM *rsa_p(काष्ठा sshkey *k);
स्थिर BIGNUM *rsa_q(काष्ठा sshkey *k);

