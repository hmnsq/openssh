/* 	$OpenBSD: common.h,v 1.3 2025/05/06 06:05:48 djm Exp $ */
/*
 * Helpers for key API tests
 *
 * Placed in the public domain
 */

/* Load a binary file into a buffer */
கட்டமைப்பு sshbuf *load_file(மாறிலி எழுத்து *name);

/* Load a text file into a buffer */
கட்டமைப்பு sshbuf *load_text_file(மாறிலி எழுத்து *name);

/* Load a bignum from a file */
BIGNUM *load_bignum(மாறிலி எழுத்து *name);

/* Accessors for key components */
மாறிலி BIGNUM *rsa_n(கட்டமைப்பு sshkey *k);
மாறிலி BIGNUM *rsa_e(கட்டமைப்பு sshkey *k);
மாறிலி BIGNUM *rsa_p(கட்டமைப்பு sshkey *k);
மாறிலி BIGNUM *rsa_q(கட்டமைப்பு sshkey *k);

