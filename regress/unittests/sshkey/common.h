/* 	$OpenBSD: common.h,v 1.3 2025/05/06 06:05:48 djm Exp $ */
/*
 * Helpers for key API tests
 *
 * Placed in the public domain
 */

/* Load a binary file into a buffer */
কাঠামো sshbuf *load_file(ধ্রুবক অক্ষর *name);

/* Load a text file into a buffer */
কাঠামো sshbuf *load_text_file(ধ্রুবক অক্ষর *name);

/* Load a bignum from a file */
BIGNUM *load_bignum(ধ্রুবক অক্ষর *name);

/* Accessors for key components */
ধ্রুবক BIGNUM *rsa_n(কাঠামো sshkey *k);
ধ্রুবক BIGNUM *rsa_e(কাঠামো sshkey *k);
ধ্রুবক BIGNUM *rsa_p(কাঠামো sshkey *k);
ধ্রুবক BIGNUM *rsa_q(কাঠামো sshkey *k);

