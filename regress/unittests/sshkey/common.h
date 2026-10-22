/* 	$OpenBSD: common.h,v 1.3 2025/05/06 06:05:48 djm Exp $ */
/*
 * Helpers for key API tests
 *
 * Placed in the public domain
 */

/* Load a binary file into a buffer */
সংরচনা sshbuf *load_file(ধ্রুৱ ৱর্ণ *name);

/* Load a text file into a buffer */
সংরচনা sshbuf *load_text_file(ধ্রুৱ ৱর্ণ *name);

/* Load a bignum from a file */
BIGNUM *load_bignum(ধ্রুৱ ৱর্ণ *name);

/* Accessors for key components */
ধ্রুৱ BIGNUM *rsa_n(সংরচনা sshkey *k);
ধ্রুৱ BIGNUM *rsa_e(সংরচনা sshkey *k);
ধ্রুৱ BIGNUM *rsa_p(সংরচনা sshkey *k);
ধ্রুৱ BIGNUM *rsa_q(সংরচনা sshkey *k);

