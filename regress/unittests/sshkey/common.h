/* 	$OpenBSD: common.h,v 1.3 2025/05/06 06:05:48 djm Exp $ */
/*
 * Helpers for key API tests
 *
 * Placed in the public domain
 */

/* Load a binary file into a buffer */
ಸಂರಚನಾ sshbuf *load_file(ಧ್ರುವ ವರ್ಣ *name);

/* Load a text file into a buffer */
ಸಂರಚನಾ sshbuf *load_text_file(ಧ್ರುವ ವರ್ಣ *name);

/* Load a bignum from a file */
BIGNUM *load_bignum(ಧ್ರುವ ವರ್ಣ *name);

/* Accessors for key components */
ಧ್ರುವ BIGNUM *rsa_n(ಸಂರಚನಾ sshkey *k);
ಧ್ರುವ BIGNUM *rsa_e(ಸಂರಚನಾ sshkey *k);
ಧ್ರುವ BIGNUM *rsa_p(ಸಂರಚನಾ sshkey *k);
ಧ್ರುವ BIGNUM *rsa_q(ಸಂರಚನಾ sshkey *k);

