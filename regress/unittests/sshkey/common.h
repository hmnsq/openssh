/* 	$OpenBSD: common.h,v 1.3 2025/05/06 06:05:48 djm Exp $ */
/*
 * Helpers for key API tests
 *
 * Placed in the public domain
 */

/* Load a binary file into a buffer */
ഘടന sshbuf *load_file(സ്ഥിരം അക്ഷരം *name);

/* Load a text file into a buffer */
ഘടന sshbuf *load_text_file(സ്ഥിരം അക്ഷരം *name);

/* Load a bignum from a file */
BIGNUM *load_bignum(സ്ഥിരം അക്ഷരം *name);

/* Accessors for key components */
സ്ഥിരം BIGNUM *rsa_n(ഘടന sshkey *k);
സ്ഥിരം BIGNUM *rsa_e(ഘടന sshkey *k);
സ്ഥിരം BIGNUM *rsa_p(ഘടന sshkey *k);
സ്ഥിരം BIGNUM *rsa_q(ഘടന sshkey *k);

