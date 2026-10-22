/* 	$OpenBSD: common.h,v 1.3 2025/05/06 06:05:48 djm Exp $ */
/*
 * Helpers for key API tests
 *
 * Placed in the public domain
 */

/* Load a binary file into a buffer */
સંરચના sshbuf *load_file(અચલ અક્ષર *name);

/* Load a text file into a buffer */
સંરચના sshbuf *load_text_file(અચલ અક્ષર *name);

/* Load a bignum from a file */
BIGNUM *load_bignum(અચલ અક્ષર *name);

/* Accessors for key components */
અચલ BIGNUM *rsa_n(સંરચના sshkey *k);
અચલ BIGNUM *rsa_e(સંરચના sshkey *k);
અચલ BIGNUM *rsa_p(સંરચના sshkey *k);
અચલ BIGNUM *rsa_q(સંરચના sshkey *k);

