/* 	$OpenBSD: common.h,v 1.3 2025/05/06 06:05:48 djm Exp $ */
/*
 * Helpers for key API tests
 *
 * Placed in the public domain
 */

/* Load a binary file into a buffer */
ਬਣਤਰ sshbuf *ਲੱਦੋ_file(ਅਚਲ ਅੱਖਰ *name);

/* Load a text file into a buffer */
ਬਣਤਰ sshbuf *ਲੱਦੋ_ਪਾਠ_file(ਅਚਲ ਅੱਖਰ *name);

/* Load a bignum from a file */
BIGNUM *ਲੱਦੋ_bignum(ਅਚਲ ਅੱਖਰ *name);

/* Accessors for key components */
ਅਚਲ BIGNUM *rsa_n(ਬਣਤਰ sshkey *k);
ਅਚਲ BIGNUM *rsa_e(ਬਣਤਰ sshkey *k);
ਅਚਲ BIGNUM *rsa_p(ਬਣਤਰ sshkey *k);
ਅਚਲ BIGNUM *rsa_q(ਬਣਤਰ sshkey *k);

