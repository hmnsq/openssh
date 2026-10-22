/* 	$OpenBSD: common.h,v 1.3 2025/05/06 06:05:48 djm Exp $ */
/*
 * Helpers for key API tests
 *
 * Placed in the public domain
 */

/* Load a binary file into a buffer */
ସଂରଚନା sshbuf *load_file(ଅଚଳ ଅକ୍ଷର *name);

/* Load a text file into a buffer */
ସଂରଚନା sshbuf *load_text_file(ଅଚଳ ଅକ୍ଷର *name);

/* Load a bignum from a file */
BIGNUM *load_bignum(ଅଚଳ ଅକ୍ଷର *name);

/* Accessors for key components */
ଅଚଳ BIGNUM *rsa_n(ସଂରଚନା sshkey *k);
ଅଚଳ BIGNUM *rsa_e(ସଂରଚନା sshkey *k);
ଅଚଳ BIGNUM *rsa_p(ସଂରଚନା sshkey *k);
ଅଚଳ BIGNUM *rsa_q(ସଂରଚନା sshkey *k);

