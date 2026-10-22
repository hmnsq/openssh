/* 	$OpenBSD: common.h,v 1.3 2025/05/06 06:05:48 djm Exp $ */
/*
 * Helpers for key API tests
 *
 * Placed in the public domain
 */

/* Load a binary file into a buffer */
ರಚನೆ sshbuf *ತುಂಬು_file(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *name);

/* Load a text file into a buffer */
ರಚನೆ sshbuf *ತುಂಬು_ಪಠ್ಯ_file(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *name);

/* Load a bignum from a file */
BIGNUM *ತುಂಬು_bignum(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *name);

/* Accessors for key components */
ಸ್ಥಿರಾಂಕ BIGNUM *rsa_n(ರಚನೆ sshkey *k);
ಸ್ಥಿರಾಂಕ BIGNUM *rsa_e(ರಚನೆ sshkey *k);
ಸ್ಥಿರಾಂಕ BIGNUM *rsa_p(ರಚನೆ sshkey *k);
ಸ್ಥಿರಾಂಕ BIGNUM *rsa_q(ರಚನೆ sshkey *k);

