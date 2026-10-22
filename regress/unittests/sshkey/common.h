/* 	$OpenBSD: common.h,v 1.3 2025/05/06 06:05:48 djm Exp $ */
/*
 * Helpers for key API tests
 *
 * Placed in the public domain
 */

/* Load a binary file into a buffer */
నిర్మాణం sshbuf *ఎక్కించు_file(స్థిరరాశి అక్షరం *name);

/* Load a text file into a buffer */
నిర్మాణం sshbuf *ఎక్కించు_పాఠ్యం_file(స్థిరరాశి అక్షరం *name);

/* Load a bignum from a file */
BIGNUM *ఎక్కించు_bignum(స్థిరరాశి అక్షరం *name);

/* Accessors for key components */
స్థిరరాశి BIGNUM *rsa_n(నిర్మాణం sshkey *k);
స్థిరరాశి BIGNUM *rsa_e(నిర్మాణం sshkey *k);
స్థిరరాశి BIGNUM *rsa_p(నిర్మాణం sshkey *k);
స్థిరరాశి BIGNUM *rsa_q(నిర్మాణం sshkey *k);

