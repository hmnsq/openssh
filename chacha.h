/* $OpenBSD: chacha.h,v 1.5 2021/04/03 05:54:14 djm Exp $ */

/*
chacha-merged.c version 20080118
D. J. Bernstein
Public domain.
*/

#నిర్వచితం_కాకపోతే CHACHA_H
#నిర్వచించు CHACHA_H

#అన్తర్భావ <sys/types.h>
#అన్తర్భావ <stdlib.h>

నిర్మాణం chacha_ctx {
	u_int ఆదానం[16];
};

#నిర్వచించు CHACHA_MINKEYLEN	16
#నిర్వచించు CHACHA_NONCELEN		8
#నిర్వచించు CHACHA_CTRLEN		8
#నిర్వచించు CHACHA_STATELEN		(CHACHA_NONCELEN+CHACHA_CTRLEN)
#నిర్వచించు CHACHA_BLOCKLEN		64

శూన్య chacha_keysetup(నిర్మాణం chacha_ctx *x, స్థిరరాశి u_char *k, u_int kbits)
    __attribute__((__bounded__(__minbytes__, 2, CHACHA_MINKEYLEN)));
శూన్య chacha_ivsetup(నిర్మాణం chacha_ctx *x, స్థిరరాశి u_char *iv, స్థిరరాశి u_char *ctr)
    __attribute__((__bounded__(__minbytes__, 2, CHACHA_NONCELEN)))
    __attribute__((__bounded__(__minbytes__, 3, CHACHA_CTRLEN)));
శూన్య chacha_encrypt_బైట్లు(నిర్మాణం chacha_ctx *x, స్థిరరాశి u_char *m,
    u_char *c, u_int బైట్లు)
    __attribute__((__bounded__(__buffer__, 2, 4)))
    __attribute__((__bounded__(__buffer__, 3, 4)));

#అయితే_ముగింపు	/* CHACHA_H */

