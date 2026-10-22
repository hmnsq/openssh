/* $OpenBSD: chacha.h,v 1.5 2021/04/03 05:54:14 djm Exp $ */

/*
chacha-merged.c version 20080118
D. J. Bernstein
Public domain.
*/

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ CHACHA_H
#ವ್ಯಾಖ್ಯಾನಿಸು CHACHA_H

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>

ರಚನೆ chacha_ctx {
	u_int ಒಳಹರಿವು[16];
};

#ವ್ಯಾಖ್ಯಾನಿಸು CHACHA_MINKEYLEN	16
#ವ್ಯಾಖ್ಯಾನಿಸು CHACHA_NONCELEN		8
#ವ್ಯಾಖ್ಯಾನಿಸು CHACHA_CTRLEN		8
#ವ್ಯಾಖ್ಯಾನಿಸು CHACHA_STATELEN		(CHACHA_NONCELEN+CHACHA_CTRLEN)
#ವ್ಯಾಖ್ಯಾನಿಸು CHACHA_BLOCKLEN		64

ಶೂನ್ಯ chacha_keysetup(ರಚನೆ chacha_ctx *x, ಸ್ಥಿರಾಂಕ u_char *k, u_int kbits)
    __attribute__((__bounded__(__minbytes__, 2, CHACHA_MINKEYLEN)));
ಶೂನ್ಯ chacha_ivsetup(ರಚನೆ chacha_ctx *x, ಸ್ಥಿರಾಂಕ u_char *iv, ಸ್ಥಿರಾಂಕ u_char *ctr)
    __attribute__((__bounded__(__minbytes__, 2, CHACHA_NONCELEN)))
    __attribute__((__bounded__(__minbytes__, 3, CHACHA_CTRLEN)));
ಶೂನ್ಯ chacha_encrypt_ಬೈಟುಗಳು(ರಚನೆ chacha_ctx *x, ಸ್ಥಿರಾಂಕ u_char *m,
    u_char *c, u_int ಬೈಟುಗಳು)
    __attribute__((__bounded__(__buffer__, 2, 4)))
    __attribute__((__bounded__(__buffer__, 3, 4)));

#ಆದರೆ_ಅಂತ್ಯ	/* CHACHA_H */

