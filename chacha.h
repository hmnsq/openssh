/* $OpenBSD: chacha.h,v 1.5 2021/04/03 05:54:14 djm Exp $ */

/*
chacha-merged.c version 20080118
D. J. Bernstein
Public domain.
*/

#ifndef CHACHA_H
#define CHACHA_H

#অন্তর্ভাব <sys/types.h>
#অন্তর্ভাব <stdlib.h>

কাঠামো chacha_ctx {
	u_int প্রবেশ[16];
};

#define CHACHA_MINKEYLEN	16
#define CHACHA_NONCELEN		8
#define CHACHA_CTRLEN		8
#define CHACHA_STATELEN		(CHACHA_NONCELEN+CHACHA_CTRLEN)
#define CHACHA_BLOCKLEN		64

শূন্য chacha_keysetup(কাঠামো chacha_ctx *x, ধ্রুবক u_char *k, u_int kbits)
    __attribute__((__bounded__(__minbytes__, 2, CHACHA_MINKEYLEN)));
শূন্য chacha_ivsetup(কাঠামো chacha_ctx *x, ধ্রুবক u_char *iv, ধ্রুবক u_char *ctr)
    __attribute__((__bounded__(__minbytes__, 2, CHACHA_NONCELEN)))
    __attribute__((__bounded__(__minbytes__, 3, CHACHA_CTRLEN)));
শূন্য chacha_encrypt_bytes(কাঠামো chacha_ctx *x, ধ্রুবক u_char *m,
    u_char *c, u_int bytes)
    __attribute__((__bounded__(__buffer__, 2, 4)))
    __attribute__((__bounded__(__buffer__, 3, 4)));

#endif	/* CHACHA_H */

