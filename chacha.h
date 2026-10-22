/* $OpenBSD: chacha.h,v 1.5 2021/04/03 05:54:14 djm Exp $ */

/*
chacha-merged.c version 20080118
D. J. Bernstein
Public domain.
*/

#ifndef CHACHA_H
#define CHACHA_H

#شامل <sys/types.h>
#شامل <stdlib.h>

ساختار chacha_ctx {
	u_int درون_داد[16];
};

#define CHACHA_MINKEYLEN	16
#define CHACHA_NONCELEN		8
#define CHACHA_CTRLEN		8
#define CHACHA_STATELEN		(CHACHA_NONCELEN+CHACHA_CTRLEN)
#define CHACHA_BLOCKLEN		64

تهی chacha_keysetup(ساختار chacha_ctx *x, ثابت u_char *k, u_int kbits)
    __attribute__((__bounded__(__minbytes__, 2, CHACHA_MINKEYLEN)));
تهی chacha_ivsetup(ساختار chacha_ctx *x, ثابت u_char *iv, ثابت u_char *ctr)
    __attribute__((__bounded__(__minbytes__, 2, CHACHA_NONCELEN)))
    __attribute__((__bounded__(__minbytes__, 3, CHACHA_CTRLEN)));
تهی chacha_encrypt_bytes(ساختار chacha_ctx *x, ثابت u_char *m,
    u_char *c, u_int bytes)
    __attribute__((__bounded__(__buffer__, 2, 4)))
    __attribute__((__bounded__(__buffer__, 3, 4)));

#endif	/* CHACHA_H */

