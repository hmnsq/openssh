/* $OpenBSD: chacha.h,v 1.5 2021/04/03 05:54:14 djm Exp $ */

/*
chacha-merged.c version 20080118
D. J. Bernstein
Public domain.
*/

#ifndef CHACHA_H
#define CHACHA_H

#അന്തര്ഭാവ <sys/types.h>
#അന്തര്ഭാവ <stdlib.h>

ഘടന chacha_ctx {
	u_int നിവേശം[16];
};

#define CHACHA_MINKEYLEN	16
#define CHACHA_NONCELEN		8
#define CHACHA_CTRLEN		8
#define CHACHA_STATELEN		(CHACHA_NONCELEN+CHACHA_CTRLEN)
#define CHACHA_BLOCKLEN		64

ശൂന്യം chacha_keysetup(ഘടന chacha_ctx *x, സ്ഥിരം u_char *k, u_int kbits)
    __attribute__((__bounded__(__minbytes__, 2, CHACHA_MINKEYLEN)));
ശൂന്യം chacha_ivsetup(ഘടന chacha_ctx *x, സ്ഥിരം u_char *iv, സ്ഥിരം u_char *ctr)
    __attribute__((__bounded__(__minbytes__, 2, CHACHA_NONCELEN)))
    __attribute__((__bounded__(__minbytes__, 3, CHACHA_CTRLEN)));
ശൂന്യം chacha_encrypt_bytes(ഘടന chacha_ctx *x, സ്ഥിരം u_char *m,
    u_char *c, u_int bytes)
    __attribute__((__bounded__(__buffer__, 2, 4)))
    __attribute__((__bounded__(__buffer__, 3, 4)));

#endif	/* CHACHA_H */

