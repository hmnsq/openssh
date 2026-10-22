/* $OpenBSD: chacha.h,v 1.5 2021/04/03 05:54:14 djm Exp $ */

/*
chacha-merged.c version 20080118
D. J. Bernstein
Public domain.
*/

#ifndef CHACHA_H
#define CHACHA_H

#અન્તર્ભાવ <sys/types.h>
#અન્તર્ભાવ <stdlib.h>

સંરચના chacha_ctx {
	u_int આગત[16];
};

#define CHACHA_MINKEYLEN	16
#define CHACHA_NONCELEN		8
#define CHACHA_CTRLEN		8
#define CHACHA_STATELEN		(CHACHA_NONCELEN+CHACHA_CTRLEN)
#define CHACHA_BLOCKLEN		64

શૂન્ય chacha_keysetup(સંરચના chacha_ctx *x, અચલ u_char *k, u_int kbits)
    __attribute__((__bounded__(__minbytes__, 2, CHACHA_MINKEYLEN)));
શૂન્ય chacha_ivsetup(સંરચના chacha_ctx *x, અચલ u_char *iv, અચલ u_char *ctr)
    __attribute__((__bounded__(__minbytes__, 2, CHACHA_NONCELEN)))
    __attribute__((__bounded__(__minbytes__, 3, CHACHA_CTRLEN)));
શૂન્ય chacha_encrypt_bytes(સંરચના chacha_ctx *x, અચલ u_char *m,
    u_char *c, u_int bytes)
    __attribute__((__bounded__(__buffer__, 2, 4)))
    __attribute__((__bounded__(__buffer__, 3, 4)));

#endif	/* CHACHA_H */

