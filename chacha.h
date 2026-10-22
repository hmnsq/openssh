/* $OpenBSD: chacha.h,v 1.5 2021/04/03 05:54:14 djm Exp $ */

/*
chacha-merged.c version 20080118
D. J. Bernstein
Public domain.
*/

#که_نه_تعریف_شوی CHACHA_H
#تعریف_کړه CHACHA_H

#ضمن <sys/types.h>
#ضمن <stdlib.h>

بنية chacha_ctx {
	u_int ننوت[16];
};

#تعریف_کړه CHACHA_MINKEYLEN	16
#تعریف_کړه CHACHA_NONCELEN		8
#تعریف_کړه CHACHA_CTRLEN		8
#تعریف_کړه CHACHA_STATELEN		(CHACHA_NONCELEN+CHACHA_CTRLEN)
#تعریف_کړه CHACHA_BLOCKLEN		64

فراغ chacha_keysetup(بنية chacha_ctx *x, ثابت u_char *k, u_int kbits)
    __attribute__((__bounded__(__minbytes__, 2, CHACHA_MINKEYLEN)));
فراغ chacha_ivsetup(بنية chacha_ctx *x, ثابت u_char *iv, ثابت u_char *ctr)
    __attribute__((__bounded__(__minbytes__, 2, CHACHA_NONCELEN)))
    __attribute__((__bounded__(__minbytes__, 3, CHACHA_CTRLEN)));
فراغ chacha_encrypt_بایټونه(بنية chacha_ctx *x, ثابت u_char *m,
    u_char *c, u_int بایټونه)
    __attribute__((__bounded__(__buffer__, 2, 4)))
    __attribute__((__bounded__(__buffer__, 3, 4)));

#د_که_پای	/* CHACHA_H */

