/* $OpenBSD: chacha.h,v 1.5 2021/04/03 05:54:14 djm Exp $ */

/*
chacha-merged.c version 20080118
D. J. Bernstein
Public domain.
*/

#جے_بنا_تعریف CHACHA_H
#تعریف_کرو CHACHA_H

#ضمن <sys/types.h>
#ضمن <stdlib.h>

بنية chacha_ctx {
	u_int داخلہ[16];
};

#تعریف_کرو CHACHA_MINKEYLEN	16
#تعریف_کرو CHACHA_NONCELEN		8
#تعریف_کرو CHACHA_CTRLEN		8
#تعریف_کرو CHACHA_STATELEN		(CHACHA_NONCELEN+CHACHA_CTRLEN)
#تعریف_کرو CHACHA_BLOCKLEN		64

فراغ chacha_keysetup(بنية chacha_ctx *x, ثابت u_char *k, u_int kbits)
    __attribute__((__bounded__(__minbytes__, 2, CHACHA_MINKEYLEN)));
فراغ chacha_ivsetup(بنية chacha_ctx *x, ثابت u_char *iv, ثابت u_char *ctr)
    __attribute__((__bounded__(__minbytes__, 2, CHACHA_NONCELEN)))
    __attribute__((__bounded__(__minbytes__, 3, CHACHA_CTRLEN)));
فراغ chacha_encrypt_بائٹاں(بنية chacha_ctx *x, ثابت u_char *m,
    u_char *c, u_int بائٹاں)
    __attribute__((__bounded__(__buffer__, 2, 4)))
    __attribute__((__bounded__(__buffer__, 3, 4)));

#جے_انت	/* CHACHA_H */

