/* $OpenBSD: chacha.h,v 1.5 2021/04/03 05:54:14 djm Exp $ */

/*
chacha-merged.c version 20080118
D. J. Bernstein
Public domain.
*/

#اگر_غیر_تعریف_شدہ CHACHA_H
#تعریف_کرو CHACHA_H

#شامل <sys/types.h>
#شامل <stdlib.h>

ساخت chacha_ctx {
	u_int داخلہ[16];
};

#تعریف_کرو CHACHA_MINKEYLEN	16
#تعریف_کرو CHACHA_NONCELEN		8
#تعریف_کرو CHACHA_CTRLEN		8
#تعریف_کرو CHACHA_STATELEN		(CHACHA_NONCELEN+CHACHA_CTRLEN)
#تعریف_کرو CHACHA_BLOCKLEN		64

خالی chacha_keysetup(ساخت chacha_ctx *x, ثابت u_char *k, u_int kbits)
    __attribute__((__bounded__(__minbytes__, 2, CHACHA_MINKEYLEN)));
خالی chacha_ivsetup(ساخت chacha_ctx *x, ثابت u_char *iv, ثابت u_char *ctr)
    __attribute__((__bounded__(__minbytes__, 2, CHACHA_NONCELEN)))
    __attribute__((__bounded__(__minbytes__, 3, CHACHA_CTRLEN)));
خالی chacha_encrypt_بائٹیں(ساخت chacha_ctx *x, ثابت u_char *m,
    u_char *c, u_int بائٹیں)
    __attribute__((__bounded__(__buffer__, 2, 4)))
    __attribute__((__bounded__(__buffer__, 3, 4)));

#اگر_ختم	/* CHACHA_H */

