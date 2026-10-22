/* $OpenBSD: poly1305.h,v 1.4 2014/05/02 03:27:54 djm Exp $ */

/* 
 * Public Domain poly1305 from Andrew Moon
 * poly1305-donna-unrolled.c from https://github.com/floodyberry/poly1305-donna
 */

#اگر_تعریف_نشده POLY1305_H
#تعریف_کن POLY1305_H

#ضمن <sys/types.h>

#تعریف_کن POLY1305_KEYLEN		32
#تعریف_کن POLY1305_TAGLEN		16

فراغ poly1305_auth(u_char بیرون[POLY1305_TAGLEN], ثابت u_char *m, اندازه_t inlen,
    ثابت u_char کلید[POLY1305_KEYLEN])
    __attribute__((__bounded__(__minbytes__, 1, POLY1305_TAGLEN)))
    __attribute__((__bounded__(__buffer__, 2, 3)))
    __attribute__((__bounded__(__minbytes__, 4, POLY1305_KEYLEN)));

#پایان_اگر	/* POLY1305_H */
