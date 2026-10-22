/* $OpenBSD: poly1305.h,v 1.4 2014/05/02 03:27:54 djm Exp $ */

/* 
 * Public Domain poly1305 from Andrew Moon
 * poly1305-donna-unrolled.c from https://github.com/floodyberry/poly1305-donna
 */

#که_نه_تعریف_شوی POLY1305_H
#تعریف_کړه POLY1305_H

#ضمن <sys/types.h>

#تعریف_کړه POLY1305_KEYLEN		32
#تعریف_کړه POLY1305_TAGLEN		16

فراغ poly1305_auth(u_char بهر[POLY1305_TAGLEN], ثابت u_char *m, اندازه_t inlen,
    ثابت u_char کلی[POLY1305_KEYLEN])
    __attribute__((__bounded__(__minbytes__, 1, POLY1305_TAGLEN)))
    __attribute__((__bounded__(__buffer__, 2, 3)))
    __attribute__((__bounded__(__minbytes__, 4, POLY1305_KEYLEN)));

#د_که_پای	/* POLY1305_H */
