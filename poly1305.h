/* $OpenBSD: poly1305.h,v 1.4 2014/05/02 03:27:54 djm Exp $ */

/* 
 * Public Domain poly1305 from Andrew Moon
 * poly1305-donna-unrolled.c from https://github.com/floodyberry/poly1305-donna
 */

#جيڪڏهن_وصف_نه_ٿيل POLY1305_H
#وصف_ڪريو POLY1305_H

#ضمن <sys/types.h>

#وصف_ڪريو POLY1305_KEYLEN		32
#وصف_ڪريو POLY1305_TAGLEN		16

فراغ poly1305_auth(u_char ٻاهريون[POLY1305_TAGLEN], ثابت u_char *m, سائيز_t inlen,
    ثابت u_char ڪنجي[POLY1305_KEYLEN])
    __attribute__((__bounded__(__minbytes__, 1, POLY1305_TAGLEN)))
    __attribute__((__bounded__(__buffer__, 2, 3)))
    __attribute__((__bounded__(__minbytes__, 4, POLY1305_KEYLEN)));

#جيڪڏهن_پورو	/* POLY1305_H */
