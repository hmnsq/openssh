/* $OpenBSD: poly1305.h,v 1.4 2014/05/02 03:27:54 djm Exp $ */

/* 
 * Public Domain poly1305 from Andrew Moon
 * poly1305-donna-unrolled.c from https://github.com/floodyberry/poly1305-donna
 */

#यदि_अपरिभाषितम् POLY1305_H
#परिभाषय POLY1305_H

#अन्तर्भाव <sys/types.h>

#परिभाषय POLY1305_KEYLEN		32
#परिभाषय POLY1305_TAGLEN		16

शून्य poly1305_auth(u_char बहिर्गमनम्[POLY1305_TAGLEN], ध्रुव u_char *m, आकार_t inlen,
    ध्रुव u_char कुञ्चिका[POLY1305_KEYLEN])
    __attribute__((__bounded__(__minbytes__, 1, POLY1305_TAGLEN)))
    __attribute__((__bounded__(__buffer__, 2, 3)))
    __attribute__((__bounded__(__minbytes__, 4, POLY1305_KEYLEN)));

#यदि_अन्तः	/* POLY1305_H */
