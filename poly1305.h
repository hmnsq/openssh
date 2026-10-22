/* $OpenBSD: poly1305.h,v 1.4 2014/05/02 03:27:54 djm Exp $ */

/* 
 * Public Domain poly1305 from Andrew Moon
 * poly1305-donna-unrolled.c from https://github.com/floodyberry/poly1305-donna
 */

#अगर_अघोषित POLY1305_H
#घोषणा POLY1305_H

#समावेश <sys/types.h>

#घोषणा POLY1305_KEYLEN		32
#घोषणा POLY1305_TAGLEN		16

व्योम poly1305_auth(u_char out[POLY1305_TAGLEN], स्थिर u_char *m, माप_प्रकार inlen,
    स्थिर u_char कुंजी[POLY1305_KEYLEN])
    __attribute__((__bounded__(__minbytes__, 1, POLY1305_TAGLEN)))
    __attribute__((__bounded__(__buffer__, 2, 3)))
    __attribute__((__bounded__(__minbytes__, 4, POLY1305_KEYLEN)));

#पूर्ण_अगर	/* POLY1305_H */
