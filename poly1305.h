/* $OpenBSD: poly1305.h,v 1.4 2014/05/02 03:27:54 djm Exp $ */

/* 
 * Public Domain poly1305 from Andrew Moon
 * poly1305-donna-unrolled.c from https://github.com/floodyberry/poly1305-donna
 */

#నిర్వచితం_కాకపోతే POLY1305_H
#నిర్వచించు POLY1305_H

#అన్తర్భావ <sys/types.h>

#నిర్వచించు POLY1305_KEYLEN		32
#నిర్వచించు POLY1305_TAGLEN		16

శూన్య poly1305_auth(u_char బహిర్గతం[POLY1305_TAGLEN], స్థిరరాశి u_char *m, కొలత_t inlen,
    స్థిరరాశి u_char కీలకం[POLY1305_KEYLEN])
    __attribute__((__bounded__(__minbytes__, 1, POLY1305_TAGLEN)))
    __attribute__((__bounded__(__buffer__, 2, 3)))
    __attribute__((__bounded__(__minbytes__, 4, POLY1305_KEYLEN)));

#అయితే_ముగింపు	/* POLY1305_H */
