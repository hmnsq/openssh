/* $OpenBSD: poly1305.h,v 1.4 2014/05/02 03:27:54 djm Exp $ */

/* 
 * Public Domain poly1305 from Andrew Moon
 * poly1305-donna-unrolled.c from https://github.com/floodyberry/poly1305-donna
 */

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ POLY1305_H
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ POLY1305_H

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ POLY1305_KEYLEN		32
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ POLY1305_TAGLEN		16

ਖਾਲੀ poly1305_auth(u_char ਬਾਹਰਲਾ[POLY1305_TAGLEN], ਅਚਲ u_char *m, ਮਾਪ_t inlen,
    ਅਚਲ u_char ਕੁੰਜੀ[POLY1305_KEYLEN])
    __attribute__((__bounded__(__minbytes__, 1, POLY1305_TAGLEN)))
    __attribute__((__bounded__(__buffer__, 2, 3)))
    __attribute__((__bounded__(__minbytes__, 4, POLY1305_KEYLEN)));

#ਜੇ_ਅੰਤ	/* POLY1305_H */
