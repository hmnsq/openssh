/* $OpenBSD: poly1305.h,v 1.4 2014/05/02 03:27:54 djm Exp $ */

/* 
 * Public Domain poly1305 from Andrew Moon
 * poly1305-donna-unrolled.c from https://github.com/floodyberry/poly1305-donna
 */

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ POLY1305_H
#ವ್ಯಾಖ್ಯಾನಿಸು POLY1305_H

#ಅನ್ತರ್ಭಾವ <sys/types.h>

#ವ್ಯಾಖ್ಯಾನಿಸು POLY1305_KEYLEN		32
#ವ್ಯಾಖ್ಯಾನಿಸು POLY1305_TAGLEN		16

ಶೂನ್ಯ poly1305_auth(u_char ಹೊರಹೋಗು[POLY1305_TAGLEN], ಸ್ಥಿರಾಂಕ u_char *m, ಗಾತ್ರ_t inlen,
    ಸ್ಥಿರಾಂಕ u_char ಕೀಲಿ[POLY1305_KEYLEN])
    __attribute__((__bounded__(__minbytes__, 1, POLY1305_TAGLEN)))
    __attribute__((__bounded__(__buffer__, 2, 3)))
    __attribute__((__bounded__(__minbytes__, 4, POLY1305_KEYLEN)));

#ಆದರೆ_ಅಂತ್ಯ	/* POLY1305_H */
