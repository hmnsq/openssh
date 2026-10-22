/* $OpenBSD: chacha.h,v 1.5 2021/04/03 05:54:14 djm Exp $ */

/*
chacha-merged.c version 20080118
D. J. Bernstein
Public domain.
*/

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ CHACHA_H
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CHACHA_H

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>

ਬਣਤਰ chacha_ctx {
	u_int ਨਿਵੇਸ਼[16];
};

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CHACHA_MINKEYLEN	16
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CHACHA_NONCELEN		8
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CHACHA_CTRLEN		8
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CHACHA_STATELEN		(CHACHA_NONCELEN+CHACHA_CTRLEN)
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ CHACHA_BLOCKLEN		64

ਖਾਲੀ chacha_keysetup(ਬਣਤਰ chacha_ctx *x, ਅਚਲ u_char *k, u_int kbits)
    __attribute__((__bounded__(__minbytes__, 2, CHACHA_MINKEYLEN)));
ਖਾਲੀ chacha_ivsetup(ਬਣਤਰ chacha_ctx *x, ਅਚਲ u_char *iv, ਅਚਲ u_char *ctr)
    __attribute__((__bounded__(__minbytes__, 2, CHACHA_NONCELEN)))
    __attribute__((__bounded__(__minbytes__, 3, CHACHA_CTRLEN)));
ਖਾਲੀ chacha_encrypt_ਬਾਈਟਾਂ(ਬਣਤਰ chacha_ctx *x, ਅਚਲ u_char *m,
    u_char *c, u_int ਬਾਈਟਾਂ)
    __attribute__((__bounded__(__buffer__, 2, 4)))
    __attribute__((__bounded__(__buffer__, 3, 4)));

#ਜੇ_ਅੰਤ	/* CHACHA_H */

