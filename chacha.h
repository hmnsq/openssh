/* $OpenBSD: chacha.h,v 1.5 2021/04/03 05:54:14 djm Exp $ */

/*
chacha-merged.c version 20080118
D. J. Bernstein
Public domain.
*/

#यदि_अपरिभाषितम् CHACHA_H
#परिभाषय CHACHA_H

#अन्तर्भाव <sys/types.h>
#अन्तर्भाव <stdlib.h>

संरचना chacha_ctx {
	u_int निवेशः[16];
};

#परिभाषय CHACHA_MINKEYLEN	16
#परिभाषय CHACHA_NONCELEN		8
#परिभाषय CHACHA_CTRLEN		8
#परिभाषय CHACHA_STATELEN		(CHACHA_NONCELEN+CHACHA_CTRLEN)
#परिभाषय CHACHA_BLOCKLEN		64

शून्य chacha_keysetup(संरचना chacha_ctx *x, ध्रुव u_char *k, u_int kbits)
    __attribute__((__bounded__(__minbytes__, 2, CHACHA_MINKEYLEN)));
शून्य chacha_ivsetup(संरचना chacha_ctx *x, ध्रुव u_char *iv, ध्रुव u_char *ctr)
    __attribute__((__bounded__(__minbytes__, 2, CHACHA_NONCELEN)))
    __attribute__((__bounded__(__minbytes__, 3, CHACHA_CTRLEN)));
शून्य chacha_encrypt_अष्टकानि(संरचना chacha_ctx *x, ध्रुव u_char *m,
    u_char *c, u_int अष्टकानि)
    __attribute__((__bounded__(__buffer__, 2, 4)))
    __attribute__((__bounded__(__buffer__, 3, 4)));

#यदि_अन्तः	/* CHACHA_H */

