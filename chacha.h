/* $OpenBSD: chacha.h,v 1.5 2021/04/03 05:54:14 djm Exp $ */

/*
chacha-merged.c version 20080118
D. J. Bernstein
Public domain.
*/

#अगर_अघोषित CHACHA_H
#घोषणा CHACHA_H

#समावेश <sys/types.h>
#समावेश <stdlib.h>

काष्ठा chacha_ctx {
	u_int निवेश[16];
};

#घोषणा CHACHA_MINKEYLEN	16
#घोषणा CHACHA_NONCELEN		8
#घोषणा CHACHA_CTRLEN		8
#घोषणा CHACHA_STATELEN		(CHACHA_NONCELEN+CHACHA_CTRLEN)
#घोषणा CHACHA_BLOCKLEN		64

व्योम chacha_keysetup(काष्ठा chacha_ctx *x, स्थिर u_char *k, u_int kbits)
    __attribute__((__bounded__(__minbytes__, 2, CHACHA_MINKEYLEN)));
व्योम chacha_ivsetup(काष्ठा chacha_ctx *x, स्थिर u_char *iv, स्थिर u_char *ctr)
    __attribute__((__bounded__(__minbytes__, 2, CHACHA_NONCELEN)))
    __attribute__((__bounded__(__minbytes__, 3, CHACHA_CTRLEN)));
व्योम chacha_encrypt_bytes(काष्ठा chacha_ctx *x, स्थिर u_char *m,
    u_char *c, u_int bytes)
    __attribute__((__bounded__(__buffer__, 2, 4)))
    __attribute__((__bounded__(__buffer__, 3, 4)));

#पूर्ण_अगर	/* CHACHA_H */

