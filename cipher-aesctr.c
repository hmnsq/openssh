/* $OpenBSD: cipher-aesctr.c,v 1.3 2026/02/09 22:15:45 dtucker Exp $ */
/*
 * Copyright (c) 2003 Markus Friedl.  All rights reserved.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#అన్తర్భావ "includes.h"

#నిర్వచితం_కాకపోతే WITH_OPENSSL

#అన్తర్భావ <sys/types.h>
#అన్తర్భావ <string.h>

#అన్తర్భావ "cipher-aesctr.h"

/*
 * increment counter 'ctr',
 * the counter is of size 'len' bytes and stored in network-byte-order.
 * (LSB at ctr[len-1], MSB at ctr[0])
 */
స్థిర అంతఃవరుస శూన్య
aesctr_inc(u8 *ctr, u32 len)
{
	ssize_t i;

#నిర్వచితం_కాకపోతే CONSTANT_సమయం_INCREMENT
	కొరకు (i = len - 1; i >= 0; i--)
		ఒకవేళ (++ctr[i])	/* continue on overflow */
			తిరిగి;
#లేకపోతే
	u8 x, కూడు = 1;

	కొరకు (i = len - 1; i >= 0; i--) {
		ctr[i] += కూడు;
		/* constant time for: x = ctr[i] ? 1 : 0 */
		x = ctr[i];
		x = (x | (x >> 4)) & 0xf;
		x = (x | (x >> 2)) & 0x3;
		x = (x | (x >> 1)) & 0x1;
		కూడు *= (x^1);
	}
#అయితే_ముగింపు
}

శూన్య
aesctr_keysetup(aesctr_ctx *x,స్థిరరాశి u8 *k,u32 kbits,u32 ivbits)
{
	x->విడతలు = rijndael_కీలకం_అమరిక_Enc(x->ek, k, kbits);
}

శూన్య
aesctr_ivsetup(aesctr_ctx *x,స్థిరరాశి u8 *iv)
{
	జ్ఞాపకం_నకలు(x->ctr, iv, AES_ఖండం_కొలత);
}

శూన్య
aesctr_encrypt_బైట్లు(aesctr_ctx *x,స్థిరరాశి u8 *m,u8 *c,u32 బైట్లు)
{
	u32 n = 0;
	u8 buf[AES_ఖండం_కొలత];

	అయితే ((బైట్లు--) > 0) {
		ఒకవేళ (n == 0) {
			rijndaelEncrypt(x->ek, x->విడతలు, x->ctr, buf);
			aesctr_inc(x->ctr, AES_ఖండం_కొలత);
		}
		*(c++) = *(m++) ^ buf[n];
		n = (n + 1) % AES_ఖండం_కొలత;
	}
}
#అయితే_ముగింపు /* !WITH_OPENSSL */
