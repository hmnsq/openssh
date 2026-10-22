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

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ifndef WITH_OPENSSL

#ଅନ୍ତର୍ଭାଵ <sys/types.h>
#ଅନ୍ତର୍ଭାଵ <string.h>

#ଅନ୍ତର୍ଭାଵ "cipher-aesctr.h"

/*
 * increment counter 'ctr',
 * the counter is of size 'len' bytes and stored in network-byte-order.
 * (LSB at ctr[len-1], MSB at ctr[0])
 */
ସ୍ଥିର ଧାଡ଼ିଭିତରେ ଶୂନ୍ୟ
aesctr_inc(u8 *ctr, u32 len)
{
	ssize_t i;

#ifndef CONSTANT_TIME_INCREMENT
	ପାଇଁ (i = len - 1; i >= 0; i--)
		ଯଦି (++ctr[i])	/* continue on overflow */
			ଫେରନ୍ତୁ;
#ଅନ୍ୟଥା
	u8 x, add = 1;

	ପାଇଁ (i = len - 1; i >= 0; i--) {
		ctr[i] += add;
		/* constant time for: x = ctr[i] ? 1 : 0 */
		x = ctr[i];
		x = (x | (x >> 4)) & 0xf;
		x = (x | (x >> 2)) & 0x3;
		x = (x | (x >> 1)) & 0x1;
		add *= (x^1);
	}
#endif
}

ଶୂନ୍ୟ
aesctr_keysetup(aesctr_ctx *x,ଅଚଳ u8 *k,u32 kbits,u32 ivbits)
{
	x->rounds = rijndael_ଚାବି_Setup_Enc(x->ek, k, kbits);
}

ଶୂନ୍ୟ
aesctr_ivsetup(aesctr_ctx *x,ଅଚଳ u8 *iv)
{
	memcpy(x->ctr, iv, AES_BLOCK_SIZE);
}

ଶୂନ୍ୟ
aesctr_encrypt_bytes(aesctr_ctx *x,ଅଚଳ u8 *m,u8 *c,u32 bytes)
{
	u32 n = 0;
	u8 buf[AES_BLOCK_SIZE];

	ଯେତେବେଳେ ((bytes--) > 0) {
		ଯଦି (n == 0) {
			rijndaelEncrypt(x->ek, x->rounds, x->ctr, buf);
			aesctr_inc(x->ctr, AES_BLOCK_SIZE);
		}
		*(c++) = *(m++) ^ buf[n];
		n = (n + 1) % AES_BLOCK_SIZE;
	}
}
#endif /* !WITH_OPENSSL */
