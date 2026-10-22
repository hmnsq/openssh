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

#ضمن "includes.h"

#جيڪڏهن_وصف_نه_ٿيل WITH_OPENSSL

#ضمن <sys/types.h>
#ضمن <string.h>

#ضمن "cipher-aesctr.h"

/*
 * increment counter 'ctr',
 * the counter is of size 'len' bytes and stored in network-byte-order.
 * (LSB at ctr[len-1], MSB at ctr[0])
 */
ساكن مضمن فراغ
aesctr_inc(u8 *ctr, u32 len)
{
	ssize_t i;

#جيڪڏهن_وصف_نه_ٿيل CONSTANT_وقت_INCREMENT
	لكل (i = len - 1; i >= 0; i--)
		إذا (++ctr[i])	/* continue on overflow */
			أرجع;
#وإلا
	u8 x, جوڙيو = 1;

	لكل (i = len - 1; i >= 0; i--) {
		ctr[i] += جوڙيو;
		/* constant time for: x = ctr[i] ? 1 : 0 */
		x = ctr[i];
		x = (x | (x >> 4)) & 0xf;
		x = (x | (x >> 2)) & 0x3;
		x = (x | (x >> 1)) & 0x1;
		جوڙيو *= (x^1);
	}
#جيڪڏهن_پورو
}

فراغ
aesctr_keysetup(aesctr_ctx *x,ثابت u8 *k,u32 kbits,u32 ivbits)
{
	x->ڦيرا = rijndael_ڪنجي_تياري_Enc(x->ek, k, kbits);
}

فراغ
aesctr_ivsetup(aesctr_ctx *x,ثابت u8 *iv)
{
	يادگيري_نقل(x->ctr, iv, AES_بلاڪ_سائيز);
}

فراغ
aesctr_encrypt_بائيٽون(aesctr_ctx *x,ثابت u8 *m,u8 *c,u32 بائيٽون)
{
	u32 n = 0;
	u8 buf[AES_بلاڪ_سائيز];

	طالما ((بائيٽون--) > 0) {
		إذا (n == 0) {
			rijndaelEncrypt(x->ek, x->ڦيرا, x->ctr, buf);
			aesctr_inc(x->ctr, AES_بلاڪ_سائيز);
		}
		*(c++) = *(m++) ^ buf[n];
		n = (n + 1) % AES_بلاڪ_سائيز;
	}
}
#جيڪڏهن_پورو /* !WITH_OPENSSL */
