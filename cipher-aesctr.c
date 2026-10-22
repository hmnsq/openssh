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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ WITH_OPENSSL

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "cipher-aesctr.h"

/*
 * increment counter 'ctr',
 * the counter is of size 'len' bytes and stored in network-byte-order.
 * (LSB at ctr[len-1], MSB at ctr[0])
 */
ਸਥਿਰ ਸਤਰਅੰਦਰ ਖਾਲੀ
aesctr_inc(u8 *ctr, u32 len)
{
	ssize_t i;

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ CONSTANT_ਸਮਾਂ_INCREMENT
	ਲਈ (i = len - 1; i >= 0; i--)
		ਜੇ (++ctr[i])	/* continue on overflow */
			ਵਾਪਸ;
#ਨਹੀਂਤਾਂ
	u8 x, ਜੋੜੋ = 1;

	ਲਈ (i = len - 1; i >= 0; i--) {
		ctr[i] += ਜੋੜੋ;
		/* constant time for: x = ctr[i] ? 1 : 0 */
		x = ctr[i];
		x = (x | (x >> 4)) & 0xf;
		x = (x | (x >> 2)) & 0x3;
		x = (x | (x >> 1)) & 0x1;
		ਜੋੜੋ *= (x^1);
	}
#ਜੇ_ਅੰਤ
}

ਖਾਲੀ
aesctr_keysetup(aesctr_ctx *x,ਅਚਲ u8 *k,u32 kbits,u32 ivbits)
{
	x->ਗੇੜ = rijndael_ਕੁੰਜੀ_ਤਿਆਰੀ_Enc(x->ek, k, kbits);
}

ਖਾਲੀ
aesctr_ivsetup(aesctr_ctx *x,ਅਚਲ u8 *iv)
{
	ਸਮ੍ਰਿਤੀ_ਨਕਲ(x->ctr, iv, AES_ਖੰਡ_ਮਾਪ);
}

ਖਾਲੀ
aesctr_encrypt_ਬਾਈਟਾਂ(aesctr_ctx *x,ਅਚਲ u8 *m,u8 *c,u32 ਬਾਈਟਾਂ)
{
	u32 n = 0;
	u8 buf[AES_ਖੰਡ_ਮਾਪ];

	ਜਦੋਂ ((ਬਾਈਟਾਂ--) > 0) {
		ਜੇ (n == 0) {
			rijndaelEncrypt(x->ek, x->ਗੇੜ, x->ctr, buf);
			aesctr_inc(x->ctr, AES_ਖੰਡ_ਮਾਪ);
		}
		*(c++) = *(m++) ^ buf[n];
		n = (n + 1) % AES_ਖੰਡ_ਮਾਪ;
	}
}
#ਜੇ_ਅੰਤ /* !WITH_OPENSSL */
