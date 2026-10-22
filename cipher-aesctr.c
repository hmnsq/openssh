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

#ಅನ್ತರ್ಭಾವ "includes.h"

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ WITH_OPENSSL

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <string.h>

#ಅನ್ತರ್ಭಾವ "cipher-aesctr.h"

/*
 * increment counter 'ctr',
 * the counter is of size 'len' bytes and stored in network-byte-order.
 * (LSB at ctr[len-1], MSB at ctr[0])
 */
ಸ್ಥಿರ ಸಾಲೊಳಗೆ ಶೂನ್ಯ
aesctr_inc(u8 *ctr, u32 len)
{
	ssize_t i;

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ CONSTANT_ಸಮಯ_INCREMENT
	ಗಾಗಿ (i = len - 1; i >= 0; i--)
		ಆದರೆ (++ctr[i])	/* continue on overflow */
			ಹಿಂತಿರುಗಿ;
#ಇಲ್ಲದಿದ್ದರೆ
	u8 x, ಕೂಡಿಸು = 1;

	ಗಾಗಿ (i = len - 1; i >= 0; i--) {
		ctr[i] += ಕೂಡಿಸು;
		/* constant time for: x = ctr[i] ? 1 : 0 */
		x = ctr[i];
		x = (x | (x >> 4)) & 0xf;
		x = (x | (x >> 2)) & 0x3;
		x = (x | (x >> 1)) & 0x1;
		ಕೂಡಿಸು *= (x^1);
	}
#ಆದರೆ_ಅಂತ್ಯ
}

ಶೂನ್ಯ
aesctr_keysetup(aesctr_ctx *x,ಸ್ಥಿರಾಂಕ u8 *k,u32 kbits,u32 ivbits)
{
	x->ಸುತ್ತುಗಳು = rijndael_ಕೀಲಿ_ಸಿದ್ಧತೆ_Enc(x->ek, k, kbits);
}

ಶೂನ್ಯ
aesctr_ivsetup(aesctr_ctx *x,ಸ್ಥಿರಾಂಕ u8 *iv)
{
	ಸ್ಮರಣೆ_ನಕಲು(x->ctr, iv, AES_ಖಂಡ_ಗಾತ್ರ);
}

ಶೂನ್ಯ
aesctr_encrypt_ಬೈಟುಗಳು(aesctr_ctx *x,ಸ್ಥಿರಾಂಕ u8 *m,u8 *c,u32 ಬೈಟುಗಳು)
{
	u32 n = 0;
	u8 buf[AES_ಖಂಡ_ಗಾತ್ರ];

	ಆಗ ((ಬೈಟುಗಳು--) > 0) {
		ಆದರೆ (n == 0) {
			rijndaelEncrypt(x->ek, x->ಸುತ್ತುಗಳು, x->ctr, buf);
			aesctr_inc(x->ctr, AES_ಖಂಡ_ಗಾತ್ರ);
		}
		*(c++) = *(m++) ^ buf[n];
		n = (n + 1) % AES_ಖಂಡ_ಗಾತ್ರ;
	}
}
#ಆದರೆ_ಅಂತ್ಯ /* !WITH_OPENSSL */
