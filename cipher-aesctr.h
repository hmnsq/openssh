/* $OpenBSD: cipher-aesctr.h,v 1.1 2014/04/29 15:39:33 markus Exp $ */
/*
 * Copyright (c) 2014 Markus Friedl
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

#اگر_تعریف_نشده OPENSSH_AESCTR_H
#تعریف_کن OPENSSH_AESCTR_H

#ضمن "rijndael.h"

#تعریف_کن AES_بلوک_اندازه 16

تعريفنوع بنية aesctr_ctx {
	صحيح	دورها;				/* keylen-dependent #rounds */
	u32	ek[4*(AES_MAXROUNDS + 1)];	/* encrypt key schedule */
	u8	ctr[AES_بلوک_اندازه];		/* counter */
} aesctr_ctx;

فراغ aesctr_keysetup(aesctr_ctx *x,ثابت u8 *k,u32 kbits,u32 ivbits);
فراغ aesctr_ivsetup(aesctr_ctx *x,ثابت u8 *iv);
فراغ aesctr_encrypt_بایتها(aesctr_ctx *x,ثابت u8 *m,u8 *c,u32 بایتها);

#پایان_اگر
