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

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ OPENSSH_AESCTR_H
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ OPENSSH_AESCTR_H

#ਅਨ੍ਤਰ੍ਭਾਵ "rijndael.h"

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ AES_ਖੰਡ_ਮਾਪ 16

ਕਿਸਮਪਰਿਭਾਸ਼ਾ ਬਣਤਰ aesctr_ctx {
	ਪੂਰਨ	ਗੇੜ;				/* keylen-dependent #rounds */
	u32	ek[4*(AES_MAXROUNDS + 1)];	/* encrypt key schedule */
	u8	ctr[AES_ਖੰਡ_ਮਾਪ];		/* counter */
} aesctr_ctx;

ਖਾਲੀ aesctr_keysetup(aesctr_ctx *x,ਅਚਲ u8 *k,u32 kbits,u32 ivbits);
ਖਾਲੀ aesctr_ivsetup(aesctr_ctx *x,ਅਚਲ u8 *iv);
ਖਾਲੀ aesctr_encrypt_ਬਾਈਟਾਂ(aesctr_ctx *x,ਅਚਲ u8 *m,u8 *c,u32 ਬਾਈਟਾਂ);

#ਜੇ_ਅੰਤ
