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

#ifndef OPENSSH_AESCTR_H
#define OPENSSH_AESCTR_H

#અન્તર્ભાવ "rijndael.h"

#define AES_BLOCK_SIZE 16

પ્રકારવ્યાખ્યા સંરચના aesctr_ctx {
	પૂર્ણાંક	rounds;				/* keylen-dependent #rounds */
	u32	ek[4*(AES_MAXROUNDS + 1)];	/* encrypt key schedule */
	u8	ctr[AES_BLOCK_SIZE];		/* counter */
} aesctr_ctx;

શૂન્ય aesctr_keysetup(aesctr_ctx *x,અચલ u8 *k,u32 kbits,u32 ivbits);
શૂન્ય aesctr_ivsetup(aesctr_ctx *x,અચલ u8 *iv);
શૂન્ય aesctr_encrypt_bytes(aesctr_ctx *x,અચલ u8 *m,u8 *c,u32 bytes);

#endif
