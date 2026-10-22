/* $OpenBSD: mac.h,v 1.11 2026/03/03 09:57:25 dtucker Exp $ */
/*
 * Copyright (c) 2001 Markus Friedl.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef SSHMAC_H
#define SSHMAC_H

#شامل <sys/types.h>

ساختار sshmac {
	نویسه	*name;
	صحیح	enabled;
	u_int	mac_len;
	u_char	*کلید;
	u_int	کلید_len;
	صحیح	type;
	صحیح	etm;		/* Encrypt-then-MAC */
	ساختار ssh_hmac_ctx	*hmac_ctx;
	ساختار umac_ctx		*umac_ctx;
};

صحیح	 mac_valid(ثابت نویسه *);
نویسه	*mac_alg_list(نویسه);
صحیح	 mac_setup(ساختار sshmac *, نویسه *);
صحیح	 mac_init(ساختار sshmac *);
صحیح	 mac_compute(ساختار sshmac *, uint32_t, ثابت u_char *, صحیح,
    u_char *, size_t);
صحیح	 mac_check(ساختار sshmac *, uint32_t, ثابت u_char *, size_t,
    ثابت u_char *, size_t);
تهی	 mac_clear(ساختار sshmac *);

#endif /* SSHMAC_H */
