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

#که_نه_تعریف_شوی SSHMAC_H
#تعریف_کړه SSHMAC_H

#ضمن <sys/types.h>

بنية sshmac {
	حرف	*name;
	صحيح	enabled;
	u_int	mac_len;
	u_char	*کلی;
	u_int	کلی_len;
	صحيح	type;
	صحيح	etm;		/* Encrypt-then-MAC */
	بنية ssh_hmac_ctx	*hmac_ctx;
	بنية umac_ctx		*umac_ctx;
};

صحيح	 mac_valid(ثابت حرف *);
حرف	*mac_alg_list(حرف);
صحيح	 mac_تیاری(بنية sshmac *, حرف *);
صحيح	 mac_init(بنية sshmac *);
صحيح	 mac_compute(بنية sshmac *, uint32_t, ثابت u_char *, صحيح,
    u_char *, اندازه_t);
صحيح	 mac_check(بنية sshmac *, uint32_t, ثابت u_char *, اندازه_t,
    ثابت u_char *, اندازه_t);
فراغ	 mac_clear(بنية sshmac *);

#د_که_پای /* SSHMAC_H */
