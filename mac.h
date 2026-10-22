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

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ SSHMAC_H
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ SSHMAC_H

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>

ਬਣਤਰ sshmac {
	ਅੱਖਰ	*name;
	ਪੂਰਨ	enabled;
	u_int	mac_len;
	u_char	*ਕੁੰਜੀ;
	u_int	ਕੁੰਜੀ_len;
	ਪੂਰਨ	type;
	ਪੂਰਨ	etm;		/* Encrypt-then-MAC */
	ਬਣਤਰ ssh_hmac_ctx	*hmac_ctx;
	ਬਣਤਰ umac_ctx		*umac_ctx;
};

ਪੂਰਨ	 mac_valid(ਅਚਲ ਅੱਖਰ *);
ਅੱਖਰ	*mac_alg_list(ਅੱਖਰ);
ਪੂਰਨ	 mac_ਤਿਆਰੀ(ਬਣਤਰ sshmac *, ਅੱਖਰ *);
ਪੂਰਨ	 mac_init(ਬਣਤਰ sshmac *);
ਪੂਰਨ	 mac_compute(ਬਣਤਰ sshmac *, uint32_t, ਅਚਲ u_char *, ਪੂਰਨ,
    u_char *, ਮਾਪ_t);
ਪੂਰਨ	 mac_check(ਬਣਤਰ sshmac *, uint32_t, ਅਚਲ u_char *, ਮਾਪ_t,
    ਅਚਲ u_char *, ਮਾਪ_t);
ਖਾਲੀ	 mac_clear(ਬਣਤਰ sshmac *);

#ਜੇ_ਅੰਤ /* SSHMAC_H */
