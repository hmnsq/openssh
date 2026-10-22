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

#ಅನ್ತರ್ಭಾವ <sys/types.h>

ಸಂರಚನಾ sshmac {
	ವರ್ಣ	*name;
	ಪೂರ್ಣಾಙ್ಕ	enabled;
	u_int	mac_len;
	u_char	*ಕೀಲಿ;
	u_int	ಕೀಲಿ_len;
	ಪೂರ್ಣಾಙ್ಕ	type;
	ಪೂರ್ಣಾಙ್ಕ	etm;		/* Encrypt-then-MAC */
	ಸಂರಚನಾ ssh_hmac_ctx	*hmac_ctx;
	ಸಂರಚನಾ umac_ctx		*umac_ctx;
};

ಪೂರ್ಣಾಙ್ಕ	 mac_valid(ಧ್ರುವ ವರ್ಣ *);
ವರ್ಣ	*mac_alg_list(ವರ್ಣ);
ಪೂರ್ಣಾಙ್ಕ	 mac_setup(ಸಂರಚನಾ sshmac *, ವರ್ಣ *);
ಪೂರ್ಣಾಙ್ಕ	 mac_init(ಸಂರಚನಾ sshmac *);
ಪೂರ್ಣಾಙ್ಕ	 mac_compute(ಸಂರಚನಾ sshmac *, uint32_t, ಧ್ರುವ u_char *, ಪೂರ್ಣಾಙ್ಕ,
    u_char *, size_t);
ಪೂರ್ಣಾಙ್ಕ	 mac_check(ಸಂರಚನಾ sshmac *, uint32_t, ಧ್ರುವ u_char *, size_t,
    ಧ್ರುವ u_char *, size_t);
ಶೂನ್ಯ	 mac_clear(ಸಂರಚನಾ sshmac *);

#endif /* SSHMAC_H */
