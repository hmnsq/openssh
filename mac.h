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

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ SSHMAC_H
#ವ್ಯಾಖ್ಯಾನಿಸು SSHMAC_H

#ಅನ್ತರ್ಭಾವ <sys/types.h>

ರಚನೆ sshmac {
	ಅಕ್ಷರ	*name;
	ಪೂರ್ಣಾಂಕ	enabled;
	u_int	mac_len;
	u_char	*ಕೀಲಿ;
	u_int	ಕೀಲಿ_len;
	ಪೂರ್ಣಾಂಕ	type;
	ಪೂರ್ಣಾಂಕ	etm;		/* Encrypt-then-MAC */
	ರಚನೆ ssh_hmac_ctx	*hmac_ctx;
	ರಚನೆ umac_ctx		*umac_ctx;
};

ಪೂರ್ಣಾಂಕ	 mac_valid(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *);
ಅಕ್ಷರ	*mac_alg_list(ಅಕ್ಷರ);
ಪೂರ್ಣಾಂಕ	 mac_ಸಿದ್ಧತೆ(ರಚನೆ sshmac *, ಅಕ್ಷರ *);
ಪೂರ್ಣಾಂಕ	 mac_init(ರಚನೆ sshmac *);
ಪೂರ್ಣಾಂಕ	 mac_compute(ರಚನೆ sshmac *, uint32_t, ಸ್ಥಿರಾಂಕ u_char *, ಪೂರ್ಣಾಂಕ,
    u_char *, ಗಾತ್ರ_t);
ಪೂರ್ಣಾಂಕ	 mac_check(ರಚನೆ sshmac *, uint32_t, ಸ್ಥಿರಾಂಕ u_char *, ಗಾತ್ರ_t,
    ಸ್ಥಿರಾಂಕ u_char *, ಗಾತ್ರ_t);
ಶೂನ್ಯ	 mac_clear(ರಚನೆ sshmac *);

#ಆದರೆ_ಅಂತ್ಯ /* SSHMAC_H */
