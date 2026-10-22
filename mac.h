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

#അന്തര്ഭാവ <sys/types.h>

ഘടന sshmac {
	അക്ഷരം	*name;
	പൂർണ്ണസംഖ്യ	enabled;
	u_int	mac_len;
	u_char	*താക്കോൽ;
	u_int	താക്കോൽ_len;
	പൂർണ്ണസംഖ്യ	type;
	പൂർണ്ണസംഖ്യ	etm;		/* Encrypt-then-MAC */
	ഘടന ssh_hmac_ctx	*hmac_ctx;
	ഘടന umac_ctx		*umac_ctx;
};

പൂർണ്ണസംഖ്യ	 mac_valid(സ്ഥിരം അക്ഷരം *);
അക്ഷരം	*mac_alg_list(അക്ഷരം);
പൂർണ്ണസംഖ്യ	 mac_setup(ഘടന sshmac *, അക്ഷരം *);
പൂർണ്ണസംഖ്യ	 mac_init(ഘടന sshmac *);
പൂർണ്ണസംഖ്യ	 mac_compute(ഘടന sshmac *, uint32_t, സ്ഥിരം u_char *, പൂർണ്ണസംഖ്യ,
    u_char *, size_t);
പൂർണ്ണസംഖ്യ	 mac_check(ഘടന sshmac *, uint32_t, സ്ഥിരം u_char *, size_t,
    സ്ഥിരം u_char *, size_t);
ശൂന്യം	 mac_clear(ഘടന sshmac *);

#endif /* SSHMAC_H */
