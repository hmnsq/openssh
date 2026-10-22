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

#અન્તર્ભાવ <sys/types.h>

સંરચના sshmac {
	અક્ષર	*name;
	પૂર્ણાંક	enabled;
	u_int	mac_len;
	u_char	*ચાવી;
	u_int	ચાવી_len;
	પૂર્ણાંક	type;
	પૂર્ણાંક	etm;		/* Encrypt-then-MAC */
	સંરચના ssh_hmac_ctx	*hmac_ctx;
	સંરચના umac_ctx		*umac_ctx;
};

પૂર્ણાંક	 mac_valid(અચલ અક્ષર *);
અક્ષર	*mac_alg_list(અક્ષર);
પૂર્ણાંક	 mac_setup(સંરચના sshmac *, અક્ષર *);
પૂર્ણાંક	 mac_init(સંરચના sshmac *);
પૂર્ણાંક	 mac_compute(સંરચના sshmac *, uint32_t, અચલ u_char *, પૂર્ણાંક,
    u_char *, size_t);
પૂર્ણાંક	 mac_check(સંરચના sshmac *, uint32_t, અચલ u_char *, size_t,
    અચલ u_char *, size_t);
શૂન્ય	 mac_clear(સંરચના sshmac *);

#endif /* SSHMAC_H */
