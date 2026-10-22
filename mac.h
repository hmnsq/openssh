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

#ଅନ୍ତର୍ଭାଵ <sys/types.h>

ସଂରଚନା sshmac {
	ଅକ୍ଷର	*name;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା	enabled;
	u_int	mac_len;
	u_char	*ଚାବି;
	u_int	ଚାବି_len;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା	type;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା	etm;		/* Encrypt-then-MAC */
	ସଂରଚନା ssh_hmac_ctx	*hmac_ctx;
	ସଂରଚନା umac_ctx		*umac_ctx;
};

ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 mac_valid(ଅଚଳ ଅକ୍ଷର *);
ଅକ୍ଷର	*mac_alg_list(ଅକ୍ଷର);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 mac_setup(ସଂରଚନା sshmac *, ଅକ୍ଷର *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 mac_init(ସଂରଚନା sshmac *);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 mac_compute(ସଂରଚନା sshmac *, uint32_t, ଅଚଳ u_char *, ପୂର୍ଣ୍ଣସଂଖ୍ୟା,
    u_char *, size_t);
ପୂର୍ଣ୍ଣସଂଖ୍ୟା	 mac_check(ସଂରଚନା sshmac *, uint32_t, ଅଚଳ u_char *, size_t,
    ଅଚଳ u_char *, size_t);
ଶୂନ୍ୟ	 mac_clear(ସଂରଚନା sshmac *);

#endif /* SSHMAC_H */
