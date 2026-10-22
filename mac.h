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

#অন্তর্ভাব <sys/types.h>

কাঠামো sshmac {
	অক্ষর	*name;
	পূর্ণসংখ্যা	enabled;
	u_int	mac_len;
	u_char	*চাবি;
	u_int	চাবি_len;
	পূর্ণসংখ্যা	type;
	পূর্ণসংখ্যা	etm;		/* Encrypt-then-MAC */
	কাঠামো ssh_hmac_ctx	*hmac_ctx;
	কাঠামো umac_ctx		*umac_ctx;
};

পূর্ণসংখ্যা	 mac_valid(ধ্রুবক অক্ষর *);
অক্ষর	*mac_alg_list(অক্ষর);
পূর্ণসংখ্যা	 mac_setup(কাঠামো sshmac *, অক্ষর *);
পূর্ণসংখ্যা	 mac_init(কাঠামো sshmac *);
পূর্ণসংখ্যা	 mac_compute(কাঠামো sshmac *, uint32_t, ধ্রুবক u_char *, পূর্ণসংখ্যা,
    u_char *, আকার_t);
পূর্ণসংখ্যা	 mac_check(কাঠামো sshmac *, uint32_t, ধ্রুবক u_char *, আকার_t,
    ধ্রুবক u_char *, আকার_t);
শূন্য	 mac_clear(কাঠামো sshmac *);

#endif /* SSHMAC_H */
