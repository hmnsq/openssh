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

#నిర్వచితం_కాకపోతే SSHMAC_H
#నిర్వచించు SSHMAC_H

#అన్తర్భావ <sys/types.h>

నిర్మాణం sshmac {
	అక్షరం	*name;
	పూర్ణాంకం	enabled;
	u_int	mac_len;
	u_char	*కీలకం;
	u_int	కీలకం_len;
	పూర్ణాంకం	type;
	పూర్ణాంకం	etm;		/* Encrypt-then-MAC */
	నిర్మాణం ssh_hmac_ctx	*hmac_ctx;
	నిర్మాణం umac_ctx		*umac_ctx;
};

పూర్ణాంకం	 mac_valid(స్థిరరాశి అక్షరం *);
అక్షరం	*mac_alg_list(అక్షరం);
పూర్ణాంకం	 mac_అమరిక(నిర్మాణం sshmac *, అక్షరం *);
పూర్ణాంకం	 mac_init(నిర్మాణం sshmac *);
పూర్ణాంకం	 mac_compute(నిర్మాణం sshmac *, uint32_t, స్థిరరాశి u_char *, పూర్ణాంకం,
    u_char *, కొలత_t);
పూర్ణాంకం	 mac_check(నిర్మాణం sshmac *, uint32_t, స్థిరరాశి u_char *, కొలత_t,
    స్థిరరాశి u_char *, కొలత_t);
శూన్య	 mac_clear(నిర్మాణం sshmac *);

#అయితే_ముగింపు /* SSHMAC_H */
