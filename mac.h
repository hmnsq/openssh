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

#अन्तर्भाव <sys/types.h>

संरचना sshmac {
	अक्षर	*name;
	पूर्णांक	enabled;
	u_int	mac_len;
	u_char	*किल्ली;
	u_int	किल्ली_len;
	पूर्णांक	type;
	पूर्णांक	etm;		/* Encrypt-then-MAC */
	संरचना ssh_hmac_ctx	*hmac_ctx;
	संरचना umac_ctx		*umac_ctx;
};

पूर्णांक	 mac_valid(स्थिरांक अक्षर *);
अक्षर	*mac_alg_list(अक्षर);
पूर्णांक	 mac_setup(संरचना sshmac *, अक्षर *);
पूर्णांक	 mac_init(संरचना sshmac *);
पूर्णांक	 mac_compute(संरचना sshmac *, uint32_t, स्थिरांक u_char *, पूर्णांक,
    u_char *, माप_प्रकार);
पूर्णांक	 mac_check(संरचना sshmac *, uint32_t, स्थिरांक u_char *, माप_प्रकार,
    स्थिरांक u_char *, माप_प्रकार);
शून्य	 mac_clear(संरचना sshmac *);

#endif /* SSHMAC_H */
