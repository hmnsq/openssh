/* $OpenBSD: auth2-passwd.c,v 1.22 2024/05/17 00:30:23 djm Exp $ */
/*
 * Copyright (c) 2000 Markus Friedl.  All rights reserved.
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

#అన్తర్భావ "includes.h"

#అన్తర్భావ <sys/types.h>

#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <stdarg.h>
#అన్తర్భావ <stdio.h>

#అన్తర్భావ "packet.h"
#అన్తర్భావ "ssherr.h"
#అన్తర్భావ "log.h"
#అన్తర్భావ "sshkey.h"
#అన్తర్భావ "hostfile.h"
#అన్తర్భావ "auth.h"
#నిర్వచితమైతే GSSAPI
#అన్తర్భావ "ssh-gss.h"
#అయితే_ముగింపు
#అన్తర్భావ "monitor_wrap.h"
#అన్తర్భావ "misc.h"
#అన్తర్భావ "servconf.h"

/* import */
బాహ్య ServerOptions options;
బాహ్య నిర్మాణం authmethod_cfg methodcfg_passwd;

స్థిర పూర్ణాంకం
userauth_passwd(నిర్మాణం ssh *ssh, స్థిరరాశి అక్షరం *పద్ధతి)
{
	అక్షరం *password = ఖాళీ;
	పూర్ణాంకం authenticated = 0, r;
	u_char change;
	కొలత_t len = 0;

	ఒకవేళ ((r = sshpkt_get_u8(ssh, &change)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &password, &len)) != 0 ||
	    (change && (r = sshpkt_get_cstring(ssh, ఖాళీ, ఖాళీ)) != 0) ||
	    (r = sshpkt_get_చివర(ssh)) != 0) {
		freezero(password, len);
		fatal_fr(r, "parse packet");
	}

	ఒకవేళ (change)
		logit("password change not supported");
	లేకపోతే ఒకవేళ (mm_auth_password(ssh, password) == 1)
		authenticated = 1;
	freezero(password, len);
	తిరిగి authenticated;
}

Authmethod పద్ధతి_passwd = {
	&methodcfg_passwd,
	userauth_passwd,
};
