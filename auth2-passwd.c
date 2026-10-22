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

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <sys/types.h>

#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <stdarg.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>

#ಅನ್ತರ್ಭಾವ "packet.h"
#ಅನ್ತರ್ಭಾವ "ssherr.h"
#ಅನ್ತರ್ಭಾವ "log.h"
#ಅನ್ತರ್ಭಾವ "sshkey.h"
#ಅನ್ತರ್ಭಾವ "hostfile.h"
#ಅನ್ತರ್ಭಾವ "auth.h"
#ifdef GSSAPI
#ಅನ್ತರ್ಭಾವ "ssh-gss.h"
#endif
#ಅನ್ತರ್ಭಾವ "monitor_wrap.h"
#ಅನ್ತರ್ಭಾವ "misc.h"
#ಅನ್ತರ್ಭಾವ "servconf.h"

/* import */
ಬಾಹ್ಯ ServerOptions options;
ಬಾಹ್ಯ ಸಂರಚನಾ authmethod_cfg methodcfg_passwd;

ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
userauth_passwd(ಸಂರಚನಾ ssh *ssh, ಧ್ರುವ ವರ್ಣ *method)
{
	ವರ್ಣ *password = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ authenticated = 0, r;
	u_char change;
	size_t len = 0;

	ಯದಿ ((r = sshpkt_get_u8(ssh, &change)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &password, &len)) != 0 ||
	    (change && (r = sshpkt_get_cstring(ssh, ರಿಕ್ತ, ರಿಕ್ತ)) != 0) ||
	    (r = sshpkt_get_end(ssh)) != 0) {
		freezero(password, len);
		fatal_fr(r, "parse packet");
	}

	ಯದಿ (change)
		logit("password change not supported");
	ಅನ್ಯಥಾ ಯದಿ (mm_auth_password(ssh, password) == 1)
		authenticated = 1;
	freezero(password, len);
	ಪ್ರತ್ಯಾಗಮ authenticated;
}

Authmethod method_passwd = {
	&methodcfg_passwd,
	userauth_passwd,
};
