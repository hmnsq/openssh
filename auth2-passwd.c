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

#અન્તર્ભાવ "includes.h"

#અન્તર્ભાવ <sys/types.h>

#અન્તર્ભાવ <stdlib.h>
#અન્તર્ભાવ <string.h>
#અન્તર્ભાવ <stdarg.h>
#અન્તર્ભાવ <stdio.h>

#અન્તર્ભાવ "packet.h"
#અન્તર્ભાવ "ssherr.h"
#અન્તર્ભાવ "log.h"
#અન્તર્ભાવ "sshkey.h"
#અન્તર્ભાવ "hostfile.h"
#અન્તર્ભાવ "auth.h"
#ifdef GSSAPI
#અન્તર્ભાવ "ssh-gss.h"
#endif
#અન્તર્ભાવ "monitor_wrap.h"
#અન્તર્ભાવ "misc.h"
#અન્તર્ભાવ "servconf.h"

/* import */
બાહ્ય ServerOptions options;
બાહ્ય સંરચના authmethod_cfg methodcfg_passwd;

સ્થિર પૂર્ણાંક
userauth_passwd(સંરચના ssh *ssh, અચલ અક્ષર *method)
{
	અક્ષર *password = ખાલી;
	પૂર્ણાંક authenticated = 0, r;
	u_char change;
	size_t len = 0;

	જો ((r = sshpkt_get_u8(ssh, &change)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &password, &len)) != 0 ||
	    (change && (r = sshpkt_get_cstring(ssh, ખાલી, ખાલી)) != 0) ||
	    (r = sshpkt_get_end(ssh)) != 0) {
		freezero(password, len);
		fatal_fr(r, "parse packet");
	}

	જો (change)
		logit("password change not supported");
	નહીંતર જો (mm_auth_password(ssh, password) == 1)
		authenticated = 1;
	freezero(password, len);
	પાછા authenticated;
}

Authmethod method_passwd = {
	&methodcfg_passwd,
	userauth_passwd,
};
