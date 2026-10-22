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

#شامل "includes.h"

#شامل <sys/types.h>

#شامل <stdlib.h>
#شامل <string.h>
#شامل <stdarg.h>
#شامل <stdio.h>

#شامل "packet.h"
#شامل "ssherr.h"
#شامل "log.h"
#شامل "sshkey.h"
#شامل "hostfile.h"
#شامل "auth.h"
#اگر_تعریف_شدہ GSSAPI
#شامل "ssh-gss.h"
#اگر_ختم
#شامل "monitor_wrap.h"
#شامل "misc.h"
#شامل "servconf.h"

/* import */
خارجی ServerOptions options;
خارجی ساخت authmethod_cfg methodcfg_passwd;

ساکن صحیح
userauth_passwd(ساخت ssh *ssh, ثابت حرف *طریقہ)
{
	حرف *password = تہی;
	صحیح authenticated = 0, r;
	u_char change;
	سائز_t len = 0;

	اگر ((r = sshpkt_get_u8(ssh, &change)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &password, &len)) != 0 ||
	    (change && (r = sshpkt_get_cstring(ssh, تہی, تہی)) != 0) ||
	    (r = sshpkt_get_انتہا(ssh)) != 0) {
		freezero(password, len);
		fatal_fr(r, "parse packet");
	}

	اگر (change)
		logit("password change not supported");
	ورنہ اگر (mm_auth_password(ssh, password) == 1)
		authenticated = 1;
	freezero(password, len);
	واپس authenticated;
}

Authmethod طریقہ_passwd = {
	&methodcfg_passwd,
	userauth_passwd,
};
