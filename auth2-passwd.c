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

#समावेश "includes.h"

#समावेश <sys/types.h>

#समावेश <stdlib.h>
#समावेश <string.h>
#समावेश <stdarg.h>
#समावेश <stdio.h>

#समावेश "packet.h"
#समावेश "ssherr.h"
#समावेश "log.h"
#समावेश "sshkey.h"
#समावेश "hostfile.h"
#समावेश "auth.h"
#अगर_घोषित GSSAPI
#समावेश "ssh-gss.h"
#पूर्ण_अगर
#समावेश "monitor_wrap.h"
#समावेश "misc.h"
#समावेश "servconf.h"

/* import */
बाह्य ServerOptions options;
बाह्य काष्ठा authmethod_cfg methodcfg_passwd;

अटल पूर्णांक
userauth_passwd(काष्ठा ssh *ssh, स्थिर अक्षर *method)
{
	अक्षर *password = शून्य;
	पूर्णांक authenticated = 0, r;
	u_char change;
	माप_प्रकार len = 0;

	अगर ((r = sshpkt_get_u8(ssh, &change)) != 0 ||
	    (r = sshpkt_get_cstring(ssh, &password, &len)) != 0 ||
	    (change && (r = sshpkt_get_cstring(ssh, शून्य, शून्य)) != 0) ||
	    (r = sshpkt_get_end(ssh)) != 0) {
		freezero(password, len);
		fatal_fr(r, "parse packet");
	}

	अगर (change)
		logit("password change not supported");
	अन्यथा अगर (mm_auth_password(ssh, password) == 1)
		authenticated = 1;
	freezero(password, len);
	वापस authenticated;
}

Authmethod method_passwd = {
	&methodcfg_passwd,
	userauth_passwd,
};
