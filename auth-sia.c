/*
 * Copyright (c) 2002 Chris Adams.  All rights reserved.
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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_OSF_SIA
#ਅਨ੍ਤਰ੍ਭਾਵ <sia.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <siad.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <pwd.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <signal.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <setjmp.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/resource.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <unistd.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdarg.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "ssh.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssh_api.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "hostfile.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "auth.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "auth-sia.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "log.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "servconf.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "canohost.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "uidswap.h"

ਬਾਹਰੀ ServerOptions options;
ਬਾਹਰੀ ਪੂਰਨ saved_argc;
ਬਾਹਰੀ ਅੱਖਰ **saved_argv;

ਪੂਰਨ
sys_auth_passwd(ਬਣਤਰ ssh *ssh, ਅਚਲ ਅੱਖਰ *pass)
{
	ਪੂਰਨ ret;
	SIAENTITY *ent = ਨਿਰਾ;
	ਅਚਲ ਅੱਖਰ *host;
	Authctxt *authctxt = ssh->authctxt;

	host = get_canonical_hostname(options.use_dns);

	ਜੇ (!authctxt->user || pass == ਨਿਰਾ || pass[0] == '\0')
		ਵਾਪਸ (0);

	ਜੇ (sia_ses_init(&ent, saved_argc, saved_argv, host, authctxt->user,
	    ਨਿਰਾ, 0, ਨਿਰਾ) != SIASUCCESS)
		ਵਾਪਸ (0);

	ਜੇ ((ret = sia_ses_authent(ਨਿਰਾ, pass, ent)) != SIASUCCESS) {
		error("Couldn't authenticate %s from %s",
		    authctxt->user, host);
		ਜੇ (ret & SIASTOP)
			sia_ses_release(&ent);

		ਵਾਪਸ (0);
	}

	sia_ses_release(&ent);

	ਵਾਪਸ (1);
}

ਖਾਲੀ
session_ਤਿਆਰੀ_sia(ਬਣਤਰ passwd *pw, ਅੱਖਰ *tty)
{
	SIAENTITY *ent = ਨਿਰਾ;
	ਅਚਲ ਅੱਖਰ *host;

	host = get_canonical_hostname(options.use_dns);

	ਜੇ (sia_ses_init(&ent, saved_argc, saved_argv, host, pw->pw_name,
	    tty, 0, ਨਿਰਾ) != SIASUCCESS)
		fatal("sia_ses_init failed");

	ਜੇ (sia_make_entity_pwd(pw, ent) != SIASUCCESS) {
		sia_ses_release(&ent);
		fatal("sia_make_entity_pwd failed");
	}

	ent->authtype = SIA_A_NONE;
	ਜੇ (sia_ses_estab(sia_collect_trm, ent) != SIASUCCESS)
		fatal("Couldn't establish session for %s from %s",
		    pw->pw_name, host);

	ਜੇ (sia_ses_launch(sia_collect_trm, ent) != SIASUCCESS)
		fatal("Couldn't launch session for %s from %s",
		    pw->pw_name, host);

	sia_ses_release(&ent);

	setuid(0);
	permanently_ਸੈੱਟ_uid(pw);
}

#ਜੇ_ਅੰਤ /* HAVE_OSF_SIA */
