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

#അന്തര്ഭാവ "includes.h"

#ifdef HAVE_OSF_SIA
#അന്തര്ഭാവ <sia.h>
#അന്തര്ഭാവ <siad.h>
#അന്തര്ഭാവ <pwd.h>
#അന്തര്ഭാവ <signal.h>
#അന്തര്ഭാവ <setjmp.h>
#അന്തര്ഭാവ <sys/resource.h>
#അന്തര്ഭാവ <unistd.h>
#അന്തര്ഭാവ <stdarg.h>
#അന്തര്ഭാവ <string.h>

#അന്തര്ഭാവ "ssh.h"
#അന്തര്ഭാവ "ssh_api.h"
#അന്തര്ഭാവ "hostfile.h"
#അന്തര്ഭാവ "auth.h"
#അന്തര്ഭാവ "auth-sia.h"
#അന്തര്ഭാവ "log.h"
#അന്തര്ഭാവ "servconf.h"
#അന്തര്ഭാവ "canohost.h"
#അന്തര്ഭാവ "uidswap.h"

ബാഹ്യ ServerOptions options;
ബാഹ്യ പൂർണ്ണസംഖ്യ saved_argc;
ബാഹ്യ അക്ഷരം **saved_argv;

പൂർണ്ണസംഖ്യ
sys_auth_passwd(ഘടന ssh *ssh, സ്ഥിരം അക്ഷരം *pass)
{
	പൂർണ്ണസംഖ്യ ret;
	SIAENTITY *ent = ശൂന്യ;
	സ്ഥിരം അക്ഷരം *host;
	Authctxt *authctxt = ssh->authctxt;

	host = get_canonical_hostname(options.use_dns);

	എങ്കിൽ (!authctxt->user || pass == ശൂന്യ || pass[0] == '\0')
		തിരികെ (0);

	എങ്കിൽ (sia_ses_init(&ent, saved_argc, saved_argv, host, authctxt->user,
	    ശൂന്യ, 0, ശൂന്യ) != SIASUCCESS)
		തിരികെ (0);

	എങ്കിൽ ((ret = sia_ses_authent(ശൂന്യ, pass, ent)) != SIASUCCESS) {
		error("Couldn't authenticate %s from %s",
		    authctxt->user, host);
		എങ്കിൽ (ret & SIASTOP)
			sia_ses_release(&ent);

		തിരികെ (0);
	}

	sia_ses_release(&ent);

	തിരികെ (1);
}

ശൂന്യം
session_setup_sia(ഘടന passwd *pw, അക്ഷരം *tty)
{
	SIAENTITY *ent = ശൂന്യ;
	സ്ഥിരം അക്ഷരം *host;

	host = get_canonical_hostname(options.use_dns);

	എങ്കിൽ (sia_ses_init(&ent, saved_argc, saved_argv, host, pw->pw_name,
	    tty, 0, ശൂന്യ) != SIASUCCESS)
		fatal("sia_ses_init failed");

	എങ്കിൽ (sia_make_entity_pwd(pw, ent) != SIASUCCESS) {
		sia_ses_release(&ent);
		fatal("sia_make_entity_pwd failed");
	}

	ent->authtype = SIA_A_NONE;
	എങ്കിൽ (sia_ses_estab(sia_collect_trm, ent) != SIASUCCESS)
		fatal("Couldn't establish session for %s from %s",
		    pw->pw_name, host);

	എങ്കിൽ (sia_ses_launch(sia_collect_trm, ent) != SIASUCCESS)
		fatal("Couldn't launch session for %s from %s",
		    pw->pw_name, host);

	sia_ses_release(&ent);

	setuid(0);
	permanently_set_uid(pw);
}

#endif /* HAVE_OSF_SIA */
