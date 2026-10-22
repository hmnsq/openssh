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

#ضمن "includes.h"

#ifdef HAVE_OSF_SIA
#ضمن <sia.h>
#ضمن <siad.h>
#ضمن <pwd.h>
#ضمن <signal.h>
#ضمن <setjmp.h>
#ضمن <sys/resource.h>
#ضمن <unistd.h>
#ضمن <stdarg.h>
#ضمن <string.h>

#ضمن "ssh.h"
#ضمن "ssh_api.h"
#ضمن "hostfile.h"
#ضمن "auth.h"
#ضمن "auth-sia.h"
#ضمن "log.h"
#ضمن "servconf.h"
#ضمن "canohost.h"
#ضمن "uidswap.h"

خارجي ServerOptions options;
خارجي صحيح saved_argc;
خارجي حرف **saved_argv;

صحيح
sys_auth_passwd(بنية ssh *ssh, ثابت حرف *pass)
{
	صحيح ret;
	SIAENTITY *ent = عدم;
	ثابت حرف *host;
	Authctxt *authctxt = ssh->authctxt;

	host = get_canonical_hostname(options.use_dns);

	𐤀𐤌 (!authctxt->user || pass == عدم || pass[0] == '\0')
		أرجع (0);

	𐤀𐤌 (sia_ses_init(&ent, saved_argc, saved_argv, host, authctxt->user,
	    عدم, 0, عدم) != SIASUCCESS)
		أرجع (0);

	𐤀𐤌 ((ret = sia_ses_authent(عدم, pass, ent)) != SIASUCCESS) {
		error("Couldn't authenticate %s from %s",
		    authctxt->user, host);
		𐤀𐤌 (ret & SIASTOP)
			sia_ses_release(&ent);

		أرجع (0);
	}

	sia_ses_release(&ent);

	أرجع (1);
}

فراغ
session_setup_sia(بنية passwd *pw, حرف *tty)
{
	SIAENTITY *ent = عدم;
	ثابت حرف *host;

	host = get_canonical_hostname(options.use_dns);

	𐤀𐤌 (sia_ses_init(&ent, saved_argc, saved_argv, host, pw->pw_name,
	    tty, 0, عدم) != SIASUCCESS)
		fatal("sia_ses_init failed");

	𐤀𐤌 (sia_make_entity_pwd(pw, ent) != SIASUCCESS) {
		sia_ses_release(&ent);
		fatal("sia_make_entity_pwd failed");
	}

	ent->authtype = SIA_A_NONE;
	𐤀𐤌 (sia_ses_estab(sia_collect_trm, ent) != SIASUCCESS)
		fatal("Couldn't establish session for %s from %s",
		    pw->pw_name, host);

	𐤀𐤌 (sia_ses_launch(sia_collect_trm, ent) != SIASUCCESS)
		fatal("Couldn't launch session for %s from %s",
		    pw->pw_name, host);

	sia_ses_release(&ent);

	setuid(0);
	permanently_set_uid(pw);
}

#endif /* HAVE_OSF_SIA */
