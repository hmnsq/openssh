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

#شامل "includes.h"

#ifdef HAVE_OSF_SIA
#شامل <sia.h>
#شامل <siad.h>
#شامل <pwd.h>
#شامل <signal.h>
#شامل <setjmp.h>
#شامل <sys/resource.h>
#شامل <unistd.h>
#شامل <stdarg.h>
#شامل <string.h>

#شامل "ssh.h"
#شامل "ssh_api.h"
#شامل "hostfile.h"
#شامل "auth.h"
#شامل "auth-sia.h"
#شامل "log.h"
#شامل "servconf.h"
#شامل "canohost.h"
#شامل "uidswap.h"

بیرونی ServerOptions options;
بیرونی صحیح saved_argc;
بیرونی نویسه **saved_argv;

صحیح
sys_auth_passwd(ساختار ssh *ssh, ثابت نویسه *pass)
{
	صحیح ret;
	SIAENTITY *ent = پوچ;
	ثابت نویسه *host;
	Authctxt *authctxt = ssh->authctxt;

	host = get_canonical_hostname(options.use_dns);

	اگر (!authctxt->user || pass == پوچ || pass[0] == '\0')
		بازگشت (0);

	اگر (sia_ses_init(&ent, saved_argc, saved_argv, host, authctxt->user,
	    پوچ, 0, پوچ) != SIASUCCESS)
		بازگشت (0);

	اگر ((ret = sia_ses_authent(پوچ, pass, ent)) != SIASUCCESS) {
		error("Couldn't authenticate %s from %s",
		    authctxt->user, host);
		اگر (ret & SIASTOP)
			sia_ses_release(&ent);

		بازگشت (0);
	}

	sia_ses_release(&ent);

	بازگشت (1);
}

تهی
session_setup_sia(ساختار passwd *pw, نویسه *tty)
{
	SIAENTITY *ent = پوچ;
	ثابت نویسه *host;

	host = get_canonical_hostname(options.use_dns);

	اگر (sia_ses_init(&ent, saved_argc, saved_argv, host, pw->pw_name,
	    tty, 0, پوچ) != SIASUCCESS)
		fatal("sia_ses_init failed");

	اگر (sia_make_entity_pwd(pw, ent) != SIASUCCESS) {
		sia_ses_release(&ent);
		fatal("sia_make_entity_pwd failed");
	}

	ent->authtype = SIA_A_NONE;
	اگر (sia_ses_estab(sia_collect_trm, ent) != SIASUCCESS)
		fatal("Couldn't establish session for %s from %s",
		    pw->pw_name, host);

	اگر (sia_ses_launch(sia_collect_trm, ent) != SIASUCCESS)
		fatal("Couldn't launch session for %s from %s",
		    pw->pw_name, host);

	sia_ses_release(&ent);

	setuid(0);
	permanently_set_uid(pw);
}

#endif /* HAVE_OSF_SIA */
