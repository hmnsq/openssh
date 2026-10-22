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

#અન્તર્ભાવ "includes.h"

#ifdef HAVE_OSF_SIA
#અન્તર્ભાવ <sia.h>
#અન્તર્ભાવ <siad.h>
#અન્તર્ભાવ <pwd.h>
#અન્તર્ભાવ <signal.h>
#અન્તર્ભાવ <setjmp.h>
#અન્તર્ભાવ <sys/resource.h>
#અન્તર્ભાવ <unistd.h>
#અન્તર્ભાવ <stdarg.h>
#અન્તર્ભાવ <string.h>

#અન્તર્ભાવ "ssh.h"
#અન્તર્ભાવ "ssh_api.h"
#અન્તર્ભાવ "hostfile.h"
#અન્તર્ભાવ "auth.h"
#અન્તર્ભાવ "auth-sia.h"
#અન્તર્ભાવ "log.h"
#અન્તર્ભાવ "servconf.h"
#અન્તર્ભાવ "canohost.h"
#અન્તર્ભાવ "uidswap.h"

બાહ્ય ServerOptions options;
બાહ્ય પૂર્ણાંક saved_argc;
બાહ્ય અક્ષર **saved_argv;

પૂર્ણાંક
sys_auth_passwd(સંરચના ssh *ssh, અચલ અક્ષર *pass)
{
	પૂર્ણાંક ret;
	SIAENTITY *ent = ખાલી;
	અચલ અક્ષર *host;
	Authctxt *authctxt = ssh->authctxt;

	host = get_canonical_hostname(options.use_dns);

	જો (!authctxt->user || pass == ખાલી || pass[0] == '\0')
		પાછા (0);

	જો (sia_ses_init(&ent, saved_argc, saved_argv, host, authctxt->user,
	    ખાલી, 0, ખાલી) != SIASUCCESS)
		પાછા (0);

	જો ((ret = sia_ses_authent(ખાલી, pass, ent)) != SIASUCCESS) {
		error("Couldn't authenticate %s from %s",
		    authctxt->user, host);
		જો (ret & SIASTOP)
			sia_ses_release(&ent);

		પાછા (0);
	}

	sia_ses_release(&ent);

	પાછા (1);
}

શૂન્ય
session_setup_sia(સંરચના passwd *pw, અક્ષર *tty)
{
	SIAENTITY *ent = ખાલી;
	અચલ અક્ષર *host;

	host = get_canonical_hostname(options.use_dns);

	જો (sia_ses_init(&ent, saved_argc, saved_argv, host, pw->pw_name,
	    tty, 0, ખાલી) != SIASUCCESS)
		fatal("sia_ses_init failed");

	જો (sia_make_entity_pwd(pw, ent) != SIASUCCESS) {
		sia_ses_release(&ent);
		fatal("sia_make_entity_pwd failed");
	}

	ent->authtype = SIA_A_NONE;
	જો (sia_ses_estab(sia_collect_trm, ent) != SIASUCCESS)
		fatal("Couldn't establish session for %s from %s",
		    pw->pw_name, host);

	જો (sia_ses_launch(sia_collect_trm, ent) != SIASUCCESS)
		fatal("Couldn't launch session for %s from %s",
		    pw->pw_name, host);

	sia_ses_release(&ent);

	setuid(0);
	permanently_set_uid(pw);
}

#endif /* HAVE_OSF_SIA */
