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

#అన్తర్భావ "includes.h"

#నిర్వచితమైతే HAVE_OSF_SIA
#అన్తర్భావ <sia.h>
#అన్తర్భావ <siad.h>
#అన్తర్భావ <pwd.h>
#అన్తర్భావ <signal.h>
#అన్తర్భావ <setjmp.h>
#అన్తర్భావ <sys/resource.h>
#అన్తర్భావ <unistd.h>
#అన్తర్భావ <stdarg.h>
#అన్తర్భావ <string.h>

#అన్తర్భావ "ssh.h"
#అన్తర్భావ "ssh_api.h"
#అన్తర్భావ "hostfile.h"
#అన్తర్భావ "auth.h"
#అన్తర్భావ "auth-sia.h"
#అన్తర్భావ "log.h"
#అన్తర్భావ "servconf.h"
#అన్తర్భావ "canohost.h"
#అన్తర్భావ "uidswap.h"

బాహ్య ServerOptions options;
బాహ్య పూర్ణాంకం saved_argc;
బాహ్య అక్షరం **saved_argv;

పూర్ణాంకం
sys_auth_passwd(నిర్మాణం ssh *ssh, స్థిరరాశి అక్షరం *pass)
{
	పూర్ణాంకం ret;
	SIAENTITY *ent = ఖాళీ;
	స్థిరరాశి అక్షరం *host;
	Authctxt *authctxt = ssh->authctxt;

	host = get_canonical_hostname(options.use_dns);

	ఒకవేళ (!authctxt->user || pass == ఖాళీ || pass[0] == '\0')
		తిరిగి (0);

	ఒకవేళ (sia_ses_init(&ent, saved_argc, saved_argv, host, authctxt->user,
	    ఖాళీ, 0, ఖాళీ) != SIASUCCESS)
		తిరిగి (0);

	ఒకవేళ ((ret = sia_ses_authent(ఖాళీ, pass, ent)) != SIASUCCESS) {
		error("Couldn't authenticate %s from %s",
		    authctxt->user, host);
		ఒకవేళ (ret & SIASTOP)
			sia_ses_release(&ent);

		తిరిగి (0);
	}

	sia_ses_release(&ent);

	తిరిగి (1);
}

శూన్య
session_అమరిక_sia(నిర్మాణం passwd *pw, అక్షరం *tty)
{
	SIAENTITY *ent = ఖాళీ;
	స్థిరరాశి అక్షరం *host;

	host = get_canonical_hostname(options.use_dns);

	ఒకవేళ (sia_ses_init(&ent, saved_argc, saved_argv, host, pw->pw_name,
	    tty, 0, ఖాళీ) != SIASUCCESS)
		fatal("sia_ses_init failed");

	ఒకవేళ (sia_make_entity_pwd(pw, ent) != SIASUCCESS) {
		sia_ses_release(&ent);
		fatal("sia_make_entity_pwd failed");
	}

	ent->authtype = SIA_A_NONE;
	ఒకవేళ (sia_ses_estab(sia_collect_trm, ent) != SIASUCCESS)
		fatal("Couldn't establish session for %s from %s",
		    pw->pw_name, host);

	ఒకవేళ (sia_ses_launch(sia_collect_trm, ent) != SIASUCCESS)
		fatal("Couldn't launch session for %s from %s",
		    pw->pw_name, host);

	sia_ses_release(&ent);

	setuid(0);
	permanently_సమితి_uid(pw);
}

#అయితే_ముగింపు /* HAVE_OSF_SIA */
