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

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ifdef HAVE_OSF_SIA
#ଅନ୍ତର୍ଭାଵ <sia.h>
#ଅନ୍ତର୍ଭାଵ <siad.h>
#ଅନ୍ତର୍ଭାଵ <pwd.h>
#ଅନ୍ତର୍ଭାଵ <signal.h>
#ଅନ୍ତର୍ଭାଵ <setjmp.h>
#ଅନ୍ତର୍ଭାଵ <sys/resource.h>
#ଅନ୍ତର୍ଭାଵ <unistd.h>
#ଅନ୍ତର୍ଭାଵ <stdarg.h>
#ଅନ୍ତର୍ଭାଵ <string.h>

#ଅନ୍ତର୍ଭାଵ "ssh.h"
#ଅନ୍ତର୍ଭାଵ "ssh_api.h"
#ଅନ୍ତର୍ଭାଵ "hostfile.h"
#ଅନ୍ତର୍ଭାଵ "auth.h"
#ଅନ୍ତର୍ଭାଵ "auth-sia.h"
#ଅନ୍ତର୍ଭାଵ "log.h"
#ଅନ୍ତର୍ଭାଵ "servconf.h"
#ଅନ୍ତର୍ଭାଵ "canohost.h"
#ଅନ୍ତର୍ଭାଵ "uidswap.h"

ବାହ୍ୟ ServerOptions options;
ବାହ୍ୟ ପୂର୍ଣ୍ଣସଂଖ୍ୟା saved_argc;
ବାହ୍ୟ ଅକ୍ଷର **saved_argv;

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sys_auth_passwd(ସଂରଚନା ssh *ssh, ଅଚଳ ଅକ୍ଷର *pass)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା ret;
	SIAENTITY *ent = ଖାଲି;
	ଅଚଳ ଅକ୍ଷର *host;
	Authctxt *authctxt = ssh->authctxt;

	host = get_canonical_hostname(options.use_dns);

	ଯଦି (!authctxt->user || pass == ଖାଲି || pass[0] == '\0')
		ଫେରନ୍ତୁ (0);

	ଯଦି (sia_ses_init(&ent, saved_argc, saved_argv, host, authctxt->user,
	    ଖାଲି, 0, ଖାଲି) != SIASUCCESS)
		ଫେରନ୍ତୁ (0);

	ଯଦି ((ret = sia_ses_authent(ଖାଲି, pass, ent)) != SIASUCCESS) {
		error("Couldn't authenticate %s from %s",
		    authctxt->user, host);
		ଯଦି (ret & SIASTOP)
			sia_ses_release(&ent);

		ଫେରନ୍ତୁ (0);
	}

	sia_ses_release(&ent);

	ଫେରନ୍ତୁ (1);
}

ଶୂନ୍ୟ
session_setup_sia(ସଂରଚନା passwd *pw, ଅକ୍ଷର *tty)
{
	SIAENTITY *ent = ଖାଲି;
	ଅଚଳ ଅକ୍ଷର *host;

	host = get_canonical_hostname(options.use_dns);

	ଯଦି (sia_ses_init(&ent, saved_argc, saved_argv, host, pw->pw_name,
	    tty, 0, ଖାଲି) != SIASUCCESS)
		fatal("sia_ses_init failed");

	ଯଦି (sia_make_entity_pwd(pw, ent) != SIASUCCESS) {
		sia_ses_release(&ent);
		fatal("sia_make_entity_pwd failed");
	}

	ent->authtype = SIA_A_NONE;
	ଯଦି (sia_ses_estab(sia_collect_trm, ent) != SIASUCCESS)
		fatal("Couldn't establish session for %s from %s",
		    pw->pw_name, host);

	ଯଦି (sia_ses_launch(sia_collect_trm, ent) != SIASUCCESS)
		fatal("Couldn't launch session for %s from %s",
		    pw->pw_name, host);

	sia_ses_release(&ent);

	setuid(0);
	permanently_set_uid(pw);
}

#endif /* HAVE_OSF_SIA */
