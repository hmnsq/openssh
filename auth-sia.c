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

#অন্তর্ভাব "includes.h"

#ifdef HAVE_OSF_SIA
#অন্তর্ভাব <sia.h>
#অন্তর্ভাব <siad.h>
#অন্তর্ভাব <pwd.h>
#অন্তর্ভাব <signal.h>
#অন্তর্ভাব <setjmp.h>
#অন্তর্ভাব <sys/resource.h>
#অন্তর্ভাব <unistd.h>
#অন্তর্ভাব <stdarg.h>
#অন্তর্ভাব <string.h>

#অন্তর্ভাব "ssh.h"
#অন্তর্ভাব "ssh_api.h"
#অন্তর্ভাব "hostfile.h"
#অন্তর্ভাব "auth.h"
#অন্তর্ভাব "auth-sia.h"
#অন্তর্ভাব "log.h"
#অন্তর্ভাব "servconf.h"
#অন্তর্ভাব "canohost.h"
#অন্তর্ভাব "uidswap.h"

বাহ্যিক ServerOptions options;
বাহ্যিক পূর্ণসংখ্যা saved_argc;
বাহ্যিক অক্ষর **saved_argv;

পূর্ণসংখ্যা
sys_auth_passwd(কাঠামো ssh *ssh, ধ্রুবক অক্ষর *pass)
{
	পূর্ণসংখ্যা ret;
	SIAENTITY *ent = ফাঁকা;
	ধ্রুবক অক্ষর *host;
	Authctxt *authctxt = ssh->authctxt;

	host = get_canonical_hostname(options.use_dns);

	যদি (!authctxt->user || pass == ফাঁকা || pass[0] == '\0')
		ফেরত (0);

	যদি (sia_ses_init(&ent, saved_argc, saved_argv, host, authctxt->user,
	    ফাঁকা, 0, ফাঁকা) != SIASUCCESS)
		ফেরত (0);

	যদি ((ret = sia_ses_authent(ফাঁকা, pass, ent)) != SIASUCCESS) {
		error("Couldn't authenticate %s from %s",
		    authctxt->user, host);
		যদি (ret & SIASTOP)
			sia_ses_release(&ent);

		ফেরত (0);
	}

	sia_ses_release(&ent);

	ফেরত (1);
}

শূন্য
session_setup_sia(কাঠামো passwd *pw, অক্ষর *tty)
{
	SIAENTITY *ent = ফাঁকা;
	ধ্রুবক অক্ষর *host;

	host = get_canonical_hostname(options.use_dns);

	যদি (sia_ses_init(&ent, saved_argc, saved_argv, host, pw->pw_name,
	    tty, 0, ফাঁকা) != SIASUCCESS)
		fatal("sia_ses_init failed");

	যদি (sia_make_entity_pwd(pw, ent) != SIASUCCESS) {
		sia_ses_release(&ent);
		fatal("sia_make_entity_pwd failed");
	}

	ent->authtype = SIA_A_NONE;
	যদি (sia_ses_estab(sia_collect_trm, ent) != SIASUCCESS)
		fatal("Couldn't establish session for %s from %s",
		    pw->pw_name, host);

	যদি (sia_ses_launch(sia_collect_trm, ent) != SIASUCCESS)
		fatal("Couldn't launch session for %s from %s",
		    pw->pw_name, host);

	sia_ses_release(&ent);

	setuid(0);
	permanently_set_uid(pw);
}

#endif /* HAVE_OSF_SIA */
