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

#अन्तर्भाव "includes.h"

#ifdef HAVE_OSF_SIA
#अन्तर्भाव <sia.h>
#अन्तर्भाव <siad.h>
#अन्तर्भाव <pwd.h>
#अन्तर्भाव <signal.h>
#अन्तर्भाव <setjmp.h>
#अन्तर्भाव <sys/resource.h>
#अन्तर्भाव <unistd.h>
#अन्तर्भाव <stdarg.h>
#अन्तर्भाव <string.h>

#अन्तर्भाव "ssh.h"
#अन्तर्भाव "ssh_api.h"
#अन्तर्भाव "hostfile.h"
#अन्तर्भाव "auth.h"
#अन्तर्भाव "auth-sia.h"
#अन्तर्भाव "log.h"
#अन्तर्भाव "servconf.h"
#अन्तर्भाव "canohost.h"
#अन्तर्भाव "uidswap.h"

बाह्य ServerOptions options;
बाह्य पूर्णाङ्क saved_argc;
बाह्य वर्ण **saved_argv;

पूर्णाङ्क
sys_auth_passwd(संरचना ssh *ssh, ध्रुव वर्ण *pass)
{
	पूर्णाङ्क ret;
	SIAENTITY *ent = रिक्त;
	ध्रुव वर्ण *host;
	Authctxt *authctxt = ssh->authctxt;

	host = get_canonical_hostname(options.use_dns);

	यदि (!authctxt->user || pass == रिक्त || pass[0] == '\0')
		प्रत्यागम (0);

	यदि (sia_ses_init(&ent, saved_argc, saved_argv, host, authctxt->user,
	    रिक्त, 0, रिक्त) != SIASUCCESS)
		प्रत्यागम (0);

	यदि ((ret = sia_ses_authent(रिक्त, pass, ent)) != SIASUCCESS) {
		error("Couldn't authenticate %s from %s",
		    authctxt->user, host);
		यदि (ret & SIASTOP)
			sia_ses_release(&ent);

		प्रत्यागम (0);
	}

	sia_ses_release(&ent);

	प्रत्यागम (1);
}

शून्य
session_setup_sia(संरचना passwd *pw, वर्ण *tty)
{
	SIAENTITY *ent = रिक्त;
	ध्रुव वर्ण *host;

	host = get_canonical_hostname(options.use_dns);

	यदि (sia_ses_init(&ent, saved_argc, saved_argv, host, pw->pw_name,
	    tty, 0, रिक्त) != SIASUCCESS)
		fatal("sia_ses_init failed");

	यदि (sia_make_entity_pwd(pw, ent) != SIASUCCESS) {
		sia_ses_release(&ent);
		fatal("sia_make_entity_pwd failed");
	}

	ent->authtype = SIA_A_NONE;
	यदि (sia_ses_estab(sia_collect_trm, ent) != SIASUCCESS)
		fatal("Couldn't establish session for %s from %s",
		    pw->pw_name, host);

	यदि (sia_ses_launch(sia_collect_trm, ent) != SIASUCCESS)
		fatal("Couldn't launch session for %s from %s",
		    pw->pw_name, host);

	sia_ses_release(&ent);

	setuid(0);
	permanently_set_uid(pw);
}

#endif /* HAVE_OSF_SIA */
