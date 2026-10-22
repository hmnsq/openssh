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

#ಅನ್ತರ್ಭಾವ "includes.h"

#ifdef HAVE_OSF_SIA
#ಅನ್ತರ್ಭಾವ <sia.h>
#ಅನ್ತರ್ಭಾವ <siad.h>
#ಅನ್ತರ್ಭಾವ <pwd.h>
#ಅನ್ತರ್ಭಾವ <signal.h>
#ಅನ್ತರ್ಭಾವ <setjmp.h>
#ಅನ್ತರ್ಭಾವ <sys/resource.h>
#ಅನ್ತರ್ಭಾವ <unistd.h>
#ಅನ್ತರ್ಭಾವ <stdarg.h>
#ಅನ್ತರ್ಭಾವ <string.h>

#ಅನ್ತರ್ಭಾವ "ssh.h"
#ಅನ್ತರ್ಭಾವ "ssh_api.h"
#ಅನ್ತರ್ಭಾವ "hostfile.h"
#ಅನ್ತರ್ಭಾವ "auth.h"
#ಅನ್ತರ್ಭಾವ "auth-sia.h"
#ಅನ್ತರ್ಭಾವ "log.h"
#ಅನ್ತರ್ಭಾವ "servconf.h"
#ಅನ್ತರ್ಭಾವ "canohost.h"
#ಅನ್ತರ್ಭಾವ "uidswap.h"

ಬಾಹ್ಯ ServerOptions options;
ಬಾಹ್ಯ ಪೂರ್ಣಾಙ್ಕ saved_argc;
ಬಾಹ್ಯ ವರ್ಣ **saved_argv;

ಪೂರ್ಣಾಙ್ಕ
sys_auth_passwd(ಸಂರಚನಾ ssh *ssh, ಧ್ರುವ ವರ್ಣ *pass)
{
	ಪೂರ್ಣಾಙ್ಕ ret;
	SIAENTITY *ent = ರಿಕ್ತ;
	ಧ್ರುವ ವರ್ಣ *host;
	Authctxt *authctxt = ssh->authctxt;

	host = get_canonical_hostname(options.use_dns);

	ಯದಿ (!authctxt->user || pass == ರಿಕ್ತ || pass[0] == '\0')
		ಪ್ರತ್ಯಾಗಮ (0);

	ಯದಿ (sia_ses_init(&ent, saved_argc, saved_argv, host, authctxt->user,
	    ರಿಕ್ತ, 0, ರಿಕ್ತ) != SIASUCCESS)
		ಪ್ರತ್ಯಾಗಮ (0);

	ಯದಿ ((ret = sia_ses_authent(ರಿಕ್ತ, pass, ent)) != SIASUCCESS) {
		error("Couldn't authenticate %s from %s",
		    authctxt->user, host);
		ಯದಿ (ret & SIASTOP)
			sia_ses_release(&ent);

		ಪ್ರತ್ಯಾಗಮ (0);
	}

	sia_ses_release(&ent);

	ಪ್ರತ್ಯಾಗಮ (1);
}

ಶೂನ್ಯ
session_setup_sia(ಸಂರಚನಾ passwd *pw, ವರ್ಣ *tty)
{
	SIAENTITY *ent = ರಿಕ್ತ;
	ಧ್ರುವ ವರ್ಣ *host;

	host = get_canonical_hostname(options.use_dns);

	ಯದಿ (sia_ses_init(&ent, saved_argc, saved_argv, host, pw->pw_name,
	    tty, 0, ರಿಕ್ತ) != SIASUCCESS)
		fatal("sia_ses_init failed");

	ಯದಿ (sia_make_entity_pwd(pw, ent) != SIASUCCESS) {
		sia_ses_release(&ent);
		fatal("sia_make_entity_pwd failed");
	}

	ent->authtype = SIA_A_NONE;
	ಯದಿ (sia_ses_estab(sia_collect_trm, ent) != SIASUCCESS)
		fatal("Couldn't establish session for %s from %s",
		    pw->pw_name, host);

	ಯದಿ (sia_ses_launch(sia_collect_trm, ent) != SIASUCCESS)
		fatal("Couldn't launch session for %s from %s",
		    pw->pw_name, host);

	sia_ses_release(&ent);

	setuid(0);
	permanently_set_uid(pw);
}

#endif /* HAVE_OSF_SIA */
