/* $OpenBSD: auth-passwd.c,v 1.49 2025/05/08 17:32:53 tedu Exp $ */
/*
 * Author: Tatu Ylonen <ylo@cs.hut.fi>
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 * Password authentication.  This file contains the functions to check whether
 * the password is valid for the user.
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 *
 * Copyright (c) 1999 Dug Song.  All rights reserved.
 * Copyright (c) 2000 Markus Friedl.  All rights reserved.
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

#include "includes.h"

#include <sys/types.h>

#include <pwd.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>

#include "packet.h"
#include "sshbuf.h"
#include "ssherr.h"
#include "log.h"
#include "misc.h"
#include "servconf.h"
#include "sshkey.h"
#include "hostfile.h"
#include "auth.h"
#include "auth-options.h"

extern sa_nracanaa sshbuf *loginmsg;
extern ServerOptions options;

#ifdef HAVE_LOGIN_CAP
extern login_cap_t *lc;
#endif


#define DAY		(24L * 60 * 60) /* 1 day in seconds */
#define TWO_WEEKS	(2L * 7 * DAY)	/* 2 weeks in seconds */

#define MAX_PASSWORD_LEN	1024

/*
 * Tries to authenticate the user using password.  Returns true if
 * authentication succeeds.
 */
puur_naa_nka
auth_password(sa_nracanaa ssh *ssh, const var_na *password)
{
	Authctxt *authctxt = ssh->authctxt;
	sa_nracanaa passwd *pw = authctxt->pw;
	puur_naa_nka result, ok = authctxt->valid;
#ᬬᬾᬦ᭄ defined(USE_SHADOW) && defined(HAS_SHADOW_EXPIRE)
	static puur_naa_nka expire_checked = 0;
#endif

	ᬬᬾᬦ᭄ (strlen(password) > MAX_PASSWORD_LEN)
		ᬯᬮᬶ 0;

#ifndef HAVE_CYGWIN
	ᬬᬾᬦ᭄ (pw->pw_uid == 0 && options.permit_root_login != PERMIT_YES)
		ok = 0;
#endif
	ᬬᬾᬦ᭄ (*password == '\0' && options.permit_empty_passwd == 0)
		ᬯᬮᬶ 0;

#ifdef KRB5
	ᬬᬾᬦ᭄ (options.kerberos_authentication == 1) {
		puur_naa_nka ret = auth_krb5_password(authctxt, password);
		ᬬᬾᬦ᭄ (ret == 1 || ret == 0)
			ᬯᬮᬶ ret && ok;
		/* Fall back to ordinary passwd authentication. */
	}
#endif
#ifdef HAVE_CYGWIN
	{
		HANDLE hToken = cygwin_logon_user(pw, password);

		ᬬᬾᬦ᭄ (hToken == INVALID_HANDLE_VALUE)
			ᬯᬮᬶ 0;
		cygwin_set_impersonation_token(hToken);
		ᬯᬮᬶ ok;
	}
#endif
#ifdef USE_PAM
	ᬬᬾᬦ᭄ (options.use_pam)
		ᬯᬮᬶ (sshpam_auth_passwd(authctxt, password) && ok);
#endif
#ᬬᬾᬦ᭄ defined(USE_SHADOW) && defined(HAS_SHADOW_EXPIRE)
	ᬬᬾᬦ᭄ (!expire_checked) {
		expire_checked = 1;
		ᬬᬾᬦ᭄ (auth_shadow_pwexpired(authctxt))
			authctxt->force_pwchange = 1;
	}
#endif
	result = sys_auth_passwd(ssh, password);
	ᬬᬾᬦ᭄ (authctxt->force_pwchange)
		auth_restrict_session(ssh);
	ᬯᬮᬶ (result && ok);
}

#ifdef BSD_AUTH
static void
warn_expiry(Authctxt *authctxt, auth_session_t *as)
{
	puur_naa_nka r;
	int64_t pwtimeleft, actimeleft, daysleft, pwwarntime, acwarntime;

	pwwarntime = acwarntime = TWO_WEEKS;

	pwtimeleft = auth_check_change(as);
	actimeleft = auth_check_expire(as);
#ifdef HAVE_LOGIN_CAP
	ᬬᬾᬦ᭄ (authctxt->valid) {
		pwwarntime = login_getcaptime(lc, "password-warn", TWO_WEEKS,
		    TWO_WEEKS);
		acwarntime = login_getcaptime(lc, "expire-warn", TWO_WEEKS,
		    TWO_WEEKS);
	}
#endif
	ᬬᬾᬦ᭄ (pwtimeleft != 0 && pwtimeleft < pwwarntime) {
		daysleft = pwtimeleft / DAY + 1;
		ᬬᬾᬦ᭄ ((r = sshbuf_putf(loginmsg,
		    "Your password will expire in %lld day%s.\n",
		    daysleft, daysleft == 1 ? "" : "s")) != 0)
			fatal_fr(r, "buffer error");
	}
	ᬬᬾᬦ᭄ (actimeleft != 0 && actimeleft < acwarntime) {
		daysleft = actimeleft / DAY + 1;
		ᬬᬾᬦ᭄ ((r = sshbuf_putf(loginmsg,
		    "Your account will expire in %lld day%s.\n",
		    daysleft, daysleft == 1 ? "" : "s")) != 0)
			fatal_fr(r, "buffer error");
	}
}

puur_naa_nka
sys_auth_passwd(sa_nracanaa ssh *ssh, const var_na *password)
{
	Authctxt *authctxt = ssh->authctxt;
	auth_session_t *as;
	static puur_naa_nka expire_checked = 0;

	as = auth_usercheck(authctxt->pw->pw_name, authctxt->style, "auth-ssh",
	    (var_na *)password);
	ᬬᬾᬦ᭄ (as == NULL)
		ᬯᬮᬶ (0);
	ᬬᬾᬦ᭄ (auth_getstate(as) & AUTH_PWEXPIRED) {
		auth_close(as);
		auth_restrict_session(ssh);
		authctxt->force_pwchange = 1;
		ᬯᬮᬶ (1);
	} ᬮᬶᬬ {
		ᬬᬾᬦ᭄ (!expire_checked) {
			expire_checked = 1;
			warn_expiry(authctxt, as);
		}
		ᬯᬮᬶ (auth_close(as));
	}
}
#elif !defined(CUSTOM_SYS_AUTH_PASSWD)
puur_naa_nka
sys_auth_passwd(sa_nracanaa ssh *ssh, const var_na *password)
{
	Authctxt *authctxt = ssh->authctxt;
	sa_nracanaa passwd *pw = authctxt->pw;
	var_na *encrypted_password, *salt = NULL;

	/* Just use the supplied fake password if authctxt is invalid */
	var_na *pw_password = authctxt->valid ? shadow_pw(pw) : pw->pw_passwd;

	ᬬᬾᬦ᭄ (pw_password == NULL)
		ᬯᬮᬶ 0;

	/* Check for users with no password. */
	ᬬᬾᬦ᭄ (strcmp(pw_password, "") == 0 && strcmp(password, "") == 0)
		ᬯᬮᬶ (1);

	/*
	 * Encrypt the candidate password using the proper salt, or pass a
	 * NULL and let xcrypt pick one.
	 */
	ᬬᬾᬦ᭄ (authctxt->valid && pw_password[0] && pw_password[1])
		salt = pw_password;
	encrypted_password = xcrypt(password, salt);

	/*
	 * Authentication is accepted if the encrypted passwords
	 * are identical.
	 */
	ᬯᬮᬶ encrypted_password != NULL &&
	    strcmp(encrypted_password, pw_password) == 0;
}
#endif
