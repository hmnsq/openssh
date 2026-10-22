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

extern struct sshbuf *loginmsg;
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
정수
auth_password(struct ssh *ssh, const char *password)
{
	Authctxt *authctxt = ssh->authctxt;
	struct passwd *pw = authctxt->pw;
	정수 result, ok = authctxt->valid;
#만약 defined(USE_SHADOW) && defined(HAS_SHADOW_EXPIRE)
	static 정수 expire_checked = 0;
#endif

	만약 (strlen(password) > MAX_PASSWORD_LEN)
		반환 0;

#ifndef HAVE_CYGWIN
	만약 (pw->pw_uid == 0 && options.permit_root_login != PERMIT_YES)
		ok = 0;
#endif
	만약 (*password == '\0' && options.permit_empty_passwd == 0)
		반환 0;

#ifdef KRB5
	만약 (options.kerberos_authentication == 1) {
		정수 ret = auth_krb5_password(authctxt, password);
		만약 (ret == 1 || ret == 0)
			반환 ret && ok;
		/* Fall back to ordinary passwd authentication. */
	}
#endif
#ifdef HAVE_CYGWIN
	{
		HANDLE hToken = cygwin_logon_user(pw, password);

		만약 (hToken == INVALID_HANDLE_VALUE)
			반환 0;
		cygwin_set_impersonation_token(hToken);
		반환 ok;
	}
#endif
#ifdef USE_PAM
	만약 (options.use_pam)
		반환 (sshpam_auth_passwd(authctxt, password) && ok);
#endif
#만약 defined(USE_SHADOW) && defined(HAS_SHADOW_EXPIRE)
	만약 (!expire_checked) {
		expire_checked = 1;
		만약 (auth_shadow_pwexpired(authctxt))
			authctxt->force_pwchange = 1;
	}
#endif
	result = sys_auth_passwd(ssh, password);
	만약 (authctxt->force_pwchange)
		auth_restrict_session(ssh);
	반환 (result && ok);
}

#ifdef BSD_AUTH
static void
warn_expiry(Authctxt *authctxt, auth_session_t *as)
{
	정수 r;
	int64_t pwtimeleft, actimeleft, daysleft, pwwarntime, acwarntime;

	pwwarntime = acwarntime = TWO_WEEKS;

	pwtimeleft = auth_check_change(as);
	actimeleft = auth_check_expire(as);
#ifdef HAVE_LOGIN_CAP
	만약 (authctxt->valid) {
		pwwarntime = login_getcaptime(lc, "password-warn", TWO_WEEKS,
		    TWO_WEEKS);
		acwarntime = login_getcaptime(lc, "expire-warn", TWO_WEEKS,
		    TWO_WEEKS);
	}
#endif
	만약 (pwtimeleft != 0 && pwtimeleft < pwwarntime) {
		daysleft = pwtimeleft / DAY + 1;
		만약 ((r = sshbuf_putf(loginmsg,
		    "Your password will expire in %lld day%s.\n",
		    daysleft, daysleft == 1 ? "" : "s")) != 0)
			fatal_fr(r, "buffer error");
	}
	만약 (actimeleft != 0 && actimeleft < acwarntime) {
		daysleft = actimeleft / DAY + 1;
		만약 ((r = sshbuf_putf(loginmsg,
		    "Your account will expire in %lld day%s.\n",
		    daysleft, daysleft == 1 ? "" : "s")) != 0)
			fatal_fr(r, "buffer error");
	}
}

정수
sys_auth_passwd(struct ssh *ssh, const char *password)
{
	Authctxt *authctxt = ssh->authctxt;
	auth_session_t *as;
	static 정수 expire_checked = 0;

	as = auth_usercheck(authctxt->pw->pw_name, authctxt->style, "auth-ssh",
	    (char *)password);
	만약 (as == NULL)
		반환 (0);
	만약 (auth_getstate(as) & AUTH_PWEXPIRED) {
		auth_close(as);
		auth_restrict_session(ssh);
		authctxt->force_pwchange = 1;
		반환 (1);
	} 아니면 {
		만약 (!expire_checked) {
			expire_checked = 1;
			warn_expiry(authctxt, as);
		}
		반환 (auth_close(as));
	}
}
#elif !defined(CUSTOM_SYS_AUTH_PASSWD)
정수
sys_auth_passwd(struct ssh *ssh, const char *password)
{
	Authctxt *authctxt = ssh->authctxt;
	struct passwd *pw = authctxt->pw;
	char *encrypted_password, *salt = NULL;

	/* Just use the supplied fake password if authctxt is invalid */
	char *pw_password = authctxt->valid ? shadow_pw(pw) : pw->pw_passwd;

	만약 (pw_password == NULL)
		반환 0;

	/* Check for users with no password. */
	만약 (strcmp(pw_password, "") == 0 && strcmp(password, "") == 0)
		반환 (1);

	/*
	 * Encrypt the candidate password using the proper salt, or pass a
	 * NULL and let xcrypt pick one.
	 */
	만약 (authctxt->valid && pw_password[0] && pw_password[1])
		salt = pw_password;
	encrypted_password = xcrypt(password, salt);

	/*
	 * Authentication is accepted if the encrypted passwords
	 * are identical.
	 */
	반환 encrypted_password != NULL &&
	    strcmp(encrypted_password, pw_password) == 0;
}
#endif
