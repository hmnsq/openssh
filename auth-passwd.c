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

#অন্তর্ভাব "includes.h"

#অন্তর্ভাব <sys/types.h>

#অন্তর্ভাব <pwd.h>
#অন্তর্ভাব <stdio.h>
#অন্তর্ভাব <string.h>
#অন্তর্ভাব <stdarg.h>

#অন্তর্ভাব "packet.h"
#অন্তর্ভাব "sshbuf.h"
#অন্তর্ভাব "ssherr.h"
#অন্তর্ভাব "log.h"
#অন্তর্ভাব "misc.h"
#অন্তর্ভাব "servconf.h"
#অন্তর্ভাব "sshkey.h"
#অন্তর্ভাব "hostfile.h"
#অন্তর্ভাব "auth.h"
#অন্তর্ভাব "auth-options.h"

বাহ্য সংরচনা sshbuf *loginmsg;
বাহ্য ServerOptions options;

#ifdef HAVE_LOGIN_CAP
বাহ্য login_cap_t *lc;
#endif


#define DAY		(24L * 60 * 60) /* 1 day in seconds */
#define TWO_WEEKS	(2L * 7 * DAY)	/* 2 weeks in seconds */

#define MAX_PASSWORD_LEN	1024

/*
 * Tries to authenticate the user using password.  Returns true if
 * authentication succeeds.
 */
পূর্ণাঙ্ক
auth_password(সংরচনা ssh *ssh, ধ্রুব বর্ণ *password)
{
	Authctxt *authctxt = ssh->authctxt;
	সংরচনা passwd *pw = authctxt->pw;
	পূর্ণাঙ্ক result, ok = authctxt->valid;
#যদি defined(USE_SHADOW) && defined(HAS_SHADOW_EXPIRE)
	স্থির পূর্ণাঙ্ক expire_checked = 0;
#endif

	যদি (strlen(password) > MAX_PASSWORD_LEN)
		প্রত্যাগম 0;

#ifndef HAVE_CYGWIN
	যদি (pw->pw_uid == 0 && options.permit_মূল_login != PERMIT_YES)
		ok = 0;
#endif
	যদি (*password == '\0' && options.permit_empty_passwd == 0)
		প্রত্যাগম 0;

#ifdef KRB5
	যদি (options.kerberos_authentication == 1) {
		পূর্ণাঙ্ক ret = auth_krb5_password(authctxt, password);
		যদি (ret == 1 || ret == 0)
			প্রত্যাগম ret && ok;
		/* Fall back to ordinary passwd authentication. */
	}
#endif
#ifdef HAVE_CYGWIN
	{
		HANDLE hToken = cygwin_logon_user(pw, password);

		যদি (hToken == INVALID_HANDLE_মান)
			প্রত্যাগম 0;
		cygwin_set_impersonation_token(hToken);
		প্রত্যাগম ok;
	}
#endif
#ifdef USE_PAM
	যদি (options.use_pam)
		প্রত্যাগম (sshpam_auth_passwd(authctxt, password) && ok);
#endif
#যদি defined(USE_SHADOW) && defined(HAS_SHADOW_EXPIRE)
	যদি (!expire_checked) {
		expire_checked = 1;
		যদি (auth_shadow_pwexpired(authctxt))
			authctxt->force_pwchange = 1;
	}
#endif
	result = sys_auth_passwd(ssh, password);
	যদি (authctxt->force_pwchange)
		auth_restrict_session(ssh);
	প্রত্যাগম (result && ok);
}

#ifdef BSD_AUTH
স্থির শূন্য
warn_expiry(Authctxt *authctxt, auth_session_t *as)
{
	পূর্ণাঙ্ক r;
	int64_t pwtimeleft, actimeleft, daysleft, pwwarntime, acwarntime;

	pwwarntime = acwarntime = TWO_WEEKS;

	pwtimeleft = auth_check_change(as);
	actimeleft = auth_check_expire(as);
#ifdef HAVE_LOGIN_CAP
	যদি (authctxt->valid) {
		pwwarntime = login_getcaptime(lc, "password-warn", TWO_WEEKS,
		    TWO_WEEKS);
		acwarntime = login_getcaptime(lc, "expire-warn", TWO_WEEKS,
		    TWO_WEEKS);
	}
#endif
	যদি (pwtimeleft != 0 && pwtimeleft < pwwarntime) {
		daysleft = pwtimeleft / DAY + 1;
		যদি ((r = sshbuf_putf(loginmsg,
		    "Your password will expire in %lld day%s.\n",
		    daysleft, daysleft == 1 ? "" : "s")) != 0)
			fatal_fr(r, "buffer error");
	}
	যদি (actimeleft != 0 && actimeleft < acwarntime) {
		daysleft = actimeleft / DAY + 1;
		যদি ((r = sshbuf_putf(loginmsg,
		    "Your account will expire in %lld day%s.\n",
		    daysleft, daysleft == 1 ? "" : "s")) != 0)
			fatal_fr(r, "buffer error");
	}
}

পূর্ণাঙ্ক
sys_auth_passwd(সংরচনা ssh *ssh, ধ্রুব বর্ণ *password)
{
	Authctxt *authctxt = ssh->authctxt;
	auth_session_t *as;
	স্থির পূর্ণাঙ্ক expire_checked = 0;

	as = auth_usercheck(authctxt->pw->pw_name, authctxt->style, "auth-ssh",
	    (বর্ণ *)password);
	যদি (as == রিক্ত)
		প্রত্যাগম (0);
	যদি (auth_getstate(as) & AUTH_PWEXPIRED) {
		auth_close(as);
		auth_restrict_session(ssh);
		authctxt->force_pwchange = 1;
		প্রত্যাগম (1);
	} অন্যথা {
		যদি (!expire_checked) {
			expire_checked = 1;
			warn_expiry(authctxt, as);
		}
		প্রত্যাগম (auth_close(as));
	}
}
#নোচেদ্যদি !defined(CUSTOM_SYS_AUTH_PASSWD)
পূর্ণাঙ্ক
sys_auth_passwd(সংরচনা ssh *ssh, ধ্রুব বর্ণ *password)
{
	Authctxt *authctxt = ssh->authctxt;
	সংরচনা passwd *pw = authctxt->pw;
	বর্ণ *encrypted_password, *salt = রিক্ত;

	/* Just use the supplied fake password if authctxt is invalid */
	বর্ণ *pw_password = authctxt->valid ? shadow_pw(pw) : pw->pw_passwd;

	যদি (pw_password == রিক্ত)
		প্রত্যাগম 0;

	/* Check for users with no password. */
	যদি (strcmp(pw_password, "") == 0 && strcmp(password, "") == 0)
		প্রত্যাগম (1);

	/*
	 * Encrypt the candidate password using the proper salt, or pass a
	 * NULL and let xcrypt pick one.
	 */
	যদি (authctxt->valid && pw_password[0] && pw_password[1])
		salt = pw_password;
	encrypted_password = xcrypt(password, salt);

	/*
	 * Authentication is accepted if the encrypted passwords
	 * are identical.
	 */
	প্রত্যাগম encrypted_password != রিক্ত &&
	    strcmp(encrypted_password, pw_password) == 0;
}
#endif
