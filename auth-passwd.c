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

#شامل "includes.h"

#شامل <sys/types.h>

#شامل <pwd.h>
#شامل <stdio.h>
#شامل <string.h>
#شامل <stdarg.h>

#شامل "packet.h"
#شامل "sshbuf.h"
#شامل "ssherr.h"
#شامل "log.h"
#شامل "misc.h"
#شامل "servconf.h"
#شامل "sshkey.h"
#شامل "hostfile.h"
#شامل "auth.h"
#شامل "auth-options.h"

بیرونی ساختار sshbuf *loginmsg;
بیرونی ServerOptions options;

#ifdef HAVE_LOGIN_CAP
بیرونی login_cap_t *lc;
#endif


#define DAY		(24L * 60 * 60) /* 1 day in seconds */
#define TWO_WEEKS	(2L * 7 * DAY)	/* 2 weeks in seconds */

#define MAX_PASSWORD_LEN	1024

/*
 * Tries to authenticate the user using password.  Returns true if
 * authentication succeeds.
 */
صحیح
auth_password(ساختار ssh *ssh, ثابت نویسه *password)
{
	Authctxt *authctxt = ssh->authctxt;
	ساختار passwd *pw = authctxt->pw;
	صحیح result, ok = authctxt->valid;
#اگر defined(USE_SHADOW) && defined(HAS_SHADOW_EXPIRE)
	ایستا صحیح expire_checked = 0;
#endif

	اگر (strlen(password) > MAX_PASSWORD_LEN)
		بازگشت 0;

#ifndef HAVE_CYGWIN
	اگر (pw->pw_uid == 0 && options.permit_ریشه_login != PERMIT_YES)
		ok = 0;
#endif
	اگر (*password == '\0' && options.permit_empty_passwd == 0)
		بازگشت 0;

#ifdef KRB5
	اگر (options.kerberos_authentication == 1) {
		صحیح ret = auth_krb5_password(authctxt, password);
		اگر (ret == 1 || ret == 0)
			بازگشت ret && ok;
		/* Fall back to ordinary passwd authentication. */
	}
#endif
#ifdef HAVE_CYGWIN
	{
		HANDLE hToken = cygwin_logon_user(pw, password);

		اگر (hToken == INVALID_HANDLE_مقدار)
			بازگشت 0;
		cygwin_set_impersonation_token(hToken);
		بازگشت ok;
	}
#endif
#ifdef USE_PAM
	اگر (options.use_pam)
		بازگشت (sshpam_auth_passwd(authctxt, password) && ok);
#endif
#اگر defined(USE_SHADOW) && defined(HAS_SHADOW_EXPIRE)
	اگر (!expire_checked) {
		expire_checked = 1;
		اگر (auth_shadow_pwexpired(authctxt))
			authctxt->force_pwchange = 1;
	}
#endif
	result = sys_auth_passwd(ssh, password);
	اگر (authctxt->force_pwchange)
		auth_restrict_session(ssh);
	بازگشت (result && ok);
}

#ifdef BSD_AUTH
ایستا تهی
warn_expiry(Authctxt *authctxt, auth_session_t *as)
{
	صحیح r;
	int64_t pwtimeleft, actimeleft, daysleft, pwwarntime, acwarntime;

	pwwarntime = acwarntime = TWO_WEEKS;

	pwtimeleft = auth_check_change(as);
	actimeleft = auth_check_expire(as);
#ifdef HAVE_LOGIN_CAP
	اگر (authctxt->valid) {
		pwwarntime = login_getcaptime(lc, "password-warn", TWO_WEEKS,
		    TWO_WEEKS);
		acwarntime = login_getcaptime(lc, "expire-warn", TWO_WEEKS,
		    TWO_WEEKS);
	}
#endif
	اگر (pwtimeleft != 0 && pwtimeleft < pwwarntime) {
		daysleft = pwtimeleft / DAY + 1;
		اگر ((r = sshbuf_putf(loginmsg,
		    "Your password will expire in %lld day%s.\n",
		    daysleft, daysleft == 1 ? "" : "s")) != 0)
			fatal_fr(r, "buffer error");
	}
	اگر (actimeleft != 0 && actimeleft < acwarntime) {
		daysleft = actimeleft / DAY + 1;
		اگر ((r = sshbuf_putf(loginmsg,
		    "Your account will expire in %lld day%s.\n",
		    daysleft, daysleft == 1 ? "" : "s")) != 0)
			fatal_fr(r, "buffer error");
	}
}

صحیح
sys_auth_passwd(ساختار ssh *ssh, ثابت نویسه *password)
{
	Authctxt *authctxt = ssh->authctxt;
	auth_session_t *as;
	ایستا صحیح expire_checked = 0;

	as = auth_usercheck(authctxt->pw->pw_name, authctxt->style, "auth-ssh",
	    (نویسه *)password);
	اگر (as == پوچ)
		بازگشت (0);
	اگر (auth_getstate(as) & AUTH_PWEXPIRED) {
		auth_close(as);
		auth_restrict_session(ssh);
		authctxt->force_pwchange = 1;
		بازگشت (1);
	} وگرنه {
		اگر (!expire_checked) {
			expire_checked = 1;
			warn_expiry(authctxt, as);
		}
		بازگشت (auth_close(as));
	}
}
#وگرنهاگر !defined(CUSTOM_SYS_AUTH_PASSWD)
صحیح
sys_auth_passwd(ساختار ssh *ssh, ثابت نویسه *password)
{
	Authctxt *authctxt = ssh->authctxt;
	ساختار passwd *pw = authctxt->pw;
	نویسه *encrypted_password, *salt = پوچ;

	/* Just use the supplied fake password if authctxt is invalid */
	نویسه *pw_password = authctxt->valid ? shadow_pw(pw) : pw->pw_passwd;

	اگر (pw_password == پوچ)
		بازگشت 0;

	/* Check for users with no password. */
	اگر (strcmp(pw_password, "") == 0 && strcmp(password, "") == 0)
		بازگشت (1);

	/*
	 * Encrypt the candidate password using the proper salt, or pass a
	 * NULL and let xcrypt pick one.
	 */
	اگر (authctxt->valid && pw_password[0] && pw_password[1])
		salt = pw_password;
	encrypted_password = xcrypt(password, salt);

	/*
	 * Authentication is accepted if the encrypted passwords
	 * are identical.
	 */
	بازگشت encrypted_password != پوچ &&
	    strcmp(encrypted_password, pw_password) == 0;
}
#endif
