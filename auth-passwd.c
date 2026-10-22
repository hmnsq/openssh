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

#समावेश "includes.h"

#समावेश <sys/types.h>

#समावेश <pwd.h>
#समावेश <stdio.h>
#समावेश <string.h>
#समावेश <stdarg.h>

#समावेश "packet.h"
#समावेश "sshbuf.h"
#समावेश "ssherr.h"
#समावेश "log.h"
#समावेश "misc.h"
#समावेश "servconf.h"
#समावेश "sshkey.h"
#समावेश "hostfile.h"
#समावेश "auth.h"
#समावेश "auth-options.h"

बाह्य काष्ठा sshbuf *loginmsg;
बाह्य ServerOptions options;

#अगर_घोषित HAVE_LOGIN_CAP
बाह्य login_cap_t *lc;
#पूर्ण_अगर


#घोषणा DAY		(24L * 60 * 60) /* 1 day in seconds */
#घोषणा TWO_WEEKS	(2L * 7 * DAY)	/* 2 weeks in seconds */

#घोषणा MAX_PASSWORD_LEN	1024

/*
 * Tries to authenticate the user using password.  Returns true if
 * authentication succeeds.
 */
पूर्णांक
auth_password(काष्ठा ssh *ssh, स्थिर अक्षर *password)
{
	Authctxt *authctxt = ssh->authctxt;
	काष्ठा passwd *pw = authctxt->pw;
	पूर्णांक परिणाम, ok = authctxt->valid;
#अगर defined(USE_SHADOW) && defined(HAS_SHADOW_EXPIRE)
	अटल पूर्णांक expire_checked = 0;
#पूर्ण_अगर

	अगर (म_माप(password) > MAX_PASSWORD_LEN)
		वापस 0;

#अगर_अघोषित HAVE_CYGWIN
	अगर (pw->pw_uid == 0 && options.permit_मूल_login != PERMIT_YES)
		ok = 0;
#पूर्ण_अगर
	अगर (*password == '\0' && options.permit_empty_passwd == 0)
		वापस 0;

#अगर_घोषित KRB5
	अगर (options.kerberos_authentication == 1) {
		पूर्णांक ret = auth_krb5_password(authctxt, password);
		अगर (ret == 1 || ret == 0)
			वापस ret && ok;
		/* Fall back to ordinary passwd authentication. */
	}
#पूर्ण_अगर
#अगर_घोषित HAVE_CYGWIN
	{
		HANDLE hToken = cygwin_logon_user(pw, password);

		अगर (hToken == INVALID_HANDLE_मूल्य)
			वापस 0;
		cygwin_set_impersonation_token(hToken);
		वापस ok;
	}
#पूर्ण_अगर
#अगर_घोषित USE_PAM
	अगर (options.use_pam)
		वापस (sshpam_auth_passwd(authctxt, password) && ok);
#पूर्ण_अगर
#अगर defined(USE_SHADOW) && defined(HAS_SHADOW_EXPIRE)
	अगर (!expire_checked) {
		expire_checked = 1;
		अगर (auth_shadow_pwexpired(authctxt))
			authctxt->force_pwchange = 1;
	}
#पूर्ण_अगर
	परिणाम = sys_auth_passwd(ssh, password);
	अगर (authctxt->force_pwchange)
		auth_restrict_session(ssh);
	वापस (परिणाम && ok);
}

#अगर_घोषित BSD_AUTH
अटल व्योम
warn_expiry(Authctxt *authctxt, auth_session_t *as)
{
	पूर्णांक r;
	int64_t pwtimeleft, actimeleft, daysleft, pwwarntime, acwarntime;

	pwwarntime = acwarntime = TWO_WEEKS;

	pwtimeleft = auth_check_change(as);
	actimeleft = auth_check_expire(as);
#अगर_घोषित HAVE_LOGIN_CAP
	अगर (authctxt->valid) {
		pwwarntime = login_getcaptime(lc, "password-warn", TWO_WEEKS,
		    TWO_WEEKS);
		acwarntime = login_getcaptime(lc, "expire-warn", TWO_WEEKS,
		    TWO_WEEKS);
	}
#पूर्ण_अगर
	अगर (pwtimeleft != 0 && pwtimeleft < pwwarntime) {
		daysleft = pwtimeleft / DAY + 1;
		अगर ((r = sshbuf_putf(loginmsg,
		    "Your password will expire in %lld day%s.\n",
		    daysleft, daysleft == 1 ? "" : "s")) != 0)
			fatal_fr(r, "buffer error");
	}
	अगर (actimeleft != 0 && actimeleft < acwarntime) {
		daysleft = actimeleft / DAY + 1;
		अगर ((r = sshbuf_putf(loginmsg,
		    "Your account will expire in %lld day%s.\n",
		    daysleft, daysleft == 1 ? "" : "s")) != 0)
			fatal_fr(r, "buffer error");
	}
}

पूर्णांक
sys_auth_passwd(काष्ठा ssh *ssh, स्थिर अक्षर *password)
{
	Authctxt *authctxt = ssh->authctxt;
	auth_session_t *as;
	अटल पूर्णांक expire_checked = 0;

	as = auth_usercheck(authctxt->pw->pw_name, authctxt->style, "auth-ssh",
	    (अक्षर *)password);
	अगर (as == शून्य)
		वापस (0);
	अगर (auth_getstate(as) & AUTH_PWEXPIRED) {
		auth_close(as);
		auth_restrict_session(ssh);
		authctxt->force_pwchange = 1;
		वापस (1);
	} अन्यथा {
		अगर (!expire_checked) {
			expire_checked = 1;
			warn_expiry(authctxt, as);
		}
		वापस (auth_close(as));
	}
}
#या_अगर !defined(CUSTOM_SYS_AUTH_PASSWD)
पूर्णांक
sys_auth_passwd(काष्ठा ssh *ssh, स्थिर अक्षर *password)
{
	Authctxt *authctxt = ssh->authctxt;
	काष्ठा passwd *pw = authctxt->pw;
	अक्षर *encrypted_password, *salt = शून्य;

	/* Just use the supplied fake password if authctxt is invalid */
	अक्षर *pw_password = authctxt->valid ? shadow_pw(pw) : pw->pw_passwd;

	अगर (pw_password == शून्य)
		वापस 0;

	/* Check for users with no password. */
	अगर (म_भेद(pw_password, "") == 0 && म_भेद(password, "") == 0)
		वापस (1);

	/*
	 * Encrypt the candidate password using the proper salt, or pass a
	 * NULL and let xcrypt pick one.
	 */
	अगर (authctxt->valid && pw_password[0] && pw_password[1])
		salt = pw_password;
	encrypted_password = xcrypt(password, salt);

	/*
	 * Authentication is accepted if the encrypted passwords
	 * are identical.
	 */
	वापस encrypted_password != शून्य &&
	    म_भेद(encrypted_password, pw_password) == 0;
}
#पूर्ण_अगर
