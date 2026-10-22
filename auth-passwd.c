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

#अन्तर्भाव "includes.h"

#अन्तर्भाव <sys/types.h>

#अन्तर्भाव <pwd.h>
#अन्तर्भाव <stdio.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <stdarg.h>

#अन्तर्भाव "packet.h"
#अन्तर्भाव "sshbuf.h"
#अन्तर्भाव "ssherr.h"
#अन्तर्भाव "log.h"
#अन्तर्भाव "misc.h"
#अन्तर्भाव "servconf.h"
#अन्तर्भाव "sshkey.h"
#अन्तर्भाव "hostfile.h"
#अन्तर्भाव "auth.h"
#अन्तर्भाव "auth-options.h"

बाह्य संरचना sshbuf *loginmsg;
बाह्य ServerOptions options;

#ifdef HAVE_LOGIN_CAP
बाह्य login_cap_t *lc;
#endif


#define DAY		(24L * 60 * 60) /* 1 day in seconds */
#define TWO_WEEKS	(2L * 7 * DAY)	/* 2 weeks in seconds */

#define MAX_PASSWORD_LEN	1024

/*
 * Tries to authenticate the user using password.  Returns true if
 * authentication succeeds.
 */
पूर्णांक
auth_password(संरचना ssh *ssh, स्थिरांक अक्षर *password)
{
	Authctxt *authctxt = ssh->authctxt;
	संरचना passwd *pw = authctxt->pw;
	पूर्णांक result, ok = authctxt->valid;
#जर defined(USE_SHADOW) && defined(HAS_SHADOW_EXPIRE)
	स्थिर पूर्णांक expire_checked = 0;
#endif

	जर (म_माप(password) > MAX_PASSWORD_LEN)
		परत 0;

#ifndef HAVE_CYGWIN
	जर (pw->pw_uid == 0 && options.permit_मूळ_login != PERMIT_YES)
		ok = 0;
#endif
	जर (*password == '\0' && options.permit_empty_passwd == 0)
		परत 0;

#ifdef KRB5
	जर (options.kerberos_authentication == 1) {
		पूर्णांक ret = auth_krb5_password(authctxt, password);
		जर (ret == 1 || ret == 0)
			परत ret && ok;
		/* Fall back to ordinary passwd authentication. */
	}
#endif
#ifdef HAVE_CYGWIN
	{
		HANDLE hToken = cygwin_logon_user(pw, password);

		जर (hToken == INVALID_HANDLE_मूल्य)
			परत 0;
		cygwin_set_impersonation_token(hToken);
		परत ok;
	}
#endif
#ifdef USE_PAM
	जर (options.use_pam)
		परत (sshpam_auth_passwd(authctxt, password) && ok);
#endif
#जर defined(USE_SHADOW) && defined(HAS_SHADOW_EXPIRE)
	जर (!expire_checked) {
		expire_checked = 1;
		जर (auth_shadow_pwexpired(authctxt))
			authctxt->force_pwchange = 1;
	}
#endif
	result = sys_auth_passwd(ssh, password);
	जर (authctxt->force_pwchange)
		auth_restrict_session(ssh);
	परत (result && ok);
}

#ifdef BSD_AUTH
स्थिर शून्य
warn_expiry(Authctxt *authctxt, auth_session_t *as)
{
	पूर्णांक r;
	int64_t pwtimeleft, actimeleft, daysleft, pwwarntime, acwarntime;

	pwwarntime = acwarntime = TWO_WEEKS;

	pwtimeleft = auth_check_change(as);
	actimeleft = auth_check_expire(as);
#ifdef HAVE_LOGIN_CAP
	जर (authctxt->valid) {
		pwwarntime = login_getcaptime(lc, "password-warn", TWO_WEEKS,
		    TWO_WEEKS);
		acwarntime = login_getcaptime(lc, "expire-warn", TWO_WEEKS,
		    TWO_WEEKS);
	}
#endif
	जर (pwtimeleft != 0 && pwtimeleft < pwwarntime) {
		daysleft = pwtimeleft / DAY + 1;
		जर ((r = sshbuf_putf(loginmsg,
		    "Your password will expire in %lld day%s.\n",
		    daysleft, daysleft == 1 ? "" : "s")) != 0)
			fatal_fr(r, "buffer error");
	}
	जर (actimeleft != 0 && actimeleft < acwarntime) {
		daysleft = actimeleft / DAY + 1;
		जर ((r = sshbuf_putf(loginmsg,
		    "Your account will expire in %lld day%s.\n",
		    daysleft, daysleft == 1 ? "" : "s")) != 0)
			fatal_fr(r, "buffer error");
	}
}

पूर्णांक
sys_auth_passwd(संरचना ssh *ssh, स्थिरांक अक्षर *password)
{
	Authctxt *authctxt = ssh->authctxt;
	auth_session_t *as;
	स्थिर पूर्णांक expire_checked = 0;

	as = auth_usercheck(authctxt->pw->pw_name, authctxt->style, "auth-ssh",
	    (अक्षर *)password);
	जर (as == रिक्त)
		परत (0);
	जर (auth_getstate(as) & AUTH_PWEXPIRED) {
		auth_close(as);
		auth_restrict_session(ssh);
		authctxt->force_pwchange = 1;
		परत (1);
	} अन्यथा {
		जर (!expire_checked) {
			expire_checked = 1;
			warn_expiry(authctxt, as);
		}
		परत (auth_close(as));
	}
}
#किंवाजर !defined(CUSTOM_SYS_AUTH_PASSWD)
पूर्णांक
sys_auth_passwd(संरचना ssh *ssh, स्थिरांक अक्षर *password)
{
	Authctxt *authctxt = ssh->authctxt;
	संरचना passwd *pw = authctxt->pw;
	अक्षर *encrypted_password, *salt = रिक्त;

	/* Just use the supplied fake password if authctxt is invalid */
	अक्षर *pw_password = authctxt->valid ? shadow_pw(pw) : pw->pw_passwd;

	जर (pw_password == रिक्त)
		परत 0;

	/* Check for users with no password. */
	जर (म_भेद(pw_password, "") == 0 && म_भेद(password, "") == 0)
		परत (1);

	/*
	 * Encrypt the candidate password using the proper salt, or pass a
	 * NULL and let xcrypt pick one.
	 */
	जर (authctxt->valid && pw_password[0] && pw_password[1])
		salt = pw_password;
	encrypted_password = xcrypt(password, salt);

	/*
	 * Authentication is accepted if the encrypted passwords
	 * are identical.
	 */
	परत encrypted_password != रिक्त &&
	    म_भेद(encrypted_password, pw_password) == 0;
}
#endif
