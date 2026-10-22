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

#ضمن "includes.h"

#ضمن <sys/types.h>

#ضمن <pwd.h>
#ضمن <stdio.h>
#ضمن <string.h>
#ضمن <stdarg.h>

#ضمن "packet.h"
#ضمن "sshbuf.h"
#ضمن "ssherr.h"
#ضمن "log.h"
#ضمن "misc.h"
#ضمن "servconf.h"
#ضمن "sshkey.h"
#ضمن "hostfile.h"
#ضمن "auth.h"
#ضمن "auth-options.h"

خارجي بنية sshbuf *loginmsg;
خارجي ServerOptions options;

#ifdef HAVE_LOGIN_CAP
خارجي login_cap_t *lc;
#endif


#define DAY		(24L * 60 * 60) /* 1 day in seconds */
#define TWO_WEEKS	(2L * 7 * DAY)	/* 2 weeks in seconds */

#define MAX_PASSWORD_LEN	1024

/*
 * Tries to authenticate the user using password.  Returns true if
 * authentication succeeds.
 */
صحيح
auth_password(بنية ssh *ssh, ثابت حرف *password)
{
	Authctxt *authctxt = ssh->authctxt;
	بنية passwd *pw = authctxt->pw;
	صحيح result, ok = authctxt->valid;
#𐤀𐤌 defined(USE_SHADOW) && defined(HAS_SHADOW_EXPIRE)
	ساكن صحيح expire_checked = 0;
#endif

	𐤀𐤌 (strlen(password) > MAX_PASSWORD_LEN)
		أرجع 0;

#ifndef HAVE_CYGWIN
	𐤀𐤌 (pw->pw_uid == 0 && options.permit_root_login != PERMIT_YES)
		ok = 0;
#endif
	𐤀𐤌 (*password == '\0' && options.permit_empty_passwd == 0)
		أرجع 0;

#ifdef KRB5
	𐤀𐤌 (options.kerberos_authentication == 1) {
		صحيح ret = auth_krb5_password(authctxt, password);
		𐤀𐤌 (ret == 1 || ret == 0)
			أرجع ret && ok;
		/* Fall back to ordinary passwd authentication. */
	}
#endif
#ifdef HAVE_CYGWIN
	{
		HANDLE hToken = cygwin_logon_user(pw, password);

		𐤀𐤌 (hToken == INVALID_HANDLE_VALUE)
			أرجع 0;
		cygwin_set_impersonation_token(hToken);
		أرجع ok;
	}
#endif
#ifdef USE_PAM
	𐤀𐤌 (options.use_pam)
		أرجع (sshpam_auth_passwd(authctxt, password) && ok);
#endif
#𐤀𐤌 defined(USE_SHADOW) && defined(HAS_SHADOW_EXPIRE)
	𐤀𐤌 (!expire_checked) {
		expire_checked = 1;
		𐤀𐤌 (auth_shadow_pwexpired(authctxt))
			authctxt->force_pwchange = 1;
	}
#endif
	result = sys_auth_passwd(ssh, password);
	𐤀𐤌 (authctxt->force_pwchange)
		auth_restrict_session(ssh);
	أرجع (result && ok);
}

#ifdef BSD_AUTH
ساكن فراغ
warn_expiry(Authctxt *authctxt, auth_session_t *as)
{
	صحيح r;
	int64_t pwtimeleft, actimeleft, daysleft, pwwarntime, acwarntime;

	pwwarntime = acwarntime = TWO_WEEKS;

	pwtimeleft = auth_check_change(as);
	actimeleft = auth_check_expire(as);
#ifdef HAVE_LOGIN_CAP
	𐤀𐤌 (authctxt->valid) {
		pwwarntime = login_getcaptime(lc, "password-warn", TWO_WEEKS,
		    TWO_WEEKS);
		acwarntime = login_getcaptime(lc, "expire-warn", TWO_WEEKS,
		    TWO_WEEKS);
	}
#endif
	𐤀𐤌 (pwtimeleft != 0 && pwtimeleft < pwwarntime) {
		daysleft = pwtimeleft / DAY + 1;
		𐤀𐤌 ((r = sshbuf_putf(loginmsg,
		    "Your password will expire in %lld day%s.\n",
		    daysleft, daysleft == 1 ? "" : "s")) != 0)
			fatal_fr(r, "buffer error");
	}
	𐤀𐤌 (actimeleft != 0 && actimeleft < acwarntime) {
		daysleft = actimeleft / DAY + 1;
		𐤀𐤌 ((r = sshbuf_putf(loginmsg,
		    "Your account will expire in %lld day%s.\n",
		    daysleft, daysleft == 1 ? "" : "s")) != 0)
			fatal_fr(r, "buffer error");
	}
}

صحيح
sys_auth_passwd(بنية ssh *ssh, ثابت حرف *password)
{
	Authctxt *authctxt = ssh->authctxt;
	auth_session_t *as;
	ساكن صحيح expire_checked = 0;

	as = auth_usercheck(authctxt->pw->pw_name, authctxt->style, "auth-ssh",
	    (حرف *)password);
	𐤀𐤌 (as == عدم)
		أرجع (0);
	𐤀𐤌 (auth_getstate(as) & AUTH_PWEXPIRED) {
		auth_close(as);
		auth_restrict_session(ssh);
		authctxt->force_pwchange = 1;
		أرجع (1);
	} وإلا {
		𐤀𐤌 (!expire_checked) {
			expire_checked = 1;
			warn_expiry(authctxt, as);
		}
		أرجع (auth_close(as));
	}
}
#وإلاإذا !defined(CUSTOM_SYS_AUTH_PASSWD)
صحيح
sys_auth_passwd(بنية ssh *ssh, ثابت حرف *password)
{
	Authctxt *authctxt = ssh->authctxt;
	بنية passwd *pw = authctxt->pw;
	حرف *encrypted_password, *salt = عدم;

	/* Just use the supplied fake password if authctxt is invalid */
	حرف *pw_password = authctxt->valid ? shadow_pw(pw) : pw->pw_passwd;

	𐤀𐤌 (pw_password == عدم)
		أرجع 0;

	/* Check for users with no password. */
	𐤀𐤌 (strcmp(pw_password, "") == 0 && strcmp(password, "") == 0)
		أرجع (1);

	/*
	 * Encrypt the candidate password using the proper salt, or pass a
	 * NULL and let xcrypt pick one.
	 */
	𐤀𐤌 (authctxt->valid && pw_password[0] && pw_password[1])
		salt = pw_password;
	encrypted_password = xcrypt(password, salt);

	/*
	 * Authentication is accepted if the encrypted passwords
	 * are identical.
	 */
	أرجع encrypted_password != عدم &&
	    strcmp(encrypted_password, pw_password) == 0;
}
#endif
