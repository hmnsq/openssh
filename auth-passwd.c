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

#അന്തര്ഭാവ "includes.h"

#അന്തര്ഭാവ <sys/types.h>

#അന്തര്ഭാവ <pwd.h>
#അന്തര്ഭാവ <stdio.h>
#അന്തര്ഭാവ <string.h>
#അന്തര്ഭാവ <stdarg.h>

#അന്തര്ഭാവ "packet.h"
#അന്തര്ഭാവ "sshbuf.h"
#അന്തര്ഭാവ "ssherr.h"
#അന്തര്ഭാവ "log.h"
#അന്തര്ഭാവ "misc.h"
#അന്തര്ഭാവ "servconf.h"
#അന്തര്ഭാവ "sshkey.h"
#അന്തര്ഭാവ "hostfile.h"
#അന്തര്ഭാവ "auth.h"
#അന്തര്ഭാവ "auth-options.h"

ബാഹ്യ ഘടന sshbuf *loginmsg;
ബാഹ്യ ServerOptions options;

#ifdef HAVE_LOGIN_CAP
ബാഹ്യ login_cap_t *lc;
#endif


#define DAY		(24L * 60 * 60) /* 1 day in seconds */
#define TWO_WEEKS	(2L * 7 * DAY)	/* 2 weeks in seconds */

#define MAX_PASSWORD_LEN	1024

/*
 * Tries to authenticate the user using password.  Returns true if
 * authentication succeeds.
 */
പൂർണ്ണസംഖ്യ
auth_password(ഘടന ssh *ssh, സ്ഥിരം അക്ഷരം *password)
{
	Authctxt *authctxt = ssh->authctxt;
	ഘടന passwd *pw = authctxt->pw;
	പൂർണ്ണസംഖ്യ result, ok = authctxt->valid;
#എങ്കിൽ defined(USE_SHADOW) && defined(HAS_SHADOW_EXPIRE)
	സ്ഥിതം പൂർണ്ണസംഖ്യ expire_checked = 0;
#endif

	എങ്കിൽ (strlen(password) > MAX_PASSWORD_LEN)
		തിരികെ 0;

#ifndef HAVE_CYGWIN
	എങ്കിൽ (pw->pw_uid == 0 && options.permit_വേര്_login != PERMIT_YES)
		ok = 0;
#endif
	എങ്കിൽ (*password == '\0' && options.permit_empty_passwd == 0)
		തിരികെ 0;

#ifdef KRB5
	എങ്കിൽ (options.kerberos_authentication == 1) {
		പൂർണ്ണസംഖ്യ ret = auth_krb5_password(authctxt, password);
		എങ്കിൽ (ret == 1 || ret == 0)
			തിരികെ ret && ok;
		/* Fall back to ordinary passwd authentication. */
	}
#endif
#ifdef HAVE_CYGWIN
	{
		HANDLE hToken = cygwin_logon_user(pw, password);

		എങ്കിൽ (hToken == INVALID_HANDLE_മൂല്യം)
			തിരികെ 0;
		cygwin_set_impersonation_token(hToken);
		തിരികെ ok;
	}
#endif
#ifdef USE_PAM
	എങ്കിൽ (options.use_pam)
		തിരികെ (sshpam_auth_passwd(authctxt, password) && ok);
#endif
#എങ്കിൽ defined(USE_SHADOW) && defined(HAS_SHADOW_EXPIRE)
	എങ്കിൽ (!expire_checked) {
		expire_checked = 1;
		എങ്കിൽ (auth_shadow_pwexpired(authctxt))
			authctxt->force_pwchange = 1;
	}
#endif
	result = sys_auth_passwd(ssh, password);
	എങ്കിൽ (authctxt->force_pwchange)
		auth_restrict_session(ssh);
	തിരികെ (result && ok);
}

#ifdef BSD_AUTH
സ്ഥിതം ശൂന്യം
warn_expiry(Authctxt *authctxt, auth_session_t *as)
{
	പൂർണ്ണസംഖ്യ r;
	int64_t pwtimeleft, actimeleft, daysleft, pwwarntime, acwarntime;

	pwwarntime = acwarntime = TWO_WEEKS;

	pwtimeleft = auth_check_change(as);
	actimeleft = auth_check_expire(as);
#ifdef HAVE_LOGIN_CAP
	എങ്കിൽ (authctxt->valid) {
		pwwarntime = login_getcaptime(lc, "password-warn", TWO_WEEKS,
		    TWO_WEEKS);
		acwarntime = login_getcaptime(lc, "expire-warn", TWO_WEEKS,
		    TWO_WEEKS);
	}
#endif
	എങ്കിൽ (pwtimeleft != 0 && pwtimeleft < pwwarntime) {
		daysleft = pwtimeleft / DAY + 1;
		എങ്കിൽ ((r = sshbuf_putf(loginmsg,
		    "Your password will expire in %lld day%s.\n",
		    daysleft, daysleft == 1 ? "" : "s")) != 0)
			fatal_fr(r, "buffer error");
	}
	എങ്കിൽ (actimeleft != 0 && actimeleft < acwarntime) {
		daysleft = actimeleft / DAY + 1;
		എങ്കിൽ ((r = sshbuf_putf(loginmsg,
		    "Your account will expire in %lld day%s.\n",
		    daysleft, daysleft == 1 ? "" : "s")) != 0)
			fatal_fr(r, "buffer error");
	}
}

പൂർണ്ണസംഖ്യ
sys_auth_passwd(ഘടന ssh *ssh, സ്ഥിരം അക്ഷരം *password)
{
	Authctxt *authctxt = ssh->authctxt;
	auth_session_t *as;
	സ്ഥിതം പൂർണ്ണസംഖ്യ expire_checked = 0;

	as = auth_usercheck(authctxt->pw->pw_name, authctxt->style, "auth-ssh",
	    (അക്ഷരം *)password);
	എങ്കിൽ (as == ശൂന്യ)
		തിരികെ (0);
	എങ്കിൽ (auth_getstate(as) & AUTH_PWEXPIRED) {
		auth_close(as);
		auth_restrict_session(ssh);
		authctxt->force_pwchange = 1;
		തിരികെ (1);
	} അല്ലെങ്കിൽ {
		എങ്കിൽ (!expire_checked) {
			expire_checked = 1;
			warn_expiry(authctxt, as);
		}
		തിരികെ (auth_close(as));
	}
}
#അല്ലെങ്കിലെങ്കിൽ !defined(CUSTOM_SYS_AUTH_PASSWD)
പൂർണ്ണസംഖ്യ
sys_auth_passwd(ഘടന ssh *ssh, സ്ഥിരം അക്ഷരം *password)
{
	Authctxt *authctxt = ssh->authctxt;
	ഘടന passwd *pw = authctxt->pw;
	അക്ഷരം *encrypted_password, *salt = ശൂന്യ;

	/* Just use the supplied fake password if authctxt is invalid */
	അക്ഷരം *pw_password = authctxt->valid ? shadow_pw(pw) : pw->pw_passwd;

	എങ്കിൽ (pw_password == ശൂന്യ)
		തിരികെ 0;

	/* Check for users with no password. */
	എങ്കിൽ (strcmp(pw_password, "") == 0 && strcmp(password, "") == 0)
		തിരികെ (1);

	/*
	 * Encrypt the candidate password using the proper salt, or pass a
	 * NULL and let xcrypt pick one.
	 */
	എങ്കിൽ (authctxt->valid && pw_password[0] && pw_password[1])
		salt = pw_password;
	encrypted_password = xcrypt(password, salt);

	/*
	 * Authentication is accepted if the encrypted passwords
	 * are identical.
	 */
	തിരികെ encrypted_password != ശൂന്യ &&
	    strcmp(encrypted_password, pw_password) == 0;
}
#endif
