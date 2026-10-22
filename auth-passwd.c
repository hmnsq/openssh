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

#અન્તર્ભાવ "includes.h"

#અન્તર્ભાવ <sys/types.h>

#અન્તર્ભાવ <pwd.h>
#અન્તર્ભાવ <stdio.h>
#અન્તર્ભાવ <string.h>
#અન્તર્ભાવ <stdarg.h>

#અન્તર્ભાવ "packet.h"
#અન્તર્ભાવ "sshbuf.h"
#અન્તર્ભાવ "ssherr.h"
#અન્તર્ભાવ "log.h"
#અન્તર્ભાવ "misc.h"
#અન્તર્ભાવ "servconf.h"
#અન્તર્ભાવ "sshkey.h"
#અન્તર્ભાવ "hostfile.h"
#અન્તર્ભાવ "auth.h"
#અન્તર્ભાવ "auth-options.h"

બાહ્ય સંરચના sshbuf *loginmsg;
બાહ્ય ServerOptions options;

#ifdef HAVE_LOGIN_CAP
બાહ્ય login_cap_t *lc;
#endif


#define DAY		(24L * 60 * 60) /* 1 day in seconds */
#define TWO_WEEKS	(2L * 7 * DAY)	/* 2 weeks in seconds */

#define MAX_PASSWORD_LEN	1024

/*
 * Tries to authenticate the user using password.  Returns true if
 * authentication succeeds.
 */
પૂર્ણાંક
auth_password(સંરચના ssh *ssh, અચલ અક્ષર *password)
{
	Authctxt *authctxt = ssh->authctxt;
	સંરચના passwd *pw = authctxt->pw;
	પૂર્ણાંક result, ok = authctxt->valid;
#જો defined(USE_SHADOW) && defined(HAS_SHADOW_EXPIRE)
	સ્થિર પૂર્ણાંક expire_checked = 0;
#endif

	જો (strlen(password) > MAX_PASSWORD_LEN)
		પાછા 0;

#ifndef HAVE_CYGWIN
	જો (pw->pw_uid == 0 && options.permit_મૂળ_login != PERMIT_YES)
		ok = 0;
#endif
	જો (*password == '\0' && options.permit_empty_passwd == 0)
		પાછા 0;

#ifdef KRB5
	જો (options.kerberos_authentication == 1) {
		પૂર્ણાંક ret = auth_krb5_password(authctxt, password);
		જો (ret == 1 || ret == 0)
			પાછા ret && ok;
		/* Fall back to ordinary passwd authentication. */
	}
#endif
#ifdef HAVE_CYGWIN
	{
		HANDLE hToken = cygwin_logon_user(pw, password);

		જો (hToken == INVALID_HANDLE_કિંમત)
			પાછા 0;
		cygwin_set_impersonation_token(hToken);
		પાછા ok;
	}
#endif
#ifdef USE_PAM
	જો (options.use_pam)
		પાછા (sshpam_auth_passwd(authctxt, password) && ok);
#endif
#જો defined(USE_SHADOW) && defined(HAS_SHADOW_EXPIRE)
	જો (!expire_checked) {
		expire_checked = 1;
		જો (auth_shadow_pwexpired(authctxt))
			authctxt->force_pwchange = 1;
	}
#endif
	result = sys_auth_passwd(ssh, password);
	જો (authctxt->force_pwchange)
		auth_restrict_session(ssh);
	પાછા (result && ok);
}

#ifdef BSD_AUTH
સ્થિર શૂન્ય
warn_expiry(Authctxt *authctxt, auth_session_t *as)
{
	પૂર્ણાંક r;
	int64_t pwtimeleft, actimeleft, daysleft, pwwarntime, acwarntime;

	pwwarntime = acwarntime = TWO_WEEKS;

	pwtimeleft = auth_check_change(as);
	actimeleft = auth_check_expire(as);
#ifdef HAVE_LOGIN_CAP
	જો (authctxt->valid) {
		pwwarntime = login_getcaptime(lc, "password-warn", TWO_WEEKS,
		    TWO_WEEKS);
		acwarntime = login_getcaptime(lc, "expire-warn", TWO_WEEKS,
		    TWO_WEEKS);
	}
#endif
	જો (pwtimeleft != 0 && pwtimeleft < pwwarntime) {
		daysleft = pwtimeleft / DAY + 1;
		જો ((r = sshbuf_putf(loginmsg,
		    "Your password will expire in %lld day%s.\n",
		    daysleft, daysleft == 1 ? "" : "s")) != 0)
			fatal_fr(r, "buffer error");
	}
	જો (actimeleft != 0 && actimeleft < acwarntime) {
		daysleft = actimeleft / DAY + 1;
		જો ((r = sshbuf_putf(loginmsg,
		    "Your account will expire in %lld day%s.\n",
		    daysleft, daysleft == 1 ? "" : "s")) != 0)
			fatal_fr(r, "buffer error");
	}
}

પૂર્ણાંક
sys_auth_passwd(સંરચના ssh *ssh, અચલ અક્ષર *password)
{
	Authctxt *authctxt = ssh->authctxt;
	auth_session_t *as;
	સ્થિર પૂર્ણાંક expire_checked = 0;

	as = auth_usercheck(authctxt->pw->pw_name, authctxt->style, "auth-ssh",
	    (અક્ષર *)password);
	જો (as == ખાલી)
		પાછા (0);
	જો (auth_getstate(as) & AUTH_PWEXPIRED) {
		auth_close(as);
		auth_restrict_session(ssh);
		authctxt->force_pwchange = 1;
		પાછા (1);
	} નહીંતર {
		જો (!expire_checked) {
			expire_checked = 1;
			warn_expiry(authctxt, as);
		}
		પાછા (auth_close(as));
	}
}
#અથવાજો !defined(CUSTOM_SYS_AUTH_PASSWD)
પૂર્ણાંક
sys_auth_passwd(સંરચના ssh *ssh, અચલ અક્ષર *password)
{
	Authctxt *authctxt = ssh->authctxt;
	સંરચના passwd *pw = authctxt->pw;
	અક્ષર *encrypted_password, *salt = ખાલી;

	/* Just use the supplied fake password if authctxt is invalid */
	અક્ષર *pw_password = authctxt->valid ? shadow_pw(pw) : pw->pw_passwd;

	જો (pw_password == ખાલી)
		પાછા 0;

	/* Check for users with no password. */
	જો (strcmp(pw_password, "") == 0 && strcmp(password, "") == 0)
		પાછા (1);

	/*
	 * Encrypt the candidate password using the proper salt, or pass a
	 * NULL and let xcrypt pick one.
	 */
	જો (authctxt->valid && pw_password[0] && pw_password[1])
		salt = pw_password;
	encrypted_password = xcrypt(password, salt);

	/*
	 * Authentication is accepted if the encrypted passwords
	 * are identical.
	 */
	પાછા encrypted_password != ખાલી &&
	    strcmp(encrypted_password, pw_password) == 0;
}
#endif
