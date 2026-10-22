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

#అన్తర్భావ "includes.h"

#అన్తర్భావ <sys/types.h>

#అన్తర్భావ <pwd.h>
#అన్తర్భావ <stdio.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <stdarg.h>

#అన్తర్భావ "packet.h"
#అన్తర్భావ "sshbuf.h"
#అన్తర్భావ "ssherr.h"
#అన్తర్భావ "log.h"
#అన్తర్భావ "misc.h"
#అన్తర్భావ "servconf.h"
#అన్తర్భావ "sshkey.h"
#అన్తర్భావ "hostfile.h"
#అన్తర్భావ "auth.h"
#అన్తర్భావ "auth-options.h"

బాహ్య నిర్మాణం sshbuf *loginmsg;
బాహ్య ServerOptions options;

#నిర్వచితమైతే HAVE_LOGIN_CAP
బాహ్య login_cap_t *lc;
#అయితే_ముగింపు


#నిర్వచించు DAY		(24L * 60 * 60) /* 1 day in seconds */
#నిర్వచించు TWO_WEEKS	(2L * 7 * DAY)	/* 2 weeks in seconds */

#నిర్వచించు MAX_PASSWORD_LEN	1024

/*
 * Tries to authenticate the user using password.  Returns true if
 * authentication succeeds.
 */
పూర్ణాంకం
auth_password(నిర్మాణం ssh *ssh, స్థిరరాశి అక్షరం *password)
{
	Authctxt *authctxt = ssh->authctxt;
	నిర్మాణం passwd *pw = authctxt->pw;
	పూర్ణాంకం ఫలితం, ok = authctxt->valid;
#ఒకవేళ defined(USE_SHADOW) && defined(HAS_SHADOW_EXPIRE)
	స్థిర పూర్ణాంకం expire_checked = 0;
#అయితే_ముగింపు

	ఒకవేళ (అక్షరశ్రేణి_పొడవు(password) > MAX_PASSWORD_LEN)
		తిరిగి 0;

#నిర్వచితం_కాకపోతే HAVE_CYGWIN
	ఒకవేళ (pw->pw_uid == 0 && options.permit_మూలం_login != PERMIT_YES)
		ok = 0;
#అయితే_ముగింపు
	ఒకవేళ (*password == '\0' && options.permit_ఖాళీలు_passwd == 0)
		తిరిగి 0;

#నిర్వచితమైతే KRB5
	ఒకవేళ (options.kerberos_authentication == 1) {
		పూర్ణాంకం ret = auth_krb5_password(authctxt, password);
		ఒకవేళ (ret == 1 || ret == 0)
			తిరిగి ret && ok;
		/* Fall back to ordinary passwd authentication. */
	}
#అయితే_ముగింపు
#నిర్వచితమైతే HAVE_CYGWIN
	{
		HANDLE hToken = cygwin_logon_user(pw, password);

		ఒకవేళ (hToken == INVALID_HANDLE_విలువ)
			తిరిగి 0;
		cygwin_సమితి_impersonation_token(hToken);
		తిరిగి ok;
	}
#అయితే_ముగింపు
#నిర్వచితమైతే USE_PAM
	ఒకవేళ (options.use_pam)
		తిరిగి (sshpam_auth_passwd(authctxt, password) && ok);
#అయితే_ముగింపు
#ఒకవేళ defined(USE_SHADOW) && defined(HAS_SHADOW_EXPIRE)
	ఒకవేళ (!expire_checked) {
		expire_checked = 1;
		ఒకవేళ (auth_shadow_pwexpired(authctxt))
			authctxt->force_pwchange = 1;
	}
#అయితే_ముగింపు
	ఫలితం = sys_auth_passwd(ssh, password);
	ఒకవేళ (authctxt->force_pwchange)
		auth_restrict_session(ssh);
	తిరిగి (ఫలితం && ok);
}

#నిర్వచితమైతే BSD_AUTH
స్థిర శూన్య
warn_expiry(Authctxt *authctxt, auth_session_t *as)
{
	పూర్ణాంకం r;
	int64_t pwtimeleft, actimeleft, daysleft, pwwarntime, acwarntime;

	pwwarntime = acwarntime = TWO_WEEKS;

	pwtimeleft = auth_check_change(as);
	actimeleft = auth_check_expire(as);
#నిర్వచితమైతే HAVE_LOGIN_CAP
	ఒకవేళ (authctxt->valid) {
		pwwarntime = login_getcaptime(lc, "password-warn", TWO_WEEKS,
		    TWO_WEEKS);
		acwarntime = login_getcaptime(lc, "expire-warn", TWO_WEEKS,
		    TWO_WEEKS);
	}
#అయితే_ముగింపు
	ఒకవేళ (pwtimeleft != 0 && pwtimeleft < pwwarntime) {
		daysleft = pwtimeleft / DAY + 1;
		ఒకవేళ ((r = sshbuf_putf(loginmsg,
		    "Your password will expire in %lld day%s.\n",
		    daysleft, daysleft == 1 ? "" : "s")) != 0)
			fatal_fr(r, "buffer error");
	}
	ఒకవేళ (actimeleft != 0 && actimeleft < acwarntime) {
		daysleft = actimeleft / DAY + 1;
		ఒకవేళ ((r = sshbuf_putf(loginmsg,
		    "Your account will expire in %lld day%s.\n",
		    daysleft, daysleft == 1 ? "" : "s")) != 0)
			fatal_fr(r, "buffer error");
	}
}

పూర్ణాంకం
sys_auth_passwd(నిర్మాణం ssh *ssh, స్థిరరాశి అక్షరం *password)
{
	Authctxt *authctxt = ssh->authctxt;
	auth_session_t *as;
	స్థిర పూర్ణాంకం expire_checked = 0;

	as = auth_usercheck(authctxt->pw->pw_name, authctxt->style, "auth-ssh",
	    (అక్షరం *)password);
	ఒకవేళ (as == ఖాళీ)
		తిరిగి (0);
	ఒకవేళ (auth_getstate(as) & AUTH_PWEXPIRED) {
		auth_close(as);
		auth_restrict_session(ssh);
		authctxt->force_pwchange = 1;
		తిరిగి (1);
	} లేకపోతే {
		ఒకవేళ (!expire_checked) {
			expire_checked = 1;
			warn_expiry(authctxt, as);
		}
		తిరిగి (auth_close(as));
	}
}
#లేదావేళ !defined(CUSTOM_SYS_AUTH_PASSWD)
పూర్ణాంకం
sys_auth_passwd(నిర్మాణం ssh *ssh, స్థిరరాశి అక్షరం *password)
{
	Authctxt *authctxt = ssh->authctxt;
	నిర్మాణం passwd *pw = authctxt->pw;
	అక్షరం *encrypted_password, *salt = ఖాళీ;

	/* Just use the supplied fake password if authctxt is invalid */
	అక్షరం *pw_password = authctxt->valid ? shadow_pw(pw) : pw->pw_passwd;

	ఒకవేళ (pw_password == ఖాళీ)
		తిరిగి 0;

	/* Check for users with no password. */
	ఒకవేళ (strcmp(pw_password, "") == 0 && strcmp(password, "") == 0)
		తిరిగి (1);

	/*
	 * Encrypt the candidate password using the proper salt, or pass a
	 * NULL and let xcrypt pick one.
	 */
	ఒకవేళ (authctxt->valid && pw_password[0] && pw_password[1])
		salt = pw_password;
	encrypted_password = xcrypt(password, salt);

	/*
	 * Authentication is accepted if the encrypted passwords
	 * are identical.
	 */
	తిరిగి encrypted_password != ఖాళీ &&
	    strcmp(encrypted_password, pw_password) == 0;
}
#అయితే_ముగింపు
