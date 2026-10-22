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

#அந்தர்பாவ "includes.h"

#அந்தர்பாவ <sys/types.h>

#அந்தர்பாவ <pwd.h>
#அந்தர்பாவ <stdio.h>
#அந்தர்பாவ <string.h>
#அந்தர்பாவ <stdarg.h>

#அந்தர்பாவ "packet.h"
#அந்தர்பாவ "sshbuf.h"
#அந்தர்பாவ "ssherr.h"
#அந்தர்பாவ "log.h"
#அந்தர்பாவ "misc.h"
#அந்தர்பாவ "servconf.h"
#அந்தர்பாவ "sshkey.h"
#அந்தர்பாவ "hostfile.h"
#அந்தர்பாவ "auth.h"
#அந்தர்பாவ "auth-options.h"

வெளி கட்டமைப்பு sshbuf *loginmsg;
வெளி ServerOptions options;

#ifdef HAVE_LOGIN_CAP
வெளி login_cap_t *lc;
#endif


#define DAY		(24L * 60 * 60) /* 1 day in seconds */
#define TWO_WEEKS	(2L * 7 * DAY)	/* 2 weeks in seconds */

#define MAX_PASSWORD_LEN	1024

/*
 * Tries to authenticate the user using password.  Returns true if
 * authentication succeeds.
 */
முழு
auth_password(கட்டமைப்பு ssh *ssh, மாறிலி எழுத்து *password)
{
	Authctxt *authctxt = ssh->authctxt;
	கட்டமைப்பு passwd *pw = authctxt->pw;
	முழு result, ok = authctxt->valid;
#எனில் defined(USE_SHADOW) && defined(HAS_SHADOW_EXPIRE)
	நிலையான முழு expire_checked = 0;
#endif

	எனில் (strlen(password) > MAX_PASSWORD_LEN)
		திரும்பு 0;

#ifndef HAVE_CYGWIN
	எனில் (pw->pw_uid == 0 && options.permit_வேர்_login != PERMIT_YES)
		ok = 0;
#endif
	எனில் (*password == '\0' && options.permit_empty_passwd == 0)
		திரும்பு 0;

#ifdef KRB5
	எனில் (options.kerberos_authentication == 1) {
		முழு ret = auth_krb5_password(authctxt, password);
		எனில் (ret == 1 || ret == 0)
			திரும்பு ret && ok;
		/* Fall back to ordinary passwd authentication. */
	}
#endif
#ifdef HAVE_CYGWIN
	{
		HANDLE hToken = cygwin_logon_user(pw, password);

		எனில் (hToken == INVALID_HANDLE_மதிப்பு)
			திரும்பு 0;
		cygwin_set_impersonation_token(hToken);
		திரும்பு ok;
	}
#endif
#ifdef USE_PAM
	எனில் (options.use_pam)
		திரும்பு (sshpam_auth_passwd(authctxt, password) && ok);
#endif
#எனில் defined(USE_SHADOW) && defined(HAS_SHADOW_EXPIRE)
	எனில் (!expire_checked) {
		expire_checked = 1;
		எனில் (auth_shadow_pwexpired(authctxt))
			authctxt->force_pwchange = 1;
	}
#endif
	result = sys_auth_passwd(ssh, password);
	எனில் (authctxt->force_pwchange)
		auth_restrict_session(ssh);
	திரும்பு (result && ok);
}

#ifdef BSD_AUTH
நிலையான வெறுமை
warn_expiry(Authctxt *authctxt, auth_session_t *as)
{
	முழு r;
	int64_t pwtimeleft, actimeleft, daysleft, pwwarntime, acwarntime;

	pwwarntime = acwarntime = TWO_WEEKS;

	pwtimeleft = auth_check_change(as);
	actimeleft = auth_check_expire(as);
#ifdef HAVE_LOGIN_CAP
	எனில் (authctxt->valid) {
		pwwarntime = login_getcaptime(lc, "password-warn", TWO_WEEKS,
		    TWO_WEEKS);
		acwarntime = login_getcaptime(lc, "expire-warn", TWO_WEEKS,
		    TWO_WEEKS);
	}
#endif
	எனில் (pwtimeleft != 0 && pwtimeleft < pwwarntime) {
		daysleft = pwtimeleft / DAY + 1;
		எனில் ((r = sshbuf_putf(loginmsg,
		    "Your password will expire in %lld day%s.\n",
		    daysleft, daysleft == 1 ? "" : "s")) != 0)
			fatal_fr(r, "buffer error");
	}
	எனில் (actimeleft != 0 && actimeleft < acwarntime) {
		daysleft = actimeleft / DAY + 1;
		எனில் ((r = sshbuf_putf(loginmsg,
		    "Your account will expire in %lld day%s.\n",
		    daysleft, daysleft == 1 ? "" : "s")) != 0)
			fatal_fr(r, "buffer error");
	}
}

முழு
sys_auth_passwd(கட்டமைப்பு ssh *ssh, மாறிலி எழுத்து *password)
{
	Authctxt *authctxt = ssh->authctxt;
	auth_session_t *as;
	நிலையான முழு expire_checked = 0;

	as = auth_usercheck(authctxt->pw->pw_name, authctxt->style, "auth-ssh",
	    (எழுத்து *)password);
	எனில் (as == வெற்று)
		திரும்பு (0);
	எனில் (auth_getstate(as) & AUTH_PWEXPIRED) {
		auth_close(as);
		auth_restrict_session(ssh);
		authctxt->force_pwchange = 1;
		திரும்பு (1);
	} இல்லையெனில் {
		எனில் (!expire_checked) {
			expire_checked = 1;
			warn_expiry(authctxt, as);
		}
		திரும்பு (auth_close(as));
	}
}
#அல்லதெனில் !defined(CUSTOM_SYS_AUTH_PASSWD)
முழு
sys_auth_passwd(கட்டமைப்பு ssh *ssh, மாறிலி எழுத்து *password)
{
	Authctxt *authctxt = ssh->authctxt;
	கட்டமைப்பு passwd *pw = authctxt->pw;
	எழுத்து *encrypted_password, *salt = வெற்று;

	/* Just use the supplied fake password if authctxt is invalid */
	எழுத்து *pw_password = authctxt->valid ? shadow_pw(pw) : pw->pw_passwd;

	எனில் (pw_password == வெற்று)
		திரும்பு 0;

	/* Check for users with no password. */
	எனில் (strcmp(pw_password, "") == 0 && strcmp(password, "") == 0)
		திரும்பு (1);

	/*
	 * Encrypt the candidate password using the proper salt, or pass a
	 * NULL and let xcrypt pick one.
	 */
	எனில் (authctxt->valid && pw_password[0] && pw_password[1])
		salt = pw_password;
	encrypted_password = xcrypt(password, salt);

	/*
	 * Authentication is accepted if the encrypted passwords
	 * are identical.
	 */
	திரும்பு encrypted_password != வெற்று &&
	    strcmp(encrypted_password, pw_password) == 0;
}
#endif
