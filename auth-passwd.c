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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <pwd.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdarg.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "packet.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshbuf.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssherr.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "log.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "misc.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "servconf.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshkey.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "hostfile.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "auth.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "auth-options.h"

ਬਾਹਰੀ ਬਣਤਰ sshbuf *loginmsg;
ਬਾਹਰੀ ServerOptions options;

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_LOGIN_CAP
ਬਾਹਰੀ login_cap_t *lc;
#ਜੇ_ਅੰਤ


#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ DAY		(24L * 60 * 60) /* 1 day in seconds */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ TWO_WEEKS	(2L * 7 * DAY)	/* 2 weeks in seconds */

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ MAX_PASSWORD_LEN	1024

/*
 * Tries to authenticate the user using password.  Returns true if
 * authentication succeeds.
 */
ਪੂਰਨ
auth_password(ਬਣਤਰ ssh *ssh, ਅਚਲ ਅੱਖਰ *password)
{
	Authctxt *authctxt = ssh->authctxt;
	ਬਣਤਰ passwd *pw = authctxt->pw;
	ਪੂਰਨ ਨਤੀਜਾ, ok = authctxt->valid;
#ਜੇ defined(USE_SHADOW) && defined(HAS_SHADOW_EXPIRE)
	ਸਥਿਰ ਪੂਰਨ expire_checked = 0;
#ਜੇ_ਅੰਤ

	ਜੇ (ਲੜੀ_ਲੰਬਾਈ(password) > MAX_PASSWORD_LEN)
		ਵਾਪਸ 0;

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ HAVE_CYGWIN
	ਜੇ (pw->pw_uid == 0 && options.permit_ਜੜ੍ਹ_login != PERMIT_YES)
		ok = 0;
#ਜੇ_ਅੰਤ
	ਜੇ (*password == '\0' && options.permit_ਖਾਲੀ_ਥਾਵਾਂ_passwd == 0)
		ਵਾਪਸ 0;

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ KRB5
	ਜੇ (options.kerberos_authentication == 1) {
		ਪੂਰਨ ret = auth_krb5_password(authctxt, password);
		ਜੇ (ret == 1 || ret == 0)
			ਵਾਪਸ ret && ok;
		/* Fall back to ordinary passwd authentication. */
	}
#ਜੇ_ਅੰਤ
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_CYGWIN
	{
		HANDLE hToken = cygwin_logon_user(pw, password);

		ਜੇ (hToken == INVALID_HANDLE_ਮੁੱਲ)
			ਵਾਪਸ 0;
		cygwin_ਸੈੱਟ_impersonation_token(hToken);
		ਵਾਪਸ ok;
	}
#ਜੇ_ਅੰਤ
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ USE_PAM
	ਜੇ (options.use_pam)
		ਵਾਪਸ (sshpam_auth_passwd(authctxt, password) && ok);
#ਜੇ_ਅੰਤ
#ਜੇ defined(USE_SHADOW) && defined(HAS_SHADOW_EXPIRE)
	ਜੇ (!expire_checked) {
		expire_checked = 1;
		ਜੇ (auth_shadow_pwexpired(authctxt))
			authctxt->force_pwchange = 1;
	}
#ਜੇ_ਅੰਤ
	ਨਤੀਜਾ = sys_auth_passwd(ssh, password);
	ਜੇ (authctxt->force_pwchange)
		auth_restrict_session(ssh);
	ਵਾਪਸ (ਨਤੀਜਾ && ok);
}

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ BSD_AUTH
ਸਥਿਰ ਖਾਲੀ
warn_expiry(Authctxt *authctxt, auth_session_t *as)
{
	ਪੂਰਨ r;
	int64_t pwtimeleft, actimeleft, daysleft, pwwarntime, acwarntime;

	pwwarntime = acwarntime = TWO_WEEKS;

	pwtimeleft = auth_check_change(as);
	actimeleft = auth_check_expire(as);
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_LOGIN_CAP
	ਜੇ (authctxt->valid) {
		pwwarntime = login_getcaptime(lc, "password-warn", TWO_WEEKS,
		    TWO_WEEKS);
		acwarntime = login_getcaptime(lc, "expire-warn", TWO_WEEKS,
		    TWO_WEEKS);
	}
#ਜੇ_ਅੰਤ
	ਜੇ (pwtimeleft != 0 && pwtimeleft < pwwarntime) {
		daysleft = pwtimeleft / DAY + 1;
		ਜੇ ((r = sshbuf_putf(loginmsg,
		    "Your password will expire in %lld day%s.\n",
		    daysleft, daysleft == 1 ? "" : "s")) != 0)
			fatal_fr(r, "buffer error");
	}
	ਜੇ (actimeleft != 0 && actimeleft < acwarntime) {
		daysleft = actimeleft / DAY + 1;
		ਜੇ ((r = sshbuf_putf(loginmsg,
		    "Your account will expire in %lld day%s.\n",
		    daysleft, daysleft == 1 ? "" : "s")) != 0)
			fatal_fr(r, "buffer error");
	}
}

ਪੂਰਨ
sys_auth_passwd(ਬਣਤਰ ssh *ssh, ਅਚਲ ਅੱਖਰ *password)
{
	Authctxt *authctxt = ssh->authctxt;
	auth_session_t *as;
	ਸਥਿਰ ਪੂਰਨ expire_checked = 0;

	as = auth_usercheck(authctxt->pw->pw_name, authctxt->style, "auth-ssh",
	    (ਅੱਖਰ *)password);
	ਜੇ (as == ਨਿਰਾ)
		ਵਾਪਸ (0);
	ਜੇ (auth_getstate(as) & AUTH_PWEXPIRED) {
		auth_close(as);
		auth_restrict_session(ssh);
		authctxt->force_pwchange = 1;
		ਵਾਪਸ (1);
	} ਨਹੀਂਤਾਂ {
		ਜੇ (!expire_checked) {
			expire_checked = 1;
			warn_expiry(authctxt, as);
		}
		ਵਾਪਸ (auth_close(as));
	}
}
#ਜਾਂਜੇ !defined(CUSTOM_SYS_AUTH_PASSWD)
ਪੂਰਨ
sys_auth_passwd(ਬਣਤਰ ssh *ssh, ਅਚਲ ਅੱਖਰ *password)
{
	Authctxt *authctxt = ssh->authctxt;
	ਬਣਤਰ passwd *pw = authctxt->pw;
	ਅੱਖਰ *encrypted_password, *salt = ਨਿਰਾ;

	/* Just use the supplied fake password if authctxt is invalid */
	ਅੱਖਰ *pw_password = authctxt->valid ? shadow_pw(pw) : pw->pw_passwd;

	ਜੇ (pw_password == ਨਿਰਾ)
		ਵਾਪਸ 0;

	/* Check for users with no password. */
	ਜੇ (strcmp(pw_password, "") == 0 && strcmp(password, "") == 0)
		ਵਾਪਸ (1);

	/*
	 * Encrypt the candidate password using the proper salt, or pass a
	 * NULL and let xcrypt pick one.
	 */
	ਜੇ (authctxt->valid && pw_password[0] && pw_password[1])
		salt = pw_password;
	encrypted_password = xcrypt(password, salt);

	/*
	 * Authentication is accepted if the encrypted passwords
	 * are identical.
	 */
	ਵਾਪਸ encrypted_password != ਨਿਰਾ &&
	    strcmp(encrypted_password, pw_password) == 0;
}
#ਜੇ_ਅੰਤ
