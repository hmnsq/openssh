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

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <sys/types.h>

#ಅನ್ತರ್ಭಾವ <pwd.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <stdarg.h>

#ಅನ್ತರ್ಭಾವ "packet.h"
#ಅನ್ತರ್ಭಾವ "sshbuf.h"
#ಅನ್ತರ್ಭಾವ "ssherr.h"
#ಅನ್ತರ್ಭಾವ "log.h"
#ಅನ್ತರ್ಭಾವ "misc.h"
#ಅನ್ತರ್ಭಾವ "servconf.h"
#ಅನ್ತರ್ಭಾವ "sshkey.h"
#ಅನ್ತರ್ಭಾವ "hostfile.h"
#ಅನ್ತರ್ಭಾವ "auth.h"
#ಅನ್ತರ್ಭಾವ "auth-options.h"

ಬಾಹ್ಯ ರಚನೆ sshbuf *loginmsg;
ಬಾಹ್ಯ ServerOptions options;

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_LOGIN_CAP
ಬಾಹ್ಯ login_cap_t *lc;
#ಆದರೆ_ಅಂತ್ಯ


#ವ್ಯಾಖ್ಯಾನಿಸು DAY		(24L * 60 * 60) /* 1 day in seconds */
#ವ್ಯಾಖ್ಯಾನಿಸು TWO_WEEKS	(2L * 7 * DAY)	/* 2 weeks in seconds */

#ವ್ಯಾಖ್ಯಾನಿಸು MAX_PASSWORD_LEN	1024

/*
 * Tries to authenticate the user using password.  Returns true if
 * authentication succeeds.
 */
ಪೂರ್ಣಾಂಕ
auth_password(ರಚನೆ ssh *ssh, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *password)
{
	Authctxt *authctxt = ssh->authctxt;
	ರಚನೆ passwd *pw = authctxt->pw;
	ಪೂರ್ಣಾಂಕ ಫಲಿತಾಂಶ, ok = authctxt->valid;
#ಆದರೆ defined(USE_SHADOW) && defined(HAS_SHADOW_EXPIRE)
	ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ expire_checked = 0;
#ಆದರೆ_ಅಂತ್ಯ

	ಆದರೆ (ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(password) > MAX_PASSWORD_LEN)
		ಹಿಂತಿರುಗಿ 0;

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_CYGWIN
	ಆದರೆ (pw->pw_uid == 0 && options.permit_ಬೇರು_login != PERMIT_YES)
		ok = 0;
#ಆದರೆ_ಅಂತ್ಯ
	ಆದರೆ (*password == '\0' && options.permit_ಖಾಲಿಗಳು_passwd == 0)
		ಹಿಂತಿರುಗಿ 0;

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ KRB5
	ಆದರೆ (options.kerberos_authentication == 1) {
		ಪೂರ್ಣಾಂಕ ret = auth_krb5_password(authctxt, password);
		ಆದರೆ (ret == 1 || ret == 0)
			ಹಿಂತಿರುಗಿ ret && ok;
		/* Fall back to ordinary passwd authentication. */
	}
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_CYGWIN
	{
		HANDLE hToken = cygwin_logon_user(pw, password);

		ಆದರೆ (hToken == INVALID_HANDLE_ಮೌಲ್ಯ)
			ಹಿಂತಿರುಗಿ 0;
		cygwin_ಗಣ_impersonation_token(hToken);
		ಹಿಂತಿರುಗಿ ok;
	}
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ USE_PAM
	ಆದರೆ (options.use_pam)
		ಹಿಂತಿರುಗಿ (sshpam_auth_passwd(authctxt, password) && ok);
#ಆದರೆ_ಅಂತ್ಯ
#ಆದರೆ defined(USE_SHADOW) && defined(HAS_SHADOW_EXPIRE)
	ಆದರೆ (!expire_checked) {
		expire_checked = 1;
		ಆದರೆ (auth_shadow_pwexpired(authctxt))
			authctxt->force_pwchange = 1;
	}
#ಆದರೆ_ಅಂತ್ಯ
	ಫಲಿತಾಂಶ = sys_auth_passwd(ssh, password);
	ಆದರೆ (authctxt->force_pwchange)
		auth_restrict_session(ssh);
	ಹಿಂತಿರುಗಿ (ಫಲಿತಾಂಶ && ok);
}

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ BSD_AUTH
ಸ್ಥಿರ ಶೂನ್ಯ
warn_expiry(Authctxt *authctxt, auth_session_t *as)
{
	ಪೂರ್ಣಾಂಕ r;
	int64_t pwtimeleft, actimeleft, daysleft, pwwarntime, acwarntime;

	pwwarntime = acwarntime = TWO_WEEKS;

	pwtimeleft = auth_check_change(as);
	actimeleft = auth_check_expire(as);
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_LOGIN_CAP
	ಆದರೆ (authctxt->valid) {
		pwwarntime = login_getcaptime(lc, "password-warn", TWO_WEEKS,
		    TWO_WEEKS);
		acwarntime = login_getcaptime(lc, "expire-warn", TWO_WEEKS,
		    TWO_WEEKS);
	}
#ಆದರೆ_ಅಂತ್ಯ
	ಆದರೆ (pwtimeleft != 0 && pwtimeleft < pwwarntime) {
		daysleft = pwtimeleft / DAY + 1;
		ಆದರೆ ((r = sshbuf_putf(loginmsg,
		    "Your password will expire in %lld day%s.\n",
		    daysleft, daysleft == 1 ? "" : "s")) != 0)
			fatal_fr(r, "buffer error");
	}
	ಆದರೆ (actimeleft != 0 && actimeleft < acwarntime) {
		daysleft = actimeleft / DAY + 1;
		ಆದರೆ ((r = sshbuf_putf(loginmsg,
		    "Your account will expire in %lld day%s.\n",
		    daysleft, daysleft == 1 ? "" : "s")) != 0)
			fatal_fr(r, "buffer error");
	}
}

ಪೂರ್ಣಾಂಕ
sys_auth_passwd(ರಚನೆ ssh *ssh, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *password)
{
	Authctxt *authctxt = ssh->authctxt;
	auth_session_t *as;
	ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ expire_checked = 0;

	as = auth_usercheck(authctxt->pw->pw_name, authctxt->style, "auth-ssh",
	    (ಅಕ್ಷರ *)password);
	ಆದರೆ (as == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ (0);
	ಆದರೆ (auth_getstate(as) & AUTH_PWEXPIRED) {
		auth_close(as);
		auth_restrict_session(ssh);
		authctxt->force_pwchange = 1;
		ಹಿಂತಿರುಗಿ (1);
	} ಇಲ್ಲದಿದ್ದರೆ {
		ಆದರೆ (!expire_checked) {
			expire_checked = 1;
			warn_expiry(authctxt, as);
		}
		ಹಿಂತಿರುಗಿ (auth_close(as));
	}
}
#ಅಥವಾಆದರೆ !defined(CUSTOM_SYS_AUTH_PASSWD)
ಪೂರ್ಣಾಂಕ
sys_auth_passwd(ರಚನೆ ssh *ssh, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *password)
{
	Authctxt *authctxt = ssh->authctxt;
	ರಚನೆ passwd *pw = authctxt->pw;
	ಅಕ್ಷರ *encrypted_password, *salt = ಖಾಲಿ;

	/* Just use the supplied fake password if authctxt is invalid */
	ಅಕ್ಷರ *pw_password = authctxt->valid ? shadow_pw(pw) : pw->pw_passwd;

	ಆದರೆ (pw_password == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ 0;

	/* Check for users with no password. */
	ಆದರೆ (strcmp(pw_password, "") == 0 && strcmp(password, "") == 0)
		ಹಿಂತಿರುಗಿ (1);

	/*
	 * Encrypt the candidate password using the proper salt, or pass a
	 * NULL and let xcrypt pick one.
	 */
	ಆದರೆ (authctxt->valid && pw_password[0] && pw_password[1])
		salt = pw_password;
	encrypted_password = xcrypt(password, salt);

	/*
	 * Authentication is accepted if the encrypted passwords
	 * are identical.
	 */
	ಹಿಂತಿರುಗಿ encrypted_password != ಖಾಲಿ &&
	    strcmp(encrypted_password, pw_password) == 0;
}
#ಆದರೆ_ಅಂತ್ಯ
