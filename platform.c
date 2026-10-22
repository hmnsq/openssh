/*
 * Copyright (c) 2006 Darren Tucker.  All rights reserved.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <stdarg.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <unistd.h>

#ಅನ್ತರ್ಭಾವ "log.h"
#ಅನ್ತರ್ಭಾವ "misc.h"
#ಅನ್ತರ್ಭಾವ "servconf.h"
#ಅನ್ತರ್ಭಾವ "sshkey.h"
#ಅನ್ತರ್ಭಾವ "hostfile.h"
#ಅನ್ತರ್ಭಾವ "auth.h"
#ಅನ್ತರ್ಭಾವ "auth-pam.h"
#ಅನ್ತರ್ಭಾವ "platform.h"

#ಅನ್ತರ್ಭಾವ "openbsd-compat/openbsd-compat.h"

ಬಾಹ್ಯ ServerOptions options;

/* return 1 if we are running with privilege to swap UIDs, 0 otherwise */
ಪೂರ್ಣಾಂಕ
platform_privileged_uidswap(ಶೂನ್ಯ)
{
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_CYGWIN
	/* uid 0 is not special on Cygwin so always try */
	ಹಿಂತಿರುಗಿ 1;
#ಇಲ್ಲದಿದ್ದರೆ
	ಹಿಂತಿರುಗಿ (getuid() == 0 || geteuid() == 0);
#ಆದರೆ_ಅಂತ್ಯ
}

/*
 * This gets called before switching UIDs, and is called even when sshd is
 * not running as root.
 */
ಶೂನ್ಯ
platform_setusercontext(ರಚನೆ passwd *pw)
{
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_SELINUX
	/* Cache selinux status for later use */
	(ಶೂನ್ಯ)ssh_selinux_enabled();
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ USE_SOLARIS_PROJECTS
	/*
	 * If solaris projects were detected, set the default now, unless
	 * we are using PAM in which case it is the responsibility of the
	 * PAM stack.
	 */
	ಆದರೆ (!options.use_pam && (getuid() == 0 || geteuid() == 0))
		solaris_ಗಣ_default_project(pw);
#ಆದರೆ_ಅಂತ್ಯ

#ಆದರೆ defined(HAVE_LOGIN_CAP) && defined (__bsdi__)
	ಆದರೆ (getuid() == 0 || geteuid() == 0)
		setpgid(0, 0);
# endif

#ಆದರೆ defined(HAVE_LOGIN_CAP) && defined(USE_PAM)
	/*
	 * If we have both LOGIN_CAP and PAM, we want to establish creds
	 * before calling setusercontext (in session.c:do_setusercontext).
	 */
	ಆದರೆ (getuid() == 0 || geteuid() == 0) {
		ಆದರೆ (options.use_pam) {
			do_pam_setcred();
		}
	}
# endif /* USE_PAM */

#ಆದರೆ !defined(HAVE_LOGIN_CAP) && defined(HAVE_GETLUID) && defined(HAVE_SETLUID)
	ಆದರೆ (getuid() == 0 || geteuid() == 0) {
		/* Sets login uid for accounting */
		ಆದರೆ (getluid() == -1 && setluid(pw->pw_uid) == -1)
			error("setluid: %s", strerror(errno));
	}
#ಆದರೆ_ಅಂತ್ಯ
}

/*
 * This gets called after we've established the user's groups, and is only
 * called if sshd is running as root.
 */
ಶೂನ್ಯ
platform_setusercontext_post_groups(ರಚನೆ passwd *pw)
{
#ಆದರೆ !defined(HAVE_LOGIN_CAP) && defined(USE_PAM)
	/*
	 * PAM credentials may take the form of supplementary groups.
	 * These will have been wiped by the above initgroups() call.
	 * Reestablish them here.
	 */
	ಆದರೆ (options.use_pam) {
		do_pam_setcred();
	}
#ಆದರೆ_ಅಂತ್ಯ /* USE_PAM */

#ಆದರೆ !defined(HAVE_LOGIN_CAP) && (defined(WITH_IRIX_PROJECT) || \
    defined(WITH_IRIX_JOBS) || defined(WITH_IRIX_ARRAY))
	irix_setusercontext(pw);
#ಆದರೆ_ಅಂತ್ಯ /* defined(WITH_IRIX_PROJECT) || defined(WITH_IRIX_JOBS) || defined(WITH_IRIX_ARRAY) */

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ _AIX
	aix_usrinfo(pw);
#ಆದರೆ_ಅಂತ್ಯ /* _AIX */

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_SETPCRED
	/*
	 * If we have a chroot directory, we set all creds except real
	 * uid which we will need for chroot.  If we don't have a
	 * chroot directory, we don't override anything.
	 */
	{
		ಅಕ್ಷರ **creds = ಖಾಲಿ, *chroot_creds[] =
		    { "REAL_USER=root", ಖಾಲಿ };

		ಆದರೆ (options.chroot_directory != ಖಾಲಿ &&
		    strcasecmp(options.chroot_directory, "none") != 0)
			creds = chroot_creds;

		ಆದರೆ (setpcred(pw->pw_name, creds) == -1)
			fatal("Failed to set process credentials");
	}
#ಆದರೆ_ಅಂತ್ಯ /* HAVE_SETPCRED */
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_SELINUX
	ssh_selinux_ಸಿದ್ಧತೆ_exec_context(pw->pw_name);
#ಆದರೆ_ಅಂತ್ಯ
}

ಅಕ್ಷರ *
platform_krb5_get_principal_name(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *pw_name)
{
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ USE_AIX_KRB_NAME
	ಹಿಂತಿರುಗಿ aix_krb5_get_principal_name(pw_name);
#ಇಲ್ಲದಿದ್ದರೆ
	ಹಿಂತಿರುಗಿ ಖಾಲಿ;
#ಆದರೆ_ಅಂತ್ಯ
}

/* returns 1 if account is locked */
ಪೂರ್ಣಾಂಕ
platform_locked_account(ರಚನೆ passwd *pw)
{
	ಪೂರ್ಣಾಂಕ locked = 0;
	ಅಕ್ಷರ *passwd = pw->pw_passwd;
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ USE_SHADOW
	ರಚನೆ spwd *spw = ಖಾಲಿ;
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ USE_LIBIAF
	ಅಕ್ಷರ *iaf_passwd = ಖಾಲಿ;
#ಆದರೆ_ಅಂತ್ಯ

	spw = getspnam(pw->pw_name);
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAS_SHADOW_EXPIRE
	ಆದರೆ (spw != ಖಾಲಿ && auth_shadow_acctexpired(spw))
		ಹಿಂತಿರುಗಿ 1;
#ಆದರೆ_ಅಂತ್ಯ /* HAS_SHADOW_EXPIRE */

	ಆದರೆ (spw != ಖಾಲಿ)
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ USE_LIBIAF
		iaf_passwd = passwd = get_iaf_password(pw);
#ಇಲ್ಲದಿದ್ದರೆ
		passwd = spw->sp_pwdp;
#ಆದರೆ_ಅಂತ್ಯ /* USE_LIBIAF */
#ಆದರೆ_ಅಂತ್ಯ

	/* check for locked account */
	ಆದರೆ (passwd && *passwd) {
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ LOCKED_PASSWD_STRING
		ಆದರೆ (strcmp(passwd, LOCKED_PASSWD_STRING) == 0) {
			debug3_f("password matches locked string '%s'",
			    LOCKED_PASSWD_STRING);
			locked = 1;
		}
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ LOCKED_PASSWD_ಪೂರ್ವಪ್ರತ್ಯಯ
		ಆದರೆ (ಅಕ್ಷರಸರಣಿ_ಹೋಲಿಕೆ(passwd, LOCKED_PASSWD_ಪೂರ್ವಪ್ರತ್ಯಯ,
		    ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(LOCKED_PASSWD_ಪೂರ್ವಪ್ರತ್ಯಯ)) == 0) {
			debug3_f("password matches locked prefix '%s'",
			    LOCKED_PASSWD_ಪೂರ್ವಪ್ರತ್ಯಯ);
			locked = 1;
		}
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ LOCKED_PASSWD_SUBSTR
		ಆದರೆ (ಅಕ್ಷರಸರಣಿ_ಹುಡುಕು(passwd, LOCKED_PASSWD_SUBSTR)) {
			debug3_f("password matches locked substring '%s'",
			   LOCKED_PASSWD_SUBSTR);
			locked = 1;
		}
#ಆದರೆ_ಅಂತ್ಯ
	}
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ USE_LIBIAF
	ಆದರೆ (iaf_passwd != ಖಾಲಿ)
		freezero(iaf_passwd, ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(iaf_passwd));
#ಆದರೆ_ಅಂತ್ಯ /* USE_LIBIAF */

	ಹಿಂತಿರುಗಿ locked;
}
