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
ಪೂರ್ಣಾಙ್ಕ
platform_privileged_uidswap(ಶೂನ್ಯ)
{
#ifdef HAVE_CYGWIN
	/* uid 0 is not special on Cygwin so always try */
	ಪ್ರತ್ಯಾಗಮ 1;
#ಅನ್ಯಥಾ
	ಪ್ರತ್ಯಾಗಮ (getuid() == 0 || geteuid() == 0);
#endif
}

/*
 * This gets called before switching UIDs, and is called even when sshd is
 * not running as root.
 */
ಶೂನ್ಯ
platform_setusercontext(ಸಂರಚನಾ passwd *pw)
{
#ifdef WITH_SELINUX
	/* Cache selinux status for later use */
	(ಶೂನ್ಯ)ssh_selinux_enabled();
#endif

#ifdef USE_SOLARIS_PROJECTS
	/*
	 * If solaris projects were detected, set the default now, unless
	 * we are using PAM in which case it is the responsibility of the
	 * PAM stack.
	 */
	ಯದಿ (!options.use_pam && (getuid() == 0 || geteuid() == 0))
		solaris_set_default_project(pw);
#endif

#ಯದಿ defined(HAVE_LOGIN_CAP) && defined (__bsdi__)
	ಯದಿ (getuid() == 0 || geteuid() == 0)
		setpgid(0, 0);
# endif

#ಯದಿ defined(HAVE_LOGIN_CAP) && defined(USE_PAM)
	/*
	 * If we have both LOGIN_CAP and PAM, we want to establish creds
	 * before calling setusercontext (in session.c:do_setusercontext).
	 */
	ಯದಿ (getuid() == 0 || geteuid() == 0) {
		ಯದಿ (options.use_pam) {
			do_pam_setcred();
		}
	}
# endif /* USE_PAM */

#ಯದಿ !defined(HAVE_LOGIN_CAP) && defined(HAVE_GETLUID) && defined(HAVE_SETLUID)
	ಯದಿ (getuid() == 0 || geteuid() == 0) {
		/* Sets login uid for accounting */
		ಯದಿ (getluid() == -1 && setluid(pw->pw_uid) == -1)
			error("setluid: %s", strerror(errno));
	}
#endif
}

/*
 * This gets called after we've established the user's groups, and is only
 * called if sshd is running as root.
 */
ಶೂನ್ಯ
platform_setusercontext_post_groups(ಸಂರಚನಾ passwd *pw)
{
#ಯದಿ !defined(HAVE_LOGIN_CAP) && defined(USE_PAM)
	/*
	 * PAM credentials may take the form of supplementary groups.
	 * These will have been wiped by the above initgroups() call.
	 * Reestablish them here.
	 */
	ಯದಿ (options.use_pam) {
		do_pam_setcred();
	}
#endif /* USE_PAM */

#ಯದಿ !defined(HAVE_LOGIN_CAP) && (defined(WITH_IRIX_PROJECT) || \
    defined(WITH_IRIX_JOBS) || defined(WITH_IRIX_ARRAY))
	irix_setusercontext(pw);
#endif /* defined(WITH_IRIX_PROJECT) || defined(WITH_IRIX_JOBS) || defined(WITH_IRIX_ARRAY) */

#ifdef _AIX
	aix_usrinfo(pw);
#endif /* _AIX */

#ifdef HAVE_SETPCRED
	/*
	 * If we have a chroot directory, we set all creds except real
	 * uid which we will need for chroot.  If we don't have a
	 * chroot directory, we don't override anything.
	 */
	{
		ವರ್ಣ **creds = ರಿಕ್ತ, *chroot_creds[] =
		    { "REAL_USER=root", ರಿಕ್ತ };

		ಯದಿ (options.chroot_directory != ರಿಕ್ತ &&
		    strcasecmp(options.chroot_directory, "none") != 0)
			creds = chroot_creds;

		ಯದಿ (setpcred(pw->pw_name, creds) == -1)
			fatal("Failed to set process credentials");
	}
#endif /* HAVE_SETPCRED */
#ifdef WITH_SELINUX
	ssh_selinux_setup_exec_context(pw->pw_name);
#endif
}

ವರ್ಣ *
platform_krb5_get_principal_name(ಧ್ರುವ ವರ್ಣ *pw_name)
{
#ifdef USE_AIX_KRB_NAME
	ಪ್ರತ್ಯಾಗಮ aix_krb5_get_principal_name(pw_name);
#ಅನ್ಯಥಾ
	ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
#endif
}

/* returns 1 if account is locked */
ಪೂರ್ಣಾಙ್ಕ
platform_locked_account(ಸಂರಚನಾ passwd *pw)
{
	ಪೂರ್ಣಾಙ್ಕ locked = 0;
	ವರ್ಣ *passwd = pw->pw_passwd;
#ifdef USE_SHADOW
	ಸಂರಚನಾ spwd *spw = ರಿಕ್ತ;
#ifdef USE_LIBIAF
	ವರ್ಣ *iaf_passwd = ರಿಕ್ತ;
#endif

	spw = getspnam(pw->pw_name);
#ifdef HAS_SHADOW_EXPIRE
	ಯದಿ (spw != ರಿಕ್ತ && auth_shadow_acctexpired(spw))
		ಪ್ರತ್ಯಾಗಮ 1;
#endif /* HAS_SHADOW_EXPIRE */

	ಯದಿ (spw != ರಿಕ್ತ)
#ifdef USE_LIBIAF
		iaf_passwd = passwd = get_iaf_password(pw);
#ಅನ್ಯಥಾ
		passwd = spw->sp_pwdp;
#endif /* USE_LIBIAF */
#endif

	/* check for locked account */
	ಯದಿ (passwd && *passwd) {
#ifdef LOCKED_PASSWD_STRING
		ಯದಿ (strcmp(passwd, LOCKED_PASSWD_STRING) == 0) {
			debug3_f("password matches locked string '%s'",
			    LOCKED_PASSWD_STRING);
			locked = 1;
		}
#endif
#ifdef LOCKED_PASSWD_PREFIX
		ಯದಿ (strncmp(passwd, LOCKED_PASSWD_PREFIX,
		    strlen(LOCKED_PASSWD_PREFIX)) == 0) {
			debug3_f("password matches locked prefix '%s'",
			    LOCKED_PASSWD_PREFIX);
			locked = 1;
		}
#endif
#ifdef LOCKED_PASSWD_SUBSTR
		ಯದಿ (strstr(passwd, LOCKED_PASSWD_SUBSTR)) {
			debug3_f("password matches locked substring '%s'",
			   LOCKED_PASSWD_SUBSTR);
			locked = 1;
		}
#endif
	}
#ifdef USE_LIBIAF
	ಯದಿ (iaf_passwd != ರಿಕ್ತ)
		freezero(iaf_passwd, strlen(iaf_passwd));
#endif /* USE_LIBIAF */

	ಪ್ರತ್ಯಾಗಮ locked;
}
