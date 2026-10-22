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

#अन्तर्भाव "includes.h"

#अन्तर्भाव <stdarg.h>
#अन्तर्भाव <stdio.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <unistd.h>

#अन्तर्भाव "log.h"
#अन्तर्भाव "misc.h"
#अन्तर्भाव "servconf.h"
#अन्तर्भाव "sshkey.h"
#अन्तर्भाव "hostfile.h"
#अन्तर्भाव "auth.h"
#अन्तर्भाव "auth-pam.h"
#अन्तर्भाव "platform.h"

#अन्तर्भाव "openbsd-compat/openbsd-compat.h"

बाह्य ServerOptions options;

/* return 1 if we are running with privilege to swap UIDs, 0 otherwise */
पूर्णाङ्क
platform_privileged_uidswap(शून्य)
{
#ifdef HAVE_CYGWIN
	/* uid 0 is not special on Cygwin so always try */
	प्रत्यागम 1;
#अण्णहा
	प्रत्यागम (getuid() == 0 || geteuid() == 0);
#endif
}

/*
 * This gets called before switching UIDs, and is called even when sshd is
 * not running as root.
 */
शून्य
platform_setusercontext(संरचना passwd *pw)
{
#ifdef WITH_SELINUX
	/* Cache selinux status for later use */
	(शून्य)ssh_selinux_enabled();
#endif

#ifdef USE_SOLARIS_PROJECTS
	/*
	 * If solaris projects were detected, set the default now, unless
	 * we are using PAM in which case it is the responsibility of the
	 * PAM stack.
	 */
	जइ (!options.use_pam && (getuid() == 0 || geteuid() == 0))
		solaris_set_default_project(pw);
#endif

#जइ defined(HAVE_LOGIN_CAP) && defined (__bsdi__)
	जइ (getuid() == 0 || geteuid() == 0)
		setpgid(0, 0);
# endif

#जइ defined(HAVE_LOGIN_CAP) && defined(USE_PAM)
	/*
	 * If we have both LOGIN_CAP and PAM, we want to establish creds
	 * before calling setusercontext (in session.c:do_setusercontext).
	 */
	जइ (getuid() == 0 || geteuid() == 0) {
		जइ (options.use_pam) {
			do_pam_setcred();
		}
	}
# endif /* USE_PAM */

#जइ !defined(HAVE_LOGIN_CAP) && defined(HAVE_GETLUID) && defined(HAVE_SETLUID)
	जइ (getuid() == 0 || geteuid() == 0) {
		/* Sets login uid for accounting */
		जइ (getluid() == -1 && setluid(pw->pw_uid) == -1)
			error("setluid: %s", strerror(errno));
	}
#endif
}

/*
 * This gets called after we've established the user's groups, and is only
 * called if sshd is running as root.
 */
शून्य
platform_setusercontext_post_groups(संरचना passwd *pw)
{
#जइ !defined(HAVE_LOGIN_CAP) && defined(USE_PAM)
	/*
	 * PAM credentials may take the form of supplementary groups.
	 * These will have been wiped by the above initgroups() call.
	 * Reestablish them here.
	 */
	जइ (options.use_pam) {
		do_pam_setcred();
	}
#endif /* USE_PAM */

#जइ !defined(HAVE_LOGIN_CAP) && (defined(WITH_IRIX_PROJECT) || \
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
		वर्ण **creds = रिक्त, *chroot_creds[] =
		    { "REAL_USER=root", रिक्त };

		जइ (options.chroot_directory != रिक्त &&
		    strcasecmp(options.chroot_directory, "none") != 0)
			creds = chroot_creds;

		जइ (setpcred(pw->pw_name, creds) == -1)
			fatal("Failed to set process credentials");
	}
#endif /* HAVE_SETPCRED */
#ifdef WITH_SELINUX
	ssh_selinux_setup_exec_context(pw->pw_name);
#endif
}

वर्ण *
platform_krb5_get_principal_name(ध्रुव वर्ण *pw_name)
{
#ifdef USE_AIX_KRB_NAME
	प्रत्यागम aix_krb5_get_principal_name(pw_name);
#अण्णहा
	प्रत्यागम रिक्त;
#endif
}

/* returns 1 if account is locked */
पूर्णाङ्क
platform_locked_account(संरचना passwd *pw)
{
	पूर्णाङ्क locked = 0;
	वर्ण *passwd = pw->pw_passwd;
#ifdef USE_SHADOW
	संरचना spwd *spw = रिक्त;
#ifdef USE_LIBIAF
	वर्ण *iaf_passwd = रिक्त;
#endif

	spw = getspnam(pw->pw_name);
#ifdef HAS_SHADOW_EXPIRE
	जइ (spw != रिक्त && auth_shadow_acctexpired(spw))
		प्रत्यागम 1;
#endif /* HAS_SHADOW_EXPIRE */

	जइ (spw != रिक्त)
#ifdef USE_LIBIAF
		iaf_passwd = passwd = get_iaf_password(pw);
#अण्णहा
		passwd = spw->sp_pwdp;
#endif /* USE_LIBIAF */
#endif

	/* check for locked account */
	जइ (passwd && *passwd) {
#ifdef LOCKED_PASSWD_STRING
		जइ (strcmp(passwd, LOCKED_PASSWD_STRING) == 0) {
			debug3_f("password matches locked string '%s'",
			    LOCKED_PASSWD_STRING);
			locked = 1;
		}
#endif
#ifdef LOCKED_PASSWD_PREFIX
		जइ (strncmp(passwd, LOCKED_PASSWD_PREFIX,
		    strlen(LOCKED_PASSWD_PREFIX)) == 0) {
			debug3_f("password matches locked prefix '%s'",
			    LOCKED_PASSWD_PREFIX);
			locked = 1;
		}
#endif
#ifdef LOCKED_PASSWD_SUBSTR
		जइ (strstr(passwd, LOCKED_PASSWD_SUBSTR)) {
			debug3_f("password matches locked substring '%s'",
			   LOCKED_PASSWD_SUBSTR);
			locked = 1;
		}
#endif
	}
#ifdef USE_LIBIAF
	जइ (iaf_passwd != रिक्त)
		freezero(iaf_passwd, strlen(iaf_passwd));
#endif /* USE_LIBIAF */

	प्रत्यागम locked;
}
