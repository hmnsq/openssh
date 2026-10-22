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
#यदि_परिभाषितम् HAVE_CYGWIN
	/* uid 0 is not special on Cygwin so always try */
	प्रत्यागम 1;
#अन्यथा
	प्रत्यागम (getuid() == 0 || geteuid() == 0);
#यदि_अन्तः
}

/*
 * This gets called before switching UIDs, and is called even when sshd is
 * not running as root.
 */
शून्य
platform_setusercontext(संरचना passwd *pw)
{
#यदि_परिभाषितम् WITH_SELINUX
	/* Cache selinux status for later use */
	(शून्य)ssh_selinux_enabled();
#यदि_अन्तः

#यदि_परिभाषितम् USE_SOLARIS_PROJECTS
	/*
	 * If solaris projects were detected, set the default now, unless
	 * we are using PAM in which case it is the responsibility of the
	 * PAM stack.
	 */
	यदि (!options.use_pam && (getuid() == 0 || geteuid() == 0))
		solaris_समुच्चयः_default_project(pw);
#यदि_अन्तः

#यदि defined(HAVE_LOGIN_CAP) && defined (__bsdi__)
	यदि (getuid() == 0 || geteuid() == 0)
		setpgid(0, 0);
# endif

#यदि defined(HAVE_LOGIN_CAP) && defined(USE_PAM)
	/*
	 * If we have both LOGIN_CAP and PAM, we want to establish creds
	 * before calling setusercontext (in session.c:do_setusercontext).
	 */
	यदि (getuid() == 0 || geteuid() == 0) {
		यदि (options.use_pam) {
			do_pam_setcred();
		}
	}
# endif /* USE_PAM */

#यदि !defined(HAVE_LOGIN_CAP) && defined(HAVE_GETLUID) && defined(HAVE_SETLUID)
	यदि (getuid() == 0 || geteuid() == 0) {
		/* Sets login uid for accounting */
		यदि (getluid() == -1 && setluid(pw->pw_uid) == -1)
			error("setluid: %s", strerror(errno));
	}
#यदि_अन्तः
}

/*
 * This gets called after we've established the user's groups, and is only
 * called if sshd is running as root.
 */
शून्य
platform_setusercontext_post_groups(संरचना passwd *pw)
{
#यदि !defined(HAVE_LOGIN_CAP) && defined(USE_PAM)
	/*
	 * PAM credentials may take the form of supplementary groups.
	 * These will have been wiped by the above initgroups() call.
	 * Reestablish them here.
	 */
	यदि (options.use_pam) {
		do_pam_setcred();
	}
#यदि_अन्तः /* USE_PAM */

#यदि !defined(HAVE_LOGIN_CAP) && (defined(WITH_IRIX_PROJECT) || \
    defined(WITH_IRIX_JOBS) || defined(WITH_IRIX_ARRAY))
	irix_setusercontext(pw);
#यदि_अन्तः /* defined(WITH_IRIX_PROJECT) || defined(WITH_IRIX_JOBS) || defined(WITH_IRIX_ARRAY) */

#यदि_परिभाषितम् _AIX
	aix_usrinfo(pw);
#यदि_अन्तः /* _AIX */

#यदि_परिभाषितम् HAVE_SETPCRED
	/*
	 * If we have a chroot directory, we set all creds except real
	 * uid which we will need for chroot.  If we don't have a
	 * chroot directory, we don't override anything.
	 */
	{
		वर्ण **creds = रिक्त, *chroot_creds[] =
		    { "REAL_USER=root", रिक्त };

		यदि (options.chroot_directory != रिक्त &&
		    strcasecmp(options.chroot_directory, "none") != 0)
			creds = chroot_creds;

		यदि (setpcred(pw->pw_name, creds) == -1)
			fatal("Failed to set process credentials");
	}
#यदि_अन्तः /* HAVE_SETPCRED */
#यदि_परिभाषितम् WITH_SELINUX
	ssh_selinux_सज्जता_exec_context(pw->pw_name);
#यदि_अन्तः
}

वर्ण *
platform_krb5_get_principal_name(ध्रुव वर्ण *pw_name)
{
#यदि_परिभाषितम् USE_AIX_KRB_NAME
	प्रत्यागम aix_krb5_get_principal_name(pw_name);
#अन्यथा
	प्रत्यागम रिक्त;
#यदि_अन्तः
}

/* returns 1 if account is locked */
पूर्णाङ्क
platform_locked_account(संरचना passwd *pw)
{
	पूर्णाङ्क locked = 0;
	वर्ण *passwd = pw->pw_passwd;
#यदि_परिभाषितम् USE_SHADOW
	संरचना spwd *spw = रिक्त;
#यदि_परिभाषितम् USE_LIBIAF
	वर्ण *iaf_passwd = रिक्त;
#यदि_अन्तः

	spw = getspnam(pw->pw_name);
#यदि_परिभाषितम् HAS_SHADOW_EXPIRE
	यदि (spw != रिक्त && auth_shadow_acctexpired(spw))
		प्रत्यागम 1;
#यदि_अन्तः /* HAS_SHADOW_EXPIRE */

	यदि (spw != रिक्त)
#यदि_परिभाषितम् USE_LIBIAF
		iaf_passwd = passwd = get_iaf_password(pw);
#अन्यथा
		passwd = spw->sp_pwdp;
#यदि_अन्तः /* USE_LIBIAF */
#यदि_अन्तः

	/* check for locked account */
	यदि (passwd && *passwd) {
#यदि_परिभाषितम् LOCKED_PASSWD_STRING
		यदि (वाक्यं_तुलय(passwd, LOCKED_PASSWD_STRING) == 0) {
			debug3_f("password matches locked string '%s'",
			    LOCKED_PASSWD_STRING);
			locked = 1;
		}
#यदि_अन्तः
#यदि_परिभाषितम् LOCKED_PASSWD_उपसर्गः
		यदि (वाक्ये_तुलय(passwd, LOCKED_PASSWD_उपसर्गः,
		    वाक्यदैर्घ्यम्(LOCKED_PASSWD_उपसर्गः)) == 0) {
			debug3_f("password matches locked prefix '%s'",
			    LOCKED_PASSWD_उपसर्गः);
			locked = 1;
		}
#यदि_अन्तः
#यदि_परिभाषितम् LOCKED_PASSWD_SUBSTR
		यदि (वाक्ये_अन्विष(passwd, LOCKED_PASSWD_SUBSTR)) {
			debug3_f("password matches locked substring '%s'",
			   LOCKED_PASSWD_SUBSTR);
			locked = 1;
		}
#यदि_अन्तः
	}
#यदि_परिभाषितम् USE_LIBIAF
	यदि (iaf_passwd != रिक्त)
		freezero(iaf_passwd, वाक्यदैर्घ्यम्(iaf_passwd));
#यदि_अन्तः /* USE_LIBIAF */

	प्रत्यागम locked;
}
