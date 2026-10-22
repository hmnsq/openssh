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

#অন্তর্ভাব "includes.h"

#অন্তর্ভাব <stdarg.h>
#অন্তর্ভাব <stdio.h>
#অন্তর্ভাব <string.h>
#অন্তর্ভাব <unistd.h>

#অন্তর্ভাব "log.h"
#অন্তর্ভাব "misc.h"
#অন্তর্ভাব "servconf.h"
#অন্তর্ভাব "sshkey.h"
#অন্তর্ভাব "hostfile.h"
#অন্তর্ভাব "auth.h"
#অন্তর্ভাব "auth-pam.h"
#অন্তর্ভাব "platform.h"

#অন্তর্ভাব "openbsd-compat/openbsd-compat.h"

বাহ্যিক ServerOptions options;

/* return 1 if we are running with privilege to swap UIDs, 0 otherwise */
পূর্ণসংখ্যা
platform_privileged_uidswap(শূন্য)
{
#ifdef HAVE_CYGWIN
	/* uid 0 is not special on Cygwin so always try */
	ফেরত 1;
#অন্যথা
	ফেরত (getuid() == 0 || geteuid() == 0);
#endif
}

/*
 * This gets called before switching UIDs, and is called even when sshd is
 * not running as root.
 */
শূন্য
platform_setusercontext(কাঠামো passwd *pw)
{
#ifdef WITH_SELINUX
	/* Cache selinux status for later use */
	(শূন্য)ssh_selinux_enabled();
#endif

#ifdef USE_SOLARIS_PROJECTS
	/*
	 * If solaris projects were detected, set the default now, unless
	 * we are using PAM in which case it is the responsibility of the
	 * PAM stack.
	 */
	যদি (!options.use_pam && (getuid() == 0 || geteuid() == 0))
		solaris_set_default_project(pw);
#endif

#যদি defined(HAVE_LOGIN_CAP) && defined (__bsdi__)
	যদি (getuid() == 0 || geteuid() == 0)
		setpgid(0, 0);
# endif

#যদি defined(HAVE_LOGIN_CAP) && defined(USE_PAM)
	/*
	 * If we have both LOGIN_CAP and PAM, we want to establish creds
	 * before calling setusercontext (in session.c:do_setusercontext).
	 */
	যদি (getuid() == 0 || geteuid() == 0) {
		যদি (options.use_pam) {
			do_pam_setcred();
		}
	}
# endif /* USE_PAM */

#যদি !defined(HAVE_LOGIN_CAP) && defined(HAVE_GETLUID) && defined(HAVE_SETLUID)
	যদি (getuid() == 0 || geteuid() == 0) {
		/* Sets login uid for accounting */
		যদি (getluid() == -1 && setluid(pw->pw_uid) == -1)
			error("setluid: %s", strerror(errno));
	}
#endif
}

/*
 * This gets called after we've established the user's groups, and is only
 * called if sshd is running as root.
 */
শূন্য
platform_setusercontext_post_groups(কাঠামো passwd *pw)
{
#যদি !defined(HAVE_LOGIN_CAP) && defined(USE_PAM)
	/*
	 * PAM credentials may take the form of supplementary groups.
	 * These will have been wiped by the above initgroups() call.
	 * Reestablish them here.
	 */
	যদি (options.use_pam) {
		do_pam_setcred();
	}
#endif /* USE_PAM */

#যদি !defined(HAVE_LOGIN_CAP) && (defined(WITH_IRIX_PROJECT) || \
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
		অক্ষর **creds = ফাঁকা, *chroot_creds[] =
		    { "REAL_USER=root", ফাঁকা };

		যদি (options.chroot_directory != ফাঁকা &&
		    strcasecmp(options.chroot_directory, "none") != 0)
			creds = chroot_creds;

		যদি (setpcred(pw->pw_name, creds) == -1)
			fatal("Failed to set process credentials");
	}
#endif /* HAVE_SETPCRED */
#ifdef WITH_SELINUX
	ssh_selinux_setup_exec_context(pw->pw_name);
#endif
}

অক্ষর *
platform_krb5_get_principal_name(ধ্রুবক অক্ষর *pw_name)
{
#ifdef USE_AIX_KRB_NAME
	ফেরত aix_krb5_get_principal_name(pw_name);
#অন্যথা
	ফেরত ফাঁকা;
#endif
}

/* returns 1 if account is locked */
পূর্ণসংখ্যা
platform_locked_account(কাঠামো passwd *pw)
{
	পূর্ণসংখ্যা locked = 0;
	অক্ষর *passwd = pw->pw_passwd;
#ifdef USE_SHADOW
	কাঠামো spwd *spw = ফাঁকা;
#ifdef USE_LIBIAF
	অক্ষর *iaf_passwd = ফাঁকা;
#endif

	spw = getspnam(pw->pw_name);
#ifdef HAS_SHADOW_EXPIRE
	যদি (spw != ফাঁকা && auth_shadow_acctexpired(spw))
		ফেরত 1;
#endif /* HAS_SHADOW_EXPIRE */

	যদি (spw != ফাঁকা)
#ifdef USE_LIBIAF
		iaf_passwd = passwd = get_iaf_password(pw);
#অন্যথা
		passwd = spw->sp_pwdp;
#endif /* USE_LIBIAF */
#endif

	/* check for locked account */
	যদি (passwd && *passwd) {
#ifdef LOCKED_PASSWD_STRING
		যদি (strcmp(passwd, LOCKED_PASSWD_STRING) == 0) {
			debug3_f("password matches locked string '%s'",
			    LOCKED_PASSWD_STRING);
			locked = 1;
		}
#endif
#ifdef LOCKED_PASSWD_PREFIX
		যদি (strncmp(passwd, LOCKED_PASSWD_PREFIX,
		    strlen(LOCKED_PASSWD_PREFIX)) == 0) {
			debug3_f("password matches locked prefix '%s'",
			    LOCKED_PASSWD_PREFIX);
			locked = 1;
		}
#endif
#ifdef LOCKED_PASSWD_SUBSTR
		যদি (strstr(passwd, LOCKED_PASSWD_SUBSTR)) {
			debug3_f("password matches locked substring '%s'",
			   LOCKED_PASSWD_SUBSTR);
			locked = 1;
		}
#endif
	}
#ifdef USE_LIBIAF
	যদি (iaf_passwd != ফাঁকা)
		freezero(iaf_passwd, strlen(iaf_passwd));
#endif /* USE_LIBIAF */

	ফেরত locked;
}
