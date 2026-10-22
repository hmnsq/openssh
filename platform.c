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

#ضمن "includes.h"

#ضمن <stdarg.h>
#ضمن <stdio.h>
#ضمن <string.h>
#ضمن <unistd.h>

#ضمن "log.h"
#ضمن "misc.h"
#ضمن "servconf.h"
#ضمن "sshkey.h"
#ضمن "hostfile.h"
#ضمن "auth.h"
#ضمن "auth-pam.h"
#ضمن "platform.h"

#ضمن "openbsd-compat/openbsd-compat.h"

خارجي ServerOptions options;

/* return 1 if we are running with privilege to swap UIDs, 0 otherwise */
صحيح
platform_privileged_uidswap(فراغ)
{
#ifdef HAVE_CYGWIN
	/* uid 0 is not special on Cygwin so always try */
	החזר 1;
#אחרת
	החזר (getuid() == 0 || geteuid() == 0);
#endif
}

/*
 * This gets called before switching UIDs, and is called even when sshd is
 * not running as root.
 */
فراغ
platform_setusercontext(بنية passwd *pw)
{
#ifdef WITH_SELINUX
	/* Cache selinux status for later use */
	(فراغ)ssh_selinux_enabled();
#endif

#ifdef USE_SOLARIS_PROJECTS
	/*
	 * If solaris projects were detected, set the default now, unless
	 * we are using PAM in which case it is the responsibility of the
	 * PAM stack.
	 */
	אם (!options.use_pam && (getuid() == 0 || geteuid() == 0))
		solaris_set_default_project(pw);
#endif

#אם defined(HAVE_LOGIN_CAP) && defined (__bsdi__)
	אם (getuid() == 0 || geteuid() == 0)
		setpgid(0, 0);
# endif

#אם defined(HAVE_LOGIN_CAP) && defined(USE_PAM)
	/*
	 * If we have both LOGIN_CAP and PAM, we want to establish creds
	 * before calling setusercontext (in session.c:do_setusercontext).
	 */
	אם (getuid() == 0 || geteuid() == 0) {
		אם (options.use_pam) {
			do_pam_setcred();
		}
	}
# endif /* USE_PAM */

#אם !defined(HAVE_LOGIN_CAP) && defined(HAVE_GETLUID) && defined(HAVE_SETLUID)
	אם (getuid() == 0 || geteuid() == 0) {
		/* Sets login uid for accounting */
		אם (getluid() == -1 && setluid(pw->pw_uid) == -1)
			error("setluid: %s", strerror(errno));
	}
#endif
}

/*
 * This gets called after we've established the user's groups, and is only
 * called if sshd is running as root.
 */
فراغ
platform_setusercontext_post_groups(بنية passwd *pw)
{
#אם !defined(HAVE_LOGIN_CAP) && defined(USE_PAM)
	/*
	 * PAM credentials may take the form of supplementary groups.
	 * These will have been wiped by the above initgroups() call.
	 * Reestablish them here.
	 */
	אם (options.use_pam) {
		do_pam_setcred();
	}
#endif /* USE_PAM */

#אם !defined(HAVE_LOGIN_CAP) && (defined(WITH_IRIX_PROJECT) || \
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
		حرف **creds = عدم, *chroot_creds[] =
		    { "REAL_USER=root", عدم };

		אם (options.chroot_directory != عدم &&
		    strcasecmp(options.chroot_directory, "none") != 0)
			creds = chroot_creds;

		אם (setpcred(pw->pw_name, creds) == -1)
			fatal("Failed to set process credentials");
	}
#endif /* HAVE_SETPCRED */
#ifdef WITH_SELINUX
	ssh_selinux_setup_exec_context(pw->pw_name);
#endif
}

حرف *
platform_krb5_get_principal_name(ثابت حرف *pw_name)
{
#ifdef USE_AIX_KRB_NAME
	החזר aix_krb5_get_principal_name(pw_name);
#אחרת
	החזר عدم;
#endif
}

/* returns 1 if account is locked */
صحيح
platform_locked_account(بنية passwd *pw)
{
	صحيح locked = 0;
	حرف *passwd = pw->pw_passwd;
#ifdef USE_SHADOW
	بنية spwd *spw = عدم;
#ifdef USE_LIBIAF
	حرف *iaf_passwd = عدم;
#endif

	spw = getspnam(pw->pw_name);
#ifdef HAS_SHADOW_EXPIRE
	אם (spw != عدم && auth_shadow_acctexpired(spw))
		החזר 1;
#endif /* HAS_SHADOW_EXPIRE */

	אם (spw != عدم)
#ifdef USE_LIBIAF
		iaf_passwd = passwd = get_iaf_password(pw);
#אחרת
		passwd = spw->sp_pwdp;
#endif /* USE_LIBIAF */
#endif

	/* check for locked account */
	אם (passwd && *passwd) {
#ifdef LOCKED_PASSWD_STRING
		אם (strcmp(passwd, LOCKED_PASSWD_STRING) == 0) {
			debug3_f("password matches locked string '%s'",
			    LOCKED_PASSWD_STRING);
			locked = 1;
		}
#endif
#ifdef LOCKED_PASSWD_PREFIX
		אם (strncmp(passwd, LOCKED_PASSWD_PREFIX,
		    strlen(LOCKED_PASSWD_PREFIX)) == 0) {
			debug3_f("password matches locked prefix '%s'",
			    LOCKED_PASSWD_PREFIX);
			locked = 1;
		}
#endif
#ifdef LOCKED_PASSWD_SUBSTR
		אם (strstr(passwd, LOCKED_PASSWD_SUBSTR)) {
			debug3_f("password matches locked substring '%s'",
			   LOCKED_PASSWD_SUBSTR);
			locked = 1;
		}
#endif
	}
#ifdef USE_LIBIAF
	אם (iaf_passwd != عدم)
		freezero(iaf_passwd, strlen(iaf_passwd));
#endif /* USE_LIBIAF */

	החזר locked;
}
