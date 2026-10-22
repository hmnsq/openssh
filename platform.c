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

#شامل "includes.h"

#شامل <stdarg.h>
#شامل <stdio.h>
#شامل <string.h>
#شامل <unistd.h>

#شامل "log.h"
#شامل "misc.h"
#شامل "servconf.h"
#شامل "sshkey.h"
#شامل "hostfile.h"
#شامل "auth.h"
#شامل "auth-pam.h"
#شامل "platform.h"

#شامل "openbsd-compat/openbsd-compat.h"

خارجی ServerOptions options;

/* return 1 if we are running with privilege to swap UIDs, 0 otherwise */
صحیح
platform_privileged_uidswap(خالی)
{
#اگر_تعریف_شدہ HAVE_CYGWIN
	/* uid 0 is not special on Cygwin so always try */
	واپس 1;
#ورنہ
	واپس (getuid() == 0 || geteuid() == 0);
#اگر_ختم
}

/*
 * This gets called before switching UIDs, and is called even when sshd is
 * not running as root.
 */
خالی
platform_setusercontext(ساخت passwd *pw)
{
#اگر_تعریف_شدہ WITH_SELINUX
	/* Cache selinux status for later use */
	(خالی)ssh_selinux_enabled();
#اگر_ختم

#اگر_تعریف_شدہ USE_SOLARIS_PROJECTS
	/*
	 * If solaris projects were detected, set the default now, unless
	 * we are using PAM in which case it is the responsibility of the
	 * PAM stack.
	 */
	اگر (!options.use_pam && (getuid() == 0 || geteuid() == 0))
		solaris_سیٹ_default_project(pw);
#اگر_ختم

#اگر defined(HAVE_LOGIN_CAP) && defined (__bsdi__)
	اگر (getuid() == 0 || geteuid() == 0)
		setpgid(0, 0);
# endif

#اگر defined(HAVE_LOGIN_CAP) && defined(USE_PAM)
	/*
	 * If we have both LOGIN_CAP and PAM, we want to establish creds
	 * before calling setusercontext (in session.c:do_setusercontext).
	 */
	اگر (getuid() == 0 || geteuid() == 0) {
		اگر (options.use_pam) {
			do_pam_setcred();
		}
	}
# endif /* USE_PAM */

#اگر !defined(HAVE_LOGIN_CAP) && defined(HAVE_GETLUID) && defined(HAVE_SETLUID)
	اگر (getuid() == 0 || geteuid() == 0) {
		/* Sets login uid for accounting */
		اگر (getluid() == -1 && setluid(pw->pw_uid) == -1)
			error("setluid: %s", strerror(errno));
	}
#اگر_ختم
}

/*
 * This gets called after we've established the user's groups, and is only
 * called if sshd is running as root.
 */
خالی
platform_setusercontext_post_groups(ساخت passwd *pw)
{
#اگر !defined(HAVE_LOGIN_CAP) && defined(USE_PAM)
	/*
	 * PAM credentials may take the form of supplementary groups.
	 * These will have been wiped by the above initgroups() call.
	 * Reestablish them here.
	 */
	اگر (options.use_pam) {
		do_pam_setcred();
	}
#اگر_ختم /* USE_PAM */

#اگر !defined(HAVE_LOGIN_CAP) && (defined(WITH_IRIX_PROJECT) || \
    defined(WITH_IRIX_JOBS) || defined(WITH_IRIX_ARRAY))
	irix_setusercontext(pw);
#اگر_ختم /* defined(WITH_IRIX_PROJECT) || defined(WITH_IRIX_JOBS) || defined(WITH_IRIX_ARRAY) */

#اگر_تعریف_شدہ _AIX
	aix_usrinfo(pw);
#اگر_ختم /* _AIX */

#اگر_تعریف_شدہ HAVE_SETPCRED
	/*
	 * If we have a chroot directory, we set all creds except real
	 * uid which we will need for chroot.  If we don't have a
	 * chroot directory, we don't override anything.
	 */
	{
		حرف **creds = تہی, *chroot_creds[] =
		    { "REAL_USER=root", تہی };

		اگر (options.chroot_directory != تہی &&
		    strcasecmp(options.chroot_directory, "none") != 0)
			creds = chroot_creds;

		اگر (setpcred(pw->pw_name, creds) == -1)
			fatal("Failed to set process credentials");
	}
#اگر_ختم /* HAVE_SETPCRED */
#اگر_تعریف_شدہ WITH_SELINUX
	ssh_selinux_تیاری_exec_context(pw->pw_name);
#اگر_ختم
}

حرف *
platform_krb5_get_principal_name(ثابت حرف *pw_name)
{
#اگر_تعریف_شدہ USE_AIX_KRB_NAME
	واپس aix_krb5_get_principal_name(pw_name);
#ورنہ
	واپس تہی;
#اگر_ختم
}

/* returns 1 if account is locked */
صحیح
platform_locked_account(ساخت passwd *pw)
{
	صحیح locked = 0;
	حرف *passwd = pw->pw_passwd;
#اگر_تعریف_شدہ USE_SHADOW
	ساخت spwd *spw = تہی;
#اگر_تعریف_شدہ USE_LIBIAF
	حرف *iaf_passwd = تہی;
#اگر_ختم

	spw = getspnam(pw->pw_name);
#اگر_تعریف_شدہ HAS_SHADOW_EXPIRE
	اگر (spw != تہی && auth_shadow_acctexpired(spw))
		واپس 1;
#اگر_ختم /* HAS_SHADOW_EXPIRE */

	اگر (spw != تہی)
#اگر_تعریف_شدہ USE_LIBIAF
		iaf_passwd = passwd = get_iaf_password(pw);
#ورنہ
		passwd = spw->sp_pwdp;
#اگر_ختم /* USE_LIBIAF */
#اگر_ختم

	/* check for locked account */
	اگر (passwd && *passwd) {
#اگر_تعریف_شدہ LOCKED_PASSWD_STRING
		اگر (strcmp(passwd, LOCKED_PASSWD_STRING) == 0) {
			debug3_f("password matches locked string '%s'",
			    LOCKED_PASSWD_STRING);
			locked = 1;
		}
#اگر_ختم
#اگر_تعریف_شدہ LOCKED_PASSWD_سابقہ
		اگر (لڑی_موازنہ(passwd, LOCKED_PASSWD_سابقہ,
		    لڑی_لمبائی(LOCKED_PASSWD_سابقہ)) == 0) {
			debug3_f("password matches locked prefix '%s'",
			    LOCKED_PASSWD_سابقہ);
			locked = 1;
		}
#اگر_ختم
#اگر_تعریف_شدہ LOCKED_PASSWD_SUBSTR
		اگر (لڑی_تلاش(passwd, LOCKED_PASSWD_SUBSTR)) {
			debug3_f("password matches locked substring '%s'",
			   LOCKED_PASSWD_SUBSTR);
			locked = 1;
		}
#اگر_ختم
	}
#اگر_تعریف_شدہ USE_LIBIAF
	اگر (iaf_passwd != تہی)
		freezero(iaf_passwd, لڑی_لمبائی(iaf_passwd));
#اگر_ختم /* USE_LIBIAF */

	واپس locked;
}
