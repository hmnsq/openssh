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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <stdarg.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <unistd.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "log.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "misc.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "servconf.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshkey.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "hostfile.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "auth.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "auth-pam.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "platform.h"

#ਅਨ੍ਤਰ੍ਭਾਵ "openbsd-compat/openbsd-compat.h"

ਬਾਹਰੀ ServerOptions options;

/* return 1 if we are running with privilege to swap UIDs, 0 otherwise */
ਪੂਰਨ
platform_privileged_uidswap(ਖਾਲੀ)
{
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_CYGWIN
	/* uid 0 is not special on Cygwin so always try */
	ਵਾਪਸ 1;
#ਨਹੀਂਤਾਂ
	ਵਾਪਸ (getuid() == 0 || geteuid() == 0);
#ਜੇ_ਅੰਤ
}

/*
 * This gets called before switching UIDs, and is called even when sshd is
 * not running as root.
 */
ਖਾਲੀ
platform_setusercontext(ਬਣਤਰ passwd *pw)
{
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_SELINUX
	/* Cache selinux status for later use */
	(ਖਾਲੀ)ssh_selinux_enabled();
#ਜੇ_ਅੰਤ

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ USE_SOLARIS_PROJECTS
	/*
	 * If solaris projects were detected, set the default now, unless
	 * we are using PAM in which case it is the responsibility of the
	 * PAM stack.
	 */
	ਜੇ (!options.use_pam && (getuid() == 0 || geteuid() == 0))
		solaris_ਸੈੱਟ_default_project(pw);
#ਜੇ_ਅੰਤ

#ਜੇ defined(HAVE_LOGIN_CAP) && defined (__bsdi__)
	ਜੇ (getuid() == 0 || geteuid() == 0)
		setpgid(0, 0);
# endif

#ਜੇ defined(HAVE_LOGIN_CAP) && defined(USE_PAM)
	/*
	 * If we have both LOGIN_CAP and PAM, we want to establish creds
	 * before calling setusercontext (in session.c:do_setusercontext).
	 */
	ਜੇ (getuid() == 0 || geteuid() == 0) {
		ਜੇ (options.use_pam) {
			do_pam_setcred();
		}
	}
# endif /* USE_PAM */

#ਜੇ !defined(HAVE_LOGIN_CAP) && defined(HAVE_GETLUID) && defined(HAVE_SETLUID)
	ਜੇ (getuid() == 0 || geteuid() == 0) {
		/* Sets login uid for accounting */
		ਜੇ (getluid() == -1 && setluid(pw->pw_uid) == -1)
			error("setluid: %s", strerror(errno));
	}
#ਜੇ_ਅੰਤ
}

/*
 * This gets called after we've established the user's groups, and is only
 * called if sshd is running as root.
 */
ਖਾਲੀ
platform_setusercontext_post_groups(ਬਣਤਰ passwd *pw)
{
#ਜੇ !defined(HAVE_LOGIN_CAP) && defined(USE_PAM)
	/*
	 * PAM credentials may take the form of supplementary groups.
	 * These will have been wiped by the above initgroups() call.
	 * Reestablish them here.
	 */
	ਜੇ (options.use_pam) {
		do_pam_setcred();
	}
#ਜੇ_ਅੰਤ /* USE_PAM */

#ਜੇ !defined(HAVE_LOGIN_CAP) && (defined(WITH_IRIX_PROJECT) || \
    defined(WITH_IRIX_JOBS) || defined(WITH_IRIX_ARRAY))
	irix_setusercontext(pw);
#ਜੇ_ਅੰਤ /* defined(WITH_IRIX_PROJECT) || defined(WITH_IRIX_JOBS) || defined(WITH_IRIX_ARRAY) */

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ _AIX
	aix_usrinfo(pw);
#ਜੇ_ਅੰਤ /* _AIX */

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_SETPCRED
	/*
	 * If we have a chroot directory, we set all creds except real
	 * uid which we will need for chroot.  If we don't have a
	 * chroot directory, we don't override anything.
	 */
	{
		ਅੱਖਰ **creds = ਨਿਰਾ, *chroot_creds[] =
		    { "REAL_USER=root", ਨਿਰਾ };

		ਜੇ (options.chroot_directory != ਨਿਰਾ &&
		    strcasecmp(options.chroot_directory, "none") != 0)
			creds = chroot_creds;

		ਜੇ (setpcred(pw->pw_name, creds) == -1)
			fatal("Failed to set process credentials");
	}
#ਜੇ_ਅੰਤ /* HAVE_SETPCRED */
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_SELINUX
	ssh_selinux_ਤਿਆਰੀ_exec_context(pw->pw_name);
#ਜੇ_ਅੰਤ
}

ਅੱਖਰ *
platform_krb5_get_principal_name(ਅਚਲ ਅੱਖਰ *pw_name)
{
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ USE_AIX_KRB_NAME
	ਵਾਪਸ aix_krb5_get_principal_name(pw_name);
#ਨਹੀਂਤਾਂ
	ਵਾਪਸ ਨਿਰਾ;
#ਜੇ_ਅੰਤ
}

/* returns 1 if account is locked */
ਪੂਰਨ
platform_locked_account(ਬਣਤਰ passwd *pw)
{
	ਪੂਰਨ locked = 0;
	ਅੱਖਰ *passwd = pw->pw_passwd;
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ USE_SHADOW
	ਬਣਤਰ spwd *spw = ਨਿਰਾ;
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ USE_LIBIAF
	ਅੱਖਰ *iaf_passwd = ਨਿਰਾ;
#ਜੇ_ਅੰਤ

	spw = getspnam(pw->pw_name);
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAS_SHADOW_EXPIRE
	ਜੇ (spw != ਨਿਰਾ && auth_shadow_acctexpired(spw))
		ਵਾਪਸ 1;
#ਜੇ_ਅੰਤ /* HAS_SHADOW_EXPIRE */

	ਜੇ (spw != ਨਿਰਾ)
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ USE_LIBIAF
		iaf_passwd = passwd = get_iaf_password(pw);
#ਨਹੀਂਤਾਂ
		passwd = spw->sp_pwdp;
#ਜੇ_ਅੰਤ /* USE_LIBIAF */
#ਜੇ_ਅੰਤ

	/* check for locked account */
	ਜੇ (passwd && *passwd) {
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ LOCKED_PASSWD_STRING
		ਜੇ (strcmp(passwd, LOCKED_PASSWD_STRING) == 0) {
			debug3_f("password matches locked string '%s'",
			    LOCKED_PASSWD_STRING);
			locked = 1;
		}
#ਜੇ_ਅੰਤ
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ LOCKED_PASSWD_ਅਗੇਤਰ
		ਜੇ (ਲੜੀ_ਤੁਲਨਾ(passwd, LOCKED_PASSWD_ਅਗੇਤਰ,
		    ਲੜੀ_ਲੰਬਾਈ(LOCKED_PASSWD_ਅਗੇਤਰ)) == 0) {
			debug3_f("password matches locked prefix '%s'",
			    LOCKED_PASSWD_ਅਗੇਤਰ);
			locked = 1;
		}
#ਜੇ_ਅੰਤ
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ LOCKED_PASSWD_SUBSTR
		ਜੇ (ਲੜੀ_ਖੋਜ(passwd, LOCKED_PASSWD_SUBSTR)) {
			debug3_f("password matches locked substring '%s'",
			   LOCKED_PASSWD_SUBSTR);
			locked = 1;
		}
#ਜੇ_ਅੰਤ
	}
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ USE_LIBIAF
	ਜੇ (iaf_passwd != ਨਿਰਾ)
		freezero(iaf_passwd, ਲੜੀ_ਲੰਬਾਈ(iaf_passwd));
#ਜੇ_ਅੰਤ /* USE_LIBIAF */

	ਵਾਪਸ locked;
}
