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

#అన్తర్భావ "includes.h"

#అన్తర్భావ <stdarg.h>
#అన్తర్భావ <stdio.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <unistd.h>

#అన్తర్భావ "log.h"
#అన్తర్భావ "misc.h"
#అన్తర్భావ "servconf.h"
#అన్తర్భావ "sshkey.h"
#అన్తర్భావ "hostfile.h"
#అన్తర్భావ "auth.h"
#అన్తర్భావ "auth-pam.h"
#అన్తర్భావ "platform.h"

#అన్తర్భావ "openbsd-compat/openbsd-compat.h"

బాహ్య ServerOptions options;

/* return 1 if we are running with privilege to swap UIDs, 0 otherwise */
పూర్ణాంకం
platform_privileged_uidswap(శూన్య)
{
#నిర్వచితమైతే HAVE_CYGWIN
	/* uid 0 is not special on Cygwin so always try */
	తిరిగి 1;
#లేకపోతే
	తిరిగి (getuid() == 0 || geteuid() == 0);
#అయితే_ముగింపు
}

/*
 * This gets called before switching UIDs, and is called even when sshd is
 * not running as root.
 */
శూన్య
platform_setusercontext(నిర్మాణం passwd *pw)
{
#నిర్వచితమైతే WITH_SELINUX
	/* Cache selinux status for later use */
	(శూన్య)ssh_selinux_enabled();
#అయితే_ముగింపు

#నిర్వచితమైతే USE_SOLARIS_PROJECTS
	/*
	 * If solaris projects were detected, set the default now, unless
	 * we are using PAM in which case it is the responsibility of the
	 * PAM stack.
	 */
	ఒకవేళ (!options.use_pam && (getuid() == 0 || geteuid() == 0))
		solaris_సమితి_default_project(pw);
#అయితే_ముగింపు

#ఒకవేళ defined(HAVE_LOGIN_CAP) && defined (__bsdi__)
	ఒకవేళ (getuid() == 0 || geteuid() == 0)
		setpgid(0, 0);
# endif

#ఒకవేళ defined(HAVE_LOGIN_CAP) && defined(USE_PAM)
	/*
	 * If we have both LOGIN_CAP and PAM, we want to establish creds
	 * before calling setusercontext (in session.c:do_setusercontext).
	 */
	ఒకవేళ (getuid() == 0 || geteuid() == 0) {
		ఒకవేళ (options.use_pam) {
			do_pam_setcred();
		}
	}
# endif /* USE_PAM */

#ఒకవేళ !defined(HAVE_LOGIN_CAP) && defined(HAVE_GETLUID) && defined(HAVE_SETLUID)
	ఒకవేళ (getuid() == 0 || geteuid() == 0) {
		/* Sets login uid for accounting */
		ఒకవేళ (getluid() == -1 && setluid(pw->pw_uid) == -1)
			error("setluid: %s", strerror(errno));
	}
#అయితే_ముగింపు
}

/*
 * This gets called after we've established the user's groups, and is only
 * called if sshd is running as root.
 */
శూన్య
platform_setusercontext_post_groups(నిర్మాణం passwd *pw)
{
#ఒకవేళ !defined(HAVE_LOGIN_CAP) && defined(USE_PAM)
	/*
	 * PAM credentials may take the form of supplementary groups.
	 * These will have been wiped by the above initgroups() call.
	 * Reestablish them here.
	 */
	ఒకవేళ (options.use_pam) {
		do_pam_setcred();
	}
#అయితే_ముగింపు /* USE_PAM */

#ఒకవేళ !defined(HAVE_LOGIN_CAP) && (defined(WITH_IRIX_PROJECT) || \
    defined(WITH_IRIX_JOBS) || defined(WITH_IRIX_ARRAY))
	irix_setusercontext(pw);
#అయితే_ముగింపు /* defined(WITH_IRIX_PROJECT) || defined(WITH_IRIX_JOBS) || defined(WITH_IRIX_ARRAY) */

#నిర్వచితమైతే _AIX
	aix_usrinfo(pw);
#అయితే_ముగింపు /* _AIX */

#నిర్వచితమైతే HAVE_SETPCRED
	/*
	 * If we have a chroot directory, we set all creds except real
	 * uid which we will need for chroot.  If we don't have a
	 * chroot directory, we don't override anything.
	 */
	{
		అక్షరం **creds = ఖాళీ, *chroot_creds[] =
		    { "REAL_USER=root", ఖాళీ };

		ఒకవేళ (options.chroot_directory != ఖాళీ &&
		    strcasecmp(options.chroot_directory, "none") != 0)
			creds = chroot_creds;

		ఒకవేళ (setpcred(pw->pw_name, creds) == -1)
			fatal("Failed to set process credentials");
	}
#అయితే_ముగింపు /* HAVE_SETPCRED */
#నిర్వచితమైతే WITH_SELINUX
	ssh_selinux_అమరిక_exec_context(pw->pw_name);
#అయితే_ముగింపు
}

అక్షరం *
platform_krb5_get_principal_name(స్థిరరాశి అక్షరం *pw_name)
{
#నిర్వచితమైతే USE_AIX_KRB_NAME
	తిరిగి aix_krb5_get_principal_name(pw_name);
#లేకపోతే
	తిరిగి ఖాళీ;
#అయితే_ముగింపు
}

/* returns 1 if account is locked */
పూర్ణాంకం
platform_locked_account(నిర్మాణం passwd *pw)
{
	పూర్ణాంకం locked = 0;
	అక్షరం *passwd = pw->pw_passwd;
#నిర్వచితమైతే USE_SHADOW
	నిర్మాణం spwd *spw = ఖాళీ;
#నిర్వచితమైతే USE_LIBIAF
	అక్షరం *iaf_passwd = ఖాళీ;
#అయితే_ముగింపు

	spw = getspnam(pw->pw_name);
#నిర్వచితమైతే HAS_SHADOW_EXPIRE
	ఒకవేళ (spw != ఖాళీ && auth_shadow_acctexpired(spw))
		తిరిగి 1;
#అయితే_ముగింపు /* HAS_SHADOW_EXPIRE */

	ఒకవేళ (spw != ఖాళీ)
#నిర్వచితమైతే USE_LIBIAF
		iaf_passwd = passwd = get_iaf_password(pw);
#లేకపోతే
		passwd = spw->sp_pwdp;
#అయితే_ముగింపు /* USE_LIBIAF */
#అయితే_ముగింపు

	/* check for locked account */
	ఒకవేళ (passwd && *passwd) {
#నిర్వచితమైతే LOCKED_PASSWD_STRING
		ఒకవేళ (strcmp(passwd, LOCKED_PASSWD_STRING) == 0) {
			debug3_f("password matches locked string '%s'",
			    LOCKED_PASSWD_STRING);
			locked = 1;
		}
#అయితే_ముగింపు
#నిర్వచితమైతే LOCKED_PASSWD_ఉపసర్గ
		ఒకవేళ (అక్షరశ్రేణి_పోలిక(passwd, LOCKED_PASSWD_ఉపసర్గ,
		    అక్షరశ్రేణి_పొడవు(LOCKED_PASSWD_ఉపసర్గ)) == 0) {
			debug3_f("password matches locked prefix '%s'",
			    LOCKED_PASSWD_ఉపసర్గ);
			locked = 1;
		}
#అయితే_ముగింపు
#నిర్వచితమైతే LOCKED_PASSWD_SUBSTR
		ఒకవేళ (అక్షరశ్రేణి_శోధన(passwd, LOCKED_PASSWD_SUBSTR)) {
			debug3_f("password matches locked substring '%s'",
			   LOCKED_PASSWD_SUBSTR);
			locked = 1;
		}
#అయితే_ముగింపు
	}
#నిర్వచితమైతే USE_LIBIAF
	ఒకవేళ (iaf_passwd != ఖాళీ)
		freezero(iaf_passwd, అక్షరశ్రేణి_పొడవు(iaf_passwd));
#అయితే_ముగింపు /* USE_LIBIAF */

	తిరిగి locked;
}
