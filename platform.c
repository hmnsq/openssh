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

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ଅନ୍ତର୍ଭାଵ <stdarg.h>
#ଅନ୍ତର୍ଭାଵ <stdio.h>
#ଅନ୍ତର୍ଭାଵ <string.h>
#ଅନ୍ତର୍ଭାଵ <unistd.h>

#ଅନ୍ତର୍ଭାଵ "log.h"
#ଅନ୍ତର୍ଭାଵ "misc.h"
#ଅନ୍ତର୍ଭାଵ "servconf.h"
#ଅନ୍ତର୍ଭାଵ "sshkey.h"
#ଅନ୍ତର୍ଭାଵ "hostfile.h"
#ଅନ୍ତର୍ଭାଵ "auth.h"
#ଅନ୍ତର୍ଭାଵ "auth-pam.h"
#ଅନ୍ତର୍ଭାଵ "platform.h"

#ଅନ୍ତର୍ଭାଵ "openbsd-compat/openbsd-compat.h"

ବାହ୍ୟ ServerOptions options;

/* return 1 if we are running with privilege to swap UIDs, 0 otherwise */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
platform_privileged_uidswap(ଶୂନ୍ୟ)
{
#ifdef HAVE_CYGWIN
	/* uid 0 is not special on Cygwin so always try */
	ଫେରନ୍ତୁ 1;
#ଅନ୍ୟଥା
	ଫେରନ୍ତୁ (getuid() == 0 || geteuid() == 0);
#endif
}

/*
 * This gets called before switching UIDs, and is called even when sshd is
 * not running as root.
 */
ଶୂନ୍ୟ
platform_setusercontext(ସଂରଚନା passwd *pw)
{
#ifdef WITH_SELINUX
	/* Cache selinux status for later use */
	(ଶୂନ୍ୟ)ssh_selinux_enabled();
#endif

#ifdef USE_SOLARIS_PROJECTS
	/*
	 * If solaris projects were detected, set the default now, unless
	 * we are using PAM in which case it is the responsibility of the
	 * PAM stack.
	 */
	ଯଦି (!options.use_pam && (getuid() == 0 || geteuid() == 0))
		solaris_set_default_project(pw);
#endif

#ଯଦି defined(HAVE_LOGIN_CAP) && defined (__bsdi__)
	ଯଦି (getuid() == 0 || geteuid() == 0)
		setpgid(0, 0);
# endif

#ଯଦି defined(HAVE_LOGIN_CAP) && defined(USE_PAM)
	/*
	 * If we have both LOGIN_CAP and PAM, we want to establish creds
	 * before calling setusercontext (in session.c:do_setusercontext).
	 */
	ଯଦି (getuid() == 0 || geteuid() == 0) {
		ଯଦି (options.use_pam) {
			do_pam_setcred();
		}
	}
# endif /* USE_PAM */

#ଯଦି !defined(HAVE_LOGIN_CAP) && defined(HAVE_GETLUID) && defined(HAVE_SETLUID)
	ଯଦି (getuid() == 0 || geteuid() == 0) {
		/* Sets login uid for accounting */
		ଯଦି (getluid() == -1 && setluid(pw->pw_uid) == -1)
			error("setluid: %s", strerror(errno));
	}
#endif
}

/*
 * This gets called after we've established the user's groups, and is only
 * called if sshd is running as root.
 */
ଶୂନ୍ୟ
platform_setusercontext_post_groups(ସଂରଚନା passwd *pw)
{
#ଯଦି !defined(HAVE_LOGIN_CAP) && defined(USE_PAM)
	/*
	 * PAM credentials may take the form of supplementary groups.
	 * These will have been wiped by the above initgroups() call.
	 * Reestablish them here.
	 */
	ଯଦି (options.use_pam) {
		do_pam_setcred();
	}
#endif /* USE_PAM */

#ଯଦି !defined(HAVE_LOGIN_CAP) && (defined(WITH_IRIX_PROJECT) || \
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
		ଅକ୍ଷର **creds = ଖାଲି, *chroot_creds[] =
		    { "REAL_USER=root", ଖାଲି };

		ଯଦି (options.chroot_directory != ଖାଲି &&
		    strcasecmp(options.chroot_directory, "none") != 0)
			creds = chroot_creds;

		ଯଦି (setpcred(pw->pw_name, creds) == -1)
			fatal("Failed to set process credentials");
	}
#endif /* HAVE_SETPCRED */
#ifdef WITH_SELINUX
	ssh_selinux_setup_exec_context(pw->pw_name);
#endif
}

ଅକ୍ଷର *
platform_krb5_get_principal_name(ଅଚଳ ଅକ୍ଷର *pw_name)
{
#ifdef USE_AIX_KRB_NAME
	ଫେରନ୍ତୁ aix_krb5_get_principal_name(pw_name);
#ଅନ୍ୟଥା
	ଫେରନ୍ତୁ ଖାଲି;
#endif
}

/* returns 1 if account is locked */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
platform_locked_account(ସଂରଚନା passwd *pw)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା locked = 0;
	ଅକ୍ଷର *passwd = pw->pw_passwd;
#ifdef USE_SHADOW
	ସଂରଚନା spwd *spw = ଖାଲି;
#ifdef USE_LIBIAF
	ଅକ୍ଷର *iaf_passwd = ଖାଲି;
#endif

	spw = getspnam(pw->pw_name);
#ifdef HAS_SHADOW_EXPIRE
	ଯଦି (spw != ଖାଲି && auth_shadow_acctexpired(spw))
		ଫେରନ୍ତୁ 1;
#endif /* HAS_SHADOW_EXPIRE */

	ଯଦି (spw != ଖାଲି)
#ifdef USE_LIBIAF
		iaf_passwd = passwd = get_iaf_password(pw);
#ଅନ୍ୟଥା
		passwd = spw->sp_pwdp;
#endif /* USE_LIBIAF */
#endif

	/* check for locked account */
	ଯଦି (passwd && *passwd) {
#ifdef LOCKED_PASSWD_STRING
		ଯଦି (strcmp(passwd, LOCKED_PASSWD_STRING) == 0) {
			debug3_f("password matches locked string '%s'",
			    LOCKED_PASSWD_STRING);
			locked = 1;
		}
#endif
#ifdef LOCKED_PASSWD_PREFIX
		ଯଦି (strncmp(passwd, LOCKED_PASSWD_PREFIX,
		    strlen(LOCKED_PASSWD_PREFIX)) == 0) {
			debug3_f("password matches locked prefix '%s'",
			    LOCKED_PASSWD_PREFIX);
			locked = 1;
		}
#endif
#ifdef LOCKED_PASSWD_SUBSTR
		ଯଦି (strstr(passwd, LOCKED_PASSWD_SUBSTR)) {
			debug3_f("password matches locked substring '%s'",
			   LOCKED_PASSWD_SUBSTR);
			locked = 1;
		}
#endif
	}
#ifdef USE_LIBIAF
	ଯଦି (iaf_passwd != ଖାଲି)
		freezero(iaf_passwd, strlen(iaf_passwd));
#endif /* USE_LIBIAF */

	ଫେରନ୍ତୁ locked;
}
