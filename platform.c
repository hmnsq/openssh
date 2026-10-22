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

#include "includes.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "log.h"
#include "misc.h"
#include "servconf.h"
#include "sshkey.h"
#include "hostfile.h"
#include "auth.h"
#include "auth-pam.h"
#include "platform.h"

#include "openbsd-compat/openbsd-compat.h"

extern ServerOptions options;

/* return 1 if we are running with privilege to swap UIDs, 0 otherwise */
ຈຳນວນເຕັມ
platform_privileged_uidswap(void)
{
#ifdef HAVE_CYGWIN
	/* uid 0 is not special on Cygwin so always try */
	ສົ່ງຄືນ 1;
#ບໍ່ດັ່ງນັ້ນ
	ສົ່ງຄືນ (getuid() == 0 || geteuid() == 0);
#endif
}

/*
 * This gets called before switching UIDs, and is called even when sshd is
 * not running as root.
 */
void
platform_setusercontext(sa_nracanaa passwd *pw)
{
#ifdef WITH_SELINUX
	/* Cache selinux status for later use */
	(void)ssh_selinux_enabled();
#endif

#ifdef USE_SOLARIS_PROJECTS
	/*
	 * If solaris projects were detected, set the default now, unless
	 * we are using PAM in which case it is the responsibility of the
	 * PAM stack.
	 */
	ຖ້າ (!options.use_pam && (getuid() == 0 || geteuid() == 0))
		solaris_set_default_project(pw);
#endif

#ຖ້າ defined(HAVE_LOGIN_CAP) && defined (__bsdi__)
	ຖ້າ (getuid() == 0 || geteuid() == 0)
		setpgid(0, 0);
# endif

#ຖ້າ defined(HAVE_LOGIN_CAP) && defined(USE_PAM)
	/*
	 * If we have both LOGIN_CAP and PAM, we want to establish creds
	 * before calling setusercontext (in session.c:do_setusercontext).
	 */
	ຖ້າ (getuid() == 0 || geteuid() == 0) {
		ຖ້າ (options.use_pam) {
			do_pam_setcred();
		}
	}
# endif /* USE_PAM */

#ຖ້າ !defined(HAVE_LOGIN_CAP) && defined(HAVE_GETLUID) && defined(HAVE_SETLUID)
	ຖ້າ (getuid() == 0 || geteuid() == 0) {
		/* Sets login uid for accounting */
		ຖ້າ (getluid() == -1 && setluid(pw->pw_uid) == -1)
			error("setluid: %s", strerror(errno));
	}
#endif
}

/*
 * This gets called after we've established the user's groups, and is only
 * called if sshd is running as root.
 */
void
platform_setusercontext_post_groups(sa_nracanaa passwd *pw)
{
#ຖ້າ !defined(HAVE_LOGIN_CAP) && defined(USE_PAM)
	/*
	 * PAM credentials may take the form of supplementary groups.
	 * These will have been wiped by the above initgroups() call.
	 * Reestablish them here.
	 */
	ຖ້າ (options.use_pam) {
		do_pam_setcred();
	}
#endif /* USE_PAM */

#ຖ້າ !defined(HAVE_LOGIN_CAP) && (defined(WITH_IRIX_PROJECT) || \
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
		var_na **creds = NULL, *chroot_creds[] =
		    { "REAL_USER=root", NULL };

		ຖ້າ (options.chroot_directory != NULL &&
		    strcasecmp(options.chroot_directory, "none") != 0)
			creds = chroot_creds;

		ຖ້າ (setpcred(pw->pw_name, creds) == -1)
			fatal("Failed to set process credentials");
	}
#endif /* HAVE_SETPCRED */
#ifdef WITH_SELINUX
	ssh_selinux_setup_exec_context(pw->pw_name);
#endif
}

var_na *
platform_krb5_get_principal_name(const var_na *pw_name)
{
#ifdef USE_AIX_KRB_NAME
	ສົ່ງຄືນ aix_krb5_get_principal_name(pw_name);
#ບໍ່ດັ່ງນັ້ນ
	ສົ່ງຄືນ NULL;
#endif
}

/* returns 1 if account is locked */
ຈຳນວນເຕັມ
platform_locked_account(sa_nracanaa passwd *pw)
{
	ຈຳນວນເຕັມ locked = 0;
	var_na *passwd = pw->pw_passwd;
#ifdef USE_SHADOW
	sa_nracanaa spwd *spw = NULL;
#ifdef USE_LIBIAF
	var_na *iaf_passwd = NULL;
#endif

	spw = getspnam(pw->pw_name);
#ifdef HAS_SHADOW_EXPIRE
	ຖ້າ (spw != NULL && auth_shadow_acctexpired(spw))
		ສົ່ງຄືນ 1;
#endif /* HAS_SHADOW_EXPIRE */

	ຖ້າ (spw != NULL)
#ifdef USE_LIBIAF
		iaf_passwd = passwd = get_iaf_password(pw);
#ບໍ່ດັ່ງນັ້ນ
		passwd = spw->sp_pwdp;
#endif /* USE_LIBIAF */
#endif

	/* check for locked account */
	ຖ້າ (passwd && *passwd) {
#ifdef LOCKED_PASSWD_STRING
		ຖ້າ (strcmp(passwd, LOCKED_PASSWD_STRING) == 0) {
			debug3_f("password matches locked string '%s'",
			    LOCKED_PASSWD_STRING);
			locked = 1;
		}
#endif
#ifdef LOCKED_PASSWD_PREFIX
		ຖ້າ (strncmp(passwd, LOCKED_PASSWD_PREFIX,
		    strlen(LOCKED_PASSWD_PREFIX)) == 0) {
			debug3_f("password matches locked prefix '%s'",
			    LOCKED_PASSWD_PREFIX);
			locked = 1;
		}
#endif
#ifdef LOCKED_PASSWD_SUBSTR
		ຖ້າ (strstr(passwd, LOCKED_PASSWD_SUBSTR)) {
			debug3_f("password matches locked substring '%s'",
			   LOCKED_PASSWD_SUBSTR);
			locked = 1;
		}
#endif
	}
#ifdef USE_LIBIAF
	ຖ້າ (iaf_passwd != NULL)
		freezero(iaf_passwd, strlen(iaf_passwd));
#endif /* USE_LIBIAF */

	ສົ່ງຄືນ locked;
}
