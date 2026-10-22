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

#समावेश "includes.h"

#समावेश <stdarg.h>
#समावेश <stdio.h>
#समावेश <string.h>
#समावेश <unistd.h>

#समावेश "log.h"
#समावेश "misc.h"
#समावेश "servconf.h"
#समावेश "sshkey.h"
#समावेश "hostfile.h"
#समावेश "auth.h"
#समावेश "auth-pam.h"
#समावेश "platform.h"

#समावेश "openbsd-compat/openbsd-compat.h"

बाह्य ServerOptions options;

/* return 1 if we are running with privilege to swap UIDs, 0 otherwise */
पूर्णांक
platform_privileged_uidswap(व्योम)
{
#अगर_घोषित HAVE_CYGWIN
	/* uid 0 is not special on Cygwin so always try */
	वापस 1;
#अन्यथा
	वापस (getuid() == 0 || geteuid() == 0);
#पूर्ण_अगर
}

/*
 * This gets called before switching UIDs, and is called even when sshd is
 * not running as root.
 */
व्योम
platform_setusercontext(काष्ठा passwd *pw)
{
#अगर_घोषित WITH_SELINUX
	/* Cache selinux status for later use */
	(व्योम)ssh_selinux_enabled();
#पूर्ण_अगर

#अगर_घोषित USE_SOLARIS_PROJECTS
	/*
	 * If solaris projects were detected, set the default now, unless
	 * we are using PAM in which case it is the responsibility of the
	 * PAM stack.
	 */
	अगर (!options.use_pam && (getuid() == 0 || geteuid() == 0))
		solaris_set_default_project(pw);
#पूर्ण_अगर

#अगर defined(HAVE_LOGIN_CAP) && defined (__bsdi__)
	अगर (getuid() == 0 || geteuid() == 0)
		setpgid(0, 0);
# endif

#अगर defined(HAVE_LOGIN_CAP) && defined(USE_PAM)
	/*
	 * If we have both LOGIN_CAP and PAM, we want to establish creds
	 * before calling setusercontext (in session.c:do_setusercontext).
	 */
	अगर (getuid() == 0 || geteuid() == 0) {
		अगर (options.use_pam) {
			do_pam_setcred();
		}
	}
# endif /* USE_PAM */

#अगर !defined(HAVE_LOGIN_CAP) && defined(HAVE_GETLUID) && defined(HAVE_SETLUID)
	अगर (getuid() == 0 || geteuid() == 0) {
		/* Sets login uid for accounting */
		अगर (getluid() == -1 && setluid(pw->pw_uid) == -1)
			error("setluid: %s", म_त्रुटि(त्रुटि_सं));
	}
#पूर्ण_अगर
}

/*
 * This gets called after we've established the user's groups, and is only
 * called if sshd is running as root.
 */
व्योम
platform_setusercontext_post_groups(काष्ठा passwd *pw)
{
#अगर !defined(HAVE_LOGIN_CAP) && defined(USE_PAM)
	/*
	 * PAM credentials may take the form of supplementary groups.
	 * These will have been wiped by the above initgroups() call.
	 * Reestablish them here.
	 */
	अगर (options.use_pam) {
		do_pam_setcred();
	}
#पूर्ण_अगर /* USE_PAM */

#अगर !defined(HAVE_LOGIN_CAP) && (defined(WITH_IRIX_PROJECT) || \
    defined(WITH_IRIX_JOBS) || defined(WITH_IRIX_ARRAY))
	irix_setusercontext(pw);
#पूर्ण_अगर /* defined(WITH_IRIX_PROJECT) || defined(WITH_IRIX_JOBS) || defined(WITH_IRIX_ARRAY) */

#अगर_घोषित _AIX
	aix_usrinfo(pw);
#पूर्ण_अगर /* _AIX */

#अगर_घोषित HAVE_SETPCRED
	/*
	 * If we have a chroot directory, we set all creds except real
	 * uid which we will need for chroot.  If we don't have a
	 * chroot directory, we don't override anything.
	 */
	{
		अक्षर **creds = शून्य, *chroot_creds[] =
		    { "REAL_USER=root", शून्य };

		अगर (options.chroot_directory != शून्य &&
		    strcasecmp(options.chroot_directory, "none") != 0)
			creds = chroot_creds;

		अगर (setpcred(pw->pw_name, creds) == -1)
			fatal("Failed to set process credentials");
	}
#पूर्ण_अगर /* HAVE_SETPCRED */
#अगर_घोषित WITH_SELINUX
	ssh_selinux_setup_exec_context(pw->pw_name);
#पूर्ण_अगर
}

अक्षर *
platform_krb5_get_principal_name(स्थिर अक्षर *pw_name)
{
#अगर_घोषित USE_AIX_KRB_NAME
	वापस aix_krb5_get_principal_name(pw_name);
#अन्यथा
	वापस शून्य;
#पूर्ण_अगर
}

/* returns 1 if account is locked */
पूर्णांक
platform_locked_account(काष्ठा passwd *pw)
{
	पूर्णांक locked = 0;
	अक्षर *passwd = pw->pw_passwd;
#अगर_घोषित USE_SHADOW
	काष्ठा spwd *spw = शून्य;
#अगर_घोषित USE_LIBIAF
	अक्षर *iaf_passwd = शून्य;
#पूर्ण_अगर

	spw = getspnam(pw->pw_name);
#अगर_घोषित HAS_SHADOW_EXPIRE
	अगर (spw != शून्य && auth_shadow_acctexpired(spw))
		वापस 1;
#पूर्ण_अगर /* HAS_SHADOW_EXPIRE */

	अगर (spw != शून्य)
#अगर_घोषित USE_LIBIAF
		iaf_passwd = passwd = get_iaf_password(pw);
#अन्यथा
		passwd = spw->sp_pwdp;
#पूर्ण_अगर /* USE_LIBIAF */
#पूर्ण_अगर

	/* check for locked account */
	अगर (passwd && *passwd) {
#अगर_घोषित LOCKED_PASSWD_STRING
		अगर (म_भेद(passwd, LOCKED_PASSWD_STRING) == 0) {
			debug3_f("password matches locked string '%s'",
			    LOCKED_PASSWD_STRING);
			locked = 1;
		}
#पूर्ण_अगर
#अगर_घोषित LOCKED_PASSWD_PREFIX
		अगर (म_भेदन(passwd, LOCKED_PASSWD_PREFIX,
		    म_माप(LOCKED_PASSWD_PREFIX)) == 0) {
			debug3_f("password matches locked prefix '%s'",
			    LOCKED_PASSWD_PREFIX);
			locked = 1;
		}
#पूर्ण_अगर
#अगर_घोषित LOCKED_PASSWD_SUBSTR
		अगर (म_माला(passwd, LOCKED_PASSWD_SUBSTR)) {
			debug3_f("password matches locked substring '%s'",
			   LOCKED_PASSWD_SUBSTR);
			locked = 1;
		}
#पूर्ण_अगर
	}
#अगर_घोषित USE_LIBIAF
	अगर (iaf_passwd != शून्य)
		freezero(iaf_passwd, म_माप(iaf_passwd));
#पूर्ण_अगर /* USE_LIBIAF */

	वापस locked;
}
