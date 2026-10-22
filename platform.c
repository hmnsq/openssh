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

#அந்தர்பாவ "includes.h"

#அந்தர்பாவ <stdarg.h>
#அந்தர்பாவ <stdio.h>
#அந்தர்பாவ <string.h>
#அந்தர்பாவ <unistd.h>

#அந்தர்பாவ "log.h"
#அந்தர்பாவ "misc.h"
#அந்தர்பாவ "servconf.h"
#அந்தர்பாவ "sshkey.h"
#அந்தர்பாவ "hostfile.h"
#அந்தர்பாவ "auth.h"
#அந்தர்பாவ "auth-pam.h"
#அந்தர்பாவ "platform.h"

#அந்தர்பாவ "openbsd-compat/openbsd-compat.h"

வெளி ServerOptions options;

/* return 1 if we are running with privilege to swap UIDs, 0 otherwise */
முழு
platform_privileged_uidswap(வெறுமை)
{
#ifdef HAVE_CYGWIN
	/* uid 0 is not special on Cygwin so always try */
	திரும்பு 1;
#இல்லையெனில்
	திரும்பு (getuid() == 0 || geteuid() == 0);
#endif
}

/*
 * This gets called before switching UIDs, and is called even when sshd is
 * not running as root.
 */
வெறுமை
platform_setusercontext(கட்டமைப்பு passwd *pw)
{
#ifdef WITH_SELINUX
	/* Cache selinux status for later use */
	(வெறுமை)ssh_selinux_enabled();
#endif

#ifdef USE_SOLARIS_PROJECTS
	/*
	 * If solaris projects were detected, set the default now, unless
	 * we are using PAM in which case it is the responsibility of the
	 * PAM stack.
	 */
	எனில் (!options.use_pam && (getuid() == 0 || geteuid() == 0))
		solaris_set_default_project(pw);
#endif

#எனில் defined(HAVE_LOGIN_CAP) && defined (__bsdi__)
	எனில் (getuid() == 0 || geteuid() == 0)
		setpgid(0, 0);
# endif

#எனில் defined(HAVE_LOGIN_CAP) && defined(USE_PAM)
	/*
	 * If we have both LOGIN_CAP and PAM, we want to establish creds
	 * before calling setusercontext (in session.c:do_setusercontext).
	 */
	எனில் (getuid() == 0 || geteuid() == 0) {
		எனில் (options.use_pam) {
			do_pam_setcred();
		}
	}
# endif /* USE_PAM */

#எனில் !defined(HAVE_LOGIN_CAP) && defined(HAVE_GETLUID) && defined(HAVE_SETLUID)
	எனில் (getuid() == 0 || geteuid() == 0) {
		/* Sets login uid for accounting */
		எனில் (getluid() == -1 && setluid(pw->pw_uid) == -1)
			error("setluid: %s", strerror(errno));
	}
#endif
}

/*
 * This gets called after we've established the user's groups, and is only
 * called if sshd is running as root.
 */
வெறுமை
platform_setusercontext_post_groups(கட்டமைப்பு passwd *pw)
{
#எனில் !defined(HAVE_LOGIN_CAP) && defined(USE_PAM)
	/*
	 * PAM credentials may take the form of supplementary groups.
	 * These will have been wiped by the above initgroups() call.
	 * Reestablish them here.
	 */
	எனில் (options.use_pam) {
		do_pam_setcred();
	}
#endif /* USE_PAM */

#எனில் !defined(HAVE_LOGIN_CAP) && (defined(WITH_IRIX_PROJECT) || \
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
		எழுத்து **creds = வெற்று, *chroot_creds[] =
		    { "REAL_USER=root", வெற்று };

		எனில் (options.chroot_directory != வெற்று &&
		    strcasecmp(options.chroot_directory, "none") != 0)
			creds = chroot_creds;

		எனில் (setpcred(pw->pw_name, creds) == -1)
			fatal("Failed to set process credentials");
	}
#endif /* HAVE_SETPCRED */
#ifdef WITH_SELINUX
	ssh_selinux_setup_exec_context(pw->pw_name);
#endif
}

எழுத்து *
platform_krb5_get_principal_name(மாறிலி எழுத்து *pw_name)
{
#ifdef USE_AIX_KRB_NAME
	திரும்பு aix_krb5_get_principal_name(pw_name);
#இல்லையெனில்
	திரும்பு வெற்று;
#endif
}

/* returns 1 if account is locked */
முழு
platform_locked_account(கட்டமைப்பு passwd *pw)
{
	முழு locked = 0;
	எழுத்து *passwd = pw->pw_passwd;
#ifdef USE_SHADOW
	கட்டமைப்பு spwd *spw = வெற்று;
#ifdef USE_LIBIAF
	எழுத்து *iaf_passwd = வெற்று;
#endif

	spw = getspnam(pw->pw_name);
#ifdef HAS_SHADOW_EXPIRE
	எனில் (spw != வெற்று && auth_shadow_acctexpired(spw))
		திரும்பு 1;
#endif /* HAS_SHADOW_EXPIRE */

	எனில் (spw != வெற்று)
#ifdef USE_LIBIAF
		iaf_passwd = passwd = get_iaf_password(pw);
#இல்லையெனில்
		passwd = spw->sp_pwdp;
#endif /* USE_LIBIAF */
#endif

	/* check for locked account */
	எனில் (passwd && *passwd) {
#ifdef LOCKED_PASSWD_STRING
		எனில் (strcmp(passwd, LOCKED_PASSWD_STRING) == 0) {
			debug3_f("password matches locked string '%s'",
			    LOCKED_PASSWD_STRING);
			locked = 1;
		}
#endif
#ifdef LOCKED_PASSWD_PREFIX
		எனில் (strncmp(passwd, LOCKED_PASSWD_PREFIX,
		    strlen(LOCKED_PASSWD_PREFIX)) == 0) {
			debug3_f("password matches locked prefix '%s'",
			    LOCKED_PASSWD_PREFIX);
			locked = 1;
		}
#endif
#ifdef LOCKED_PASSWD_SUBSTR
		எனில் (strstr(passwd, LOCKED_PASSWD_SUBSTR)) {
			debug3_f("password matches locked substring '%s'",
			   LOCKED_PASSWD_SUBSTR);
			locked = 1;
		}
#endif
	}
#ifdef USE_LIBIAF
	எனில் (iaf_passwd != வெற்று)
		freezero(iaf_passwd, strlen(iaf_passwd));
#endif /* USE_LIBIAF */

	திரும்பு locked;
}
