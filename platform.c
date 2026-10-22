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

#അന്തര്ഭാവ "includes.h"

#അന്തര്ഭാവ <stdarg.h>
#അന്തര്ഭാവ <stdio.h>
#അന്തര്ഭാവ <string.h>
#അന്തര്ഭാവ <unistd.h>

#അന്തര്ഭാവ "log.h"
#അന്തര്ഭാവ "misc.h"
#അന്തര്ഭാവ "servconf.h"
#അന്തര്ഭാവ "sshkey.h"
#അന്തര്ഭാവ "hostfile.h"
#അന്തര്ഭാവ "auth.h"
#അന്തര്ഭാവ "auth-pam.h"
#അന്തര്ഭാവ "platform.h"

#അന്തര്ഭാവ "openbsd-compat/openbsd-compat.h"

ബാഹ്യ ServerOptions options;

/* return 1 if we are running with privilege to swap UIDs, 0 otherwise */
പൂർണ്ണസംഖ്യ
platform_privileged_uidswap(ശൂന്യം)
{
#ifdef HAVE_CYGWIN
	/* uid 0 is not special on Cygwin so always try */
	തിരികെ 1;
#അല്ലെങ്കിൽ
	തിരികെ (getuid() == 0 || geteuid() == 0);
#endif
}

/*
 * This gets called before switching UIDs, and is called even when sshd is
 * not running as root.
 */
ശൂന്യം
platform_setusercontext(ഘടന passwd *pw)
{
#ifdef WITH_SELINUX
	/* Cache selinux status for later use */
	(ശൂന്യം)ssh_selinux_enabled();
#endif

#ifdef USE_SOLARIS_PROJECTS
	/*
	 * If solaris projects were detected, set the default now, unless
	 * we are using PAM in which case it is the responsibility of the
	 * PAM stack.
	 */
	എങ്കിൽ (!options.use_pam && (getuid() == 0 || geteuid() == 0))
		solaris_set_default_project(pw);
#endif

#എങ്കിൽ defined(HAVE_LOGIN_CAP) && defined (__bsdi__)
	എങ്കിൽ (getuid() == 0 || geteuid() == 0)
		setpgid(0, 0);
# endif

#എങ്കിൽ defined(HAVE_LOGIN_CAP) && defined(USE_PAM)
	/*
	 * If we have both LOGIN_CAP and PAM, we want to establish creds
	 * before calling setusercontext (in session.c:do_setusercontext).
	 */
	എങ്കിൽ (getuid() == 0 || geteuid() == 0) {
		എങ്കിൽ (options.use_pam) {
			do_pam_setcred();
		}
	}
# endif /* USE_PAM */

#എങ്കിൽ !defined(HAVE_LOGIN_CAP) && defined(HAVE_GETLUID) && defined(HAVE_SETLUID)
	എങ്കിൽ (getuid() == 0 || geteuid() == 0) {
		/* Sets login uid for accounting */
		എങ്കിൽ (getluid() == -1 && setluid(pw->pw_uid) == -1)
			error("setluid: %s", strerror(errno));
	}
#endif
}

/*
 * This gets called after we've established the user's groups, and is only
 * called if sshd is running as root.
 */
ശൂന്യം
platform_setusercontext_post_groups(ഘടന passwd *pw)
{
#എങ്കിൽ !defined(HAVE_LOGIN_CAP) && defined(USE_PAM)
	/*
	 * PAM credentials may take the form of supplementary groups.
	 * These will have been wiped by the above initgroups() call.
	 * Reestablish them here.
	 */
	എങ്കിൽ (options.use_pam) {
		do_pam_setcred();
	}
#endif /* USE_PAM */

#എങ്കിൽ !defined(HAVE_LOGIN_CAP) && (defined(WITH_IRIX_PROJECT) || \
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
		അക്ഷരം **creds = ശൂന്യ, *chroot_creds[] =
		    { "REAL_USER=root", ശൂന്യ };

		എങ്കിൽ (options.chroot_directory != ശൂന്യ &&
		    strcasecmp(options.chroot_directory, "none") != 0)
			creds = chroot_creds;

		എങ്കിൽ (setpcred(pw->pw_name, creds) == -1)
			fatal("Failed to set process credentials");
	}
#endif /* HAVE_SETPCRED */
#ifdef WITH_SELINUX
	ssh_selinux_setup_exec_context(pw->pw_name);
#endif
}

അക്ഷരം *
platform_krb5_get_principal_name(സ്ഥിരം അക്ഷരം *pw_name)
{
#ifdef USE_AIX_KRB_NAME
	തിരികെ aix_krb5_get_principal_name(pw_name);
#അല്ലെങ്കിൽ
	തിരികെ ശൂന്യ;
#endif
}

/* returns 1 if account is locked */
പൂർണ്ണസംഖ്യ
platform_locked_account(ഘടന passwd *pw)
{
	പൂർണ്ണസംഖ്യ locked = 0;
	അക്ഷരം *passwd = pw->pw_passwd;
#ifdef USE_SHADOW
	ഘടന spwd *spw = ശൂന്യ;
#ifdef USE_LIBIAF
	അക്ഷരം *iaf_passwd = ശൂന്യ;
#endif

	spw = getspnam(pw->pw_name);
#ifdef HAS_SHADOW_EXPIRE
	എങ്കിൽ (spw != ശൂന്യ && auth_shadow_acctexpired(spw))
		തിരികെ 1;
#endif /* HAS_SHADOW_EXPIRE */

	എങ്കിൽ (spw != ശൂന്യ)
#ifdef USE_LIBIAF
		iaf_passwd = passwd = get_iaf_password(pw);
#അല്ലെങ്കിൽ
		passwd = spw->sp_pwdp;
#endif /* USE_LIBIAF */
#endif

	/* check for locked account */
	എങ്കിൽ (passwd && *passwd) {
#ifdef LOCKED_PASSWD_STRING
		എങ്കിൽ (strcmp(passwd, LOCKED_PASSWD_STRING) == 0) {
			debug3_f("password matches locked string '%s'",
			    LOCKED_PASSWD_STRING);
			locked = 1;
		}
#endif
#ifdef LOCKED_PASSWD_PREFIX
		എങ്കിൽ (strncmp(passwd, LOCKED_PASSWD_PREFIX,
		    strlen(LOCKED_PASSWD_PREFIX)) == 0) {
			debug3_f("password matches locked prefix '%s'",
			    LOCKED_PASSWD_PREFIX);
			locked = 1;
		}
#endif
#ifdef LOCKED_PASSWD_SUBSTR
		എങ്കിൽ (strstr(passwd, LOCKED_PASSWD_SUBSTR)) {
			debug3_f("password matches locked substring '%s'",
			   LOCKED_PASSWD_SUBSTR);
			locked = 1;
		}
#endif
	}
#ifdef USE_LIBIAF
	എങ്കിൽ (iaf_passwd != ശൂന്യ)
		freezero(iaf_passwd, strlen(iaf_passwd));
#endif /* USE_LIBIAF */

	തിരികെ locked;
}
