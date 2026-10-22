/*
 *
 * Copyright (c) 2001 Gert Doering.  All rights reserved.
 * Copyright (c) 2003,2004,2005,2006 Darren Tucker.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */
#অন্তর্ভাব "includes.h"

#ifdef _AIX

#অন্তর্ভাব "xmalloc.h"
#অন্তর্ভাব "sshbuf.h"
#অন্তর্ভাব "ssherr.h"
#অন্তর্ভাব "sshkey.h"
#অন্তর্ভাব "hostfile.h"
#অন্তর্ভাব "auth.h"
#অন্তর্ভাব "ssh.h"
#অন্তর্ভাব "ssh_api.h"
#অন্তর্ভাব "log.h"

#অন্তর্ভাব <errno.h>
#যদি defined(HAVE_NETDB_H)
# include <netdb.h>
#endif
#অন্তর্ভাব <uinfo.h>
#অন্তর্ভাব <stdarg.h>
#অন্তর্ভাব <string.h>
#অন্তর্ভাব <unistd.h>
#অন্তর্ভাব <sys/socket.h>

#ifdef WITH_AIXAUTHENTICATE
# include <login.h>
# include <userpw.h>
# যদি defined(HAVE_SYS_AUDIT_H) && defined(AIX_LOGINFAILED_4ARG)
#  include <sys/audit.h>
# endif
# include <usersec.h>
#endif

#অন্তর্ভাব "port-aix.h"

স্থির বর্ণ *lastlogin_বার্তা = রিক্ত;

# ifdef HAVE_SETAUTHDB
স্থির বর্ণ old_registry[REGISTRY_SIZE] = "";
# endif

/*
 * AIX has a "usrinfo" area where logname and other stuff is stored -
 * a few applications actually use this and die if it's not set
 *
 * NOTE: TTY= should be set, but since no one uses it and it's hard to
 * acquire due to privsep code.  We will just drop support.
 */
শূন্য
aix_usrinfo(সংরচনা passwd *pw)
{
	u_int i;
	size_t len;
	বর্ণ *cp;

	len = পরিমাণ("LOGNAME= NAME= ") + (2 * strlen(pw->pw_name));
	cp = xmalloc(len);

	i = snprintf(cp, len, "LOGNAME=%s%cNAME=%s%c", pw->pw_name, '\0',
	    pw->pw_name, '\0');
	যদি (usrinfo(SETUINFO, cp, i) == -1)
		fatal("Couldn't set usrinfo: %s", strerror(errno));
	debug3("AIX/UsrInfo: set len %d", i);

	মুক্ত(cp);
}

# ifdef WITH_AIXAUTHENTICATE
/*
 * Remove embedded newlines in string (if any).
 * Used before logging messages returned by AIX authentication functions
 * so the message is logged on one line.
 */
শূন্য
aix_remove_embedded_newlines(বর্ণ *p)
{
	যদি (p == রিক্ত)
		প্রত্যাগম;

	প্রতি (; *p; p++) {
		যদি (*p == '\n')
			*p = ' ';
	}
	/* Remove trailing whitespace */
	যদি (*--p == ' ')
		*p = '\0';
}

/*
 * Test specifically for the case where SYSTEM == NONE and AUTH1 contains
 * anything other than NONE or SYSTEM, which indicates that the admin has
 * configured the account for purely AUTH1-type authentication.
 *
 * Since authenticate() doesn't check AUTH1, and sshd can't sanely support
 * AUTH1 itself, in such a case authenticate() will allow access without
 * authentation, which is almost certainly not what the admin intends.
 *
 * (The native tools, eg login, will process the AUTH1 list in addition to
 * the SYSTEM list by using ckuserID(), however ckuserID() and AUTH1 methods
 * have been deprecated since AIX 4.2.x and would be very difficult for sshd
 * to support.
 *
 * Returns 0 if an unsupportable combination is found, 1 otherwise.
 */
স্থির পূর্ণাঙ্ক
aix_valid_authentications(ধ্রুব বর্ণ *user)
{
	বর্ণ *auth1, *sys, *p;
	পূর্ণাঙ্ক valid = 1;

	যদি (getuserattr((বর্ণ *)user, S_AUTHSYSTEM, &sys, SEC_CHAR) != 0) {
		logit("Can't retrieve attribute SYSTEM for %s: %.100s",
		    user, strerror(errno));
		প্রত্যাগম 0;
	}

	debug3("AIX SYSTEM attribute %s", sys);
	যদি (strcmp(sys, "NONE") != 0)
		প্রত্যাগম 1;	/* not "NONE", so is OK */

	যদি (getuserattr((বর্ণ *)user, S_AUTH1, &auth1, SEC_LIST) != 0) {
		logit("Can't retrieve attribute auth1 for %s: %.100s",
		    user, strerror(errno));
		প্রত্যাগম 0;
	}

	p = auth1;
	/* A SEC_LIST is concatenated strings, ending with two NULs. */
	যাবত্ (p[0] != '\0' && p[1] != '\0') {
		debug3("AIX auth1 attribute list member %s", p);
		যদি (strcmp(p, "NONE") != 0 && strcmp(p, "SYSTEM")) {
			logit("Account %s has unsupported auth1 value '%s'",
			    user, p);
			valid = 0;
		}
		p += strlen(p) + 1;
	}

	প্রত্যাগম (valid);
}

/*
 * Do authentication via AIX's authenticate routine.  We loop until the
 * reenter parameter is 0, but normally authenticate is called only once.
 *
 * Note: this function returns 1 on success, whereas AIX's authenticate()
 * returns 0.
 */
পূর্ণাঙ্ক
sys_auth_passwd(সংরচনা ssh *ssh, ধ্রুব বর্ণ *password)
{
	Authctxt *ctxt = ssh->authctxt;
	বর্ণ *authmsg = রিক্ত, *বার্তা = রিক্ত, *name = ctxt->pw->pw_name;
	পূর্ণাঙ্ক r, authsuccess = 0, expired, reenter, result;

	কুরু {
		result = authenticate((বর্ণ *)name, (বর্ণ *)password, &reenter,
		    &authmsg);
		aix_remove_embedded_newlines(authmsg);
		debug3("AIX/authenticate result %d, authmsg %.100s", result,
		    authmsg);
	} যাবত্ (reenter);

	যদি (!aix_valid_authentications(name))
		result = -1;

	যদি (result == 0) {
		authsuccess = 1;

		/*
		 * Record successful login.  We don't have a pty yet, so just
		 * label the line as "ssh"
		 */
		aix_setauthdb(name);

		/*
		 * Check if the user's password is expired.
		 */
		expired = passwdexpired(name, &বার্তা);
		যদি (বার্তা && *বার্তা) {
			যদি ((r = sshbuf_put(ctxt->loginmsg,
			    বার্তা, strlen(বার্তা))) != 0)
				fatal("%s: buffer error: %s",
				    __func__, ssh_err(r));
			aix_remove_embedded_newlines(বার্তা);
		}
		debug3("AIX/passwdexpired returned %d msg %.100s", expired, বার্তা);

		বিকল্প (expired) {
		পক্ষ 0: /* password not expired */
			ভঙ্গ;
		পক্ষ 1: /* expired, password change required */
			ctxt->force_pwchange = 1;
			ভঙ্গ;
		স্বভাব: /* user can't change(2) or other error (-1) */
			logit("Password can't be changed for user %s: %.100s",
			    name, বার্তা);
			মুক্ত(বার্তা);
			authsuccess = 0;
		}

		aix_restoreauthdb();
	}

	মুক্ত(authmsg);

	প্রত্যাগম authsuccess;
}

/*
 * Check if specified account is permitted to log in.
 * Returns 1 if login is allowed, 0 if not allowed.
 */
পূর্ণাঙ্ক
sys_auth_allowed_user(সংরচনা passwd *pw, সংরচনা sshbuf *loginmsg)
{
	বর্ণ *বার্তা = রিক্ত;
	পূর্ণাঙ্ক r, result, permitted = 0;
	সংরচনা stat st;

	/*
	 * Don't perform checks for root account (PermitRootLogin controls
	 * logins via ssh) or if running as non-root user (since
	 * loginrestrictions will always fail due to insufficient privilege).
	 */
	যদি (pw->pw_uid == 0 || geteuid() != 0) {
		debug3("%s: not checking", __func__);
		প্রত্যাগম 1;
	}

	result = loginrestrictions(pw->pw_name, S_RLOGIN, রিক্ত, &বার্তা);
	যদি (result == 0)
		permitted = 1;
	/*
	 * If restricted because /etc/nologin exists, the login will be denied
	 * in session.c after the nologin message is sent, so allow for now
	 * and do not append the returned message.
	 */
	যদি (result == -1 && errno == EPERM && stat(_PATH_NOLOGIN, &st) == 0)
		permitted = 1;
	অন্যথা যদি (বার্তা != রিক্ত) {
		যদি ((r = sshbuf_put(loginmsg, বার্তা, strlen(বার্তা))) != 0)
			fatal("%s: buffer error: %s", __func__, ssh_err(r));
	}
	যদি (বার্তা == রিক্ত)
		বার্তা = xstrdup("(none)");
	aix_remove_embedded_newlines(বার্তা);
	debug3("AIX/loginrestrictions returned %d msg %.100s", result, বার্তা);

	যদি (!permitted)
		logit("Login restricted for %s: %.100s", pw->pw_name, বার্তা);
	মুক্ত(বার্তা);
	প্রত্যাগম permitted;
}

পূর্ণাঙ্ক
sys_auth_record_login(ধ্রুব বর্ণ *user, ধ্রুব বর্ণ *host, ধ্রুব বর্ণ *ttynm,
    সংরচনা sshbuf *loginmsg)
{
	বর্ণ *বার্তা = রিক্ত;
	পূর্ণাঙ্ক success = 0;

	aix_setauthdb(user);
	যদি (loginsuccess((বর্ণ *)user, (বর্ণ *)host, (বর্ণ *)ttynm, &বার্তা) == 0) {
		success = 1;
		যদি (বার্তা != রিক্ত) {
			debug("AIX/loginsuccess: msg %s", বার্তা);
			যদি (lastlogin_বার্তা == রিক্ত)
				lastlogin_বার্তা = বার্তা;
		}
	}
	aix_restoreauthdb();
	প্রত্যাগম (success);
}

বর্ণ *
sys_auth_get_lastlogin_বার্তা(ধ্রুব বর্ণ *user, uid_t uid)
{
	বর্ণ *বার্তা = lastlogin_বার্তা;

	lastlogin_বার্তা = রিক্ত;
	প্রত্যাগম বার্তা;
}

#  ifdef CUSTOM_FAILED_LOGIN
/*
 * record_failed_login: generic "login failed" interface function
 */
শূন্য
record_failed_login(সংরচনা ssh *ssh, ধ্রুব বর্ণ *user, ধ্রুব বর্ণ *hostname,
    ধ্রুব বর্ণ *ttyname)
{
	যদি (geteuid() != 0)
		প্রত্যাগম;

	aix_setauthdb(user);
#   ifdef AIX_LOGINFAILED_4ARG
	loginfailed((বর্ণ *)user, (বর্ণ *)hostname, (বর্ণ *)ttyname,
	    AUDIT_FAIL_AUTH);
#   অন্যথা
	loginfailed((বর্ণ *)user, (বর্ণ *)hostname, (বর্ণ *)ttyname);
#   endif
	aix_restoreauthdb();
}
#  endif /* CUSTOM_FAILED_LOGIN */

/*
 * If we have setauthdb, retrieve the password registry for the user's
 * account then feed it to setauthdb.  This will mean that subsequent AIX auth
 * functions will only use the specified loadable module.  If we don't have
 * setauthdb this is a no-op.
 */
শূন্য
aix_setauthdb(ধ্রুব বর্ণ *user)
{
#  ifdef HAVE_SETAUTHDB
	বর্ণ *registry;

	যদি (setuserdb(S_READ) == -1) {
		debug3("%s: Could not open userdb to read", __func__);
		প্রত্যাগম;
	}

	যদি (getuserattr((বর্ণ *)user, S_REGISTRY, &registry, SEC_CHAR) == 0) {
		যদি (setauthdb(registry, old_registry) == 0)
			debug3("AIX/setauthdb set registry '%s'", registry);
		অন্যথা
			debug3("AIX/setauthdb set registry '%s' failed: %s",
			    registry, strerror(errno));
	} অন্যথা
		debug3("%s: Could not read S_REGISTRY for user: %s", __func__,
		    strerror(errno));
	enduserdb();
#  endif /* HAVE_SETAUTHDB */
}

/*
 * Restore the user's registry settings from old_registry.
 * Note that if the first aix_setauthdb fails, setauthdb("") is still safe
 * (it restores the system default behaviour).  If we don't have setauthdb,
 * this is a no-op.
 */
শূন্য
aix_restoreauthdb(শূন্য)
{
#  ifdef HAVE_SETAUTHDB
	যদি (setauthdb(old_registry, রিক্ত) == 0)
		debug3("%s: restoring old registry '%s'", __func__,
		    old_registry);
	অন্যথা
		debug3("%s: failed to restore old registry %s", __func__,
		    old_registry);
#  endif /* HAVE_SETAUTHDB */
}

# endif /* WITH_AIXAUTHENTICATE */

# ifdef USE_AIX_KRB_NAME
/*
 * aix_krb5_get_principal_name: returns the user's kerberos client principal
 * name if configured, otherwise NULL.  Caller must free returned string.
 */
বর্ণ *
aix_krb5_get_principal_name(ধ্রুব বর্ণ *const_pw_name)
{
	বর্ণ *pw_name = (বর্ণ *)const_pw_name;
	বর্ণ *authname = রিক্ত, *authdomain = রিক্ত, *principal = রিক্ত;

	setuserdb(S_READ);
	যদি (getuserattr(pw_name, S_AUTHDOMAIN, &authdomain, SEC_CHAR) != 0)
		debug("AIX getuserattr S_AUTHDOMAIN: %s", strerror(errno));
	যদি (getuserattr(pw_name, S_AUTHNAME, &authname, SEC_CHAR) != 0)
		debug("AIX getuserattr S_AUTHNAME: %s", strerror(errno));

	যদি (authdomain != রিক্ত)
		xasprintf(&principal, "%s@%s", authname ? authname : pw_name,
		    authdomain);
	অন্যথা যদি (authname != রিক্ত)
		principal = xstrdup(authname);
	enduserdb();
	প্রত্যাগম principal;
}
# endif /* USE_AIX_KRB_NAME */

# যদি defined(AIX_GETNAMEINFO_HACK) && !defined(BROKEN_ADDRINFO)
# undef getnameinfo
/*
 * For some reason, AIX's getnameinfo will refuse to resolve the all-zeros
 * IPv6 address into its textual representation ("::"), so we wrap it
 * with a function that will.
 */
পূর্ণাঙ্ক
sshaix_getnameinfo(ধ্রুব সংরচনা sockaddr *sa, size_t salen, বর্ণ *host,
    size_t hostlen, বর্ণ *serv, size_t servlen, পূর্ণাঙ্ক flags)
{
	সংরচনা sockaddr_in6 *sa6;
	u_int32_t *a6;

	যদি (flags & (NI_NUMERICHOST|NI_NUMERICSERV) &&
	    sa->sa_family == AF_INET6) {
		sa6 = (সংরচনা sockaddr_in6 *)sa;
		a6 = sa6->sin6_addr.u6_addr.u6_addr32;

		যদি (a6[0] == 0 && a6[1] == 0 && a6[2] == 0 && a6[3] == 0) {
			strlcpy(host, "::", hostlen);
			snprintf(serv, servlen, "%d", sa6->sin6_port);
			প্রত্যাগম 0;
		}
	}
	প্রত্যাগম getnameinfo(sa, salen, host, hostlen, serv, servlen, flags);
}
# endif /* AIX_GETNAMEINFO_HACK */

# যদি defined(USE_GETGRSET)
#  include <stdlib.h>
পূর্ণাঙ্ক
getgrouplist(ধ্রুব বর্ণ *user, gid_t pgid, gid_t *groups, পূর্ণাঙ্ক *grpcnt)
{
	বর্ণ *cp, *grplist, *grp;
	gid_t gid;
	পূর্ণাঙ্ক ret = 0, ngroups = 0, maxgroups;
	long long ll;

	maxgroups = *grpcnt;

	যদি ((cp = grplist = getgrset(user)) == রিক্ত)
		প্রত্যাগম -1;

	/* handle zero-length case */
	যদি (maxgroups <= 0) {
		*grpcnt = 0;
		প্রত্যাগম -1;
	}

	/* copy primary group */
	groups[ngroups++] = pgid;

	/* copy each entry from getgrset into group list */
	যাবত্ ((grp = strsep(&grplist, ",")) != রিক্ত) {
		ll = strtoll(grp, রিক্ত, 10);
		যদি (ngroups >= maxgroups || ll < 0 || ll > UID_MAX) {
			ret = -1;
			গচ্ছ out;
		}
		gid = (gid_t)ll;
		যদি (gid == pgid)
			অনুবর্ত;	/* we have already added primary gid */
		groups[ngroups++] = gid;
	}
out:
	মুক্ত(cp);
	*grpcnt = ngroups;
	প্রত্যাগম ret;
}
# endif	/* USE_GETGRSET */

#endif /* _AIX */
