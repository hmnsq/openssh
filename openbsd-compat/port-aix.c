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

স্থির অক্ষর *lastlogin_বার্তা = ফাঁকা;

# ifdef HAVE_SETAUTHDB
স্থির অক্ষর old_registry[REGISTRY_আকার] = "";
# endif

/*
 * AIX has a "usrinfo" area where logname and other stuff is stored -
 * a few applications actually use this and die if it's not set
 *
 * NOTE: TTY= should be set, but since no one uses it and it's hard to
 * acquire due to privsep code.  We will just drop support.
 */
শূন্য
aix_usrinfo(কাঠামো passwd *pw)
{
	u_int i;
	আকার_t len;
	অক্ষর *cp;

	len = আকার("LOGNAME= NAME= ") + (2 * strlen(pw->pw_name));
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
aix_remove_embedded_newlines(অক্ষর *p)
{
	যদি (p == ফাঁকা)
		ফেরত;

	জন্য (; *p; p++) {
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
স্থির পূর্ণসংখ্যা
aix_valid_authentications(ধ্রুবক অক্ষর *user)
{
	অক্ষর *auth1, *sys, *p;
	পূর্ণসংখ্যা valid = 1;

	যদি (getuserattr((অক্ষর *)user, S_AUTHSYSTEM, &sys, SEC_CHAR) != 0) {
		logit("Can't retrieve attribute SYSTEM for %s: %.100s",
		    user, strerror(errno));
		ফেরত 0;
	}

	debug3("AIX SYSTEM attribute %s", sys);
	যদি (strcmp(sys, "NONE") != 0)
		ফেরত 1;	/* not "NONE", so is OK */

	যদি (getuserattr((অক্ষর *)user, S_AUTH1, &auth1, SEC_LIST) != 0) {
		logit("Can't retrieve attribute auth1 for %s: %.100s",
		    user, strerror(errno));
		ফেরত 0;
	}

	p = auth1;
	/* A SEC_LIST is concatenated strings, ending with two NULs. */
	যখন (p[0] != '\0' && p[1] != '\0') {
		debug3("AIX auth1 attribute list member %s", p);
		যদি (strcmp(p, "NONE") != 0 && strcmp(p, "SYSTEM")) {
			logit("Account %s has unsupported auth1 value '%s'",
			    user, p);
			valid = 0;
		}
		p += strlen(p) + 1;
	}

	ফেরত (valid);
}

/*
 * Do authentication via AIX's authenticate routine.  We loop until the
 * reenter parameter is 0, but normally authenticate is called only once.
 *
 * Note: this function returns 1 on success, whereas AIX's authenticate()
 * returns 0.
 */
পূর্ণসংখ্যা
sys_auth_passwd(কাঠামো ssh *ssh, ধ্রুবক অক্ষর *password)
{
	Authctxt *ctxt = ssh->authctxt;
	অক্ষর *authmsg = ফাঁকা, *বার্তা = ফাঁকা, *name = ctxt->pw->pw_name;
	পূর্ণসংখ্যা r, authsuccess = 0, expired, reenter, ফলাফল;

	করো {
		ফলাফল = authenticate((অক্ষর *)name, (অক্ষর *)password, &reenter,
		    &authmsg);
		aix_remove_embedded_newlines(authmsg);
		debug3("AIX/authenticate result %d, authmsg %.100s", ফলাফল,
		    authmsg);
	} যখন (reenter);

	যদি (!aix_valid_authentications(name))
		ফলাফল = -1;

	যদি (ফলাফল == 0) {
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

		নির্বাচন (expired) {
		ক্ষেত্র 0: /* password not expired */
			বিরতি;
		ক্ষেত্র 1: /* expired, password change required */
			ctxt->force_pwchange = 1;
			বিরতি;
		পূর্বনির্ধারিত: /* user can't change(2) or other error (-1) */
			logit("Password can't be changed for user %s: %.100s",
			    name, বার্তা);
			মুক্ত(বার্তা);
			authsuccess = 0;
		}

		aix_restoreauthdb();
	}

	মুক্ত(authmsg);

	ফেরত authsuccess;
}

/*
 * Check if specified account is permitted to log in.
 * Returns 1 if login is allowed, 0 if not allowed.
 */
পূর্ণসংখ্যা
sys_auth_allowed_user(কাঠামো passwd *pw, কাঠামো sshbuf *loginmsg)
{
	অক্ষর *বার্তা = ফাঁকা;
	পূর্ণসংখ্যা r, ফলাফল, permitted = 0;
	কাঠামো stat st;

	/*
	 * Don't perform checks for root account (PermitRootLogin controls
	 * logins via ssh) or if running as non-root user (since
	 * loginrestrictions will always fail due to insufficient privilege).
	 */
	যদি (pw->pw_uid == 0 || geteuid() != 0) {
		debug3("%s: not checking", __func__);
		ফেরত 1;
	}

	ফলাফল = loginrestrictions(pw->pw_name, S_RLOGIN, ফাঁকা, &বার্তা);
	যদি (ফলাফল == 0)
		permitted = 1;
	/*
	 * If restricted because /etc/nologin exists, the login will be denied
	 * in session.c after the nologin message is sent, so allow for now
	 * and do not append the returned message.
	 */
	যদি (ফলাফল == -1 && errno == EPERM && stat(_PATH_NOLOGIN, &st) == 0)
		permitted = 1;
	অন্যথা যদি (বার্তা != ফাঁকা) {
		যদি ((r = sshbuf_put(loginmsg, বার্তা, strlen(বার্তা))) != 0)
			fatal("%s: buffer error: %s", __func__, ssh_err(r));
	}
	যদি (বার্তা == ফাঁকা)
		বার্তা = xstrdup("(none)");
	aix_remove_embedded_newlines(বার্তা);
	debug3("AIX/loginrestrictions returned %d msg %.100s", ফলাফল, বার্তা);

	যদি (!permitted)
		logit("Login restricted for %s: %.100s", pw->pw_name, বার্তা);
	মুক্ত(বার্তা);
	ফেরত permitted;
}

পূর্ণসংখ্যা
sys_auth_record_login(ধ্রুবক অক্ষর *user, ধ্রুবক অক্ষর *host, ধ্রুবক অক্ষর *ttynm,
    কাঠামো sshbuf *loginmsg)
{
	অক্ষর *বার্তা = ফাঁকা;
	পূর্ণসংখ্যা success = 0;

	aix_setauthdb(user);
	যদি (loginsuccess((অক্ষর *)user, (অক্ষর *)host, (অক্ষর *)ttynm, &বার্তা) == 0) {
		success = 1;
		যদি (বার্তা != ফাঁকা) {
			debug("AIX/loginsuccess: msg %s", বার্তা);
			যদি (lastlogin_বার্তা == ফাঁকা)
				lastlogin_বার্তা = বার্তা;
		}
	}
	aix_restoreauthdb();
	ফেরত (success);
}

অক্ষর *
sys_auth_get_lastlogin_বার্তা(ধ্রুবক অক্ষর *user, uid_t uid)
{
	অক্ষর *বার্তা = lastlogin_বার্তা;

	lastlogin_বার্তা = ফাঁকা;
	ফেরত বার্তা;
}

#  ifdef CUSTOM_FAILED_LOGIN
/*
 * record_failed_login: generic "login failed" interface function
 */
শূন্য
record_failed_login(কাঠামো ssh *ssh, ধ্রুবক অক্ষর *user, ধ্রুবক অক্ষর *hostname,
    ধ্রুবক অক্ষর *ttyname)
{
	যদি (geteuid() != 0)
		ফেরত;

	aix_setauthdb(user);
#   ifdef AIX_LOGINFAILED_4ARG
	loginfailed((অক্ষর *)user, (অক্ষর *)hostname, (অক্ষর *)ttyname,
	    AUDIT_FAIL_AUTH);
#   অন্যথা
	loginfailed((অক্ষর *)user, (অক্ষর *)hostname, (অক্ষর *)ttyname);
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
aix_setauthdb(ধ্রুবক অক্ষর *user)
{
#  ifdef HAVE_SETAUTHDB
	অক্ষর *registry;

	যদি (setuserdb(S_READ) == -1) {
		debug3("%s: Could not open userdb to read", __func__);
		ফেরত;
	}

	যদি (getuserattr((অক্ষর *)user, S_REGISTRY, &registry, SEC_CHAR) == 0) {
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
	যদি (setauthdb(old_registry, ফাঁকা) == 0)
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
অক্ষর *
aix_krb5_get_principal_name(ধ্রুবক অক্ষর *const_pw_name)
{
	অক্ষর *pw_name = (অক্ষর *)const_pw_name;
	অক্ষর *authname = ফাঁকা, *authdomain = ফাঁকা, *principal = ফাঁকা;

	setuserdb(S_READ);
	যদি (getuserattr(pw_name, S_AUTHDOMAIN, &authdomain, SEC_CHAR) != 0)
		debug("AIX getuserattr S_AUTHDOMAIN: %s", strerror(errno));
	যদি (getuserattr(pw_name, S_AUTHNAME, &authname, SEC_CHAR) != 0)
		debug("AIX getuserattr S_AUTHNAME: %s", strerror(errno));

	যদি (authdomain != ফাঁকা)
		xasprintf(&principal, "%s@%s", authname ? authname : pw_name,
		    authdomain);
	অন্যথা যদি (authname != ফাঁকা)
		principal = xstrdup(authname);
	enduserdb();
	ফেরত principal;
}
# endif /* USE_AIX_KRB_NAME */

# যদি defined(AIX_GETNAMEINFO_HACK) && !defined(BROKEN_ADDRINFO)
# undef getnameinfo
/*
 * For some reason, AIX's getnameinfo will refuse to resolve the all-zeros
 * IPv6 address into its textual representation ("::"), so we wrap it
 * with a function that will.
 */
পূর্ণসংখ্যা
sshaix_getnameinfo(ধ্রুবক কাঠামো sockaddr *sa, আকার_t salen, অক্ষর *host,
    আকার_t hostlen, অক্ষর *serv, আকার_t servlen, পূর্ণসংখ্যা flags)
{
	কাঠামো sockaddr_in6 *sa6;
	u_int32_t *a6;

	যদি (flags & (NI_NUMERICHOST|NI_NUMERICSERV) &&
	    sa->sa_family == AF_INET6) {
		sa6 = (কাঠামো sockaddr_in6 *)sa;
		a6 = sa6->sin6_addr.u6_addr.u6_addr32;

		যদি (a6[0] == 0 && a6[1] == 0 && a6[2] == 0 && a6[3] == 0) {
			strlcpy(host, "::", hostlen);
			snprintf(serv, servlen, "%d", sa6->sin6_port);
			ফেরত 0;
		}
	}
	ফেরত getnameinfo(sa, salen, host, hostlen, serv, servlen, flags);
}
# endif /* AIX_GETNAMEINFO_HACK */

# যদি defined(USE_GETGRSET)
#  include <stdlib.h>
পূর্ণসংখ্যা
getgrouplist(ধ্রুবক অক্ষর *user, gid_t pgid, gid_t *groups, পূর্ণসংখ্যা *grpcnt)
{
	অক্ষর *cp, *grplist, *grp;
	gid_t gid;
	পূর্ণসংখ্যা ret = 0, ngroups = 0, maxgroups;
	long long ll;

	maxgroups = *grpcnt;

	যদি ((cp = grplist = getgrset(user)) == ফাঁকা)
		ফেরত -1;

	/* handle zero-length case */
	যদি (maxgroups <= 0) {
		*grpcnt = 0;
		ফেরত -1;
	}

	/* copy primary group */
	groups[ngroups++] = pgid;

	/* copy each entry from getgrset into group list */
	যখন ((grp = strsep(&grplist, ",")) != ফাঁকা) {
		ll = strtoll(grp, ফাঁকা, 10);
		যদি (ngroups >= maxgroups || ll < 0 || ll > UID_MAX) {
			ret = -1;
			যাও out;
		}
		gid = (gid_t)ll;
		যদি (gid == pgid)
			চালু;	/* we have already added primary gid */
		groups[ngroups++] = gid;
	}
out:
	মুক্ত(cp);
	*grpcnt = ngroups;
	ফেরত ret;
}
# endif	/* USE_GETGRSET */

#endif /* _AIX */
