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
#అన్తర్భావ "includes.h"

#నిర్వచితమైతే _AIX

#అన్తర్భావ "xmalloc.h"
#అన్తర్భావ "sshbuf.h"
#అన్తర్భావ "ssherr.h"
#అన్తర్భావ "sshkey.h"
#అన్తర్భావ "hostfile.h"
#అన్తర్భావ "auth.h"
#అన్తర్భావ "ssh.h"
#అన్తర్భావ "ssh_api.h"
#అన్తర్భావ "log.h"

#అన్తర్భావ <errno.h>
#ఒకవేళ defined(HAVE_NETDB_H)
# include <netdb.h>
#అయితే_ముగింపు
#అన్తర్భావ <uinfo.h>
#అన్తర్భావ <stdarg.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <unistd.h>
#అన్తర్భావ <sys/socket.h>

#నిర్వచితమైతే WITH_AIXAUTHENTICATE
# include <login.h>
# include <userpw.h>
# ఒకవేళ defined(HAVE_SYS_AUDIT_H) && defined(AIX_LOGINFAILED_4ARG)
#  include <sys/audit.h>
# endif
# include <usersec.h>
#అయితే_ముగింపు

#అన్తర్భావ "port-aix.h"

స్థిర అక్షరం *lastlogin_సందేశం = ఖాళీ;

# ifdef HAVE_SETAUTHDB
స్థిర అక్షరం old_registry[REGISTRY_కొలత] = "";
# endif

/*
 * AIX has a "usrinfo" area where logname and other stuff is stored -
 * a few applications actually use this and die if it's not set
 *
 * NOTE: TTY= should be set, but since no one uses it and it's hard to
 * acquire due to privsep code.  We will just drop support.
 */
శూన్య
aix_usrinfo(నిర్మాణం passwd *pw)
{
	u_int i;
	కొలత_t len;
	అక్షరం *cp;

	len = పరిమాణం("LOGNAME= NAME= ") + (2 * అక్షరశ్రేణి_పొడవు(pw->pw_name));
	cp = xmalloc(len);

	i = snprintf(cp, len, "LOGNAME=%s%cNAME=%s%c", pw->pw_name, '\0',
	    pw->pw_name, '\0');
	ఒకవేళ (usrinfo(SETUINFO, cp, i) == -1)
		fatal("Couldn't set usrinfo: %s", strerror(errno));
	debug3("AIX/UsrInfo: set len %d", i);

	విడుదల(cp);
}

# ifdef WITH_AIXAUTHENTICATE
/*
 * Remove embedded newlines in string (if any).
 * Used before logging messages returned by AIX authentication functions
 * so the message is logged on one line.
 */
శూన్య
aix_remove_embedded_newlines(అక్షరం *p)
{
	ఒకవేళ (p == ఖాళీ)
		తిరిగి;

	కొరకు (; *p; p++) {
		ఒకవేళ (*p == '\n')
			*p = ' ';
	}
	/* Remove trailing whitespace */
	ఒకవేళ (*--p == ' ')
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
స్థిర పూర్ణాంకం
aix_valid_authentications(స్థిరరాశి అక్షరం *user)
{
	అక్షరం *auth1, *sys, *p;
	పూర్ణాంకం valid = 1;

	ఒకవేళ (getuserattr((అక్షరం *)user, S_AUTHSYSTEM, &sys, SEC_CHAR) != 0) {
		logit("Can't retrieve attribute SYSTEM for %s: %.100s",
		    user, strerror(errno));
		తిరిగి 0;
	}

	debug3("AIX SYSTEM attribute %s", sys);
	ఒకవేళ (strcmp(sys, "NONE") != 0)
		తిరిగి 1;	/* not "NONE", so is OK */

	ఒకవేళ (getuserattr((అక్షరం *)user, S_AUTH1, &auth1, SEC_LIST) != 0) {
		logit("Can't retrieve attribute auth1 for %s: %.100s",
		    user, strerror(errno));
		తిరిగి 0;
	}

	p = auth1;
	/* A SEC_LIST is concatenated strings, ending with two NULs. */
	అయితే (p[0] != '\0' && p[1] != '\0') {
		debug3("AIX auth1 attribute list member %s", p);
		ఒకవేళ (strcmp(p, "NONE") != 0 && strcmp(p, "SYSTEM")) {
			logit("Account %s has unsupported auth1 value '%s'",
			    user, p);
			valid = 0;
		}
		p += అక్షరశ్రేణి_పొడవు(p) + 1;
	}

	తిరిగి (valid);
}

/*
 * Do authentication via AIX's authenticate routine.  We loop until the
 * reenter parameter is 0, but normally authenticate is called only once.
 *
 * Note: this function returns 1 on success, whereas AIX's authenticate()
 * returns 0.
 */
పూర్ణాంకం
sys_auth_passwd(నిర్మాణం ssh *ssh, స్థిరరాశి అక్షరం *password)
{
	Authctxt *ctxt = ssh->authctxt;
	అక్షరం *authmsg = ఖాళీ, *సందేశం = ఖాళీ, *name = ctxt->pw->pw_name;
	పూర్ణాంకం r, authsuccess = 0, expired, reenter, ఫలితం;

	చేయి {
		ఫలితం = authenticate((అక్షరం *)name, (అక్షరం *)password, &reenter,
		    &authmsg);
		aix_remove_embedded_newlines(authmsg);
		debug3("AIX/authenticate result %d, authmsg %.100s", ఫలితం,
		    authmsg);
	} అయితే (reenter);

	ఒకవేళ (!aix_valid_authentications(name))
		ఫలితం = -1;

	ఒకవేళ (ఫలితం == 0) {
		authsuccess = 1;

		/*
		 * Record successful login.  We don't have a pty yet, so just
		 * label the line as "ssh"
		 */
		aix_setauthdb(name);

		/*
		 * Check if the user's password is expired.
		 */
		expired = passwdexpired(name, &సందేశం);
		ఒకవేళ (సందేశం && *సందేశం) {
			ఒకవేళ ((r = sshbuf_put(ctxt->loginmsg,
			    సందేశం, అక్షరశ్రేణి_పొడవు(సందేశం))) != 0)
				fatal("%s: buffer error: %s",
				    __func__, ssh_err(r));
			aix_remove_embedded_newlines(సందేశం);
		}
		debug3("AIX/passwdexpired returned %d msg %.100s", expired, సందేశం);

		ఎంపిక (expired) {
		స్థితి 0: /* password not expired */
			ఆపు;
		స్థితి 1: /* expired, password change required */
			ctxt->force_pwchange = 1;
			ఆపు;
		అప్రమేయ: /* user can't change(2) or other error (-1) */
			logit("Password can't be changed for user %s: %.100s",
			    name, సందేశం);
			విడుదల(సందేశం);
			authsuccess = 0;
		}

		aix_restoreauthdb();
	}

	విడుదల(authmsg);

	తిరిగి authsuccess;
}

/*
 * Check if specified account is permitted to log in.
 * Returns 1 if login is allowed, 0 if not allowed.
 */
పూర్ణాంకం
sys_auth_allowed_user(నిర్మాణం passwd *pw, నిర్మాణం sshbuf *loginmsg)
{
	అక్షరం *సందేశం = ఖాళీ;
	పూర్ణాంకం r, ఫలితం, permitted = 0;
	నిర్మాణం stat st;

	/*
	 * Don't perform checks for root account (PermitRootLogin controls
	 * logins via ssh) or if running as non-root user (since
	 * loginrestrictions will always fail due to insufficient privilege).
	 */
	ఒకవేళ (pw->pw_uid == 0 || geteuid() != 0) {
		debug3("%s: not checking", __func__);
		తిరిగి 1;
	}

	ఫలితం = loginrestrictions(pw->pw_name, S_RLOGIN, ఖాళీ, &సందేశం);
	ఒకవేళ (ఫలితం == 0)
		permitted = 1;
	/*
	 * If restricted because /etc/nologin exists, the login will be denied
	 * in session.c after the nologin message is sent, so allow for now
	 * and do not append the returned message.
	 */
	ఒకవేళ (ఫలితం == -1 && errno == EPERM && stat(_PATH_NOLOGIN, &st) == 0)
		permitted = 1;
	లేకపోతే ఒకవేళ (సందేశం != ఖాళీ) {
		ఒకవేళ ((r = sshbuf_put(loginmsg, సందేశం, అక్షరశ్రేణి_పొడవు(సందేశం))) != 0)
			fatal("%s: buffer error: %s", __func__, ssh_err(r));
	}
	ఒకవేళ (సందేశం == ఖాళీ)
		సందేశం = xstrdup("(none)");
	aix_remove_embedded_newlines(సందేశం);
	debug3("AIX/loginrestrictions returned %d msg %.100s", ఫలితం, సందేశం);

	ఒకవేళ (!permitted)
		logit("Login restricted for %s: %.100s", pw->pw_name, సందేశం);
	విడుదల(సందేశం);
	తిరిగి permitted;
}

పూర్ణాంకం
sys_auth_రికార్డు_login(స్థిరరాశి అక్షరం *user, స్థిరరాశి అక్షరం *host, స్థిరరాశి అక్షరం *ttynm,
    నిర్మాణం sshbuf *loginmsg)
{
	అక్షరం *సందేశం = ఖాళీ;
	పూర్ణాంకం success = 0;

	aix_setauthdb(user);
	ఒకవేళ (loginsuccess((అక్షరం *)user, (అక్షరం *)host, (అక్షరం *)ttynm, &సందేశం) == 0) {
		success = 1;
		ఒకవేళ (సందేశం != ఖాళీ) {
			debug("AIX/loginsuccess: msg %s", సందేశం);
			ఒకవేళ (lastlogin_సందేశం == ఖాళీ)
				lastlogin_సందేశం = సందేశం;
		}
	}
	aix_restoreauthdb();
	తిరిగి (success);
}

అక్షరం *
sys_auth_get_lastlogin_సందేశం(స్థిరరాశి అక్షరం *user, uid_t uid)
{
	అక్షరం *సందేశం = lastlogin_సందేశం;

	lastlogin_సందేశం = ఖాళీ;
	తిరిగి సందేశం;
}

#  ifdef CUSTOM_FAILED_LOGIN
/*
 * record_failed_login: generic "login failed" interface function
 */
శూన్య
రికార్డు_failed_login(నిర్మాణం ssh *ssh, స్థిరరాశి అక్షరం *user, స్థిరరాశి అక్షరం *hostname,
    స్థిరరాశి అక్షరం *ttyname)
{
	ఒకవేళ (geteuid() != 0)
		తిరిగి;

	aix_setauthdb(user);
#   ifdef AIX_LOGINFAILED_4ARG
	loginfailed((అక్షరం *)user, (అక్షరం *)hostname, (అక్షరం *)ttyname,
	    AUDIT_FAIL_AUTH);
#   లేకపోతే
	loginfailed((అక్షరం *)user, (అక్షరం *)hostname, (అక్షరం *)ttyname);
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
శూన్య
aix_setauthdb(స్థిరరాశి అక్షరం *user)
{
#  ifdef HAVE_SETAUTHDB
	అక్షరం *registry;

	ఒకవేళ (setuserdb(S_READ) == -1) {
		debug3("%s: Could not open userdb to read", __func__);
		తిరిగి;
	}

	ఒకవేళ (getuserattr((అక్షరం *)user, S_REGISTRY, &registry, SEC_CHAR) == 0) {
		ఒకవేళ (setauthdb(registry, old_registry) == 0)
			debug3("AIX/setauthdb set registry '%s'", registry);
		లేకపోతే
			debug3("AIX/setauthdb set registry '%s' failed: %s",
			    registry, strerror(errno));
	} లేకపోతే
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
శూన్య
aix_restoreauthdb(శూన్య)
{
#  ifdef HAVE_SETAUTHDB
	ఒకవేళ (setauthdb(old_registry, ఖాళీ) == 0)
		debug3("%s: restoring old registry '%s'", __func__,
		    old_registry);
	లేకపోతే
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
అక్షరం *
aix_krb5_get_principal_name(స్థిరరాశి అక్షరం *const_pw_name)
{
	అక్షరం *pw_name = (అక్షరం *)const_pw_name;
	అక్షరం *authname = ఖాళీ, *authdomain = ఖాళీ, *principal = ఖాళీ;

	setuserdb(S_READ);
	ఒకవేళ (getuserattr(pw_name, S_AUTHDOMAIN, &authdomain, SEC_CHAR) != 0)
		debug("AIX getuserattr S_AUTHDOMAIN: %s", strerror(errno));
	ఒకవేళ (getuserattr(pw_name, S_AUTHNAME, &authname, SEC_CHAR) != 0)
		debug("AIX getuserattr S_AUTHNAME: %s", strerror(errno));

	ఒకవేళ (authdomain != ఖాళీ)
		xasprintf(&principal, "%s@%s", authname ? authname : pw_name,
		    authdomain);
	లేకపోతే ఒకవేళ (authname != ఖాళీ)
		principal = xstrdup(authname);
	enduserdb();
	తిరిగి principal;
}
# endif /* USE_AIX_KRB_NAME */

# ఒకవేళ defined(AIX_GETNAMEINFO_HACK) && !defined(BROKEN_ADDRINFO)
# undef getnameinfo
/*
 * For some reason, AIX's getnameinfo will refuse to resolve the all-zeros
 * IPv6 address into its textual representation ("::"), so we wrap it
 * with a function that will.
 */
పూర్ణాంకం
sshaix_getnameinfo(స్థిరరాశి నిర్మాణం sockaddr *sa, కొలత_t salen, అక్షరం *host,
    కొలత_t hostlen, అక్షరం *serv, కొలత_t servlen, పూర్ణాంకం flags)
{
	నిర్మాణం sockaddr_in6 *sa6;
	u_int32_t *a6;

	ఒకవేళ (flags & (NI_NUMERICHOST|NI_NUMERICSERV) &&
	    sa->sa_family == AF_INET6) {
		sa6 = (నిర్మాణం sockaddr_in6 *)sa;
		a6 = sa6->sin6_addr.u6_addr.u6_addr32;

		ఒకవేళ (a6[0] == 0 && a6[1] == 0 && a6[2] == 0 && a6[3] == 0) {
			strlcpy(host, "::", hostlen);
			snprintf(serv, servlen, "%d", sa6->sin6_port);
			తిరిగి 0;
		}
	}
	తిరిగి getnameinfo(sa, salen, host, hostlen, serv, servlen, flags);
}
# endif /* AIX_GETNAMEINFO_HACK */

# ఒకవేళ defined(USE_GETGRSET)
#  include <stdlib.h>
పూర్ణాంకం
getgrouplist(స్థిరరాశి అక్షరం *user, gid_t pgid, gid_t *groups, పూర్ణాంకం *grpcnt)
{
	అక్షరం *cp, *grplist, *grp;
	gid_t gid;
	పూర్ణాంకం ret = 0, ngroups = 0, maxgroups;
	దీర్ఘ దీర్ఘ ll;

	maxgroups = *grpcnt;

	ఒకవేళ ((cp = grplist = getgrset(user)) == ఖాళీ)
		తిరిగి -1;

	/* handle zero-length case */
	ఒకవేళ (maxgroups <= 0) {
		*grpcnt = 0;
		తిరిగి -1;
	}

	/* copy primary group */
	groups[ngroups++] = pgid;

	/* copy each entry from getgrset into group list */
	అయితే ((grp = strsep(&grplist, ",")) != ఖాళీ) {
		ll = strtoll(grp, ఖాళీ, 10);
		ఒకవేళ (ngroups >= maxgroups || ll < 0 || ll > UID_MAX) {
			ret = -1;
			వెళ్ళు బహిర్గతం;
		}
		gid = (gid_t)ll;
		ఒకవేళ (gid == pgid)
			కొనసాగు;	/* we have already added primary gid */
		groups[ngroups++] = gid;
	}
బహిర్గతం:
	విడుదల(cp);
	*grpcnt = ngroups;
	తిరిగి ret;
}
# endif	/* USE_GETGRSET */

#అయితే_ముగింపు /* _AIX */
