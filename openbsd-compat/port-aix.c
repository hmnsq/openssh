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
#অন্তর্ভাৱ "includes.h"

#ifdef _AIX

#অন্তর্ভাৱ "xmalloc.h"
#অন্তর্ভাৱ "sshbuf.h"
#অন্তর্ভাৱ "ssherr.h"
#অন্তর্ভাৱ "sshkey.h"
#অন্তর্ভাৱ "hostfile.h"
#অন্তর্ভাৱ "auth.h"
#অন্তর্ভাৱ "ssh.h"
#অন্তর্ভাৱ "ssh_api.h"
#অন্তর্ভাৱ "log.h"

#অন্তর্ভাৱ <errno.h>
#যদি defined(HAVE_NETDB_H)
# include <netdb.h>
#endif
#অন্তর্ভাৱ <uinfo.h>
#অন্তর্ভাৱ <stdarg.h>
#অন্তর্ভাৱ <string.h>
#অন্তর্ভাৱ <unistd.h>
#অন্তর্ভাৱ <sys/socket.h>

#ifdef WITH_AIXAUTHENTICATE
# include <login.h>
# include <userpw.h>
# যদি defined(HAVE_SYS_AUDIT_H) && defined(AIX_LOGINFAILED_4ARG)
#  include <sys/audit.h>
# endif
# include <usersec.h>
#endif

#অন্তর্ভাৱ "port-aix.h"

স্থির ৱর্ণ *lastlogin_বাৰ্তা = রিক্ত;

# ifdef HAVE_SETAUTHDB
স্থির ৱর্ণ old_registry[REGISTRY_SIZE] = "";
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
	ৱর্ণ *cp;

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
aix_remove_embedded_newlines(ৱর্ণ *p)
{
	যদি (p == রিক্ত)
		ঘূৰাই;

	বাবে (; *p; p++) {
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
aix_valid_authentications(ধ্রুৱ ৱর্ণ *user)
{
	ৱর্ণ *auth1, *sys, *p;
	পূর্ণাঙ্ক valid = 1;

	যদি (getuserattr((ৱর্ণ *)user, S_AUTHSYSTEM, &sys, SEC_CHAR) != 0) {
		logit("Can't retrieve attribute SYSTEM for %s: %.100s",
		    user, strerror(errno));
		ঘূৰাই 0;
	}

	debug3("AIX SYSTEM attribute %s", sys);
	যদি (strcmp(sys, "NONE") != 0)
		ঘূৰাই 1;	/* not "NONE", so is OK */

	যদি (getuserattr((ৱর্ণ *)user, S_AUTH1, &auth1, SEC_LIST) != 0) {
		logit("Can't retrieve attribute auth1 for %s: %.100s",
		    user, strerror(errno));
		ঘূৰাই 0;
	}

	p = auth1;
	/* A SEC_LIST is concatenated strings, ending with two NULs. */
	যেতিয়ালৈ (p[0] != '\0' && p[1] != '\0') {
		debug3("AIX auth1 attribute list member %s", p);
		যদি (strcmp(p, "NONE") != 0 && strcmp(p, "SYSTEM")) {
			logit("Account %s has unsupported auth1 value '%s'",
			    user, p);
			valid = 0;
		}
		p += strlen(p) + 1;
	}

	ঘূৰাই (valid);
}

/*
 * Do authentication via AIX's authenticate routine.  We loop until the
 * reenter parameter is 0, but normally authenticate is called only once.
 *
 * Note: this function returns 1 on success, whereas AIX's authenticate()
 * returns 0.
 */
পূর্ণাঙ্ক
sys_auth_passwd(সংরচনা ssh *ssh, ধ্রুৱ ৱর্ণ *password)
{
	Authctxt *ctxt = ssh->authctxt;
	ৱর্ণ *authmsg = রিক্ত, *বাৰ্তা = রিক্ত, *name = ctxt->pw->pw_name;
	পূর্ণাঙ্ক r, authsuccess = 0, expired, reenter, result;

	কৰা {
		result = authenticate((ৱর্ণ *)name, (ৱর্ণ *)password, &reenter,
		    &authmsg);
		aix_remove_embedded_newlines(authmsg);
		debug3("AIX/authenticate result %d, authmsg %.100s", result,
		    authmsg);
	} যেতিয়ালৈ (reenter);

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
		expired = passwdexpired(name, &বাৰ্তা);
		যদি (বাৰ্তা && *বাৰ্তা) {
			যদি ((r = sshbuf_put(ctxt->loginmsg,
			    বাৰ্তা, strlen(বাৰ্তা))) != 0)
				fatal("%s: buffer error: %s",
				    __func__, ssh_err(r));
			aix_remove_embedded_newlines(বাৰ্তা);
		}
		debug3("AIX/passwdexpired returned %d msg %.100s", expired, বাৰ্তা);

		ৱিকল্প (expired) {
		পক্ষ 0: /* password not expired */
			ভঙ্গ;
		পক্ষ 1: /* expired, password change required */
			ctxt->force_pwchange = 1;
			ভঙ্গ;
		স্ৱভাৱ: /* user can't change(2) or other error (-1) */
			logit("Password can't be changed for user %s: %.100s",
			    name, বাৰ্তা);
			মুক্ত(বাৰ্তা);
			authsuccess = 0;
		}

		aix_restoreauthdb();
	}

	মুক্ত(authmsg);

	ঘূৰাই authsuccess;
}

/*
 * Check if specified account is permitted to log in.
 * Returns 1 if login is allowed, 0 if not allowed.
 */
পূর্ণাঙ্ক
sys_auth_allowed_user(সংরচনা passwd *pw, সংরচনা sshbuf *loginmsg)
{
	ৱর্ণ *বাৰ্তা = রিক্ত;
	পূর্ণাঙ্ক r, result, permitted = 0;
	সংরচনা stat st;

	/*
	 * Don't perform checks for root account (PermitRootLogin controls
	 * logins via ssh) or if running as non-root user (since
	 * loginrestrictions will always fail due to insufficient privilege).
	 */
	যদি (pw->pw_uid == 0 || geteuid() != 0) {
		debug3("%s: not checking", __func__);
		ঘূৰাই 1;
	}

	result = loginrestrictions(pw->pw_name, S_RLOGIN, রিক্ত, &বাৰ্তা);
	যদি (result == 0)
		permitted = 1;
	/*
	 * If restricted because /etc/nologin exists, the login will be denied
	 * in session.c after the nologin message is sent, so allow for now
	 * and do not append the returned message.
	 */
	যদি (result == -1 && errno == EPERM && stat(_PATH_NOLOGIN, &st) == 0)
		permitted = 1;
	অন্যথা যদি (বাৰ্তা != রিক্ত) {
		যদি ((r = sshbuf_put(loginmsg, বাৰ্তা, strlen(বাৰ্তা))) != 0)
			fatal("%s: buffer error: %s", __func__, ssh_err(r));
	}
	যদি (বাৰ্তা == রিক্ত)
		বাৰ্তা = xstrdup("(none)");
	aix_remove_embedded_newlines(বাৰ্তা);
	debug3("AIX/loginrestrictions returned %d msg %.100s", result, বাৰ্তা);

	যদি (!permitted)
		logit("Login restricted for %s: %.100s", pw->pw_name, বাৰ্তা);
	মুক্ত(বাৰ্তা);
	ঘূৰাই permitted;
}

পূর্ণাঙ্ক
sys_auth_record_login(ধ্রুৱ ৱর্ণ *user, ধ্রুৱ ৱর্ণ *host, ধ্রুৱ ৱর্ণ *ttynm,
    সংরচনা sshbuf *loginmsg)
{
	ৱর্ণ *বাৰ্তা = রিক্ত;
	পূর্ণাঙ্ক success = 0;

	aix_setauthdb(user);
	যদি (loginsuccess((ৱর্ণ *)user, (ৱর্ণ *)host, (ৱর্ণ *)ttynm, &বাৰ্তা) == 0) {
		success = 1;
		যদি (বাৰ্তা != রিক্ত) {
			debug("AIX/loginsuccess: msg %s", বাৰ্তা);
			যদি (lastlogin_বাৰ্তা == রিক্ত)
				lastlogin_বাৰ্তা = বাৰ্তা;
		}
	}
	aix_restoreauthdb();
	ঘূৰাই (success);
}

ৱর্ণ *
sys_auth_get_lastlogin_বাৰ্তা(ধ্রুৱ ৱর্ণ *user, uid_t uid)
{
	ৱর্ণ *বাৰ্তা = lastlogin_বাৰ্তা;

	lastlogin_বাৰ্তা = রিক্ত;
	ঘূৰাই বাৰ্তা;
}

#  ifdef CUSTOM_FAILED_LOGIN
/*
 * record_failed_login: generic "login failed" interface function
 */
শূন্য
record_failed_login(সংরচনা ssh *ssh, ধ্রুৱ ৱর্ণ *user, ধ্রুৱ ৱর্ণ *hostname,
    ধ্রুৱ ৱর্ণ *ttyname)
{
	যদি (geteuid() != 0)
		ঘূৰাই;

	aix_setauthdb(user);
#   ifdef AIX_LOGINFAILED_4ARG
	loginfailed((ৱর্ণ *)user, (ৱর্ণ *)hostname, (ৱর্ণ *)ttyname,
	    AUDIT_FAIL_AUTH);
#   অন্যথা
	loginfailed((ৱর্ণ *)user, (ৱর্ণ *)hostname, (ৱর্ণ *)ttyname);
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
aix_setauthdb(ধ্রুৱ ৱর্ণ *user)
{
#  ifdef HAVE_SETAUTHDB
	ৱর্ণ *registry;

	যদি (setuserdb(S_READ) == -1) {
		debug3("%s: Could not open userdb to read", __func__);
		ঘূৰাই;
	}

	যদি (getuserattr((ৱর্ণ *)user, S_REGISTRY, &registry, SEC_CHAR) == 0) {
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
ৱর্ণ *
aix_krb5_get_principal_name(ধ্রুৱ ৱর্ণ *const_pw_name)
{
	ৱর্ণ *pw_name = (ৱর্ণ *)const_pw_name;
	ৱর্ণ *authname = রিক্ত, *authdomain = রিক্ত, *principal = রিক্ত;

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
	ঘূৰাই principal;
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
sshaix_getnameinfo(ধ্রুৱ সংরচনা sockaddr *sa, size_t salen, ৱর্ণ *host,
    size_t hostlen, ৱর্ণ *serv, size_t servlen, পূর্ণাঙ্ক flags)
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
			ঘূৰাই 0;
		}
	}
	ঘূৰাই getnameinfo(sa, salen, host, hostlen, serv, servlen, flags);
}
# endif /* AIX_GETNAMEINFO_HACK */

# যদি defined(USE_GETGRSET)
#  include <stdlib.h>
পূর্ণাঙ্ক
getgrouplist(ধ্রুৱ ৱর্ণ *user, gid_t pgid, gid_t *groups, পূর্ণাঙ্ক *grpcnt)
{
	ৱর্ণ *cp, *grplist, *grp;
	gid_t gid;
	পূর্ণাঙ্ক ret = 0, ngroups = 0, maxgroups;
	long long ll;

	maxgroups = *grpcnt;

	যদি ((cp = grplist = getgrset(user)) == রিক্ত)
		ঘূৰাই -1;

	/* handle zero-length case */
	যদি (maxgroups <= 0) {
		*grpcnt = 0;
		ঘূৰাই -1;
	}

	/* copy primary group */
	groups[ngroups++] = pgid;

	/* copy each entry from getgrset into group list */
	যেতিয়ালৈ ((grp = strsep(&grplist, ",")) != রিক্ত) {
		ll = strtoll(grp, রিক্ত, 10);
		যদি (ngroups >= maxgroups || ll < 0 || ll > UID_MAX) {
			ret = -1;
			গচ্ছ out;
		}
		gid = (gid_t)ll;
		যদি (gid == pgid)
			অনুৱর্ত;	/* we have already added primary gid */
		groups[ngroups++] = gid;
	}
out:
	মুক্ত(cp);
	*grpcnt = ngroups;
	ঘূৰাই ret;
}
# endif	/* USE_GETGRSET */

#endif /* _AIX */
