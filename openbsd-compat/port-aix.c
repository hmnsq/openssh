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
#ଅନ୍ତର୍ଭାଵ "includes.h"

#ifdef _AIX

#ଅନ୍ତର୍ଭାଵ "xmalloc.h"
#ଅନ୍ତର୍ଭାଵ "sshbuf.h"
#ଅନ୍ତର୍ଭାଵ "ssherr.h"
#ଅନ୍ତର୍ଭାଵ "sshkey.h"
#ଅନ୍ତର୍ଭାଵ "hostfile.h"
#ଅନ୍ତର୍ଭାଵ "auth.h"
#ଅନ୍ତର୍ଭାଵ "ssh.h"
#ଅନ୍ତର୍ଭାଵ "ssh_api.h"
#ଅନ୍ତର୍ଭାଵ "log.h"

#ଅନ୍ତର୍ଭାଵ <errno.h>
#ଯଦି defined(HAVE_NETDB_H)
# include <netdb.h>
#endif
#ଅନ୍ତର୍ଭାଵ <uinfo.h>
#ଅନ୍ତର୍ଭାଵ <stdarg.h>
#ଅନ୍ତର୍ଭାଵ <string.h>
#ଅନ୍ତର୍ଭାଵ <unistd.h>
#ଅନ୍ତର୍ଭାଵ <sys/socket.h>

#ifdef WITH_AIXAUTHENTICATE
# include <login.h>
# include <userpw.h>
# ଯଦି defined(HAVE_SYS_AUDIT_H) && defined(AIX_LOGINFAILED_4ARG)
#  include <sys/audit.h>
# endif
# include <usersec.h>
#endif

#ଅନ୍ତର୍ଭାଵ "port-aix.h"

ସ୍ଥିର ଅକ୍ଷର *lastlogin_ସନ୍ଦେଶ = ଖାଲି;

# ifdef HAVE_SETAUTHDB
ସ୍ଥିର ଅକ୍ଷର old_registry[REGISTRY_SIZE] = "";
# endif

/*
 * AIX has a "usrinfo" area where logname and other stuff is stored -
 * a few applications actually use this and die if it's not set
 *
 * NOTE: TTY= should be set, but since no one uses it and it's hard to
 * acquire due to privsep code.  We will just drop support.
 */
ଶୂନ୍ୟ
aix_usrinfo(ସଂରଚନା passwd *pw)
{
	u_int i;
	size_t len;
	ଅକ୍ଷର *cp;

	len = ଆକାର("LOGNAME= NAME= ") + (2 * strlen(pw->pw_name));
	cp = xmalloc(len);

	i = snprintf(cp, len, "LOGNAME=%s%cNAME=%s%c", pw->pw_name, '\0',
	    pw->pw_name, '\0');
	ଯଦି (usrinfo(SETUINFO, cp, i) == -1)
		fatal("Couldn't set usrinfo: %s", strerror(errno));
	debug3("AIX/UsrInfo: set len %d", i);

	ମୁକ୍ତ(cp);
}

# ifdef WITH_AIXAUTHENTICATE
/*
 * Remove embedded newlines in string (if any).
 * Used before logging messages returned by AIX authentication functions
 * so the message is logged on one line.
 */
ଶୂନ୍ୟ
aix_remove_embedded_newlines(ଅକ୍ଷର *p)
{
	ଯଦି (p == ଖାଲି)
		ଫେରନ୍ତୁ;

	ପାଇଁ (; *p; p++) {
		ଯଦି (*p == '\n')
			*p = ' ';
	}
	/* Remove trailing whitespace */
	ଯଦି (*--p == ' ')
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
ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା
aix_valid_authentications(ଅଚଳ ଅକ୍ଷର *user)
{
	ଅକ୍ଷର *auth1, *sys, *p;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା valid = 1;

	ଯଦି (getuserattr((ଅକ୍ଷର *)user, S_AUTHSYSTEM, &sys, SEC_CHAR) != 0) {
		logit("Can't retrieve attribute SYSTEM for %s: %.100s",
		    user, strerror(errno));
		ଫେରନ୍ତୁ 0;
	}

	debug3("AIX SYSTEM attribute %s", sys);
	ଯଦି (strcmp(sys, "NONE") != 0)
		ଫେରନ୍ତୁ 1;	/* not "NONE", so is OK */

	ଯଦି (getuserattr((ଅକ୍ଷର *)user, S_AUTH1, &auth1, SEC_LIST) != 0) {
		logit("Can't retrieve attribute auth1 for %s: %.100s",
		    user, strerror(errno));
		ଫେରନ୍ତୁ 0;
	}

	p = auth1;
	/* A SEC_LIST is concatenated strings, ending with two NULs. */
	ଯେତେବେଳେ (p[0] != '\0' && p[1] != '\0') {
		debug3("AIX auth1 attribute list member %s", p);
		ଯଦି (strcmp(p, "NONE") != 0 && strcmp(p, "SYSTEM")) {
			logit("Account %s has unsupported auth1 value '%s'",
			    user, p);
			valid = 0;
		}
		p += strlen(p) + 1;
	}

	ଫେରନ୍ତୁ (valid);
}

/*
 * Do authentication via AIX's authenticate routine.  We loop until the
 * reenter parameter is 0, but normally authenticate is called only once.
 *
 * Note: this function returns 1 on success, whereas AIX's authenticate()
 * returns 0.
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sys_auth_passwd(ସଂରଚନା ssh *ssh, ଅଚଳ ଅକ୍ଷର *password)
{
	Authctxt *ctxt = ssh->authctxt;
	ଅକ୍ଷର *authmsg = ଖାଲି, *ସନ୍ଦେଶ = ଖାଲି, *name = ctxt->pw->pw_name;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, authsuccess = 0, expired, reenter, result;

	କର {
		result = authenticate((ଅକ୍ଷର *)name, (ଅକ୍ଷର *)password, &reenter,
		    &authmsg);
		aix_remove_embedded_newlines(authmsg);
		debug3("AIX/authenticate result %d, authmsg %.100s", result,
		    authmsg);
	} ଯେତେବେଳେ (reenter);

	ଯଦି (!aix_valid_authentications(name))
		result = -1;

	ଯଦି (result == 0) {
		authsuccess = 1;

		/*
		 * Record successful login.  We don't have a pty yet, so just
		 * label the line as "ssh"
		 */
		aix_setauthdb(name);

		/*
		 * Check if the user's password is expired.
		 */
		expired = passwdexpired(name, &ସନ୍ଦେଶ);
		ଯଦି (ସନ୍ଦେଶ && *ସନ୍ଦେଶ) {
			ଯଦି ((r = sshbuf_put(ctxt->loginmsg,
			    ସନ୍ଦେଶ, strlen(ସନ୍ଦେଶ))) != 0)
				fatal("%s: buffer error: %s",
				    __func__, ssh_err(r));
			aix_remove_embedded_newlines(ସନ୍ଦେଶ);
		}
		debug3("AIX/passwdexpired returned %d msg %.100s", expired, ସନ୍ଦେଶ);

		ବାଛ (expired) {
		ସ୍ଥିତି 0: /* password not expired */
			ଭାଙ୍ଗ;
		ସ୍ଥିତି 1: /* expired, password change required */
			ctxt->force_pwchange = 1;
			ଭାଙ୍ଗ;
		ପୂର୍ବନିର୍ଦ୍ଧାରିତ: /* user can't change(2) or other error (-1) */
			logit("Password can't be changed for user %s: %.100s",
			    name, ସନ୍ଦେଶ);
			ମୁକ୍ତ(ସନ୍ଦେଶ);
			authsuccess = 0;
		}

		aix_restoreauthdb();
	}

	ମୁକ୍ତ(authmsg);

	ଫେରନ୍ତୁ authsuccess;
}

/*
 * Check if specified account is permitted to log in.
 * Returns 1 if login is allowed, 0 if not allowed.
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sys_auth_allowed_user(ସଂରଚନା passwd *pw, ସଂରଚନା sshbuf *loginmsg)
{
	ଅକ୍ଷର *ସନ୍ଦେଶ = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r, result, permitted = 0;
	ସଂରଚନା stat st;

	/*
	 * Don't perform checks for root account (PermitRootLogin controls
	 * logins via ssh) or if running as non-root user (since
	 * loginrestrictions will always fail due to insufficient privilege).
	 */
	ଯଦି (pw->pw_uid == 0 || geteuid() != 0) {
		debug3("%s: not checking", __func__);
		ଫେରନ୍ତୁ 1;
	}

	result = loginrestrictions(pw->pw_name, S_RLOGIN, ଖାଲି, &ସନ୍ଦେଶ);
	ଯଦି (result == 0)
		permitted = 1;
	/*
	 * If restricted because /etc/nologin exists, the login will be denied
	 * in session.c after the nologin message is sent, so allow for now
	 * and do not append the returned message.
	 */
	ଯଦି (result == -1 && errno == EPERM && stat(_PATH_NOLOGIN, &st) == 0)
		permitted = 1;
	ଅନ୍ୟଥା ଯଦି (ସନ୍ଦେଶ != ଖାଲି) {
		ଯଦି ((r = sshbuf_put(loginmsg, ସନ୍ଦେଶ, strlen(ସନ୍ଦେଶ))) != 0)
			fatal("%s: buffer error: %s", __func__, ssh_err(r));
	}
	ଯଦି (ସନ୍ଦେଶ == ଖାଲି)
		ସନ୍ଦେଶ = xstrdup("(none)");
	aix_remove_embedded_newlines(ସନ୍ଦେଶ);
	debug3("AIX/loginrestrictions returned %d msg %.100s", result, ସନ୍ଦେଶ);

	ଯଦି (!permitted)
		logit("Login restricted for %s: %.100s", pw->pw_name, ସନ୍ଦେଶ);
	ମୁକ୍ତ(ସନ୍ଦେଶ);
	ଫେରନ୍ତୁ permitted;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sys_auth_record_login(ଅଚଳ ଅକ୍ଷର *user, ଅଚଳ ଅକ୍ଷର *host, ଅଚଳ ଅକ୍ଷର *ttynm,
    ସଂରଚନା sshbuf *loginmsg)
{
	ଅକ୍ଷର *ସନ୍ଦେଶ = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା success = 0;

	aix_setauthdb(user);
	ଯଦି (loginsuccess((ଅକ୍ଷର *)user, (ଅକ୍ଷର *)host, (ଅକ୍ଷର *)ttynm, &ସନ୍ଦେଶ) == 0) {
		success = 1;
		ଯଦି (ସନ୍ଦେଶ != ଖାଲି) {
			debug("AIX/loginsuccess: msg %s", ସନ୍ଦେଶ);
			ଯଦି (lastlogin_ସନ୍ଦେଶ == ଖାଲି)
				lastlogin_ସନ୍ଦେଶ = ସନ୍ଦେଶ;
		}
	}
	aix_restoreauthdb();
	ଫେରନ୍ତୁ (success);
}

ଅକ୍ଷର *
sys_auth_get_lastlogin_ସନ୍ଦେଶ(ଅଚଳ ଅକ୍ଷର *user, uid_t uid)
{
	ଅକ୍ଷର *ସନ୍ଦେଶ = lastlogin_ସନ୍ଦେଶ;

	lastlogin_ସନ୍ଦେଶ = ଖାଲି;
	ଫେରନ୍ତୁ ସନ୍ଦେଶ;
}

#  ifdef CUSTOM_FAILED_LOGIN
/*
 * record_failed_login: generic "login failed" interface function
 */
ଶୂନ୍ୟ
record_failed_login(ସଂରଚନା ssh *ssh, ଅଚଳ ଅକ୍ଷର *user, ଅଚଳ ଅକ୍ଷର *hostname,
    ଅଚଳ ଅକ୍ଷର *ttyname)
{
	ଯଦି (geteuid() != 0)
		ଫେରନ୍ତୁ;

	aix_setauthdb(user);
#   ifdef AIX_LOGINFAILED_4ARG
	loginfailed((ଅକ୍ଷର *)user, (ଅକ୍ଷର *)hostname, (ଅକ୍ଷର *)ttyname,
	    AUDIT_FAIL_AUTH);
#   ଅନ୍ୟଥା
	loginfailed((ଅକ୍ଷର *)user, (ଅକ୍ଷର *)hostname, (ଅକ୍ଷର *)ttyname);
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
ଶୂନ୍ୟ
aix_setauthdb(ଅଚଳ ଅକ୍ଷର *user)
{
#  ifdef HAVE_SETAUTHDB
	ଅକ୍ଷର *registry;

	ଯଦି (setuserdb(S_READ) == -1) {
		debug3("%s: Could not open userdb to read", __func__);
		ଫେରନ୍ତୁ;
	}

	ଯଦି (getuserattr((ଅକ୍ଷର *)user, S_REGISTRY, &registry, SEC_CHAR) == 0) {
		ଯଦି (setauthdb(registry, old_registry) == 0)
			debug3("AIX/setauthdb set registry '%s'", registry);
		ଅନ୍ୟଥା
			debug3("AIX/setauthdb set registry '%s' failed: %s",
			    registry, strerror(errno));
	} ଅନ୍ୟଥା
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
ଶୂନ୍ୟ
aix_restoreauthdb(ଶୂନ୍ୟ)
{
#  ifdef HAVE_SETAUTHDB
	ଯଦି (setauthdb(old_registry, ଖାଲି) == 0)
		debug3("%s: restoring old registry '%s'", __func__,
		    old_registry);
	ଅନ୍ୟଥା
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
ଅକ୍ଷର *
aix_krb5_get_principal_name(ଅଚଳ ଅକ୍ଷର *const_pw_name)
{
	ଅକ୍ଷର *pw_name = (ଅକ୍ଷର *)const_pw_name;
	ଅକ୍ଷର *authname = ଖାଲି, *authdomain = ଖାଲି, *principal = ଖାଲି;

	setuserdb(S_READ);
	ଯଦି (getuserattr(pw_name, S_AUTHDOMAIN, &authdomain, SEC_CHAR) != 0)
		debug("AIX getuserattr S_AUTHDOMAIN: %s", strerror(errno));
	ଯଦି (getuserattr(pw_name, S_AUTHNAME, &authname, SEC_CHAR) != 0)
		debug("AIX getuserattr S_AUTHNAME: %s", strerror(errno));

	ଯଦି (authdomain != ଖାଲି)
		xasprintf(&principal, "%s@%s", authname ? authname : pw_name,
		    authdomain);
	ଅନ୍ୟଥା ଯଦି (authname != ଖାଲି)
		principal = xstrdup(authname);
	enduserdb();
	ଫେରନ୍ତୁ principal;
}
# endif /* USE_AIX_KRB_NAME */

# ଯଦି defined(AIX_GETNAMEINFO_HACK) && !defined(BROKEN_ADDRINFO)
# undef getnameinfo
/*
 * For some reason, AIX's getnameinfo will refuse to resolve the all-zeros
 * IPv6 address into its textual representation ("::"), so we wrap it
 * with a function that will.
 */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sshaix_getnameinfo(ଅଚଳ ସଂରଚନା sockaddr *sa, size_t salen, ଅକ୍ଷର *host,
    size_t hostlen, ଅକ୍ଷର *serv, size_t servlen, ପୂର୍ଣ୍ଣସଂଖ୍ୟା flags)
{
	ସଂରଚନା sockaddr_in6 *sa6;
	u_int32_t *a6;

	ଯଦି (flags & (NI_NUMERICHOST|NI_NUMERICSERV) &&
	    sa->sa_family == AF_INET6) {
		sa6 = (ସଂରଚନା sockaddr_in6 *)sa;
		a6 = sa6->sin6_addr.u6_addr.u6_addr32;

		ଯଦି (a6[0] == 0 && a6[1] == 0 && a6[2] == 0 && a6[3] == 0) {
			strlcpy(host, "::", hostlen);
			snprintf(serv, servlen, "%d", sa6->sin6_port);
			ଫେରନ୍ତୁ 0;
		}
	}
	ଫେରନ୍ତୁ getnameinfo(sa, salen, host, hostlen, serv, servlen, flags);
}
# endif /* AIX_GETNAMEINFO_HACK */

# ଯଦି defined(USE_GETGRSET)
#  include <stdlib.h>
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
getgrouplist(ଅଚଳ ଅକ୍ଷର *user, gid_t pgid, gid_t *groups, ପୂର୍ଣ୍ଣସଂଖ୍ୟା *grpcnt)
{
	ଅକ୍ଷର *cp, *grplist, *grp;
	gid_t gid;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା ret = 0, ngroups = 0, maxgroups;
	long long ll;

	maxgroups = *grpcnt;

	ଯଦି ((cp = grplist = getgrset(user)) == ଖାଲି)
		ଫେରନ୍ତୁ -1;

	/* handle zero-length case */
	ଯଦି (maxgroups <= 0) {
		*grpcnt = 0;
		ଫେରନ୍ତୁ -1;
	}

	/* copy primary group */
	groups[ngroups++] = pgid;

	/* copy each entry from getgrset into group list */
	ଯେତେବେଳେ ((grp = strsep(&grplist, ",")) != ଖାଲି) {
		ll = strtoll(grp, ଖାଲି, 10);
		ଯଦି (ngroups >= maxgroups || ll < 0 || ll > UID_MAX) {
			ret = -1;
			ଯାଅ out;
		}
		gid = (gid_t)ll;
		ଯଦି (gid == pgid)
			ଜାରି;	/* we have already added primary gid */
		groups[ngroups++] = gid;
	}
out:
	ମୁକ୍ତ(cp);
	*grpcnt = ngroups;
	ଫେରନ୍ତୁ ret;
}
# endif	/* USE_GETGRSET */

#endif /* _AIX */
