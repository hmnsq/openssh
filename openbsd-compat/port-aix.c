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
#அந்தர்பாவ "includes.h"

#ifdef _AIX

#அந்தர்பாவ "xmalloc.h"
#அந்தர்பாவ "sshbuf.h"
#அந்தர்பாவ "ssherr.h"
#அந்தர்பாவ "sshkey.h"
#அந்தர்பாவ "hostfile.h"
#அந்தர்பாவ "auth.h"
#அந்தர்பாவ "ssh.h"
#அந்தர்பாவ "ssh_api.h"
#அந்தர்பாவ "log.h"

#அந்தர்பாவ <errno.h>
#எனில் defined(HAVE_NETDB_H)
# include <netdb.h>
#endif
#அந்தர்பாவ <uinfo.h>
#அந்தர்பாவ <stdarg.h>
#அந்தர்பாவ <string.h>
#அந்தர்பாவ <unistd.h>
#அந்தர்பாவ <sys/socket.h>

#ifdef WITH_AIXAUTHENTICATE
# include <login.h>
# include <userpw.h>
# எனில் defined(HAVE_SYS_AUDIT_H) && defined(AIX_LOGINFAILED_4ARG)
#  include <sys/audit.h>
# endif
# include <usersec.h>
#endif

#அந்தர்பாவ "port-aix.h"

நிலையான எழுத்து *lastlogin_செய்தி = வெற்று;

# ifdef HAVE_SETAUTHDB
நிலையான எழுத்து old_registry[REGISTRY_SIZE] = "";
# endif

/*
 * AIX has a "usrinfo" area where logname and other stuff is stored -
 * a few applications actually use this and die if it's not set
 *
 * NOTE: TTY= should be set, but since no one uses it and it's hard to
 * acquire due to privsep code.  We will just drop support.
 */
வெறுமை
aix_usrinfo(கட்டமைப்பு passwd *pw)
{
	u_int i;
	size_t len;
	எழுத்து *cp;

	len = அளவு("LOGNAME= NAME= ") + (2 * strlen(pw->pw_name));
	cp = xmalloc(len);

	i = snprintf(cp, len, "LOGNAME=%s%cNAME=%s%c", pw->pw_name, '\0',
	    pw->pw_name, '\0');
	எனில் (usrinfo(SETUINFO, cp, i) == -1)
		fatal("Couldn't set usrinfo: %s", strerror(errno));
	debug3("AIX/UsrInfo: set len %d", i);

	விடுவி(cp);
}

# ifdef WITH_AIXAUTHENTICATE
/*
 * Remove embedded newlines in string (if any).
 * Used before logging messages returned by AIX authentication functions
 * so the message is logged on one line.
 */
வெறுமை
aix_remove_embedded_newlines(எழுத்து *p)
{
	எனில் (p == வெற்று)
		திரும்பு;

	க்கு (; *p; p++) {
		எனில் (*p == '\n')
			*p = ' ';
	}
	/* Remove trailing whitespace */
	எனில் (*--p == ' ')
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
நிலையான முழு
aix_valid_authentications(மாறிலி எழுத்து *user)
{
	எழுத்து *auth1, *sys, *p;
	முழு valid = 1;

	எனில் (getuserattr((எழுத்து *)user, S_AUTHSYSTEM, &sys, SEC_CHAR) != 0) {
		logit("Can't retrieve attribute SYSTEM for %s: %.100s",
		    user, strerror(errno));
		திரும்பு 0;
	}

	debug3("AIX SYSTEM attribute %s", sys);
	எனில் (strcmp(sys, "NONE") != 0)
		திரும்பு 1;	/* not "NONE", so is OK */

	எனில் (getuserattr((எழுத்து *)user, S_AUTH1, &auth1, SEC_LIST) != 0) {
		logit("Can't retrieve attribute auth1 for %s: %.100s",
		    user, strerror(errno));
		திரும்பு 0;
	}

	p = auth1;
	/* A SEC_LIST is concatenated strings, ending with two NULs. */
	போது (p[0] != '\0' && p[1] != '\0') {
		debug3("AIX auth1 attribute list member %s", p);
		எனில் (strcmp(p, "NONE") != 0 && strcmp(p, "SYSTEM")) {
			logit("Account %s has unsupported auth1 value '%s'",
			    user, p);
			valid = 0;
		}
		p += strlen(p) + 1;
	}

	திரும்பு (valid);
}

/*
 * Do authentication via AIX's authenticate routine.  We loop until the
 * reenter parameter is 0, but normally authenticate is called only once.
 *
 * Note: this function returns 1 on success, whereas AIX's authenticate()
 * returns 0.
 */
முழு
sys_auth_passwd(கட்டமைப்பு ssh *ssh, மாறிலி எழுத்து *password)
{
	Authctxt *ctxt = ssh->authctxt;
	எழுத்து *authmsg = வெற்று, *செய்தி = வெற்று, *name = ctxt->pw->pw_name;
	முழு r, authsuccess = 0, expired, reenter, result;

	செய் {
		result = authenticate((எழுத்து *)name, (எழுத்து *)password, &reenter,
		    &authmsg);
		aix_remove_embedded_newlines(authmsg);
		debug3("AIX/authenticate result %d, authmsg %.100s", result,
		    authmsg);
	} போது (reenter);

	எனில் (!aix_valid_authentications(name))
		result = -1;

	எனில் (result == 0) {
		authsuccess = 1;

		/*
		 * Record successful login.  We don't have a pty yet, so just
		 * label the line as "ssh"
		 */
		aix_setauthdb(name);

		/*
		 * Check if the user's password is expired.
		 */
		expired = passwdexpired(name, &செய்தி);
		எனில் (செய்தி && *செய்தி) {
			எனில் ((r = sshbuf_put(ctxt->loginmsg,
			    செய்தி, strlen(செய்தி))) != 0)
				fatal("%s: buffer error: %s",
				    __func__, ssh_err(r));
			aix_remove_embedded_newlines(செய்தி);
		}
		debug3("AIX/passwdexpired returned %d msg %.100s", expired, செய்தி);

		தேர்வு (expired) {
		நிலை 0: /* password not expired */
			நிறுத்து;
		நிலை 1: /* expired, password change required */
			ctxt->force_pwchange = 1;
			நிறுத்து;
		இயல்பு: /* user can't change(2) or other error (-1) */
			logit("Password can't be changed for user %s: %.100s",
			    name, செய்தி);
			விடுவி(செய்தி);
			authsuccess = 0;
		}

		aix_restoreauthdb();
	}

	விடுவி(authmsg);

	திரும்பு authsuccess;
}

/*
 * Check if specified account is permitted to log in.
 * Returns 1 if login is allowed, 0 if not allowed.
 */
முழு
sys_auth_allowed_user(கட்டமைப்பு passwd *pw, கட்டமைப்பு sshbuf *loginmsg)
{
	எழுத்து *செய்தி = வெற்று;
	முழு r, result, permitted = 0;
	கட்டமைப்பு stat st;

	/*
	 * Don't perform checks for root account (PermitRootLogin controls
	 * logins via ssh) or if running as non-root user (since
	 * loginrestrictions will always fail due to insufficient privilege).
	 */
	எனில் (pw->pw_uid == 0 || geteuid() != 0) {
		debug3("%s: not checking", __func__);
		திரும்பு 1;
	}

	result = loginrestrictions(pw->pw_name, S_RLOGIN, வெற்று, &செய்தி);
	எனில் (result == 0)
		permitted = 1;
	/*
	 * If restricted because /etc/nologin exists, the login will be denied
	 * in session.c after the nologin message is sent, so allow for now
	 * and do not append the returned message.
	 */
	எனில் (result == -1 && errno == EPERM && stat(_PATH_NOLOGIN, &st) == 0)
		permitted = 1;
	இல்லையெனில் எனில் (செய்தி != வெற்று) {
		எனில் ((r = sshbuf_put(loginmsg, செய்தி, strlen(செய்தி))) != 0)
			fatal("%s: buffer error: %s", __func__, ssh_err(r));
	}
	எனில் (செய்தி == வெற்று)
		செய்தி = xstrdup("(none)");
	aix_remove_embedded_newlines(செய்தி);
	debug3("AIX/loginrestrictions returned %d msg %.100s", result, செய்தி);

	எனில் (!permitted)
		logit("Login restricted for %s: %.100s", pw->pw_name, செய்தி);
	விடுவி(செய்தி);
	திரும்பு permitted;
}

முழு
sys_auth_record_login(மாறிலி எழுத்து *user, மாறிலி எழுத்து *host, மாறிலி எழுத்து *ttynm,
    கட்டமைப்பு sshbuf *loginmsg)
{
	எழுத்து *செய்தி = வெற்று;
	முழு success = 0;

	aix_setauthdb(user);
	எனில் (loginsuccess((எழுத்து *)user, (எழுத்து *)host, (எழுத்து *)ttynm, &செய்தி) == 0) {
		success = 1;
		எனில் (செய்தி != வெற்று) {
			debug("AIX/loginsuccess: msg %s", செய்தி);
			எனில் (lastlogin_செய்தி == வெற்று)
				lastlogin_செய்தி = செய்தி;
		}
	}
	aix_restoreauthdb();
	திரும்பு (success);
}

எழுத்து *
sys_auth_get_lastlogin_செய்தி(மாறிலி எழுத்து *user, uid_t uid)
{
	எழுத்து *செய்தி = lastlogin_செய்தி;

	lastlogin_செய்தி = வெற்று;
	திரும்பு செய்தி;
}

#  ifdef CUSTOM_FAILED_LOGIN
/*
 * record_failed_login: generic "login failed" interface function
 */
வெறுமை
record_failed_login(கட்டமைப்பு ssh *ssh, மாறிலி எழுத்து *user, மாறிலி எழுத்து *hostname,
    மாறிலி எழுத்து *ttyname)
{
	எனில் (geteuid() != 0)
		திரும்பு;

	aix_setauthdb(user);
#   ifdef AIX_LOGINFAILED_4ARG
	loginfailed((எழுத்து *)user, (எழுத்து *)hostname, (எழுத்து *)ttyname,
	    AUDIT_FAIL_AUTH);
#   இல்லையெனில்
	loginfailed((எழுத்து *)user, (எழுத்து *)hostname, (எழுத்து *)ttyname);
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
வெறுமை
aix_setauthdb(மாறிலி எழுத்து *user)
{
#  ifdef HAVE_SETAUTHDB
	எழுத்து *registry;

	எனில் (setuserdb(S_READ) == -1) {
		debug3("%s: Could not open userdb to read", __func__);
		திரும்பு;
	}

	எனில் (getuserattr((எழுத்து *)user, S_REGISTRY, &registry, SEC_CHAR) == 0) {
		எனில் (setauthdb(registry, old_registry) == 0)
			debug3("AIX/setauthdb set registry '%s'", registry);
		இல்லையெனில்
			debug3("AIX/setauthdb set registry '%s' failed: %s",
			    registry, strerror(errno));
	} இல்லையெனில்
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
வெறுமை
aix_restoreauthdb(வெறுமை)
{
#  ifdef HAVE_SETAUTHDB
	எனில் (setauthdb(old_registry, வெற்று) == 0)
		debug3("%s: restoring old registry '%s'", __func__,
		    old_registry);
	இல்லையெனில்
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
எழுத்து *
aix_krb5_get_principal_name(மாறிலி எழுத்து *const_pw_name)
{
	எழுத்து *pw_name = (எழுத்து *)const_pw_name;
	எழுத்து *authname = வெற்று, *authdomain = வெற்று, *principal = வெற்று;

	setuserdb(S_READ);
	எனில் (getuserattr(pw_name, S_AUTHDOMAIN, &authdomain, SEC_CHAR) != 0)
		debug("AIX getuserattr S_AUTHDOMAIN: %s", strerror(errno));
	எனில் (getuserattr(pw_name, S_AUTHNAME, &authname, SEC_CHAR) != 0)
		debug("AIX getuserattr S_AUTHNAME: %s", strerror(errno));

	எனில் (authdomain != வெற்று)
		xasprintf(&principal, "%s@%s", authname ? authname : pw_name,
		    authdomain);
	இல்லையெனில் எனில் (authname != வெற்று)
		principal = xstrdup(authname);
	enduserdb();
	திரும்பு principal;
}
# endif /* USE_AIX_KRB_NAME */

# எனில் defined(AIX_GETNAMEINFO_HACK) && !defined(BROKEN_ADDRINFO)
# undef getnameinfo
/*
 * For some reason, AIX's getnameinfo will refuse to resolve the all-zeros
 * IPv6 address into its textual representation ("::"), so we wrap it
 * with a function that will.
 */
முழு
sshaix_getnameinfo(மாறிலி கட்டமைப்பு sockaddr *sa, size_t salen, எழுத்து *host,
    size_t hostlen, எழுத்து *serv, size_t servlen, முழு flags)
{
	கட்டமைப்பு sockaddr_in6 *sa6;
	u_int32_t *a6;

	எனில் (flags & (NI_NUMERICHOST|NI_NUMERICSERV) &&
	    sa->sa_family == AF_INET6) {
		sa6 = (கட்டமைப்பு sockaddr_in6 *)sa;
		a6 = sa6->sin6_addr.u6_addr.u6_addr32;

		எனில் (a6[0] == 0 && a6[1] == 0 && a6[2] == 0 && a6[3] == 0) {
			strlcpy(host, "::", hostlen);
			snprintf(serv, servlen, "%d", sa6->sin6_port);
			திரும்பு 0;
		}
	}
	திரும்பு getnameinfo(sa, salen, host, hostlen, serv, servlen, flags);
}
# endif /* AIX_GETNAMEINFO_HACK */

# எனில் defined(USE_GETGRSET)
#  include <stdlib.h>
முழு
getgrouplist(மாறிலி எழுத்து *user, gid_t pgid, gid_t *groups, முழு *grpcnt)
{
	எழுத்து *cp, *grplist, *grp;
	gid_t gid;
	முழு ret = 0, ngroups = 0, maxgroups;
	long long ll;

	maxgroups = *grpcnt;

	எனில் ((cp = grplist = getgrset(user)) == வெற்று)
		திரும்பு -1;

	/* handle zero-length case */
	எனில் (maxgroups <= 0) {
		*grpcnt = 0;
		திரும்பு -1;
	}

	/* copy primary group */
	groups[ngroups++] = pgid;

	/* copy each entry from getgrset into group list */
	போது ((grp = strsep(&grplist, ",")) != வெற்று) {
		ll = strtoll(grp, வெற்று, 10);
		எனில் (ngroups >= maxgroups || ll < 0 || ll > UID_MAX) {
			ret = -1;
			செல் out;
		}
		gid = (gid_t)ll;
		எனில் (gid == pgid)
			தொடர்;	/* we have already added primary gid */
		groups[ngroups++] = gid;
	}
out:
	விடுவி(cp);
	*grpcnt = ngroups;
	திரும்பு ret;
}
# endif	/* USE_GETGRSET */

#endif /* _AIX */
