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
#അന്തര്ഭാവ "includes.h"

#ifdef _AIX

#അന്തര്ഭാവ "xmalloc.h"
#അന്തര്ഭാവ "sshbuf.h"
#അന്തര്ഭാവ "ssherr.h"
#അന്തര്ഭാവ "sshkey.h"
#അന്തര്ഭാവ "hostfile.h"
#അന്തര്ഭാവ "auth.h"
#അന്തര്ഭാവ "ssh.h"
#അന്തര്ഭാവ "ssh_api.h"
#അന്തര്ഭാവ "log.h"

#അന്തര്ഭാവ <errno.h>
#എങ്കിൽ defined(HAVE_NETDB_H)
# include <netdb.h>
#endif
#അന്തര്ഭാവ <uinfo.h>
#അന്തര്ഭാവ <stdarg.h>
#അന്തര്ഭാവ <string.h>
#അന്തര്ഭാവ <unistd.h>
#അന്തര്ഭാവ <sys/socket.h>

#ifdef WITH_AIXAUTHENTICATE
# include <login.h>
# include <userpw.h>
# എങ്കിൽ defined(HAVE_SYS_AUDIT_H) && defined(AIX_LOGINFAILED_4ARG)
#  include <sys/audit.h>
# endif
# include <usersec.h>
#endif

#അന്തര്ഭാവ "port-aix.h"

സ്ഥിതം അക്ഷരം *lastlogin_സന്ദേശം = ശൂന്യ;

# ifdef HAVE_SETAUTHDB
സ്ഥിതം അക്ഷരം old_registry[REGISTRY_SIZE] = "";
# endif

/*
 * AIX has a "usrinfo" area where logname and other stuff is stored -
 * a few applications actually use this and die if it's not set
 *
 * NOTE: TTY= should be set, but since no one uses it and it's hard to
 * acquire due to privsep code.  We will just drop support.
 */
ശൂന്യം
aix_usrinfo(ഘടന passwd *pw)
{
	u_int i;
	size_t len;
	അക്ഷരം *cp;

	len = വലുപ്പം("LOGNAME= NAME= ") + (2 * strlen(pw->pw_name));
	cp = xmalloc(len);

	i = snprintf(cp, len, "LOGNAME=%s%cNAME=%s%c", pw->pw_name, '\0',
	    pw->pw_name, '\0');
	എങ്കിൽ (usrinfo(SETUINFO, cp, i) == -1)
		fatal("Couldn't set usrinfo: %s", strerror(errno));
	debug3("AIX/UsrInfo: set len %d", i);

	സ്വതന്ത്രം(cp);
}

# ifdef WITH_AIXAUTHENTICATE
/*
 * Remove embedded newlines in string (if any).
 * Used before logging messages returned by AIX authentication functions
 * so the message is logged on one line.
 */
ശൂന്യം
aix_remove_embedded_newlines(അക്ഷരം *p)
{
	എങ്കിൽ (p == ശൂന്യ)
		തിരികെ;

	വേണ്ടി (; *p; p++) {
		എങ്കിൽ (*p == '\n')
			*p = ' ';
	}
	/* Remove trailing whitespace */
	എങ്കിൽ (*--p == ' ')
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
സ്ഥിതം പൂർണ്ണസംഖ്യ
aix_valid_authentications(സ്ഥിരം അക്ഷരം *user)
{
	അക്ഷരം *auth1, *sys, *p;
	പൂർണ്ണസംഖ്യ valid = 1;

	എങ്കിൽ (getuserattr((അക്ഷരം *)user, S_AUTHSYSTEM, &sys, SEC_CHAR) != 0) {
		logit("Can't retrieve attribute SYSTEM for %s: %.100s",
		    user, strerror(errno));
		തിരികെ 0;
	}

	debug3("AIX SYSTEM attribute %s", sys);
	എങ്കിൽ (strcmp(sys, "NONE") != 0)
		തിരികെ 1;	/* not "NONE", so is OK */

	എങ്കിൽ (getuserattr((അക്ഷരം *)user, S_AUTH1, &auth1, SEC_LIST) != 0) {
		logit("Can't retrieve attribute auth1 for %s: %.100s",
		    user, strerror(errno));
		തിരികെ 0;
	}

	p = auth1;
	/* A SEC_LIST is concatenated strings, ending with two NULs. */
	ആകുമ്പോൾ (p[0] != '\0' && p[1] != '\0') {
		debug3("AIX auth1 attribute list member %s", p);
		എങ്കിൽ (strcmp(p, "NONE") != 0 && strcmp(p, "SYSTEM")) {
			logit("Account %s has unsupported auth1 value '%s'",
			    user, p);
			valid = 0;
		}
		p += strlen(p) + 1;
	}

	തിരികെ (valid);
}

/*
 * Do authentication via AIX's authenticate routine.  We loop until the
 * reenter parameter is 0, but normally authenticate is called only once.
 *
 * Note: this function returns 1 on success, whereas AIX's authenticate()
 * returns 0.
 */
പൂർണ്ണസംഖ്യ
sys_auth_passwd(ഘടന ssh *ssh, സ്ഥിരം അക്ഷരം *password)
{
	Authctxt *ctxt = ssh->authctxt;
	അക്ഷരം *authmsg = ശൂന്യ, *സന്ദേശം = ശൂന്യ, *name = ctxt->pw->pw_name;
	പൂർണ്ണസംഖ്യ r, authsuccess = 0, expired, reenter, result;

	ചെയ്യുക {
		result = authenticate((അക്ഷരം *)name, (അക്ഷരം *)password, &reenter,
		    &authmsg);
		aix_remove_embedded_newlines(authmsg);
		debug3("AIX/authenticate result %d, authmsg %.100s", result,
		    authmsg);
	} ആകുമ്പോൾ (reenter);

	എങ്കിൽ (!aix_valid_authentications(name))
		result = -1;

	എങ്കിൽ (result == 0) {
		authsuccess = 1;

		/*
		 * Record successful login.  We don't have a pty yet, so just
		 * label the line as "ssh"
		 */
		aix_setauthdb(name);

		/*
		 * Check if the user's password is expired.
		 */
		expired = passwdexpired(name, &സന്ദേശം);
		എങ്കിൽ (സന്ദേശം && *സന്ദേശം) {
			എങ്കിൽ ((r = sshbuf_put(ctxt->loginmsg,
			    സന്ദേശം, strlen(സന്ദേശം))) != 0)
				fatal("%s: buffer error: %s",
				    __func__, ssh_err(r));
			aix_remove_embedded_newlines(സന്ദേശം);
		}
		debug3("AIX/passwdexpired returned %d msg %.100s", expired, സന്ദേശം);

		തിരഞ്ഞെടുപ്പ് (expired) {
		അവസ്ഥ 0: /* password not expired */
			നിർത്തുക;
		അവസ്ഥ 1: /* expired, password change required */
			ctxt->force_pwchange = 1;
			നിർത്തുക;
		സ്ഥിരസ്ഥിതി: /* user can't change(2) or other error (-1) */
			logit("Password can't be changed for user %s: %.100s",
			    name, സന്ദേശം);
			സ്വതന്ത്രം(സന്ദേശം);
			authsuccess = 0;
		}

		aix_restoreauthdb();
	}

	സ്വതന്ത്രം(authmsg);

	തിരികെ authsuccess;
}

/*
 * Check if specified account is permitted to log in.
 * Returns 1 if login is allowed, 0 if not allowed.
 */
പൂർണ്ണസംഖ്യ
sys_auth_allowed_user(ഘടന passwd *pw, ഘടന sshbuf *loginmsg)
{
	അക്ഷരം *സന്ദേശം = ശൂന്യ;
	പൂർണ്ണസംഖ്യ r, result, permitted = 0;
	ഘടന stat st;

	/*
	 * Don't perform checks for root account (PermitRootLogin controls
	 * logins via ssh) or if running as non-root user (since
	 * loginrestrictions will always fail due to insufficient privilege).
	 */
	എങ്കിൽ (pw->pw_uid == 0 || geteuid() != 0) {
		debug3("%s: not checking", __func__);
		തിരികെ 1;
	}

	result = loginrestrictions(pw->pw_name, S_RLOGIN, ശൂന്യ, &സന്ദേശം);
	എങ്കിൽ (result == 0)
		permitted = 1;
	/*
	 * If restricted because /etc/nologin exists, the login will be denied
	 * in session.c after the nologin message is sent, so allow for now
	 * and do not append the returned message.
	 */
	എങ്കിൽ (result == -1 && errno == EPERM && stat(_PATH_NOLOGIN, &st) == 0)
		permitted = 1;
	അല്ലെങ്കിൽ എങ്കിൽ (സന്ദേശം != ശൂന്യ) {
		എങ്കിൽ ((r = sshbuf_put(loginmsg, സന്ദേശം, strlen(സന്ദേശം))) != 0)
			fatal("%s: buffer error: %s", __func__, ssh_err(r));
	}
	എങ്കിൽ (സന്ദേശം == ശൂന്യ)
		സന്ദേശം = xstrdup("(none)");
	aix_remove_embedded_newlines(സന്ദേശം);
	debug3("AIX/loginrestrictions returned %d msg %.100s", result, സന്ദേശം);

	എങ്കിൽ (!permitted)
		logit("Login restricted for %s: %.100s", pw->pw_name, സന്ദേശം);
	സ്വതന്ത്രം(സന്ദേശം);
	തിരികെ permitted;
}

പൂർണ്ണസംഖ്യ
sys_auth_record_login(സ്ഥിരം അക്ഷരം *user, സ്ഥിരം അക്ഷരം *host, സ്ഥിരം അക്ഷരം *ttynm,
    ഘടന sshbuf *loginmsg)
{
	അക്ഷരം *സന്ദേശം = ശൂന്യ;
	പൂർണ്ണസംഖ്യ success = 0;

	aix_setauthdb(user);
	എങ്കിൽ (loginsuccess((അക്ഷരം *)user, (അക്ഷരം *)host, (അക്ഷരം *)ttynm, &സന്ദേശം) == 0) {
		success = 1;
		എങ്കിൽ (സന്ദേശം != ശൂന്യ) {
			debug("AIX/loginsuccess: msg %s", സന്ദേശം);
			എങ്കിൽ (lastlogin_സന്ദേശം == ശൂന്യ)
				lastlogin_സന്ദേശം = സന്ദേശം;
		}
	}
	aix_restoreauthdb();
	തിരികെ (success);
}

അക്ഷരം *
sys_auth_get_lastlogin_സന്ദേശം(സ്ഥിരം അക്ഷരം *user, uid_t uid)
{
	അക്ഷരം *സന്ദേശം = lastlogin_സന്ദേശം;

	lastlogin_സന്ദേശം = ശൂന്യ;
	തിരികെ സന്ദേശം;
}

#  ifdef CUSTOM_FAILED_LOGIN
/*
 * record_failed_login: generic "login failed" interface function
 */
ശൂന്യം
record_failed_login(ഘടന ssh *ssh, സ്ഥിരം അക്ഷരം *user, സ്ഥിരം അക്ഷരം *hostname,
    സ്ഥിരം അക്ഷരം *ttyname)
{
	എങ്കിൽ (geteuid() != 0)
		തിരികെ;

	aix_setauthdb(user);
#   ifdef AIX_LOGINFAILED_4ARG
	loginfailed((അക്ഷരം *)user, (അക്ഷരം *)hostname, (അക്ഷരം *)ttyname,
	    AUDIT_FAIL_AUTH);
#   അല്ലെങ്കിൽ
	loginfailed((അക്ഷരം *)user, (അക്ഷരം *)hostname, (അക്ഷരം *)ttyname);
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
ശൂന്യം
aix_setauthdb(സ്ഥിരം അക്ഷരം *user)
{
#  ifdef HAVE_SETAUTHDB
	അക്ഷരം *registry;

	എങ്കിൽ (setuserdb(S_READ) == -1) {
		debug3("%s: Could not open userdb to read", __func__);
		തിരികെ;
	}

	എങ്കിൽ (getuserattr((അക്ഷരം *)user, S_REGISTRY, &registry, SEC_CHAR) == 0) {
		എങ്കിൽ (setauthdb(registry, old_registry) == 0)
			debug3("AIX/setauthdb set registry '%s'", registry);
		അല്ലെങ്കിൽ
			debug3("AIX/setauthdb set registry '%s' failed: %s",
			    registry, strerror(errno));
	} അല്ലെങ്കിൽ
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
ശൂന്യം
aix_restoreauthdb(ശൂന്യം)
{
#  ifdef HAVE_SETAUTHDB
	എങ്കിൽ (setauthdb(old_registry, ശൂന്യ) == 0)
		debug3("%s: restoring old registry '%s'", __func__,
		    old_registry);
	അല്ലെങ്കിൽ
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
അക്ഷരം *
aix_krb5_get_principal_name(സ്ഥിരം അക്ഷരം *const_pw_name)
{
	അക്ഷരം *pw_name = (അക്ഷരം *)const_pw_name;
	അക്ഷരം *authname = ശൂന്യ, *authdomain = ശൂന്യ, *principal = ശൂന്യ;

	setuserdb(S_READ);
	എങ്കിൽ (getuserattr(pw_name, S_AUTHDOMAIN, &authdomain, SEC_CHAR) != 0)
		debug("AIX getuserattr S_AUTHDOMAIN: %s", strerror(errno));
	എങ്കിൽ (getuserattr(pw_name, S_AUTHNAME, &authname, SEC_CHAR) != 0)
		debug("AIX getuserattr S_AUTHNAME: %s", strerror(errno));

	എങ്കിൽ (authdomain != ശൂന്യ)
		xasprintf(&principal, "%s@%s", authname ? authname : pw_name,
		    authdomain);
	അല്ലെങ്കിൽ എങ്കിൽ (authname != ശൂന്യ)
		principal = xstrdup(authname);
	enduserdb();
	തിരികെ principal;
}
# endif /* USE_AIX_KRB_NAME */

# എങ്കിൽ defined(AIX_GETNAMEINFO_HACK) && !defined(BROKEN_ADDRINFO)
# undef getnameinfo
/*
 * For some reason, AIX's getnameinfo will refuse to resolve the all-zeros
 * IPv6 address into its textual representation ("::"), so we wrap it
 * with a function that will.
 */
പൂർണ്ണസംഖ്യ
sshaix_getnameinfo(സ്ഥിരം ഘടന sockaddr *sa, size_t salen, അക്ഷരം *host,
    size_t hostlen, അക്ഷരം *serv, size_t servlen, പൂർണ്ണസംഖ്യ flags)
{
	ഘടന sockaddr_in6 *sa6;
	u_int32_t *a6;

	എങ്കിൽ (flags & (NI_NUMERICHOST|NI_NUMERICSERV) &&
	    sa->sa_family == AF_INET6) {
		sa6 = (ഘടന sockaddr_in6 *)sa;
		a6 = sa6->sin6_addr.u6_addr.u6_addr32;

		എങ്കിൽ (a6[0] == 0 && a6[1] == 0 && a6[2] == 0 && a6[3] == 0) {
			strlcpy(host, "::", hostlen);
			snprintf(serv, servlen, "%d", sa6->sin6_port);
			തിരികെ 0;
		}
	}
	തിരികെ getnameinfo(sa, salen, host, hostlen, serv, servlen, flags);
}
# endif /* AIX_GETNAMEINFO_HACK */

# എങ്കിൽ defined(USE_GETGRSET)
#  include <stdlib.h>
പൂർണ്ണസംഖ്യ
getgrouplist(സ്ഥിരം അക്ഷരം *user, gid_t pgid, gid_t *groups, പൂർണ്ണസംഖ്യ *grpcnt)
{
	അക്ഷരം *cp, *grplist, *grp;
	gid_t gid;
	പൂർണ്ണസംഖ്യ ret = 0, ngroups = 0, maxgroups;
	long long ll;

	maxgroups = *grpcnt;

	എങ്കിൽ ((cp = grplist = getgrset(user)) == ശൂന്യ)
		തിരികെ -1;

	/* handle zero-length case */
	എങ്കിൽ (maxgroups <= 0) {
		*grpcnt = 0;
		തിരികെ -1;
	}

	/* copy primary group */
	groups[ngroups++] = pgid;

	/* copy each entry from getgrset into group list */
	ആകുമ്പോൾ ((grp = strsep(&grplist, ",")) != ശൂന്യ) {
		ll = strtoll(grp, ശൂന്യ, 10);
		എങ്കിൽ (ngroups >= maxgroups || ll < 0 || ll > UID_MAX) {
			ret = -1;
			പോകുക out;
		}
		gid = (gid_t)ll;
		എങ്കിൽ (gid == pgid)
			തുടരുക;	/* we have already added primary gid */
		groups[ngroups++] = gid;
	}
out:
	സ്വതന്ത്രം(cp);
	*grpcnt = ngroups;
	തിരികെ ret;
}
# endif	/* USE_GETGRSET */

#endif /* _AIX */
