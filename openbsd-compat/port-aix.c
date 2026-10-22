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
#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ _AIX

#ਅਨ੍ਤਰ੍ਭਾਵ "xmalloc.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshbuf.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssherr.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshkey.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "hostfile.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "auth.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssh.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssh_api.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "log.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <errno.h>
#ਜੇ defined(HAVE_NETDB_H)
# include <netdb.h>
#ਜੇ_ਅੰਤ
#ਅਨ੍ਤਰ੍ਭਾਵ <uinfo.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdarg.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <unistd.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/socket.h>

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_AIXAUTHENTICATE
# include <login.h>
# include <userpw.h>
# ਜੇ defined(HAVE_SYS_AUDIT_H) && defined(AIX_LOGINFAILED_4ARG)
#  include <sys/audit.h>
# endif
# include <usersec.h>
#ਜੇ_ਅੰਤ

#ਅਨ੍ਤਰ੍ਭਾਵ "port-aix.h"

ਸਥਿਰ ਅੱਖਰ *lastlogin_ਸੁਨੇਹਾ = ਨਿਰਾ;

# ifdef HAVE_SETAUTHDB
ਸਥਿਰ ਅੱਖਰ old_registry[REGISTRY_ਮਾਪ] = "";
# endif

/*
 * AIX has a "usrinfo" area where logname and other stuff is stored -
 * a few applications actually use this and die if it's not set
 *
 * NOTE: TTY= should be set, but since no one uses it and it's hard to
 * acquire due to privsep code.  We will just drop support.
 */
ਖਾਲੀ
aix_usrinfo(ਬਣਤਰ passwd *pw)
{
	u_int i;
	ਮਾਪ_t len;
	ਅੱਖਰ *cp;

	len = ਆਕਾਰ("LOGNAME= NAME= ") + (2 * ਲੜੀ_ਲੰਬਾਈ(pw->pw_name));
	cp = xmalloc(len);

	i = snprintf(cp, len, "LOGNAME=%s%cNAME=%s%c", pw->pw_name, '\0',
	    pw->pw_name, '\0');
	ਜੇ (usrinfo(SETUINFO, cp, i) == -1)
		fatal("Couldn't set usrinfo: %s", strerror(errno));
	debug3("AIX/UsrInfo: set len %d", i);

	ਮੁਕਤ(cp);
}

# ifdef WITH_AIXAUTHENTICATE
/*
 * Remove embedded newlines in string (if any).
 * Used before logging messages returned by AIX authentication functions
 * so the message is logged on one line.
 */
ਖਾਲੀ
aix_remove_embedded_newlines(ਅੱਖਰ *p)
{
	ਜੇ (p == ਨਿਰਾ)
		ਵਾਪਸ;

	ਲਈ (; *p; p++) {
		ਜੇ (*p == '\n')
			*p = ' ';
	}
	/* Remove trailing whitespace */
	ਜੇ (*--p == ' ')
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
ਸਥਿਰ ਪੂਰਨ
aix_valid_authentications(ਅਚਲ ਅੱਖਰ *user)
{
	ਅੱਖਰ *auth1, *sys, *p;
	ਪੂਰਨ valid = 1;

	ਜੇ (getuserattr((ਅੱਖਰ *)user, S_AUTHSYSTEM, &sys, SEC_CHAR) != 0) {
		logit("Can't retrieve attribute SYSTEM for %s: %.100s",
		    user, strerror(errno));
		ਵਾਪਸ 0;
	}

	debug3("AIX SYSTEM attribute %s", sys);
	ਜੇ (strcmp(sys, "NONE") != 0)
		ਵਾਪਸ 1;	/* not "NONE", so is OK */

	ਜੇ (getuserattr((ਅੱਖਰ *)user, S_AUTH1, &auth1, SEC_LIST) != 0) {
		logit("Can't retrieve attribute auth1 for %s: %.100s",
		    user, strerror(errno));
		ਵਾਪਸ 0;
	}

	p = auth1;
	/* A SEC_LIST is concatenated strings, ending with two NULs. */
	ਜਦੋਂ (p[0] != '\0' && p[1] != '\0') {
		debug3("AIX auth1 attribute list member %s", p);
		ਜੇ (strcmp(p, "NONE") != 0 && strcmp(p, "SYSTEM")) {
			logit("Account %s has unsupported auth1 value '%s'",
			    user, p);
			valid = 0;
		}
		p += ਲੜੀ_ਲੰਬਾਈ(p) + 1;
	}

	ਵਾਪਸ (valid);
}

/*
 * Do authentication via AIX's authenticate routine.  We loop until the
 * reenter parameter is 0, but normally authenticate is called only once.
 *
 * Note: this function returns 1 on success, whereas AIX's authenticate()
 * returns 0.
 */
ਪੂਰਨ
sys_auth_passwd(ਬਣਤਰ ssh *ssh, ਅਚਲ ਅੱਖਰ *password)
{
	Authctxt *ctxt = ssh->authctxt;
	ਅੱਖਰ *authmsg = ਨਿਰਾ, *ਸੁਨੇਹਾ = ਨਿਰਾ, *name = ctxt->pw->pw_name;
	ਪੂਰਨ r, authsuccess = 0, expired, reenter, ਨਤੀਜਾ;

	ਕਰੋ {
		ਨਤੀਜਾ = authenticate((ਅੱਖਰ *)name, (ਅੱਖਰ *)password, &reenter,
		    &authmsg);
		aix_remove_embedded_newlines(authmsg);
		debug3("AIX/authenticate result %d, authmsg %.100s", ਨਤੀਜਾ,
		    authmsg);
	} ਜਦੋਂ (reenter);

	ਜੇ (!aix_valid_authentications(name))
		ਨਤੀਜਾ = -1;

	ਜੇ (ਨਤੀਜਾ == 0) {
		authsuccess = 1;

		/*
		 * Record successful login.  We don't have a pty yet, so just
		 * label the line as "ssh"
		 */
		aix_setauthdb(name);

		/*
		 * Check if the user's password is expired.
		 */
		expired = passwdexpired(name, &ਸੁਨੇਹਾ);
		ਜੇ (ਸੁਨੇਹਾ && *ਸੁਨੇਹਾ) {
			ਜੇ ((r = sshbuf_put(ctxt->loginmsg,
			    ਸੁਨੇਹਾ, ਲੜੀ_ਲੰਬਾਈ(ਸੁਨੇਹਾ))) != 0)
				fatal("%s: buffer error: %s",
				    __func__, ssh_err(r));
			aix_remove_embedded_newlines(ਸੁਨੇਹਾ);
		}
		debug3("AIX/passwdexpired returned %d msg %.100s", expired, ਸੁਨੇਹਾ);

		ਚੋਣ (expired) {
		ਹਾਲਤ 0: /* password not expired */
			ਰੋਕੋ;
		ਹਾਲਤ 1: /* expired, password change required */
			ctxt->force_pwchange = 1;
			ਰੋਕੋ;
		ਮੂਲ: /* user can't change(2) or other error (-1) */
			logit("Password can't be changed for user %s: %.100s",
			    name, ਸੁਨੇਹਾ);
			ਮੁਕਤ(ਸੁਨੇਹਾ);
			authsuccess = 0;
		}

		aix_restoreauthdb();
	}

	ਮੁਕਤ(authmsg);

	ਵਾਪਸ authsuccess;
}

/*
 * Check if specified account is permitted to log in.
 * Returns 1 if login is allowed, 0 if not allowed.
 */
ਪੂਰਨ
sys_auth_allowed_user(ਬਣਤਰ passwd *pw, ਬਣਤਰ sshbuf *loginmsg)
{
	ਅੱਖਰ *ਸੁਨੇਹਾ = ਨਿਰਾ;
	ਪੂਰਨ r, ਨਤੀਜਾ, permitted = 0;
	ਬਣਤਰ stat st;

	/*
	 * Don't perform checks for root account (PermitRootLogin controls
	 * logins via ssh) or if running as non-root user (since
	 * loginrestrictions will always fail due to insufficient privilege).
	 */
	ਜੇ (pw->pw_uid == 0 || geteuid() != 0) {
		debug3("%s: not checking", __func__);
		ਵਾਪਸ 1;
	}

	ਨਤੀਜਾ = loginrestrictions(pw->pw_name, S_RLOGIN, ਨਿਰਾ, &ਸੁਨੇਹਾ);
	ਜੇ (ਨਤੀਜਾ == 0)
		permitted = 1;
	/*
	 * If restricted because /etc/nologin exists, the login will be denied
	 * in session.c after the nologin message is sent, so allow for now
	 * and do not append the returned message.
	 */
	ਜੇ (ਨਤੀਜਾ == -1 && errno == EPERM && stat(_PATH_NOLOGIN, &st) == 0)
		permitted = 1;
	ਨਹੀਂਤਾਂ ਜੇ (ਸੁਨੇਹਾ != ਨਿਰਾ) {
		ਜੇ ((r = sshbuf_put(loginmsg, ਸੁਨੇਹਾ, ਲੜੀ_ਲੰਬਾਈ(ਸੁਨੇਹਾ))) != 0)
			fatal("%s: buffer error: %s", __func__, ssh_err(r));
	}
	ਜੇ (ਸੁਨੇਹਾ == ਨਿਰਾ)
		ਸੁਨੇਹਾ = xstrdup("(none)");
	aix_remove_embedded_newlines(ਸੁਨੇਹਾ);
	debug3("AIX/loginrestrictions returned %d msg %.100s", ਨਤੀਜਾ, ਸੁਨੇਹਾ);

	ਜੇ (!permitted)
		logit("Login restricted for %s: %.100s", pw->pw_name, ਸੁਨੇਹਾ);
	ਮੁਕਤ(ਸੁਨੇਹਾ);
	ਵਾਪਸ permitted;
}

ਪੂਰਨ
sys_auth_ਰਿਕਾਰਡ_login(ਅਚਲ ਅੱਖਰ *user, ਅਚਲ ਅੱਖਰ *host, ਅਚਲ ਅੱਖਰ *ttynm,
    ਬਣਤਰ sshbuf *loginmsg)
{
	ਅੱਖਰ *ਸੁਨੇਹਾ = ਨਿਰਾ;
	ਪੂਰਨ success = 0;

	aix_setauthdb(user);
	ਜੇ (loginsuccess((ਅੱਖਰ *)user, (ਅੱਖਰ *)host, (ਅੱਖਰ *)ttynm, &ਸੁਨੇਹਾ) == 0) {
		success = 1;
		ਜੇ (ਸੁਨੇਹਾ != ਨਿਰਾ) {
			debug("AIX/loginsuccess: msg %s", ਸੁਨੇਹਾ);
			ਜੇ (lastlogin_ਸੁਨੇਹਾ == ਨਿਰਾ)
				lastlogin_ਸੁਨੇਹਾ = ਸੁਨੇਹਾ;
		}
	}
	aix_restoreauthdb();
	ਵਾਪਸ (success);
}

ਅੱਖਰ *
sys_auth_get_lastlogin_ਸੁਨੇਹਾ(ਅਚਲ ਅੱਖਰ *user, uid_t uid)
{
	ਅੱਖਰ *ਸੁਨੇਹਾ = lastlogin_ਸੁਨੇਹਾ;

	lastlogin_ਸੁਨੇਹਾ = ਨਿਰਾ;
	ਵਾਪਸ ਸੁਨੇਹਾ;
}

#  ifdef CUSTOM_FAILED_LOGIN
/*
 * record_failed_login: generic "login failed" interface function
 */
ਖਾਲੀ
ਰਿਕਾਰਡ_failed_login(ਬਣਤਰ ssh *ssh, ਅਚਲ ਅੱਖਰ *user, ਅਚਲ ਅੱਖਰ *hostname,
    ਅਚਲ ਅੱਖਰ *ttyname)
{
	ਜੇ (geteuid() != 0)
		ਵਾਪਸ;

	aix_setauthdb(user);
#   ifdef AIX_LOGINFAILED_4ARG
	loginfailed((ਅੱਖਰ *)user, (ਅੱਖਰ *)hostname, (ਅੱਖਰ *)ttyname,
	    AUDIT_FAIL_AUTH);
#   ਨਹੀਂਤਾਂ
	loginfailed((ਅੱਖਰ *)user, (ਅੱਖਰ *)hostname, (ਅੱਖਰ *)ttyname);
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
ਖਾਲੀ
aix_setauthdb(ਅਚਲ ਅੱਖਰ *user)
{
#  ifdef HAVE_SETAUTHDB
	ਅੱਖਰ *registry;

	ਜੇ (setuserdb(S_READ) == -1) {
		debug3("%s: Could not open userdb to read", __func__);
		ਵਾਪਸ;
	}

	ਜੇ (getuserattr((ਅੱਖਰ *)user, S_REGISTRY, &registry, SEC_CHAR) == 0) {
		ਜੇ (setauthdb(registry, old_registry) == 0)
			debug3("AIX/setauthdb set registry '%s'", registry);
		ਨਹੀਂਤਾਂ
			debug3("AIX/setauthdb set registry '%s' failed: %s",
			    registry, strerror(errno));
	} ਨਹੀਂਤਾਂ
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
ਖਾਲੀ
aix_restoreauthdb(ਖਾਲੀ)
{
#  ifdef HAVE_SETAUTHDB
	ਜੇ (setauthdb(old_registry, ਨਿਰਾ) == 0)
		debug3("%s: restoring old registry '%s'", __func__,
		    old_registry);
	ਨਹੀਂਤਾਂ
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
ਅੱਖਰ *
aix_krb5_get_principal_name(ਅਚਲ ਅੱਖਰ *const_pw_name)
{
	ਅੱਖਰ *pw_name = (ਅੱਖਰ *)const_pw_name;
	ਅੱਖਰ *authname = ਨਿਰਾ, *authdomain = ਨਿਰਾ, *principal = ਨਿਰਾ;

	setuserdb(S_READ);
	ਜੇ (getuserattr(pw_name, S_AUTHDOMAIN, &authdomain, SEC_CHAR) != 0)
		debug("AIX getuserattr S_AUTHDOMAIN: %s", strerror(errno));
	ਜੇ (getuserattr(pw_name, S_AUTHNAME, &authname, SEC_CHAR) != 0)
		debug("AIX getuserattr S_AUTHNAME: %s", strerror(errno));

	ਜੇ (authdomain != ਨਿਰਾ)
		xasprintf(&principal, "%s@%s", authname ? authname : pw_name,
		    authdomain);
	ਨਹੀਂਤਾਂ ਜੇ (authname != ਨਿਰਾ)
		principal = xstrdup(authname);
	enduserdb();
	ਵਾਪਸ principal;
}
# endif /* USE_AIX_KRB_NAME */

# ਜੇ defined(AIX_GETNAMEINFO_HACK) && !defined(BROKEN_ADDRINFO)
# undef getnameinfo
/*
 * For some reason, AIX's getnameinfo will refuse to resolve the all-zeros
 * IPv6 address into its textual representation ("::"), so we wrap it
 * with a function that will.
 */
ਪੂਰਨ
sshaix_getnameinfo(ਅਚਲ ਬਣਤਰ sockaddr *sa, ਮਾਪ_t salen, ਅੱਖਰ *host,
    ਮਾਪ_t hostlen, ਅੱਖਰ *serv, ਮਾਪ_t servlen, ਪੂਰਨ flags)
{
	ਬਣਤਰ sockaddr_in6 *sa6;
	u_int32_t *a6;

	ਜੇ (flags & (NI_NUMERICHOST|NI_NUMERICSERV) &&
	    sa->sa_family == AF_INET6) {
		sa6 = (ਬਣਤਰ sockaddr_in6 *)sa;
		a6 = sa6->sin6_addr.u6_addr.u6_addr32;

		ਜੇ (a6[0] == 0 && a6[1] == 0 && a6[2] == 0 && a6[3] == 0) {
			strlcpy(host, "::", hostlen);
			snprintf(serv, servlen, "%d", sa6->sin6_port);
			ਵਾਪਸ 0;
		}
	}
	ਵਾਪਸ getnameinfo(sa, salen, host, hostlen, serv, servlen, flags);
}
# endif /* AIX_GETNAMEINFO_HACK */

# ਜੇ defined(USE_GETGRSET)
#  include <stdlib.h>
ਪੂਰਨ
getgrouplist(ਅਚਲ ਅੱਖਰ *user, gid_t pgid, gid_t *groups, ਪੂਰਨ *grpcnt)
{
	ਅੱਖਰ *cp, *grplist, *grp;
	gid_t gid;
	ਪੂਰਨ ret = 0, ngroups = 0, maxgroups;
	ਲੰਮਾ ਲੰਮਾ ll;

	maxgroups = *grpcnt;

	ਜੇ ((cp = grplist = getgrset(user)) == ਨਿਰਾ)
		ਵਾਪਸ -1;

	/* handle zero-length case */
	ਜੇ (maxgroups <= 0) {
		*grpcnt = 0;
		ਵਾਪਸ -1;
	}

	/* copy primary group */
	groups[ngroups++] = pgid;

	/* copy each entry from getgrset into group list */
	ਜਦੋਂ ((grp = strsep(&grplist, ",")) != ਨਿਰਾ) {
		ll = strtoll(grp, ਨਿਰਾ, 10);
		ਜੇ (ngroups >= maxgroups || ll < 0 || ll > UID_MAX) {
			ret = -1;
			ਜਾਓ ਬਾਹਰਲਾ;
		}
		gid = (gid_t)ll;
		ਜੇ (gid == pgid)
			ਜਾਰੀ;	/* we have already added primary gid */
		groups[ngroups++] = gid;
	}
ਬਾਹਰਲਾ:
	ਮੁਕਤ(cp);
	*grpcnt = ngroups;
	ਵਾਪਸ ret;
}
# endif	/* USE_GETGRSET */

#ਜੇ_ਅੰਤ /* _AIX */
