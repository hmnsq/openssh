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
#ಅನ್ತರ್ಭಾವ "includes.h"

#ifdef _AIX

#ಅನ್ತರ್ಭಾವ "xmalloc.h"
#ಅನ್ತರ್ಭಾವ "sshbuf.h"
#ಅನ್ತರ್ಭಾವ "ssherr.h"
#ಅನ್ತರ್ಭಾವ "sshkey.h"
#ಅನ್ತರ್ಭಾವ "hostfile.h"
#ಅನ್ತರ್ಭಾವ "auth.h"
#ಅನ್ತರ್ಭಾವ "ssh.h"
#ಅನ್ತರ್ಭಾವ "ssh_api.h"
#ಅನ್ತರ್ಭಾವ "log.h"

#ಅನ್ತರ್ಭಾವ <errno.h>
#ಯದಿ defined(HAVE_NETDB_H)
# include <netdb.h>
#endif
#ಅನ್ತರ್ಭಾವ <uinfo.h>
#ಅನ್ತರ್ಭಾವ <stdarg.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <unistd.h>
#ಅನ್ತರ್ಭಾವ <sys/socket.h>

#ifdef WITH_AIXAUTHENTICATE
# include <login.h>
# include <userpw.h>
# ಯದಿ defined(HAVE_SYS_AUDIT_H) && defined(AIX_LOGINFAILED_4ARG)
#  include <sys/audit.h>
# endif
# include <usersec.h>
#endif

#ಅನ್ತರ್ಭಾವ "port-aix.h"

ಸ್ಥಿರ ವರ್ಣ *lastlogin_ಸಂದೇಶ = ರಿಕ್ತ;

# ifdef HAVE_SETAUTHDB
ಸ್ಥಿರ ವರ್ಣ old_registry[REGISTRY_SIZE] = "";
# endif

/*
 * AIX has a "usrinfo" area where logname and other stuff is stored -
 * a few applications actually use this and die if it's not set
 *
 * NOTE: TTY= should be set, but since no one uses it and it's hard to
 * acquire due to privsep code.  We will just drop support.
 */
ಶೂನ್ಯ
aix_usrinfo(ಸಂರಚನಾ passwd *pw)
{
	u_int i;
	size_t len;
	ವರ್ಣ *cp;

	len = ಪರಿಮಾಣ("LOGNAME= NAME= ") + (2 * strlen(pw->pw_name));
	cp = xmalloc(len);

	i = snprintf(cp, len, "LOGNAME=%s%cNAME=%s%c", pw->pw_name, '\0',
	    pw->pw_name, '\0');
	ಯದಿ (usrinfo(SETUINFO, cp, i) == -1)
		fatal("Couldn't set usrinfo: %s", strerror(errno));
	debug3("AIX/UsrInfo: set len %d", i);

	ಮುಕ್ತ(cp);
}

# ifdef WITH_AIXAUTHENTICATE
/*
 * Remove embedded newlines in string (if any).
 * Used before logging messages returned by AIX authentication functions
 * so the message is logged on one line.
 */
ಶೂನ್ಯ
aix_remove_embedded_newlines(ವರ್ಣ *p)
{
	ಯದಿ (p == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ;

	ಪ್ರತಿ (; *p; p++) {
		ಯದಿ (*p == '\n')
			*p = ' ';
	}
	/* Remove trailing whitespace */
	ಯದಿ (*--p == ' ')
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
ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ
aix_valid_authentications(ಧ್ರುವ ವರ್ಣ *user)
{
	ವರ್ಣ *auth1, *sys, *p;
	ಪೂರ್ಣಾಙ್ಕ valid = 1;

	ಯದಿ (getuserattr((ವರ್ಣ *)user, S_AUTHSYSTEM, &sys, SEC_CHAR) != 0) {
		logit("Can't retrieve attribute SYSTEM for %s: %.100s",
		    user, strerror(errno));
		ಪ್ರತ್ಯಾಗಮ 0;
	}

	debug3("AIX SYSTEM attribute %s", sys);
	ಯದಿ (strcmp(sys, "NONE") != 0)
		ಪ್ರತ್ಯಾಗಮ 1;	/* not "NONE", so is OK */

	ಯದಿ (getuserattr((ವರ್ಣ *)user, S_AUTH1, &auth1, SEC_LIST) != 0) {
		logit("Can't retrieve attribute auth1 for %s: %.100s",
		    user, strerror(errno));
		ಪ್ರತ್ಯಾಗಮ 0;
	}

	p = auth1;
	/* A SEC_LIST is concatenated strings, ending with two NULs. */
	ಯಾವತ್ (p[0] != '\0' && p[1] != '\0') {
		debug3("AIX auth1 attribute list member %s", p);
		ಯದಿ (strcmp(p, "NONE") != 0 && strcmp(p, "SYSTEM")) {
			logit("Account %s has unsupported auth1 value '%s'",
			    user, p);
			valid = 0;
		}
		p += strlen(p) + 1;
	}

	ಪ್ರತ್ಯಾಗಮ (valid);
}

/*
 * Do authentication via AIX's authenticate routine.  We loop until the
 * reenter parameter is 0, but normally authenticate is called only once.
 *
 * Note: this function returns 1 on success, whereas AIX's authenticate()
 * returns 0.
 */
ಪೂರ್ಣಾಙ್ಕ
sys_auth_passwd(ಸಂರಚನಾ ssh *ssh, ಧ್ರುವ ವರ್ಣ *password)
{
	Authctxt *ctxt = ssh->authctxt;
	ವರ್ಣ *authmsg = ರಿಕ್ತ, *ಸಂದೇಶ = ರಿಕ್ತ, *name = ctxt->pw->pw_name;
	ಪೂರ್ಣಾಙ್ಕ r, authsuccess = 0, expired, reenter, result;

	ಕುರು {
		result = authenticate((ವರ್ಣ *)name, (ವರ್ಣ *)password, &reenter,
		    &authmsg);
		aix_remove_embedded_newlines(authmsg);
		debug3("AIX/authenticate result %d, authmsg %.100s", result,
		    authmsg);
	} ಯಾವತ್ (reenter);

	ಯದಿ (!aix_valid_authentications(name))
		result = -1;

	ಯದಿ (result == 0) {
		authsuccess = 1;

		/*
		 * Record successful login.  We don't have a pty yet, so just
		 * label the line as "ssh"
		 */
		aix_setauthdb(name);

		/*
		 * Check if the user's password is expired.
		 */
		expired = passwdexpired(name, &ಸಂದೇಶ);
		ಯದಿ (ಸಂದೇಶ && *ಸಂದೇಶ) {
			ಯದಿ ((r = sshbuf_put(ctxt->loginmsg,
			    ಸಂದೇಶ, strlen(ಸಂದೇಶ))) != 0)
				fatal("%s: buffer error: %s",
				    __func__, ssh_err(r));
			aix_remove_embedded_newlines(ಸಂದೇಶ);
		}
		debug3("AIX/passwdexpired returned %d msg %.100s", expired, ಸಂದೇಶ);

		ವಿಕಲ್ಪ (expired) {
		ಪಕ್ಷ 0: /* password not expired */
			ಭಙ್ಗ;
		ಪಕ್ಷ 1: /* expired, password change required */
			ctxt->force_pwchange = 1;
			ಭಙ್ಗ;
		ಸ್ವಭಾವ: /* user can't change(2) or other error (-1) */
			logit("Password can't be changed for user %s: %.100s",
			    name, ಸಂದೇಶ);
			ಮುಕ್ತ(ಸಂದೇಶ);
			authsuccess = 0;
		}

		aix_restoreauthdb();
	}

	ಮುಕ್ತ(authmsg);

	ಪ್ರತ್ಯಾಗಮ authsuccess;
}

/*
 * Check if specified account is permitted to log in.
 * Returns 1 if login is allowed, 0 if not allowed.
 */
ಪೂರ್ಣಾಙ್ಕ
sys_auth_allowed_user(ಸಂರಚನಾ passwd *pw, ಸಂರಚನಾ sshbuf *loginmsg)
{
	ವರ್ಣ *ಸಂದೇಶ = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ r, result, permitted = 0;
	ಸಂರಚನಾ stat st;

	/*
	 * Don't perform checks for root account (PermitRootLogin controls
	 * logins via ssh) or if running as non-root user (since
	 * loginrestrictions will always fail due to insufficient privilege).
	 */
	ಯದಿ (pw->pw_uid == 0 || geteuid() != 0) {
		debug3("%s: not checking", __func__);
		ಪ್ರತ್ಯಾಗಮ 1;
	}

	result = loginrestrictions(pw->pw_name, S_RLOGIN, ರಿಕ್ತ, &ಸಂದೇಶ);
	ಯದಿ (result == 0)
		permitted = 1;
	/*
	 * If restricted because /etc/nologin exists, the login will be denied
	 * in session.c after the nologin message is sent, so allow for now
	 * and do not append the returned message.
	 */
	ಯದಿ (result == -1 && errno == EPERM && stat(_PATH_NOLOGIN, &st) == 0)
		permitted = 1;
	ಅನ್ಯಥಾ ಯದಿ (ಸಂದೇಶ != ರಿಕ್ತ) {
		ಯದಿ ((r = sshbuf_put(loginmsg, ಸಂದೇಶ, strlen(ಸಂದೇಶ))) != 0)
			fatal("%s: buffer error: %s", __func__, ssh_err(r));
	}
	ಯದಿ (ಸಂದೇಶ == ರಿಕ್ತ)
		ಸಂದೇಶ = xstrdup("(none)");
	aix_remove_embedded_newlines(ಸಂದೇಶ);
	debug3("AIX/loginrestrictions returned %d msg %.100s", result, ಸಂದೇಶ);

	ಯದಿ (!permitted)
		logit("Login restricted for %s: %.100s", pw->pw_name, ಸಂದೇಶ);
	ಮುಕ್ತ(ಸಂದೇಶ);
	ಪ್ರತ್ಯಾಗಮ permitted;
}

ಪೂರ್ಣಾಙ್ಕ
sys_auth_record_login(ಧ್ರುವ ವರ್ಣ *user, ಧ್ರುವ ವರ್ಣ *host, ಧ್ರುವ ವರ್ಣ *ttynm,
    ಸಂರಚನಾ sshbuf *loginmsg)
{
	ವರ್ಣ *ಸಂದೇಶ = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ success = 0;

	aix_setauthdb(user);
	ಯದಿ (loginsuccess((ವರ್ಣ *)user, (ವರ್ಣ *)host, (ವರ್ಣ *)ttynm, &ಸಂದೇಶ) == 0) {
		success = 1;
		ಯದಿ (ಸಂದೇಶ != ರಿಕ್ತ) {
			debug("AIX/loginsuccess: msg %s", ಸಂದೇಶ);
			ಯದಿ (lastlogin_ಸಂದೇಶ == ರಿಕ್ತ)
				lastlogin_ಸಂದೇಶ = ಸಂದೇಶ;
		}
	}
	aix_restoreauthdb();
	ಪ್ರತ್ಯಾಗಮ (success);
}

ವರ್ಣ *
sys_auth_get_lastlogin_ಸಂದೇಶ(ಧ್ರುವ ವರ್ಣ *user, uid_t uid)
{
	ವರ್ಣ *ಸಂದೇಶ = lastlogin_ಸಂದೇಶ;

	lastlogin_ಸಂದೇಶ = ರಿಕ್ತ;
	ಪ್ರತ್ಯಾಗಮ ಸಂದೇಶ;
}

#  ifdef CUSTOM_FAILED_LOGIN
/*
 * record_failed_login: generic "login failed" interface function
 */
ಶೂನ್ಯ
record_failed_login(ಸಂರಚನಾ ssh *ssh, ಧ್ರುವ ವರ್ಣ *user, ಧ್ರುವ ವರ್ಣ *hostname,
    ಧ್ರುವ ವರ್ಣ *ttyname)
{
	ಯದಿ (geteuid() != 0)
		ಪ್ರತ್ಯಾಗಮ;

	aix_setauthdb(user);
#   ifdef AIX_LOGINFAILED_4ARG
	loginfailed((ವರ್ಣ *)user, (ವರ್ಣ *)hostname, (ವರ್ಣ *)ttyname,
	    AUDIT_FAIL_AUTH);
#   ಅನ್ಯಥಾ
	loginfailed((ವರ್ಣ *)user, (ವರ್ಣ *)hostname, (ವರ್ಣ *)ttyname);
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
ಶೂನ್ಯ
aix_setauthdb(ಧ್ರುವ ವರ್ಣ *user)
{
#  ifdef HAVE_SETAUTHDB
	ವರ್ಣ *registry;

	ಯದಿ (setuserdb(S_READ) == -1) {
		debug3("%s: Could not open userdb to read", __func__);
		ಪ್ರತ್ಯಾಗಮ;
	}

	ಯದಿ (getuserattr((ವರ್ಣ *)user, S_REGISTRY, &registry, SEC_CHAR) == 0) {
		ಯದಿ (setauthdb(registry, old_registry) == 0)
			debug3("AIX/setauthdb set registry '%s'", registry);
		ಅನ್ಯಥಾ
			debug3("AIX/setauthdb set registry '%s' failed: %s",
			    registry, strerror(errno));
	} ಅನ್ಯಥಾ
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
ಶೂನ್ಯ
aix_restoreauthdb(ಶೂನ್ಯ)
{
#  ifdef HAVE_SETAUTHDB
	ಯದಿ (setauthdb(old_registry, ರಿಕ್ತ) == 0)
		debug3("%s: restoring old registry '%s'", __func__,
		    old_registry);
	ಅನ್ಯಥಾ
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
ವರ್ಣ *
aix_krb5_get_principal_name(ಧ್ರುವ ವರ್ಣ *const_pw_name)
{
	ವರ್ಣ *pw_name = (ವರ್ಣ *)const_pw_name;
	ವರ್ಣ *authname = ರಿಕ್ತ, *authdomain = ರಿಕ್ತ, *principal = ರಿಕ್ತ;

	setuserdb(S_READ);
	ಯದಿ (getuserattr(pw_name, S_AUTHDOMAIN, &authdomain, SEC_CHAR) != 0)
		debug("AIX getuserattr S_AUTHDOMAIN: %s", strerror(errno));
	ಯದಿ (getuserattr(pw_name, S_AUTHNAME, &authname, SEC_CHAR) != 0)
		debug("AIX getuserattr S_AUTHNAME: %s", strerror(errno));

	ಯದಿ (authdomain != ರಿಕ್ತ)
		xasprintf(&principal, "%s@%s", authname ? authname : pw_name,
		    authdomain);
	ಅನ್ಯಥಾ ಯದಿ (authname != ರಿಕ್ತ)
		principal = xstrdup(authname);
	enduserdb();
	ಪ್ರತ್ಯಾಗಮ principal;
}
# endif /* USE_AIX_KRB_NAME */

# ಯದಿ defined(AIX_GETNAMEINFO_HACK) && !defined(BROKEN_ADDRINFO)
# undef getnameinfo
/*
 * For some reason, AIX's getnameinfo will refuse to resolve the all-zeros
 * IPv6 address into its textual representation ("::"), so we wrap it
 * with a function that will.
 */
ಪೂರ್ಣಾಙ್ಕ
sshaix_getnameinfo(ಧ್ರುವ ಸಂರಚನಾ sockaddr *sa, size_t salen, ವರ್ಣ *host,
    size_t hostlen, ವರ್ಣ *serv, size_t servlen, ಪೂರ್ಣಾಙ್ಕ flags)
{
	ಸಂರಚನಾ sockaddr_in6 *sa6;
	u_int32_t *a6;

	ಯದಿ (flags & (NI_NUMERICHOST|NI_NUMERICSERV) &&
	    sa->sa_family == AF_INET6) {
		sa6 = (ಸಂರಚನಾ sockaddr_in6 *)sa;
		a6 = sa6->sin6_addr.u6_addr.u6_addr32;

		ಯದಿ (a6[0] == 0 && a6[1] == 0 && a6[2] == 0 && a6[3] == 0) {
			strlcpy(host, "::", hostlen);
			snprintf(serv, servlen, "%d", sa6->sin6_port);
			ಪ್ರತ್ಯಾಗಮ 0;
		}
	}
	ಪ್ರತ್ಯಾಗಮ getnameinfo(sa, salen, host, hostlen, serv, servlen, flags);
}
# endif /* AIX_GETNAMEINFO_HACK */

# ಯದಿ defined(USE_GETGRSET)
#  include <stdlib.h>
ಪೂರ್ಣಾಙ್ಕ
getgrouplist(ಧ್ರುವ ವರ್ಣ *user, gid_t pgid, gid_t *groups, ಪೂರ್ಣಾಙ್ಕ *grpcnt)
{
	ವರ್ಣ *cp, *grplist, *grp;
	gid_t gid;
	ಪೂರ್ಣಾಙ್ಕ ret = 0, ngroups = 0, maxgroups;
	long long ll;

	maxgroups = *grpcnt;

	ಯದಿ ((cp = grplist = getgrset(user)) == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ -1;

	/* handle zero-length case */
	ಯದಿ (maxgroups <= 0) {
		*grpcnt = 0;
		ಪ್ರತ್ಯಾಗಮ -1;
	}

	/* copy primary group */
	groups[ngroups++] = pgid;

	/* copy each entry from getgrset into group list */
	ಯಾವತ್ ((grp = strsep(&grplist, ",")) != ರಿಕ್ತ) {
		ll = strtoll(grp, ರಿಕ್ತ, 10);
		ಯದಿ (ngroups >= maxgroups || ll < 0 || ll > UID_MAX) {
			ret = -1;
			ಗಚ್ಛ out;
		}
		gid = (gid_t)ll;
		ಯದಿ (gid == pgid)
			ಅನುವರ್ತ;	/* we have already added primary gid */
		groups[ngroups++] = gid;
	}
out:
	ಮುಕ್ತ(cp);
	*grpcnt = ngroups;
	ಪ್ರತ್ಯಾಗಮ ret;
}
# endif	/* USE_GETGRSET */

#endif /* _AIX */
