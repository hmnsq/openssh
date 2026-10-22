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

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ _AIX

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
#ಆದರೆ defined(HAVE_NETDB_H)
# include <netdb.h>
#ಆದರೆ_ಅಂತ್ಯ
#ಅನ್ತರ್ಭಾವ <uinfo.h>
#ಅನ್ತರ್ಭಾವ <stdarg.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <unistd.h>
#ಅನ್ತರ್ಭಾವ <sys/socket.h>

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_AIXAUTHENTICATE
# include <login.h>
# include <userpw.h>
# ಆದರೆ defined(HAVE_SYS_AUDIT_H) && defined(AIX_LOGINFAILED_4ARG)
#  include <sys/audit.h>
# endif
# include <usersec.h>
#ಆದರೆ_ಅಂತ್ಯ

#ಅನ್ತರ್ಭಾವ "port-aix.h"

ಸ್ಥಿರ ಅಕ್ಷರ *lastlogin_ಸಂದೇಶ = ಖಾಲಿ;

# ifdef HAVE_SETAUTHDB
ಸ್ಥಿರ ಅಕ್ಷರ old_registry[REGISTRY_ಗಾತ್ರ] = "";
# endif

/*
 * AIX has a "usrinfo" area where logname and other stuff is stored -
 * a few applications actually use this and die if it's not set
 *
 * NOTE: TTY= should be set, but since no one uses it and it's hard to
 * acquire due to privsep code.  We will just drop support.
 */
ಶೂನ್ಯ
aix_usrinfo(ರಚನೆ passwd *pw)
{
	u_int i;
	ಗಾತ್ರ_t len;
	ಅಕ್ಷರ *cp;

	len = ಗಾತ್ರ("LOGNAME= NAME= ") + (2 * ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(pw->pw_name));
	cp = xmalloc(len);

	i = snprintf(cp, len, "LOGNAME=%s%cNAME=%s%c", pw->pw_name, '\0',
	    pw->pw_name, '\0');
	ಆದರೆ (usrinfo(SETUINFO, cp, i) == -1)
		fatal("Couldn't set usrinfo: %s", strerror(errno));
	debug3("AIX/UsrInfo: set len %d", i);

	ಬಿಡುಗಡೆ(cp);
}

# ifdef WITH_AIXAUTHENTICATE
/*
 * Remove embedded newlines in string (if any).
 * Used before logging messages returned by AIX authentication functions
 * so the message is logged on one line.
 */
ಶೂನ್ಯ
aix_remove_embedded_newlines(ಅಕ್ಷರ *p)
{
	ಆದರೆ (p == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ;

	ಗಾಗಿ (; *p; p++) {
		ಆದರೆ (*p == '\n')
			*p = ' ';
	}
	/* Remove trailing whitespace */
	ಆದರೆ (*--p == ' ')
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
ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ
aix_valid_authentications(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *user)
{
	ಅಕ್ಷರ *auth1, *sys, *p;
	ಪೂರ್ಣಾಂಕ valid = 1;

	ಆದರೆ (getuserattr((ಅಕ್ಷರ *)user, S_AUTHSYSTEM, &sys, SEC_CHAR) != 0) {
		logit("Can't retrieve attribute SYSTEM for %s: %.100s",
		    user, strerror(errno));
		ಹಿಂತಿರುಗಿ 0;
	}

	debug3("AIX SYSTEM attribute %s", sys);
	ಆದರೆ (strcmp(sys, "NONE") != 0)
		ಹಿಂತಿರುಗಿ 1;	/* not "NONE", so is OK */

	ಆದರೆ (getuserattr((ಅಕ್ಷರ *)user, S_AUTH1, &auth1, SEC_LIST) != 0) {
		logit("Can't retrieve attribute auth1 for %s: %.100s",
		    user, strerror(errno));
		ಹಿಂತಿರುಗಿ 0;
	}

	p = auth1;
	/* A SEC_LIST is concatenated strings, ending with two NULs. */
	ಆಗ (p[0] != '\0' && p[1] != '\0') {
		debug3("AIX auth1 attribute list member %s", p);
		ಆದರೆ (strcmp(p, "NONE") != 0 && strcmp(p, "SYSTEM")) {
			logit("Account %s has unsupported auth1 value '%s'",
			    user, p);
			valid = 0;
		}
		p += ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(p) + 1;
	}

	ಹಿಂತಿರುಗಿ (valid);
}

/*
 * Do authentication via AIX's authenticate routine.  We loop until the
 * reenter parameter is 0, but normally authenticate is called only once.
 *
 * Note: this function returns 1 on success, whereas AIX's authenticate()
 * returns 0.
 */
ಪೂರ್ಣಾಂಕ
sys_auth_passwd(ರಚನೆ ssh *ssh, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *password)
{
	Authctxt *ctxt = ssh->authctxt;
	ಅಕ್ಷರ *authmsg = ಖಾಲಿ, *ಸಂದೇಶ = ಖಾಲಿ, *name = ctxt->pw->pw_name;
	ಪೂರ್ಣಾಂಕ r, authsuccess = 0, expired, reenter, ಫಲಿತಾಂಶ;

	ಮಾಡು {
		ಫಲಿತಾಂಶ = authenticate((ಅಕ್ಷರ *)name, (ಅಕ್ಷರ *)password, &reenter,
		    &authmsg);
		aix_remove_embedded_newlines(authmsg);
		debug3("AIX/authenticate result %d, authmsg %.100s", ಫಲಿತಾಂಶ,
		    authmsg);
	} ಆಗ (reenter);

	ಆದರೆ (!aix_valid_authentications(name))
		ಫಲಿತಾಂಶ = -1;

	ಆದರೆ (ಫಲಿತಾಂಶ == 0) {
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
		ಆದರೆ (ಸಂದೇಶ && *ಸಂದೇಶ) {
			ಆದರೆ ((r = sshbuf_put(ctxt->loginmsg,
			    ಸಂದೇಶ, ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(ಸಂದೇಶ))) != 0)
				fatal("%s: buffer error: %s",
				    __func__, ssh_err(r));
			aix_remove_embedded_newlines(ಸಂದೇಶ);
		}
		debug3("AIX/passwdexpired returned %d msg %.100s", expired, ಸಂದೇಶ);

		ಆಯ್ಕೆ (expired) {
		ಸ್ಥಿತಿ 0: /* password not expired */
			ನಿಲ್ಲಿಸು;
		ಸ್ಥಿತಿ 1: /* expired, password change required */
			ctxt->force_pwchange = 1;
			ನಿಲ್ಲಿಸು;
		ಪೂರ್ವನಿಯೋಜಿತ: /* user can't change(2) or other error (-1) */
			logit("Password can't be changed for user %s: %.100s",
			    name, ಸಂದೇಶ);
			ಬಿಡುಗಡೆ(ಸಂದೇಶ);
			authsuccess = 0;
		}

		aix_restoreauthdb();
	}

	ಬಿಡುಗಡೆ(authmsg);

	ಹಿಂತಿರುಗಿ authsuccess;
}

/*
 * Check if specified account is permitted to log in.
 * Returns 1 if login is allowed, 0 if not allowed.
 */
ಪೂರ್ಣಾಂಕ
sys_auth_allowed_user(ರಚನೆ passwd *pw, ರಚನೆ sshbuf *loginmsg)
{
	ಅಕ್ಷರ *ಸಂದೇಶ = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ r, ಫಲಿತಾಂಶ, permitted = 0;
	ರಚನೆ stat st;

	/*
	 * Don't perform checks for root account (PermitRootLogin controls
	 * logins via ssh) or if running as non-root user (since
	 * loginrestrictions will always fail due to insufficient privilege).
	 */
	ಆದರೆ (pw->pw_uid == 0 || geteuid() != 0) {
		debug3("%s: not checking", __func__);
		ಹಿಂತಿರುಗಿ 1;
	}

	ಫಲಿತಾಂಶ = loginrestrictions(pw->pw_name, S_RLOGIN, ಖಾಲಿ, &ಸಂದೇಶ);
	ಆದರೆ (ಫಲಿತಾಂಶ == 0)
		permitted = 1;
	/*
	 * If restricted because /etc/nologin exists, the login will be denied
	 * in session.c after the nologin message is sent, so allow for now
	 * and do not append the returned message.
	 */
	ಆದರೆ (ಫಲಿತಾಂಶ == -1 && errno == EPERM && stat(_PATH_NOLOGIN, &st) == 0)
		permitted = 1;
	ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (ಸಂದೇಶ != ಖಾಲಿ) {
		ಆದರೆ ((r = sshbuf_put(loginmsg, ಸಂದೇಶ, ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(ಸಂದೇಶ))) != 0)
			fatal("%s: buffer error: %s", __func__, ssh_err(r));
	}
	ಆದರೆ (ಸಂದೇಶ == ಖಾಲಿ)
		ಸಂದೇಶ = xstrdup("(none)");
	aix_remove_embedded_newlines(ಸಂದೇಶ);
	debug3("AIX/loginrestrictions returned %d msg %.100s", ಫಲಿತಾಂಶ, ಸಂದೇಶ);

	ಆದರೆ (!permitted)
		logit("Login restricted for %s: %.100s", pw->pw_name, ಸಂದೇಶ);
	ಬಿಡುಗಡೆ(ಸಂದೇಶ);
	ಹಿಂತಿರುಗಿ permitted;
}

ಪೂರ್ಣಾಂಕ
sys_auth_ದಾಖಲೆ_login(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *user, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *host, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ttynm,
    ರಚನೆ sshbuf *loginmsg)
{
	ಅಕ್ಷರ *ಸಂದೇಶ = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ success = 0;

	aix_setauthdb(user);
	ಆದರೆ (loginsuccess((ಅಕ್ಷರ *)user, (ಅಕ್ಷರ *)host, (ಅಕ್ಷರ *)ttynm, &ಸಂದೇಶ) == 0) {
		success = 1;
		ಆದರೆ (ಸಂದೇಶ != ಖಾಲಿ) {
			debug("AIX/loginsuccess: msg %s", ಸಂದೇಶ);
			ಆದರೆ (lastlogin_ಸಂದೇಶ == ಖಾಲಿ)
				lastlogin_ಸಂದೇಶ = ಸಂದೇಶ;
		}
	}
	aix_restoreauthdb();
	ಹಿಂತಿರುಗಿ (success);
}

ಅಕ್ಷರ *
sys_auth_get_lastlogin_ಸಂದೇಶ(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *user, uid_t uid)
{
	ಅಕ್ಷರ *ಸಂದೇಶ = lastlogin_ಸಂದೇಶ;

	lastlogin_ಸಂದೇಶ = ಖಾಲಿ;
	ಹಿಂತಿರುಗಿ ಸಂದೇಶ;
}

#  ifdef CUSTOM_FAILED_LOGIN
/*
 * record_failed_login: generic "login failed" interface function
 */
ಶೂನ್ಯ
ದಾಖಲೆ_failed_login(ರಚನೆ ssh *ssh, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *user, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *hostname,
    ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ttyname)
{
	ಆದರೆ (geteuid() != 0)
		ಹಿಂತಿರುಗಿ;

	aix_setauthdb(user);
#   ifdef AIX_LOGINFAILED_4ARG
	loginfailed((ಅಕ್ಷರ *)user, (ಅಕ್ಷರ *)hostname, (ಅಕ್ಷರ *)ttyname,
	    AUDIT_FAIL_AUTH);
#   ಇಲ್ಲದಿದ್ದರೆ
	loginfailed((ಅಕ್ಷರ *)user, (ಅಕ್ಷರ *)hostname, (ಅಕ್ಷರ *)ttyname);
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
aix_setauthdb(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *user)
{
#  ifdef HAVE_SETAUTHDB
	ಅಕ್ಷರ *registry;

	ಆದರೆ (setuserdb(S_READ) == -1) {
		debug3("%s: Could not open userdb to read", __func__);
		ಹಿಂತಿರುಗಿ;
	}

	ಆದರೆ (getuserattr((ಅಕ್ಷರ *)user, S_REGISTRY, &registry, SEC_CHAR) == 0) {
		ಆದರೆ (setauthdb(registry, old_registry) == 0)
			debug3("AIX/setauthdb set registry '%s'", registry);
		ಇಲ್ಲದಿದ್ದರೆ
			debug3("AIX/setauthdb set registry '%s' failed: %s",
			    registry, strerror(errno));
	} ಇಲ್ಲದಿದ್ದರೆ
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
	ಆದರೆ (setauthdb(old_registry, ಖಾಲಿ) == 0)
		debug3("%s: restoring old registry '%s'", __func__,
		    old_registry);
	ಇಲ್ಲದಿದ್ದರೆ
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
ಅಕ್ಷರ *
aix_krb5_get_principal_name(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *const_pw_name)
{
	ಅಕ್ಷರ *pw_name = (ಅಕ್ಷರ *)const_pw_name;
	ಅಕ್ಷರ *authname = ಖಾಲಿ, *authdomain = ಖಾಲಿ, *principal = ಖಾಲಿ;

	setuserdb(S_READ);
	ಆದರೆ (getuserattr(pw_name, S_AUTHDOMAIN, &authdomain, SEC_CHAR) != 0)
		debug("AIX getuserattr S_AUTHDOMAIN: %s", strerror(errno));
	ಆದರೆ (getuserattr(pw_name, S_AUTHNAME, &authname, SEC_CHAR) != 0)
		debug("AIX getuserattr S_AUTHNAME: %s", strerror(errno));

	ಆದರೆ (authdomain != ಖಾಲಿ)
		xasprintf(&principal, "%s@%s", authname ? authname : pw_name,
		    authdomain);
	ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (authname != ಖಾಲಿ)
		principal = xstrdup(authname);
	enduserdb();
	ಹಿಂತಿರುಗಿ principal;
}
# endif /* USE_AIX_KRB_NAME */

# ಆದರೆ defined(AIX_GETNAMEINFO_HACK) && !defined(BROKEN_ADDRINFO)
# undef getnameinfo
/*
 * For some reason, AIX's getnameinfo will refuse to resolve the all-zeros
 * IPv6 address into its textual representation ("::"), so we wrap it
 * with a function that will.
 */
ಪೂರ್ಣಾಂಕ
sshaix_getnameinfo(ಸ್ಥಿರಾಂಕ ರಚನೆ sockaddr *sa, ಗಾತ್ರ_t salen, ಅಕ್ಷರ *host,
    ಗಾತ್ರ_t hostlen, ಅಕ್ಷರ *serv, ಗಾತ್ರ_t servlen, ಪೂರ್ಣಾಂಕ flags)
{
	ರಚನೆ sockaddr_in6 *sa6;
	u_int32_t *a6;

	ಆದರೆ (flags & (NI_NUMERICHOST|NI_NUMERICSERV) &&
	    sa->sa_family == AF_INET6) {
		sa6 = (ರಚನೆ sockaddr_in6 *)sa;
		a6 = sa6->sin6_addr.u6_addr.u6_addr32;

		ಆದರೆ (a6[0] == 0 && a6[1] == 0 && a6[2] == 0 && a6[3] == 0) {
			strlcpy(host, "::", hostlen);
			snprintf(serv, servlen, "%d", sa6->sin6_port);
			ಹಿಂತಿರುಗಿ 0;
		}
	}
	ಹಿಂತಿರುಗಿ getnameinfo(sa, salen, host, hostlen, serv, servlen, flags);
}
# endif /* AIX_GETNAMEINFO_HACK */

# ಆದರೆ defined(USE_GETGRSET)
#  include <stdlib.h>
ಪೂರ್ಣಾಂಕ
getgrouplist(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *user, gid_t pgid, gid_t *groups, ಪೂರ್ಣಾಂಕ *grpcnt)
{
	ಅಕ್ಷರ *cp, *grplist, *grp;
	gid_t gid;
	ಪೂರ್ಣಾಂಕ ret = 0, ngroups = 0, maxgroups;
	ದೀರ್ಘ ದೀರ್ಘ ll;

	maxgroups = *grpcnt;

	ಆದರೆ ((cp = grplist = getgrset(user)) == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ -1;

	/* handle zero-length case */
	ಆದರೆ (maxgroups <= 0) {
		*grpcnt = 0;
		ಹಿಂತಿರುಗಿ -1;
	}

	/* copy primary group */
	groups[ngroups++] = pgid;

	/* copy each entry from getgrset into group list */
	ಆಗ ((grp = strsep(&grplist, ",")) != ಖಾಲಿ) {
		ll = strtoll(grp, ಖಾಲಿ, 10);
		ಆದರೆ (ngroups >= maxgroups || ll < 0 || ll > UID_MAX) {
			ret = -1;
			ಹೋಗು ಹೊರಹೋಗು;
		}
		gid = (gid_t)ll;
		ಆದರೆ (gid == pgid)
			ಮುಂದುವರಿ;	/* we have already added primary gid */
		groups[ngroups++] = gid;
	}
ಹೊರಹೋಗು:
	ಬಿಡುಗಡೆ(cp);
	*grpcnt = ngroups;
	ಹಿಂತಿರುಗಿ ret;
}
# endif	/* USE_GETGRSET */

#ಆದರೆ_ಅಂತ್ಯ /* _AIX */
