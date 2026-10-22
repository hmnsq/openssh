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
#અન્તર્ભાવ "includes.h"

#ifdef _AIX

#અન્તર્ભાવ "xmalloc.h"
#અન્તર્ભાવ "sshbuf.h"
#અન્તર્ભાવ "ssherr.h"
#અન્તર્ભાવ "sshkey.h"
#અન્તર્ભાવ "hostfile.h"
#અન્તર્ભાવ "auth.h"
#અન્તર્ભાવ "ssh.h"
#અન્તર્ભાવ "ssh_api.h"
#અન્તર્ભાવ "log.h"

#અન્તર્ભાવ <errno.h>
#જો defined(HAVE_NETDB_H)
# include <netdb.h>
#endif
#અન્તર્ભાવ <uinfo.h>
#અન્તર્ભાવ <stdarg.h>
#અન્તર્ભાવ <string.h>
#અન્તર્ભાવ <unistd.h>
#અન્તર્ભાવ <sys/socket.h>

#ifdef WITH_AIXAUTHENTICATE
# include <login.h>
# include <userpw.h>
# જો defined(HAVE_SYS_AUDIT_H) && defined(AIX_LOGINFAILED_4ARG)
#  include <sys/audit.h>
# endif
# include <usersec.h>
#endif

#અન્તર્ભાવ "port-aix.h"

સ્થિર અક્ષર *lastlogin_સંદેશ = ખાલી;

# ifdef HAVE_SETAUTHDB
સ્થિર અક્ષર old_registry[REGISTRY_SIZE] = "";
# endif

/*
 * AIX has a "usrinfo" area where logname and other stuff is stored -
 * a few applications actually use this and die if it's not set
 *
 * NOTE: TTY= should be set, but since no one uses it and it's hard to
 * acquire due to privsep code.  We will just drop support.
 */
શૂન્ય
aix_usrinfo(સંરચના passwd *pw)
{
	u_int i;
	size_t len;
	અક્ષર *cp;

	len = કદ("LOGNAME= NAME= ") + (2 * strlen(pw->pw_name));
	cp = xmalloc(len);

	i = snprintf(cp, len, "LOGNAME=%s%cNAME=%s%c", pw->pw_name, '\0',
	    pw->pw_name, '\0');
	જો (usrinfo(SETUINFO, cp, i) == -1)
		fatal("Couldn't set usrinfo: %s", strerror(errno));
	debug3("AIX/UsrInfo: set len %d", i);

	મુક્ત(cp);
}

# ifdef WITH_AIXAUTHENTICATE
/*
 * Remove embedded newlines in string (if any).
 * Used before logging messages returned by AIX authentication functions
 * so the message is logged on one line.
 */
શૂન્ય
aix_remove_embedded_newlines(અક્ષર *p)
{
	જો (p == ખાલી)
		પાછા;

	માટે (; *p; p++) {
		જો (*p == '\n')
			*p = ' ';
	}
	/* Remove trailing whitespace */
	જો (*--p == ' ')
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
સ્થિર પૂર્ણાંક
aix_valid_authentications(અચલ અક્ષર *user)
{
	અક્ષર *auth1, *sys, *p;
	પૂર્ણાંક valid = 1;

	જો (getuserattr((અક્ષર *)user, S_AUTHSYSTEM, &sys, SEC_CHAR) != 0) {
		logit("Can't retrieve attribute SYSTEM for %s: %.100s",
		    user, strerror(errno));
		પાછા 0;
	}

	debug3("AIX SYSTEM attribute %s", sys);
	જો (strcmp(sys, "NONE") != 0)
		પાછા 1;	/* not "NONE", so is OK */

	જો (getuserattr((અક્ષર *)user, S_AUTH1, &auth1, SEC_LIST) != 0) {
		logit("Can't retrieve attribute auth1 for %s: %.100s",
		    user, strerror(errno));
		પાછા 0;
	}

	p = auth1;
	/* A SEC_LIST is concatenated strings, ending with two NULs. */
	જ્યારે (p[0] != '\0' && p[1] != '\0') {
		debug3("AIX auth1 attribute list member %s", p);
		જો (strcmp(p, "NONE") != 0 && strcmp(p, "SYSTEM")) {
			logit("Account %s has unsupported auth1 value '%s'",
			    user, p);
			valid = 0;
		}
		p += strlen(p) + 1;
	}

	પાછા (valid);
}

/*
 * Do authentication via AIX's authenticate routine.  We loop until the
 * reenter parameter is 0, but normally authenticate is called only once.
 *
 * Note: this function returns 1 on success, whereas AIX's authenticate()
 * returns 0.
 */
પૂર્ણાંક
sys_auth_passwd(સંરચના ssh *ssh, અચલ અક્ષર *password)
{
	Authctxt *ctxt = ssh->authctxt;
	અક્ષર *authmsg = ખાલી, *સંદેશ = ખાલી, *name = ctxt->pw->pw_name;
	પૂર્ણાંક r, authsuccess = 0, expired, reenter, result;

	કરો {
		result = authenticate((અક્ષર *)name, (અક્ષર *)password, &reenter,
		    &authmsg);
		aix_remove_embedded_newlines(authmsg);
		debug3("AIX/authenticate result %d, authmsg %.100s", result,
		    authmsg);
	} જ્યારે (reenter);

	જો (!aix_valid_authentications(name))
		result = -1;

	જો (result == 0) {
		authsuccess = 1;

		/*
		 * Record successful login.  We don't have a pty yet, so just
		 * label the line as "ssh"
		 */
		aix_setauthdb(name);

		/*
		 * Check if the user's password is expired.
		 */
		expired = passwdexpired(name, &સંદેશ);
		જો (સંદેશ && *સંદેશ) {
			જો ((r = sshbuf_put(ctxt->loginmsg,
			    સંદેશ, strlen(સંદેશ))) != 0)
				fatal("%s: buffer error: %s",
				    __func__, ssh_err(r));
			aix_remove_embedded_newlines(સંદેશ);
		}
		debug3("AIX/passwdexpired returned %d msg %.100s", expired, સંદેશ);

		પસંદગી (expired) {
		સ્થિતિ 0: /* password not expired */
			તોડો;
		સ્થિતિ 1: /* expired, password change required */
			ctxt->force_pwchange = 1;
			તોડો;
		મૂળભૂત: /* user can't change(2) or other error (-1) */
			logit("Password can't be changed for user %s: %.100s",
			    name, સંદેશ);
			મુક્ત(સંદેશ);
			authsuccess = 0;
		}

		aix_restoreauthdb();
	}

	મુક્ત(authmsg);

	પાછા authsuccess;
}

/*
 * Check if specified account is permitted to log in.
 * Returns 1 if login is allowed, 0 if not allowed.
 */
પૂર્ણાંક
sys_auth_allowed_user(સંરચના passwd *pw, સંરચના sshbuf *loginmsg)
{
	અક્ષર *સંદેશ = ખાલી;
	પૂર્ણાંક r, result, permitted = 0;
	સંરચના stat st;

	/*
	 * Don't perform checks for root account (PermitRootLogin controls
	 * logins via ssh) or if running as non-root user (since
	 * loginrestrictions will always fail due to insufficient privilege).
	 */
	જો (pw->pw_uid == 0 || geteuid() != 0) {
		debug3("%s: not checking", __func__);
		પાછા 1;
	}

	result = loginrestrictions(pw->pw_name, S_RLOGIN, ખાલી, &સંદેશ);
	જો (result == 0)
		permitted = 1;
	/*
	 * If restricted because /etc/nologin exists, the login will be denied
	 * in session.c after the nologin message is sent, so allow for now
	 * and do not append the returned message.
	 */
	જો (result == -1 && errno == EPERM && stat(_PATH_NOLOGIN, &st) == 0)
		permitted = 1;
	નહીંતર જો (સંદેશ != ખાલી) {
		જો ((r = sshbuf_put(loginmsg, સંદેશ, strlen(સંદેશ))) != 0)
			fatal("%s: buffer error: %s", __func__, ssh_err(r));
	}
	જો (સંદેશ == ખાલી)
		સંદેશ = xstrdup("(none)");
	aix_remove_embedded_newlines(સંદેશ);
	debug3("AIX/loginrestrictions returned %d msg %.100s", result, સંદેશ);

	જો (!permitted)
		logit("Login restricted for %s: %.100s", pw->pw_name, સંદેશ);
	મુક્ત(સંદેશ);
	પાછા permitted;
}

પૂર્ણાંક
sys_auth_record_login(અચલ અક્ષર *user, અચલ અક્ષર *host, અચલ અક્ષર *ttynm,
    સંરચના sshbuf *loginmsg)
{
	અક્ષર *સંદેશ = ખાલી;
	પૂર્ણાંક success = 0;

	aix_setauthdb(user);
	જો (loginsuccess((અક્ષર *)user, (અક્ષર *)host, (અક્ષર *)ttynm, &સંદેશ) == 0) {
		success = 1;
		જો (સંદેશ != ખાલી) {
			debug("AIX/loginsuccess: msg %s", સંદેશ);
			જો (lastlogin_સંદેશ == ખાલી)
				lastlogin_સંદેશ = સંદેશ;
		}
	}
	aix_restoreauthdb();
	પાછા (success);
}

અક્ષર *
sys_auth_get_lastlogin_સંદેશ(અચલ અક્ષર *user, uid_t uid)
{
	અક્ષર *સંદેશ = lastlogin_સંદેશ;

	lastlogin_સંદેશ = ખાલી;
	પાછા સંદેશ;
}

#  ifdef CUSTOM_FAILED_LOGIN
/*
 * record_failed_login: generic "login failed" interface function
 */
શૂન્ય
record_failed_login(સંરચના ssh *ssh, અચલ અક્ષર *user, અચલ અક્ષર *hostname,
    અચલ અક્ષર *ttyname)
{
	જો (geteuid() != 0)
		પાછા;

	aix_setauthdb(user);
#   ifdef AIX_LOGINFAILED_4ARG
	loginfailed((અક્ષર *)user, (અક્ષર *)hostname, (અક્ષર *)ttyname,
	    AUDIT_FAIL_AUTH);
#   નહીંતર
	loginfailed((અક્ષર *)user, (અક્ષર *)hostname, (અક્ષર *)ttyname);
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
શૂન્ય
aix_setauthdb(અચલ અક્ષર *user)
{
#  ifdef HAVE_SETAUTHDB
	અક્ષર *registry;

	જો (setuserdb(S_READ) == -1) {
		debug3("%s: Could not open userdb to read", __func__);
		પાછા;
	}

	જો (getuserattr((અક્ષર *)user, S_REGISTRY, &registry, SEC_CHAR) == 0) {
		જો (setauthdb(registry, old_registry) == 0)
			debug3("AIX/setauthdb set registry '%s'", registry);
		નહીંતર
			debug3("AIX/setauthdb set registry '%s' failed: %s",
			    registry, strerror(errno));
	} નહીંતર
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
શૂન્ય
aix_restoreauthdb(શૂન્ય)
{
#  ifdef HAVE_SETAUTHDB
	જો (setauthdb(old_registry, ખાલી) == 0)
		debug3("%s: restoring old registry '%s'", __func__,
		    old_registry);
	નહીંતર
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
અક્ષર *
aix_krb5_get_principal_name(અચલ અક્ષર *const_pw_name)
{
	અક્ષર *pw_name = (અક્ષર *)const_pw_name;
	અક્ષર *authname = ખાલી, *authdomain = ખાલી, *principal = ખાલી;

	setuserdb(S_READ);
	જો (getuserattr(pw_name, S_AUTHDOMAIN, &authdomain, SEC_CHAR) != 0)
		debug("AIX getuserattr S_AUTHDOMAIN: %s", strerror(errno));
	જો (getuserattr(pw_name, S_AUTHNAME, &authname, SEC_CHAR) != 0)
		debug("AIX getuserattr S_AUTHNAME: %s", strerror(errno));

	જો (authdomain != ખાલી)
		xasprintf(&principal, "%s@%s", authname ? authname : pw_name,
		    authdomain);
	નહીંતર જો (authname != ખાલી)
		principal = xstrdup(authname);
	enduserdb();
	પાછા principal;
}
# endif /* USE_AIX_KRB_NAME */

# જો defined(AIX_GETNAMEINFO_HACK) && !defined(BROKEN_ADDRINFO)
# undef getnameinfo
/*
 * For some reason, AIX's getnameinfo will refuse to resolve the all-zeros
 * IPv6 address into its textual representation ("::"), so we wrap it
 * with a function that will.
 */
પૂર્ણાંક
sshaix_getnameinfo(અચલ સંરચના sockaddr *sa, size_t salen, અક્ષર *host,
    size_t hostlen, અક્ષર *serv, size_t servlen, પૂર્ણાંક flags)
{
	સંરચના sockaddr_in6 *sa6;
	u_int32_t *a6;

	જો (flags & (NI_NUMERICHOST|NI_NUMERICSERV) &&
	    sa->sa_family == AF_INET6) {
		sa6 = (સંરચના sockaddr_in6 *)sa;
		a6 = sa6->sin6_addr.u6_addr.u6_addr32;

		જો (a6[0] == 0 && a6[1] == 0 && a6[2] == 0 && a6[3] == 0) {
			strlcpy(host, "::", hostlen);
			snprintf(serv, servlen, "%d", sa6->sin6_port);
			પાછા 0;
		}
	}
	પાછા getnameinfo(sa, salen, host, hostlen, serv, servlen, flags);
}
# endif /* AIX_GETNAMEINFO_HACK */

# જો defined(USE_GETGRSET)
#  include <stdlib.h>
પૂર્ણાંક
getgrouplist(અચલ અક્ષર *user, gid_t pgid, gid_t *groups, પૂર્ણાંક *grpcnt)
{
	અક્ષર *cp, *grplist, *grp;
	gid_t gid;
	પૂર્ણાંક ret = 0, ngroups = 0, maxgroups;
	long long ll;

	maxgroups = *grpcnt;

	જો ((cp = grplist = getgrset(user)) == ખાલી)
		પાછા -1;

	/* handle zero-length case */
	જો (maxgroups <= 0) {
		*grpcnt = 0;
		પાછા -1;
	}

	/* copy primary group */
	groups[ngroups++] = pgid;

	/* copy each entry from getgrset into group list */
	જ્યારે ((grp = strsep(&grplist, ",")) != ખાલી) {
		ll = strtoll(grp, ખાલી, 10);
		જો (ngroups >= maxgroups || ll < 0 || ll > UID_MAX) {
			ret = -1;
			જાઓ out;
		}
		gid = (gid_t)ll;
		જો (gid == pgid)
			ચાલુ;	/* we have already added primary gid */
		groups[ngroups++] = gid;
	}
out:
	મુક્ત(cp);
	*grpcnt = ngroups;
	પાછા ret;
}
# endif	/* USE_GETGRSET */

#endif /* _AIX */
