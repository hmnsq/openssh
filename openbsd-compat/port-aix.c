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
#include "includes.h"

#ifdef _AIX

#include "xmalloc.h"
#include "sshbuf.h"
#include "ssherr.h"
#include "sshkey.h"
#include "hostfile.h"
#include "auth.h"
#include "ssh.h"
#include "ssh_api.h"
#include "log.h"

#include <errno.h>
#если defined(HAVE_NETDB_H)
# include <netdb.h>
#endif
#include <uinfo.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>

#ifdef WITH_AIXAUTHENTICATE
# include <login.h>
# include <userpw.h>
# если defined(HAVE_SYS_AUDIT_H) && defined(AIX_LOGINFAILED_4ARG)
#  include <sys/audit.h>
# endif
# include <usersec.h>
#endif

#include "port-aix.h"

static char *lastlogin_msg = NULL;

# ifdef HAVE_SETAUTHDB
static char old_registry[REGISTRY_SIZE] = "";
# endif

/*
 * AIX has a "usrinfo" area where logname and other stuff is stored -
 * a few applications actually use this and die if it's not set
 *
 * NOTE: TTY= should be set, but since no one uses it and it's hard to
 * acquire due to privsep code.  We will just drop support.
 */
void
aix_usrinfo(struct passwd *pw)
{
	u_int i;
	size_t len;
	char *cp;

	len = sizeof("LOGNAME= NAME= ") + (2 * strlen(pw->pw_name));
	cp = xmalloc(len);

	i = snprintf(cp, len, "LOGNAME=%s%cNAME=%s%c", pw->pw_name, '\0',
	    pw->pw_name, '\0');
	если (usrinfo(SETUINFO, cp, i) == -1)
		fatal("Couldn't set usrinfo: %s", strerror(errno));
	debug3("AIX/UsrInfo: set len %d", i);

	free(cp);
}

# ifdef WITH_AIXAUTHENTICATE
/*
 * Remove embedded newlines in string (if any).
 * Used before logging messages returned by AIX authentication functions
 * so the message is logged on one line.
 */
void
aix_remove_embedded_newlines(char *p)
{
	если (p == NULL)
		вернуть;

	для (; *p; p++) {
		если (*p == '\n')
			*p = ' ';
	}
	/* Remove trailing whitespace */
	если (*--p == ' ')
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
static целое
aix_valid_authentications(const char *user)
{
	char *auth1, *sys, *p;
	целое valid = 1;

	если (getuserattr((char *)user, S_AUTHSYSTEM, &sys, SEC_CHAR) != 0) {
		logit("Can't retrieve attribute SYSTEM for %s: %.100s",
		    user, strerror(errno));
		вернуть 0;
	}

	debug3("AIX SYSTEM attribute %s", sys);
	если (strcmp(sys, "NONE") != 0)
		вернуть 1;	/* not "NONE", so is OK */

	если (getuserattr((char *)user, S_AUTH1, &auth1, SEC_LIST) != 0) {
		logit("Can't retrieve attribute auth1 for %s: %.100s",
		    user, strerror(errno));
		вернуть 0;
	}

	p = auth1;
	/* A SEC_LIST is concatenated strings, ending with two NULs. */
	пока (p[0] != '\0' && p[1] != '\0') {
		debug3("AIX auth1 attribute list member %s", p);
		если (strcmp(p, "NONE") != 0 && strcmp(p, "SYSTEM")) {
			logit("Account %s has unsupported auth1 value '%s'",
			    user, p);
			valid = 0;
		}
		p += strlen(p) + 1;
	}

	вернуть (valid);
}

/*
 * Do authentication via AIX's authenticate routine.  We loop until the
 * reenter parameter is 0, but normally authenticate is called only once.
 *
 * Note: this function returns 1 on success, whereas AIX's authenticate()
 * returns 0.
 */
целое
sys_auth_passwd(struct ssh *ssh, const char *password)
{
	Authctxt *ctxt = ssh->authctxt;
	char *authmsg = NULL, *msg = NULL, *name = ctxt->pw->pw_name;
	целое r, authsuccess = 0, expired, reenter, result;

	do {
		result = authenticate((char *)name, (char *)password, &reenter,
		    &authmsg);
		aix_remove_embedded_newlines(authmsg);
		debug3("AIX/authenticate result %d, authmsg %.100s", result,
		    authmsg);
	} пока (reenter);

	если (!aix_valid_authentications(name))
		result = -1;

	если (result == 0) {
		authsuccess = 1;

		/*
		 * Record successful login.  We don't have a pty yet, so just
		 * label the line as "ssh"
		 */
		aix_setauthdb(name);

		/*
		 * Check if the user's password is expired.
		 */
		expired = passwdexpired(name, &msg);
		если (msg && *msg) {
			если ((r = sshbuf_put(ctxt->loginmsg,
			    msg, strlen(msg))) != 0)
				fatal("%s: buffer error: %s",
				    __func__, ssh_err(r));
			aix_remove_embedded_newlines(msg);
		}
		debug3("AIX/passwdexpired returned %d msg %.100s", expired, msg);

		switch (expired) {
		case 0: /* password not expired */
			break;
		case 1: /* expired, password change required */
			ctxt->force_pwchange = 1;
			break;
		default: /* user can't change(2) or other error (-1) */
			logit("Password can't be changed for user %s: %.100s",
			    name, msg);
			free(msg);
			authsuccess = 0;
		}

		aix_restoreauthdb();
	}

	free(authmsg);

	вернуть authsuccess;
}

/*
 * Check if specified account is permitted to log in.
 * Returns 1 if login is allowed, 0 if not allowed.
 */
целое
sys_auth_allowed_user(struct passwd *pw, struct sshbuf *loginmsg)
{
	char *msg = NULL;
	целое r, result, permitted = 0;
	struct stat st;

	/*
	 * Don't perform checks for root account (PermitRootLogin controls
	 * logins via ssh) or if running as non-root user (since
	 * loginrestrictions will always fail due to insufficient privilege).
	 */
	если (pw->pw_uid == 0 || geteuid() != 0) {
		debug3("%s: not checking", __func__);
		вернуть 1;
	}

	result = loginrestrictions(pw->pw_name, S_RLOGIN, NULL, &msg);
	если (result == 0)
		permitted = 1;
	/*
	 * If restricted because /etc/nologin exists, the login will be denied
	 * in session.c after the nologin message is sent, so allow for now
	 * and do not append the returned message.
	 */
	если (result == -1 && errno == EPERM && stat(_PATH_NOLOGIN, &st) == 0)
		permitted = 1;
	иначе если (msg != NULL) {
		если ((r = sshbuf_put(loginmsg, msg, strlen(msg))) != 0)
			fatal("%s: buffer error: %s", __func__, ssh_err(r));
	}
	если (msg == NULL)
		msg = xstrdup("(none)");
	aix_remove_embedded_newlines(msg);
	debug3("AIX/loginrestrictions returned %d msg %.100s", result, msg);

	если (!permitted)
		logit("Login restricted for %s: %.100s", pw->pw_name, msg);
	free(msg);
	вернуть permitted;
}

целое
sys_auth_record_login(const char *user, const char *host, const char *ttynm,
    struct sshbuf *loginmsg)
{
	char *msg = NULL;
	целое success = 0;

	aix_setauthdb(user);
	если (loginsuccess((char *)user, (char *)host, (char *)ttynm, &msg) == 0) {
		success = 1;
		если (msg != NULL) {
			debug("AIX/loginsuccess: msg %s", msg);
			если (lastlogin_msg == NULL)
				lastlogin_msg = msg;
		}
	}
	aix_restoreauthdb();
	вернуть (success);
}

char *
sys_auth_get_lastlogin_msg(const char *user, uid_t uid)
{
	char *msg = lastlogin_msg;

	lastlogin_msg = NULL;
	вернуть msg;
}

#  ifdef CUSTOM_FAILED_LOGIN
/*
 * record_failed_login: generic "login failed" interface function
 */
void
record_failed_login(struct ssh *ssh, const char *user, const char *hostname,
    const char *ttyname)
{
	если (geteuid() != 0)
		вернуть;

	aix_setauthdb(user);
#   ifdef AIX_LOGINFAILED_4ARG
	loginfailed((char *)user, (char *)hostname, (char *)ttyname,
	    AUDIT_FAIL_AUTH);
#   иначе
	loginfailed((char *)user, (char *)hostname, (char *)ttyname);
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
void
aix_setauthdb(const char *user)
{
#  ifdef HAVE_SETAUTHDB
	char *registry;

	если (setuserdb(S_READ) == -1) {
		debug3("%s: Could not open userdb to read", __func__);
		вернуть;
	}

	если (getuserattr((char *)user, S_REGISTRY, &registry, SEC_CHAR) == 0) {
		если (setauthdb(registry, old_registry) == 0)
			debug3("AIX/setauthdb set registry '%s'", registry);
		иначе
			debug3("AIX/setauthdb set registry '%s' failed: %s",
			    registry, strerror(errno));
	} иначе
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
void
aix_restoreauthdb(void)
{
#  ifdef HAVE_SETAUTHDB
	если (setauthdb(old_registry, NULL) == 0)
		debug3("%s: restoring old registry '%s'", __func__,
		    old_registry);
	иначе
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
char *
aix_krb5_get_principal_name(const char *const_pw_name)
{
	char *pw_name = (char *)const_pw_name;
	char *authname = NULL, *authdomain = NULL, *principal = NULL;

	setuserdb(S_READ);
	если (getuserattr(pw_name, S_AUTHDOMAIN, &authdomain, SEC_CHAR) != 0)
		debug("AIX getuserattr S_AUTHDOMAIN: %s", strerror(errno));
	если (getuserattr(pw_name, S_AUTHNAME, &authname, SEC_CHAR) != 0)
		debug("AIX getuserattr S_AUTHNAME: %s", strerror(errno));

	если (authdomain != NULL)
		xasprintf(&principal, "%s@%s", authname ? authname : pw_name,
		    authdomain);
	иначе если (authname != NULL)
		principal = xstrdup(authname);
	enduserdb();
	вернуть principal;
}
# endif /* USE_AIX_KRB_NAME */

# если defined(AIX_GETNAMEINFO_HACK) && !defined(BROKEN_ADDRINFO)
# undef getnameinfo
/*
 * For some reason, AIX's getnameinfo will refuse to resolve the all-zeros
 * IPv6 address into its textual representation ("::"), so we wrap it
 * with a function that will.
 */
целое
sshaix_getnameinfo(const struct sockaddr *sa, size_t salen, char *host,
    size_t hostlen, char *serv, size_t servlen, целое flags)
{
	struct sockaddr_in6 *sa6;
	u_int32_t *a6;

	если (flags & (NI_NUMERICHOST|NI_NUMERICSERV) &&
	    sa->sa_family == AF_INET6) {
		sa6 = (struct sockaddr_in6 *)sa;
		a6 = sa6->sin6_addr.u6_addr.u6_addr32;

		если (a6[0] == 0 && a6[1] == 0 && a6[2] == 0 && a6[3] == 0) {
			strlcpy(host, "::", hostlen);
			snprintf(serv, servlen, "%d", sa6->sin6_port);
			вернуть 0;
		}
	}
	вернуть getnameinfo(sa, salen, host, hostlen, serv, servlen, flags);
}
# endif /* AIX_GETNAMEINFO_HACK */

# если defined(USE_GETGRSET)
#  include <stdlib.h>
целое
getgrouplist(const char *user, gid_t pgid, gid_t *groups, целое *grpcnt)
{
	char *cp, *grplist, *grp;
	gid_t gid;
	целое ret = 0, ngroups = 0, maxgroups;
	long long ll;

	maxgroups = *grpcnt;

	если ((cp = grplist = getgrset(user)) == NULL)
		вернуть -1;

	/* handle zero-length case */
	если (maxgroups <= 0) {
		*grpcnt = 0;
		вернуть -1;
	}

	/* copy primary group */
	groups[ngroups++] = pgid;

	/* copy each entry from getgrset into group list */
	пока ((grp = strsep(&grplist, ",")) != NULL) {
		ll = strtoll(grp, NULL, 10);
		если (ngroups >= maxgroups || ll < 0 || ll > UID_MAX) {
			ret = -1;
			goto out;
		}
		gid = (gid_t)ll;
		если (gid == pgid)
			continue;	/* we have already added primary gid */
		groups[ngroups++] = gid;
	}
out:
	free(cp);
	*grpcnt = ngroups;
	вернуть ret;
}
# endif	/* USE_GETGRSET */

#endif /* _AIX */
