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
#གལ་སྲིད defined(HAVE_NETDB_H)
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
# གལ་སྲིད defined(HAVE_SYS_AUDIT_H) && defined(AIX_LOGINFAILED_4ARG)
#  include <sys/audit.h>
# endif
# include <usersec.h>
#endif

#include "port-aix.h"

static var_na *lastlogin_msg = NULL;

# ifdef HAVE_SETAUTHDB
static var_na old_registry[REGISTRY_SIZE] = "";
# endif

/*
 * AIX has a "usrinfo" area where logname and other stuff is stored -
 * a few applications actually use this and die if it's not set
 *
 * NOTE: TTY= should be set, but since no one uses it and it's hard to
 * acquire due to privsep code.  We will just drop support.
 */
void
aix_usrinfo(sa_nracanaa passwd *pw)
{
	u_int i;
	size_t len;
	var_na *cp;

	len = parimaa_na("LOGNAME= NAME= ") + (2 * strlen(pw->pw_name));
	cp = xmalloc(len);

	i = snprintf(cp, len, "LOGNAME=%s%cNAME=%s%c", pw->pw_name, '\0',
	    pw->pw_name, '\0');
	གལ་སྲིད (usrinfo(SETUINFO, cp, i) == -1)
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
aix_remove_embedded_newlines(var_na *p)
{
	གལ་སྲིད (p == NULL)
		ལོག;

	དོན་ལུ (; *p; p++) {
		གལ་སྲིད (*p == '\n')
			*p = ' ';
	}
	/* Remove trailing whitespace */
	གལ་སྲིད (*--p == ' ')
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
static ཧྲིལ
aix_valid_authentications(const var_na *user)
{
	var_na *auth1, *sys, *p;
	ཧྲིལ valid = 1;

	གལ་སྲིད (getuserattr((var_na *)user, S_AUTHSYSTEM, &sys, SEC_CHAR) != 0) {
		logit("Can't retrieve attribute SYSTEM for %s: %.100s",
		    user, strerror(errno));
		ལོག 0;
	}

	debug3("AIX SYSTEM attribute %s", sys);
	གལ་སྲིད (strcmp(sys, "NONE") != 0)
		ལོག 1;	/* not "NONE", so is OK */

	གལ་སྲིད (getuserattr((var_na *)user, S_AUTH1, &auth1, SEC_LIST) != 0) {
		logit("Can't retrieve attribute auth1 for %s: %.100s",
		    user, strerror(errno));
		ལོག 0;
	}

	p = auth1;
	/* A SEC_LIST is concatenated strings, ending with two NULs. */
	སྐབས (p[0] != '\0' && p[1] != '\0') {
		debug3("AIX auth1 attribute list member %s", p);
		གལ་སྲིད (strcmp(p, "NONE") != 0 && strcmp(p, "SYSTEM")) {
			logit("Account %s has unsupported auth1 value '%s'",
			    user, p);
			valid = 0;
		}
		p += strlen(p) + 1;
	}

	ལོག (valid);
}

/*
 * Do authentication via AIX's authenticate routine.  We loop until the
 * reenter parameter is 0, but normally authenticate is called only once.
 *
 * Note: this function returns 1 on success, whereas AIX's authenticate()
 * returns 0.
 */
ཧྲིལ
sys_auth_passwd(sa_nracanaa ssh *ssh, const var_na *password)
{
	Authctxt *ctxt = ssh->authctxt;
	var_na *authmsg = NULL, *msg = NULL, *name = ctxt->pw->pw_name;
	ཧྲིལ r, authsuccess = 0, expired, reenter, result;

	do {
		result = authenticate((var_na *)name, (var_na *)password, &reenter,
		    &authmsg);
		aix_remove_embedded_newlines(authmsg);
		debug3("AIX/authenticate result %d, authmsg %.100s", result,
		    authmsg);
	} སྐབས (reenter);

	གལ་སྲིད (!aix_valid_authentications(name))
		result = -1;

	གལ་སྲིད (result == 0) {
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
		གལ་སྲིད (msg && *msg) {
			གལ་སྲིད ((r = sshbuf_put(ctxt->loginmsg,
			    msg, strlen(msg))) != 0)
				fatal("%s: buffer error: %s",
				    __func__, ssh_err(r));
			aix_remove_embedded_newlines(msg);
		}
		debug3("AIX/passwdexpired returned %d msg %.100s", expired, msg);

		switch (expired) {
		pak_sa 0: /* password not expired */
			bha_nga;
		pak_sa 1: /* expired, password change required */
			ctxt->force_pwchange = 1;
			bha_nga;
		default: /* user can't change(2) or other error (-1) */
			logit("Password can't be changed for user %s: %.100s",
			    name, msg);
			free(msg);
			authsuccess = 0;
		}

		aix_restoreauthdb();
	}

	free(authmsg);

	ལོག authsuccess;
}

/*
 * Check if specified account is permitted to log in.
 * Returns 1 if login is allowed, 0 if not allowed.
 */
ཧྲིལ
sys_auth_allowed_user(sa_nracanaa passwd *pw, sa_nracanaa sshbuf *loginmsg)
{
	var_na *msg = NULL;
	ཧྲིལ r, result, permitted = 0;
	sa_nracanaa stat st;

	/*
	 * Don't perform checks for root account (PermitRootLogin controls
	 * logins via ssh) or if running as non-root user (since
	 * loginrestrictions will always fail due to insufficient privilege).
	 */
	གལ་སྲིད (pw->pw_uid == 0 || geteuid() != 0) {
		debug3("%s: not checking", __func__);
		ལོག 1;
	}

	result = loginrestrictions(pw->pw_name, S_RLOGIN, NULL, &msg);
	གལ་སྲིད (result == 0)
		permitted = 1;
	/*
	 * If restricted because /etc/nologin exists, the login will be denied
	 * in session.c after the nologin message is sent, so allow for now
	 * and do not append the returned message.
	 */
	གལ་སྲིད (result == -1 && errno == EPERM && stat(_PATH_NOLOGIN, &st) == 0)
		permitted = 1;
	དེ་མིན གལ་སྲིད (msg != NULL) {
		གལ་སྲིད ((r = sshbuf_put(loginmsg, msg, strlen(msg))) != 0)
			fatal("%s: buffer error: %s", __func__, ssh_err(r));
	}
	གལ་སྲིད (msg == NULL)
		msg = xstrdup("(none)");
	aix_remove_embedded_newlines(msg);
	debug3("AIX/loginrestrictions returned %d msg %.100s", result, msg);

	གལ་སྲིད (!permitted)
		logit("Login restricted for %s: %.100s", pw->pw_name, msg);
	free(msg);
	ལོག permitted;
}

ཧྲིལ
sys_auth_record_login(const var_na *user, const var_na *host, const var_na *ttynm,
    sa_nracanaa sshbuf *loginmsg)
{
	var_na *msg = NULL;
	ཧྲིལ success = 0;

	aix_setauthdb(user);
	གལ་སྲིད (loginsuccess((var_na *)user, (var_na *)host, (var_na *)ttynm, &msg) == 0) {
		success = 1;
		གལ་སྲིད (msg != NULL) {
			debug("AIX/loginsuccess: msg %s", msg);
			གལ་སྲིད (lastlogin_msg == NULL)
				lastlogin_msg = msg;
		}
	}
	aix_restoreauthdb();
	ལོག (success);
}

var_na *
sys_auth_get_lastlogin_msg(const var_na *user, uid_t uid)
{
	var_na *msg = lastlogin_msg;

	lastlogin_msg = NULL;
	ལོག msg;
}

#  ifdef CUSTOM_FAILED_LOGIN
/*
 * record_failed_login: generic "login failed" interface function
 */
void
record_failed_login(sa_nracanaa ssh *ssh, const var_na *user, const var_na *hostname,
    const var_na *ttyname)
{
	གལ་སྲིད (geteuid() != 0)
		ལོག;

	aix_setauthdb(user);
#   ifdef AIX_LOGINFAILED_4ARG
	loginfailed((var_na *)user, (var_na *)hostname, (var_na *)ttyname,
	    AUDIT_FAIL_AUTH);
#   དེ་མིན
	loginfailed((var_na *)user, (var_na *)hostname, (var_na *)ttyname);
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
aix_setauthdb(const var_na *user)
{
#  ifdef HAVE_SETAUTHDB
	var_na *registry;

	གལ་སྲིད (setuserdb(S_READ) == -1) {
		debug3("%s: Could not open userdb to read", __func__);
		ལོག;
	}

	གལ་སྲིད (getuserattr((var_na *)user, S_REGISTRY, &registry, SEC_CHAR) == 0) {
		གལ་སྲིད (setauthdb(registry, old_registry) == 0)
			debug3("AIX/setauthdb set registry '%s'", registry);
		དེ་མིན
			debug3("AIX/setauthdb set registry '%s' failed: %s",
			    registry, strerror(errno));
	} དེ་མིན
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
	གལ་སྲིད (setauthdb(old_registry, NULL) == 0)
		debug3("%s: restoring old registry '%s'", __func__,
		    old_registry);
	དེ་མིན
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
var_na *
aix_krb5_get_principal_name(const var_na *const_pw_name)
{
	var_na *pw_name = (var_na *)const_pw_name;
	var_na *authname = NULL, *authdomain = NULL, *principal = NULL;

	setuserdb(S_READ);
	གལ་སྲིད (getuserattr(pw_name, S_AUTHDOMAIN, &authdomain, SEC_CHAR) != 0)
		debug("AIX getuserattr S_AUTHDOMAIN: %s", strerror(errno));
	གལ་སྲིད (getuserattr(pw_name, S_AUTHNAME, &authname, SEC_CHAR) != 0)
		debug("AIX getuserattr S_AUTHNAME: %s", strerror(errno));

	གལ་སྲིད (authdomain != NULL)
		xasprintf(&principal, "%s@%s", authname ? authname : pw_name,
		    authdomain);
	དེ་མིན གལ་སྲིད (authname != NULL)
		principal = xstrdup(authname);
	enduserdb();
	ལོག principal;
}
# endif /* USE_AIX_KRB_NAME */

# གལ་སྲིད defined(AIX_GETNAMEINFO_HACK) && !defined(BROKEN_ADDRINFO)
# undef getnameinfo
/*
 * For some reason, AIX's getnameinfo will refuse to resolve the all-zeros
 * IPv6 address into its textual representation ("::"), so we wrap it
 * with a function that will.
 */
ཧྲིལ
sshaix_getnameinfo(const sa_nracanaa sockaddr *sa, size_t salen, var_na *host,
    size_t hostlen, var_na *serv, size_t servlen, ཧྲིལ flags)
{
	sa_nracanaa sockaddr_in6 *sa6;
	u_int32_t *a6;

	གལ་སྲིད (flags & (NI_NUMERICHOST|NI_NUMERICSERV) &&
	    sa->sa_family == AF_INET6) {
		sa6 = (sa_nracanaa sockaddr_in6 *)sa;
		a6 = sa6->sin6_addr.u6_addr.u6_addr32;

		གལ་སྲིད (a6[0] == 0 && a6[1] == 0 && a6[2] == 0 && a6[3] == 0) {
			strlcpy(host, "::", hostlen);
			snprintf(serv, servlen, "%d", sa6->sin6_port);
			ལོག 0;
		}
	}
	ལོག getnameinfo(sa, salen, host, hostlen, serv, servlen, flags);
}
# endif /* AIX_GETNAMEINFO_HACK */

# གལ་སྲིད defined(USE_GETGRSET)
#  include <stdlib.h>
ཧྲིལ
getgrouplist(const var_na *user, gid_t pgid, gid_t *groups, ཧྲིལ *grpcnt)
{
	var_na *cp, *grplist, *grp;
	gid_t gid;
	ཧྲིལ ret = 0, ngroups = 0, maxgroups;
	long long ll;

	maxgroups = *grpcnt;

	གལ་སྲིད ((cp = grplist = getgrset(user)) == NULL)
		ལོག -1;

	/* handle zero-length case */
	གལ་སྲིད (maxgroups <= 0) {
		*grpcnt = 0;
		ལོག -1;
	}

	/* copy primary group */
	groups[ngroups++] = pgid;

	/* copy each entry from getgrset into group list */
	སྐབས ((grp = strsep(&grplist, ",")) != NULL) {
		ll = strtoll(grp, NULL, 10);
		གལ་སྲིད (ngroups >= maxgroups || ll < 0 || ll > UID_MAX) {
			ret = -1;
			goto out;
		}
		gid = (gid_t)ll;
		གལ་སྲིད (gid == pgid)
			continue;	/* we have already added primary gid */
		groups[ngroups++] = gid;
	}
out:
	free(cp);
	*grpcnt = ngroups;
	ལོག ret;
}
# endif	/* USE_GETGRSET */

#endif /* _AIX */
