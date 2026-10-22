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
#شامل "includes.h"

#ifdef _AIX

#شامل "xmalloc.h"
#شامل "sshbuf.h"
#شامل "ssherr.h"
#شامل "sshkey.h"
#شامل "hostfile.h"
#شامل "auth.h"
#شامل "ssh.h"
#شامل "ssh_api.h"
#شامل "log.h"

#شامل <errno.h>
#اگر defined(HAVE_NETDB_H)
# include <netdb.h>
#endif
#شامل <uinfo.h>
#شامل <stdarg.h>
#شامل <string.h>
#شامل <unistd.h>
#شامل <sys/socket.h>

#ifdef WITH_AIXAUTHENTICATE
# include <login.h>
# include <userpw.h>
# اگر defined(HAVE_SYS_AUDIT_H) && defined(AIX_LOGINFAILED_4ARG)
#  include <sys/audit.h>
# endif
# include <usersec.h>
#endif

#شامل "port-aix.h"

ایستا نویسه *lastlogin_پیام = پوچ;

# ifdef HAVE_SETAUTHDB
ایستا نویسه old_registry[REGISTRY_SIZE] = "";
# endif

/*
 * AIX has a "usrinfo" area where logname and other stuff is stored -
 * a few applications actually use this and die if it's not set
 *
 * NOTE: TTY= should be set, but since no one uses it and it's hard to
 * acquire due to privsep code.  We will just drop support.
 */
تهی
aix_usrinfo(ساختار passwd *pw)
{
	u_int i;
	size_t len;
	نویسه *cp;

	len = اندازه("LOGNAME= NAME= ") + (2 * strlen(pw->pw_name));
	cp = xmalloc(len);

	i = snprintf(cp, len, "LOGNAME=%s%cNAME=%s%c", pw->pw_name, '\0',
	    pw->pw_name, '\0');
	اگر (usrinfo(SETUINFO, cp, i) == -1)
		fatal("Couldn't set usrinfo: %s", strerror(errno));
	debug3("AIX/UsrInfo: set len %d", i);

	آزاد(cp);
}

# ifdef WITH_AIXAUTHENTICATE
/*
 * Remove embedded newlines in string (if any).
 * Used before logging messages returned by AIX authentication functions
 * so the message is logged on one line.
 */
تهی
aix_remove_embedded_newlines(نویسه *p)
{
	اگر (p == پوچ)
		بازگشت;

	برای (; *p; p++) {
		اگر (*p == '\n')
			*p = ' ';
	}
	/* Remove trailing whitespace */
	اگر (*--p == ' ')
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
ایستا صحیح
aix_valid_authentications(ثابت نویسه *user)
{
	نویسه *auth1, *sys, *p;
	صحیح valid = 1;

	اگر (getuserattr((نویسه *)user, S_AUTHSYSTEM, &sys, SEC_CHAR) != 0) {
		logit("Can't retrieve attribute SYSTEM for %s: %.100s",
		    user, strerror(errno));
		بازگشت 0;
	}

	debug3("AIX SYSTEM attribute %s", sys);
	اگر (strcmp(sys, "NONE") != 0)
		بازگشت 1;	/* not "NONE", so is OK */

	اگر (getuserattr((نویسه *)user, S_AUTH1, &auth1, SEC_LIST) != 0) {
		logit("Can't retrieve attribute auth1 for %s: %.100s",
		    user, strerror(errno));
		بازگشت 0;
	}

	p = auth1;
	/* A SEC_LIST is concatenated strings, ending with two NULs. */
	وقتی (p[0] != '\0' && p[1] != '\0') {
		debug3("AIX auth1 attribute list member %s", p);
		اگر (strcmp(p, "NONE") != 0 && strcmp(p, "SYSTEM")) {
			logit("Account %s has unsupported auth1 value '%s'",
			    user, p);
			valid = 0;
		}
		p += strlen(p) + 1;
	}

	بازگشت (valid);
}

/*
 * Do authentication via AIX's authenticate routine.  We loop until the
 * reenter parameter is 0, but normally authenticate is called only once.
 *
 * Note: this function returns 1 on success, whereas AIX's authenticate()
 * returns 0.
 */
صحیح
sys_auth_passwd(ساختار ssh *ssh, ثابت نویسه *password)
{
	Authctxt *ctxt = ssh->authctxt;
	نویسه *authmsg = پوچ, *پیام = پوچ, *name = ctxt->pw->pw_name;
	صحیح r, authsuccess = 0, expired, reenter, result;

	انجامبده {
		result = authenticate((نویسه *)name, (نویسه *)password, &reenter,
		    &authmsg);
		aix_remove_embedded_newlines(authmsg);
		debug3("AIX/authenticate result %d, authmsg %.100s", result,
		    authmsg);
	} وقتی (reenter);

	اگر (!aix_valid_authentications(name))
		result = -1;

	اگر (result == 0) {
		authsuccess = 1;

		/*
		 * Record successful login.  We don't have a pty yet, so just
		 * label the line as "ssh"
		 */
		aix_setauthdb(name);

		/*
		 * Check if the user's password is expired.
		 */
		expired = passwdexpired(name, &پیام);
		اگر (پیام && *پیام) {
			اگر ((r = sshbuf_put(ctxt->loginmsg,
			    پیام, strlen(پیام))) != 0)
				fatal("%s: buffer error: %s",
				    __func__, ssh_err(r));
			aix_remove_embedded_newlines(پیام);
		}
		debug3("AIX/passwdexpired returned %d msg %.100s", expired, پیام);

		انتخاب (expired) {
		حالت 0: /* password not expired */
			بشکن;
		حالت 1: /* expired, password change required */
			ctxt->force_pwchange = 1;
			بشکن;
		پیشفرض: /* user can't change(2) or other error (-1) */
			logit("Password can't be changed for user %s: %.100s",
			    name, پیام);
			آزاد(پیام);
			authsuccess = 0;
		}

		aix_restoreauthdb();
	}

	آزاد(authmsg);

	بازگشت authsuccess;
}

/*
 * Check if specified account is permitted to log in.
 * Returns 1 if login is allowed, 0 if not allowed.
 */
صحیح
sys_auth_allowed_user(ساختار passwd *pw, ساختار sshbuf *loginmsg)
{
	نویسه *پیام = پوچ;
	صحیح r, result, permitted = 0;
	ساختار stat st;

	/*
	 * Don't perform checks for root account (PermitRootLogin controls
	 * logins via ssh) or if running as non-root user (since
	 * loginrestrictions will always fail due to insufficient privilege).
	 */
	اگر (pw->pw_uid == 0 || geteuid() != 0) {
		debug3("%s: not checking", __func__);
		بازگشت 1;
	}

	result = loginrestrictions(pw->pw_name, S_RLOGIN, پوچ, &پیام);
	اگر (result == 0)
		permitted = 1;
	/*
	 * If restricted because /etc/nologin exists, the login will be denied
	 * in session.c after the nologin message is sent, so allow for now
	 * and do not append the returned message.
	 */
	اگر (result == -1 && errno == EPERM && stat(_PATH_NOLOGIN, &st) == 0)
		permitted = 1;
	وگرنه اگر (پیام != پوچ) {
		اگر ((r = sshbuf_put(loginmsg, پیام, strlen(پیام))) != 0)
			fatal("%s: buffer error: %s", __func__, ssh_err(r));
	}
	اگر (پیام == پوچ)
		پیام = xstrdup("(none)");
	aix_remove_embedded_newlines(پیام);
	debug3("AIX/loginrestrictions returned %d msg %.100s", result, پیام);

	اگر (!permitted)
		logit("Login restricted for %s: %.100s", pw->pw_name, پیام);
	آزاد(پیام);
	بازگشت permitted;
}

صحیح
sys_auth_record_login(ثابت نویسه *user, ثابت نویسه *host, ثابت نویسه *ttynm,
    ساختار sshbuf *loginmsg)
{
	نویسه *پیام = پوچ;
	صحیح success = 0;

	aix_setauthdb(user);
	اگر (loginsuccess((نویسه *)user, (نویسه *)host, (نویسه *)ttynm, &پیام) == 0) {
		success = 1;
		اگر (پیام != پوچ) {
			debug("AIX/loginsuccess: msg %s", پیام);
			اگر (lastlogin_پیام == پوچ)
				lastlogin_پیام = پیام;
		}
	}
	aix_restoreauthdb();
	بازگشت (success);
}

نویسه *
sys_auth_get_lastlogin_پیام(ثابت نویسه *user, uid_t uid)
{
	نویسه *پیام = lastlogin_پیام;

	lastlogin_پیام = پوچ;
	بازگشت پیام;
}

#  ifdef CUSTOM_FAILED_LOGIN
/*
 * record_failed_login: generic "login failed" interface function
 */
تهی
record_failed_login(ساختار ssh *ssh, ثابت نویسه *user, ثابت نویسه *hostname,
    ثابت نویسه *ttyname)
{
	اگر (geteuid() != 0)
		بازگشت;

	aix_setauthdb(user);
#   ifdef AIX_LOGINFAILED_4ARG
	loginfailed((نویسه *)user, (نویسه *)hostname, (نویسه *)ttyname,
	    AUDIT_FAIL_AUTH);
#   وگرنه
	loginfailed((نویسه *)user, (نویسه *)hostname, (نویسه *)ttyname);
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
تهی
aix_setauthdb(ثابت نویسه *user)
{
#  ifdef HAVE_SETAUTHDB
	نویسه *registry;

	اگر (setuserdb(S_READ) == -1) {
		debug3("%s: Could not open userdb to read", __func__);
		بازگشت;
	}

	اگر (getuserattr((نویسه *)user, S_REGISTRY, &registry, SEC_CHAR) == 0) {
		اگر (setauthdb(registry, old_registry) == 0)
			debug3("AIX/setauthdb set registry '%s'", registry);
		وگرنه
			debug3("AIX/setauthdb set registry '%s' failed: %s",
			    registry, strerror(errno));
	} وگرنه
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
تهی
aix_restoreauthdb(تهی)
{
#  ifdef HAVE_SETAUTHDB
	اگر (setauthdb(old_registry, پوچ) == 0)
		debug3("%s: restoring old registry '%s'", __func__,
		    old_registry);
	وگرنه
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
نویسه *
aix_krb5_get_principal_name(ثابت نویسه *const_pw_name)
{
	نویسه *pw_name = (نویسه *)const_pw_name;
	نویسه *authname = پوچ, *authdomain = پوچ, *principal = پوچ;

	setuserdb(S_READ);
	اگر (getuserattr(pw_name, S_AUTHDOMAIN, &authdomain, SEC_CHAR) != 0)
		debug("AIX getuserattr S_AUTHDOMAIN: %s", strerror(errno));
	اگر (getuserattr(pw_name, S_AUTHNAME, &authname, SEC_CHAR) != 0)
		debug("AIX getuserattr S_AUTHNAME: %s", strerror(errno));

	اگر (authdomain != پوچ)
		xasprintf(&principal, "%s@%s", authname ? authname : pw_name,
		    authdomain);
	وگرنه اگر (authname != پوچ)
		principal = xstrdup(authname);
	enduserdb();
	بازگشت principal;
}
# endif /* USE_AIX_KRB_NAME */

# اگر defined(AIX_GETNAMEINFO_HACK) && !defined(BROKEN_ADDRINFO)
# undef getnameinfo
/*
 * For some reason, AIX's getnameinfo will refuse to resolve the all-zeros
 * IPv6 address into its textual representation ("::"), so we wrap it
 * with a function that will.
 */
صحیح
sshaix_getnameinfo(ثابت ساختار sockaddr *sa, size_t salen, نویسه *host,
    size_t hostlen, نویسه *serv, size_t servlen, صحیح flags)
{
	ساختار sockaddr_in6 *sa6;
	u_int32_t *a6;

	اگر (flags & (NI_NUMERICHOST|NI_NUMERICSERV) &&
	    sa->sa_family == AF_INET6) {
		sa6 = (ساختار sockaddr_in6 *)sa;
		a6 = sa6->sin6_addr.u6_addr.u6_addr32;

		اگر (a6[0] == 0 && a6[1] == 0 && a6[2] == 0 && a6[3] == 0) {
			strlcpy(host, "::", hostlen);
			snprintf(serv, servlen, "%d", sa6->sin6_port);
			بازگشت 0;
		}
	}
	بازگشت getnameinfo(sa, salen, host, hostlen, serv, servlen, flags);
}
# endif /* AIX_GETNAMEINFO_HACK */

# اگر defined(USE_GETGRSET)
#  include <stdlib.h>
صحیح
getgrouplist(ثابت نویسه *user, gid_t pgid, gid_t *groups, صحیح *grpcnt)
{
	نویسه *cp, *grplist, *grp;
	gid_t gid;
	صحیح ret = 0, ngroups = 0, maxgroups;
	long long ll;

	maxgroups = *grpcnt;

	اگر ((cp = grplist = getgrset(user)) == پوچ)
		بازگشت -1;

	/* handle zero-length case */
	اگر (maxgroups <= 0) {
		*grpcnt = 0;
		بازگشت -1;
	}

	/* copy primary group */
	groups[ngroups++] = pgid;

	/* copy each entry from getgrset into group list */
	وقتی ((grp = strsep(&grplist, ",")) != پوچ) {
		ll = strtoll(grp, پوچ, 10);
		اگر (ngroups >= maxgroups || ll < 0 || ll > UID_MAX) {
			ret = -1;
			برو out;
		}
		gid = (gid_t)ll;
		اگر (gid == pgid)
			ادامه;	/* we have already added primary gid */
		groups[ngroups++] = gid;
	}
out:
	آزاد(cp);
	*grpcnt = ngroups;
	بازگشت ret;
}
# endif	/* USE_GETGRSET */

#endif /* _AIX */
