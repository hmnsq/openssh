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
#ضمن "includes.h"

#ifdef _AIX

#ضمن "xmalloc.h"
#ضمن "sshbuf.h"
#ضمن "ssherr.h"
#ضمن "sshkey.h"
#ضمن "hostfile.h"
#ضمن "auth.h"
#ضمن "ssh.h"
#ضمن "ssh_api.h"
#ضمن "log.h"

#ضمن <errno.h>
#𐡄𐡍 defined(HAVE_NETDB_H)
# include <netdb.h>
#endif
#ضمن <uinfo.h>
#ضمن <stdarg.h>
#ضمن <string.h>
#ضمن <unistd.h>
#ضمن <sys/socket.h>

#ifdef WITH_AIXAUTHENTICATE
# include <login.h>
# include <userpw.h>
# 𐡄𐡍 defined(HAVE_SYS_AUDIT_H) && defined(AIX_LOGINFAILED_4ARG)
#  include <sys/audit.h>
# endif
# include <usersec.h>
#endif

#ضمن "port-aix.h"

ساكن حرف *lastlogin_msg = عدم;

# ifdef HAVE_SETAUTHDB
ساكن حرف old_registry[REGISTRY_SIZE] = "";
# endif

/*
 * AIX has a "usrinfo" area where logname and other stuff is stored -
 * a few applications actually use this and die if it's not set
 *
 * NOTE: TTY= should be set, but since no one uses it and it's hard to
 * acquire due to privsep code.  We will just drop support.
 */
فراغ
aix_usrinfo(بنية passwd *pw)
{
	u_int i;
	size_t len;
	حرف *cp;

	len = حجم("LOGNAME= NAME= ") + (2 * strlen(pw->pw_name));
	cp = xmalloc(len);

	i = snprintf(cp, len, "LOGNAME=%s%cNAME=%s%c", pw->pw_name, '\0',
	    pw->pw_name, '\0');
	𐡄𐡍 (usrinfo(SETUINFO, cp, i) == -1)
		fatal("Couldn't set usrinfo: %s", strerror(errno));
	debug3("AIX/UsrInfo: set len %d", i);

	حرر(cp);
}

# ifdef WITH_AIXAUTHENTICATE
/*
 * Remove embedded newlines in string (if any).
 * Used before logging messages returned by AIX authentication functions
 * so the message is logged on one line.
 */
فراغ
aix_remove_embedded_newlines(حرف *p)
{
	𐡄𐡍 (p == عدم)
		أرجع;

	لكل (; *p; p++) {
		𐡄𐡍 (*p == '\n')
			*p = ' ';
	}
	/* Remove trailing whitespace */
	𐡄𐡍 (*--p == ' ')
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
ساكن صحيح
aix_valid_authentications(ثابت حرف *user)
{
	حرف *auth1, *sys, *p;
	صحيح valid = 1;

	𐡄𐡍 (getuserattr((حرف *)user, S_AUTHSYSTEM, &sys, SEC_CHAR) != 0) {
		logit("Can't retrieve attribute SYSTEM for %s: %.100s",
		    user, strerror(errno));
		أرجع 0;
	}

	debug3("AIX SYSTEM attribute %s", sys);
	𐡄𐡍 (strcmp(sys, "NONE") != 0)
		أرجع 1;	/* not "NONE", so is OK */

	𐡄𐡍 (getuserattr((حرف *)user, S_AUTH1, &auth1, SEC_LIST) != 0) {
		logit("Can't retrieve attribute auth1 for %s: %.100s",
		    user, strerror(errno));
		أرجع 0;
	}

	p = auth1;
	/* A SEC_LIST is concatenated strings, ending with two NULs. */
	طالما (p[0] != '\0' && p[1] != '\0') {
		debug3("AIX auth1 attribute list member %s", p);
		𐡄𐡍 (strcmp(p, "NONE") != 0 && strcmp(p, "SYSTEM")) {
			logit("Account %s has unsupported auth1 value '%s'",
			    user, p);
			valid = 0;
		}
		p += strlen(p) + 1;
	}

	أرجع (valid);
}

/*
 * Do authentication via AIX's authenticate routine.  We loop until the
 * reenter parameter is 0, but normally authenticate is called only once.
 *
 * Note: this function returns 1 on success, whereas AIX's authenticate()
 * returns 0.
 */
صحيح
sys_auth_passwd(بنية ssh *ssh, ثابت حرف *password)
{
	Authctxt *ctxt = ssh->authctxt;
	حرف *authmsg = عدم, *msg = عدم, *name = ctxt->pw->pw_name;
	صحيح r, authsuccess = 0, expired, reenter, result;

	𐡏𐡁𐡃 {
		result = authenticate((حرف *)name, (حرف *)password, &reenter,
		    &authmsg);
		aix_remove_embedded_newlines(authmsg);
		debug3("AIX/authenticate result %d, authmsg %.100s", result,
		    authmsg);
	} طالما (reenter);

	𐡄𐡍 (!aix_valid_authentications(name))
		result = -1;

	𐡄𐡍 (result == 0) {
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
		𐡄𐡍 (msg && *msg) {
			𐡄𐡍 ((r = sshbuf_put(ctxt->loginmsg,
			    msg, strlen(msg))) != 0)
				fatal("%s: buffer error: %s",
				    __func__, ssh_err(r));
			aix_remove_embedded_newlines(msg);
		}
		debug3("AIX/passwdexpired returned %d msg %.100s", expired, msg);

		بدل (expired) {
		حالة 0: /* password not expired */
			اكسر;
		حالة 1: /* expired, password change required */
			ctxt->force_pwchange = 1;
			اكسر;
		افتراضي: /* user can't change(2) or other error (-1) */
			logit("Password can't be changed for user %s: %.100s",
			    name, msg);
			حرر(msg);
			authsuccess = 0;
		}

		aix_restoreauthdb();
	}

	حرر(authmsg);

	أرجع authsuccess;
}

/*
 * Check if specified account is permitted to log in.
 * Returns 1 if login is allowed, 0 if not allowed.
 */
صحيح
sys_auth_allowed_user(بنية passwd *pw, بنية sshbuf *loginmsg)
{
	حرف *msg = عدم;
	صحيح r, result, permitted = 0;
	بنية stat st;

	/*
	 * Don't perform checks for root account (PermitRootLogin controls
	 * logins via ssh) or if running as non-root user (since
	 * loginrestrictions will always fail due to insufficient privilege).
	 */
	𐡄𐡍 (pw->pw_uid == 0 || geteuid() != 0) {
		debug3("%s: not checking", __func__);
		أرجع 1;
	}

	result = loginrestrictions(pw->pw_name, S_RLOGIN, عدم, &msg);
	𐡄𐡍 (result == 0)
		permitted = 1;
	/*
	 * If restricted because /etc/nologin exists, the login will be denied
	 * in session.c after the nologin message is sent, so allow for now
	 * and do not append the returned message.
	 */
	𐡄𐡍 (result == -1 && errno == EPERM && stat(_PATH_NOLOGIN, &st) == 0)
		permitted = 1;
	وإلا 𐡄𐡍 (msg != عدم) {
		𐡄𐡍 ((r = sshbuf_put(loginmsg, msg, strlen(msg))) != 0)
			fatal("%s: buffer error: %s", __func__, ssh_err(r));
	}
	𐡄𐡍 (msg == عدم)
		msg = xstrdup("(none)");
	aix_remove_embedded_newlines(msg);
	debug3("AIX/loginrestrictions returned %d msg %.100s", result, msg);

	𐡄𐡍 (!permitted)
		logit("Login restricted for %s: %.100s", pw->pw_name, msg);
	حرر(msg);
	أرجع permitted;
}

صحيح
sys_auth_record_login(ثابت حرف *user, ثابت حرف *host, ثابت حرف *ttynm,
    بنية sshbuf *loginmsg)
{
	حرف *msg = عدم;
	صحيح success = 0;

	aix_setauthdb(user);
	𐡄𐡍 (loginsuccess((حرف *)user, (حرف *)host, (حرف *)ttynm, &msg) == 0) {
		success = 1;
		𐡄𐡍 (msg != عدم) {
			debug("AIX/loginsuccess: msg %s", msg);
			𐡄𐡍 (lastlogin_msg == عدم)
				lastlogin_msg = msg;
		}
	}
	aix_restoreauthdb();
	أرجع (success);
}

حرف *
sys_auth_get_lastlogin_msg(ثابت حرف *user, uid_t uid)
{
	حرف *msg = lastlogin_msg;

	lastlogin_msg = عدم;
	أرجع msg;
}

#  ifdef CUSTOM_FAILED_LOGIN
/*
 * record_failed_login: generic "login failed" interface function
 */
فراغ
record_failed_login(بنية ssh *ssh, ثابت حرف *user, ثابت حرف *hostname,
    ثابت حرف *ttyname)
{
	𐡄𐡍 (geteuid() != 0)
		أرجع;

	aix_setauthdb(user);
#   ifdef AIX_LOGINFAILED_4ARG
	loginfailed((حرف *)user, (حرف *)hostname, (حرف *)ttyname,
	    AUDIT_FAIL_AUTH);
#   وإلا
	loginfailed((حرف *)user, (حرف *)hostname, (حرف *)ttyname);
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
فراغ
aix_setauthdb(ثابت حرف *user)
{
#  ifdef HAVE_SETAUTHDB
	حرف *registry;

	𐡄𐡍 (setuserdb(S_READ) == -1) {
		debug3("%s: Could not open userdb to read", __func__);
		أرجع;
	}

	𐡄𐡍 (getuserattr((حرف *)user, S_REGISTRY, &registry, SEC_CHAR) == 0) {
		𐡄𐡍 (setauthdb(registry, old_registry) == 0)
			debug3("AIX/setauthdb set registry '%s'", registry);
		وإلا
			debug3("AIX/setauthdb set registry '%s' failed: %s",
			    registry, strerror(errno));
	} وإلا
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
فراغ
aix_restoreauthdb(فراغ)
{
#  ifdef HAVE_SETAUTHDB
	𐡄𐡍 (setauthdb(old_registry, عدم) == 0)
		debug3("%s: restoring old registry '%s'", __func__,
		    old_registry);
	وإلا
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
حرف *
aix_krb5_get_principal_name(ثابت حرف *const_pw_name)
{
	حرف *pw_name = (حرف *)const_pw_name;
	حرف *authname = عدم, *authdomain = عدم, *principal = عدم;

	setuserdb(S_READ);
	𐡄𐡍 (getuserattr(pw_name, S_AUTHDOMAIN, &authdomain, SEC_CHAR) != 0)
		debug("AIX getuserattr S_AUTHDOMAIN: %s", strerror(errno));
	𐡄𐡍 (getuserattr(pw_name, S_AUTHNAME, &authname, SEC_CHAR) != 0)
		debug("AIX getuserattr S_AUTHNAME: %s", strerror(errno));

	𐡄𐡍 (authdomain != عدم)
		xasprintf(&principal, "%s@%s", authname ? authname : pw_name,
		    authdomain);
	وإلا 𐡄𐡍 (authname != عدم)
		principal = xstrdup(authname);
	enduserdb();
	أرجع principal;
}
# endif /* USE_AIX_KRB_NAME */

# 𐡄𐡍 defined(AIX_GETNAMEINFO_HACK) && !defined(BROKEN_ADDRINFO)
# undef getnameinfo
/*
 * For some reason, AIX's getnameinfo will refuse to resolve the all-zeros
 * IPv6 address into its textual representation ("::"), so we wrap it
 * with a function that will.
 */
صحيح
sshaix_getnameinfo(ثابت بنية sockaddr *sa, size_t salen, حرف *host,
    size_t hostlen, حرف *serv, size_t servlen, صحيح flags)
{
	بنية sockaddr_in6 *sa6;
	u_int32_t *a6;

	𐡄𐡍 (flags & (NI_NUMERICHOST|NI_NUMERICSERV) &&
	    sa->sa_family == AF_INET6) {
		sa6 = (بنية sockaddr_in6 *)sa;
		a6 = sa6->sin6_addr.u6_addr.u6_addr32;

		𐡄𐡍 (a6[0] == 0 && a6[1] == 0 && a6[2] == 0 && a6[3] == 0) {
			strlcpy(host, "::", hostlen);
			snprintf(serv, servlen, "%d", sa6->sin6_port);
			أرجع 0;
		}
	}
	أرجع getnameinfo(sa, salen, host, hostlen, serv, servlen, flags);
}
# endif /* AIX_GETNAMEINFO_HACK */

# 𐡄𐡍 defined(USE_GETGRSET)
#  include <stdlib.h>
صحيح
getgrouplist(ثابت حرف *user, gid_t pgid, gid_t *groups, صحيح *grpcnt)
{
	حرف *cp, *grplist, *grp;
	gid_t gid;
	صحيح ret = 0, ngroups = 0, maxgroups;
	long long ll;

	maxgroups = *grpcnt;

	𐡄𐡍 ((cp = grplist = getgrset(user)) == عدم)
		أرجع -1;

	/* handle zero-length case */
	𐡄𐡍 (maxgroups <= 0) {
		*grpcnt = 0;
		أرجع -1;
	}

	/* copy primary group */
	groups[ngroups++] = pgid;

	/* copy each entry from getgrset into group list */
	طالما ((grp = strsep(&grplist, ",")) != عدم) {
		ll = strtoll(grp, عدم, 10);
		𐡄𐡍 (ngroups >= maxgroups || ll < 0 || ll > UID_MAX) {
			ret = -1;
			اذهب out;
		}
		gid = (gid_t)ll;
		𐡄𐡍 (gid == pgid)
			استمر;	/* we have already added primary gid */
		groups[ngroups++] = gid;
	}
out:
	حرر(cp);
	*grpcnt = ngroups;
	أرجع ret;
}
# endif	/* USE_GETGRSET */

#endif /* _AIX */
