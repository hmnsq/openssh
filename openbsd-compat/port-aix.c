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

#اگر_تعریف_شدہ _AIX

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
#اگر_ختم
#شامل <uinfo.h>
#شامل <stdarg.h>
#شامل <string.h>
#شامل <unistd.h>
#شامل <sys/socket.h>

#اگر_تعریف_شدہ WITH_AIXAUTHENTICATE
# include <login.h>
# include <userpw.h>
# اگر defined(HAVE_SYS_AUDIT_H) && defined(AIX_LOGINFAILED_4ARG)
#  include <sys/audit.h>
# endif
# include <usersec.h>
#اگر_ختم

#شامل "port-aix.h"

ساکن حرف *lastlogin_پیغام = تہی;

# ifdef HAVE_SETAUTHDB
ساکن حرف old_registry[REGISTRY_سائز] = "";
# endif

/*
 * AIX has a "usrinfo" area where logname and other stuff is stored -
 * a few applications actually use this and die if it's not set
 *
 * NOTE: TTY= should be set, but since no one uses it and it's hard to
 * acquire due to privsep code.  We will just drop support.
 */
خالی
aix_usrinfo(ساخت passwd *pw)
{
	u_int i;
	سائز_t len;
	حرف *cp;

	len = حجم("LOGNAME= NAME= ") + (2 * لڑی_لمبائی(pw->pw_name));
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
خالی
aix_remove_embedded_newlines(حرف *p)
{
	اگر (p == تہی)
		واپس;

	برائے (; *p; p++) {
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
ساکن صحیح
aix_valid_authentications(ثابت حرف *user)
{
	حرف *auth1, *sys, *p;
	صحیح valid = 1;

	اگر (getuserattr((حرف *)user, S_AUTHSYSTEM, &sys, SEC_CHAR) != 0) {
		logit("Can't retrieve attribute SYSTEM for %s: %.100s",
		    user, strerror(errno));
		واپس 0;
	}

	debug3("AIX SYSTEM attribute %s", sys);
	اگر (strcmp(sys, "NONE") != 0)
		واپس 1;	/* not "NONE", so is OK */

	اگر (getuserattr((حرف *)user, S_AUTH1, &auth1, SEC_LIST) != 0) {
		logit("Can't retrieve attribute auth1 for %s: %.100s",
		    user, strerror(errno));
		واپس 0;
	}

	p = auth1;
	/* A SEC_LIST is concatenated strings, ending with two NULs. */
	جب (p[0] != '\0' && p[1] != '\0') {
		debug3("AIX auth1 attribute list member %s", p);
		اگر (strcmp(p, "NONE") != 0 && strcmp(p, "SYSTEM")) {
			logit("Account %s has unsupported auth1 value '%s'",
			    user, p);
			valid = 0;
		}
		p += لڑی_لمبائی(p) + 1;
	}

	واپس (valid);
}

/*
 * Do authentication via AIX's authenticate routine.  We loop until the
 * reenter parameter is 0, but normally authenticate is called only once.
 *
 * Note: this function returns 1 on success, whereas AIX's authenticate()
 * returns 0.
 */
صحیح
sys_auth_passwd(ساخت ssh *ssh, ثابت حرف *password)
{
	Authctxt *ctxt = ssh->authctxt;
	حرف *authmsg = تہی, *پیغام = تہی, *name = ctxt->pw->pw_name;
	صحیح r, authsuccess = 0, expired, reenter, نتیجہ;

	کرو {
		نتیجہ = authenticate((حرف *)name, (حرف *)password, &reenter,
		    &authmsg);
		aix_remove_embedded_newlines(authmsg);
		debug3("AIX/authenticate result %d, authmsg %.100s", نتیجہ,
		    authmsg);
	} جب (reenter);

	اگر (!aix_valid_authentications(name))
		نتیجہ = -1;

	اگر (نتیجہ == 0) {
		authsuccess = 1;

		/*
		 * Record successful login.  We don't have a pty yet, so just
		 * label the line as "ssh"
		 */
		aix_setauthdb(name);

		/*
		 * Check if the user's password is expired.
		 */
		expired = passwdexpired(name, &پیغام);
		اگر (پیغام && *پیغام) {
			اگر ((r = sshbuf_put(ctxt->loginmsg,
			    پیغام, لڑی_لمبائی(پیغام))) != 0)
				fatal("%s: buffer error: %s",
				    __func__, ssh_err(r));
			aix_remove_embedded_newlines(پیغام);
		}
		debug3("AIX/passwdexpired returned %d msg %.100s", expired, پیغام);

		انتخاب (expired) {
		حالت 0: /* password not expired */
			توڑو;
		حالت 1: /* expired, password change required */
			ctxt->force_pwchange = 1;
			توڑو;
		طےشدہ: /* user can't change(2) or other error (-1) */
			logit("Password can't be changed for user %s: %.100s",
			    name, پیغام);
			آزاد(پیغام);
			authsuccess = 0;
		}

		aix_restoreauthdb();
	}

	آزاد(authmsg);

	واپس authsuccess;
}

/*
 * Check if specified account is permitted to log in.
 * Returns 1 if login is allowed, 0 if not allowed.
 */
صحیح
sys_auth_allowed_user(ساخت passwd *pw, ساخت sshbuf *loginmsg)
{
	حرف *پیغام = تہی;
	صحیح r, نتیجہ, permitted = 0;
	ساخت stat st;

	/*
	 * Don't perform checks for root account (PermitRootLogin controls
	 * logins via ssh) or if running as non-root user (since
	 * loginrestrictions will always fail due to insufficient privilege).
	 */
	اگر (pw->pw_uid == 0 || geteuid() != 0) {
		debug3("%s: not checking", __func__);
		واپس 1;
	}

	نتیجہ = loginrestrictions(pw->pw_name, S_RLOGIN, تہی, &پیغام);
	اگر (نتیجہ == 0)
		permitted = 1;
	/*
	 * If restricted because /etc/nologin exists, the login will be denied
	 * in session.c after the nologin message is sent, so allow for now
	 * and do not append the returned message.
	 */
	اگر (نتیجہ == -1 && errno == EPERM && stat(_PATH_NOLOGIN, &st) == 0)
		permitted = 1;
	ورنہ اگر (پیغام != تہی) {
		اگر ((r = sshbuf_put(loginmsg, پیغام, لڑی_لمبائی(پیغام))) != 0)
			fatal("%s: buffer error: %s", __func__, ssh_err(r));
	}
	اگر (پیغام == تہی)
		پیغام = xstrdup("(none)");
	aix_remove_embedded_newlines(پیغام);
	debug3("AIX/loginrestrictions returned %d msg %.100s", نتیجہ, پیغام);

	اگر (!permitted)
		logit("Login restricted for %s: %.100s", pw->pw_name, پیغام);
	آزاد(پیغام);
	واپس permitted;
}

صحیح
sys_auth_ریکارڈ_login(ثابت حرف *user, ثابت حرف *host, ثابت حرف *ttynm,
    ساخت sshbuf *loginmsg)
{
	حرف *پیغام = تہی;
	صحیح success = 0;

	aix_setauthdb(user);
	اگر (loginsuccess((حرف *)user, (حرف *)host, (حرف *)ttynm, &پیغام) == 0) {
		success = 1;
		اگر (پیغام != تہی) {
			debug("AIX/loginsuccess: msg %s", پیغام);
			اگر (lastlogin_پیغام == تہی)
				lastlogin_پیغام = پیغام;
		}
	}
	aix_restoreauthdb();
	واپس (success);
}

حرف *
sys_auth_get_lastlogin_پیغام(ثابت حرف *user, uid_t uid)
{
	حرف *پیغام = lastlogin_پیغام;

	lastlogin_پیغام = تہی;
	واپس پیغام;
}

#  ifdef CUSTOM_FAILED_LOGIN
/*
 * record_failed_login: generic "login failed" interface function
 */
خالی
ریکارڈ_failed_login(ساخت ssh *ssh, ثابت حرف *user, ثابت حرف *hostname,
    ثابت حرف *ttyname)
{
	اگر (geteuid() != 0)
		واپس;

	aix_setauthdb(user);
#   ifdef AIX_LOGINFAILED_4ARG
	loginfailed((حرف *)user, (حرف *)hostname, (حرف *)ttyname,
	    AUDIT_FAIL_AUTH);
#   ورنہ
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
خالی
aix_setauthdb(ثابت حرف *user)
{
#  ifdef HAVE_SETAUTHDB
	حرف *registry;

	اگر (setuserdb(S_READ) == -1) {
		debug3("%s: Could not open userdb to read", __func__);
		واپس;
	}

	اگر (getuserattr((حرف *)user, S_REGISTRY, &registry, SEC_CHAR) == 0) {
		اگر (setauthdb(registry, old_registry) == 0)
			debug3("AIX/setauthdb set registry '%s'", registry);
		ورنہ
			debug3("AIX/setauthdb set registry '%s' failed: %s",
			    registry, strerror(errno));
	} ورنہ
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
خالی
aix_restoreauthdb(خالی)
{
#  ifdef HAVE_SETAUTHDB
	اگر (setauthdb(old_registry, تہی) == 0)
		debug3("%s: restoring old registry '%s'", __func__,
		    old_registry);
	ورنہ
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
	حرف *authname = تہی, *authdomain = تہی, *principal = تہی;

	setuserdb(S_READ);
	اگر (getuserattr(pw_name, S_AUTHDOMAIN, &authdomain, SEC_CHAR) != 0)
		debug("AIX getuserattr S_AUTHDOMAIN: %s", strerror(errno));
	اگر (getuserattr(pw_name, S_AUTHNAME, &authname, SEC_CHAR) != 0)
		debug("AIX getuserattr S_AUTHNAME: %s", strerror(errno));

	اگر (authdomain != تہی)
		xasprintf(&principal, "%s@%s", authname ? authname : pw_name,
		    authdomain);
	ورنہ اگر (authname != تہی)
		principal = xstrdup(authname);
	enduserdb();
	واپس principal;
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
sshaix_getnameinfo(ثابت ساخت sockaddr *sa, سائز_t salen, حرف *host,
    سائز_t hostlen, حرف *serv, سائز_t servlen, صحیح flags)
{
	ساخت sockaddr_in6 *sa6;
	u_int32_t *a6;

	اگر (flags & (NI_NUMERICHOST|NI_NUMERICSERV) &&
	    sa->sa_family == AF_INET6) {
		sa6 = (ساخت sockaddr_in6 *)sa;
		a6 = sa6->sin6_addr.u6_addr.u6_addr32;

		اگر (a6[0] == 0 && a6[1] == 0 && a6[2] == 0 && a6[3] == 0) {
			strlcpy(host, "::", hostlen);
			snprintf(serv, servlen, "%d", sa6->sin6_port);
			واپس 0;
		}
	}
	واپس getnameinfo(sa, salen, host, hostlen, serv, servlen, flags);
}
# endif /* AIX_GETNAMEINFO_HACK */

# اگر defined(USE_GETGRSET)
#  include <stdlib.h>
صحیح
getgrouplist(ثابت حرف *user, gid_t pgid, gid_t *groups, صحیح *grpcnt)
{
	حرف *cp, *grplist, *grp;
	gid_t gid;
	صحیح ret = 0, ngroups = 0, maxgroups;
	طویل طویل ll;

	maxgroups = *grpcnt;

	اگر ((cp = grplist = getgrset(user)) == تہی)
		واپس -1;

	/* handle zero-length case */
	اگر (maxgroups <= 0) {
		*grpcnt = 0;
		واپس -1;
	}

	/* copy primary group */
	groups[ngroups++] = pgid;

	/* copy each entry from getgrset into group list */
	جب ((grp = strsep(&grplist, ",")) != تہی) {
		ll = strtoll(grp, تہی, 10);
		اگر (ngroups >= maxgroups || ll < 0 || ll > UID_MAX) {
			ret = -1;
			جاؤ برآمد;
		}
		gid = (gid_t)ll;
		اگر (gid == pgid)
			جاری;	/* we have already added primary gid */
		groups[ngroups++] = gid;
	}
برآمد:
	آزاد(cp);
	*grpcnt = ngroups;
	واپس ret;
}
# endif	/* USE_GETGRSET */

#اگر_ختم /* _AIX */
