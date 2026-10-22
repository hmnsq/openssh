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
#अन्तर्भाव "includes.h"

#ifdef _AIX

#अन्तर्भाव "xmalloc.h"
#अन्तर्भाव "sshbuf.h"
#अन्तर्भाव "ssherr.h"
#अन्तर्भाव "sshkey.h"
#अन्तर्भाव "hostfile.h"
#अन्तर्भाव "auth.h"
#अन्तर्भाव "ssh.h"
#अन्तर्भाव "ssh_api.h"
#अन्तर्भाव "log.h"

#अन्तर्भाव <errno.h>
#यदि defined(HAVE_NETDB_H)
# include <netdb.h>
#endif
#अन्तर्भाव <uinfo.h>
#अन्तर्भाव <stdarg.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <unistd.h>
#अन्तर्भाव <sys/socket.h>

#ifdef WITH_AIXAUTHENTICATE
# include <login.h>
# include <userpw.h>
# यदि defined(HAVE_SYS_AUDIT_H) && defined(AIX_LOGINFAILED_4ARG)
#  include <sys/audit.h>
# endif
# include <usersec.h>
#endif

#अन्तर्भाव "port-aix.h"

स्थिर वर्ण *lastlogin_संदेश = रिक्त;

# ifdef HAVE_SETAUTHDB
स्थिर वर्ण old_registry[REGISTRY_SIZE] = "";
# endif

/*
 * AIX has a "usrinfo" area where logname and other stuff is stored -
 * a few applications actually use this and die if it's not set
 *
 * NOTE: TTY= should be set, but since no one uses it and it's hard to
 * acquire due to privsep code.  We will just drop support.
 */
शून्य
aix_usrinfo(संरचना passwd *pw)
{
	u_int i;
	माप_प्रकार len;
	वर्ण *cp;

	len = परिमाण("LOGNAME= NAME= ") + (2 * म_माप(pw->pw_name));
	cp = xmalloc(len);

	i = snprintf(cp, len, "LOGNAME=%s%cNAME=%s%c", pw->pw_name, '\0',
	    pw->pw_name, '\0');
	यदि (usrinfo(SETUINFO, cp, i) == -1)
		fatal("Couldn't set usrinfo: %s", म_त्रुटि(त्रुटि_सं));
	debug3("AIX/UsrInfo: set len %d", i);

	मुक्त(cp);
}

# ifdef WITH_AIXAUTHENTICATE
/*
 * Remove embedded newlines in string (if any).
 * Used before logging messages returned by AIX authentication functions
 * so the message is logged on one line.
 */
शून्य
aix_remove_embedded_newlines(वर्ण *p)
{
	यदि (p == रिक्त)
		प्रत्यागम;

	प्रति (; *p; p++) {
		यदि (*p == '\n')
			*p = ' ';
	}
	/* Remove trailing whitespace */
	यदि (*--p == ' ')
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
स्थिर पूर्णाङ्क
aix_valid_authentications(ध्रुव वर्ण *user)
{
	वर्ण *auth1, *sys, *p;
	पूर्णाङ्क valid = 1;

	यदि (getuserattr((वर्ण *)user, S_AUTHSYSTEM, &sys, SEC_CHAR) != 0) {
		logit("Can't retrieve attribute SYSTEM for %s: %.100s",
		    user, म_त्रुटि(त्रुटि_सं));
		प्रत्यागम 0;
	}

	debug3("AIX SYSTEM attribute %s", sys);
	यदि (म_भेद(sys, "NONE") != 0)
		प्रत्यागम 1;	/* not "NONE", so is OK */

	यदि (getuserattr((वर्ण *)user, S_AUTH1, &auth1, SEC_LIST) != 0) {
		logit("Can't retrieve attribute auth1 for %s: %.100s",
		    user, म_त्रुटि(त्रुटि_सं));
		प्रत्यागम 0;
	}

	p = auth1;
	/* A SEC_LIST is concatenated strings, ending with two NULs. */
	यावत् (p[0] != '\0' && p[1] != '\0') {
		debug3("AIX auth1 attribute list member %s", p);
		यदि (म_भेद(p, "NONE") != 0 && म_भेद(p, "SYSTEM")) {
			logit("Account %s has unsupported auth1 value '%s'",
			    user, p);
			valid = 0;
		}
		p += म_माप(p) + 1;
	}

	प्रत्यागम (valid);
}

/*
 * Do authentication via AIX's authenticate routine.  We loop until the
 * reenter parameter is 0, but normally authenticate is called only once.
 *
 * Note: this function returns 1 on success, whereas AIX's authenticate()
 * returns 0.
 */
पूर्णाङ्क
sys_auth_passwd(संरचना ssh *ssh, ध्रुव वर्ण *password)
{
	Authctxt *ctxt = ssh->authctxt;
	वर्ण *authmsg = रिक्त, *संदेश = रिक्त, *name = ctxt->pw->pw_name;
	पूर्णाङ्क r, authsuccess = 0, expired, reenter, result;

	कुरु {
		result = authenticate((वर्ण *)name, (वर्ण *)password, &reenter,
		    &authmsg);
		aix_remove_embedded_newlines(authmsg);
		debug3("AIX/authenticate result %d, authmsg %.100s", result,
		    authmsg);
	} यावत् (reenter);

	यदि (!aix_valid_authentications(name))
		result = -1;

	यदि (result == 0) {
		authsuccess = 1;

		/*
		 * Record successful login.  We don't have a pty yet, so just
		 * label the line as "ssh"
		 */
		aix_setauthdb(name);

		/*
		 * Check if the user's password is expired.
		 */
		expired = passwdexpired(name, &संदेश);
		यदि (संदेश && *संदेश) {
			यदि ((r = sshbuf_put(ctxt->loginmsg,
			    संदेश, म_माप(संदेश))) != 0)
				fatal("%s: buffer error: %s",
				    __func__, ssh_err(r));
			aix_remove_embedded_newlines(संदेश);
		}
		debug3("AIX/passwdexpired returned %d msg %.100s", expired, संदेश);

		विकल्प (expired) {
		पक्ष 0: /* password not expired */
			भङ्ग;
		पक्ष 1: /* expired, password change required */
			ctxt->force_pwchange = 1;
			भङ्ग;
		स्वभाव: /* user can't change(2) or other error (-1) */
			logit("Password can't be changed for user %s: %.100s",
			    name, संदेश);
			मुक्त(संदेश);
			authsuccess = 0;
		}

		aix_restoreauthdb();
	}

	मुक्त(authmsg);

	प्रत्यागम authsuccess;
}

/*
 * Check if specified account is permitted to log in.
 * Returns 1 if login is allowed, 0 if not allowed.
 */
पूर्णाङ्क
sys_auth_allowed_user(संरचना passwd *pw, संरचना sshbuf *loginmsg)
{
	वर्ण *संदेश = रिक्त;
	पूर्णाङ्क r, result, permitted = 0;
	संरचना stat st;

	/*
	 * Don't perform checks for root account (PermitRootLogin controls
	 * logins via ssh) or if running as non-root user (since
	 * loginrestrictions will always fail due to insufficient privilege).
	 */
	यदि (pw->pw_uid == 0 || geteuid() != 0) {
		debug3("%s: not checking", __func__);
		प्रत्यागम 1;
	}

	result = loginrestrictions(pw->pw_name, S_RLOGIN, रिक्त, &संदेश);
	यदि (result == 0)
		permitted = 1;
	/*
	 * If restricted because /etc/nologin exists, the login will be denied
	 * in session.c after the nologin message is sent, so allow for now
	 * and do not append the returned message.
	 */
	यदि (result == -1 && त्रुटि_सं == EPERM && stat(_PATH_NOLOGIN, &st) == 0)
		permitted = 1;
	अन्यथा यदि (संदेश != रिक्त) {
		यदि ((r = sshbuf_put(loginmsg, संदेश, म_माप(संदेश))) != 0)
			fatal("%s: buffer error: %s", __func__, ssh_err(r));
	}
	यदि (संदेश == रिक्त)
		संदेश = xstrdup("(none)");
	aix_remove_embedded_newlines(संदेश);
	debug3("AIX/loginrestrictions returned %d msg %.100s", result, संदेश);

	यदि (!permitted)
		logit("Login restricted for %s: %.100s", pw->pw_name, संदेश);
	मुक्त(संदेश);
	प्रत्यागम permitted;
}

पूर्णाङ्क
sys_auth_record_login(ध्रुव वर्ण *user, ध्रुव वर्ण *host, ध्रुव वर्ण *ttynm,
    संरचना sshbuf *loginmsg)
{
	वर्ण *संदेश = रिक्त;
	पूर्णाङ्क success = 0;

	aix_setauthdb(user);
	यदि (loginsuccess((वर्ण *)user, (वर्ण *)host, (वर्ण *)ttynm, &संदेश) == 0) {
		success = 1;
		यदि (संदेश != रिक्त) {
			debug("AIX/loginsuccess: msg %s", संदेश);
			यदि (lastlogin_संदेश == रिक्त)
				lastlogin_संदेश = संदेश;
		}
	}
	aix_restoreauthdb();
	प्रत्यागम (success);
}

वर्ण *
sys_auth_get_lastlogin_संदेश(ध्रुव वर्ण *user, uid_t uid)
{
	वर्ण *संदेश = lastlogin_संदेश;

	lastlogin_संदेश = रिक्त;
	प्रत्यागम संदेश;
}

#  ifdef CUSTOM_FAILED_LOGIN
/*
 * record_failed_login: generic "login failed" interface function
 */
शून्य
record_failed_login(संरचना ssh *ssh, ध्रुव वर्ण *user, ध्रुव वर्ण *hostname,
    ध्रुव वर्ण *ttyname)
{
	यदि (geteuid() != 0)
		प्रत्यागम;

	aix_setauthdb(user);
#   ifdef AIX_LOGINFAILED_4ARG
	loginfailed((वर्ण *)user, (वर्ण *)hostname, (वर्ण *)ttyname,
	    AUDIT_FAIL_AUTH);
#   अन्यथा
	loginfailed((वर्ण *)user, (वर्ण *)hostname, (वर्ण *)ttyname);
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
शून्य
aix_setauthdb(ध्रुव वर्ण *user)
{
#  ifdef HAVE_SETAUTHDB
	वर्ण *registry;

	यदि (setuserdb(S_READ) == -1) {
		debug3("%s: Could not open userdb to read", __func__);
		प्रत्यागम;
	}

	यदि (getuserattr((वर्ण *)user, S_REGISTRY, &registry, SEC_CHAR) == 0) {
		यदि (setauthdb(registry, old_registry) == 0)
			debug3("AIX/setauthdb set registry '%s'", registry);
		अन्यथा
			debug3("AIX/setauthdb set registry '%s' failed: %s",
			    registry, म_त्रुटि(त्रुटि_सं));
	} अन्यथा
		debug3("%s: Could not read S_REGISTRY for user: %s", __func__,
		    म_त्रुटि(त्रुटि_सं));
	enduserdb();
#  endif /* HAVE_SETAUTHDB */
}

/*
 * Restore the user's registry settings from old_registry.
 * Note that if the first aix_setauthdb fails, setauthdb("") is still safe
 * (it restores the system default behaviour).  If we don't have setauthdb,
 * this is a no-op.
 */
शून्य
aix_restoreauthdb(शून्य)
{
#  ifdef HAVE_SETAUTHDB
	यदि (setauthdb(old_registry, रिक्त) == 0)
		debug3("%s: restoring old registry '%s'", __func__,
		    old_registry);
	अन्यथा
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
वर्ण *
aix_krb5_get_principal_name(ध्रुव वर्ण *const_pw_name)
{
	वर्ण *pw_name = (वर्ण *)const_pw_name;
	वर्ण *authname = रिक्त, *authdomain = रिक्त, *principal = रिक्त;

	setuserdb(S_READ);
	यदि (getuserattr(pw_name, S_AUTHDOMAIN, &authdomain, SEC_CHAR) != 0)
		debug("AIX getuserattr S_AUTHDOMAIN: %s", म_त्रुटि(त्रुटि_सं));
	यदि (getuserattr(pw_name, S_AUTHNAME, &authname, SEC_CHAR) != 0)
		debug("AIX getuserattr S_AUTHNAME: %s", म_त्रुटि(त्रुटि_सं));

	यदि (authdomain != रिक्त)
		xasprintf(&principal, "%s@%s", authname ? authname : pw_name,
		    authdomain);
	अन्यथा यदि (authname != रिक्त)
		principal = xstrdup(authname);
	enduserdb();
	प्रत्यागम principal;
}
# endif /* USE_AIX_KRB_NAME */

# यदि defined(AIX_GETNAMEINFO_HACK) && !defined(BROKEN_ADDRINFO)
# undef getnameinfo
/*
 * For some reason, AIX's getnameinfo will refuse to resolve the all-zeros
 * IPv6 address into its textual representation ("::"), so we wrap it
 * with a function that will.
 */
पूर्णाङ्क
sshaix_getnameinfo(ध्रुव संरचना sockaddr *sa, माप_प्रकार salen, वर्ण *host,
    माप_प्रकार hostlen, वर्ण *serv, माप_प्रकार servlen, पूर्णाङ्क flags)
{
	संरचना sockaddr_in6 *sa6;
	u_int32_t *a6;

	यदि (flags & (NI_NUMERICHOST|NI_NUMERICSERV) &&
	    sa->sa_family == AF_INET6) {
		sa6 = (संरचना sockaddr_in6 *)sa;
		a6 = sa6->sin6_addr.u6_addr.u6_addr32;

		यदि (a6[0] == 0 && a6[1] == 0 && a6[2] == 0 && a6[3] == 0) {
			strlcpy(host, "::", hostlen);
			snprintf(serv, servlen, "%d", sa6->sin6_port);
			प्रत्यागम 0;
		}
	}
	प्रत्यागम getnameinfo(sa, salen, host, hostlen, serv, servlen, flags);
}
# endif /* AIX_GETNAMEINFO_HACK */

# यदि defined(USE_GETGRSET)
#  include <stdlib.h>
पूर्णाङ्क
getgrouplist(ध्रुव वर्ण *user, gid_t pgid, gid_t *groups, पूर्णाङ्क *grpcnt)
{
	वर्ण *cp, *grplist, *grp;
	gid_t gid;
	पूर्णाङ्क ret = 0, ngroups = 0, maxgroups;
	दीर्घ दीर्घ ll;

	maxgroups = *grpcnt;

	यदि ((cp = grplist = getgrset(user)) == रिक्त)
		प्रत्यागम -1;

	/* handle zero-length case */
	यदि (maxgroups <= 0) {
		*grpcnt = 0;
		प्रत्यागम -1;
	}

	/* copy primary group */
	groups[ngroups++] = pgid;

	/* copy each entry from getgrset into group list */
	यावत् ((grp = strsep(&grplist, ",")) != रिक्त) {
		ll = strtoll(grp, रिक्त, 10);
		यदि (ngroups >= maxgroups || ll < 0 || ll > UID_MAX) {
			ret = -1;
			गच्छ out;
		}
		gid = (gid_t)ll;
		यदि (gid == pgid)
			अनुवर्त;	/* we have already added primary gid */
		groups[ngroups++] = gid;
	}
out:
	मुक्त(cp);
	*grpcnt = ngroups;
	प्रत्यागम ret;
}
# endif	/* USE_GETGRSET */

#endif /* _AIX */
