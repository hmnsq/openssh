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
#समावेश "includes.h"

#अगर_घोषित _AIX

#समावेश "xmalloc.h"
#समावेश "sshbuf.h"
#समावेश "ssherr.h"
#समावेश "sshkey.h"
#समावेश "hostfile.h"
#समावेश "auth.h"
#समावेश "ssh.h"
#समावेश "ssh_api.h"
#समावेश "log.h"

#समावेश <errno.h>
#अगर defined(HAVE_NETDB_H)
# include <netdb.h>
#पूर्ण_अगर
#समावेश <uinfo.h>
#समावेश <stdarg.h>
#समावेश <string.h>
#समावेश <unistd.h>
#समावेश <sys/socket.h>

#अगर_घोषित WITH_AIXAUTHENTICATE
# include <login.h>
# include <userpw.h>
# अगर defined(HAVE_SYS_AUDIT_H) && defined(AIX_LOGINFAILED_4ARG)
#  include <sys/audit.h>
# endif
# include <usersec.h>
#पूर्ण_अगर

#समावेश "port-aix.h"

अटल अक्षर *lastlogin_संदेश = शून्य;

# ifdef HAVE_SETAUTHDB
अटल अक्षर old_registry[REGISTRY_आकार] = "";
# endif

/*
 * AIX has a "usrinfo" area where logname and other stuff is stored -
 * a few applications actually use this and die if it's not set
 *
 * NOTE: TTY= should be set, but since no one uses it and it's hard to
 * acquire due to privsep code.  We will just drop support.
 */
व्योम
aix_usrinfo(काष्ठा passwd *pw)
{
	u_int i;
	माप_प्रकार len;
	अक्षर *cp;

	len = माप("LOGNAME= NAME= ") + (2 * म_माप(pw->pw_name));
	cp = xmalloc(len);

	i = snprintf(cp, len, "LOGNAME=%s%cNAME=%s%c", pw->pw_name, '\0',
	    pw->pw_name, '\0');
	अगर (usrinfo(SETUINFO, cp, i) == -1)
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
व्योम
aix_remove_embedded_newlines(अक्षर *p)
{
	अगर (p == शून्य)
		वापस;

	क्रम (; *p; p++) {
		अगर (*p == '\n')
			*p = ' ';
	}
	/* Remove trailing whitespace */
	अगर (*--p == ' ')
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
अटल पूर्णांक
aix_valid_authentications(स्थिर अक्षर *user)
{
	अक्षर *auth1, *sys, *p;
	पूर्णांक valid = 1;

	अगर (getuserattr((अक्षर *)user, S_AUTHSYSTEM, &sys, SEC_CHAR) != 0) {
		logit("Can't retrieve attribute SYSTEM for %s: %.100s",
		    user, म_त्रुटि(त्रुटि_सं));
		वापस 0;
	}

	debug3("AIX SYSTEM attribute %s", sys);
	अगर (म_भेद(sys, "NONE") != 0)
		वापस 1;	/* not "NONE", so is OK */

	अगर (getuserattr((अक्षर *)user, S_AUTH1, &auth1, SEC_LIST) != 0) {
		logit("Can't retrieve attribute auth1 for %s: %.100s",
		    user, म_त्रुटि(त्रुटि_सं));
		वापस 0;
	}

	p = auth1;
	/* A SEC_LIST is concatenated strings, ending with two NULs. */
	जबतक (p[0] != '\0' && p[1] != '\0') {
		debug3("AIX auth1 attribute list member %s", p);
		अगर (म_भेद(p, "NONE") != 0 && म_भेद(p, "SYSTEM")) {
			logit("Account %s has unsupported auth1 value '%s'",
			    user, p);
			valid = 0;
		}
		p += म_माप(p) + 1;
	}

	वापस (valid);
}

/*
 * Do authentication via AIX's authenticate routine.  We loop until the
 * reenter parameter is 0, but normally authenticate is called only once.
 *
 * Note: this function returns 1 on success, whereas AIX's authenticate()
 * returns 0.
 */
पूर्णांक
sys_auth_passwd(काष्ठा ssh *ssh, स्थिर अक्षर *password)
{
	Authctxt *ctxt = ssh->authctxt;
	अक्षर *authmsg = शून्य, *संदेश = शून्य, *name = ctxt->pw->pw_name;
	पूर्णांक r, authsuccess = 0, expired, reenter, परिणाम;

	करो {
		परिणाम = authenticate((अक्षर *)name, (अक्षर *)password, &reenter,
		    &authmsg);
		aix_remove_embedded_newlines(authmsg);
		debug3("AIX/authenticate result %d, authmsg %.100s", परिणाम,
		    authmsg);
	} जबतक (reenter);

	अगर (!aix_valid_authentications(name))
		परिणाम = -1;

	अगर (परिणाम == 0) {
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
		अगर (संदेश && *संदेश) {
			अगर ((r = sshbuf_put(ctxt->loginmsg,
			    संदेश, म_माप(संदेश))) != 0)
				fatal("%s: buffer error: %s",
				    __func__, ssh_err(r));
			aix_remove_embedded_newlines(संदेश);
		}
		debug3("AIX/passwdexpired returned %d msg %.100s", expired, संदेश);

		चयन (expired) {
		हाल 0: /* password not expired */
			अवरोध;
		हाल 1: /* expired, password change required */
			ctxt->force_pwchange = 1;
			अवरोध;
		शेष: /* user can't change(2) or other error (-1) */
			logit("Password can't be changed for user %s: %.100s",
			    name, संदेश);
			मुक्त(संदेश);
			authsuccess = 0;
		}

		aix_restoreauthdb();
	}

	मुक्त(authmsg);

	वापस authsuccess;
}

/*
 * Check if specified account is permitted to log in.
 * Returns 1 if login is allowed, 0 if not allowed.
 */
पूर्णांक
sys_auth_allowed_user(काष्ठा passwd *pw, काष्ठा sshbuf *loginmsg)
{
	अक्षर *संदेश = शून्य;
	पूर्णांक r, परिणाम, permitted = 0;
	काष्ठा stat st;

	/*
	 * Don't perform checks for root account (PermitRootLogin controls
	 * logins via ssh) or if running as non-root user (since
	 * loginrestrictions will always fail due to insufficient privilege).
	 */
	अगर (pw->pw_uid == 0 || geteuid() != 0) {
		debug3("%s: not checking", __func__);
		वापस 1;
	}

	परिणाम = loginrestrictions(pw->pw_name, S_RLOGIN, शून्य, &संदेश);
	अगर (परिणाम == 0)
		permitted = 1;
	/*
	 * If restricted because /etc/nologin exists, the login will be denied
	 * in session.c after the nologin message is sent, so allow for now
	 * and do not append the returned message.
	 */
	अगर (परिणाम == -1 && त्रुटि_सं == EPERM && stat(_PATH_NOLOGIN, &st) == 0)
		permitted = 1;
	अन्यथा अगर (संदेश != शून्य) {
		अगर ((r = sshbuf_put(loginmsg, संदेश, म_माप(संदेश))) != 0)
			fatal("%s: buffer error: %s", __func__, ssh_err(r));
	}
	अगर (संदेश == शून्य)
		संदेश = xstrdup("(none)");
	aix_remove_embedded_newlines(संदेश);
	debug3("AIX/loginrestrictions returned %d msg %.100s", परिणाम, संदेश);

	अगर (!permitted)
		logit("Login restricted for %s: %.100s", pw->pw_name, संदेश);
	मुक्त(संदेश);
	वापस permitted;
}

पूर्णांक
sys_auth_record_login(स्थिर अक्षर *user, स्थिर अक्षर *host, स्थिर अक्षर *ttynm,
    काष्ठा sshbuf *loginmsg)
{
	अक्षर *संदेश = शून्य;
	पूर्णांक success = 0;

	aix_setauthdb(user);
	अगर (loginsuccess((अक्षर *)user, (अक्षर *)host, (अक्षर *)ttynm, &संदेश) == 0) {
		success = 1;
		अगर (संदेश != शून्य) {
			debug("AIX/loginsuccess: msg %s", संदेश);
			अगर (lastlogin_संदेश == शून्य)
				lastlogin_संदेश = संदेश;
		}
	}
	aix_restoreauthdb();
	वापस (success);
}

अक्षर *
sys_auth_get_lastlogin_संदेश(स्थिर अक्षर *user, uid_t uid)
{
	अक्षर *संदेश = lastlogin_संदेश;

	lastlogin_संदेश = शून्य;
	वापस संदेश;
}

#  ifdef CUSTOM_FAILED_LOGIN
/*
 * record_failed_login: generic "login failed" interface function
 */
व्योम
record_failed_login(काष्ठा ssh *ssh, स्थिर अक्षर *user, स्थिर अक्षर *hostname,
    स्थिर अक्षर *ttyname)
{
	अगर (geteuid() != 0)
		वापस;

	aix_setauthdb(user);
#   ifdef AIX_LOGINFAILED_4ARG
	loginfailed((अक्षर *)user, (अक्षर *)hostname, (अक्षर *)ttyname,
	    AUDIT_FAIL_AUTH);
#   अन्यथा
	loginfailed((अक्षर *)user, (अक्षर *)hostname, (अक्षर *)ttyname);
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
व्योम
aix_setauthdb(स्थिर अक्षर *user)
{
#  ifdef HAVE_SETAUTHDB
	अक्षर *registry;

	अगर (setuserdb(S_READ) == -1) {
		debug3("%s: Could not open userdb to read", __func__);
		वापस;
	}

	अगर (getuserattr((अक्षर *)user, S_REGISTRY, &registry, SEC_CHAR) == 0) {
		अगर (setauthdb(registry, old_registry) == 0)
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
व्योम
aix_restoreauthdb(व्योम)
{
#  ifdef HAVE_SETAUTHDB
	अगर (setauthdb(old_registry, शून्य) == 0)
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
अक्षर *
aix_krb5_get_principal_name(स्थिर अक्षर *const_pw_name)
{
	अक्षर *pw_name = (अक्षर *)const_pw_name;
	अक्षर *authname = शून्य, *authdomain = शून्य, *principal = शून्य;

	setuserdb(S_READ);
	अगर (getuserattr(pw_name, S_AUTHDOMAIN, &authdomain, SEC_CHAR) != 0)
		debug("AIX getuserattr S_AUTHDOMAIN: %s", म_त्रुटि(त्रुटि_सं));
	अगर (getuserattr(pw_name, S_AUTHNAME, &authname, SEC_CHAR) != 0)
		debug("AIX getuserattr S_AUTHNAME: %s", म_त्रुटि(त्रुटि_सं));

	अगर (authdomain != शून्य)
		xasprintf(&principal, "%s@%s", authname ? authname : pw_name,
		    authdomain);
	अन्यथा अगर (authname != शून्य)
		principal = xstrdup(authname);
	enduserdb();
	वापस principal;
}
# endif /* USE_AIX_KRB_NAME */

# अगर defined(AIX_GETNAMEINFO_HACK) && !defined(BROKEN_ADDRINFO)
# undef getnameinfo
/*
 * For some reason, AIX's getnameinfo will refuse to resolve the all-zeros
 * IPv6 address into its textual representation ("::"), so we wrap it
 * with a function that will.
 */
पूर्णांक
sshaix_getnameinfo(स्थिर काष्ठा sockaddr *sa, माप_प्रकार salen, अक्षर *host,
    माप_प्रकार hostlen, अक्षर *serv, माप_प्रकार servlen, पूर्णांक flags)
{
	काष्ठा sockaddr_in6 *sa6;
	u_int32_t *a6;

	अगर (flags & (NI_NUMERICHOST|NI_NUMERICSERV) &&
	    sa->sa_family == AF_INET6) {
		sa6 = (काष्ठा sockaddr_in6 *)sa;
		a6 = sa6->sin6_addr.u6_addr.u6_addr32;

		अगर (a6[0] == 0 && a6[1] == 0 && a6[2] == 0 && a6[3] == 0) {
			strlcpy(host, "::", hostlen);
			snprintf(serv, servlen, "%d", sa6->sin6_port);
			वापस 0;
		}
	}
	वापस getnameinfo(sa, salen, host, hostlen, serv, servlen, flags);
}
# endif /* AIX_GETNAMEINFO_HACK */

# अगर defined(USE_GETGRSET)
#  include <stdlib.h>
पूर्णांक
getgrouplist(स्थिर अक्षर *user, gid_t pgid, gid_t *groups, पूर्णांक *grpcnt)
{
	अक्षर *cp, *grplist, *grp;
	gid_t gid;
	पूर्णांक ret = 0, ngroups = 0, maxgroups;
	दीर्घ दीर्घ ll;

	maxgroups = *grpcnt;

	अगर ((cp = grplist = getgrset(user)) == शून्य)
		वापस -1;

	/* handle zero-length case */
	अगर (maxgroups <= 0) {
		*grpcnt = 0;
		वापस -1;
	}

	/* copy primary group */
	groups[ngroups++] = pgid;

	/* copy each entry from getgrset into group list */
	जबतक ((grp = strsep(&grplist, ",")) != शून्य) {
		ll = strtoll(grp, शून्य, 10);
		अगर (ngroups >= maxgroups || ll < 0 || ll > UID_MAX) {
			ret = -1;
			जाओ out;
		}
		gid = (gid_t)ll;
		अगर (gid == pgid)
			जारी;	/* we have already added primary gid */
		groups[ngroups++] = gid;
	}
out:
	मुक्त(cp);
	*grpcnt = ngroups;
	वापस ret;
}
# endif	/* USE_GETGRSET */

#पूर्ण_अगर /* _AIX */
