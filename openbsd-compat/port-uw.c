/*
 * Copyright (c) 2005 The SCO Group. All rights reserved.
 * Copyright (c) 2005 Tim Rice. All rights reserved.
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
 */

#समावेश "includes.h"

#अगर defined(HAVE_LIBIAF)  &&  !defined(HAVE_SECUREWARE)
#समावेश <sys/types.h>
#अगर_घोषित HAVE_CRYPT_H
# include <crypt.h>
#पूर्ण_अगर
#समावेश <pwd.h>
#समावेश <stdarg.h>
#समावेश <stdlib.h>
#समावेश <stdio.h>
#समावेश <string.h>

#समावेश "xmalloc.h"
#समावेश "packet.h"
#समावेश "auth-options.h"
#समावेश "log.h"
#समावेश "misc.h"	/* servconf.h needs misc.h for struct ForwardOptions */
#समावेश "servconf.h"
#समावेश "hostfile.h"
#समावेश "auth.h"
#समावेश "ssh.h"
#समावेश "ssh_api.h"

पूर्णांक nischeck(अक्षर *);

पूर्णांक
sys_auth_passwd(काष्ठा ssh *ssh, स्थिर अक्षर *password)
{
	Authctxt *authctxt = ssh->authctxt;
	काष्ठा passwd *pw = authctxt->pw;
	अक्षर *salt;
	पूर्णांक परिणाम;

	/* Just use the supplied fake password if authctxt is invalid */
	अक्षर *pw_password = authctxt->valid ? shadow_pw(pw) : pw->pw_passwd;

	अगर (pw_password == शून्य)
		वापस 0;

	/* Check for users with no password. */
	अगर (म_भेद(pw_password, "") == 0 && म_भेद(password, "") == 0)
		वापस (1);

	/* Encrypt the candidate password using the proper salt. */
	salt = (pw_password[0] && pw_password[1]) ? pw_password : "xx";

	/*
	 * Authentication is accepted if the encrypted passwords
	 * are identical.
	 */
#अगर_घोषित UNIXWARE_LONG_PASSWORDS
	अगर (!nischeck(pw->pw_name)) {
		परिणाम = ((म_भेद(bigcrypt(password, salt), pw_password) == 0)
		||  (म_भेद(osr5bigcrypt(password, salt), pw_password) == 0));
	}
	अन्यथा
#पूर्ण_अगर /* UNIXWARE_LONG_PASSWORDS */
		परिणाम = (म_भेद(xcrypt(password, salt), pw_password) == 0);

#अगर_घोषित USE_LIBIAF
	अगर (authctxt->valid)
		मुक्त(pw_password);
#पूर्ण_अगर
	वापस(परिणाम);
}

#अगर_घोषित UNIXWARE_LONG_PASSWORDS
पूर्णांक
nischeck(अक्षर *namep)
{
	अक्षर password_file[] = "/etc/passwd";
	खाता *fd;
	काष्ठा passwd *ent = शून्य;

	अगर ((fd = ख_खोलो (password_file, "r")) == शून्य) {
		/*
		 * If the passwd file has disappeared we are in a bad state.
		 * However, returning 0 will send us back through the
		 * authentication scheme that has checked the ia database for
		 * passwords earlier.
		 */
		वापस(0);
	}

	/*
	 * fgetpwent() only reads from password file, so we know for certain
	 * that the user is local.
	 */
	जबतक (ent = fgetpwent(fd)) {
		अगर (म_भेद (ent->pw_name, namep) == 0) {
			/* Local user */
			ख_बंद (fd);
			वापस(0);
		}
	}

	ख_बंद (fd);
	वापस (1);
}

#पूर्ण_अगर /* UNIXWARE_LONG_PASSWORDS */

/*
	NOTE: ia_get_logpwd() allocates memory for arg 2
	functions that call shadow_pw() will need to free
 */

#अगर_घोषित USE_LIBIAF
अक्षर *
get_iaf_password(काष्ठा passwd *pw)
{
	अक्षर *pw_password = शून्य;

	uinfo_t uinfo;
	अगर (!ia_openinfo(pw->pw_name,&uinfo)) {
		ia_get_logpwd(uinfo, &pw_password);
		अगर (pw_password == शून्य)
			fatal("ia_get_logpwd: Unable to get the shadow passwd");
		ia_closeinfo(uinfo);
		वापस pw_password;
	}
	अन्यथा
		fatal("ia_openinfo: Unable to open the shadow passwd file");
}
#पूर्ण_अगर /* USE_LIBIAF */
#पूर्ण_अगर /* HAVE_LIBIAF and not HAVE_SECUREWARE */

