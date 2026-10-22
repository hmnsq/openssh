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

#अन्तर्भाव "includes.h"

#जर defined(HAVE_LIBIAF)  &&  !defined(HAVE_SECUREWARE)
#अन्तर्भाव <sys/types.h>
#ifdef HAVE_CRYPT_H
# include <crypt.h>
#endif
#अन्तर्भाव <pwd.h>
#अन्तर्भाव <stdarg.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <stdio.h>
#अन्तर्भाव <string.h>

#अन्तर्भाव "xmalloc.h"
#अन्तर्भाव "packet.h"
#अन्तर्भाव "auth-options.h"
#अन्तर्भाव "log.h"
#अन्तर्भाव "misc.h"	/* servconf.h needs misc.h for struct ForwardOptions */
#अन्तर्भाव "servconf.h"
#अन्तर्भाव "hostfile.h"
#अन्तर्भाव "auth.h"
#अन्तर्भाव "ssh.h"
#अन्तर्भाव "ssh_api.h"

पूर्णांक nischeck(अक्षर *);

पूर्णांक
sys_auth_passwd(संरचना ssh *ssh, स्थिरांक अक्षर *password)
{
	Authctxt *authctxt = ssh->authctxt;
	संरचना passwd *pw = authctxt->pw;
	अक्षर *salt;
	पूर्णांक result;

	/* Just use the supplied fake password if authctxt is invalid */
	अक्षर *pw_password = authctxt->valid ? shadow_pw(pw) : pw->pw_passwd;

	जर (pw_password == रिक्त)
		परत 0;

	/* Check for users with no password. */
	जर (म_भेद(pw_password, "") == 0 && म_भेद(password, "") == 0)
		परत (1);

	/* Encrypt the candidate password using the proper salt. */
	salt = (pw_password[0] && pw_password[1]) ? pw_password : "xx";

	/*
	 * Authentication is accepted if the encrypted passwords
	 * are identical.
	 */
#ifdef UNIXWARE_LONG_PASSWORDS
	जर (!nischeck(pw->pw_name)) {
		result = ((म_भेद(bigcrypt(password, salt), pw_password) == 0)
		||  (म_भेद(osr5bigcrypt(password, salt), pw_password) == 0));
	}
	अन्यथा
#endif /* UNIXWARE_LONG_PASSWORDS */
		result = (म_भेद(xcrypt(password, salt), pw_password) == 0);

#ifdef USE_LIBIAF
	जर (authctxt->valid)
		मुक्त(pw_password);
#endif
	परत(result);
}

#ifdef UNIXWARE_LONG_PASSWORDS
पूर्णांक
nischeck(अक्षर *namep)
{
	अक्षर password_file[] = "/etc/passwd";
	खाता *fd;
	संरचना passwd *ent = रिक्त;

	जर ((fd = ख_खोलो (password_file, "r")) == रिक्त) {
		/*
		 * If the passwd file has disappeared we are in a bad state.
		 * However, returning 0 will send us back through the
		 * authentication scheme that has checked the ia database for
		 * passwords earlier.
		 */
		परत(0);
	}

	/*
	 * fgetpwent() only reads from password file, so we know for certain
	 * that the user is local.
	 */
	पर्यंत (ent = fgetpwent(fd)) {
		जर (म_भेद (ent->pw_name, namep) == 0) {
			/* Local user */
			ख_बंद (fd);
			परत(0);
		}
	}

	ख_बंद (fd);
	परत (1);
}

#endif /* UNIXWARE_LONG_PASSWORDS */

/*
	NOTE: ia_get_logpwd() allocates memory for arg 2
	functions that call shadow_pw() will need to free
 */

#ifdef USE_LIBIAF
अक्षर *
get_iaf_password(संरचना passwd *pw)
{
	अक्षर *pw_password = रिक्त;

	uinfo_t uinfo;
	जर (!ia_openinfo(pw->pw_name,&uinfo)) {
		ia_get_logpwd(uinfo, &pw_password);
		जर (pw_password == रिक्त)
			fatal("ia_get_logpwd: Unable to get the shadow passwd");
		ia_closeinfo(uinfo);
		परत pw_password;
	}
	अन्यथा
		fatal("ia_openinfo: Unable to open the shadow passwd file");
}
#endif /* USE_LIBIAF */
#endif /* HAVE_LIBIAF and not HAVE_SECUREWARE */

