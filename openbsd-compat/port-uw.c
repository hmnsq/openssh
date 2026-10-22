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

#यदि defined(HAVE_LIBIAF)  &&  !defined(HAVE_SECUREWARE)
#अन्तर्भाव <sys/types.h>
#यदि_परिभाषितम् HAVE_CRYPT_H
# include <crypt.h>
#यदि_अन्तः
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

पूर्णाङ्क nischeck(वर्ण *);

पूर्णाङ्क
sys_auth_passwd(संरचना ssh *ssh, ध्रुव वर्ण *password)
{
	Authctxt *authctxt = ssh->authctxt;
	संरचना passwd *pw = authctxt->pw;
	वर्ण *salt;
	पूर्णाङ्क परिणाम;

	/* Just use the supplied fake password if authctxt is invalid */
	वर्ण *pw_password = authctxt->valid ? shadow_pw(pw) : pw->pw_passwd;

	यदि (pw_password == रिक्त)
		प्रत्यागम 0;

	/* Check for users with no password. */
	यदि (वाक्यं_तुलय(pw_password, "") == 0 && वाक्यं_तुलय(password, "") == 0)
		प्रत्यागम (1);

	/* Encrypt the candidate password using the proper salt. */
	salt = (pw_password[0] && pw_password[1]) ? pw_password : "xx";

	/*
	 * Authentication is accepted if the encrypted passwords
	 * are identical.
	 */
#यदि_परिभाषितम् UNIXWARE_LONG_PASSWORDS
	यदि (!nischeck(pw->pw_name)) {
		परिणाम = ((वाक्यं_तुलय(bigcrypt(password, salt), pw_password) == 0)
		||  (वाक्यं_तुलय(osr5bigcrypt(password, salt), pw_password) == 0));
	}
	अन्यथा
#यदि_अन्तः /* UNIXWARE_LONG_PASSWORDS */
		परिणाम = (वाक्यं_तुलय(xcrypt(password, salt), pw_password) == 0);

#यदि_परिभाषितम् USE_LIBIAF
	यदि (authctxt->valid)
		मुक्त(pw_password);
#यदि_अन्तः
	प्रत्यागम(परिणाम);
}

#यदि_परिभाषितम् UNIXWARE_LONG_PASSWORDS
पूर्णाङ्क
nischeck(वर्ण *namep)
{
	वर्ण password_file[] = "/etc/passwd";
	FILE *fd;
	संरचना passwd *ent = रिक्त;

	यदि ((fd = fopen (password_file, "r")) == रिक्त) {
		/*
		 * If the passwd file has disappeared we are in a bad state.
		 * However, returning 0 will send us back through the
		 * authentication scheme that has checked the ia database for
		 * passwords earlier.
		 */
		प्रत्यागम(0);
	}

	/*
	 * fgetpwent() only reads from password file, so we know for certain
	 * that the user is local.
	 */
	यावत् (ent = fgetpwent(fd)) {
		यदि (वाक्यं_तुलय (ent->pw_name, namep) == 0) {
			/* Local user */
			fclose (fd);
			प्रत्यागम(0);
		}
	}

	fclose (fd);
	प्रत्यागम (1);
}

#यदि_अन्तः /* UNIXWARE_LONG_PASSWORDS */

/*
	NOTE: ia_get_logpwd() allocates memory for arg 2
	functions that call shadow_pw() will need to free
 */

#यदि_परिभाषितम् USE_LIBIAF
वर्ण *
get_iaf_password(संरचना passwd *pw)
{
	वर्ण *pw_password = रिक्त;

	uinfo_t uinfo;
	यदि (!ia_openinfo(pw->pw_name,&uinfo)) {
		ia_get_logpwd(uinfo, &pw_password);
		यदि (pw_password == रिक्त)
			fatal("ia_get_logpwd: Unable to get the shadow passwd");
		ia_closeinfo(uinfo);
		प्रत्यागम pw_password;
	}
	अन्यथा
		fatal("ia_openinfo: Unable to open the shadow passwd file");
}
#यदि_अन्तः /* USE_LIBIAF */
#यदि_अन्तः /* HAVE_LIBIAF and not HAVE_SECUREWARE */

