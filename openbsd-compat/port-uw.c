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

#ضمن "includes.h"

#إذا defined(HAVE_LIBIAF)  &&  !defined(HAVE_SECUREWARE)
#ضمن <sys/types.h>
#اگر_تعریف_شده HAVE_CRYPT_H
# include <crypt.h>
#پایان_اگر
#ضمن <pwd.h>
#ضمن <stdarg.h>
#ضمن <stdlib.h>
#ضمن <stdio.h>
#ضمن <string.h>

#ضمن "xmalloc.h"
#ضمن "packet.h"
#ضمن "auth-options.h"
#ضمن "log.h"
#ضمن "misc.h"	/* servconf.h needs misc.h for struct ForwardOptions */
#ضمن "servconf.h"
#ضمن "hostfile.h"
#ضمن "auth.h"
#ضمن "ssh.h"
#ضمن "ssh_api.h"

صحيح nischeck(حرف *);

صحيح
sys_auth_passwd(بنية ssh *ssh, ثابت حرف *password)
{
	Authctxt *authctxt = ssh->authctxt;
	بنية passwd *pw = authctxt->pw;
	حرف *salt;
	صحيح نتیجه;

	/* Just use the supplied fake password if authctxt is invalid */
	حرف *pw_password = authctxt->valid ? shadow_pw(pw) : pw->pw_passwd;

	إذا (pw_password == عدم)
		أرجع 0;

	/* Check for users with no password. */
	إذا (strcmp(pw_password, "") == 0 && strcmp(password, "") == 0)
		أرجع (1);

	/* Encrypt the candidate password using the proper salt. */
	salt = (pw_password[0] && pw_password[1]) ? pw_password : "xx";

	/*
	 * Authentication is accepted if the encrypted passwords
	 * are identical.
	 */
#اگر_تعریف_شده UNIXWARE_LONG_PASSWORDS
	إذا (!nischeck(pw->pw_name)) {
		نتیجه = ((strcmp(bigcrypt(password, salt), pw_password) == 0)
		||  (strcmp(osr5bigcrypt(password, salt), pw_password) == 0));
	}
	وإلا
#پایان_اگر /* UNIXWARE_LONG_PASSWORDS */
		نتیجه = (strcmp(xcrypt(password, salt), pw_password) == 0);

#اگر_تعریف_شده USE_LIBIAF
	إذا (authctxt->valid)
		حرر(pw_password);
#پایان_اگر
	أرجع(نتیجه);
}

#اگر_تعریف_شده UNIXWARE_LONG_PASSWORDS
صحيح
nischeck(حرف *namep)
{
	حرف password_file[] = "/etc/passwd";
	FILE *fd;
	بنية passwd *ent = عدم;

	إذا ((fd = fopen (password_file, "r")) == عدم) {
		/*
		 * If the passwd file has disappeared we are in a bad state.
		 * However, returning 0 will send us back through the
		 * authentication scheme that has checked the ia database for
		 * passwords earlier.
		 */
		أرجع(0);
	}

	/*
	 * fgetpwent() only reads from password file, so we know for certain
	 * that the user is local.
	 */
	طالما (ent = fgetpwent(fd)) {
		إذا (strcmp (ent->pw_name, namep) == 0) {
			/* Local user */
			fclose (fd);
			أرجع(0);
		}
	}

	fclose (fd);
	أرجع (1);
}

#پایان_اگر /* UNIXWARE_LONG_PASSWORDS */

/*
	NOTE: ia_get_logpwd() allocates memory for arg 2
	functions that call shadow_pw() will need to free
 */

#اگر_تعریف_شده USE_LIBIAF
حرف *
get_iaf_password(بنية passwd *pw)
{
	حرف *pw_password = عدم;

	uinfo_t uinfo;
	إذا (!ia_openinfo(pw->pw_name,&uinfo)) {
		ia_get_logpwd(uinfo, &pw_password);
		إذا (pw_password == عدم)
			fatal("ia_get_logpwd: Unable to get the shadow passwd");
		ia_closeinfo(uinfo);
		أرجع pw_password;
	}
	وإلا
		fatal("ia_openinfo: Unable to open the shadow passwd file");
}
#پایان_اگر /* USE_LIBIAF */
#پایان_اگر /* HAVE_LIBIAF and not HAVE_SECUREWARE */

