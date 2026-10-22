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

#شامل "includes.h"

#اگر defined(HAVE_LIBIAF)  &&  !defined(HAVE_SECUREWARE)
#شامل <sys/types.h>
#اگر_تعریف_شدہ HAVE_CRYPT_H
# include <crypt.h>
#اگر_ختم
#شامل <pwd.h>
#شامل <stdarg.h>
#شامل <stdlib.h>
#شامل <stdio.h>
#شامل <string.h>

#شامل "xmalloc.h"
#شامل "packet.h"
#شامل "auth-options.h"
#شامل "log.h"
#شامل "misc.h"	/* servconf.h needs misc.h for struct ForwardOptions */
#شامل "servconf.h"
#شامل "hostfile.h"
#شامل "auth.h"
#شامل "ssh.h"
#شامل "ssh_api.h"

صحیح nischeck(حرف *);

صحیح
sys_auth_passwd(ساخت ssh *ssh, ثابت حرف *password)
{
	Authctxt *authctxt = ssh->authctxt;
	ساخت passwd *pw = authctxt->pw;
	حرف *salt;
	صحیح نتیجہ;

	/* Just use the supplied fake password if authctxt is invalid */
	حرف *pw_password = authctxt->valid ? shadow_pw(pw) : pw->pw_passwd;

	اگر (pw_password == تہی)
		واپس 0;

	/* Check for users with no password. */
	اگر (strcmp(pw_password, "") == 0 && strcmp(password, "") == 0)
		واپس (1);

	/* Encrypt the candidate password using the proper salt. */
	salt = (pw_password[0] && pw_password[1]) ? pw_password : "xx";

	/*
	 * Authentication is accepted if the encrypted passwords
	 * are identical.
	 */
#اگر_تعریف_شدہ UNIXWARE_LONG_PASSWORDS
	اگر (!nischeck(pw->pw_name)) {
		نتیجہ = ((strcmp(bigcrypt(password, salt), pw_password) == 0)
		||  (strcmp(osr5bigcrypt(password, salt), pw_password) == 0));
	}
	ورنہ
#اگر_ختم /* UNIXWARE_LONG_PASSWORDS */
		نتیجہ = (strcmp(xcrypt(password, salt), pw_password) == 0);

#اگر_تعریف_شدہ USE_LIBIAF
	اگر (authctxt->valid)
		آزاد(pw_password);
#اگر_ختم
	واپس(نتیجہ);
}

#اگر_تعریف_شدہ UNIXWARE_LONG_PASSWORDS
صحیح
nischeck(حرف *namep)
{
	حرف password_file[] = "/etc/passwd";
	FILE *fd;
	ساخت passwd *ent = تہی;

	اگر ((fd = fopen (password_file, "r")) == تہی) {
		/*
		 * If the passwd file has disappeared we are in a bad state.
		 * However, returning 0 will send us back through the
		 * authentication scheme that has checked the ia database for
		 * passwords earlier.
		 */
		واپس(0);
	}

	/*
	 * fgetpwent() only reads from password file, so we know for certain
	 * that the user is local.
	 */
	جب (ent = fgetpwent(fd)) {
		اگر (strcmp (ent->pw_name, namep) == 0) {
			/* Local user */
			fclose (fd);
			واپس(0);
		}
	}

	fclose (fd);
	واپس (1);
}

#اگر_ختم /* UNIXWARE_LONG_PASSWORDS */

/*
	NOTE: ia_get_logpwd() allocates memory for arg 2
	functions that call shadow_pw() will need to free
 */

#اگر_تعریف_شدہ USE_LIBIAF
حرف *
get_iaf_password(ساخت passwd *pw)
{
	حرف *pw_password = تہی;

	uinfo_t uinfo;
	اگر (!ia_openinfo(pw->pw_name,&uinfo)) {
		ia_get_logpwd(uinfo, &pw_password);
		اگر (pw_password == تہی)
			fatal("ia_get_logpwd: Unable to get the shadow passwd");
		ia_closeinfo(uinfo);
		واپس pw_password;
	}
	ورنہ
		fatal("ia_openinfo: Unable to open the shadow passwd file");
}
#اگر_ختم /* USE_LIBIAF */
#اگر_ختم /* HAVE_LIBIAF and not HAVE_SECUREWARE */

