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

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಯದಿ defined(HAVE_LIBIAF)  &&  !defined(HAVE_SECUREWARE)
#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ifdef HAVE_CRYPT_H
# include <crypt.h>
#endif
#ಅನ್ತರ್ಭಾವ <pwd.h>
#ಅನ್ತರ್ಭಾವ <stdarg.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <string.h>

#ಅನ್ತರ್ಭಾವ "xmalloc.h"
#ಅನ್ತರ್ಭಾವ "packet.h"
#ಅನ್ತರ್ಭಾವ "auth-options.h"
#ಅನ್ತರ್ಭಾವ "log.h"
#ಅನ್ತರ್ಭಾವ "misc.h"	/* servconf.h needs misc.h for struct ForwardOptions */
#ಅನ್ತರ್ಭಾವ "servconf.h"
#ಅನ್ತರ್ಭಾವ "hostfile.h"
#ಅನ್ತರ್ಭಾವ "auth.h"
#ಅನ್ತರ್ಭಾವ "ssh.h"
#ಅನ್ತರ್ಭಾವ "ssh_api.h"

ಪೂರ್ಣಾಙ್ಕ nischeck(ವರ್ಣ *);

ಪೂರ್ಣಾಙ್ಕ
sys_auth_passwd(ಸಂರಚನಾ ssh *ssh, ಧ್ರುವ ವರ್ಣ *password)
{
	Authctxt *authctxt = ssh->authctxt;
	ಸಂರಚನಾ passwd *pw = authctxt->pw;
	ವರ್ಣ *salt;
	ಪೂರ್ಣಾಙ್ಕ result;

	/* Just use the supplied fake password if authctxt is invalid */
	ವರ್ಣ *pw_password = authctxt->valid ? shadow_pw(pw) : pw->pw_passwd;

	ಯದಿ (pw_password == ರಿಕ್ತ)
		ಪ್ರತ್ಯಾಗಮ 0;

	/* Check for users with no password. */
	ಯದಿ (strcmp(pw_password, "") == 0 && strcmp(password, "") == 0)
		ಪ್ರತ್ಯಾಗಮ (1);

	/* Encrypt the candidate password using the proper salt. */
	salt = (pw_password[0] && pw_password[1]) ? pw_password : "xx";

	/*
	 * Authentication is accepted if the encrypted passwords
	 * are identical.
	 */
#ifdef UNIXWARE_LONG_PASSWORDS
	ಯದಿ (!nischeck(pw->pw_name)) {
		result = ((strcmp(bigcrypt(password, salt), pw_password) == 0)
		||  (strcmp(osr5bigcrypt(password, salt), pw_password) == 0));
	}
	ಅನ್ಯಥಾ
#endif /* UNIXWARE_LONG_PASSWORDS */
		result = (strcmp(xcrypt(password, salt), pw_password) == 0);

#ifdef USE_LIBIAF
	ಯದಿ (authctxt->valid)
		ಮುಕ್ತ(pw_password);
#endif
	ಪ್ರತ್ಯಾಗಮ(result);
}

#ifdef UNIXWARE_LONG_PASSWORDS
ಪೂರ್ಣಾಙ್ಕ
nischeck(ವರ್ಣ *namep)
{
	ವರ್ಣ password_file[] = "/etc/passwd";
	FILE *fd;
	ಸಂರಚನಾ passwd *ent = ರಿಕ್ತ;

	ಯದಿ ((fd = fopen (password_file, "r")) == ರಿಕ್ತ) {
		/*
		 * If the passwd file has disappeared we are in a bad state.
		 * However, returning 0 will send us back through the
		 * authentication scheme that has checked the ia database for
		 * passwords earlier.
		 */
		ಪ್ರತ್ಯಾಗಮ(0);
	}

	/*
	 * fgetpwent() only reads from password file, so we know for certain
	 * that the user is local.
	 */
	ಯಾವತ್ (ent = fgetpwent(fd)) {
		ಯದಿ (strcmp (ent->pw_name, namep) == 0) {
			/* Local user */
			fclose (fd);
			ಪ್ರತ್ಯಾಗಮ(0);
		}
	}

	fclose (fd);
	ಪ್ರತ್ಯಾಗಮ (1);
}

#endif /* UNIXWARE_LONG_PASSWORDS */

/*
	NOTE: ia_get_logpwd() allocates memory for arg 2
	functions that call shadow_pw() will need to free
 */

#ifdef USE_LIBIAF
ವರ್ಣ *
get_iaf_password(ಸಂರಚನಾ passwd *pw)
{
	ವರ್ಣ *pw_password = ರಿಕ್ತ;

	uinfo_t uinfo;
	ಯದಿ (!ia_openinfo(pw->pw_name,&uinfo)) {
		ia_get_logpwd(uinfo, &pw_password);
		ಯದಿ (pw_password == ರಿಕ್ತ)
			fatal("ia_get_logpwd: Unable to get the shadow passwd");
		ia_closeinfo(uinfo);
		ಪ್ರತ್ಯಾಗಮ pw_password;
	}
	ಅನ್ಯಥಾ
		fatal("ia_openinfo: Unable to open the shadow passwd file");
}
#endif /* USE_LIBIAF */
#endif /* HAVE_LIBIAF and not HAVE_SECUREWARE */

