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

#ಆದರೆ defined(HAVE_LIBIAF)  &&  !defined(HAVE_SECUREWARE)
#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_CRYPT_H
# include <crypt.h>
#ಆದರೆ_ಅಂತ್ಯ
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

ಪೂರ್ಣಾಂಕ nischeck(ಅಕ್ಷರ *);

ಪೂರ್ಣಾಂಕ
sys_auth_passwd(ರಚನೆ ssh *ssh, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *password)
{
	Authctxt *authctxt = ssh->authctxt;
	ರಚನೆ passwd *pw = authctxt->pw;
	ಅಕ್ಷರ *salt;
	ಪೂರ್ಣಾಂಕ ಫಲಿತಾಂಶ;

	/* Just use the supplied fake password if authctxt is invalid */
	ಅಕ್ಷರ *pw_password = authctxt->valid ? shadow_pw(pw) : pw->pw_passwd;

	ಆದರೆ (pw_password == ಖಾಲಿ)
		ಹಿಂತಿರುಗಿ 0;

	/* Check for users with no password. */
	ಆದರೆ (strcmp(pw_password, "") == 0 && strcmp(password, "") == 0)
		ಹಿಂತಿರುಗಿ (1);

	/* Encrypt the candidate password using the proper salt. */
	salt = (pw_password[0] && pw_password[1]) ? pw_password : "xx";

	/*
	 * Authentication is accepted if the encrypted passwords
	 * are identical.
	 */
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ UNIXWARE_LONG_PASSWORDS
	ಆದರೆ (!nischeck(pw->pw_name)) {
		ಫಲಿತಾಂಶ = ((strcmp(bigcrypt(password, salt), pw_password) == 0)
		||  (strcmp(osr5bigcrypt(password, salt), pw_password) == 0));
	}
	ಇಲ್ಲದಿದ್ದರೆ
#ಆದರೆ_ಅಂತ್ಯ /* UNIXWARE_LONG_PASSWORDS */
		ಫಲಿತಾಂಶ = (strcmp(xcrypt(password, salt), pw_password) == 0);

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ USE_LIBIAF
	ಆದರೆ (authctxt->valid)
		ಬಿಡುಗಡೆ(pw_password);
#ಆದರೆ_ಅಂತ್ಯ
	ಹಿಂತಿರುಗಿ(ಫಲಿತಾಂಶ);
}

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ UNIXWARE_LONG_PASSWORDS
ಪೂರ್ಣಾಂಕ
nischeck(ಅಕ್ಷರ *namep)
{
	ಅಕ್ಷರ password_file[] = "/etc/passwd";
	FILE *fd;
	ರಚನೆ passwd *ent = ಖಾಲಿ;

	ಆದರೆ ((fd = fopen (password_file, "r")) == ಖಾಲಿ) {
		/*
		 * If the passwd file has disappeared we are in a bad state.
		 * However, returning 0 will send us back through the
		 * authentication scheme that has checked the ia database for
		 * passwords earlier.
		 */
		ಹಿಂತಿರುಗಿ(0);
	}

	/*
	 * fgetpwent() only reads from password file, so we know for certain
	 * that the user is local.
	 */
	ಆಗ (ent = fgetpwent(fd)) {
		ಆದರೆ (strcmp (ent->pw_name, namep) == 0) {
			/* Local user */
			fclose (fd);
			ಹಿಂತಿರುಗಿ(0);
		}
	}

	fclose (fd);
	ಹಿಂತಿರುಗಿ (1);
}

#ಆದರೆ_ಅಂತ್ಯ /* UNIXWARE_LONG_PASSWORDS */

/*
	NOTE: ia_get_logpwd() allocates memory for arg 2
	functions that call shadow_pw() will need to free
 */

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ USE_LIBIAF
ಅಕ್ಷರ *
get_iaf_password(ರಚನೆ passwd *pw)
{
	ಅಕ್ಷರ *pw_password = ಖಾಲಿ;

	uinfo_t uinfo;
	ಆದರೆ (!ia_openinfo(pw->pw_name,&uinfo)) {
		ia_get_logpwd(uinfo, &pw_password);
		ಆದರೆ (pw_password == ಖಾಲಿ)
			fatal("ia_get_logpwd: Unable to get the shadow passwd");
		ia_closeinfo(uinfo);
		ಹಿಂತಿರುಗಿ pw_password;
	}
	ಇಲ್ಲದಿದ್ದರೆ
		fatal("ia_openinfo: Unable to open the shadow passwd file");
}
#ಆದರೆ_ಅಂತ್ಯ /* USE_LIBIAF */
#ಆದರೆ_ಅಂತ್ಯ /* HAVE_LIBIAF and not HAVE_SECUREWARE */

