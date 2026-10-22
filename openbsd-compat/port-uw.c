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

#അന്തര്ഭാവ "includes.h"

#എങ്കിൽ defined(HAVE_LIBIAF)  &&  !defined(HAVE_SECUREWARE)
#അന്തര്ഭാവ <sys/types.h>
#ifdef HAVE_CRYPT_H
# include <crypt.h>
#endif
#അന്തര്ഭാവ <pwd.h>
#അന്തര്ഭാവ <stdarg.h>
#അന്തര്ഭാവ <stdlib.h>
#അന്തര്ഭാവ <stdio.h>
#അന്തര്ഭാവ <string.h>

#അന്തര്ഭാവ "xmalloc.h"
#അന്തര്ഭാവ "packet.h"
#അന്തര്ഭാവ "auth-options.h"
#അന്തര്ഭാവ "log.h"
#അന്തര്ഭാവ "misc.h"	/* servconf.h needs misc.h for struct ForwardOptions */
#അന്തര്ഭാവ "servconf.h"
#അന്തര്ഭാവ "hostfile.h"
#അന്തര്ഭാവ "auth.h"
#അന്തര്ഭാവ "ssh.h"
#അന്തര്ഭാവ "ssh_api.h"

പൂർണ്ണസംഖ്യ nischeck(അക്ഷരം *);

പൂർണ്ണസംഖ്യ
sys_auth_passwd(ഘടന ssh *ssh, സ്ഥിരം അക്ഷരം *password)
{
	Authctxt *authctxt = ssh->authctxt;
	ഘടന passwd *pw = authctxt->pw;
	അക്ഷരം *salt;
	പൂർണ്ണസംഖ്യ result;

	/* Just use the supplied fake password if authctxt is invalid */
	അക്ഷരം *pw_password = authctxt->valid ? shadow_pw(pw) : pw->pw_passwd;

	എങ്കിൽ (pw_password == ശൂന്യ)
		തിരികെ 0;

	/* Check for users with no password. */
	എങ്കിൽ (strcmp(pw_password, "") == 0 && strcmp(password, "") == 0)
		തിരികെ (1);

	/* Encrypt the candidate password using the proper salt. */
	salt = (pw_password[0] && pw_password[1]) ? pw_password : "xx";

	/*
	 * Authentication is accepted if the encrypted passwords
	 * are identical.
	 */
#ifdef UNIXWARE_LONG_PASSWORDS
	എങ്കിൽ (!nischeck(pw->pw_name)) {
		result = ((strcmp(bigcrypt(password, salt), pw_password) == 0)
		||  (strcmp(osr5bigcrypt(password, salt), pw_password) == 0));
	}
	അല്ലെങ്കിൽ
#endif /* UNIXWARE_LONG_PASSWORDS */
		result = (strcmp(xcrypt(password, salt), pw_password) == 0);

#ifdef USE_LIBIAF
	എങ്കിൽ (authctxt->valid)
		സ്വതന്ത്രം(pw_password);
#endif
	തിരികെ(result);
}

#ifdef UNIXWARE_LONG_PASSWORDS
പൂർണ്ണസംഖ്യ
nischeck(അക്ഷരം *namep)
{
	അക്ഷരം password_file[] = "/etc/passwd";
	FILE *fd;
	ഘടന passwd *ent = ശൂന്യ;

	എങ്കിൽ ((fd = fopen (password_file, "r")) == ശൂന്യ) {
		/*
		 * If the passwd file has disappeared we are in a bad state.
		 * However, returning 0 will send us back through the
		 * authentication scheme that has checked the ia database for
		 * passwords earlier.
		 */
		തിരികെ(0);
	}

	/*
	 * fgetpwent() only reads from password file, so we know for certain
	 * that the user is local.
	 */
	ആകുമ്പോൾ (ent = fgetpwent(fd)) {
		എങ്കിൽ (strcmp (ent->pw_name, namep) == 0) {
			/* Local user */
			fclose (fd);
			തിരികെ(0);
		}
	}

	fclose (fd);
	തിരികെ (1);
}

#endif /* UNIXWARE_LONG_PASSWORDS */

/*
	NOTE: ia_get_logpwd() allocates memory for arg 2
	functions that call shadow_pw() will need to free
 */

#ifdef USE_LIBIAF
അക്ഷരം *
get_iaf_password(ഘടന passwd *pw)
{
	അക്ഷരം *pw_password = ശൂന്യ;

	uinfo_t uinfo;
	എങ്കിൽ (!ia_openinfo(pw->pw_name,&uinfo)) {
		ia_get_logpwd(uinfo, &pw_password);
		എങ്കിൽ (pw_password == ശൂന്യ)
			fatal("ia_get_logpwd: Unable to get the shadow passwd");
		ia_closeinfo(uinfo);
		തിരികെ pw_password;
	}
	അല്ലെങ്കിൽ
		fatal("ia_openinfo: Unable to open the shadow passwd file");
}
#endif /* USE_LIBIAF */
#endif /* HAVE_LIBIAF and not HAVE_SECUREWARE */

