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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਜੇ defined(HAVE_LIBIAF)  &&  !defined(HAVE_SECUREWARE)
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_CRYPT_H
# include <crypt.h>
#ਜੇ_ਅੰਤ
#ਅਨ੍ਤਰ੍ਭਾਵ <pwd.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdarg.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "xmalloc.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "packet.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "auth-options.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "log.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "misc.h"	/* servconf.h needs misc.h for struct ForwardOptions */
#ਅਨ੍ਤਰ੍ਭਾਵ "servconf.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "hostfile.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "auth.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssh.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssh_api.h"

ਪੂਰਨ nischeck(ਅੱਖਰ *);

ਪੂਰਨ
sys_auth_passwd(ਬਣਤਰ ssh *ssh, ਅਚਲ ਅੱਖਰ *password)
{
	Authctxt *authctxt = ssh->authctxt;
	ਬਣਤਰ passwd *pw = authctxt->pw;
	ਅੱਖਰ *salt;
	ਪੂਰਨ ਨਤੀਜਾ;

	/* Just use the supplied fake password if authctxt is invalid */
	ਅੱਖਰ *pw_password = authctxt->valid ? shadow_pw(pw) : pw->pw_passwd;

	ਜੇ (pw_password == ਨਿਰਾ)
		ਵਾਪਸ 0;

	/* Check for users with no password. */
	ਜੇ (strcmp(pw_password, "") == 0 && strcmp(password, "") == 0)
		ਵਾਪਸ (1);

	/* Encrypt the candidate password using the proper salt. */
	salt = (pw_password[0] && pw_password[1]) ? pw_password : "xx";

	/*
	 * Authentication is accepted if the encrypted passwords
	 * are identical.
	 */
#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ UNIXWARE_LONG_PASSWORDS
	ਜੇ (!nischeck(pw->pw_name)) {
		ਨਤੀਜਾ = ((strcmp(bigcrypt(password, salt), pw_password) == 0)
		||  (strcmp(osr5bigcrypt(password, salt), pw_password) == 0));
	}
	ਨਹੀਂਤਾਂ
#ਜੇ_ਅੰਤ /* UNIXWARE_LONG_PASSWORDS */
		ਨਤੀਜਾ = (strcmp(xcrypt(password, salt), pw_password) == 0);

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ USE_LIBIAF
	ਜੇ (authctxt->valid)
		ਮੁਕਤ(pw_password);
#ਜੇ_ਅੰਤ
	ਵਾਪਸ(ਨਤੀਜਾ);
}

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ UNIXWARE_LONG_PASSWORDS
ਪੂਰਨ
nischeck(ਅੱਖਰ *namep)
{
	ਅੱਖਰ password_file[] = "/etc/passwd";
	FILE *fd;
	ਬਣਤਰ passwd *ent = ਨਿਰਾ;

	ਜੇ ((fd = fopen (password_file, "r")) == ਨਿਰਾ) {
		/*
		 * If the passwd file has disappeared we are in a bad state.
		 * However, returning 0 will send us back through the
		 * authentication scheme that has checked the ia database for
		 * passwords earlier.
		 */
		ਵਾਪਸ(0);
	}

	/*
	 * fgetpwent() only reads from password file, so we know for certain
	 * that the user is local.
	 */
	ਜਦੋਂ (ent = fgetpwent(fd)) {
		ਜੇ (strcmp (ent->pw_name, namep) == 0) {
			/* Local user */
			fclose (fd);
			ਵਾਪਸ(0);
		}
	}

	fclose (fd);
	ਵਾਪਸ (1);
}

#ਜੇ_ਅੰਤ /* UNIXWARE_LONG_PASSWORDS */

/*
	NOTE: ia_get_logpwd() allocates memory for arg 2
	functions that call shadow_pw() will need to free
 */

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ USE_LIBIAF
ਅੱਖਰ *
get_iaf_password(ਬਣਤਰ passwd *pw)
{
	ਅੱਖਰ *pw_password = ਨਿਰਾ;

	uinfo_t uinfo;
	ਜੇ (!ia_openinfo(pw->pw_name,&uinfo)) {
		ia_get_logpwd(uinfo, &pw_password);
		ਜੇ (pw_password == ਨਿਰਾ)
			fatal("ia_get_logpwd: Unable to get the shadow passwd");
		ia_closeinfo(uinfo);
		ਵਾਪਸ pw_password;
	}
	ਨਹੀਂਤਾਂ
		fatal("ia_openinfo: Unable to open the shadow passwd file");
}
#ਜੇ_ਅੰਤ /* USE_LIBIAF */
#ਜੇ_ਅੰਤ /* HAVE_LIBIAF and not HAVE_SECUREWARE */

