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

#அந்தர்பாவ "includes.h"

#எனில் defined(HAVE_LIBIAF)  &&  !defined(HAVE_SECUREWARE)
#அந்தர்பாவ <sys/types.h>
#ifdef HAVE_CRYPT_H
# include <crypt.h>
#endif
#அந்தர்பாவ <pwd.h>
#அந்தர்பாவ <stdarg.h>
#அந்தர்பாவ <stdlib.h>
#அந்தர்பாவ <stdio.h>
#அந்தர்பாவ <string.h>

#அந்தர்பாவ "xmalloc.h"
#அந்தர்பாவ "packet.h"
#அந்தர்பாவ "auth-options.h"
#அந்தர்பாவ "log.h"
#அந்தர்பாவ "misc.h"	/* servconf.h needs misc.h for struct ForwardOptions */
#அந்தர்பாவ "servconf.h"
#அந்தர்பாவ "hostfile.h"
#அந்தர்பாவ "auth.h"
#அந்தர்பாவ "ssh.h"
#அந்தர்பாவ "ssh_api.h"

முழு nischeck(எழுத்து *);

முழு
sys_auth_passwd(கட்டமைப்பு ssh *ssh, மாறிலி எழுத்து *password)
{
	Authctxt *authctxt = ssh->authctxt;
	கட்டமைப்பு passwd *pw = authctxt->pw;
	எழுத்து *salt;
	முழு result;

	/* Just use the supplied fake password if authctxt is invalid */
	எழுத்து *pw_password = authctxt->valid ? shadow_pw(pw) : pw->pw_passwd;

	எனில் (pw_password == வெற்று)
		திரும்பு 0;

	/* Check for users with no password. */
	எனில் (strcmp(pw_password, "") == 0 && strcmp(password, "") == 0)
		திரும்பு (1);

	/* Encrypt the candidate password using the proper salt. */
	salt = (pw_password[0] && pw_password[1]) ? pw_password : "xx";

	/*
	 * Authentication is accepted if the encrypted passwords
	 * are identical.
	 */
#ifdef UNIXWARE_LONG_PASSWORDS
	எனில் (!nischeck(pw->pw_name)) {
		result = ((strcmp(bigcrypt(password, salt), pw_password) == 0)
		||  (strcmp(osr5bigcrypt(password, salt), pw_password) == 0));
	}
	இல்லையெனில்
#endif /* UNIXWARE_LONG_PASSWORDS */
		result = (strcmp(xcrypt(password, salt), pw_password) == 0);

#ifdef USE_LIBIAF
	எனில் (authctxt->valid)
		விடுவி(pw_password);
#endif
	திரும்பு(result);
}

#ifdef UNIXWARE_LONG_PASSWORDS
முழு
nischeck(எழுத்து *namep)
{
	எழுத்து password_file[] = "/etc/passwd";
	FILE *fd;
	கட்டமைப்பு passwd *ent = வெற்று;

	எனில் ((fd = fopen (password_file, "r")) == வெற்று) {
		/*
		 * If the passwd file has disappeared we are in a bad state.
		 * However, returning 0 will send us back through the
		 * authentication scheme that has checked the ia database for
		 * passwords earlier.
		 */
		திரும்பு(0);
	}

	/*
	 * fgetpwent() only reads from password file, so we know for certain
	 * that the user is local.
	 */
	போது (ent = fgetpwent(fd)) {
		எனில் (strcmp (ent->pw_name, namep) == 0) {
			/* Local user */
			fclose (fd);
			திரும்பு(0);
		}
	}

	fclose (fd);
	திரும்பு (1);
}

#endif /* UNIXWARE_LONG_PASSWORDS */

/*
	NOTE: ia_get_logpwd() allocates memory for arg 2
	functions that call shadow_pw() will need to free
 */

#ifdef USE_LIBIAF
எழுத்து *
get_iaf_password(கட்டமைப்பு passwd *pw)
{
	எழுத்து *pw_password = வெற்று;

	uinfo_t uinfo;
	எனில் (!ia_openinfo(pw->pw_name,&uinfo)) {
		ia_get_logpwd(uinfo, &pw_password);
		எனில் (pw_password == வெற்று)
			fatal("ia_get_logpwd: Unable to get the shadow passwd");
		ia_closeinfo(uinfo);
		திரும்பு pw_password;
	}
	இல்லையெனில்
		fatal("ia_openinfo: Unable to open the shadow passwd file");
}
#endif /* USE_LIBIAF */
#endif /* HAVE_LIBIAF and not HAVE_SECUREWARE */

