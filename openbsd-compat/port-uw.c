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

#অন্তর্ভাৱ "includes.h"

#যদি defined(HAVE_LIBIAF)  &&  !defined(HAVE_SECUREWARE)
#অন্তর্ভাৱ <sys/types.h>
#ifdef HAVE_CRYPT_H
# include <crypt.h>
#endif
#অন্তর্ভাৱ <pwd.h>
#অন্তর্ভাৱ <stdarg.h>
#অন্তর্ভাৱ <stdlib.h>
#অন্তর্ভাৱ <stdio.h>
#অন্তর্ভাৱ <string.h>

#অন্তর্ভাৱ "xmalloc.h"
#অন্তর্ভাৱ "packet.h"
#অন্তর্ভাৱ "auth-options.h"
#অন্তর্ভাৱ "log.h"
#অন্তর্ভাৱ "misc.h"	/* servconf.h needs misc.h for struct ForwardOptions */
#অন্তর্ভাৱ "servconf.h"
#অন্তর্ভাৱ "hostfile.h"
#অন্তর্ভাৱ "auth.h"
#অন্তর্ভাৱ "ssh.h"
#অন্তর্ভাৱ "ssh_api.h"

পূর্ণাঙ্ক nischeck(ৱর্ণ *);

পূর্ণাঙ্ক
sys_auth_passwd(সংরচনা ssh *ssh, ধ্রুৱ ৱর্ণ *password)
{
	Authctxt *authctxt = ssh->authctxt;
	সংরচনা passwd *pw = authctxt->pw;
	ৱর্ণ *salt;
	পূর্ণাঙ্ক result;

	/* Just use the supplied fake password if authctxt is invalid */
	ৱর্ণ *pw_password = authctxt->valid ? shadow_pw(pw) : pw->pw_passwd;

	যদি (pw_password == রিক্ত)
		ঘূৰাই 0;

	/* Check for users with no password. */
	যদি (strcmp(pw_password, "") == 0 && strcmp(password, "") == 0)
		ঘূৰাই (1);

	/* Encrypt the candidate password using the proper salt. */
	salt = (pw_password[0] && pw_password[1]) ? pw_password : "xx";

	/*
	 * Authentication is accepted if the encrypted passwords
	 * are identical.
	 */
#ifdef UNIXWARE_LONG_PASSWORDS
	যদি (!nischeck(pw->pw_name)) {
		result = ((strcmp(bigcrypt(password, salt), pw_password) == 0)
		||  (strcmp(osr5bigcrypt(password, salt), pw_password) == 0));
	}
	অন্যথা
#endif /* UNIXWARE_LONG_PASSWORDS */
		result = (strcmp(xcrypt(password, salt), pw_password) == 0);

#ifdef USE_LIBIAF
	যদি (authctxt->valid)
		মুক্ত(pw_password);
#endif
	ঘূৰাই(result);
}

#ifdef UNIXWARE_LONG_PASSWORDS
পূর্ণাঙ্ক
nischeck(ৱর্ণ *namep)
{
	ৱর্ণ password_file[] = "/etc/passwd";
	FILE *fd;
	সংরচনা passwd *ent = রিক্ত;

	যদি ((fd = fopen (password_file, "r")) == রিক্ত) {
		/*
		 * If the passwd file has disappeared we are in a bad state.
		 * However, returning 0 will send us back through the
		 * authentication scheme that has checked the ia database for
		 * passwords earlier.
		 */
		ঘূৰাই(0);
	}

	/*
	 * fgetpwent() only reads from password file, so we know for certain
	 * that the user is local.
	 */
	যেতিয়ালৈ (ent = fgetpwent(fd)) {
		যদি (strcmp (ent->pw_name, namep) == 0) {
			/* Local user */
			fclose (fd);
			ঘূৰাই(0);
		}
	}

	fclose (fd);
	ঘূৰাই (1);
}

#endif /* UNIXWARE_LONG_PASSWORDS */

/*
	NOTE: ia_get_logpwd() allocates memory for arg 2
	functions that call shadow_pw() will need to free
 */

#ifdef USE_LIBIAF
ৱর্ণ *
get_iaf_password(সংরচনা passwd *pw)
{
	ৱর্ণ *pw_password = রিক্ত;

	uinfo_t uinfo;
	যদি (!ia_openinfo(pw->pw_name,&uinfo)) {
		ia_get_logpwd(uinfo, &pw_password);
		যদি (pw_password == রিক্ত)
			fatal("ia_get_logpwd: Unable to get the shadow passwd");
		ia_closeinfo(uinfo);
		ঘূৰাই pw_password;
	}
	অন্যথা
		fatal("ia_openinfo: Unable to open the shadow passwd file");
}
#endif /* USE_LIBIAF */
#endif /* HAVE_LIBIAF and not HAVE_SECUREWARE */

