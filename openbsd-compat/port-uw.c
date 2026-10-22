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

#అన్తర్భావ "includes.h"

#ఒకవేళ defined(HAVE_LIBIAF)  &&  !defined(HAVE_SECUREWARE)
#అన్తర్భావ <sys/types.h>
#నిర్వచితమైతే HAVE_CRYPT_H
# include <crypt.h>
#అయితే_ముగింపు
#అన్తర్భావ <pwd.h>
#అన్తర్భావ <stdarg.h>
#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <stdio.h>
#అన్తర్భావ <string.h>

#అన్తర్భావ "xmalloc.h"
#అన్తర్భావ "packet.h"
#అన్తర్భావ "auth-options.h"
#అన్తర్భావ "log.h"
#అన్తర్భావ "misc.h"	/* servconf.h needs misc.h for struct ForwardOptions */
#అన్తర్భావ "servconf.h"
#అన్తర్భావ "hostfile.h"
#అన్తర్భావ "auth.h"
#అన్తర్భావ "ssh.h"
#అన్తర్భావ "ssh_api.h"

పూర్ణాంకం nischeck(అక్షరం *);

పూర్ణాంకం
sys_auth_passwd(నిర్మాణం ssh *ssh, స్థిరరాశి అక్షరం *password)
{
	Authctxt *authctxt = ssh->authctxt;
	నిర్మాణం passwd *pw = authctxt->pw;
	అక్షరం *salt;
	పూర్ణాంకం ఫలితం;

	/* Just use the supplied fake password if authctxt is invalid */
	అక్షరం *pw_password = authctxt->valid ? shadow_pw(pw) : pw->pw_passwd;

	ఒకవేళ (pw_password == ఖాళీ)
		తిరిగి 0;

	/* Check for users with no password. */
	ఒకవేళ (strcmp(pw_password, "") == 0 && strcmp(password, "") == 0)
		తిరిగి (1);

	/* Encrypt the candidate password using the proper salt. */
	salt = (pw_password[0] && pw_password[1]) ? pw_password : "xx";

	/*
	 * Authentication is accepted if the encrypted passwords
	 * are identical.
	 */
#నిర్వచితమైతే UNIXWARE_LONG_PASSWORDS
	ఒకవేళ (!nischeck(pw->pw_name)) {
		ఫలితం = ((strcmp(bigcrypt(password, salt), pw_password) == 0)
		||  (strcmp(osr5bigcrypt(password, salt), pw_password) == 0));
	}
	లేకపోతే
#అయితే_ముగింపు /* UNIXWARE_LONG_PASSWORDS */
		ఫలితం = (strcmp(xcrypt(password, salt), pw_password) == 0);

#నిర్వచితమైతే USE_LIBIAF
	ఒకవేళ (authctxt->valid)
		విడుదల(pw_password);
#అయితే_ముగింపు
	తిరిగి(ఫలితం);
}

#నిర్వచితమైతే UNIXWARE_LONG_PASSWORDS
పూర్ణాంకం
nischeck(అక్షరం *namep)
{
	అక్షరం password_file[] = "/etc/passwd";
	FILE *fd;
	నిర్మాణం passwd *ent = ఖాళీ;

	ఒకవేళ ((fd = fopen (password_file, "r")) == ఖాళీ) {
		/*
		 * If the passwd file has disappeared we are in a bad state.
		 * However, returning 0 will send us back through the
		 * authentication scheme that has checked the ia database for
		 * passwords earlier.
		 */
		తిరిగి(0);
	}

	/*
	 * fgetpwent() only reads from password file, so we know for certain
	 * that the user is local.
	 */
	అయితే (ent = fgetpwent(fd)) {
		ఒకవేళ (strcmp (ent->pw_name, namep) == 0) {
			/* Local user */
			fclose (fd);
			తిరిగి(0);
		}
	}

	fclose (fd);
	తిరిగి (1);
}

#అయితే_ముగింపు /* UNIXWARE_LONG_PASSWORDS */

/*
	NOTE: ia_get_logpwd() allocates memory for arg 2
	functions that call shadow_pw() will need to free
 */

#నిర్వచితమైతే USE_LIBIAF
అక్షరం *
get_iaf_password(నిర్మాణం passwd *pw)
{
	అక్షరం *pw_password = ఖాళీ;

	uinfo_t uinfo;
	ఒకవేళ (!ia_openinfo(pw->pw_name,&uinfo)) {
		ia_get_logpwd(uinfo, &pw_password);
		ఒకవేళ (pw_password == ఖాళీ)
			fatal("ia_get_logpwd: Unable to get the shadow passwd");
		ia_closeinfo(uinfo);
		తిరిగి pw_password;
	}
	లేకపోతే
		fatal("ia_openinfo: Unable to open the shadow passwd file");
}
#అయితే_ముగింపు /* USE_LIBIAF */
#అయితే_ముగింపు /* HAVE_LIBIAF and not HAVE_SECUREWARE */

