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

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ଯଦି defined(HAVE_LIBIAF)  &&  !defined(HAVE_SECUREWARE)
#ଅନ୍ତର୍ଭାଵ <sys/types.h>
#ifdef HAVE_CRYPT_H
# include <crypt.h>
#endif
#ଅନ୍ତର୍ଭାଵ <pwd.h>
#ଅନ୍ତର୍ଭାଵ <stdarg.h>
#ଅନ୍ତର୍ଭାଵ <stdlib.h>
#ଅନ୍ତର୍ଭାଵ <stdio.h>
#ଅନ୍ତର୍ଭାଵ <string.h>

#ଅନ୍ତର୍ଭାଵ "xmalloc.h"
#ଅନ୍ତର୍ଭାଵ "packet.h"
#ଅନ୍ତର୍ଭାଵ "auth-options.h"
#ଅନ୍ତର୍ଭାଵ "log.h"
#ଅନ୍ତର୍ଭାଵ "misc.h"	/* servconf.h needs misc.h for struct ForwardOptions */
#ଅନ୍ତର୍ଭାଵ "servconf.h"
#ଅନ୍ତର୍ଭାଵ "hostfile.h"
#ଅନ୍ତର୍ଭାଵ "auth.h"
#ଅନ୍ତର୍ଭାଵ "ssh.h"
#ଅନ୍ତର୍ଭାଵ "ssh_api.h"

ପୂର୍ଣ୍ଣସଂଖ୍ୟା nischeck(ଅକ୍ଷର *);

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
sys_auth_passwd(ସଂରଚନା ssh *ssh, ଅଚଳ ଅକ୍ଷର *password)
{
	Authctxt *authctxt = ssh->authctxt;
	ସଂରଚନା passwd *pw = authctxt->pw;
	ଅକ୍ଷର *salt;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା result;

	/* Just use the supplied fake password if authctxt is invalid */
	ଅକ୍ଷର *pw_password = authctxt->valid ? shadow_pw(pw) : pw->pw_passwd;

	ଯଦି (pw_password == ଖାଲି)
		ଫେରନ୍ତୁ 0;

	/* Check for users with no password. */
	ଯଦି (strcmp(pw_password, "") == 0 && strcmp(password, "") == 0)
		ଫେରନ୍ତୁ (1);

	/* Encrypt the candidate password using the proper salt. */
	salt = (pw_password[0] && pw_password[1]) ? pw_password : "xx";

	/*
	 * Authentication is accepted if the encrypted passwords
	 * are identical.
	 */
#ifdef UNIXWARE_LONG_PASSWORDS
	ଯଦି (!nischeck(pw->pw_name)) {
		result = ((strcmp(bigcrypt(password, salt), pw_password) == 0)
		||  (strcmp(osr5bigcrypt(password, salt), pw_password) == 0));
	}
	ଅନ୍ୟଥା
#endif /* UNIXWARE_LONG_PASSWORDS */
		result = (strcmp(xcrypt(password, salt), pw_password) == 0);

#ifdef USE_LIBIAF
	ଯଦି (authctxt->valid)
		ମୁକ୍ତ(pw_password);
#endif
	ଫେରନ୍ତୁ(result);
}

#ifdef UNIXWARE_LONG_PASSWORDS
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
nischeck(ଅକ୍ଷର *namep)
{
	ଅକ୍ଷର password_file[] = "/etc/passwd";
	FILE *fd;
	ସଂରଚନା passwd *ent = ଖାଲି;

	ଯଦି ((fd = fopen (password_file, "r")) == ଖାଲି) {
		/*
		 * If the passwd file has disappeared we are in a bad state.
		 * However, returning 0 will send us back through the
		 * authentication scheme that has checked the ia database for
		 * passwords earlier.
		 */
		ଫେରନ୍ତୁ(0);
	}

	/*
	 * fgetpwent() only reads from password file, so we know for certain
	 * that the user is local.
	 */
	ଯେତେବେଳେ (ent = fgetpwent(fd)) {
		ଯଦି (strcmp (ent->pw_name, namep) == 0) {
			/* Local user */
			fclose (fd);
			ଫେରନ୍ତୁ(0);
		}
	}

	fclose (fd);
	ଫେରନ୍ତୁ (1);
}

#endif /* UNIXWARE_LONG_PASSWORDS */

/*
	NOTE: ia_get_logpwd() allocates memory for arg 2
	functions that call shadow_pw() will need to free
 */

#ifdef USE_LIBIAF
ଅକ୍ଷର *
get_iaf_password(ସଂରଚନା passwd *pw)
{
	ଅକ୍ଷର *pw_password = ଖାଲି;

	uinfo_t uinfo;
	ଯଦି (!ia_openinfo(pw->pw_name,&uinfo)) {
		ia_get_logpwd(uinfo, &pw_password);
		ଯଦି (pw_password == ଖାଲି)
			fatal("ia_get_logpwd: Unable to get the shadow passwd");
		ia_closeinfo(uinfo);
		ଫେରନ୍ତୁ pw_password;
	}
	ଅନ୍ୟଥା
		fatal("ia_openinfo: Unable to open the shadow passwd file");
}
#endif /* USE_LIBIAF */
#endif /* HAVE_LIBIAF and not HAVE_SECUREWARE */

