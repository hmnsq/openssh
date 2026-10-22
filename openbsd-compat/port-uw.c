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

#અન્તર્ભાવ "includes.h"

#જો defined(HAVE_LIBIAF)  &&  !defined(HAVE_SECUREWARE)
#અન્તર્ભાવ <sys/types.h>
#ifdef HAVE_CRYPT_H
# include <crypt.h>
#endif
#અન્તર્ભાવ <pwd.h>
#અન્તર્ભાવ <stdarg.h>
#અન્તર્ભાવ <stdlib.h>
#અન્તર્ભાવ <stdio.h>
#અન્તર્ભાવ <string.h>

#અન્તર્ભાવ "xmalloc.h"
#અન્તર્ભાવ "packet.h"
#અન્તર્ભાવ "auth-options.h"
#અન્તર્ભાવ "log.h"
#અન્તર્ભાવ "misc.h"	/* servconf.h needs misc.h for struct ForwardOptions */
#અન્તર્ભાવ "servconf.h"
#અન્તર્ભાવ "hostfile.h"
#અન્તર્ભાવ "auth.h"
#અન્તર્ભાવ "ssh.h"
#અન્તર્ભાવ "ssh_api.h"

પૂર્ણાંક nischeck(અક્ષર *);

પૂર્ણાંક
sys_auth_passwd(સંરચના ssh *ssh, અચલ અક્ષર *password)
{
	Authctxt *authctxt = ssh->authctxt;
	સંરચના passwd *pw = authctxt->pw;
	અક્ષર *salt;
	પૂર્ણાંક result;

	/* Just use the supplied fake password if authctxt is invalid */
	અક્ષર *pw_password = authctxt->valid ? shadow_pw(pw) : pw->pw_passwd;

	જો (pw_password == ખાલી)
		પાછા 0;

	/* Check for users with no password. */
	જો (strcmp(pw_password, "") == 0 && strcmp(password, "") == 0)
		પાછા (1);

	/* Encrypt the candidate password using the proper salt. */
	salt = (pw_password[0] && pw_password[1]) ? pw_password : "xx";

	/*
	 * Authentication is accepted if the encrypted passwords
	 * are identical.
	 */
#ifdef UNIXWARE_LONG_PASSWORDS
	જો (!nischeck(pw->pw_name)) {
		result = ((strcmp(bigcrypt(password, salt), pw_password) == 0)
		||  (strcmp(osr5bigcrypt(password, salt), pw_password) == 0));
	}
	નહીંતર
#endif /* UNIXWARE_LONG_PASSWORDS */
		result = (strcmp(xcrypt(password, salt), pw_password) == 0);

#ifdef USE_LIBIAF
	જો (authctxt->valid)
		મુક્ત(pw_password);
#endif
	પાછા(result);
}

#ifdef UNIXWARE_LONG_PASSWORDS
પૂર્ણાંક
nischeck(અક્ષર *namep)
{
	અક્ષર password_file[] = "/etc/passwd";
	FILE *fd;
	સંરચના passwd *ent = ખાલી;

	જો ((fd = fopen (password_file, "r")) == ખાલી) {
		/*
		 * If the passwd file has disappeared we are in a bad state.
		 * However, returning 0 will send us back through the
		 * authentication scheme that has checked the ia database for
		 * passwords earlier.
		 */
		પાછા(0);
	}

	/*
	 * fgetpwent() only reads from password file, so we know for certain
	 * that the user is local.
	 */
	જ્યારે (ent = fgetpwent(fd)) {
		જો (strcmp (ent->pw_name, namep) == 0) {
			/* Local user */
			fclose (fd);
			પાછા(0);
		}
	}

	fclose (fd);
	પાછા (1);
}

#endif /* UNIXWARE_LONG_PASSWORDS */

/*
	NOTE: ia_get_logpwd() allocates memory for arg 2
	functions that call shadow_pw() will need to free
 */

#ifdef USE_LIBIAF
અક્ષર *
get_iaf_password(સંરચના passwd *pw)
{
	અક્ષર *pw_password = ખાલી;

	uinfo_t uinfo;
	જો (!ia_openinfo(pw->pw_name,&uinfo)) {
		ia_get_logpwd(uinfo, &pw_password);
		જો (pw_password == ખાલી)
			fatal("ia_get_logpwd: Unable to get the shadow passwd");
		ia_closeinfo(uinfo);
		પાછા pw_password;
	}
	નહીંતર
		fatal("ia_openinfo: Unable to open the shadow passwd file");
}
#endif /* USE_LIBIAF */
#endif /* HAVE_LIBIAF and not HAVE_SECUREWARE */

