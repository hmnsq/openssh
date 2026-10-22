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

#include "includes.h"

#ꦪꦼꦤ꧀ defined(HAVE_LIBIAF)  &&  !defined(HAVE_SECUREWARE)
#include <sys/types.h>
#ifdef HAVE_CRYPT_H
# include <crypt.h>
#endif
#include <pwd.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "xmalloc.h"
#include "packet.h"
#include "auth-options.h"
#include "log.h"
#include "misc.h"	/* servconf.h needs misc.h for struct ForwardOptions */
#include "servconf.h"
#include "hostfile.h"
#include "auth.h"
#include "ssh.h"
#include "ssh_api.h"

puur_naa_nka nischeck(var_na *);

puur_naa_nka
sys_auth_passwd(sa_nracanaa ssh *ssh, const var_na *password)
{
	Authctxt *authctxt = ssh->authctxt;
	sa_nracanaa passwd *pw = authctxt->pw;
	var_na *salt;
	puur_naa_nka result;

	/* Just use the supplied fake password if authctxt is invalid */
	var_na *pw_password = authctxt->valid ? shadow_pw(pw) : pw->pw_passwd;

	ꦪꦼꦤ꧀ (pw_password == NULL)
		ꦮꦭꦶ 0;

	/* Check for users with no password. */
	ꦪꦼꦤ꧀ (strcmp(pw_password, "") == 0 && strcmp(password, "") == 0)
		ꦮꦭꦶ (1);

	/* Encrypt the candidate password using the proper salt. */
	salt = (pw_password[0] && pw_password[1]) ? pw_password : "xx";

	/*
	 * Authentication is accepted if the encrypted passwords
	 * are identical.
	 */
#ifdef UNIXWARE_LONG_PASSWORDS
	ꦪꦼꦤ꧀ (!nischeck(pw->pw_name)) {
		result = ((strcmp(bigcrypt(password, salt), pw_password) == 0)
		||  (strcmp(osr5bigcrypt(password, salt), pw_password) == 0));
	}
	ꦭꦶꦪ
#endif /* UNIXWARE_LONG_PASSWORDS */
		result = (strcmp(xcrypt(password, salt), pw_password) == 0);

#ifdef USE_LIBIAF
	ꦪꦼꦤ꧀ (authctxt->valid)
		free(pw_password);
#endif
	ꦮꦭꦶ(result);
}

#ifdef UNIXWARE_LONG_PASSWORDS
puur_naa_nka
nischeck(var_na *namep)
{
	var_na password_file[] = "/etc/passwd";
	FILE *fd;
	sa_nracanaa passwd *ent = NULL;

	ꦪꦼꦤ꧀ ((fd = fopen (password_file, "r")) == NULL) {
		/*
		 * If the passwd file has disappeared we are in a bad state.
		 * However, returning 0 will send us back through the
		 * authentication scheme that has checked the ia database for
		 * passwords earlier.
		 */
		ꦮꦭꦶ(0);
	}

	/*
	 * fgetpwent() only reads from password file, so we know for certain
	 * that the user is local.
	 */
	ꦱꦼꦢꦼꦭ (ent = fgetpwent(fd)) {
		ꦪꦼꦤ꧀ (strcmp (ent->pw_name, namep) == 0) {
			/* Local user */
			fclose (fd);
			ꦮꦭꦶ(0);
		}
	}

	fclose (fd);
	ꦮꦭꦶ (1);
}

#endif /* UNIXWARE_LONG_PASSWORDS */

/*
	NOTE: ia_get_logpwd() allocates memory for arg 2
	functions that call shadow_pw() will need to free
 */

#ifdef USE_LIBIAF
var_na *
get_iaf_password(sa_nracanaa passwd *pw)
{
	var_na *pw_password = NULL;

	uinfo_t uinfo;
	ꦪꦼꦤ꧀ (!ia_openinfo(pw->pw_name,&uinfo)) {
		ia_get_logpwd(uinfo, &pw_password);
		ꦪꦼꦤ꧀ (pw_password == NULL)
			fatal("ia_get_logpwd: Unable to get the shadow passwd");
		ia_closeinfo(uinfo);
		ꦮꦭꦶ pw_password;
	}
	ꦭꦶꦪ
		fatal("ia_openinfo: Unable to open the shadow passwd file");
}
#endif /* USE_LIBIAF */
#endif /* HAVE_LIBIAF and not HAVE_SECUREWARE */

