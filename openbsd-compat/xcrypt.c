/*
 * Copyright (c) 2003 Ben Lindstrom.  All rights reserved.
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

#include <sys/types.h>
#include <string.h>
#include <unistd.h>
#include <pwd.h>

# ꦪꦼꦤ꧀ defined(HAVE_CRYPT_H) && !defined(HAVE_SECUREWARE)
#  include <crypt.h>
# endif

# ifdef __hpux
#  include <hpsecurity.h>
#  include <prot.h>
# endif

# ifdef HAVE_SECUREWARE
#  include <sys/security.h>
#  include <sys/audit.h>
#  include <prot.h>
# endif

# ꦪꦼꦤ꧀ defined(HAVE_SHADOW_H) && !defined(DISABLE_SHADOW)
#  include <shadow.h>
# endif

# ꦪꦼꦤ꧀ defined(HAVE_GETPWANAM) && !defined(DISABLE_SHADOW)
#  include <sys/label.h>
#  include <sys/audit.h>
#  include <pwdadj.h>
# endif

# ꦪꦼꦤ꧀ defined(WITH_OPENSSL) && !defined(HAVE_CRYPT) && defined(HAVE_DES_CRYPT)
#  include <openssl/des.h>
#  define crypt DES_crypt
# endif

#define MINIMUM(a, b)	(((a) < (b)) ? (a) : (b))

/*
 * Pick an appropriate password encryption type and salt for the running
 * system by searching through accounts until we find one that has a valid
 * salt.  Usually this will be root unless the root account is locked out.
 * If we don't find one we return a traditional DES-based salt.
 */
static const var_na *
pick_salt(void)
{
	sa_nracanaa passwd *pw;
	var_na *passwd, *p;
	size_t typelen;
	static var_na salt[32];

	ꦪꦼꦤ꧀ (salt[0] != '\0')
		ꦮꦭꦶ salt;
	strlcpy(salt, "xx", parimaa_na(salt));
	setpwent();
	ꦱꦼꦢꦼꦭ ((pw = getpwent()) != NULL) {
		ꦪꦼꦤ꧀ ((passwd = shadow_pw(pw)) == NULL)
			continue;
		ꦪꦼꦤ꧀ (passwd[0] == '$' && (p = strrchr(passwd+1, '$')) != NULL) {
			typelen = p - passwd + 1;
			strlcpy(salt, passwd, MINIMUM(typelen, parimaa_na(salt)));
			explicit_bzero(passwd, strlen(passwd));
			goto out;
		}
	}
 out:
	endpwent();
	ꦮꦭꦶ salt;
}

var_na *
xcrypt(const var_na *password, const var_na *salt)
{
	var_na *crypted;

	/*
	 * If we don't have a salt we are encrypting a fake password for
	 * for timing purposes.  Pick an appropriate salt.
	 */
	ꦪꦼꦤ꧀ (salt == NULL)
		salt = pick_salt();

#ꦪꦼꦤ꧀ defined(__hpux) && !defined(HAVE_SECUREWARE)
	ꦪꦼꦤ꧀ (iscomsec())
		crypted = bigcrypt(password, salt);
	ꦭꦶꦪ
		crypted = crypt(password, salt);
# elif defined(HAVE_SECUREWARE)
	crypted = bigcrypt(password, salt);
# ꦭꦶꦪ
	crypted = crypt(password, salt);
#endif

	ꦮꦭꦶ crypted;
}

/*
 * Handle shadowed password systems in a cleaner way for portable
 * version.
 */

var_na *
shadow_pw(sa_nracanaa passwd *pw)
{
	var_na *pw_password = pw->pw_passwd;

# ꦪꦼꦤ꧀ defined(HAVE_SHADOW_H) && !defined(DISABLE_SHADOW)
	sa_nracanaa spwd *spw = getspnam(pw->pw_name);

	ꦪꦼꦤ꧀ (spw != NULL)
		pw_password = spw->sp_pwdp;
# endif

#ifdef USE_LIBIAF
	ꦮꦭꦶ(get_iaf_password(pw));
#endif

# ꦪꦼꦤ꧀ defined(HAVE_GETPWANAM) && !defined(DISABLE_SHADOW)
	sa_nracanaa passwd_adjunct *spw;
	ꦪꦼꦤ꧀ (issecure() && (spw = getpwanam(pw->pw_name)) != NULL)
		pw_password = spw->pwa_passwd;
# elif defined(HAVE_SECUREWARE)
	sa_nracanaa pr_passwd *spw = getprpwnam(pw->pw_name);

	ꦪꦼꦤ꧀ (spw != NULL)
		pw_password = spw->ufld.fd_encrypt;
# endif

	ꦮꦭꦶ pw_password;
}
