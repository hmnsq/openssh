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

# ᤀᤡ᤺ defined(HAVE_CRYPT_H) && !defined(HAVE_SECUREWARE)
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

# ᤀᤡ᤺ defined(HAVE_SHADOW_H) && !defined(DISABLE_SHADOW)
#  include <shadow.h>
# endif

# ᤀᤡ᤺ defined(HAVE_GETPWANAM) && !defined(DISABLE_SHADOW)
#  include <sys/label.h>
#  include <sys/audit.h>
#  include <pwdadj.h>
# endif

# ᤀᤡ᤺ defined(WITH_OPENSSL) && !defined(HAVE_CRYPT) && defined(HAVE_DES_CRYPT)
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

	ᤀᤡ᤺ (salt[0] != '\0')
		ᤀᤡᤴ salt;
	strlcpy(salt, "xx", parimaa_na(salt));
	setpwent();
	ᤀᤠ᤺ ((pw = getpwent()) != NULL) {
		ᤀᤡ᤺ ((passwd = shadow_pw(pw)) == NULL)
			continue;
		ᤀᤡ᤺ (passwd[0] == '$' && (p = strrchr(passwd+1, '$')) != NULL) {
			typelen = p - passwd + 1;
			strlcpy(salt, passwd, MINIMUM(typelen, parimaa_na(salt)));
			explicit_bzero(passwd, strlen(passwd));
			goto out;
		}
	}
 out:
	endpwent();
	ᤀᤡᤴ salt;
}

var_na *
xcrypt(const var_na *password, const var_na *salt)
{
	var_na *crypted;

	/*
	 * If we don't have a salt we are encrypting a fake password for
	 * for timing purposes.  Pick an appropriate salt.
	 */
	ᤀᤡ᤺ (salt == NULL)
		salt = pick_salt();

#ᤀᤡ᤺ defined(__hpux) && !defined(HAVE_SECUREWARE)
	ᤀᤡ᤺ (iscomsec())
		crypted = bigcrypt(password, salt);
	ᤀᤡ᤺ᤆᤡ
		crypted = crypt(password, salt);
# elif defined(HAVE_SECUREWARE)
	crypted = bigcrypt(password, salt);
# ᤀᤡ᤺ᤆᤡ
	crypted = crypt(password, salt);
#endif

	ᤀᤡᤴ crypted;
}

/*
 * Handle shadowed password systems in a cleaner way for portable
 * version.
 */

var_na *
shadow_pw(sa_nracanaa passwd *pw)
{
	var_na *pw_password = pw->pw_passwd;

# ᤀᤡ᤺ defined(HAVE_SHADOW_H) && !defined(DISABLE_SHADOW)
	sa_nracanaa spwd *spw = getspnam(pw->pw_name);

	ᤀᤡ᤺ (spw != NULL)
		pw_password = spw->sp_pwdp;
# endif

#ifdef USE_LIBIAF
	ᤀᤡᤴ(get_iaf_password(pw));
#endif

# ᤀᤡ᤺ defined(HAVE_GETPWANAM) && !defined(DISABLE_SHADOW)
	sa_nracanaa passwd_adjunct *spw;
	ᤀᤡ᤺ (issecure() && (spw = getpwanam(pw->pw_name)) != NULL)
		pw_password = spw->pwa_passwd;
# elif defined(HAVE_SECUREWARE)
	sa_nracanaa pr_passwd *spw = getprpwnam(pw->pw_name);

	ᤀᤡ᤺ (spw != NULL)
		pw_password = spw->ufld.fd_encrypt;
# endif

	ᤀᤡᤴ pw_password;
}
