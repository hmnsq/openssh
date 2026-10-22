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

#अन्तर्भाव "includes.h"

#अन्तर्भाव <sys/types.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <unistd.h>
#अन्तर्भाव <pwd.h>

# जइ defined(HAVE_CRYPT_H) && !defined(HAVE_SECUREWARE)
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

# जइ defined(HAVE_SHADOW_H) && !defined(DISABLE_SHADOW)
#  include <shadow.h>
# endif

# जइ defined(HAVE_GETPWANAM) && !defined(DISABLE_SHADOW)
#  include <sys/label.h>
#  include <sys/audit.h>
#  include <pwdadj.h>
# endif

# जइ defined(WITH_OPENSSL) && !defined(HAVE_CRYPT) && defined(HAVE_DES_CRYPT)
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
स्थिर ध्रुव वर्ण *
pick_salt(शून्य)
{
	संरचना passwd *pw;
	वर्ण *passwd, *p;
	size_t typelen;
	स्थिर वर्ण salt[32];

	जइ (salt[0] != '\0')
		प्रत्यागम salt;
	strlcpy(salt, "xx", परिमाण(salt));
	setpwent();
	जाव ((pw = getpwent()) != रिक्त) {
		जइ ((passwd = shadow_pw(pw)) == रिक्त)
			अनुवर्त;
		जइ (passwd[0] == '$' && (p = strrchr(passwd+1, '$')) != रिक्त) {
			typelen = p - passwd + 1;
			strlcpy(salt, passwd, MINIMUM(typelen, परिमाण(salt)));
			explicit_bzero(passwd, strlen(passwd));
			गच्छ out;
		}
	}
 out:
	endpwent();
	प्रत्यागम salt;
}

वर्ण *
xcrypt(ध्रुव वर्ण *password, ध्रुव वर्ण *salt)
{
	वर्ण *crypted;

	/*
	 * If we don't have a salt we are encrypting a fake password for
	 * for timing purposes.  Pick an appropriate salt.
	 */
	जइ (salt == रिक्त)
		salt = pick_salt();

#जइ defined(__hpux) && !defined(HAVE_SECUREWARE)
	जइ (iscomsec())
		crypted = bigcrypt(password, salt);
	अण्णहा
		crypted = crypt(password, salt);
# elif defined(HAVE_SECUREWARE)
	crypted = bigcrypt(password, salt);
# अण्णहा
	crypted = crypt(password, salt);
#endif

	प्रत्यागम crypted;
}

/*
 * Handle shadowed password systems in a cleaner way for portable
 * version.
 */

वर्ण *
shadow_pw(संरचना passwd *pw)
{
	वर्ण *pw_password = pw->pw_passwd;

# जइ defined(HAVE_SHADOW_H) && !defined(DISABLE_SHADOW)
	संरचना spwd *spw = getspnam(pw->pw_name);

	जइ (spw != रिक्त)
		pw_password = spw->sp_pwdp;
# endif

#ifdef USE_LIBIAF
	प्रत्यागम(get_iaf_password(pw));
#endif

# जइ defined(HAVE_GETPWANAM) && !defined(DISABLE_SHADOW)
	संरचना passwd_adjunct *spw;
	जइ (issecure() && (spw = getpwanam(pw->pw_name)) != रिक्त)
		pw_password = spw->pwa_passwd;
# elif defined(HAVE_SECUREWARE)
	संरचना pr_passwd *spw = getprpwnam(pw->pw_name);

	जइ (spw != रिक्त)
		pw_password = spw->ufld.fd_encrypt;
# endif

	प्रत्यागम pw_password;
}
