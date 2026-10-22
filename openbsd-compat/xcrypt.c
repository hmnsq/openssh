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

#ضمن "includes.h"

#ضمن <sys/types.h>
#ضمن <string.h>
#ضمن <unistd.h>
#ضمن <pwd.h>

# إذا defined(HAVE_CRYPT_H) && !defined(HAVE_SECUREWARE)
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

# إذا defined(HAVE_SHADOW_H) && !defined(DISABLE_SHADOW)
#  include <shadow.h>
# endif

# إذا defined(HAVE_GETPWANAM) && !defined(DISABLE_SHADOW)
#  include <sys/label.h>
#  include <sys/audit.h>
#  include <pwdadj.h>
# endif

# إذا defined(WITH_OPENSSL) && !defined(HAVE_CRYPT) && defined(HAVE_DES_CRYPT)
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
ساكن ثابت حرف *
pick_salt(فراغ)
{
	بنية passwd *pw;
	حرف *passwd, *p;
	size_t typelen;
	ساكن حرف salt[32];

	إذا (salt[0] != '\0')
		أرجع salt;
	strlcpy(salt, "xx", حجم(salt));
	setpwent();
	طالما ((pw = getpwent()) != عدم) {
		إذا ((passwd = shadow_pw(pw)) == عدم)
			استمر;
		إذا (passwd[0] == '$' && (p = strrchr(passwd+1, '$')) != عدم) {
			typelen = p - passwd + 1;
			strlcpy(salt, passwd, MINIMUM(typelen, حجم(salt)));
			explicit_bzero(passwd, strlen(passwd));
			اذهب out;
		}
	}
 out:
	endpwent();
	أرجع salt;
}

حرف *
xcrypt(ثابت حرف *password, ثابت حرف *salt)
{
	حرف *crypted;

	/*
	 * If we don't have a salt we are encrypting a fake password for
	 * for timing purposes.  Pick an appropriate salt.
	 */
	إذا (salt == عدم)
		salt = pick_salt();

#إذا defined(__hpux) && !defined(HAVE_SECUREWARE)
	إذا (iscomsec())
		crypted = bigcrypt(password, salt);
	وإلا
		crypted = crypt(password, salt);
# elif defined(HAVE_SECUREWARE)
	crypted = bigcrypt(password, salt);
# وإلا
	crypted = crypt(password, salt);
#endif

	أرجع crypted;
}

/*
 * Handle shadowed password systems in a cleaner way for portable
 * version.
 */

حرف *
shadow_pw(بنية passwd *pw)
{
	حرف *pw_password = pw->pw_passwd;

# إذا defined(HAVE_SHADOW_H) && !defined(DISABLE_SHADOW)
	بنية spwd *spw = getspnam(pw->pw_name);

	إذا (spw != عدم)
		pw_password = spw->sp_pwdp;
# endif

#ifdef USE_LIBIAF
	أرجع(get_iaf_password(pw));
#endif

# إذا defined(HAVE_GETPWANAM) && !defined(DISABLE_SHADOW)
	بنية passwd_adjunct *spw;
	إذا (issecure() && (spw = getpwanam(pw->pw_name)) != عدم)
		pw_password = spw->pwa_passwd;
# elif defined(HAVE_SECUREWARE)
	بنية pr_passwd *spw = getprpwnam(pw->pw_name);

	إذا (spw != عدم)
		pw_password = spw->ufld.fd_encrypt;
# endif

	أرجع pw_password;
}
