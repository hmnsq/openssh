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

# जर defined(HAVE_CRYPT_H) && !defined(HAVE_SECUREWARE)
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

# जर defined(HAVE_SHADOW_H) && !defined(DISABLE_SHADOW)
#  include <shadow.h>
# endif

# जर defined(HAVE_GETPWANAM) && !defined(DISABLE_SHADOW)
#  include <sys/label.h>
#  include <sys/audit.h>
#  include <pwdadj.h>
# endif

# जर defined(WITH_OPENSSL) && !defined(HAVE_CRYPT) && defined(HAVE_DES_CRYPT)
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
स्थिर स्थिरांक अक्षर *
pick_salt(शून्य)
{
	संरचना passwd *pw;
	अक्षर *passwd, *p;
	माप_प्रकार typelen;
	स्थिर अक्षर salt[32];

	जर (salt[0] != '\0')
		परत salt;
	strlcpy(salt, "xx", आकार(salt));
	setpwent();
	पर्यंत ((pw = getpwent()) != रिक्त) {
		जर ((passwd = shadow_pw(pw)) == रिक्त)
			सुरूठेवा;
		जर (passwd[0] == '$' && (p = म_खोजप(passwd+1, '$')) != रिक्त) {
			typelen = p - passwd + 1;
			strlcpy(salt, passwd, MINIMUM(typelen, आकार(salt)));
			explicit_bzero(passwd, म_माप(passwd));
			जा out;
		}
	}
 out:
	endpwent();
	परत salt;
}

अक्षर *
xcrypt(स्थिरांक अक्षर *password, स्थिरांक अक्षर *salt)
{
	अक्षर *crypted;

	/*
	 * If we don't have a salt we are encrypting a fake password for
	 * for timing purposes.  Pick an appropriate salt.
	 */
	जर (salt == रिक्त)
		salt = pick_salt();

#जर defined(__hpux) && !defined(HAVE_SECUREWARE)
	जर (iscomsec())
		crypted = bigcrypt(password, salt);
	अन्यथा
		crypted = crypt(password, salt);
# elif defined(HAVE_SECUREWARE)
	crypted = bigcrypt(password, salt);
# अन्यथा
	crypted = crypt(password, salt);
#endif

	परत crypted;
}

/*
 * Handle shadowed password systems in a cleaner way for portable
 * version.
 */

अक्षर *
shadow_pw(संरचना passwd *pw)
{
	अक्षर *pw_password = pw->pw_passwd;

# जर defined(HAVE_SHADOW_H) && !defined(DISABLE_SHADOW)
	संरचना spwd *spw = getspnam(pw->pw_name);

	जर (spw != रिक्त)
		pw_password = spw->sp_pwdp;
# endif

#ifdef USE_LIBIAF
	परत(get_iaf_password(pw));
#endif

# जर defined(HAVE_GETPWANAM) && !defined(DISABLE_SHADOW)
	संरचना passwd_adjunct *spw;
	जर (issecure() && (spw = getpwanam(pw->pw_name)) != रिक्त)
		pw_password = spw->pwa_passwd;
# elif defined(HAVE_SECUREWARE)
	संरचना pr_passwd *spw = getprpwnam(pw->pw_name);

	जर (spw != रिक्त)
		pw_password = spw->ufld.fd_encrypt;
# endif

	परत pw_password;
}
