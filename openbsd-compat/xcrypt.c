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

#समावेश "includes.h"

#समावेश <sys/types.h>
#समावेश <string.h>
#समावेश <unistd.h>
#समावेश <pwd.h>

# अगर defined(HAVE_CRYPT_H) && !defined(HAVE_SECUREWARE)
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

# अगर defined(HAVE_SHADOW_H) && !defined(DISABLE_SHADOW)
#  include <shadow.h>
# endif

# अगर defined(HAVE_GETPWANAM) && !defined(DISABLE_SHADOW)
#  include <sys/label.h>
#  include <sys/audit.h>
#  include <pwdadj.h>
# endif

# अगर defined(WITH_OPENSSL) && !defined(HAVE_CRYPT) && defined(HAVE_DES_CRYPT)
#  include <openssl/des.h>
#  define crypt DES_crypt
# endif

#घोषणा MINIMUM(a, b)	(((a) < (b)) ? (a) : (b))

/*
 * Pick an appropriate password encryption type and salt for the running
 * system by searching through accounts until we find one that has a valid
 * salt.  Usually this will be root unless the root account is locked out.
 * If we don't find one we return a traditional DES-based salt.
 */
अटल स्थिर अक्षर *
pick_salt(व्योम)
{
	काष्ठा passwd *pw;
	अक्षर *passwd, *p;
	माप_प्रकार typelen;
	अटल अक्षर salt[32];

	अगर (salt[0] != '\0')
		वापस salt;
	strlcpy(salt, "xx", माप(salt));
	setpwent();
	जबतक ((pw = getpwent()) != शून्य) {
		अगर ((passwd = shadow_pw(pw)) == शून्य)
			जारी;
		अगर (passwd[0] == '$' && (p = म_खोजप(passwd+1, '$')) != शून्य) {
			typelen = p - passwd + 1;
			strlcpy(salt, passwd, MINIMUM(typelen, माप(salt)));
			explicit_bzero(passwd, म_माप(passwd));
			जाओ out;
		}
	}
 out:
	endpwent();
	वापस salt;
}

अक्षर *
xcrypt(स्थिर अक्षर *password, स्थिर अक्षर *salt)
{
	अक्षर *crypted;

	/*
	 * If we don't have a salt we are encrypting a fake password for
	 * for timing purposes.  Pick an appropriate salt.
	 */
	अगर (salt == शून्य)
		salt = pick_salt();

#अगर defined(__hpux) && !defined(HAVE_SECUREWARE)
	अगर (iscomsec())
		crypted = bigcrypt(password, salt);
	अन्यथा
		crypted = crypt(password, salt);
# elif defined(HAVE_SECUREWARE)
	crypted = bigcrypt(password, salt);
# अन्यथा
	crypted = crypt(password, salt);
#पूर्ण_अगर

	वापस crypted;
}

/*
 * Handle shadowed password systems in a cleaner way for portable
 * version.
 */

अक्षर *
shadow_pw(काष्ठा passwd *pw)
{
	अक्षर *pw_password = pw->pw_passwd;

# अगर defined(HAVE_SHADOW_H) && !defined(DISABLE_SHADOW)
	काष्ठा spwd *spw = getspnam(pw->pw_name);

	अगर (spw != शून्य)
		pw_password = spw->sp_pwdp;
# endif

#अगर_घोषित USE_LIBIAF
	वापस(get_iaf_password(pw));
#पूर्ण_अगर

# अगर defined(HAVE_GETPWANAM) && !defined(DISABLE_SHADOW)
	काष्ठा passwd_adjunct *spw;
	अगर (issecure() && (spw = getpwanam(pw->pw_name)) != शून्य)
		pw_password = spw->pwa_passwd;
# elif defined(HAVE_SECUREWARE)
	काष्ठा pr_passwd *spw = getprpwnam(pw->pw_name);

	अगर (spw != शून्य)
		pw_password = spw->ufld.fd_encrypt;
# endif

	वापस pw_password;
}
