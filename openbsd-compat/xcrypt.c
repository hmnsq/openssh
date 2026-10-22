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

#അന്തര്ഭാവ "includes.h"

#അന്തര്ഭാവ <sys/types.h>
#അന്തര്ഭാവ <string.h>
#അന്തര്ഭാവ <unistd.h>
#അന്തര്ഭാവ <pwd.h>

# എങ്കിൽ defined(HAVE_CRYPT_H) && !defined(HAVE_SECUREWARE)
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

# എങ്കിൽ defined(HAVE_SHADOW_H) && !defined(DISABLE_SHADOW)
#  include <shadow.h>
# endif

# എങ്കിൽ defined(HAVE_GETPWANAM) && !defined(DISABLE_SHADOW)
#  include <sys/label.h>
#  include <sys/audit.h>
#  include <pwdadj.h>
# endif

# എങ്കിൽ defined(WITH_OPENSSL) && !defined(HAVE_CRYPT) && defined(HAVE_DES_CRYPT)
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
സ്ഥിതം സ്ഥിരം അക്ഷരം *
pick_salt(ശൂന്യം)
{
	ഘടന passwd *pw;
	അക്ഷരം *passwd, *p;
	size_t typelen;
	സ്ഥിതം അക്ഷരം salt[32];

	എങ്കിൽ (salt[0] != '\0')
		തിരികെ salt;
	strlcpy(salt, "xx", വലുപ്പം(salt));
	setpwent();
	ആകുമ്പോൾ ((pw = getpwent()) != ശൂന്യ) {
		എങ്കിൽ ((passwd = shadow_pw(pw)) == ശൂന്യ)
			തുടരുക;
		എങ്കിൽ (passwd[0] == '$' && (p = strrchr(passwd+1, '$')) != ശൂന്യ) {
			typelen = p - passwd + 1;
			strlcpy(salt, passwd, MINIMUM(typelen, വലുപ്പം(salt)));
			explicit_bzero(passwd, strlen(passwd));
			പോകുക out;
		}
	}
 out:
	endpwent();
	തിരികെ salt;
}

അക്ഷരം *
xcrypt(സ്ഥിരം അക്ഷരം *password, സ്ഥിരം അക്ഷരം *salt)
{
	അക്ഷരം *crypted;

	/*
	 * If we don't have a salt we are encrypting a fake password for
	 * for timing purposes.  Pick an appropriate salt.
	 */
	എങ്കിൽ (salt == ശൂന്യ)
		salt = pick_salt();

#എങ്കിൽ defined(__hpux) && !defined(HAVE_SECUREWARE)
	എങ്കിൽ (iscomsec())
		crypted = bigcrypt(password, salt);
	അല്ലെങ്കിൽ
		crypted = crypt(password, salt);
# elif defined(HAVE_SECUREWARE)
	crypted = bigcrypt(password, salt);
# അല്ലെങ്കിൽ
	crypted = crypt(password, salt);
#endif

	തിരികെ crypted;
}

/*
 * Handle shadowed password systems in a cleaner way for portable
 * version.
 */

അക്ഷരം *
shadow_pw(ഘടന passwd *pw)
{
	അക്ഷരം *pw_password = pw->pw_passwd;

# എങ്കിൽ defined(HAVE_SHADOW_H) && !defined(DISABLE_SHADOW)
	ഘടന spwd *spw = getspnam(pw->pw_name);

	എങ്കിൽ (spw != ശൂന്യ)
		pw_password = spw->sp_pwdp;
# endif

#ifdef USE_LIBIAF
	തിരികെ(get_iaf_password(pw));
#endif

# എങ്കിൽ defined(HAVE_GETPWANAM) && !defined(DISABLE_SHADOW)
	ഘടന passwd_adjunct *spw;
	എങ്കിൽ (issecure() && (spw = getpwanam(pw->pw_name)) != ശൂന്യ)
		pw_password = spw->pwa_passwd;
# elif defined(HAVE_SECUREWARE)
	ഘടന pr_passwd *spw = getprpwnam(pw->pw_name);

	എങ്കിൽ (spw != ശൂന്യ)
		pw_password = spw->ufld.fd_encrypt;
# endif

	തിരികെ pw_password;
}
