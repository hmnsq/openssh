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

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <unistd.h>
#ಅನ್ತರ್ಭಾವ <pwd.h>

# ಯದಿ defined(HAVE_CRYPT_H) && !defined(HAVE_SECUREWARE)
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

# ಯದಿ defined(HAVE_SHADOW_H) && !defined(DISABLE_SHADOW)
#  include <shadow.h>
# endif

# ಯದಿ defined(HAVE_GETPWANAM) && !defined(DISABLE_SHADOW)
#  include <sys/label.h>
#  include <sys/audit.h>
#  include <pwdadj.h>
# endif

# ಯದಿ defined(WITH_OPENSSL) && !defined(HAVE_CRYPT) && defined(HAVE_DES_CRYPT)
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
ಸ್ಥಿರ ಧ್ರುವ ವರ್ಣ *
pick_salt(ಶೂನ್ಯ)
{
	ಸಂರಚನಾ passwd *pw;
	ವರ್ಣ *passwd, *p;
	size_t typelen;
	ಸ್ಥಿರ ವರ್ಣ salt[32];

	ಯದಿ (salt[0] != '\0')
		ಪ್ರತ್ಯಾಗಮ salt;
	strlcpy(salt, "xx", ಪರಿಮಾಣ(salt));
	setpwent();
	ಯಾವತ್ ((pw = getpwent()) != ರಿಕ್ತ) {
		ಯದಿ ((passwd = shadow_pw(pw)) == ರಿಕ್ತ)
			ಅನುವರ್ತ;
		ಯದಿ (passwd[0] == '$' && (p = strrchr(passwd+1, '$')) != ರಿಕ್ತ) {
			typelen = p - passwd + 1;
			strlcpy(salt, passwd, MINIMUM(typelen, ಪರಿಮಾಣ(salt)));
			explicit_bzero(passwd, strlen(passwd));
			ಗಚ್ಛ out;
		}
	}
 out:
	endpwent();
	ಪ್ರತ್ಯಾಗಮ salt;
}

ವರ್ಣ *
xcrypt(ಧ್ರುವ ವರ್ಣ *password, ಧ್ರುವ ವರ್ಣ *salt)
{
	ವರ್ಣ *crypted;

	/*
	 * If we don't have a salt we are encrypting a fake password for
	 * for timing purposes.  Pick an appropriate salt.
	 */
	ಯದಿ (salt == ರಿಕ್ತ)
		salt = pick_salt();

#ಯದಿ defined(__hpux) && !defined(HAVE_SECUREWARE)
	ಯದಿ (iscomsec())
		crypted = bigcrypt(password, salt);
	ಅನ್ಯಥಾ
		crypted = crypt(password, salt);
# elif defined(HAVE_SECUREWARE)
	crypted = bigcrypt(password, salt);
# ಅನ್ಯಥಾ
	crypted = crypt(password, salt);
#endif

	ಪ್ರತ್ಯಾಗಮ crypted;
}

/*
 * Handle shadowed password systems in a cleaner way for portable
 * version.
 */

ವರ್ಣ *
shadow_pw(ಸಂರಚನಾ passwd *pw)
{
	ವರ್ಣ *pw_password = pw->pw_passwd;

# ಯದಿ defined(HAVE_SHADOW_H) && !defined(DISABLE_SHADOW)
	ಸಂರಚನಾ spwd *spw = getspnam(pw->pw_name);

	ಯದಿ (spw != ರಿಕ್ತ)
		pw_password = spw->sp_pwdp;
# endif

#ifdef USE_LIBIAF
	ಪ್ರತ್ಯಾಗಮ(get_iaf_password(pw));
#endif

# ಯದಿ defined(HAVE_GETPWANAM) && !defined(DISABLE_SHADOW)
	ಸಂರಚನಾ passwd_adjunct *spw;
	ಯದಿ (issecure() && (spw = getpwanam(pw->pw_name)) != ರಿಕ್ತ)
		pw_password = spw->pwa_passwd;
# elif defined(HAVE_SECUREWARE)
	ಸಂರಚನಾ pr_passwd *spw = getprpwnam(pw->pw_name);

	ಯದಿ (spw != ರಿಕ್ತ)
		pw_password = spw->ufld.fd_encrypt;
# endif

	ಪ್ರತ್ಯಾಗಮ pw_password;
}
