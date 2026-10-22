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

# ಆದರೆ defined(HAVE_CRYPT_H) && !defined(HAVE_SECUREWARE)
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

# ಆದರೆ defined(HAVE_SHADOW_H) && !defined(DISABLE_SHADOW)
#  include <shadow.h>
# endif

# ಆದರೆ defined(HAVE_GETPWANAM) && !defined(DISABLE_SHADOW)
#  include <sys/label.h>
#  include <sys/audit.h>
#  include <pwdadj.h>
# endif

# ಆದರೆ defined(WITH_OPENSSL) && !defined(HAVE_CRYPT) && defined(HAVE_DES_CRYPT)
#  include <openssl/des.h>
#  define crypt DES_crypt
# endif

#ವ್ಯಾಖ್ಯಾನಿಸು MINIMUM(a, b)	(((a) < (b)) ? (a) : (b))

/*
 * Pick an appropriate password encryption type and salt for the running
 * system by searching through accounts until we find one that has a valid
 * salt.  Usually this will be root unless the root account is locked out.
 * If we don't find one we return a traditional DES-based salt.
 */
ಸ್ಥಿರ ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *
pick_salt(ಶೂನ್ಯ)
{
	ರಚನೆ passwd *pw;
	ಅಕ್ಷರ *passwd, *p;
	ಗಾತ್ರ_t typelen;
	ಸ್ಥಿರ ಅಕ್ಷರ salt[32];

	ಆದರೆ (salt[0] != '\0')
		ಹಿಂತಿರುಗಿ salt;
	strlcpy(salt, "xx", ಗಾತ್ರ(salt));
	setpwent();
	ಆಗ ((pw = getpwent()) != ಖಾಲಿ) {
		ಆದರೆ ((passwd = shadow_pw(pw)) == ಖಾಲಿ)
			ಮುಂದುವರಿ;
		ಆದರೆ (passwd[0] == '$' && (p = strrchr(passwd+1, '$')) != ಖಾಲಿ) {
			typelen = p - passwd + 1;
			strlcpy(salt, passwd, MINIMUM(typelen, ಗಾತ್ರ(salt)));
			explicit_bzero(passwd, ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(passwd));
			ಹೋಗು ಹೊರಹೋಗು;
		}
	}
 ಹೊರಹೋಗು:
	endpwent();
	ಹಿಂತಿರುಗಿ salt;
}

ಅಕ್ಷರ *
xcrypt(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *password, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *salt)
{
	ಅಕ್ಷರ *crypted;

	/*
	 * If we don't have a salt we are encrypting a fake password for
	 * for timing purposes.  Pick an appropriate salt.
	 */
	ಆದರೆ (salt == ಖಾಲಿ)
		salt = pick_salt();

#ಆದರೆ defined(__hpux) && !defined(HAVE_SECUREWARE)
	ಆದರೆ (iscomsec())
		crypted = bigcrypt(password, salt);
	ಇಲ್ಲದಿದ್ದರೆ
		crypted = crypt(password, salt);
# elif defined(HAVE_SECUREWARE)
	crypted = bigcrypt(password, salt);
# ಇಲ್ಲದಿದ್ದರೆ
	crypted = crypt(password, salt);
#ಆದರೆ_ಅಂತ್ಯ

	ಹಿಂತಿರುಗಿ crypted;
}

/*
 * Handle shadowed password systems in a cleaner way for portable
 * version.
 */

ಅಕ್ಷರ *
shadow_pw(ರಚನೆ passwd *pw)
{
	ಅಕ್ಷರ *pw_password = pw->pw_passwd;

# ಆದರೆ defined(HAVE_SHADOW_H) && !defined(DISABLE_SHADOW)
	ರಚನೆ spwd *spw = getspnam(pw->pw_name);

	ಆದರೆ (spw != ಖಾಲಿ)
		pw_password = spw->sp_pwdp;
# endif

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ USE_LIBIAF
	ಹಿಂತಿರುಗಿ(get_iaf_password(pw));
#ಆದರೆ_ಅಂತ್ಯ

# ಆದರೆ defined(HAVE_GETPWANAM) && !defined(DISABLE_SHADOW)
	ರಚನೆ passwd_adjunct *spw;
	ಆದರೆ (issecure() && (spw = getpwanam(pw->pw_name)) != ಖಾಲಿ)
		pw_password = spw->pwa_passwd;
# elif defined(HAVE_SECUREWARE)
	ರಚನೆ pr_passwd *spw = getprpwnam(pw->pw_name);

	ಆದರೆ (spw != ಖಾಲಿ)
		pw_password = spw->ufld.fd_encrypt;
# endif

	ಹಿಂತಿರುಗಿ pw_password;
}
