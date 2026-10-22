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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <unistd.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <pwd.h>

# ਜੇ defined(HAVE_CRYPT_H) && !defined(HAVE_SECUREWARE)
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

# ਜੇ defined(HAVE_SHADOW_H) && !defined(DISABLE_SHADOW)
#  include <shadow.h>
# endif

# ਜੇ defined(HAVE_GETPWANAM) && !defined(DISABLE_SHADOW)
#  include <sys/label.h>
#  include <sys/audit.h>
#  include <pwdadj.h>
# endif

# ਜੇ defined(WITH_OPENSSL) && !defined(HAVE_CRYPT) && defined(HAVE_DES_CRYPT)
#  include <openssl/des.h>
#  define crypt DES_crypt
# endif

#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ MINIMUM(a, b)	(((a) < (b)) ? (a) : (b))

/*
 * Pick an appropriate password encryption type and salt for the running
 * system by searching through accounts until we find one that has a valid
 * salt.  Usually this will be root unless the root account is locked out.
 * If we don't find one we return a traditional DES-based salt.
 */
ਸਥਿਰ ਅਚਲ ਅੱਖਰ *
pick_salt(ਖਾਲੀ)
{
	ਬਣਤਰ passwd *pw;
	ਅੱਖਰ *passwd, *p;
	ਮਾਪ_t typelen;
	ਸਥਿਰ ਅੱਖਰ salt[32];

	ਜੇ (salt[0] != '\0')
		ਵਾਪਸ salt;
	strlcpy(salt, "xx", ਆਕਾਰ(salt));
	setpwent();
	ਜਦੋਂ ((pw = getpwent()) != ਨਿਰਾ) {
		ਜੇ ((passwd = shadow_pw(pw)) == ਨਿਰਾ)
			ਜਾਰੀ;
		ਜੇ (passwd[0] == '$' && (p = strrchr(passwd+1, '$')) != ਨਿਰਾ) {
			typelen = p - passwd + 1;
			strlcpy(salt, passwd, MINIMUM(typelen, ਆਕਾਰ(salt)));
			explicit_bzero(passwd, ਲੜੀ_ਲੰਬਾਈ(passwd));
			ਜਾਓ ਬਾਹਰਲਾ;
		}
	}
 ਬਾਹਰਲਾ:
	endpwent();
	ਵਾਪਸ salt;
}

ਅੱਖਰ *
xcrypt(ਅਚਲ ਅੱਖਰ *password, ਅਚਲ ਅੱਖਰ *salt)
{
	ਅੱਖਰ *crypted;

	/*
	 * If we don't have a salt we are encrypting a fake password for
	 * for timing purposes.  Pick an appropriate salt.
	 */
	ਜੇ (salt == ਨਿਰਾ)
		salt = pick_salt();

#ਜੇ defined(__hpux) && !defined(HAVE_SECUREWARE)
	ਜੇ (iscomsec())
		crypted = bigcrypt(password, salt);
	ਨਹੀਂਤਾਂ
		crypted = crypt(password, salt);
# elif defined(HAVE_SECUREWARE)
	crypted = bigcrypt(password, salt);
# ਨਹੀਂਤਾਂ
	crypted = crypt(password, salt);
#ਜੇ_ਅੰਤ

	ਵਾਪਸ crypted;
}

/*
 * Handle shadowed password systems in a cleaner way for portable
 * version.
 */

ਅੱਖਰ *
shadow_pw(ਬਣਤਰ passwd *pw)
{
	ਅੱਖਰ *pw_password = pw->pw_passwd;

# ਜੇ defined(HAVE_SHADOW_H) && !defined(DISABLE_SHADOW)
	ਬਣਤਰ spwd *spw = getspnam(pw->pw_name);

	ਜੇ (spw != ਨਿਰਾ)
		pw_password = spw->sp_pwdp;
# endif

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ USE_LIBIAF
	ਵਾਪਸ(get_iaf_password(pw));
#ਜੇ_ਅੰਤ

# ਜੇ defined(HAVE_GETPWANAM) && !defined(DISABLE_SHADOW)
	ਬਣਤਰ passwd_adjunct *spw;
	ਜੇ (issecure() && (spw = getpwanam(pw->pw_name)) != ਨਿਰਾ)
		pw_password = spw->pwa_passwd;
# elif defined(HAVE_SECUREWARE)
	ਬਣਤਰ pr_passwd *spw = getprpwnam(pw->pw_name);

	ਜੇ (spw != ਨਿਰਾ)
		pw_password = spw->ufld.fd_encrypt;
# endif

	ਵਾਪਸ pw_password;
}
