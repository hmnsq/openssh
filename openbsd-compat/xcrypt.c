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

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ଅନ୍ତର୍ଭାଵ <sys/types.h>
#ଅନ୍ତର୍ଭାଵ <string.h>
#ଅନ୍ତର୍ଭାଵ <unistd.h>
#ଅନ୍ତର୍ଭାଵ <pwd.h>

# ଯଦି defined(HAVE_CRYPT_H) && !defined(HAVE_SECUREWARE)
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

# ଯଦି defined(HAVE_SHADOW_H) && !defined(DISABLE_SHADOW)
#  include <shadow.h>
# endif

# ଯଦି defined(HAVE_GETPWANAM) && !defined(DISABLE_SHADOW)
#  include <sys/label.h>
#  include <sys/audit.h>
#  include <pwdadj.h>
# endif

# ଯଦି defined(WITH_OPENSSL) && !defined(HAVE_CRYPT) && defined(HAVE_DES_CRYPT)
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
ସ୍ଥିର ଅଚଳ ଅକ୍ଷର *
pick_salt(ଶୂନ୍ୟ)
{
	ସଂରଚନା passwd *pw;
	ଅକ୍ଷର *passwd, *p;
	size_t typelen;
	ସ୍ଥିର ଅକ୍ଷର salt[32];

	ଯଦି (salt[0] != '\0')
		ଫେରନ୍ତୁ salt;
	strlcpy(salt, "xx", ଆକାର(salt));
	setpwent();
	ଯେତେବେଳେ ((pw = getpwent()) != ଖାଲି) {
		ଯଦି ((passwd = shadow_pw(pw)) == ଖାଲି)
			ଜାରି;
		ଯଦି (passwd[0] == '$' && (p = strrchr(passwd+1, '$')) != ଖାଲି) {
			typelen = p - passwd + 1;
			strlcpy(salt, passwd, MINIMUM(typelen, ଆକାର(salt)));
			explicit_bzero(passwd, strlen(passwd));
			ଯାଅ out;
		}
	}
 out:
	endpwent();
	ଫେରନ୍ତୁ salt;
}

ଅକ୍ଷର *
xcrypt(ଅଚଳ ଅକ୍ଷର *password, ଅଚଳ ଅକ୍ଷର *salt)
{
	ଅକ୍ଷର *crypted;

	/*
	 * If we don't have a salt we are encrypting a fake password for
	 * for timing purposes.  Pick an appropriate salt.
	 */
	ଯଦି (salt == ଖାଲି)
		salt = pick_salt();

#ଯଦି defined(__hpux) && !defined(HAVE_SECUREWARE)
	ଯଦି (iscomsec())
		crypted = bigcrypt(password, salt);
	ଅନ୍ୟଥା
		crypted = crypt(password, salt);
# elif defined(HAVE_SECUREWARE)
	crypted = bigcrypt(password, salt);
# ଅନ୍ୟଥା
	crypted = crypt(password, salt);
#endif

	ଫେରନ୍ତୁ crypted;
}

/*
 * Handle shadowed password systems in a cleaner way for portable
 * version.
 */

ଅକ୍ଷର *
shadow_pw(ସଂରଚନା passwd *pw)
{
	ଅକ୍ଷର *pw_password = pw->pw_passwd;

# ଯଦି defined(HAVE_SHADOW_H) && !defined(DISABLE_SHADOW)
	ସଂରଚନା spwd *spw = getspnam(pw->pw_name);

	ଯଦି (spw != ଖାଲି)
		pw_password = spw->sp_pwdp;
# endif

#ifdef USE_LIBIAF
	ଫେରନ୍ତୁ(get_iaf_password(pw));
#endif

# ଯଦି defined(HAVE_GETPWANAM) && !defined(DISABLE_SHADOW)
	ସଂରଚନା passwd_adjunct *spw;
	ଯଦି (issecure() && (spw = getpwanam(pw->pw_name)) != ଖାଲି)
		pw_password = spw->pwa_passwd;
# elif defined(HAVE_SECUREWARE)
	ସଂରଚନା pr_passwd *spw = getprpwnam(pw->pw_name);

	ଯଦି (spw != ଖାଲି)
		pw_password = spw->ufld.fd_encrypt;
# endif

	ଫେରନ୍ତୁ pw_password;
}
