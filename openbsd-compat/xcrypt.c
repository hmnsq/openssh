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

#অন্তর্ভাব "includes.h"

#অন্তর্ভাব <sys/types.h>
#অন্তর্ভাব <string.h>
#অন্তর্ভাব <unistd.h>
#অন্তর্ভাব <pwd.h>

# যদি defined(HAVE_CRYPT_H) && !defined(HAVE_SECUREWARE)
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

# যদি defined(HAVE_SHADOW_H) && !defined(DISABLE_SHADOW)
#  include <shadow.h>
# endif

# যদি defined(HAVE_GETPWANAM) && !defined(DISABLE_SHADOW)
#  include <sys/label.h>
#  include <sys/audit.h>
#  include <pwdadj.h>
# endif

# যদি defined(WITH_OPENSSL) && !defined(HAVE_CRYPT) && defined(HAVE_DES_CRYPT)
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
স্থির ধ্রুব বর্ণ *
pick_salt(শূন্য)
{
	সংরচনা passwd *pw;
	বর্ণ *passwd, *p;
	size_t typelen;
	স্থির বর্ণ salt[32];

	যদি (salt[0] != '\0')
		প্রত্যাগম salt;
	strlcpy(salt, "xx", পরিমাণ(salt));
	setpwent();
	যাবত্ ((pw = getpwent()) != রিক্ত) {
		যদি ((passwd = shadow_pw(pw)) == রিক্ত)
			অনুবর্ত;
		যদি (passwd[0] == '$' && (p = strrchr(passwd+1, '$')) != রিক্ত) {
			typelen = p - passwd + 1;
			strlcpy(salt, passwd, MINIMUM(typelen, পরিমাণ(salt)));
			explicit_bzero(passwd, strlen(passwd));
			গচ্ছ out;
		}
	}
 out:
	endpwent();
	প্রত্যাগম salt;
}

বর্ণ *
xcrypt(ধ্রুব বর্ণ *password, ধ্রুব বর্ণ *salt)
{
	বর্ণ *crypted;

	/*
	 * If we don't have a salt we are encrypting a fake password for
	 * for timing purposes.  Pick an appropriate salt.
	 */
	যদি (salt == রিক্ত)
		salt = pick_salt();

#যদি defined(__hpux) && !defined(HAVE_SECUREWARE)
	যদি (iscomsec())
		crypted = bigcrypt(password, salt);
	অন্যথা
		crypted = crypt(password, salt);
# elif defined(HAVE_SECUREWARE)
	crypted = bigcrypt(password, salt);
# অন্যথা
	crypted = crypt(password, salt);
#endif

	প্রত্যাগম crypted;
}

/*
 * Handle shadowed password systems in a cleaner way for portable
 * version.
 */

বর্ণ *
shadow_pw(সংরচনা passwd *pw)
{
	বর্ণ *pw_password = pw->pw_passwd;

# যদি defined(HAVE_SHADOW_H) && !defined(DISABLE_SHADOW)
	সংরচনা spwd *spw = getspnam(pw->pw_name);

	যদি (spw != রিক্ত)
		pw_password = spw->sp_pwdp;
# endif

#ifdef USE_LIBIAF
	প্রত্যাগম(get_iaf_password(pw));
#endif

# যদি defined(HAVE_GETPWANAM) && !defined(DISABLE_SHADOW)
	সংরচনা passwd_adjunct *spw;
	যদি (issecure() && (spw = getpwanam(pw->pw_name)) != রিক্ত)
		pw_password = spw->pwa_passwd;
# elif defined(HAVE_SECUREWARE)
	সংরচনা pr_passwd *spw = getprpwnam(pw->pw_name);

	যদি (spw != রিক্ত)
		pw_password = spw->ufld.fd_encrypt;
# endif

	প্রত্যাগম pw_password;
}
