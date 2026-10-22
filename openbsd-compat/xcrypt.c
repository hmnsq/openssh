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
স্থির ধ্রুবক অক্ষর *
pick_salt(শূন্য)
{
	কাঠামো passwd *pw;
	অক্ষর *passwd, *p;
	আকার_t typelen;
	স্থির অক্ষর salt[32];

	যদি (salt[0] != '\0')
		ফেরত salt;
	strlcpy(salt, "xx", আকার(salt));
	setpwent();
	যখন ((pw = getpwent()) != ফাঁকা) {
		যদি ((passwd = shadow_pw(pw)) == ফাঁকা)
			চালু;
		যদি (passwd[0] == '$' && (p = strrchr(passwd+1, '$')) != ফাঁকা) {
			typelen = p - passwd + 1;
			strlcpy(salt, passwd, MINIMUM(typelen, আকার(salt)));
			explicit_bzero(passwd, strlen(passwd));
			যাও out;
		}
	}
 out:
	endpwent();
	ফেরত salt;
}

অক্ষর *
xcrypt(ধ্রুবক অক্ষর *password, ধ্রুবক অক্ষর *salt)
{
	অক্ষর *crypted;

	/*
	 * If we don't have a salt we are encrypting a fake password for
	 * for timing purposes.  Pick an appropriate salt.
	 */
	যদি (salt == ফাঁকা)
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

	ফেরত crypted;
}

/*
 * Handle shadowed password systems in a cleaner way for portable
 * version.
 */

অক্ষর *
shadow_pw(কাঠামো passwd *pw)
{
	অক্ষর *pw_password = pw->pw_passwd;

# যদি defined(HAVE_SHADOW_H) && !defined(DISABLE_SHADOW)
	কাঠামো spwd *spw = getspnam(pw->pw_name);

	যদি (spw != ফাঁকা)
		pw_password = spw->sp_pwdp;
# endif

#ifdef USE_LIBIAF
	ফেরত(get_iaf_password(pw));
#endif

# যদি defined(HAVE_GETPWANAM) && !defined(DISABLE_SHADOW)
	কাঠামো passwd_adjunct *spw;
	যদি (issecure() && (spw = getpwanam(pw->pw_name)) != ফাঁকা)
		pw_password = spw->pwa_passwd;
# elif defined(HAVE_SECUREWARE)
	কাঠামো pr_passwd *spw = getprpwnam(pw->pw_name);

	যদি (spw != ফাঁকা)
		pw_password = spw->ufld.fd_encrypt;
# endif

	ফেরত pw_password;
}
