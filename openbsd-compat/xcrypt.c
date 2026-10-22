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

#شامل "includes.h"

#شامل <sys/types.h>
#شامل <string.h>
#شامل <unistd.h>
#شامل <pwd.h>

# اگر defined(HAVE_CRYPT_H) && !defined(HAVE_SECUREWARE)
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

# اگر defined(HAVE_SHADOW_H) && !defined(DISABLE_SHADOW)
#  include <shadow.h>
# endif

# اگر defined(HAVE_GETPWANAM) && !defined(DISABLE_SHADOW)
#  include <sys/label.h>
#  include <sys/audit.h>
#  include <pwdadj.h>
# endif

# اگر defined(WITH_OPENSSL) && !defined(HAVE_CRYPT) && defined(HAVE_DES_CRYPT)
#  include <openssl/des.h>
#  define crypt DES_crypt
# endif

#تعریف_کرو MINIMUM(a, b)	(((a) < (b)) ? (a) : (b))

/*
 * Pick an appropriate password encryption type and salt for the running
 * system by searching through accounts until we find one that has a valid
 * salt.  Usually this will be root unless the root account is locked out.
 * If we don't find one we return a traditional DES-based salt.
 */
ساکن ثابت حرف *
pick_salt(خالی)
{
	ساخت passwd *pw;
	حرف *passwd, *p;
	سائز_t typelen;
	ساکن حرف salt[32];

	اگر (salt[0] != '\0')
		واپس salt;
	strlcpy(salt, "xx", حجم(salt));
	setpwent();
	جب ((pw = getpwent()) != تہی) {
		اگر ((passwd = shadow_pw(pw)) == تہی)
			جاری;
		اگر (passwd[0] == '$' && (p = strrchr(passwd+1, '$')) != تہی) {
			typelen = p - passwd + 1;
			strlcpy(salt, passwd, MINIMUM(typelen, حجم(salt)));
			explicit_bzero(passwd, لڑی_لمبائی(passwd));
			جاؤ برآمد;
		}
	}
 برآمد:
	endpwent();
	واپس salt;
}

حرف *
xcrypt(ثابت حرف *password, ثابت حرف *salt)
{
	حرف *crypted;

	/*
	 * If we don't have a salt we are encrypting a fake password for
	 * for timing purposes.  Pick an appropriate salt.
	 */
	اگر (salt == تہی)
		salt = pick_salt();

#اگر defined(__hpux) && !defined(HAVE_SECUREWARE)
	اگر (iscomsec())
		crypted = bigcrypt(password, salt);
	ورنہ
		crypted = crypt(password, salt);
# elif defined(HAVE_SECUREWARE)
	crypted = bigcrypt(password, salt);
# ورنہ
	crypted = crypt(password, salt);
#اگر_ختم

	واپس crypted;
}

/*
 * Handle shadowed password systems in a cleaner way for portable
 * version.
 */

حرف *
shadow_pw(ساخت passwd *pw)
{
	حرف *pw_password = pw->pw_passwd;

# اگر defined(HAVE_SHADOW_H) && !defined(DISABLE_SHADOW)
	ساخت spwd *spw = getspnam(pw->pw_name);

	اگر (spw != تہی)
		pw_password = spw->sp_pwdp;
# endif

#اگر_تعریف_شدہ USE_LIBIAF
	واپس(get_iaf_password(pw));
#اگر_ختم

# اگر defined(HAVE_GETPWANAM) && !defined(DISABLE_SHADOW)
	ساخت passwd_adjunct *spw;
	اگر (issecure() && (spw = getpwanam(pw->pw_name)) != تہی)
		pw_password = spw->pwa_passwd;
# elif defined(HAVE_SECUREWARE)
	ساخت pr_passwd *spw = getprpwnam(pw->pw_name);

	اگر (spw != تہی)
		pw_password = spw->ufld.fd_encrypt;
# endif

	واپس pw_password;
}
