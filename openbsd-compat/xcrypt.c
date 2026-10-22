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

#અન્તર્ભાવ "includes.h"

#અન્તર્ભાવ <sys/types.h>
#અન્તર્ભાવ <string.h>
#અન્તર્ભાવ <unistd.h>
#અન્તર્ભાવ <pwd.h>

# જો defined(HAVE_CRYPT_H) && !defined(HAVE_SECUREWARE)
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

# જો defined(HAVE_SHADOW_H) && !defined(DISABLE_SHADOW)
#  include <shadow.h>
# endif

# જો defined(HAVE_GETPWANAM) && !defined(DISABLE_SHADOW)
#  include <sys/label.h>
#  include <sys/audit.h>
#  include <pwdadj.h>
# endif

# જો defined(WITH_OPENSSL) && !defined(HAVE_CRYPT) && defined(HAVE_DES_CRYPT)
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
સ્થિર અચલ અક્ષર *
pick_salt(શૂન્ય)
{
	સંરચના passwd *pw;
	અક્ષર *passwd, *p;
	size_t typelen;
	સ્થિર અક્ષર salt[32];

	જો (salt[0] != '\0')
		પાછા salt;
	strlcpy(salt, "xx", કદ(salt));
	setpwent();
	જ્યારે ((pw = getpwent()) != ખાલી) {
		જો ((passwd = shadow_pw(pw)) == ખાલી)
			ચાલુ;
		જો (passwd[0] == '$' && (p = strrchr(passwd+1, '$')) != ખાલી) {
			typelen = p - passwd + 1;
			strlcpy(salt, passwd, MINIMUM(typelen, કદ(salt)));
			explicit_bzero(passwd, strlen(passwd));
			જાઓ out;
		}
	}
 out:
	endpwent();
	પાછા salt;
}

અક્ષર *
xcrypt(અચલ અક્ષર *password, અચલ અક્ષર *salt)
{
	અક્ષર *crypted;

	/*
	 * If we don't have a salt we are encrypting a fake password for
	 * for timing purposes.  Pick an appropriate salt.
	 */
	જો (salt == ખાલી)
		salt = pick_salt();

#જો defined(__hpux) && !defined(HAVE_SECUREWARE)
	જો (iscomsec())
		crypted = bigcrypt(password, salt);
	નહીંતર
		crypted = crypt(password, salt);
# elif defined(HAVE_SECUREWARE)
	crypted = bigcrypt(password, salt);
# નહીંતર
	crypted = crypt(password, salt);
#endif

	પાછા crypted;
}

/*
 * Handle shadowed password systems in a cleaner way for portable
 * version.
 */

અક્ષર *
shadow_pw(સંરચના passwd *pw)
{
	અક્ષર *pw_password = pw->pw_passwd;

# જો defined(HAVE_SHADOW_H) && !defined(DISABLE_SHADOW)
	સંરચના spwd *spw = getspnam(pw->pw_name);

	જો (spw != ખાલી)
		pw_password = spw->sp_pwdp;
# endif

#ifdef USE_LIBIAF
	પાછા(get_iaf_password(pw));
#endif

# જો defined(HAVE_GETPWANAM) && !defined(DISABLE_SHADOW)
	સંરચના passwd_adjunct *spw;
	જો (issecure() && (spw = getpwanam(pw->pw_name)) != ખાલી)
		pw_password = spw->pwa_passwd;
# elif defined(HAVE_SECUREWARE)
	સંરચના pr_passwd *spw = getprpwnam(pw->pw_name);

	જો (spw != ખાલી)
		pw_password = spw->ufld.fd_encrypt;
# endif

	પાછા pw_password;
}
