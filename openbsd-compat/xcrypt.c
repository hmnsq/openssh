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

#அந்தர்பாவ "includes.h"

#அந்தர்பாவ <sys/types.h>
#அந்தர்பாவ <string.h>
#அந்தர்பாவ <unistd.h>
#அந்தர்பாவ <pwd.h>

# எனில் defined(HAVE_CRYPT_H) && !defined(HAVE_SECUREWARE)
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

# எனில் defined(HAVE_SHADOW_H) && !defined(DISABLE_SHADOW)
#  include <shadow.h>
# endif

# எனில் defined(HAVE_GETPWANAM) && !defined(DISABLE_SHADOW)
#  include <sys/label.h>
#  include <sys/audit.h>
#  include <pwdadj.h>
# endif

# எனில் defined(WITH_OPENSSL) && !defined(HAVE_CRYPT) && defined(HAVE_DES_CRYPT)
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
நிலையான மாறிலி எழுத்து *
pick_salt(வெறுமை)
{
	கட்டமைப்பு passwd *pw;
	எழுத்து *passwd, *p;
	size_t typelen;
	நிலையான எழுத்து salt[32];

	எனில் (salt[0] != '\0')
		திரும்பு salt;
	strlcpy(salt, "xx", அளவு(salt));
	setpwent();
	போது ((pw = getpwent()) != வெற்று) {
		எனில் ((passwd = shadow_pw(pw)) == வெற்று)
			தொடர்;
		எனில் (passwd[0] == '$' && (p = strrchr(passwd+1, '$')) != வெற்று) {
			typelen = p - passwd + 1;
			strlcpy(salt, passwd, MINIMUM(typelen, அளவு(salt)));
			explicit_bzero(passwd, strlen(passwd));
			செல் out;
		}
	}
 out:
	endpwent();
	திரும்பு salt;
}

எழுத்து *
xcrypt(மாறிலி எழுத்து *password, மாறிலி எழுத்து *salt)
{
	எழுத்து *crypted;

	/*
	 * If we don't have a salt we are encrypting a fake password for
	 * for timing purposes.  Pick an appropriate salt.
	 */
	எனில் (salt == வெற்று)
		salt = pick_salt();

#எனில் defined(__hpux) && !defined(HAVE_SECUREWARE)
	எனில் (iscomsec())
		crypted = bigcrypt(password, salt);
	இல்லையெனில்
		crypted = crypt(password, salt);
# elif defined(HAVE_SECUREWARE)
	crypted = bigcrypt(password, salt);
# இல்லையெனில்
	crypted = crypt(password, salt);
#endif

	திரும்பு crypted;
}

/*
 * Handle shadowed password systems in a cleaner way for portable
 * version.
 */

எழுத்து *
shadow_pw(கட்டமைப்பு passwd *pw)
{
	எழுத்து *pw_password = pw->pw_passwd;

# எனில் defined(HAVE_SHADOW_H) && !defined(DISABLE_SHADOW)
	கட்டமைப்பு spwd *spw = getspnam(pw->pw_name);

	எனில் (spw != வெற்று)
		pw_password = spw->sp_pwdp;
# endif

#ifdef USE_LIBIAF
	திரும்பு(get_iaf_password(pw));
#endif

# எனில் defined(HAVE_GETPWANAM) && !defined(DISABLE_SHADOW)
	கட்டமைப்பு passwd_adjunct *spw;
	எனில் (issecure() && (spw = getpwanam(pw->pw_name)) != வெற்று)
		pw_password = spw->pwa_passwd;
# elif defined(HAVE_SECUREWARE)
	கட்டமைப்பு pr_passwd *spw = getprpwnam(pw->pw_name);

	எனில் (spw != வெற்று)
		pw_password = spw->ufld.fd_encrypt;
# endif

	திரும்பு pw_password;
}
