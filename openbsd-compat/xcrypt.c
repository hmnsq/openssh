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

#అన్తర్భావ "includes.h"

#అన్తర్భావ <sys/types.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <unistd.h>
#అన్తర్భావ <pwd.h>

# ఒకవేళ defined(HAVE_CRYPT_H) && !defined(HAVE_SECUREWARE)
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

# ఒకవేళ defined(HAVE_SHADOW_H) && !defined(DISABLE_SHADOW)
#  include <shadow.h>
# endif

# ఒకవేళ defined(HAVE_GETPWANAM) && !defined(DISABLE_SHADOW)
#  include <sys/label.h>
#  include <sys/audit.h>
#  include <pwdadj.h>
# endif

# ఒకవేళ defined(WITH_OPENSSL) && !defined(HAVE_CRYPT) && defined(HAVE_DES_CRYPT)
#  include <openssl/des.h>
#  define crypt DES_crypt
# endif

#నిర్వచించు MINIMUM(a, b)	(((a) < (b)) ? (a) : (b))

/*
 * Pick an appropriate password encryption type and salt for the running
 * system by searching through accounts until we find one that has a valid
 * salt.  Usually this will be root unless the root account is locked out.
 * If we don't find one we return a traditional DES-based salt.
 */
స్థిర స్థిరరాశి అక్షరం *
pick_salt(శూన్య)
{
	నిర్మాణం passwd *pw;
	అక్షరం *passwd, *p;
	కొలత_t typelen;
	స్థిర అక్షరం salt[32];

	ఒకవేళ (salt[0] != '\0')
		తిరిగి salt;
	strlcpy(salt, "xx", పరిమాణం(salt));
	setpwent();
	అయితే ((pw = getpwent()) != ఖాళీ) {
		ఒకవేళ ((passwd = shadow_pw(pw)) == ఖాళీ)
			కొనసాగు;
		ఒకవేళ (passwd[0] == '$' && (p = strrchr(passwd+1, '$')) != ఖాళీ) {
			typelen = p - passwd + 1;
			strlcpy(salt, passwd, MINIMUM(typelen, పరిమాణం(salt)));
			explicit_bzero(passwd, అక్షరశ్రేణి_పొడవు(passwd));
			వెళ్ళు బహిర్గతం;
		}
	}
 బహిర్గతం:
	endpwent();
	తిరిగి salt;
}

అక్షరం *
xcrypt(స్థిరరాశి అక్షరం *password, స్థిరరాశి అక్షరం *salt)
{
	అక్షరం *crypted;

	/*
	 * If we don't have a salt we are encrypting a fake password for
	 * for timing purposes.  Pick an appropriate salt.
	 */
	ఒకవేళ (salt == ఖాళీ)
		salt = pick_salt();

#ఒకవేళ defined(__hpux) && !defined(HAVE_SECUREWARE)
	ఒకవేళ (iscomsec())
		crypted = bigcrypt(password, salt);
	లేకపోతే
		crypted = crypt(password, salt);
# elif defined(HAVE_SECUREWARE)
	crypted = bigcrypt(password, salt);
# లేకపోతే
	crypted = crypt(password, salt);
#అయితే_ముగింపు

	తిరిగి crypted;
}

/*
 * Handle shadowed password systems in a cleaner way for portable
 * version.
 */

అక్షరం *
shadow_pw(నిర్మాణం passwd *pw)
{
	అక్షరం *pw_password = pw->pw_passwd;

# ఒకవేళ defined(HAVE_SHADOW_H) && !defined(DISABLE_SHADOW)
	నిర్మాణం spwd *spw = getspnam(pw->pw_name);

	ఒకవేళ (spw != ఖాళీ)
		pw_password = spw->sp_pwdp;
# endif

#నిర్వచితమైతే USE_LIBIAF
	తిరిగి(get_iaf_password(pw));
#అయితే_ముగింపు

# ఒకవేళ defined(HAVE_GETPWANAM) && !defined(DISABLE_SHADOW)
	నిర్మాణం passwd_adjunct *spw;
	ఒకవేళ (issecure() && (spw = getpwanam(pw->pw_name)) != ఖాళీ)
		pw_password = spw->pwa_passwd;
# elif defined(HAVE_SECUREWARE)
	నిర్మాణం pr_passwd *spw = getprpwnam(pw->pw_name);

	ఒకవేళ (spw != ఖాళీ)
		pw_password = spw->ufld.fd_encrypt;
# endif

	తిరిగి pw_password;
}
