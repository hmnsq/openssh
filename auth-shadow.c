/*
 * Copyright (c) 2004 Darren Tucker.  All rights reserved.
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

#अन्तर्भाव "includes.h"

#यदि defined(USE_SHADOW) && defined(HAS_SHADOW_EXPIRE)
#अन्तर्भाव <shadow.h>
#अन्तर्भाव <stdarg.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <time.h>

#अन्तर्भाव "hostfile.h"
#अन्तर्भाव "auth.h"
#अन्तर्भाव "sshbuf.h"
#अन्तर्भाव "ssherr.h"
#अन्तर्भाव "log.h"

#यदि_परिभाषितम् DAY
# undef DAY
#यदि_अन्तः
#परिभाषय DAY	(24L * 60 * 60) /* 1 day in seconds */

बाह्य संरचना sshbuf *loginmsg;

/*
 * For the account and password expiration functions, we assume the expiry
 * occurs the day after the day specified.
 */

/*
 * Check if specified account is expired.  Returns 1 if account is expired,
 * 0 otherwise.
 */
पूर्णाङ्क
auth_shadow_acctexpired(संरचना spwd *spw)
{
	time_t today;
	दीर्घ दीर्घ daysleft;
	पूर्णाङ्क r;

	today = time(रिक्त) / DAY;
	daysleft = spw->sp_expire - today;
	debug3("%s: today %lld sp_expire %lld days left %lld", __func__,
	    (दीर्घ दीर्घ)today, (दीर्घ दीर्घ)spw->sp_expire, daysleft);

	यदि (spw->sp_expire == -1) {
		debug3("account expiration disabled");
	} अन्यथा यदि (daysleft < 0) {
		logit("Account %.100s has expired", spw->sp_namp);
		प्रत्यागम 1;
	} अन्यथा यदि (daysleft <= spw->sp_warn) {
		debug3("account will expire in %lld days", daysleft);
		यदि ((r = sshbuf_putf(loginmsg, 
		    "Your account will expire in %lld day%s.\n", daysleft,
		    daysleft == 1 ? "" : "s")) != 0)
			fatal_fr(r, "buffer error");
	}

	प्रत्यागम 0;
}

/*
 * Checks password expiry for platforms that use shadow passwd files.
 * Returns: 1 = password expired, 0 = password not expired
 */
पूर्णाङ्क
auth_shadow_pwexpired(Authctxt *ctxt)
{
	संरचना spwd *spw = रिक्त;
	ध्रुव वर्ण *user = ctxt->pw->pw_name;
	time_t today;
	पूर्णाङ्क r, daysleft, disabled = 0;

	यदि ((spw = getspnam((वर्ण *)user)) == रिक्त) {
		error("Could not get shadow information for %.100s", user);
		प्रत्यागम 0;
	}

	today = time(रिक्त) / DAY;
	debug3_f("today %lld sp_lstchg %lld sp_max %lld", (दीर्घ दीर्घ)today,
	    (दीर्घ दीर्घ)spw->sp_lstchg, (दीर्घ दीर्घ)spw->sp_max);

#यदि defined(__hpux) && !defined(HAVE_SECUREWARE)
	यदि (iscomsec()) {
		संरचना pr_passwd *pr;

		pr = getprpwnam((वर्ण *)user);

		/* Test for Trusted Mode expiry disabled */
		यदि (pr != रिक्त && pr->ufld.fd_min == 0 &&
		    pr->ufld.fd_lifetime == 0 && pr->ufld.fd_expire == 0 &&
		    pr->ufld.fd_pw_expire_warning == 0 &&
		    pr->ufld.fd_schange != 0)
			disabled = 1;
	}
#यदि_अन्तः

	/* TODO: check sp_inact */
	daysleft = spw->sp_lstchg + spw->sp_max - today;
	यदि (disabled) {
		debug3("password expiration disabled");
	} अन्यथा यदि (spw->sp_lstchg == 0) {
		logit("User %.100s password has expired (root forced)", user);
		प्रत्यागम 1;
	} अन्यथा यदि (spw->sp_max == -1) {
		debug3("password expiration disabled");
	} अन्यथा यदि (daysleft < 0) {
		logit("User %.100s password has expired (password aged)", user);
		प्रत्यागम 1;
	} अन्यथा यदि (daysleft <= spw->sp_warn) {
		debug3("password will expire in %d days", daysleft);
		यदि ((r = sshbuf_putf(loginmsg, 
		    "Your password will expire in %d day%s.\n", daysleft,
		    daysleft == 1 ? "" : "s")) != 0)
			fatal_fr(r, "buffer error");
	}

	प्रत्यागम 0;
}
#यदि_अन्तः	/* USE_SHADOW && HAS_SHADOW_EXPIRE */
