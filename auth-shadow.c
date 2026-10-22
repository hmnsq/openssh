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

#অন্তর্ভাব "includes.h"

#যদি defined(USE_SHADOW) && defined(HAS_SHADOW_EXPIRE)
#অন্তর্ভাব <shadow.h>
#অন্তর্ভাব <stdarg.h>
#অন্তর্ভাব <string.h>
#অন্তর্ভাব <time.h>

#অন্তর্ভাব "hostfile.h"
#অন্তর্ভাব "auth.h"
#অন্তর্ভাব "sshbuf.h"
#অন্তর্ভাব "ssherr.h"
#অন্তর্ভাব "log.h"

#ifdef DAY
# undef DAY
#endif
#define DAY	(24L * 60 * 60) /* 1 day in seconds */

বাহ্য সংরচনা sshbuf *loginmsg;

/*
 * For the account and password expiration functions, we assume the expiry
 * occurs the day after the day specified.
 */

/*
 * Check if specified account is expired.  Returns 1 if account is expired,
 * 0 otherwise.
 */
পূর্ণাঙ্ক
auth_shadow_acctexpired(সংরচনা spwd *spw)
{
	time_t today;
	long long daysleft;
	পূর্ণাঙ্ক r;

	today = time(রিক্ত) / DAY;
	daysleft = spw->sp_expire - today;
	debug3("%s: today %lld sp_expire %lld days left %lld", __func__,
	    (long long)today, (long long)spw->sp_expire, daysleft);

	যদি (spw->sp_expire == -1) {
		debug3("account expiration disabled");
	} অন্যথা যদি (daysleft < 0) {
		logit("Account %.100s has expired", spw->sp_namp);
		প্রত্যাগম 1;
	} অন্যথা যদি (daysleft <= spw->sp_warn) {
		debug3("account will expire in %lld days", daysleft);
		যদি ((r = sshbuf_putf(loginmsg, 
		    "Your account will expire in %lld day%s.\n", daysleft,
		    daysleft == 1 ? "" : "s")) != 0)
			fatal_fr(r, "buffer error");
	}

	প্রত্যাগম 0;
}

/*
 * Checks password expiry for platforms that use shadow passwd files.
 * Returns: 1 = password expired, 0 = password not expired
 */
পূর্ণাঙ্ক
auth_shadow_pwexpired(Authctxt *ctxt)
{
	সংরচনা spwd *spw = রিক্ত;
	ধ্রুব বর্ণ *user = ctxt->pw->pw_name;
	time_t today;
	পূর্ণাঙ্ক r, daysleft, disabled = 0;

	যদি ((spw = getspnam((বর্ণ *)user)) == রিক্ত) {
		error("Could not get shadow information for %.100s", user);
		প্রত্যাগম 0;
	}

	today = time(রিক্ত) / DAY;
	debug3_f("today %lld sp_lstchg %lld sp_max %lld", (long long)today,
	    (long long)spw->sp_lstchg, (long long)spw->sp_max);

#যদি defined(__hpux) && !defined(HAVE_SECUREWARE)
	যদি (iscomsec()) {
		সংরচনা pr_passwd *pr;

		pr = getprpwnam((বর্ণ *)user);

		/* Test for Trusted Mode expiry disabled */
		যদি (pr != রিক্ত && pr->ufld.fd_min == 0 &&
		    pr->ufld.fd_lifetime == 0 && pr->ufld.fd_expire == 0 &&
		    pr->ufld.fd_pw_expire_warning == 0 &&
		    pr->ufld.fd_schange != 0)
			disabled = 1;
	}
#endif

	/* TODO: check sp_inact */
	daysleft = spw->sp_lstchg + spw->sp_max - today;
	যদি (disabled) {
		debug3("password expiration disabled");
	} অন্যথা যদি (spw->sp_lstchg == 0) {
		logit("User %.100s password has expired (root forced)", user);
		প্রত্যাগম 1;
	} অন্যথা যদি (spw->sp_max == -1) {
		debug3("password expiration disabled");
	} অন্যথা যদি (daysleft < 0) {
		logit("User %.100s password has expired (password aged)", user);
		প্রত্যাগম 1;
	} অন্যথা যদি (daysleft <= spw->sp_warn) {
		debug3("password will expire in %d days", daysleft);
		যদি ((r = sshbuf_putf(loginmsg, 
		    "Your password will expire in %d day%s.\n", daysleft,
		    daysleft == 1 ? "" : "s")) != 0)
			fatal_fr(r, "buffer error");
	}

	প্রত্যাগম 0;
}
#endif	/* USE_SHADOW && HAS_SHADOW_EXPIRE */
