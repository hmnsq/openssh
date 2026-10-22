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

#అన్తర్భావ "includes.h"

#ఒకవేళ defined(USE_SHADOW) && defined(HAS_SHADOW_EXPIRE)
#అన్తర్భావ <shadow.h>
#అన్తర్భావ <stdarg.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <time.h>

#అన్తర్భావ "hostfile.h"
#అన్తర్భావ "auth.h"
#అన్తర్భావ "sshbuf.h"
#అన్తర్భావ "ssherr.h"
#అన్తర్భావ "log.h"

#నిర్వచితమైతే DAY
# undef DAY
#అయితే_ముగింపు
#నిర్వచించు DAY	(24L * 60 * 60) /* 1 day in seconds */

బాహ్య నిర్మాణం sshbuf *loginmsg;

/*
 * For the account and password expiration functions, we assume the expiry
 * occurs the day after the day specified.
 */

/*
 * Check if specified account is expired.  Returns 1 if account is expired,
 * 0 otherwise.
 */
పూర్ణాంకం
auth_shadow_acctexpired(నిర్మాణం spwd *spw)
{
	time_t today;
	దీర్ఘ దీర్ఘ daysleft;
	పూర్ణాంకం r;

	today = time(ఖాళీ) / DAY;
	daysleft = spw->sp_expire - today;
	debug3("%s: today %lld sp_expire %lld days left %lld", __func__,
	    (దీర్ఘ దీర్ఘ)today, (దీర్ఘ దీర్ఘ)spw->sp_expire, daysleft);

	ఒకవేళ (spw->sp_expire == -1) {
		debug3("account expiration disabled");
	} లేకపోతే ఒకవేళ (daysleft < 0) {
		logit("Account %.100s has expired", spw->sp_namp);
		తిరిగి 1;
	} లేకపోతే ఒకవేళ (daysleft <= spw->sp_warn) {
		debug3("account will expire in %lld days", daysleft);
		ఒకవేళ ((r = sshbuf_putf(loginmsg, 
		    "Your account will expire in %lld day%s.\n", daysleft,
		    daysleft == 1 ? "" : "s")) != 0)
			fatal_fr(r, "buffer error");
	}

	తిరిగి 0;
}

/*
 * Checks password expiry for platforms that use shadow passwd files.
 * Returns: 1 = password expired, 0 = password not expired
 */
పూర్ణాంకం
auth_shadow_pwexpired(Authctxt *ctxt)
{
	నిర్మాణం spwd *spw = ఖాళీ;
	స్థిరరాశి అక్షరం *user = ctxt->pw->pw_name;
	time_t today;
	పూర్ణాంకం r, daysleft, disabled = 0;

	ఒకవేళ ((spw = getspnam((అక్షరం *)user)) == ఖాళీ) {
		error("Could not get shadow information for %.100s", user);
		తిరిగి 0;
	}

	today = time(ఖాళీ) / DAY;
	debug3_f("today %lld sp_lstchg %lld sp_max %lld", (దీర్ఘ దీర్ఘ)today,
	    (దీర్ఘ దీర్ఘ)spw->sp_lstchg, (దీర్ఘ దీర్ఘ)spw->sp_max);

#ఒకవేళ defined(__hpux) && !defined(HAVE_SECUREWARE)
	ఒకవేళ (iscomsec()) {
		నిర్మాణం pr_passwd *pr;

		pr = getprpwnam((అక్షరం *)user);

		/* Test for Trusted Mode expiry disabled */
		ఒకవేళ (pr != ఖాళీ && pr->ufld.fd_min == 0 &&
		    pr->ufld.fd_lifetime == 0 && pr->ufld.fd_expire == 0 &&
		    pr->ufld.fd_pw_expire_warning == 0 &&
		    pr->ufld.fd_schange != 0)
			disabled = 1;
	}
#అయితే_ముగింపు

	/* TODO: check sp_inact */
	daysleft = spw->sp_lstchg + spw->sp_max - today;
	ఒకవేళ (disabled) {
		debug3("password expiration disabled");
	} లేకపోతే ఒకవేళ (spw->sp_lstchg == 0) {
		logit("User %.100s password has expired (root forced)", user);
		తిరిగి 1;
	} లేకపోతే ఒకవేళ (spw->sp_max == -1) {
		debug3("password expiration disabled");
	} లేకపోతే ఒకవేళ (daysleft < 0) {
		logit("User %.100s password has expired (password aged)", user);
		తిరిగి 1;
	} లేకపోతే ఒకవేళ (daysleft <= spw->sp_warn) {
		debug3("password will expire in %d days", daysleft);
		ఒకవేళ ((r = sshbuf_putf(loginmsg, 
		    "Your password will expire in %d day%s.\n", daysleft,
		    daysleft == 1 ? "" : "s")) != 0)
			fatal_fr(r, "buffer error");
	}

	తిరిగి 0;
}
#అయితే_ముగింపు	/* USE_SHADOW && HAS_SHADOW_EXPIRE */
