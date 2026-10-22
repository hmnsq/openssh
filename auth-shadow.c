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

#અન્તર્ભાવ "includes.h"

#જો defined(USE_SHADOW) && defined(HAS_SHADOW_EXPIRE)
#અન્તર્ભાવ <shadow.h>
#અન્તર્ભાવ <stdarg.h>
#અન્તર્ભાવ <string.h>
#અન્તર્ભાવ <time.h>

#અન્તર્ભાવ "hostfile.h"
#અન્તર્ભાવ "auth.h"
#અન્તર્ભાવ "sshbuf.h"
#અન્તર્ભાવ "ssherr.h"
#અન્તર્ભાવ "log.h"

#ifdef DAY
# undef DAY
#endif
#define DAY	(24L * 60 * 60) /* 1 day in seconds */

બાહ્ય સંરચના sshbuf *loginmsg;

/*
 * For the account and password expiration functions, we assume the expiry
 * occurs the day after the day specified.
 */

/*
 * Check if specified account is expired.  Returns 1 if account is expired,
 * 0 otherwise.
 */
પૂર્ણાંક
auth_shadow_acctexpired(સંરચના spwd *spw)
{
	time_t today;
	long long daysleft;
	પૂર્ણાંક r;

	today = time(ખાલી) / DAY;
	daysleft = spw->sp_expire - today;
	debug3("%s: today %lld sp_expire %lld days left %lld", __func__,
	    (long long)today, (long long)spw->sp_expire, daysleft);

	જો (spw->sp_expire == -1) {
		debug3("account expiration disabled");
	} નહીંતર જો (daysleft < 0) {
		logit("Account %.100s has expired", spw->sp_namp);
		પાછા 1;
	} નહીંતર જો (daysleft <= spw->sp_warn) {
		debug3("account will expire in %lld days", daysleft);
		જો ((r = sshbuf_putf(loginmsg, 
		    "Your account will expire in %lld day%s.\n", daysleft,
		    daysleft == 1 ? "" : "s")) != 0)
			fatal_fr(r, "buffer error");
	}

	પાછા 0;
}

/*
 * Checks password expiry for platforms that use shadow passwd files.
 * Returns: 1 = password expired, 0 = password not expired
 */
પૂર્ણાંક
auth_shadow_pwexpired(Authctxt *ctxt)
{
	સંરચના spwd *spw = ખાલી;
	અચલ અક્ષર *user = ctxt->pw->pw_name;
	time_t today;
	પૂર્ણાંક r, daysleft, disabled = 0;

	જો ((spw = getspnam((અક્ષર *)user)) == ખાલી) {
		error("Could not get shadow information for %.100s", user);
		પાછા 0;
	}

	today = time(ખાલી) / DAY;
	debug3_f("today %lld sp_lstchg %lld sp_max %lld", (long long)today,
	    (long long)spw->sp_lstchg, (long long)spw->sp_max);

#જો defined(__hpux) && !defined(HAVE_SECUREWARE)
	જો (iscomsec()) {
		સંરચના pr_passwd *pr;

		pr = getprpwnam((અક્ષર *)user);

		/* Test for Trusted Mode expiry disabled */
		જો (pr != ખાલી && pr->ufld.fd_min == 0 &&
		    pr->ufld.fd_lifetime == 0 && pr->ufld.fd_expire == 0 &&
		    pr->ufld.fd_pw_expire_warning == 0 &&
		    pr->ufld.fd_schange != 0)
			disabled = 1;
	}
#endif

	/* TODO: check sp_inact */
	daysleft = spw->sp_lstchg + spw->sp_max - today;
	જો (disabled) {
		debug3("password expiration disabled");
	} નહીંતર જો (spw->sp_lstchg == 0) {
		logit("User %.100s password has expired (root forced)", user);
		પાછા 1;
	} નહીંતર જો (spw->sp_max == -1) {
		debug3("password expiration disabled");
	} નહીંતર જો (daysleft < 0) {
		logit("User %.100s password has expired (password aged)", user);
		પાછા 1;
	} નહીંતર જો (daysleft <= spw->sp_warn) {
		debug3("password will expire in %d days", daysleft);
		જો ((r = sshbuf_putf(loginmsg, 
		    "Your password will expire in %d day%s.\n", daysleft,
		    daysleft == 1 ? "" : "s")) != 0)
			fatal_fr(r, "buffer error");
	}

	પાછા 0;
}
#endif	/* USE_SHADOW && HAS_SHADOW_EXPIRE */
