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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਜੇ defined(USE_SHADOW) && defined(HAS_SHADOW_EXPIRE)
#ਅਨ੍ਤਰ੍ਭਾਵ <shadow.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdarg.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <time.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "hostfile.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "auth.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "sshbuf.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssherr.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "log.h"

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ DAY
# undef DAY
#ਜੇ_ਅੰਤ
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ DAY	(24L * 60 * 60) /* 1 day in seconds */

ਬਾਹਰੀ ਬਣਤਰ sshbuf *loginmsg;

/*
 * For the account and password expiration functions, we assume the expiry
 * occurs the day after the day specified.
 */

/*
 * Check if specified account is expired.  Returns 1 if account is expired,
 * 0 otherwise.
 */
ਪੂਰਨ
auth_shadow_acctexpired(ਬਣਤਰ spwd *spw)
{
	time_t today;
	ਲੰਮਾ ਲੰਮਾ daysleft;
	ਪੂਰਨ r;

	today = time(ਨਿਰਾ) / DAY;
	daysleft = spw->sp_expire - today;
	debug3("%s: today %lld sp_expire %lld days left %lld", __func__,
	    (ਲੰਮਾ ਲੰਮਾ)today, (ਲੰਮਾ ਲੰਮਾ)spw->sp_expire, daysleft);

	ਜੇ (spw->sp_expire == -1) {
		debug3("account expiration disabled");
	} ਨਹੀਂਤਾਂ ਜੇ (daysleft < 0) {
		logit("Account %.100s has expired", spw->sp_namp);
		ਵਾਪਸ 1;
	} ਨਹੀਂਤਾਂ ਜੇ (daysleft <= spw->sp_warn) {
		debug3("account will expire in %lld days", daysleft);
		ਜੇ ((r = sshbuf_putf(loginmsg, 
		    "Your account will expire in %lld day%s.\n", daysleft,
		    daysleft == 1 ? "" : "s")) != 0)
			fatal_fr(r, "buffer error");
	}

	ਵਾਪਸ 0;
}

/*
 * Checks password expiry for platforms that use shadow passwd files.
 * Returns: 1 = password expired, 0 = password not expired
 */
ਪੂਰਨ
auth_shadow_pwexpired(Authctxt *ctxt)
{
	ਬਣਤਰ spwd *spw = ਨਿਰਾ;
	ਅਚਲ ਅੱਖਰ *user = ctxt->pw->pw_name;
	time_t today;
	ਪੂਰਨ r, daysleft, disabled = 0;

	ਜੇ ((spw = getspnam((ਅੱਖਰ *)user)) == ਨਿਰਾ) {
		error("Could not get shadow information for %.100s", user);
		ਵਾਪਸ 0;
	}

	today = time(ਨਿਰਾ) / DAY;
	debug3_f("today %lld sp_lstchg %lld sp_max %lld", (ਲੰਮਾ ਲੰਮਾ)today,
	    (ਲੰਮਾ ਲੰਮਾ)spw->sp_lstchg, (ਲੰਮਾ ਲੰਮਾ)spw->sp_max);

#ਜੇ defined(__hpux) && !defined(HAVE_SECUREWARE)
	ਜੇ (iscomsec()) {
		ਬਣਤਰ pr_passwd *pr;

		pr = getprpwnam((ਅੱਖਰ *)user);

		/* Test for Trusted Mode expiry disabled */
		ਜੇ (pr != ਨਿਰਾ && pr->ufld.fd_min == 0 &&
		    pr->ufld.fd_lifetime == 0 && pr->ufld.fd_expire == 0 &&
		    pr->ufld.fd_pw_expire_warning == 0 &&
		    pr->ufld.fd_schange != 0)
			disabled = 1;
	}
#ਜੇ_ਅੰਤ

	/* TODO: check sp_inact */
	daysleft = spw->sp_lstchg + spw->sp_max - today;
	ਜੇ (disabled) {
		debug3("password expiration disabled");
	} ਨਹੀਂਤਾਂ ਜੇ (spw->sp_lstchg == 0) {
		logit("User %.100s password has expired (root forced)", user);
		ਵਾਪਸ 1;
	} ਨਹੀਂਤਾਂ ਜੇ (spw->sp_max == -1) {
		debug3("password expiration disabled");
	} ਨਹੀਂਤਾਂ ਜੇ (daysleft < 0) {
		logit("User %.100s password has expired (password aged)", user);
		ਵਾਪਸ 1;
	} ਨਹੀਂਤਾਂ ਜੇ (daysleft <= spw->sp_warn) {
		debug3("password will expire in %d days", daysleft);
		ਜੇ ((r = sshbuf_putf(loginmsg, 
		    "Your password will expire in %d day%s.\n", daysleft,
		    daysleft == 1 ? "" : "s")) != 0)
			fatal_fr(r, "buffer error");
	}

	ਵਾਪਸ 0;
}
#ਜੇ_ਅੰਤ	/* USE_SHADOW && HAS_SHADOW_EXPIRE */
