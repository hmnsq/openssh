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

#شامل "includes.h"

#اگر defined(USE_SHADOW) && defined(HAS_SHADOW_EXPIRE)
#شامل <shadow.h>
#شامل <stdarg.h>
#شامل <string.h>
#شامل <time.h>

#شامل "hostfile.h"
#شامل "auth.h"
#شامل "sshbuf.h"
#شامل "ssherr.h"
#شامل "log.h"

#اگر_تعریف_شدہ DAY
# undef DAY
#اگر_ختم
#تعریف_کرو DAY	(24L * 60 * 60) /* 1 day in seconds */

خارجی ساخت sshbuf *loginmsg;

/*
 * For the account and password expiration functions, we assume the expiry
 * occurs the day after the day specified.
 */

/*
 * Check if specified account is expired.  Returns 1 if account is expired,
 * 0 otherwise.
 */
صحیح
auth_shadow_acctexpired(ساخت spwd *spw)
{
	time_t today;
	طویل طویل daysleft;
	صحیح r;

	today = time(تہی) / DAY;
	daysleft = spw->sp_expire - today;
	debug3("%s: today %lld sp_expire %lld days left %lld", __func__,
	    (طویل طویل)today, (طویل طویل)spw->sp_expire, daysleft);

	اگر (spw->sp_expire == -1) {
		debug3("account expiration disabled");
	} ورنہ اگر (daysleft < 0) {
		logit("Account %.100s has expired", spw->sp_namp);
		واپس 1;
	} ورنہ اگر (daysleft <= spw->sp_warn) {
		debug3("account will expire in %lld days", daysleft);
		اگر ((r = sshbuf_putf(loginmsg, 
		    "Your account will expire in %lld day%s.\n", daysleft,
		    daysleft == 1 ? "" : "s")) != 0)
			fatal_fr(r, "buffer error");
	}

	واپس 0;
}

/*
 * Checks password expiry for platforms that use shadow passwd files.
 * Returns: 1 = password expired, 0 = password not expired
 */
صحیح
auth_shadow_pwexpired(Authctxt *ctxt)
{
	ساخت spwd *spw = تہی;
	ثابت حرف *user = ctxt->pw->pw_name;
	time_t today;
	صحیح r, daysleft, disabled = 0;

	اگر ((spw = getspnam((حرف *)user)) == تہی) {
		error("Could not get shadow information for %.100s", user);
		واپس 0;
	}

	today = time(تہی) / DAY;
	debug3_f("today %lld sp_lstchg %lld sp_max %lld", (طویل طویل)today,
	    (طویل طویل)spw->sp_lstchg, (طویل طویل)spw->sp_max);

#اگر defined(__hpux) && !defined(HAVE_SECUREWARE)
	اگر (iscomsec()) {
		ساخت pr_passwd *pr;

		pr = getprpwnam((حرف *)user);

		/* Test for Trusted Mode expiry disabled */
		اگر (pr != تہی && pr->ufld.fd_min == 0 &&
		    pr->ufld.fd_lifetime == 0 && pr->ufld.fd_expire == 0 &&
		    pr->ufld.fd_pw_expire_warning == 0 &&
		    pr->ufld.fd_schange != 0)
			disabled = 1;
	}
#اگر_ختم

	/* TODO: check sp_inact */
	daysleft = spw->sp_lstchg + spw->sp_max - today;
	اگر (disabled) {
		debug3("password expiration disabled");
	} ورنہ اگر (spw->sp_lstchg == 0) {
		logit("User %.100s password has expired (root forced)", user);
		واپس 1;
	} ورنہ اگر (spw->sp_max == -1) {
		debug3("password expiration disabled");
	} ورنہ اگر (daysleft < 0) {
		logit("User %.100s password has expired (password aged)", user);
		واپس 1;
	} ورنہ اگر (daysleft <= spw->sp_warn) {
		debug3("password will expire in %d days", daysleft);
		اگر ((r = sshbuf_putf(loginmsg, 
		    "Your password will expire in %d day%s.\n", daysleft,
		    daysleft == 1 ? "" : "s")) != 0)
			fatal_fr(r, "buffer error");
	}

	واپس 0;
}
#اگر_ختم	/* USE_SHADOW && HAS_SHADOW_EXPIRE */
