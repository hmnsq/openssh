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

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಆದರೆ defined(USE_SHADOW) && defined(HAS_SHADOW_EXPIRE)
#ಅನ್ತರ್ಭಾವ <shadow.h>
#ಅನ್ತರ್ಭಾವ <stdarg.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <time.h>

#ಅನ್ತರ್ಭಾವ "hostfile.h"
#ಅನ್ತರ್ಭಾವ "auth.h"
#ಅನ್ತರ್ಭಾವ "sshbuf.h"
#ಅನ್ತರ್ಭಾವ "ssherr.h"
#ಅನ್ತರ್ಭಾವ "log.h"

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ DAY
# undef DAY
#ಆದರೆ_ಅಂತ್ಯ
#ವ್ಯಾಖ್ಯಾನಿಸು DAY	(24L * 60 * 60) /* 1 day in seconds */

ಬಾಹ್ಯ ರಚನೆ sshbuf *loginmsg;

/*
 * For the account and password expiration functions, we assume the expiry
 * occurs the day after the day specified.
 */

/*
 * Check if specified account is expired.  Returns 1 if account is expired,
 * 0 otherwise.
 */
ಪೂರ್ಣಾಂಕ
auth_shadow_acctexpired(ರಚನೆ spwd *spw)
{
	time_t today;
	ದೀರ್ಘ ದೀರ್ಘ daysleft;
	ಪೂರ್ಣಾಂಕ r;

	today = time(ಖಾಲಿ) / DAY;
	daysleft = spw->sp_expire - today;
	debug3("%s: today %lld sp_expire %lld days left %lld", __func__,
	    (ದೀರ್ಘ ದೀರ್ಘ)today, (ದೀರ್ಘ ದೀರ್ಘ)spw->sp_expire, daysleft);

	ಆದರೆ (spw->sp_expire == -1) {
		debug3("account expiration disabled");
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (daysleft < 0) {
		logit("Account %.100s has expired", spw->sp_namp);
		ಹಿಂತಿರುಗಿ 1;
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (daysleft <= spw->sp_warn) {
		debug3("account will expire in %lld days", daysleft);
		ಆದರೆ ((r = sshbuf_putf(loginmsg, 
		    "Your account will expire in %lld day%s.\n", daysleft,
		    daysleft == 1 ? "" : "s")) != 0)
			fatal_fr(r, "buffer error");
	}

	ಹಿಂತಿರುಗಿ 0;
}

/*
 * Checks password expiry for platforms that use shadow passwd files.
 * Returns: 1 = password expired, 0 = password not expired
 */
ಪೂರ್ಣಾಂಕ
auth_shadow_pwexpired(Authctxt *ctxt)
{
	ರಚನೆ spwd *spw = ಖಾಲಿ;
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *user = ctxt->pw->pw_name;
	time_t today;
	ಪೂರ್ಣಾಂಕ r, daysleft, disabled = 0;

	ಆದರೆ ((spw = getspnam((ಅಕ್ಷರ *)user)) == ಖಾಲಿ) {
		error("Could not get shadow information for %.100s", user);
		ಹಿಂತಿರುಗಿ 0;
	}

	today = time(ಖಾಲಿ) / DAY;
	debug3_f("today %lld sp_lstchg %lld sp_max %lld", (ದೀರ್ಘ ದೀರ್ಘ)today,
	    (ದೀರ್ಘ ದೀರ್ಘ)spw->sp_lstchg, (ದೀರ್ಘ ದೀರ್ಘ)spw->sp_max);

#ಆದರೆ defined(__hpux) && !defined(HAVE_SECUREWARE)
	ಆದರೆ (iscomsec()) {
		ರಚನೆ pr_passwd *pr;

		pr = getprpwnam((ಅಕ್ಷರ *)user);

		/* Test for Trusted Mode expiry disabled */
		ಆದರೆ (pr != ಖಾಲಿ && pr->ufld.fd_min == 0 &&
		    pr->ufld.fd_lifetime == 0 && pr->ufld.fd_expire == 0 &&
		    pr->ufld.fd_pw_expire_warning == 0 &&
		    pr->ufld.fd_schange != 0)
			disabled = 1;
	}
#ಆದರೆ_ಅಂತ್ಯ

	/* TODO: check sp_inact */
	daysleft = spw->sp_lstchg + spw->sp_max - today;
	ಆದರೆ (disabled) {
		debug3("password expiration disabled");
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (spw->sp_lstchg == 0) {
		logit("User %.100s password has expired (root forced)", user);
		ಹಿಂತಿರುಗಿ 1;
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (spw->sp_max == -1) {
		debug3("password expiration disabled");
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (daysleft < 0) {
		logit("User %.100s password has expired (password aged)", user);
		ಹಿಂತಿರುಗಿ 1;
	} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (daysleft <= spw->sp_warn) {
		debug3("password will expire in %d days", daysleft);
		ಆದರೆ ((r = sshbuf_putf(loginmsg, 
		    "Your password will expire in %d day%s.\n", daysleft,
		    daysleft == 1 ? "" : "s")) != 0)
			fatal_fr(r, "buffer error");
	}

	ಹಿಂತಿರುಗಿ 0;
}
#ಆದರೆ_ಅಂತ್ಯ	/* USE_SHADOW && HAS_SHADOW_EXPIRE */
