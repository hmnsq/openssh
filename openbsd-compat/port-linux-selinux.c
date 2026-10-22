/*
 * Copyright (c) 2005 Daniel Walsh <dwalsh@redhat.com>
 * Copyright (c) 2006 Damien Miller <djm@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * Linux-specific portability code: SELinux support
 */

#అన్తర్భావ "includes.h"

#నిర్వచితమైతే WITH_SELINUX

#అన్తర్భావ <sys/socket.h>
#అన్తర్భావ <sys/un.h>

#అన్తర్భావ <errno.h>
#అన్తర్భావ <stdarg.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <stdio.h>
#అన్తర్భావ <stdlib.h>

#అన్తర్భావ "log.h"
#అన్తర్భావ "xmalloc.h"
#అన్తర్భావ "port-linux.h"
#అన్తర్భావ "misc.h"

#అన్తర్భావ <selinux/selinux.h>
#అన్తర్భావ <selinux/label.h>
#అన్తర్భావ <selinux/get_context_list.h>

#నిర్వచితం_కాకపోతే SSH_SELINUX_UNCONFINED_TYPE
# define SSH_SELINUX_UNCONFINED_TYPE ":unconfined_t:"
#అయితే_ముగింపు

/* Wrapper around is_selinux_enabled() to log its return value once only */
పూర్ణాంకం
ssh_selinux_enabled(శూన్య)
{
	స్థిర పూర్ణాంకం enabled = -1;

	ఒకవేళ (enabled == -1) {
		enabled = (is_selinux_enabled() == 1);
		debug("SELinux support %s", enabled ? "enabled" : "disabled");
	}

	తిరిగి (enabled);
}

/* Return the default security context for the given username */
స్థిర అక్షరం *
ssh_selinux_getctxbyname(అక్షరం *pwname)
{
	అక్షరం *sc = ఖాళీ, *sename = ఖాళీ, *lvl = ఖాళీ;
	పూర్ణాంకం r;

#నిర్వచితమైతే HAVE_GETSEUSERBYNAME
	ఒకవేళ (getseuserbyname(pwname, &sename, &lvl) != 0)
		తిరిగి ఖాళీ;
#లేకపోతే
	sename = pwname;
	lvl = ఖాళీ;
#అయితే_ముగింపు

#నిర్వచితమైతే HAVE_GET_DEFAULT_CONTEXT_WITH_LEVEL
	r = get_default_context_with_level(sename, lvl, ఖాళీ, &sc);
#లేకపోతే
	r = get_default_context(sename, ఖాళీ, &sc);
#అయితే_ముగింపు

	ఒకవేళ (r != 0) {
		ఎంపిక (security_getenforce()) {
		స్థితి -1:
			fatal("%s: ssh_selinux_getctxbyname: "
			    "security_getenforce() failed", __func__);
		స్థితి 0:
			error("%s: Failed to get default SELinux security "
			    "context for %s", __func__, pwname);
			sc = ఖాళీ;
			ఆపు;
		అప్రమేయ:
			fatal("%s: Failed to get default SELinux security "
			    "context for %s (in enforcing mode)",
			    __func__, pwname);
		}
	}

#నిర్వచితమైతే HAVE_GETSEUSERBYNAME
	విడుదల(sename);
	విడుదల(lvl);
#అయితే_ముగింపు

	తిరిగి sc;
}

/* Set the execution context to the default for the specified user */
శూన్య
ssh_selinux_అమరిక_exec_context(అక్షరం *pwname)
{
	అక్షరం *user_ctx = ఖాళీ;

	ఒకవేళ (!ssh_selinux_enabled())
		తిరిగి;

	debug3("%s: setting execution context", __func__);

	user_ctx = ssh_selinux_getctxbyname(pwname);
	ఒకవేళ (setexeccon(user_ctx) != 0) {
		ఎంపిక (security_getenforce()) {
		స్థితి -1:
			fatal("%s: security_getenforce() failed", __func__);
		స్థితి 0:
			error("%s: Failed to set SELinux execution "
			    "context for %s", __func__, pwname);
			ఆపు;
		అప్రమేయ:
			fatal("%s: Failed to set SELinux execution context "
			    "for %s (in enforcing mode)", __func__, pwname);
		}
	}
	ఒకవేళ (user_ctx != ఖాళీ)
		freecon(user_ctx);

	debug3("%s: done", __func__);
}

/* Set the TTY context for the specified user */
శూన్య
ssh_selinux_అమరిక_pty(అక్షరం *pwname, స్థిరరాశి అక్షరం *tty)
{
	అక్షరం *new_tty_ctx = ఖాళీ, *user_ctx = ఖాళీ, *old_tty_ctx = ఖాళీ;
	security_class_t chrclass;

	ఒకవేళ (!ssh_selinux_enabled())
		తిరిగి;

	debug3("%s: setting TTY context on %s", __func__, tty);

	user_ctx = ssh_selinux_getctxbyname(pwname);

	/* XXX: should these calls fatal() upon failure in enforcing mode? */

	ఒకవేళ (getfilecon(tty, &old_tty_ctx) == -1) {
		error("%s: getfilecon: %s", __func__, strerror(errno));
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ ((chrclass = string_గమ్యం_security_class("chr_file")) == 0) {
		error("%s: couldn't get security class for chr_file", __func__);
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ (security_compute_relabel(user_ctx, old_tty_ctx,
	    chrclass, &new_tty_ctx) != 0) {
		error("%s: security_compute_relabel: %s",
		    __func__, strerror(errno));
		వెళ్ళు బహిర్గతం;
	}

	ఒకవేళ (setfilecon(tty, new_tty_ctx) != 0)
		error("%s: setfilecon: %s", __func__, strerror(errno));
 బహిర్గతం:
	ఒకవేళ (new_tty_ctx != ఖాళీ)
		freecon(new_tty_ctx);
	ఒకవేళ (old_tty_ctx != ఖాళీ)
		freecon(old_tty_ctx);
	ఒకవేళ (user_ctx != ఖాళీ)
		freecon(user_ctx);
	debug3("%s: done", __func__);
}

శూన్య
ssh_selinux_change_context(స్థిరరాశి అక్షరం *newname)
{
	అక్షరం *oldctx, *newctx, *cx, *cx2;
	LogLevel log_level = SYSLOG_LEVEL_INFO;

	ఒకవేళ (!ssh_selinux_enabled())
		తిరిగి;

	ఒకవేళ (getcon(&oldctx) < 0) {
		logit_f("getcon failed with %s", strerror(errno));
		తిరిగి;
	}
	ఒకవేళ ((cx = strchr(oldctx, ':')) == ఖాళీ ||
	    (cx = strchr(cx + 1, ':')) == ఖాళీ ||
	    (cx - oldctx) >= గరిష్ఠ_పూర్ణాంకం) {
		logit_f("unparsable context %s", oldctx);
		తిరిగి;
	}

	/*
	 * Check whether we are attempting to switch away from an unconfined
	 * security context.
	 */
	ఒకవేళ (అక్షరశ్రేణి_పోలిక(cx, SSH_SELINUX_UNCONFINED_TYPE,
	    పరిమాణం(SSH_SELINUX_UNCONFINED_TYPE) - 1) == 0)
		log_level = SYSLOG_LEVEL_DEBUG3;

	cx2 = strchr(cx + 1, ':');
	xasprintf(&newctx, "%.*s%s%s", (పూర్ణాంకం)(cx - oldctx + 1), oldctx,
	    newname, cx2 == ఖాళీ ? "" : cx2);

	debug3_f("setting context from '%s' to '%s'", oldctx, newctx);
	ఒకవేళ (setcon(newctx) < 0)
		do_log2_f(log_level, "setcon %s from %s failed with %s",
		    newctx, oldctx, strerror(errno));
	విడుదల(oldctx);
	విడుదల(newctx);
}

శూన్య
ssh_selinux_setfscreatecon(స్థిరరాశి అక్షరం *మార్గం)
{
	అక్షరం *context;
	నిర్మాణం selabel_handle *shandle = ఖాళీ;

	ఒకవేళ (!ssh_selinux_enabled())
		తిరిగి;
	ఒకవేళ (మార్గం == ఖాళీ) {
		setfscreatecon(ఖాళీ);
		తిరిగి;
	}
	ఒకవేళ ((shandle = selabel_open(SELABEL_CTX_FILE, ఖాళీ, 0)) == ఖాళీ) {
		debug_f("selabel_open failed");
		తిరిగి;
	}
	ఒకవేళ (selabel_lookup(shandle, &context, మార్గం, 0700) == 0)
		setfscreatecon(context);
	selabel_close(shandle);
}

#అయితే_ముగింపు /* WITH_SELINUX */
