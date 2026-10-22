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

#অন্তর্ভাব "includes.h"

#ifdef WITH_SELINUX

#অন্তর্ভাব <sys/socket.h>
#অন্তর্ভাব <sys/un.h>

#অন্তর্ভাব <errno.h>
#অন্তর্ভাব <stdarg.h>
#অন্তর্ভাব <string.h>
#অন্তর্ভাব <stdio.h>
#অন্তর্ভাব <stdlib.h>

#অন্তর্ভাব "log.h"
#অন্তর্ভাব "xmalloc.h"
#অন্তর্ভাব "port-linux.h"
#অন্তর্ভাব "misc.h"

#অন্তর্ভাব <selinux/selinux.h>
#অন্তর্ভাব <selinux/label.h>
#অন্তর্ভাব <selinux/get_context_list.h>

#ifndef SSH_SELINUX_UNCONFINED_TYPE
# define SSH_SELINUX_UNCONFINED_TYPE ":unconfined_t:"
#endif

/* Wrapper around is_selinux_enabled() to log its return value once only */
পূর্ণসংখ্যা
ssh_selinux_enabled(শূন্য)
{
	স্থির পূর্ণসংখ্যা enabled = -1;

	যদি (enabled == -1) {
		enabled = (is_selinux_enabled() == 1);
		debug("SELinux support %s", enabled ? "enabled" : "disabled");
	}

	ফেরত (enabled);
}

/* Return the default security context for the given username */
স্থির অক্ষর *
ssh_selinux_getctxbyname(অক্ষর *pwname)
{
	অক্ষর *sc = ফাঁকা, *sename = ফাঁকা, *lvl = ফাঁকা;
	পূর্ণসংখ্যা r;

#ifdef HAVE_GETSEUSERBYNAME
	যদি (getseuserbyname(pwname, &sename, &lvl) != 0)
		ফেরত ফাঁকা;
#অন্যথা
	sename = pwname;
	lvl = ফাঁকা;
#endif

#ifdef HAVE_GET_DEFAULT_CONTEXT_WITH_LEVEL
	r = get_default_context_with_level(sename, lvl, ফাঁকা, &sc);
#অন্যথা
	r = get_default_context(sename, ফাঁকা, &sc);
#endif

	যদি (r != 0) {
		নির্বাচন (security_getenforce()) {
		ক্ষেত্র -1:
			fatal("%s: ssh_selinux_getctxbyname: "
			    "security_getenforce() failed", __func__);
		ক্ষেত্র 0:
			error("%s: Failed to get default SELinux security "
			    "context for %s", __func__, pwname);
			sc = ফাঁকা;
			বিরতি;
		পূর্বনির্ধারিত:
			fatal("%s: Failed to get default SELinux security "
			    "context for %s (in enforcing mode)",
			    __func__, pwname);
		}
	}

#ifdef HAVE_GETSEUSERBYNAME
	মুক্ত(sename);
	মুক্ত(lvl);
#endif

	ফেরত sc;
}

/* Set the execution context to the default for the specified user */
শূন্য
ssh_selinux_setup_exec_context(অক্ষর *pwname)
{
	অক্ষর *user_ctx = ফাঁকা;

	যদি (!ssh_selinux_enabled())
		ফেরত;

	debug3("%s: setting execution context", __func__);

	user_ctx = ssh_selinux_getctxbyname(pwname);
	যদি (setexeccon(user_ctx) != 0) {
		নির্বাচন (security_getenforce()) {
		ক্ষেত্র -1:
			fatal("%s: security_getenforce() failed", __func__);
		ক্ষেত্র 0:
			error("%s: Failed to set SELinux execution "
			    "context for %s", __func__, pwname);
			বিরতি;
		পূর্বনির্ধারিত:
			fatal("%s: Failed to set SELinux execution context "
			    "for %s (in enforcing mode)", __func__, pwname);
		}
	}
	যদি (user_ctx != ফাঁকা)
		freecon(user_ctx);

	debug3("%s: done", __func__);
}

/* Set the TTY context for the specified user */
শূন্য
ssh_selinux_setup_pty(অক্ষর *pwname, ধ্রুবক অক্ষর *tty)
{
	অক্ষর *new_tty_ctx = ফাঁকা, *user_ctx = ফাঁকা, *old_tty_ctx = ফাঁকা;
	security_class_t chrclass;

	যদি (!ssh_selinux_enabled())
		ফেরত;

	debug3("%s: setting TTY context on %s", __func__, tty);

	user_ctx = ssh_selinux_getctxbyname(pwname);

	/* XXX: should these calls fatal() upon failure in enforcing mode? */

	যদি (getfilecon(tty, &old_tty_ctx) == -1) {
		error("%s: getfilecon: %s", __func__, strerror(errno));
		যাও out;
	}
	যদি ((chrclass = string_to_security_class("chr_file")) == 0) {
		error("%s: couldn't get security class for chr_file", __func__);
		যাও out;
	}
	যদি (security_compute_relabel(user_ctx, old_tty_ctx,
	    chrclass, &new_tty_ctx) != 0) {
		error("%s: security_compute_relabel: %s",
		    __func__, strerror(errno));
		যাও out;
	}

	যদি (setfilecon(tty, new_tty_ctx) != 0)
		error("%s: setfilecon: %s", __func__, strerror(errno));
 out:
	যদি (new_tty_ctx != ফাঁকা)
		freecon(new_tty_ctx);
	যদি (old_tty_ctx != ফাঁকা)
		freecon(old_tty_ctx);
	যদি (user_ctx != ফাঁকা)
		freecon(user_ctx);
	debug3("%s: done", __func__);
}

শূন্য
ssh_selinux_change_context(ধ্রুবক অক্ষর *newname)
{
	অক্ষর *oldctx, *newctx, *cx, *cx2;
	LogLevel log_level = SYSLOG_LEVEL_INFO;

	যদি (!ssh_selinux_enabled())
		ফেরত;

	যদি (getcon(&oldctx) < 0) {
		logit_f("getcon failed with %s", strerror(errno));
		ফেরত;
	}
	যদি ((cx = strchr(oldctx, ':')) == ফাঁকা ||
	    (cx = strchr(cx + 1, ':')) == ফাঁকা ||
	    (cx - oldctx) >= INT_MAX) {
		logit_f("unparsable context %s", oldctx);
		ফেরত;
	}

	/*
	 * Check whether we are attempting to switch away from an unconfined
	 * security context.
	 */
	যদি (strncmp(cx, SSH_SELINUX_UNCONFINED_TYPE,
	    আকার(SSH_SELINUX_UNCONFINED_TYPE) - 1) == 0)
		log_level = SYSLOG_LEVEL_DEBUG3;

	cx2 = strchr(cx + 1, ':');
	xasprintf(&newctx, "%.*s%s%s", (পূর্ণসংখ্যা)(cx - oldctx + 1), oldctx,
	    newname, cx2 == ফাঁকা ? "" : cx2);

	debug3_f("setting context from '%s' to '%s'", oldctx, newctx);
	যদি (setcon(newctx) < 0)
		do_log2_f(log_level, "setcon %s from %s failed with %s",
		    newctx, oldctx, strerror(errno));
	মুক্ত(oldctx);
	মুক্ত(newctx);
}

শূন্য
ssh_selinux_setfscreatecon(ধ্রুবক অক্ষর *path)
{
	অক্ষর *context;
	কাঠামো selabel_handle *shandle = ফাঁকা;

	যদি (!ssh_selinux_enabled())
		ফেরত;
	যদি (path == ফাঁকা) {
		setfscreatecon(ফাঁকা);
		ফেরত;
	}
	যদি ((shandle = selabel_open(SELABEL_CTX_FILE, ফাঁকা, 0)) == ফাঁকা) {
		debug_f("selabel_open failed");
		ফেরত;
	}
	যদি (selabel_lookup(shandle, &context, path, 0700) == 0)
		setfscreatecon(context);
	selabel_close(shandle);
}

#endif /* WITH_SELINUX */
