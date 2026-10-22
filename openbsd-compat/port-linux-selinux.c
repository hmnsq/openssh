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
পূর্ণাঙ্ক
ssh_selinux_enabled(শূন্য)
{
	স্থির পূর্ণাঙ্ক enabled = -1;

	যদি (enabled == -1) {
		enabled = (is_selinux_enabled() == 1);
		debug("SELinux support %s", enabled ? "enabled" : "disabled");
	}

	প্রত্যাগম (enabled);
}

/* Return the default security context for the given username */
স্থির বর্ণ *
ssh_selinux_getctxbyname(বর্ণ *pwname)
{
	বর্ণ *sc = রিক্ত, *sename = রিক্ত, *lvl = রিক্ত;
	পূর্ণাঙ্ক r;

#ifdef HAVE_GETSEUSERBYNAME
	যদি (getseuserbyname(pwname, &sename, &lvl) != 0)
		প্রত্যাগম রিক্ত;
#অন্যথা
	sename = pwname;
	lvl = রিক্ত;
#endif

#ifdef HAVE_GET_DEFAULT_CONTEXT_WITH_LEVEL
	r = get_default_context_with_level(sename, lvl, রিক্ত, &sc);
#অন্যথা
	r = get_default_context(sename, রিক্ত, &sc);
#endif

	যদি (r != 0) {
		বিকল্প (security_getenforce()) {
		পক্ষ -1:
			fatal("%s: ssh_selinux_getctxbyname: "
			    "security_getenforce() failed", __func__);
		পক্ষ 0:
			error("%s: Failed to get default SELinux security "
			    "context for %s", __func__, pwname);
			sc = রিক্ত;
			ভঙ্গ;
		স্বভাব:
			fatal("%s: Failed to get default SELinux security "
			    "context for %s (in enforcing mode)",
			    __func__, pwname);
		}
	}

#ifdef HAVE_GETSEUSERBYNAME
	মুক্ত(sename);
	মুক্ত(lvl);
#endif

	প্রত্যাগম sc;
}

/* Set the execution context to the default for the specified user */
শূন্য
ssh_selinux_setup_exec_context(বর্ণ *pwname)
{
	বর্ণ *user_ctx = রিক্ত;

	যদি (!ssh_selinux_enabled())
		প্রত্যাগম;

	debug3("%s: setting execution context", __func__);

	user_ctx = ssh_selinux_getctxbyname(pwname);
	যদি (setexeccon(user_ctx) != 0) {
		বিকল্প (security_getenforce()) {
		পক্ষ -1:
			fatal("%s: security_getenforce() failed", __func__);
		পক্ষ 0:
			error("%s: Failed to set SELinux execution "
			    "context for %s", __func__, pwname);
			ভঙ্গ;
		স্বভাব:
			fatal("%s: Failed to set SELinux execution context "
			    "for %s (in enforcing mode)", __func__, pwname);
		}
	}
	যদি (user_ctx != রিক্ত)
		freecon(user_ctx);

	debug3("%s: done", __func__);
}

/* Set the TTY context for the specified user */
শূন্য
ssh_selinux_setup_pty(বর্ণ *pwname, ধ্রুব বর্ণ *tty)
{
	বর্ণ *new_tty_ctx = রিক্ত, *user_ctx = রিক্ত, *old_tty_ctx = রিক্ত;
	security_class_t chrclass;

	যদি (!ssh_selinux_enabled())
		প্রত্যাগম;

	debug3("%s: setting TTY context on %s", __func__, tty);

	user_ctx = ssh_selinux_getctxbyname(pwname);

	/* XXX: should these calls fatal() upon failure in enforcing mode? */

	যদি (getfilecon(tty, &old_tty_ctx) == -1) {
		error("%s: getfilecon: %s", __func__, strerror(errno));
		গচ্ছ out;
	}
	যদি ((chrclass = string_to_security_class("chr_file")) == 0) {
		error("%s: couldn't get security class for chr_file", __func__);
		গচ্ছ out;
	}
	যদি (security_compute_relabel(user_ctx, old_tty_ctx,
	    chrclass, &new_tty_ctx) != 0) {
		error("%s: security_compute_relabel: %s",
		    __func__, strerror(errno));
		গচ্ছ out;
	}

	যদি (setfilecon(tty, new_tty_ctx) != 0)
		error("%s: setfilecon: %s", __func__, strerror(errno));
 out:
	যদি (new_tty_ctx != রিক্ত)
		freecon(new_tty_ctx);
	যদি (old_tty_ctx != রিক্ত)
		freecon(old_tty_ctx);
	যদি (user_ctx != রিক্ত)
		freecon(user_ctx);
	debug3("%s: done", __func__);
}

শূন্য
ssh_selinux_change_context(ধ্রুব বর্ণ *newname)
{
	বর্ণ *oldctx, *newctx, *cx, *cx2;
	LogLevel log_level = SYSLOG_LEVEL_INFO;

	যদি (!ssh_selinux_enabled())
		প্রত্যাগম;

	যদি (getcon(&oldctx) < 0) {
		logit_f("getcon failed with %s", strerror(errno));
		প্রত্যাগম;
	}
	যদি ((cx = strchr(oldctx, ':')) == রিক্ত ||
	    (cx = strchr(cx + 1, ':')) == রিক্ত ||
	    (cx - oldctx) >= INT_MAX) {
		logit_f("unparsable context %s", oldctx);
		প্রত্যাগম;
	}

	/*
	 * Check whether we are attempting to switch away from an unconfined
	 * security context.
	 */
	যদি (strncmp(cx, SSH_SELINUX_UNCONFINED_TYPE,
	    পরিমাণ(SSH_SELINUX_UNCONFINED_TYPE) - 1) == 0)
		log_level = SYSLOG_LEVEL_DEBUG3;

	cx2 = strchr(cx + 1, ':');
	xasprintf(&newctx, "%.*s%s%s", (পূর্ণাঙ্ক)(cx - oldctx + 1), oldctx,
	    newname, cx2 == রিক্ত ? "" : cx2);

	debug3_f("setting context from '%s' to '%s'", oldctx, newctx);
	যদি (setcon(newctx) < 0)
		do_log2_f(log_level, "setcon %s from %s failed with %s",
		    newctx, oldctx, strerror(errno));
	মুক্ত(oldctx);
	মুক্ত(newctx);
}

শূন্য
ssh_selinux_setfscreatecon(ধ্রুব বর্ণ *path)
{
	বর্ণ *context;
	সংরচনা selabel_handle *shandle = রিক্ত;

	যদি (!ssh_selinux_enabled())
		প্রত্যাগম;
	যদি (path == রিক্ত) {
		setfscreatecon(রিক্ত);
		প্রত্যাগম;
	}
	যদি ((shandle = selabel_open(SELABEL_CTX_FILE, রিক্ত, 0)) == রিক্ত) {
		debug_f("selabel_open failed");
		প্রত্যাগম;
	}
	যদি (selabel_lookup(shandle, &context, path, 0700) == 0)
		setfscreatecon(context);
	selabel_close(shandle);
}

#endif /* WITH_SELINUX */
