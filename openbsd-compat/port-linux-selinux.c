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

#ضمن "includes.h"

#ifdef WITH_SELINUX

#ضمن <sys/socket.h>
#ضمن <sys/un.h>

#ضمن <errno.h>
#ضمن <stdarg.h>
#ضمن <string.h>
#ضمن <stdio.h>
#ضمن <stdlib.h>

#ضمن "log.h"
#ضمن "xmalloc.h"
#ضمن "port-linux.h"
#ضمن "misc.h"

#ضمن <selinux/selinux.h>
#ضمن <selinux/label.h>
#ضمن <selinux/get_context_list.h>

#ifndef SSH_SELINUX_UNCONFINED_TYPE
# define SSH_SELINUX_UNCONFINED_TYPE ":unconfined_t:"
#endif

/* Wrapper around is_selinux_enabled() to log its return value once only */
صحيح
ssh_selinux_enabled(فراغ)
{
	ساكن صحيح enabled = -1;

	אם (enabled == -1) {
		enabled = (is_selinux_enabled() == 1);
		debug("SELinux support %s", enabled ? "enabled" : "disabled");
	}

	החזר (enabled);
}

/* Return the default security context for the given username */
ساكن حرف *
ssh_selinux_getctxbyname(حرف *pwname)
{
	حرف *sc = عدم, *sename = عدم, *lvl = عدم;
	صحيح r;

#ifdef HAVE_GETSEUSERBYNAME
	אם (getseuserbyname(pwname, &sename, &lvl) != 0)
		החזר عدم;
#אחרת
	sename = pwname;
	lvl = عدم;
#endif

#ifdef HAVE_GET_DEFAULT_CONTEXT_WITH_LEVEL
	r = get_default_context_with_level(sename, lvl, عدم, &sc);
#אחרת
	r = get_default_context(sename, عدم, &sc);
#endif

	אם (r != 0) {
		بدل (security_getenforce()) {
		حالة -1:
			fatal("%s: ssh_selinux_getctxbyname: "
			    "security_getenforce() failed", __func__);
		حالة 0:
			error("%s: Failed to get default SELinux security "
			    "context for %s", __func__, pwname);
			sc = عدم;
			اكسر;
		افتراضي:
			fatal("%s: Failed to get default SELinux security "
			    "context for %s (in enforcing mode)",
			    __func__, pwname);
		}
	}

#ifdef HAVE_GETSEUSERBYNAME
	حرر(sename);
	حرر(lvl);
#endif

	החזר sc;
}

/* Set the execution context to the default for the specified user */
فراغ
ssh_selinux_setup_exec_context(حرف *pwname)
{
	حرف *user_ctx = عدم;

	אם (!ssh_selinux_enabled())
		החזר;

	debug3("%s: setting execution context", __func__);

	user_ctx = ssh_selinux_getctxbyname(pwname);
	אם (setexeccon(user_ctx) != 0) {
		بدل (security_getenforce()) {
		حالة -1:
			fatal("%s: security_getenforce() failed", __func__);
		حالة 0:
			error("%s: Failed to set SELinux execution "
			    "context for %s", __func__, pwname);
			اكسر;
		افتراضي:
			fatal("%s: Failed to set SELinux execution context "
			    "for %s (in enforcing mode)", __func__, pwname);
		}
	}
	אם (user_ctx != عدم)
		freecon(user_ctx);

	debug3("%s: done", __func__);
}

/* Set the TTY context for the specified user */
فراغ
ssh_selinux_setup_pty(حرف *pwname, ثابت حرف *tty)
{
	حرف *new_tty_ctx = عدم, *user_ctx = عدم, *old_tty_ctx = عدم;
	security_class_t chrclass;

	אם (!ssh_selinux_enabled())
		החזר;

	debug3("%s: setting TTY context on %s", __func__, tty);

	user_ctx = ssh_selinux_getctxbyname(pwname);

	/* XXX: should these calls fatal() upon failure in enforcing mode? */

	אם (getfilecon(tty, &old_tty_ctx) == -1) {
		error("%s: getfilecon: %s", __func__, strerror(errno));
		اذهب out;
	}
	אם ((chrclass = string_to_security_class("chr_file")) == 0) {
		error("%s: couldn't get security class for chr_file", __func__);
		اذهب out;
	}
	אם (security_compute_relabel(user_ctx, old_tty_ctx,
	    chrclass, &new_tty_ctx) != 0) {
		error("%s: security_compute_relabel: %s",
		    __func__, strerror(errno));
		اذهب out;
	}

	אם (setfilecon(tty, new_tty_ctx) != 0)
		error("%s: setfilecon: %s", __func__, strerror(errno));
 out:
	אם (new_tty_ctx != عدم)
		freecon(new_tty_ctx);
	אם (old_tty_ctx != عدم)
		freecon(old_tty_ctx);
	אם (user_ctx != عدم)
		freecon(user_ctx);
	debug3("%s: done", __func__);
}

فراغ
ssh_selinux_change_context(ثابت حرف *newname)
{
	حرف *oldctx, *newctx, *cx, *cx2;
	LogLevel log_level = SYSLOG_LEVEL_INFO;

	אם (!ssh_selinux_enabled())
		החזר;

	אם (getcon(&oldctx) < 0) {
		logit_f("getcon failed with %s", strerror(errno));
		החזר;
	}
	אם ((cx = strchr(oldctx, ':')) == عدم ||
	    (cx = strchr(cx + 1, ':')) == عدم ||
	    (cx - oldctx) >= INT_MAX) {
		logit_f("unparsable context %s", oldctx);
		החזר;
	}

	/*
	 * Check whether we are attempting to switch away from an unconfined
	 * security context.
	 */
	אם (strncmp(cx, SSH_SELINUX_UNCONFINED_TYPE,
	    حجم(SSH_SELINUX_UNCONFINED_TYPE) - 1) == 0)
		log_level = SYSLOG_LEVEL_DEBUG3;

	cx2 = strchr(cx + 1, ':');
	xasprintf(&newctx, "%.*s%s%s", (صحيح)(cx - oldctx + 1), oldctx,
	    newname, cx2 == عدم ? "" : cx2);

	debug3_f("setting context from '%s' to '%s'", oldctx, newctx);
	אם (setcon(newctx) < 0)
		do_log2_f(log_level, "setcon %s from %s failed with %s",
		    newctx, oldctx, strerror(errno));
	حرر(oldctx);
	حرر(newctx);
}

فراغ
ssh_selinux_setfscreatecon(ثابت حرف *path)
{
	حرف *context;
	بنية selabel_handle *shandle = عدم;

	אם (!ssh_selinux_enabled())
		החזר;
	אם (path == عدم) {
		setfscreatecon(عدم);
		החזר;
	}
	אם ((shandle = selabel_open(SELABEL_CTX_FILE, عدم, 0)) == عدم) {
		debug_f("selabel_open failed");
		החזר;
	}
	אם (selabel_lookup(shandle, &context, path, 0700) == 0)
		setfscreatecon(context);
	selabel_close(shandle);
}

#endif /* WITH_SELINUX */
