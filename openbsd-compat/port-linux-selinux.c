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

#شامل "includes.h"

#ifdef WITH_SELINUX

#شامل <sys/socket.h>
#شامل <sys/un.h>

#شامل <errno.h>
#شامل <stdarg.h>
#شامل <string.h>
#شامل <stdio.h>
#شامل <stdlib.h>

#شامل "log.h"
#شامل "xmalloc.h"
#شامل "port-linux.h"
#شامل "misc.h"

#شامل <selinux/selinux.h>
#شامل <selinux/label.h>
#شامل <selinux/get_context_list.h>

#ifndef SSH_SELINUX_UNCONFINED_TYPE
# define SSH_SELINUX_UNCONFINED_TYPE ":unconfined_t:"
#endif

/* Wrapper around is_selinux_enabled() to log its return value once only */
صحیح
ssh_selinux_enabled(تهی)
{
	ایستا صحیح enabled = -1;

	اگر (enabled == -1) {
		enabled = (is_selinux_enabled() == 1);
		debug("SELinux support %s", enabled ? "enabled" : "disabled");
	}

	بازگشت (enabled);
}

/* Return the default security context for the given username */
ایستا نویسه *
ssh_selinux_getctxbyname(نویسه *pwname)
{
	نویسه *sc = پوچ, *sename = پوچ, *lvl = پوچ;
	صحیح r;

#ifdef HAVE_GETSEUSERBYNAME
	اگر (getseuserbyname(pwname, &sename, &lvl) != 0)
		بازگشت پوچ;
#وگرنه
	sename = pwname;
	lvl = پوچ;
#endif

#ifdef HAVE_GET_DEFAULT_CONTEXT_WITH_LEVEL
	r = get_default_context_with_level(sename, lvl, پوچ, &sc);
#وگرنه
	r = get_default_context(sename, پوچ, &sc);
#endif

	اگر (r != 0) {
		انتخاب (security_getenforce()) {
		حالت -1:
			fatal("%s: ssh_selinux_getctxbyname: "
			    "security_getenforce() failed", __func__);
		حالت 0:
			error("%s: Failed to get default SELinux security "
			    "context for %s", __func__, pwname);
			sc = پوچ;
			بشکن;
		پیشفرض:
			fatal("%s: Failed to get default SELinux security "
			    "context for %s (in enforcing mode)",
			    __func__, pwname);
		}
	}

#ifdef HAVE_GETSEUSERBYNAME
	آزاد(sename);
	آزاد(lvl);
#endif

	بازگشت sc;
}

/* Set the execution context to the default for the specified user */
تهی
ssh_selinux_setup_exec_context(نویسه *pwname)
{
	نویسه *user_ctx = پوچ;

	اگر (!ssh_selinux_enabled())
		بازگشت;

	debug3("%s: setting execution context", __func__);

	user_ctx = ssh_selinux_getctxbyname(pwname);
	اگر (setexeccon(user_ctx) != 0) {
		انتخاب (security_getenforce()) {
		حالت -1:
			fatal("%s: security_getenforce() failed", __func__);
		حالت 0:
			error("%s: Failed to set SELinux execution "
			    "context for %s", __func__, pwname);
			بشکن;
		پیشفرض:
			fatal("%s: Failed to set SELinux execution context "
			    "for %s (in enforcing mode)", __func__, pwname);
		}
	}
	اگر (user_ctx != پوچ)
		freecon(user_ctx);

	debug3("%s: done", __func__);
}

/* Set the TTY context for the specified user */
تهی
ssh_selinux_setup_pty(نویسه *pwname, ثابت نویسه *tty)
{
	نویسه *new_tty_ctx = پوچ, *user_ctx = پوچ, *old_tty_ctx = پوچ;
	security_class_t chrclass;

	اگر (!ssh_selinux_enabled())
		بازگشت;

	debug3("%s: setting TTY context on %s", __func__, tty);

	user_ctx = ssh_selinux_getctxbyname(pwname);

	/* XXX: should these calls fatal() upon failure in enforcing mode? */

	اگر (getfilecon(tty, &old_tty_ctx) == -1) {
		error("%s: getfilecon: %s", __func__, strerror(errno));
		برو out;
	}
	اگر ((chrclass = string_to_security_class("chr_file")) == 0) {
		error("%s: couldn't get security class for chr_file", __func__);
		برو out;
	}
	اگر (security_compute_relabel(user_ctx, old_tty_ctx,
	    chrclass, &new_tty_ctx) != 0) {
		error("%s: security_compute_relabel: %s",
		    __func__, strerror(errno));
		برو out;
	}

	اگر (setfilecon(tty, new_tty_ctx) != 0)
		error("%s: setfilecon: %s", __func__, strerror(errno));
 out:
	اگر (new_tty_ctx != پوچ)
		freecon(new_tty_ctx);
	اگر (old_tty_ctx != پوچ)
		freecon(old_tty_ctx);
	اگر (user_ctx != پوچ)
		freecon(user_ctx);
	debug3("%s: done", __func__);
}

تهی
ssh_selinux_change_context(ثابت نویسه *newname)
{
	نویسه *oldctx, *newctx, *cx, *cx2;
	LogLevel log_level = SYSLOG_LEVEL_INFO;

	اگر (!ssh_selinux_enabled())
		بازگشت;

	اگر (getcon(&oldctx) < 0) {
		logit_f("getcon failed with %s", strerror(errno));
		بازگشت;
	}
	اگر ((cx = strchr(oldctx, ':')) == پوچ ||
	    (cx = strchr(cx + 1, ':')) == پوچ ||
	    (cx - oldctx) >= INT_MAX) {
		logit_f("unparsable context %s", oldctx);
		بازگشت;
	}

	/*
	 * Check whether we are attempting to switch away from an unconfined
	 * security context.
	 */
	اگر (strncmp(cx, SSH_SELINUX_UNCONFINED_TYPE,
	    اندازه(SSH_SELINUX_UNCONFINED_TYPE) - 1) == 0)
		log_level = SYSLOG_LEVEL_DEBUG3;

	cx2 = strchr(cx + 1, ':');
	xasprintf(&newctx, "%.*s%s%s", (صحیح)(cx - oldctx + 1), oldctx,
	    newname, cx2 == پوچ ? "" : cx2);

	debug3_f("setting context from '%s' to '%s'", oldctx, newctx);
	اگر (setcon(newctx) < 0)
		do_log2_f(log_level, "setcon %s from %s failed with %s",
		    newctx, oldctx, strerror(errno));
	آزاد(oldctx);
	آزاد(newctx);
}

تهی
ssh_selinux_setfscreatecon(ثابت نویسه *path)
{
	نویسه *context;
	ساختار selabel_handle *shandle = پوچ;

	اگر (!ssh_selinux_enabled())
		بازگشت;
	اگر (path == پوچ) {
		setfscreatecon(پوچ);
		بازگشت;
	}
	اگر ((shandle = selabel_open(SELABEL_CTX_FILE, پوچ, 0)) == پوچ) {
		debug_f("selabel_open failed");
		بازگشت;
	}
	اگر (selabel_lookup(shandle, &context, path, 0700) == 0)
		setfscreatecon(context);
	selabel_close(shandle);
}

#endif /* WITH_SELINUX */
