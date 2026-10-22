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

#اگر_تعریف_شدہ WITH_SELINUX

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

#اگر_غیر_تعریف_شدہ SSH_SELINUX_UNCONFINED_TYPE
# define SSH_SELINUX_UNCONFINED_TYPE ":unconfined_t:"
#اگر_ختم

/* Wrapper around is_selinux_enabled() to log its return value once only */
صحیح
ssh_selinux_enabled(خالی)
{
	ساکن صحیح enabled = -1;

	اگر (enabled == -1) {
		enabled = (is_selinux_enabled() == 1);
		debug("SELinux support %s", enabled ? "enabled" : "disabled");
	}

	واپس (enabled);
}

/* Return the default security context for the given username */
ساکن حرف *
ssh_selinux_getctxbyname(حرف *pwname)
{
	حرف *sc = تہی, *sename = تہی, *lvl = تہی;
	صحیح r;

#اگر_تعریف_شدہ HAVE_GETSEUSERBYNAME
	اگر (getseuserbyname(pwname, &sename, &lvl) != 0)
		واپس تہی;
#ورنہ
	sename = pwname;
	lvl = تہی;
#اگر_ختم

#اگر_تعریف_شدہ HAVE_GET_DEFAULT_CONTEXT_WITH_LEVEL
	r = get_default_context_with_level(sename, lvl, تہی, &sc);
#ورنہ
	r = get_default_context(sename, تہی, &sc);
#اگر_ختم

	اگر (r != 0) {
		انتخاب (security_getenforce()) {
		حالت -1:
			fatal("%s: ssh_selinux_getctxbyname: "
			    "security_getenforce() failed", __func__);
		حالت 0:
			error("%s: Failed to get default SELinux security "
			    "context for %s", __func__, pwname);
			sc = تہی;
			توڑو;
		طےشدہ:
			fatal("%s: Failed to get default SELinux security "
			    "context for %s (in enforcing mode)",
			    __func__, pwname);
		}
	}

#اگر_تعریف_شدہ HAVE_GETSEUSERBYNAME
	آزاد(sename);
	آزاد(lvl);
#اگر_ختم

	واپس sc;
}

/* Set the execution context to the default for the specified user */
خالی
ssh_selinux_تیاری_exec_context(حرف *pwname)
{
	حرف *user_ctx = تہی;

	اگر (!ssh_selinux_enabled())
		واپس;

	debug3("%s: setting execution context", __func__);

	user_ctx = ssh_selinux_getctxbyname(pwname);
	اگر (setexeccon(user_ctx) != 0) {
		انتخاب (security_getenforce()) {
		حالت -1:
			fatal("%s: security_getenforce() failed", __func__);
		حالت 0:
			error("%s: Failed to set SELinux execution "
			    "context for %s", __func__, pwname);
			توڑو;
		طےشدہ:
			fatal("%s: Failed to set SELinux execution context "
			    "for %s (in enforcing mode)", __func__, pwname);
		}
	}
	اگر (user_ctx != تہی)
		freecon(user_ctx);

	debug3("%s: done", __func__);
}

/* Set the TTY context for the specified user */
خالی
ssh_selinux_تیاری_pty(حرف *pwname, ثابت حرف *tty)
{
	حرف *new_tty_ctx = تہی, *user_ctx = تہی, *old_tty_ctx = تہی;
	security_class_t chrclass;

	اگر (!ssh_selinux_enabled())
		واپس;

	debug3("%s: setting TTY context on %s", __func__, tty);

	user_ctx = ssh_selinux_getctxbyname(pwname);

	/* XXX: should these calls fatal() upon failure in enforcing mode? */

	اگر (getfilecon(tty, &old_tty_ctx) == -1) {
		error("%s: getfilecon: %s", __func__, strerror(errno));
		جاؤ برآمد;
	}
	اگر ((chrclass = string_مقصد_security_class("chr_file")) == 0) {
		error("%s: couldn't get security class for chr_file", __func__);
		جاؤ برآمد;
	}
	اگر (security_compute_relabel(user_ctx, old_tty_ctx,
	    chrclass, &new_tty_ctx) != 0) {
		error("%s: security_compute_relabel: %s",
		    __func__, strerror(errno));
		جاؤ برآمد;
	}

	اگر (setfilecon(tty, new_tty_ctx) != 0)
		error("%s: setfilecon: %s", __func__, strerror(errno));
 برآمد:
	اگر (new_tty_ctx != تہی)
		freecon(new_tty_ctx);
	اگر (old_tty_ctx != تہی)
		freecon(old_tty_ctx);
	اگر (user_ctx != تہی)
		freecon(user_ctx);
	debug3("%s: done", __func__);
}

خالی
ssh_selinux_change_context(ثابت حرف *newname)
{
	حرف *oldctx, *newctx, *cx, *cx2;
	LogLevel log_level = SYSLOG_LEVEL_INFO;

	اگر (!ssh_selinux_enabled())
		واپس;

	اگر (getcon(&oldctx) < 0) {
		logit_f("getcon failed with %s", strerror(errno));
		واپس;
	}
	اگر ((cx = strchr(oldctx, ':')) == تہی ||
	    (cx = strchr(cx + 1, ':')) == تہی ||
	    (cx - oldctx) >= زیادہ_سے_زیادہ_عدد) {
		logit_f("unparsable context %s", oldctx);
		واپس;
	}

	/*
	 * Check whether we are attempting to switch away from an unconfined
	 * security context.
	 */
	اگر (لڑی_موازنہ(cx, SSH_SELINUX_UNCONFINED_TYPE,
	    حجم(SSH_SELINUX_UNCONFINED_TYPE) - 1) == 0)
		log_level = SYSLOG_LEVEL_DEBUG3;

	cx2 = strchr(cx + 1, ':');
	xasprintf(&newctx, "%.*s%s%s", (صحیح)(cx - oldctx + 1), oldctx,
	    newname, cx2 == تہی ? "" : cx2);

	debug3_f("setting context from '%s' to '%s'", oldctx, newctx);
	اگر (setcon(newctx) < 0)
		do_log2_f(log_level, "setcon %s from %s failed with %s",
		    newctx, oldctx, strerror(errno));
	آزاد(oldctx);
	آزاد(newctx);
}

خالی
ssh_selinux_setfscreatecon(ثابت حرف *راستہ)
{
	حرف *context;
	ساخت selabel_handle *shandle = تہی;

	اگر (!ssh_selinux_enabled())
		واپس;
	اگر (راستہ == تہی) {
		setfscreatecon(تہی);
		واپس;
	}
	اگر ((shandle = selabel_open(SELABEL_CTX_FILE, تہی, 0)) == تہی) {
		debug_f("selabel_open failed");
		واپس;
	}
	اگر (selabel_lookup(shandle, &context, راستہ, 0700) == 0)
		setfscreatecon(context);
	selabel_close(shandle);
}

#اگر_ختم /* WITH_SELINUX */
