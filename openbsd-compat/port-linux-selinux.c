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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ WITH_SELINUX

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/socket.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/un.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <errno.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdarg.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "log.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "xmalloc.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "port-linux.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "misc.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <selinux/selinux.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <selinux/label.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <selinux/get_context_list.h>

#ਜੇ_ਅਪਰਿਭਾਸ਼ਿਤ SSH_SELINUX_UNCONFINED_TYPE
# define SSH_SELINUX_UNCONFINED_TYPE ":unconfined_t:"
#ਜੇ_ਅੰਤ

/* Wrapper around is_selinux_enabled() to log its return value once only */
ਪੂਰਨ
ssh_selinux_enabled(ਖਾਲੀ)
{
	ਸਥਿਰ ਪੂਰਨ enabled = -1;

	ਜੇ (enabled == -1) {
		enabled = (is_selinux_enabled() == 1);
		debug("SELinux support %s", enabled ? "enabled" : "disabled");
	}

	ਵਾਪਸ (enabled);
}

/* Return the default security context for the given username */
ਸਥਿਰ ਅੱਖਰ *
ssh_selinux_getctxbyname(ਅੱਖਰ *pwname)
{
	ਅੱਖਰ *sc = ਨਿਰਾ, *sename = ਨਿਰਾ, *lvl = ਨਿਰਾ;
	ਪੂਰਨ r;

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_GETSEUSERBYNAME
	ਜੇ (getseuserbyname(pwname, &sename, &lvl) != 0)
		ਵਾਪਸ ਨਿਰਾ;
#ਨਹੀਂਤਾਂ
	sename = pwname;
	lvl = ਨਿਰਾ;
#ਜੇ_ਅੰਤ

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_GET_DEFAULT_CONTEXT_WITH_LEVEL
	r = get_default_context_with_level(sename, lvl, ਨਿਰਾ, &sc);
#ਨਹੀਂਤਾਂ
	r = get_default_context(sename, ਨਿਰਾ, &sc);
#ਜੇ_ਅੰਤ

	ਜੇ (r != 0) {
		ਚੋਣ (security_getenforce()) {
		ਹਾਲਤ -1:
			fatal("%s: ssh_selinux_getctxbyname: "
			    "security_getenforce() failed", __func__);
		ਹਾਲਤ 0:
			error("%s: Failed to get default SELinux security "
			    "context for %s", __func__, pwname);
			sc = ਨਿਰਾ;
			ਰੋਕੋ;
		ਮੂਲ:
			fatal("%s: Failed to get default SELinux security "
			    "context for %s (in enforcing mode)",
			    __func__, pwname);
		}
	}

#ਜੇ_ਪਰਿਭਾਸ਼ਿਤ HAVE_GETSEUSERBYNAME
	ਮੁਕਤ(sename);
	ਮੁਕਤ(lvl);
#ਜੇ_ਅੰਤ

	ਵਾਪਸ sc;
}

/* Set the execution context to the default for the specified user */
ਖਾਲੀ
ssh_selinux_ਤਿਆਰੀ_exec_context(ਅੱਖਰ *pwname)
{
	ਅੱਖਰ *user_ctx = ਨਿਰਾ;

	ਜੇ (!ssh_selinux_enabled())
		ਵਾਪਸ;

	debug3("%s: setting execution context", __func__);

	user_ctx = ssh_selinux_getctxbyname(pwname);
	ਜੇ (setexeccon(user_ctx) != 0) {
		ਚੋਣ (security_getenforce()) {
		ਹਾਲਤ -1:
			fatal("%s: security_getenforce() failed", __func__);
		ਹਾਲਤ 0:
			error("%s: Failed to set SELinux execution "
			    "context for %s", __func__, pwname);
			ਰੋਕੋ;
		ਮੂਲ:
			fatal("%s: Failed to set SELinux execution context "
			    "for %s (in enforcing mode)", __func__, pwname);
		}
	}
	ਜੇ (user_ctx != ਨਿਰਾ)
		freecon(user_ctx);

	debug3("%s: done", __func__);
}

/* Set the TTY context for the specified user */
ਖਾਲੀ
ssh_selinux_ਤਿਆਰੀ_pty(ਅੱਖਰ *pwname, ਅਚਲ ਅੱਖਰ *tty)
{
	ਅੱਖਰ *new_tty_ctx = ਨਿਰਾ, *user_ctx = ਨਿਰਾ, *old_tty_ctx = ਨਿਰਾ;
	security_class_t chrclass;

	ਜੇ (!ssh_selinux_enabled())
		ਵਾਪਸ;

	debug3("%s: setting TTY context on %s", __func__, tty);

	user_ctx = ssh_selinux_getctxbyname(pwname);

	/* XXX: should these calls fatal() upon failure in enforcing mode? */

	ਜੇ (getfilecon(tty, &old_tty_ctx) == -1) {
		error("%s: getfilecon: %s", __func__, strerror(errno));
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ ((chrclass = string_ਮੰਜ਼ਿਲ_security_class("chr_file")) == 0) {
		error("%s: couldn't get security class for chr_file", __func__);
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ (security_compute_relabel(user_ctx, old_tty_ctx,
	    chrclass, &new_tty_ctx) != 0) {
		error("%s: security_compute_relabel: %s",
		    __func__, strerror(errno));
		ਜਾਓ ਬਾਹਰਲਾ;
	}

	ਜੇ (setfilecon(tty, new_tty_ctx) != 0)
		error("%s: setfilecon: %s", __func__, strerror(errno));
 ਬਾਹਰਲਾ:
	ਜੇ (new_tty_ctx != ਨਿਰਾ)
		freecon(new_tty_ctx);
	ਜੇ (old_tty_ctx != ਨਿਰਾ)
		freecon(old_tty_ctx);
	ਜੇ (user_ctx != ਨਿਰਾ)
		freecon(user_ctx);
	debug3("%s: done", __func__);
}

ਖਾਲੀ
ssh_selinux_change_context(ਅਚਲ ਅੱਖਰ *newname)
{
	ਅੱਖਰ *oldctx, *newctx, *cx, *cx2;
	LogLevel log_level = SYSLOG_LEVEL_INFO;

	ਜੇ (!ssh_selinux_enabled())
		ਵਾਪਸ;

	ਜੇ (getcon(&oldctx) < 0) {
		logit_f("getcon failed with %s", strerror(errno));
		ਵਾਪਸ;
	}
	ਜੇ ((cx = strchr(oldctx, ':')) == ਨਿਰਾ ||
	    (cx = strchr(cx + 1, ':')) == ਨਿਰਾ ||
	    (cx - oldctx) >= ਵੱਧ_ਤੋਂ_ਵੱਧ_ਅੰਕ) {
		logit_f("unparsable context %s", oldctx);
		ਵਾਪਸ;
	}

	/*
	 * Check whether we are attempting to switch away from an unconfined
	 * security context.
	 */
	ਜੇ (ਲੜੀ_ਤੁਲਨਾ(cx, SSH_SELINUX_UNCONFINED_TYPE,
	    ਆਕਾਰ(SSH_SELINUX_UNCONFINED_TYPE) - 1) == 0)
		log_level = SYSLOG_LEVEL_DEBUG3;

	cx2 = strchr(cx + 1, ':');
	xasprintf(&newctx, "%.*s%s%s", (ਪੂਰਨ)(cx - oldctx + 1), oldctx,
	    newname, cx2 == ਨਿਰਾ ? "" : cx2);

	debug3_f("setting context from '%s' to '%s'", oldctx, newctx);
	ਜੇ (setcon(newctx) < 0)
		do_log2_f(log_level, "setcon %s from %s failed with %s",
		    newctx, oldctx, strerror(errno));
	ਮੁਕਤ(oldctx);
	ਮੁਕਤ(newctx);
}

ਖਾਲੀ
ssh_selinux_setfscreatecon(ਅਚਲ ਅੱਖਰ *ਰਸਤਾ)
{
	ਅੱਖਰ *context;
	ਬਣਤਰ selabel_handle *shandle = ਨਿਰਾ;

	ਜੇ (!ssh_selinux_enabled())
		ਵਾਪਸ;
	ਜੇ (ਰਸਤਾ == ਨਿਰਾ) {
		setfscreatecon(ਨਿਰਾ);
		ਵਾਪਸ;
	}
	ਜੇ ((shandle = selabel_open(SELABEL_CTX_FILE, ਨਿਰਾ, 0)) == ਨਿਰਾ) {
		debug_f("selabel_open failed");
		ਵਾਪਸ;
	}
	ਜੇ (selabel_lookup(shandle, &context, ਰਸਤਾ, 0700) == 0)
		setfscreatecon(context);
	selabel_close(shandle);
}

#ਜੇ_ਅੰਤ /* WITH_SELINUX */
