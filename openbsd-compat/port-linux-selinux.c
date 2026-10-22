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

#ಅನ್ತರ್ಭಾವ "includes.h"

#ifdef WITH_SELINUX

#ಅನ್ತರ್ಭಾವ <sys/socket.h>
#ಅನ್ತರ್ಭಾವ <sys/un.h>

#ಅನ್ತರ್ಭಾವ <errno.h>
#ಅನ್ತರ್ಭಾವ <stdarg.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>

#ಅನ್ತರ್ಭಾವ "log.h"
#ಅನ್ತರ್ಭಾವ "xmalloc.h"
#ಅನ್ತರ್ಭಾವ "port-linux.h"
#ಅನ್ತರ್ಭಾವ "misc.h"

#ಅನ್ತರ್ಭಾವ <selinux/selinux.h>
#ಅನ್ತರ್ಭಾವ <selinux/label.h>
#ಅನ್ತರ್ಭಾವ <selinux/get_context_list.h>

#ifndef SSH_SELINUX_UNCONFINED_TYPE
# define SSH_SELINUX_UNCONFINED_TYPE ":unconfined_t:"
#endif

/* Wrapper around is_selinux_enabled() to log its return value once only */
ಪೂರ್ಣಾಙ್ಕ
ssh_selinux_enabled(ಶೂನ್ಯ)
{
	ಸ್ಥಿರ ಪೂರ್ಣಾಙ್ಕ enabled = -1;

	ಯದಿ (enabled == -1) {
		enabled = (is_selinux_enabled() == 1);
		debug("SELinux support %s", enabled ? "enabled" : "disabled");
	}

	ಪ್ರತ್ಯಾಗಮ (enabled);
}

/* Return the default security context for the given username */
ಸ್ಥಿರ ವರ್ಣ *
ssh_selinux_getctxbyname(ವರ್ಣ *pwname)
{
	ವರ್ಣ *sc = ರಿಕ್ತ, *sename = ರಿಕ್ತ, *lvl = ರಿಕ್ತ;
	ಪೂರ್ಣಾಙ್ಕ r;

#ifdef HAVE_GETSEUSERBYNAME
	ಯದಿ (getseuserbyname(pwname, &sename, &lvl) != 0)
		ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
#ಅನ್ಯಥಾ
	sename = pwname;
	lvl = ರಿಕ್ತ;
#endif

#ifdef HAVE_GET_DEFAULT_CONTEXT_WITH_LEVEL
	r = get_default_context_with_level(sename, lvl, ರಿಕ್ತ, &sc);
#ಅನ್ಯಥಾ
	r = get_default_context(sename, ರಿಕ್ತ, &sc);
#endif

	ಯದಿ (r != 0) {
		ವಿಕಲ್ಪ (security_getenforce()) {
		ಪಕ್ಷ -1:
			fatal("%s: ssh_selinux_getctxbyname: "
			    "security_getenforce() failed", __func__);
		ಪಕ್ಷ 0:
			error("%s: Failed to get default SELinux security "
			    "context for %s", __func__, pwname);
			sc = ರಿಕ್ತ;
			ಭಙ್ಗ;
		ಸ್ವಭಾವ:
			fatal("%s: Failed to get default SELinux security "
			    "context for %s (in enforcing mode)",
			    __func__, pwname);
		}
	}

#ifdef HAVE_GETSEUSERBYNAME
	ಮುಕ್ತ(sename);
	ಮುಕ್ತ(lvl);
#endif

	ಪ್ರತ್ಯಾಗಮ sc;
}

/* Set the execution context to the default for the specified user */
ಶೂನ್ಯ
ssh_selinux_setup_exec_context(ವರ್ಣ *pwname)
{
	ವರ್ಣ *user_ctx = ರಿಕ್ತ;

	ಯದಿ (!ssh_selinux_enabled())
		ಪ್ರತ್ಯಾಗಮ;

	debug3("%s: setting execution context", __func__);

	user_ctx = ssh_selinux_getctxbyname(pwname);
	ಯದಿ (setexeccon(user_ctx) != 0) {
		ವಿಕಲ್ಪ (security_getenforce()) {
		ಪಕ್ಷ -1:
			fatal("%s: security_getenforce() failed", __func__);
		ಪಕ್ಷ 0:
			error("%s: Failed to set SELinux execution "
			    "context for %s", __func__, pwname);
			ಭಙ್ಗ;
		ಸ್ವಭಾವ:
			fatal("%s: Failed to set SELinux execution context "
			    "for %s (in enforcing mode)", __func__, pwname);
		}
	}
	ಯದಿ (user_ctx != ರಿಕ್ತ)
		freecon(user_ctx);

	debug3("%s: done", __func__);
}

/* Set the TTY context for the specified user */
ಶೂನ್ಯ
ssh_selinux_setup_pty(ವರ್ಣ *pwname, ಧ್ರುವ ವರ್ಣ *tty)
{
	ವರ್ಣ *new_tty_ctx = ರಿಕ್ತ, *user_ctx = ರಿಕ್ತ, *old_tty_ctx = ರಿಕ್ತ;
	security_class_t chrclass;

	ಯದಿ (!ssh_selinux_enabled())
		ಪ್ರತ್ಯಾಗಮ;

	debug3("%s: setting TTY context on %s", __func__, tty);

	user_ctx = ssh_selinux_getctxbyname(pwname);

	/* XXX: should these calls fatal() upon failure in enforcing mode? */

	ಯದಿ (getfilecon(tty, &old_tty_ctx) == -1) {
		error("%s: getfilecon: %s", __func__, strerror(errno));
		ಗಚ್ಛ out;
	}
	ಯದಿ ((chrclass = string_to_security_class("chr_file")) == 0) {
		error("%s: couldn't get security class for chr_file", __func__);
		ಗಚ್ಛ out;
	}
	ಯದಿ (security_compute_relabel(user_ctx, old_tty_ctx,
	    chrclass, &new_tty_ctx) != 0) {
		error("%s: security_compute_relabel: %s",
		    __func__, strerror(errno));
		ಗಚ್ಛ out;
	}

	ಯದಿ (setfilecon(tty, new_tty_ctx) != 0)
		error("%s: setfilecon: %s", __func__, strerror(errno));
 out:
	ಯದಿ (new_tty_ctx != ರಿಕ್ತ)
		freecon(new_tty_ctx);
	ಯದಿ (old_tty_ctx != ರಿಕ್ತ)
		freecon(old_tty_ctx);
	ಯದಿ (user_ctx != ರಿಕ್ತ)
		freecon(user_ctx);
	debug3("%s: done", __func__);
}

ಶೂನ್ಯ
ssh_selinux_change_context(ಧ್ರುವ ವರ್ಣ *newname)
{
	ವರ್ಣ *oldctx, *newctx, *cx, *cx2;
	LogLevel log_level = SYSLOG_LEVEL_INFO;

	ಯದಿ (!ssh_selinux_enabled())
		ಪ್ರತ್ಯಾಗಮ;

	ಯದಿ (getcon(&oldctx) < 0) {
		logit_f("getcon failed with %s", strerror(errno));
		ಪ್ರತ್ಯಾಗಮ;
	}
	ಯದಿ ((cx = strchr(oldctx, ':')) == ರಿಕ್ತ ||
	    (cx = strchr(cx + 1, ':')) == ರಿಕ್ತ ||
	    (cx - oldctx) >= INT_MAX) {
		logit_f("unparsable context %s", oldctx);
		ಪ್ರತ್ಯಾಗಮ;
	}

	/*
	 * Check whether we are attempting to switch away from an unconfined
	 * security context.
	 */
	ಯದಿ (strncmp(cx, SSH_SELINUX_UNCONFINED_TYPE,
	    ಪರಿಮಾಣ(SSH_SELINUX_UNCONFINED_TYPE) - 1) == 0)
		log_level = SYSLOG_LEVEL_DEBUG3;

	cx2 = strchr(cx + 1, ':');
	xasprintf(&newctx, "%.*s%s%s", (ಪೂರ್ಣಾಙ್ಕ)(cx - oldctx + 1), oldctx,
	    newname, cx2 == ರಿಕ್ತ ? "" : cx2);

	debug3_f("setting context from '%s' to '%s'", oldctx, newctx);
	ಯದಿ (setcon(newctx) < 0)
		do_log2_f(log_level, "setcon %s from %s failed with %s",
		    newctx, oldctx, strerror(errno));
	ಮುಕ್ತ(oldctx);
	ಮುಕ್ತ(newctx);
}

ಶೂನ್ಯ
ssh_selinux_setfscreatecon(ಧ್ರುವ ವರ್ಣ *path)
{
	ವರ್ಣ *context;
	ಸಂರಚನಾ selabel_handle *shandle = ರಿಕ್ತ;

	ಯದಿ (!ssh_selinux_enabled())
		ಪ್ರತ್ಯಾಗಮ;
	ಯದಿ (path == ರಿಕ್ತ) {
		setfscreatecon(ರಿಕ್ತ);
		ಪ್ರತ್ಯಾಗಮ;
	}
	ಯದಿ ((shandle = selabel_open(SELABEL_CTX_FILE, ರಿಕ್ತ, 0)) == ರಿಕ್ತ) {
		debug_f("selabel_open failed");
		ಪ್ರತ್ಯಾಗಮ;
	}
	ಯದಿ (selabel_lookup(shandle, &context, path, 0700) == 0)
		setfscreatecon(context);
	selabel_close(shandle);
}

#endif /* WITH_SELINUX */
