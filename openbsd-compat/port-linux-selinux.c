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

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ WITH_SELINUX

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

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ SSH_SELINUX_UNCONFINED_TYPE
# define SSH_SELINUX_UNCONFINED_TYPE ":unconfined_t:"
#ಆದರೆ_ಅಂತ್ಯ

/* Wrapper around is_selinux_enabled() to log its return value once only */
ಪೂರ್ಣಾಂಕ
ssh_selinux_enabled(ಶೂನ್ಯ)
{
	ಸ್ಥಿರ ಪೂರ್ಣಾಂಕ enabled = -1;

	ಆದರೆ (enabled == -1) {
		enabled = (is_selinux_enabled() == 1);
		debug("SELinux support %s", enabled ? "enabled" : "disabled");
	}

	ಹಿಂತಿರುಗಿ (enabled);
}

/* Return the default security context for the given username */
ಸ್ಥಿರ ಅಕ್ಷರ *
ssh_selinux_getctxbyname(ಅಕ್ಷರ *pwname)
{
	ಅಕ್ಷರ *sc = ಖಾಲಿ, *sename = ಖಾಲಿ, *lvl = ಖಾಲಿ;
	ಪೂರ್ಣಾಂಕ r;

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_GETSEUSERBYNAME
	ಆದರೆ (getseuserbyname(pwname, &sename, &lvl) != 0)
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;
#ಇಲ್ಲದಿದ್ದರೆ
	sename = pwname;
	lvl = ಖಾಲಿ;
#ಆದರೆ_ಅಂತ್ಯ

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_GET_DEFAULT_CONTEXT_WITH_LEVEL
	r = get_default_context_with_level(sename, lvl, ಖಾಲಿ, &sc);
#ಇಲ್ಲದಿದ್ದರೆ
	r = get_default_context(sename, ಖಾಲಿ, &sc);
#ಆದರೆ_ಅಂತ್ಯ

	ಆದರೆ (r != 0) {
		ಆಯ್ಕೆ (security_getenforce()) {
		ಸ್ಥಿತಿ -1:
			fatal("%s: ssh_selinux_getctxbyname: "
			    "security_getenforce() failed", __func__);
		ಸ್ಥಿತಿ 0:
			error("%s: Failed to get default SELinux security "
			    "context for %s", __func__, pwname);
			sc = ಖಾಲಿ;
			ನಿಲ್ಲಿಸು;
		ಪೂರ್ವನಿಯೋಜಿತ:
			fatal("%s: Failed to get default SELinux security "
			    "context for %s (in enforcing mode)",
			    __func__, pwname);
		}
	}

#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ HAVE_GETSEUSERBYNAME
	ಬಿಡುಗಡೆ(sename);
	ಬಿಡುಗಡೆ(lvl);
#ಆದರೆ_ಅಂತ್ಯ

	ಹಿಂತಿರುಗಿ sc;
}

/* Set the execution context to the default for the specified user */
ಶೂನ್ಯ
ssh_selinux_ಸಿದ್ಧತೆ_exec_context(ಅಕ್ಷರ *pwname)
{
	ಅಕ್ಷರ *user_ctx = ಖಾಲಿ;

	ಆದರೆ (!ssh_selinux_enabled())
		ಹಿಂತಿರುಗಿ;

	debug3("%s: setting execution context", __func__);

	user_ctx = ssh_selinux_getctxbyname(pwname);
	ಆದರೆ (setexeccon(user_ctx) != 0) {
		ಆಯ್ಕೆ (security_getenforce()) {
		ಸ್ಥಿತಿ -1:
			fatal("%s: security_getenforce() failed", __func__);
		ಸ್ಥಿತಿ 0:
			error("%s: Failed to set SELinux execution "
			    "context for %s", __func__, pwname);
			ನಿಲ್ಲಿಸು;
		ಪೂರ್ವನಿಯೋಜಿತ:
			fatal("%s: Failed to set SELinux execution context "
			    "for %s (in enforcing mode)", __func__, pwname);
		}
	}
	ಆದರೆ (user_ctx != ಖಾಲಿ)
		freecon(user_ctx);

	debug3("%s: done", __func__);
}

/* Set the TTY context for the specified user */
ಶೂನ್ಯ
ssh_selinux_ಸಿದ್ಧತೆ_pty(ಅಕ್ಷರ *pwname, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *tty)
{
	ಅಕ್ಷರ *new_tty_ctx = ಖಾಲಿ, *user_ctx = ಖಾಲಿ, *old_tty_ctx = ಖಾಲಿ;
	security_class_t chrclass;

	ಆದರೆ (!ssh_selinux_enabled())
		ಹಿಂತಿರುಗಿ;

	debug3("%s: setting TTY context on %s", __func__, tty);

	user_ctx = ssh_selinux_getctxbyname(pwname);

	/* XXX: should these calls fatal() upon failure in enforcing mode? */

	ಆದರೆ (getfilecon(tty, &old_tty_ctx) == -1) {
		error("%s: getfilecon: %s", __func__, strerror(errno));
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ ((chrclass = string_ಗಮ್ಯ_security_class("chr_file")) == 0) {
		error("%s: couldn't get security class for chr_file", __func__);
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ (security_compute_relabel(user_ctx, old_tty_ctx,
	    chrclass, &new_tty_ctx) != 0) {
		error("%s: security_compute_relabel: %s",
		    __func__, strerror(errno));
		ಹೋಗು ಹೊರಹೋಗು;
	}

	ಆದರೆ (setfilecon(tty, new_tty_ctx) != 0)
		error("%s: setfilecon: %s", __func__, strerror(errno));
 ಹೊರಹೋಗು:
	ಆದರೆ (new_tty_ctx != ಖಾಲಿ)
		freecon(new_tty_ctx);
	ಆದರೆ (old_tty_ctx != ಖಾಲಿ)
		freecon(old_tty_ctx);
	ಆದರೆ (user_ctx != ಖಾಲಿ)
		freecon(user_ctx);
	debug3("%s: done", __func__);
}

ಶೂನ್ಯ
ssh_selinux_change_context(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *newname)
{
	ಅಕ್ಷರ *oldctx, *newctx, *cx, *cx2;
	LogLevel log_level = SYSLOG_LEVEL_INFO;

	ಆದರೆ (!ssh_selinux_enabled())
		ಹಿಂತಿರುಗಿ;

	ಆದರೆ (getcon(&oldctx) < 0) {
		logit_f("getcon failed with %s", strerror(errno));
		ಹಿಂತಿರುಗಿ;
	}
	ಆದರೆ ((cx = strchr(oldctx, ':')) == ಖಾಲಿ ||
	    (cx = strchr(cx + 1, ':')) == ಖಾಲಿ ||
	    (cx - oldctx) >= ಗರಿಷ್ಠ_ಪೂರ್ಣಾಂಕ) {
		logit_f("unparsable context %s", oldctx);
		ಹಿಂತಿರುಗಿ;
	}

	/*
	 * Check whether we are attempting to switch away from an unconfined
	 * security context.
	 */
	ಆದರೆ (ಅಕ್ಷರಸರಣಿ_ಹೋಲಿಕೆ(cx, SSH_SELINUX_UNCONFINED_TYPE,
	    ಗಾತ್ರ(SSH_SELINUX_UNCONFINED_TYPE) - 1) == 0)
		log_level = SYSLOG_LEVEL_DEBUG3;

	cx2 = strchr(cx + 1, ':');
	xasprintf(&newctx, "%.*s%s%s", (ಪೂರ್ಣಾಂಕ)(cx - oldctx + 1), oldctx,
	    newname, cx2 == ಖಾಲಿ ? "" : cx2);

	debug3_f("setting context from '%s' to '%s'", oldctx, newctx);
	ಆದರೆ (setcon(newctx) < 0)
		do_log2_f(log_level, "setcon %s from %s failed with %s",
		    newctx, oldctx, strerror(errno));
	ಬಿಡುಗಡೆ(oldctx);
	ಬಿಡುಗಡೆ(newctx);
}

ಶೂನ್ಯ
ssh_selinux_setfscreatecon(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಮಾರ್ಗ)
{
	ಅಕ್ಷರ *context;
	ರಚನೆ selabel_handle *shandle = ಖಾಲಿ;

	ಆದರೆ (!ssh_selinux_enabled())
		ಹಿಂತಿರುಗಿ;
	ಆದರೆ (ಮಾರ್ಗ == ಖಾಲಿ) {
		setfscreatecon(ಖಾಲಿ);
		ಹಿಂತಿರುಗಿ;
	}
	ಆದರೆ ((shandle = selabel_open(SELABEL_CTX_FILE, ಖಾಲಿ, 0)) == ಖಾಲಿ) {
		debug_f("selabel_open failed");
		ಹಿಂತಿರುಗಿ;
	}
	ಆದರೆ (selabel_lookup(shandle, &context, ಮಾರ್ಗ, 0700) == 0)
		setfscreatecon(context);
	selabel_close(shandle);
}

#ಆದರೆ_ಅಂತ್ಯ /* WITH_SELINUX */
