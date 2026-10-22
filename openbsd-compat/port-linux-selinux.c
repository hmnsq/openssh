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

#അന്തര്ഭാവ "includes.h"

#ifdef WITH_SELINUX

#അന്തര്ഭാവ <sys/socket.h>
#അന്തര്ഭാവ <sys/un.h>

#അന്തര്ഭാവ <errno.h>
#അന്തര്ഭാവ <stdarg.h>
#അന്തര്ഭാവ <string.h>
#അന്തര്ഭാവ <stdio.h>
#അന്തര്ഭാവ <stdlib.h>

#അന്തര്ഭാവ "log.h"
#അന്തര്ഭാവ "xmalloc.h"
#അന്തര്ഭാവ "port-linux.h"
#അന്തര്ഭാവ "misc.h"

#അന്തര്ഭാവ <selinux/selinux.h>
#അന്തര്ഭാവ <selinux/label.h>
#അന്തര്ഭാവ <selinux/get_context_list.h>

#ifndef SSH_SELINUX_UNCONFINED_TYPE
# define SSH_SELINUX_UNCONFINED_TYPE ":unconfined_t:"
#endif

/* Wrapper around is_selinux_enabled() to log its return value once only */
പൂർണ്ണസംഖ്യ
ssh_selinux_enabled(ശൂന്യം)
{
	സ്ഥിതം പൂർണ്ണസംഖ്യ enabled = -1;

	എങ്കിൽ (enabled == -1) {
		enabled = (is_selinux_enabled() == 1);
		debug("SELinux support %s", enabled ? "enabled" : "disabled");
	}

	തിരികെ (enabled);
}

/* Return the default security context for the given username */
സ്ഥിതം അക്ഷരം *
ssh_selinux_getctxbyname(അക്ഷരം *pwname)
{
	അക്ഷരം *sc = ശൂന്യ, *sename = ശൂന്യ, *lvl = ശൂന്യ;
	പൂർണ്ണസംഖ്യ r;

#ifdef HAVE_GETSEUSERBYNAME
	എങ്കിൽ (getseuserbyname(pwname, &sename, &lvl) != 0)
		തിരികെ ശൂന്യ;
#അല്ലെങ്കിൽ
	sename = pwname;
	lvl = ശൂന്യ;
#endif

#ifdef HAVE_GET_DEFAULT_CONTEXT_WITH_LEVEL
	r = get_default_context_with_level(sename, lvl, ശൂന്യ, &sc);
#അല്ലെങ്കിൽ
	r = get_default_context(sename, ശൂന്യ, &sc);
#endif

	എങ്കിൽ (r != 0) {
		തിരഞ്ഞെടുപ്പ് (security_getenforce()) {
		അവസ്ഥ -1:
			fatal("%s: ssh_selinux_getctxbyname: "
			    "security_getenforce() failed", __func__);
		അവസ്ഥ 0:
			error("%s: Failed to get default SELinux security "
			    "context for %s", __func__, pwname);
			sc = ശൂന്യ;
			നിർത്തുക;
		സ്ഥിരസ്ഥിതി:
			fatal("%s: Failed to get default SELinux security "
			    "context for %s (in enforcing mode)",
			    __func__, pwname);
		}
	}

#ifdef HAVE_GETSEUSERBYNAME
	സ്വതന്ത്രം(sename);
	സ്വതന്ത്രം(lvl);
#endif

	തിരികെ sc;
}

/* Set the execution context to the default for the specified user */
ശൂന്യം
ssh_selinux_setup_exec_context(അക്ഷരം *pwname)
{
	അക്ഷരം *user_ctx = ശൂന്യ;

	എങ്കിൽ (!ssh_selinux_enabled())
		തിരികെ;

	debug3("%s: setting execution context", __func__);

	user_ctx = ssh_selinux_getctxbyname(pwname);
	എങ്കിൽ (setexeccon(user_ctx) != 0) {
		തിരഞ്ഞെടുപ്പ് (security_getenforce()) {
		അവസ്ഥ -1:
			fatal("%s: security_getenforce() failed", __func__);
		അവസ്ഥ 0:
			error("%s: Failed to set SELinux execution "
			    "context for %s", __func__, pwname);
			നിർത്തുക;
		സ്ഥിരസ്ഥിതി:
			fatal("%s: Failed to set SELinux execution context "
			    "for %s (in enforcing mode)", __func__, pwname);
		}
	}
	എങ്കിൽ (user_ctx != ശൂന്യ)
		freecon(user_ctx);

	debug3("%s: done", __func__);
}

/* Set the TTY context for the specified user */
ശൂന്യം
ssh_selinux_setup_pty(അക്ഷരം *pwname, സ്ഥിരം അക്ഷരം *tty)
{
	അക്ഷരം *new_tty_ctx = ശൂന്യ, *user_ctx = ശൂന്യ, *old_tty_ctx = ശൂന്യ;
	security_class_t chrclass;

	എങ്കിൽ (!ssh_selinux_enabled())
		തിരികെ;

	debug3("%s: setting TTY context on %s", __func__, tty);

	user_ctx = ssh_selinux_getctxbyname(pwname);

	/* XXX: should these calls fatal() upon failure in enforcing mode? */

	എങ്കിൽ (getfilecon(tty, &old_tty_ctx) == -1) {
		error("%s: getfilecon: %s", __func__, strerror(errno));
		പോകുക out;
	}
	എങ്കിൽ ((chrclass = string_to_security_class("chr_file")) == 0) {
		error("%s: couldn't get security class for chr_file", __func__);
		പോകുക out;
	}
	എങ്കിൽ (security_compute_relabel(user_ctx, old_tty_ctx,
	    chrclass, &new_tty_ctx) != 0) {
		error("%s: security_compute_relabel: %s",
		    __func__, strerror(errno));
		പോകുക out;
	}

	എങ്കിൽ (setfilecon(tty, new_tty_ctx) != 0)
		error("%s: setfilecon: %s", __func__, strerror(errno));
 out:
	എങ്കിൽ (new_tty_ctx != ശൂന്യ)
		freecon(new_tty_ctx);
	എങ്കിൽ (old_tty_ctx != ശൂന്യ)
		freecon(old_tty_ctx);
	എങ്കിൽ (user_ctx != ശൂന്യ)
		freecon(user_ctx);
	debug3("%s: done", __func__);
}

ശൂന്യം
ssh_selinux_change_context(സ്ഥിരം അക്ഷരം *newname)
{
	അക്ഷരം *oldctx, *newctx, *cx, *cx2;
	LogLevel log_level = SYSLOG_LEVEL_INFO;

	എങ്കിൽ (!ssh_selinux_enabled())
		തിരികെ;

	എങ്കിൽ (getcon(&oldctx) < 0) {
		logit_f("getcon failed with %s", strerror(errno));
		തിരികെ;
	}
	എങ്കിൽ ((cx = strchr(oldctx, ':')) == ശൂന്യ ||
	    (cx = strchr(cx + 1, ':')) == ശൂന്യ ||
	    (cx - oldctx) >= INT_MAX) {
		logit_f("unparsable context %s", oldctx);
		തിരികെ;
	}

	/*
	 * Check whether we are attempting to switch away from an unconfined
	 * security context.
	 */
	എങ്കിൽ (strncmp(cx, SSH_SELINUX_UNCONFINED_TYPE,
	    വലുപ്പം(SSH_SELINUX_UNCONFINED_TYPE) - 1) == 0)
		log_level = SYSLOG_LEVEL_DEBUG3;

	cx2 = strchr(cx + 1, ':');
	xasprintf(&newctx, "%.*s%s%s", (പൂർണ്ണസംഖ്യ)(cx - oldctx + 1), oldctx,
	    newname, cx2 == ശൂന്യ ? "" : cx2);

	debug3_f("setting context from '%s' to '%s'", oldctx, newctx);
	എങ്കിൽ (setcon(newctx) < 0)
		do_log2_f(log_level, "setcon %s from %s failed with %s",
		    newctx, oldctx, strerror(errno));
	സ്വതന്ത്രം(oldctx);
	സ്വതന്ത്രം(newctx);
}

ശൂന്യം
ssh_selinux_setfscreatecon(സ്ഥിരം അക്ഷരം *path)
{
	അക്ഷരം *context;
	ഘടന selabel_handle *shandle = ശൂന്യ;

	എങ്കിൽ (!ssh_selinux_enabled())
		തിരികെ;
	എങ്കിൽ (path == ശൂന്യ) {
		setfscreatecon(ശൂന്യ);
		തിരികെ;
	}
	എങ്കിൽ ((shandle = selabel_open(SELABEL_CTX_FILE, ശൂന്യ, 0)) == ശൂന്യ) {
		debug_f("selabel_open failed");
		തിരികെ;
	}
	എങ്കിൽ (selabel_lookup(shandle, &context, path, 0700) == 0)
		setfscreatecon(context);
	selabel_close(shandle);
}

#endif /* WITH_SELINUX */
