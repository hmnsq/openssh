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

#अन्तर्भाव "includes.h"

#ifdef WITH_SELINUX

#अन्तर्भाव <sys/socket.h>
#अन्तर्भाव <sys/un.h>

#अन्तर्भाव <errno.h>
#अन्तर्भाव <stdarg.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <stdio.h>
#अन्तर्भाव <stdlib.h>

#अन्तर्भाव "log.h"
#अन्तर्भाव "xmalloc.h"
#अन्तर्भाव "port-linux.h"
#अन्तर्भाव "misc.h"

#अन्तर्भाव <selinux/selinux.h>
#अन्तर्भाव <selinux/label.h>
#अन्तर्भाव <selinux/get_context_list.h>

#ifndef SSH_SELINUX_UNCONFINED_TYPE
# define SSH_SELINUX_UNCONFINED_TYPE ":unconfined_t:"
#endif

/* Wrapper around is_selinux_enabled() to log its return value once only */
पूर्णाङ्क
ssh_selinux_enabled(शून्य)
{
	स्थिर पूर्णाङ्क enabled = -1;

	सचे (enabled == -1) {
		enabled = (is_selinux_enabled() == 1);
		debug("SELinux support %s", enabled ? "enabled" : "disabled");
	}

	पटिनिवत्त (enabled);
}

/* Return the default security context for the given username */
स्थिर वर्ण *
ssh_selinux_getctxbyname(वर्ण *pwname)
{
	वर्ण *sc = रिक्त, *sename = रिक्त, *lvl = रिक्त;
	पूर्णाङ्क r;

#ifdef HAVE_GETSEUSERBYNAME
	सचे (getseuserbyname(pwname, &sename, &lvl) != 0)
		पटिनिवत्त रिक्त;
#अञ्ञथा
	sename = pwname;
	lvl = रिक्त;
#endif

#ifdef HAVE_GET_DEFAULT_CONTEXT_WITH_LEVEL
	r = get_default_context_with_level(sename, lvl, रिक्त, &sc);
#अञ्ञथा
	r = get_default_context(sename, रिक्त, &sc);
#endif

	सचे (r != 0) {
		विकल्प (security_getenforce()) {
		पक्ष -1:
			fatal("%s: ssh_selinux_getctxbyname: "
			    "security_getenforce() failed", __func__);
		पक्ष 0:
			error("%s: Failed to get default SELinux security "
			    "context for %s", __func__, pwname);
			sc = रिक्त;
			भङ्ग;
		स्वभाव:
			fatal("%s: Failed to get default SELinux security "
			    "context for %s (in enforcing mode)",
			    __func__, pwname);
		}
	}

#ifdef HAVE_GETSEUSERBYNAME
	मुक्त(sename);
	मुक्त(lvl);
#endif

	पटिनिवत्त sc;
}

/* Set the execution context to the default for the specified user */
शून्य
ssh_selinux_setup_exec_context(वर्ण *pwname)
{
	वर्ण *user_ctx = रिक्त;

	सचे (!ssh_selinux_enabled())
		पटिनिवत्त;

	debug3("%s: setting execution context", __func__);

	user_ctx = ssh_selinux_getctxbyname(pwname);
	सचे (setexeccon(user_ctx) != 0) {
		विकल्प (security_getenforce()) {
		पक्ष -1:
			fatal("%s: security_getenforce() failed", __func__);
		पक्ष 0:
			error("%s: Failed to set SELinux execution "
			    "context for %s", __func__, pwname);
			भङ्ग;
		स्वभाव:
			fatal("%s: Failed to set SELinux execution context "
			    "for %s (in enforcing mode)", __func__, pwname);
		}
	}
	सचे (user_ctx != रिक्त)
		freecon(user_ctx);

	debug3("%s: done", __func__);
}

/* Set the TTY context for the specified user */
शून्य
ssh_selinux_setup_pty(वर्ण *pwname, ध्रुव वर्ण *tty)
{
	वर्ण *new_tty_ctx = रिक्त, *user_ctx = रिक्त, *old_tty_ctx = रिक्त;
	security_class_t chrclass;

	सचे (!ssh_selinux_enabled())
		पटिनिवत्त;

	debug3("%s: setting TTY context on %s", __func__, tty);

	user_ctx = ssh_selinux_getctxbyname(pwname);

	/* XXX: should these calls fatal() upon failure in enforcing mode? */

	सचे (getfilecon(tty, &old_tty_ctx) == -1) {
		error("%s: getfilecon: %s", __func__, strerror(errno));
		गच्छ out;
	}
	सचे ((chrclass = string_to_security_class("chr_file")) == 0) {
		error("%s: couldn't get security class for chr_file", __func__);
		गच्छ out;
	}
	सचे (security_compute_relabel(user_ctx, old_tty_ctx,
	    chrclass, &new_tty_ctx) != 0) {
		error("%s: security_compute_relabel: %s",
		    __func__, strerror(errno));
		गच्छ out;
	}

	सचे (setfilecon(tty, new_tty_ctx) != 0)
		error("%s: setfilecon: %s", __func__, strerror(errno));
 out:
	सचे (new_tty_ctx != रिक्त)
		freecon(new_tty_ctx);
	सचे (old_tty_ctx != रिक्त)
		freecon(old_tty_ctx);
	सचे (user_ctx != रिक्त)
		freecon(user_ctx);
	debug3("%s: done", __func__);
}

शून्य
ssh_selinux_change_context(ध्रुव वर्ण *newname)
{
	वर्ण *oldctx, *newctx, *cx, *cx2;
	LogLevel log_level = SYSLOG_LEVEL_INFO;

	सचे (!ssh_selinux_enabled())
		पटिनिवत्त;

	सचे (getcon(&oldctx) < 0) {
		logit_f("getcon failed with %s", strerror(errno));
		पटिनिवत्त;
	}
	सचे ((cx = strchr(oldctx, ':')) == रिक्त ||
	    (cx = strchr(cx + 1, ':')) == रिक्त ||
	    (cx - oldctx) >= INT_MAX) {
		logit_f("unparsable context %s", oldctx);
		पटिनिवत्त;
	}

	/*
	 * Check whether we are attempting to switch away from an unconfined
	 * security context.
	 */
	सचे (strncmp(cx, SSH_SELINUX_UNCONFINED_TYPE,
	    परिमाण(SSH_SELINUX_UNCONFINED_TYPE) - 1) == 0)
		log_level = SYSLOG_LEVEL_DEBUG3;

	cx2 = strchr(cx + 1, ':');
	xasprintf(&newctx, "%.*s%s%s", (पूर्णाङ्क)(cx - oldctx + 1), oldctx,
	    newname, cx2 == रिक्त ? "" : cx2);

	debug3_f("setting context from '%s' to '%s'", oldctx, newctx);
	सचे (setcon(newctx) < 0)
		do_log2_f(log_level, "setcon %s from %s failed with %s",
		    newctx, oldctx, strerror(errno));
	मुक्त(oldctx);
	मुक्त(newctx);
}

शून्य
ssh_selinux_setfscreatecon(ध्रुव वर्ण *path)
{
	वर्ण *context;
	संरचना selabel_handle *shandle = रिक्त;

	सचे (!ssh_selinux_enabled())
		पटिनिवत्त;
	सचे (path == रिक्त) {
		setfscreatecon(रिक्त);
		पटिनिवत्त;
	}
	सचे ((shandle = selabel_open(SELABEL_CTX_FILE, रिक्त, 0)) == रिक्त) {
		debug_f("selabel_open failed");
		पटिनिवत्त;
	}
	सचे (selabel_lookup(shandle, &context, path, 0700) == 0)
		setfscreatecon(context);
	selabel_close(shandle);
}

#endif /* WITH_SELINUX */
