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
पूर्णांक
ssh_selinux_enabled(शून्य)
{
	स्थिर पूर्णांक enabled = -1;

	जर (enabled == -1) {
		enabled = (is_selinux_enabled() == 1);
		debug("SELinux support %s", enabled ? "enabled" : "disabled");
	}

	परत (enabled);
}

/* Return the default security context for the given username */
स्थिर अक्षर *
ssh_selinux_getctxbyname(अक्षर *pwname)
{
	अक्षर *sc = रिक्त, *sename = रिक्त, *lvl = रिक्त;
	पूर्णांक r;

#ifdef HAVE_GETSEUSERBYNAME
	जर (getseuserbyname(pwname, &sename, &lvl) != 0)
		परत रिक्त;
#अन्यथा
	sename = pwname;
	lvl = रिक्त;
#endif

#ifdef HAVE_GET_DEFAULT_CONTEXT_WITH_LEVEL
	r = get_default_context_with_level(sename, lvl, रिक्त, &sc);
#अन्यथा
	r = get_default_context(sename, रिक्त, &sc);
#endif

	जर (r != 0) {
		निवड (security_getenforce()) {
		स्थिती -1:
			fatal("%s: ssh_selinux_getctxbyname: "
			    "security_getenforce() failed", __func__);
		स्थिती 0:
			error("%s: Failed to get default SELinux security "
			    "context for %s", __func__, pwname);
			sc = रिक्त;
			थांबा;
		पूर्वनिर्धारित:
			fatal("%s: Failed to get default SELinux security "
			    "context for %s (in enforcing mode)",
			    __func__, pwname);
		}
	}

#ifdef HAVE_GETSEUSERBYNAME
	मुक्त(sename);
	मुक्त(lvl);
#endif

	परत sc;
}

/* Set the execution context to the default for the specified user */
शून्य
ssh_selinux_setup_exec_context(अक्षर *pwname)
{
	अक्षर *user_ctx = रिक्त;

	जर (!ssh_selinux_enabled())
		परत;

	debug3("%s: setting execution context", __func__);

	user_ctx = ssh_selinux_getctxbyname(pwname);
	जर (setexeccon(user_ctx) != 0) {
		निवड (security_getenforce()) {
		स्थिती -1:
			fatal("%s: security_getenforce() failed", __func__);
		स्थिती 0:
			error("%s: Failed to set SELinux execution "
			    "context for %s", __func__, pwname);
			थांबा;
		पूर्वनिर्धारित:
			fatal("%s: Failed to set SELinux execution context "
			    "for %s (in enforcing mode)", __func__, pwname);
		}
	}
	जर (user_ctx != रिक्त)
		freecon(user_ctx);

	debug3("%s: done", __func__);
}

/* Set the TTY context for the specified user */
शून्य
ssh_selinux_setup_pty(अक्षर *pwname, स्थिरांक अक्षर *tty)
{
	अक्षर *new_tty_ctx = रिक्त, *user_ctx = रिक्त, *old_tty_ctx = रिक्त;
	security_class_t chrclass;

	जर (!ssh_selinux_enabled())
		परत;

	debug3("%s: setting TTY context on %s", __func__, tty);

	user_ctx = ssh_selinux_getctxbyname(pwname);

	/* XXX: should these calls fatal() upon failure in enforcing mode? */

	जर (getfilecon(tty, &old_tty_ctx) == -1) {
		error("%s: getfilecon: %s", __func__, म_त्रुटि(त्रुटि_सं));
		जा out;
	}
	जर ((chrclass = string_to_security_class("chr_file")) == 0) {
		error("%s: couldn't get security class for chr_file", __func__);
		जा out;
	}
	जर (security_compute_relabel(user_ctx, old_tty_ctx,
	    chrclass, &new_tty_ctx) != 0) {
		error("%s: security_compute_relabel: %s",
		    __func__, म_त्रुटि(त्रुटि_सं));
		जा out;
	}

	जर (setfilecon(tty, new_tty_ctx) != 0)
		error("%s: setfilecon: %s", __func__, म_त्रुटि(त्रुटि_सं));
 out:
	जर (new_tty_ctx != रिक्त)
		freecon(new_tty_ctx);
	जर (old_tty_ctx != रिक्त)
		freecon(old_tty_ctx);
	जर (user_ctx != रिक्त)
		freecon(user_ctx);
	debug3("%s: done", __func__);
}

शून्य
ssh_selinux_change_context(स्थिरांक अक्षर *newname)
{
	अक्षर *oldctx, *newctx, *cx, *cx2;
	LogLevel log_level = SYSLOG_LEVEL_INFO;

	जर (!ssh_selinux_enabled())
		परत;

	जर (getcon(&oldctx) < 0) {
		logit_f("getcon failed with %s", म_त्रुटि(त्रुटि_सं));
		परत;
	}
	जर ((cx = म_अक्षर(oldctx, ':')) == रिक्त ||
	    (cx = म_अक्षर(cx + 1, ':')) == रिक्त ||
	    (cx - oldctx) >= पूर्णांक_उच्च) {
		logit_f("unparsable context %s", oldctx);
		परत;
	}

	/*
	 * Check whether we are attempting to switch away from an unconfined
	 * security context.
	 */
	जर (म_भेदन(cx, SSH_SELINUX_UNCONFINED_TYPE,
	    आकार(SSH_SELINUX_UNCONFINED_TYPE) - 1) == 0)
		log_level = SYSLOG_LEVEL_DEBUG3;

	cx2 = म_अक्षर(cx + 1, ':');
	xasprintf(&newctx, "%.*s%s%s", (पूर्णांक)(cx - oldctx + 1), oldctx,
	    newname, cx2 == रिक्त ? "" : cx2);

	debug3_f("setting context from '%s' to '%s'", oldctx, newctx);
	जर (setcon(newctx) < 0)
		do_log2_f(log_level, "setcon %s from %s failed with %s",
		    newctx, oldctx, म_त्रुटि(त्रुटि_सं));
	मुक्त(oldctx);
	मुक्त(newctx);
}

शून्य
ssh_selinux_setfscreatecon(स्थिरांक अक्षर *path)
{
	अक्षर *context;
	संरचना selabel_handle *shandle = रिक्त;

	जर (!ssh_selinux_enabled())
		परत;
	जर (path == रिक्त) {
		setfscreatecon(रिक्त);
		परत;
	}
	जर ((shandle = selabel_open(SELABEL_CTX_FILE, रिक्त, 0)) == रिक्त) {
		debug_f("selabel_open failed");
		परत;
	}
	जर (selabel_lookup(shandle, &context, path, 0700) == 0)
		setfscreatecon(context);
	selabel_close(shandle);
}

#endif /* WITH_SELINUX */
