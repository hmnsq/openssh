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

#அந்தர்பாவ "includes.h"

#ifdef WITH_SELINUX

#அந்தர்பாவ <sys/socket.h>
#அந்தர்பாவ <sys/un.h>

#அந்தர்பாவ <errno.h>
#அந்தர்பாவ <stdarg.h>
#அந்தர்பாவ <string.h>
#அந்தர்பாவ <stdio.h>
#அந்தர்பாவ <stdlib.h>

#அந்தர்பாவ "log.h"
#அந்தர்பாவ "xmalloc.h"
#அந்தர்பாவ "port-linux.h"
#அந்தர்பாவ "misc.h"

#அந்தர்பாவ <selinux/selinux.h>
#அந்தர்பாவ <selinux/label.h>
#அந்தர்பாவ <selinux/get_context_list.h>

#ifndef SSH_SELINUX_UNCONFINED_TYPE
# define SSH_SELINUX_UNCONFINED_TYPE ":unconfined_t:"
#endif

/* Wrapper around is_selinux_enabled() to log its return value once only */
முழு
ssh_selinux_enabled(வெறுமை)
{
	நிலையான முழு enabled = -1;

	எனில் (enabled == -1) {
		enabled = (is_selinux_enabled() == 1);
		debug("SELinux support %s", enabled ? "enabled" : "disabled");
	}

	திரும்பு (enabled);
}

/* Return the default security context for the given username */
நிலையான எழுத்து *
ssh_selinux_getctxbyname(எழுத்து *pwname)
{
	எழுத்து *sc = வெற்று, *sename = வெற்று, *lvl = வெற்று;
	முழு r;

#ifdef HAVE_GETSEUSERBYNAME
	எனில் (getseuserbyname(pwname, &sename, &lvl) != 0)
		திரும்பு வெற்று;
#இல்லையெனில்
	sename = pwname;
	lvl = வெற்று;
#endif

#ifdef HAVE_GET_DEFAULT_CONTEXT_WITH_LEVEL
	r = get_default_context_with_level(sename, lvl, வெற்று, &sc);
#இல்லையெனில்
	r = get_default_context(sename, வெற்று, &sc);
#endif

	எனில் (r != 0) {
		தேர்வு (security_getenforce()) {
		நிலை -1:
			fatal("%s: ssh_selinux_getctxbyname: "
			    "security_getenforce() failed", __func__);
		நிலை 0:
			error("%s: Failed to get default SELinux security "
			    "context for %s", __func__, pwname);
			sc = வெற்று;
			நிறுத்து;
		இயல்பு:
			fatal("%s: Failed to get default SELinux security "
			    "context for %s (in enforcing mode)",
			    __func__, pwname);
		}
	}

#ifdef HAVE_GETSEUSERBYNAME
	விடுவி(sename);
	விடுவி(lvl);
#endif

	திரும்பு sc;
}

/* Set the execution context to the default for the specified user */
வெறுமை
ssh_selinux_setup_exec_context(எழுத்து *pwname)
{
	எழுத்து *user_ctx = வெற்று;

	எனில் (!ssh_selinux_enabled())
		திரும்பு;

	debug3("%s: setting execution context", __func__);

	user_ctx = ssh_selinux_getctxbyname(pwname);
	எனில் (setexeccon(user_ctx) != 0) {
		தேர்வு (security_getenforce()) {
		நிலை -1:
			fatal("%s: security_getenforce() failed", __func__);
		நிலை 0:
			error("%s: Failed to set SELinux execution "
			    "context for %s", __func__, pwname);
			நிறுத்து;
		இயல்பு:
			fatal("%s: Failed to set SELinux execution context "
			    "for %s (in enforcing mode)", __func__, pwname);
		}
	}
	எனில் (user_ctx != வெற்று)
		freecon(user_ctx);

	debug3("%s: done", __func__);
}

/* Set the TTY context for the specified user */
வெறுமை
ssh_selinux_setup_pty(எழுத்து *pwname, மாறிலி எழுத்து *tty)
{
	எழுத்து *new_tty_ctx = வெற்று, *user_ctx = வெற்று, *old_tty_ctx = வெற்று;
	security_class_t chrclass;

	எனில் (!ssh_selinux_enabled())
		திரும்பு;

	debug3("%s: setting TTY context on %s", __func__, tty);

	user_ctx = ssh_selinux_getctxbyname(pwname);

	/* XXX: should these calls fatal() upon failure in enforcing mode? */

	எனில் (getfilecon(tty, &old_tty_ctx) == -1) {
		error("%s: getfilecon: %s", __func__, strerror(errno));
		செல் out;
	}
	எனில் ((chrclass = string_to_security_class("chr_file")) == 0) {
		error("%s: couldn't get security class for chr_file", __func__);
		செல் out;
	}
	எனில் (security_compute_relabel(user_ctx, old_tty_ctx,
	    chrclass, &new_tty_ctx) != 0) {
		error("%s: security_compute_relabel: %s",
		    __func__, strerror(errno));
		செல் out;
	}

	எனில் (setfilecon(tty, new_tty_ctx) != 0)
		error("%s: setfilecon: %s", __func__, strerror(errno));
 out:
	எனில் (new_tty_ctx != வெற்று)
		freecon(new_tty_ctx);
	எனில் (old_tty_ctx != வெற்று)
		freecon(old_tty_ctx);
	எனில் (user_ctx != வெற்று)
		freecon(user_ctx);
	debug3("%s: done", __func__);
}

வெறுமை
ssh_selinux_change_context(மாறிலி எழுத்து *newname)
{
	எழுத்து *oldctx, *newctx, *cx, *cx2;
	LogLevel log_level = SYSLOG_LEVEL_INFO;

	எனில் (!ssh_selinux_enabled())
		திரும்பு;

	எனில் (getcon(&oldctx) < 0) {
		logit_f("getcon failed with %s", strerror(errno));
		திரும்பு;
	}
	எனில் ((cx = strchr(oldctx, ':')) == வெற்று ||
	    (cx = strchr(cx + 1, ':')) == வெற்று ||
	    (cx - oldctx) >= INT_MAX) {
		logit_f("unparsable context %s", oldctx);
		திரும்பு;
	}

	/*
	 * Check whether we are attempting to switch away from an unconfined
	 * security context.
	 */
	எனில் (strncmp(cx, SSH_SELINUX_UNCONFINED_TYPE,
	    அளவு(SSH_SELINUX_UNCONFINED_TYPE) - 1) == 0)
		log_level = SYSLOG_LEVEL_DEBUG3;

	cx2 = strchr(cx + 1, ':');
	xasprintf(&newctx, "%.*s%s%s", (முழு)(cx - oldctx + 1), oldctx,
	    newname, cx2 == வெற்று ? "" : cx2);

	debug3_f("setting context from '%s' to '%s'", oldctx, newctx);
	எனில் (setcon(newctx) < 0)
		do_log2_f(log_level, "setcon %s from %s failed with %s",
		    newctx, oldctx, strerror(errno));
	விடுவி(oldctx);
	விடுவி(newctx);
}

வெறுமை
ssh_selinux_setfscreatecon(மாறிலி எழுத்து *path)
{
	எழுத்து *context;
	கட்டமைப்பு selabel_handle *shandle = வெற்று;

	எனில் (!ssh_selinux_enabled())
		திரும்பு;
	எனில் (path == வெற்று) {
		setfscreatecon(வெற்று);
		திரும்பு;
	}
	எனில் ((shandle = selabel_open(SELABEL_CTX_FILE, வெற்று, 0)) == வெற்று) {
		debug_f("selabel_open failed");
		திரும்பு;
	}
	எனில் (selabel_lookup(shandle, &context, path, 0700) == 0)
		setfscreatecon(context);
	selabel_close(shandle);
}

#endif /* WITH_SELINUX */
