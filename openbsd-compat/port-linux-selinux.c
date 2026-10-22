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

#include "includes.h"

#ifdef WITH_SELINUX

#include <sys/socket.h>
#include <sys/un.h>

#include <errno.h>
#include <stdarg.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "log.h"
#include "xmalloc.h"
#include "port-linux.h"
#include "misc.h"

#include <selinux/selinux.h>
#include <selinux/label.h>
#include <selinux/get_context_list.h>

#ifndef SSH_SELINUX_UNCONFINED_TYPE
# define SSH_SELINUX_UNCONFINED_TYPE ":unconfined_t:"
#endif

/* Wrapper around is_selinux_enabled() to log its return value once only */
整数
ssh_selinux_enabled(void)
{
	static 整数 enabled = -1;

	もし (enabled == -1) {
		enabled = (is_selinux_enabled() == 1);
		debug("SELinux support %s", enabled ? "enabled" : "disabled");
	}

	戻る (enabled);
}

/* Return the default security context for the given username */
static char *
ssh_selinux_getctxbyname(char *pwname)
{
	char *sc = NULL, *sename = NULL, *lvl = NULL;
	整数 r;

#ifdef HAVE_GETSEUSERBYNAME
	もし (getseuserbyname(pwname, &sename, &lvl) != 0)
		戻る NULL;
#否则
	sename = pwname;
	lvl = NULL;
#endif

#ifdef HAVE_GET_DEFAULT_CONTEXT_WITH_LEVEL
	r = get_default_context_with_level(sename, lvl, NULL, &sc);
#否则
	r = get_default_context(sename, NULL, &sc);
#endif

	もし (r != 0) {
		switch (security_getenforce()) {
		case -1:
			fatal("%s: ssh_selinux_getctxbyname: "
			    "security_getenforce() failed", __func__);
		case 0:
			error("%s: Failed to get default SELinux security "
			    "context for %s", __func__, pwname);
			sc = NULL;
			break;
		default:
			fatal("%s: Failed to get default SELinux security "
			    "context for %s (in enforcing mode)",
			    __func__, pwname);
		}
	}

#ifdef HAVE_GETSEUSERBYNAME
	free(sename);
	free(lvl);
#endif

	戻る sc;
}

/* Set the execution context to the default for the specified user */
void
ssh_selinux_setup_exec_context(char *pwname)
{
	char *user_ctx = NULL;

	もし (!ssh_selinux_enabled())
		戻る;

	debug3("%s: setting execution context", __func__);

	user_ctx = ssh_selinux_getctxbyname(pwname);
	もし (setexeccon(user_ctx) != 0) {
		switch (security_getenforce()) {
		case -1:
			fatal("%s: security_getenforce() failed", __func__);
		case 0:
			error("%s: Failed to set SELinux execution "
			    "context for %s", __func__, pwname);
			break;
		default:
			fatal("%s: Failed to set SELinux execution context "
			    "for %s (in enforcing mode)", __func__, pwname);
		}
	}
	もし (user_ctx != NULL)
		freecon(user_ctx);

	debug3("%s: done", __func__);
}

/* Set the TTY context for the specified user */
void
ssh_selinux_setup_pty(char *pwname, const char *tty)
{
	char *new_tty_ctx = NULL, *user_ctx = NULL, *old_tty_ctx = NULL;
	security_class_t chrclass;

	もし (!ssh_selinux_enabled())
		戻る;

	debug3("%s: setting TTY context on %s", __func__, tty);

	user_ctx = ssh_selinux_getctxbyname(pwname);

	/* XXX: should these calls fatal() upon failure in enforcing mode? */

	もし (getfilecon(tty, &old_tty_ctx) == -1) {
		error("%s: getfilecon: %s", __func__, strerror(errno));
		goto out;
	}
	もし ((chrclass = string_to_security_class("chr_file")) == 0) {
		error("%s: couldn't get security class for chr_file", __func__);
		goto out;
	}
	もし (security_compute_relabel(user_ctx, old_tty_ctx,
	    chrclass, &new_tty_ctx) != 0) {
		error("%s: security_compute_relabel: %s",
		    __func__, strerror(errno));
		goto out;
	}

	もし (setfilecon(tty, new_tty_ctx) != 0)
		error("%s: setfilecon: %s", __func__, strerror(errno));
 out:
	もし (new_tty_ctx != NULL)
		freecon(new_tty_ctx);
	もし (old_tty_ctx != NULL)
		freecon(old_tty_ctx);
	もし (user_ctx != NULL)
		freecon(user_ctx);
	debug3("%s: done", __func__);
}

void
ssh_selinux_change_context(const char *newname)
{
	char *oldctx, *newctx, *cx, *cx2;
	LogLevel log_level = SYSLOG_LEVEL_INFO;

	もし (!ssh_selinux_enabled())
		戻る;

	もし (getcon(&oldctx) < 0) {
		logit_f("getcon failed with %s", strerror(errno));
		戻る;
	}
	もし ((cx = strchr(oldctx, ':')) == NULL ||
	    (cx = strchr(cx + 1, ':')) == NULL ||
	    (cx - oldctx) >= INT_MAX) {
		logit_f("unparsable context %s", oldctx);
		戻る;
	}

	/*
	 * Check whether we are attempting to switch away from an unconfined
	 * security context.
	 */
	もし (strncmp(cx, SSH_SELINUX_UNCONFINED_TYPE,
	    sizeof(SSH_SELINUX_UNCONFINED_TYPE) - 1) == 0)
		log_level = SYSLOG_LEVEL_DEBUG3;

	cx2 = strchr(cx + 1, ':');
	xasprintf(&newctx, "%.*s%s%s", (整数)(cx - oldctx + 1), oldctx,
	    newname, cx2 == NULL ? "" : cx2);

	debug3_f("setting context from '%s' to '%s'", oldctx, newctx);
	もし (setcon(newctx) < 0)
		do_log2_f(log_level, "setcon %s from %s failed with %s",
		    newctx, oldctx, strerror(errno));
	free(oldctx);
	free(newctx);
}

void
ssh_selinux_setfscreatecon(const char *path)
{
	char *context;
	struct selabel_handle *shandle = NULL;

	もし (!ssh_selinux_enabled())
		戻る;
	もし (path == NULL) {
		setfscreatecon(NULL);
		戻る;
	}
	もし ((shandle = selabel_open(SELABEL_CTX_FILE, NULL, 0)) == NULL) {
		debug_f("selabel_open failed");
		戻る;
	}
	もし (selabel_lookup(shandle, &context, path, 0700) == 0)
		setfscreatecon(context);
	selabel_close(shandle);
}

#endif /* WITH_SELINUX */
