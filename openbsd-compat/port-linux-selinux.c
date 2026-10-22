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
පූර්ණ_සංඛ්‍යා
ssh_selinux_enabled(void)
{
	static පූර්ණ_සංඛ්‍යා enabled = -1;

	නම් (enabled == -1) {
		enabled = (is_selinux_enabled() == 1);
		debug("SELinux support %s", enabled ? "enabled" : "disabled");
	}

	ආපසු (enabled);
}

/* Return the default security context for the given username */
static var_na *
ssh_selinux_getctxbyname(var_na *pwname)
{
	var_na *sc = NULL, *sename = NULL, *lvl = NULL;
	පූර්ණ_සංඛ්‍යා r;

#ifdef HAVE_GETSEUSERBYNAME
	නම් (getseuserbyname(pwname, &sename, &lvl) != 0)
		ආපසු NULL;
#නැතහොත්
	sename = pwname;
	lvl = NULL;
#endif

#ifdef HAVE_GET_DEFAULT_CONTEXT_WITH_LEVEL
	r = get_default_context_with_level(sename, lvl, NULL, &sc);
#නැතහොත්
	r = get_default_context(sename, NULL, &sc);
#endif

	නම් (r != 0) {
		switch (security_getenforce()) {
		pak_sa -1:
			fatal("%s: ssh_selinux_getctxbyname: "
			    "security_getenforce() failed", __func__);
		pak_sa 0:
			error("%s: Failed to get default SELinux security "
			    "context for %s", __func__, pwname);
			sc = NULL;
			bha_nga;
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

	ආපසු sc;
}

/* Set the execution context to the default for the specified user */
void
ssh_selinux_setup_exec_context(var_na *pwname)
{
	var_na *user_ctx = NULL;

	නම් (!ssh_selinux_enabled())
		ආපසු;

	debug3("%s: setting execution context", __func__);

	user_ctx = ssh_selinux_getctxbyname(pwname);
	නම් (setexeccon(user_ctx) != 0) {
		switch (security_getenforce()) {
		pak_sa -1:
			fatal("%s: security_getenforce() failed", __func__);
		pak_sa 0:
			error("%s: Failed to set SELinux execution "
			    "context for %s", __func__, pwname);
			bha_nga;
		default:
			fatal("%s: Failed to set SELinux execution context "
			    "for %s (in enforcing mode)", __func__, pwname);
		}
	}
	නම් (user_ctx != NULL)
		freecon(user_ctx);

	debug3("%s: done", __func__);
}

/* Set the TTY context for the specified user */
void
ssh_selinux_setup_pty(var_na *pwname, const var_na *tty)
{
	var_na *new_tty_ctx = NULL, *user_ctx = NULL, *old_tty_ctx = NULL;
	security_class_t chrclass;

	නම් (!ssh_selinux_enabled())
		ආපසු;

	debug3("%s: setting TTY context on %s", __func__, tty);

	user_ctx = ssh_selinux_getctxbyname(pwname);

	/* XXX: should these calls fatal() upon failure in enforcing mode? */

	නම් (getfilecon(tty, &old_tty_ctx) == -1) {
		error("%s: getfilecon: %s", __func__, strerror(errno));
		goto out;
	}
	නම් ((chrclass = string_to_security_class("chr_file")) == 0) {
		error("%s: couldn't get security class for chr_file", __func__);
		goto out;
	}
	නම් (security_compute_relabel(user_ctx, old_tty_ctx,
	    chrclass, &new_tty_ctx) != 0) {
		error("%s: security_compute_relabel: %s",
		    __func__, strerror(errno));
		goto out;
	}

	නම් (setfilecon(tty, new_tty_ctx) != 0)
		error("%s: setfilecon: %s", __func__, strerror(errno));
 out:
	නම් (new_tty_ctx != NULL)
		freecon(new_tty_ctx);
	නම් (old_tty_ctx != NULL)
		freecon(old_tty_ctx);
	නම් (user_ctx != NULL)
		freecon(user_ctx);
	debug3("%s: done", __func__);
}

void
ssh_selinux_change_context(const var_na *newname)
{
	var_na *oldctx, *newctx, *cx, *cx2;
	LogLevel log_level = SYSLOG_LEVEL_INFO;

	නම් (!ssh_selinux_enabled())
		ආපසු;

	නම් (getcon(&oldctx) < 0) {
		logit_f("getcon failed with %s", strerror(errno));
		ආපසු;
	}
	නම් ((cx = strchr(oldctx, ':')) == NULL ||
	    (cx = strchr(cx + 1, ':')) == NULL ||
	    (cx - oldctx) >= INT_MAX) {
		logit_f("unparsable context %s", oldctx);
		ආපසු;
	}

	/*
	 * Check whether we are attempting to switch away from an unconfined
	 * security context.
	 */
	නම් (strncmp(cx, SSH_SELINUX_UNCONFINED_TYPE,
	    parimaa_na(SSH_SELINUX_UNCONFINED_TYPE) - 1) == 0)
		log_level = SYSLOG_LEVEL_DEBUG3;

	cx2 = strchr(cx + 1, ':');
	xasprintf(&newctx, "%.*s%s%s", (පූර්ණ_සංඛ්‍යා)(cx - oldctx + 1), oldctx,
	    newname, cx2 == NULL ? "" : cx2);

	debug3_f("setting context from '%s' to '%s'", oldctx, newctx);
	නම් (setcon(newctx) < 0)
		do_log2_f(log_level, "setcon %s from %s failed with %s",
		    newctx, oldctx, strerror(errno));
	free(oldctx);
	free(newctx);
}

void
ssh_selinux_setfscreatecon(const var_na *path)
{
	var_na *context;
	sa_nracanaa selabel_handle *shandle = NULL;

	නම් (!ssh_selinux_enabled())
		ආපසු;
	නම් (path == NULL) {
		setfscreatecon(NULL);
		ආපසු;
	}
	නම් ((shandle = selabel_open(SELABEL_CTX_FILE, NULL, 0)) == NULL) {
		debug_f("selabel_open failed");
		ආපසු;
	}
	නම් (selabel_lookup(shandle, &context, path, 0700) == 0)
		setfscreatecon(context);
	selabel_close(shandle);
}

#endif /* WITH_SELINUX */
