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

#અન્તર્ભાવ "includes.h"

#ifdef WITH_SELINUX

#અન્તર્ભાવ <sys/socket.h>
#અન્તર્ભાવ <sys/un.h>

#અન્તર્ભાવ <errno.h>
#અન્તર્ભાવ <stdarg.h>
#અન્તર્ભાવ <string.h>
#અન્તર્ભાવ <stdio.h>
#અન્તર્ભાવ <stdlib.h>

#અન્તર્ભાવ "log.h"
#અન્તર્ભાવ "xmalloc.h"
#અન્તર્ભાવ "port-linux.h"
#અન્તર્ભાવ "misc.h"

#અન્તર્ભાવ <selinux/selinux.h>
#અન્તર્ભાવ <selinux/label.h>
#અન્તર્ભાવ <selinux/get_context_list.h>

#ifndef SSH_SELINUX_UNCONFINED_TYPE
# define SSH_SELINUX_UNCONFINED_TYPE ":unconfined_t:"
#endif

/* Wrapper around is_selinux_enabled() to log its return value once only */
પૂર્ણાંક
ssh_selinux_enabled(શૂન્ય)
{
	સ્થિર પૂર્ણાંક enabled = -1;

	જો (enabled == -1) {
		enabled = (is_selinux_enabled() == 1);
		debug("SELinux support %s", enabled ? "enabled" : "disabled");
	}

	પાછા (enabled);
}

/* Return the default security context for the given username */
સ્થિર અક્ષર *
ssh_selinux_getctxbyname(અક્ષર *pwname)
{
	અક્ષર *sc = ખાલી, *sename = ખાલી, *lvl = ખાલી;
	પૂર્ણાંક r;

#ifdef HAVE_GETSEUSERBYNAME
	જો (getseuserbyname(pwname, &sename, &lvl) != 0)
		પાછા ખાલી;
#નહીંતર
	sename = pwname;
	lvl = ખાલી;
#endif

#ifdef HAVE_GET_DEFAULT_CONTEXT_WITH_LEVEL
	r = get_default_context_with_level(sename, lvl, ખાલી, &sc);
#નહીંતર
	r = get_default_context(sename, ખાલી, &sc);
#endif

	જો (r != 0) {
		પસંદગી (security_getenforce()) {
		સ્થિતિ -1:
			fatal("%s: ssh_selinux_getctxbyname: "
			    "security_getenforce() failed", __func__);
		સ્થિતિ 0:
			error("%s: Failed to get default SELinux security "
			    "context for %s", __func__, pwname);
			sc = ખાલી;
			તોડો;
		મૂળભૂત:
			fatal("%s: Failed to get default SELinux security "
			    "context for %s (in enforcing mode)",
			    __func__, pwname);
		}
	}

#ifdef HAVE_GETSEUSERBYNAME
	મુક્ત(sename);
	મુક્ત(lvl);
#endif

	પાછા sc;
}

/* Set the execution context to the default for the specified user */
શૂન્ય
ssh_selinux_setup_exec_context(અક્ષર *pwname)
{
	અક્ષર *user_ctx = ખાલી;

	જો (!ssh_selinux_enabled())
		પાછા;

	debug3("%s: setting execution context", __func__);

	user_ctx = ssh_selinux_getctxbyname(pwname);
	જો (setexeccon(user_ctx) != 0) {
		પસંદગી (security_getenforce()) {
		સ્થિતિ -1:
			fatal("%s: security_getenforce() failed", __func__);
		સ્થિતિ 0:
			error("%s: Failed to set SELinux execution "
			    "context for %s", __func__, pwname);
			તોડો;
		મૂળભૂત:
			fatal("%s: Failed to set SELinux execution context "
			    "for %s (in enforcing mode)", __func__, pwname);
		}
	}
	જો (user_ctx != ખાલી)
		freecon(user_ctx);

	debug3("%s: done", __func__);
}

/* Set the TTY context for the specified user */
શૂન્ય
ssh_selinux_setup_pty(અક્ષર *pwname, અચલ અક્ષર *tty)
{
	અક્ષર *new_tty_ctx = ખાલી, *user_ctx = ખાલી, *old_tty_ctx = ખાલી;
	security_class_t chrclass;

	જો (!ssh_selinux_enabled())
		પાછા;

	debug3("%s: setting TTY context on %s", __func__, tty);

	user_ctx = ssh_selinux_getctxbyname(pwname);

	/* XXX: should these calls fatal() upon failure in enforcing mode? */

	જો (getfilecon(tty, &old_tty_ctx) == -1) {
		error("%s: getfilecon: %s", __func__, strerror(errno));
		જાઓ out;
	}
	જો ((chrclass = string_to_security_class("chr_file")) == 0) {
		error("%s: couldn't get security class for chr_file", __func__);
		જાઓ out;
	}
	જો (security_compute_relabel(user_ctx, old_tty_ctx,
	    chrclass, &new_tty_ctx) != 0) {
		error("%s: security_compute_relabel: %s",
		    __func__, strerror(errno));
		જાઓ out;
	}

	જો (setfilecon(tty, new_tty_ctx) != 0)
		error("%s: setfilecon: %s", __func__, strerror(errno));
 out:
	જો (new_tty_ctx != ખાલી)
		freecon(new_tty_ctx);
	જો (old_tty_ctx != ખાલી)
		freecon(old_tty_ctx);
	જો (user_ctx != ખાલી)
		freecon(user_ctx);
	debug3("%s: done", __func__);
}

શૂન્ય
ssh_selinux_change_context(અચલ અક્ષર *newname)
{
	અક્ષર *oldctx, *newctx, *cx, *cx2;
	LogLevel log_level = SYSLOG_LEVEL_INFO;

	જો (!ssh_selinux_enabled())
		પાછા;

	જો (getcon(&oldctx) < 0) {
		logit_f("getcon failed with %s", strerror(errno));
		પાછા;
	}
	જો ((cx = strchr(oldctx, ':')) == ખાલી ||
	    (cx = strchr(cx + 1, ':')) == ખાલી ||
	    (cx - oldctx) >= INT_MAX) {
		logit_f("unparsable context %s", oldctx);
		પાછા;
	}

	/*
	 * Check whether we are attempting to switch away from an unconfined
	 * security context.
	 */
	જો (strncmp(cx, SSH_SELINUX_UNCONFINED_TYPE,
	    કદ(SSH_SELINUX_UNCONFINED_TYPE) - 1) == 0)
		log_level = SYSLOG_LEVEL_DEBUG3;

	cx2 = strchr(cx + 1, ':');
	xasprintf(&newctx, "%.*s%s%s", (પૂર્ણાંક)(cx - oldctx + 1), oldctx,
	    newname, cx2 == ખાલી ? "" : cx2);

	debug3_f("setting context from '%s' to '%s'", oldctx, newctx);
	જો (setcon(newctx) < 0)
		do_log2_f(log_level, "setcon %s from %s failed with %s",
		    newctx, oldctx, strerror(errno));
	મુક્ત(oldctx);
	મુક્ત(newctx);
}

શૂન્ય
ssh_selinux_setfscreatecon(અચલ અક્ષર *path)
{
	અક્ષર *context;
	સંરચના selabel_handle *shandle = ખાલી;

	જો (!ssh_selinux_enabled())
		પાછા;
	જો (path == ખાલી) {
		setfscreatecon(ખાલી);
		પાછા;
	}
	જો ((shandle = selabel_open(SELABEL_CTX_FILE, ખાલી, 0)) == ખાલી) {
		debug_f("selabel_open failed");
		પાછા;
	}
	જો (selabel_lookup(shandle, &context, path, 0700) == 0)
		setfscreatecon(context);
	selabel_close(shandle);
}

#endif /* WITH_SELINUX */
