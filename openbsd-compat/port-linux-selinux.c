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

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ifdef WITH_SELINUX

#ଅନ୍ତର୍ଭାଵ <sys/socket.h>
#ଅନ୍ତର୍ଭାଵ <sys/un.h>

#ଅନ୍ତର୍ଭାଵ <errno.h>
#ଅନ୍ତର୍ଭାଵ <stdarg.h>
#ଅନ୍ତର୍ଭାଵ <string.h>
#ଅନ୍ତର୍ଭାଵ <stdio.h>
#ଅନ୍ତର୍ଭାଵ <stdlib.h>

#ଅନ୍ତର୍ଭାଵ "log.h"
#ଅନ୍ତର୍ଭାଵ "xmalloc.h"
#ଅନ୍ତର୍ଭାଵ "port-linux.h"
#ଅନ୍ତର୍ଭାଵ "misc.h"

#ଅନ୍ତର୍ଭାଵ <selinux/selinux.h>
#ଅନ୍ତର୍ଭାଵ <selinux/label.h>
#ଅନ୍ତର୍ଭାଵ <selinux/get_context_list.h>

#ifndef SSH_SELINUX_UNCONFINED_TYPE
# define SSH_SELINUX_UNCONFINED_TYPE ":unconfined_t:"
#endif

/* Wrapper around is_selinux_enabled() to log its return value once only */
ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ssh_selinux_enabled(ଶୂନ୍ୟ)
{
	ସ୍ଥିର ପୂର୍ଣ୍ଣସଂଖ୍ୟା enabled = -1;

	ଯଦି (enabled == -1) {
		enabled = (is_selinux_enabled() == 1);
		debug("SELinux support %s", enabled ? "enabled" : "disabled");
	}

	ଫେରନ୍ତୁ (enabled);
}

/* Return the default security context for the given username */
ସ୍ଥିର ଅକ୍ଷର *
ssh_selinux_getctxbyname(ଅକ୍ଷର *pwname)
{
	ଅକ୍ଷର *sc = ଖାଲି, *sename = ଖାଲି, *lvl = ଖାଲି;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା r;

#ifdef HAVE_GETSEUSERBYNAME
	ଯଦି (getseuserbyname(pwname, &sename, &lvl) != 0)
		ଫେରନ୍ତୁ ଖାଲି;
#ଅନ୍ୟଥା
	sename = pwname;
	lvl = ଖାଲି;
#endif

#ifdef HAVE_GET_DEFAULT_CONTEXT_WITH_LEVEL
	r = get_default_context_with_level(sename, lvl, ଖାଲି, &sc);
#ଅନ୍ୟଥା
	r = get_default_context(sename, ଖାଲି, &sc);
#endif

	ଯଦି (r != 0) {
		ବାଛ (security_getenforce()) {
		ସ୍ଥିତି -1:
			fatal("%s: ssh_selinux_getctxbyname: "
			    "security_getenforce() failed", __func__);
		ସ୍ଥିତି 0:
			error("%s: Failed to get default SELinux security "
			    "context for %s", __func__, pwname);
			sc = ଖାଲି;
			ଭାଙ୍ଗ;
		ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
			fatal("%s: Failed to get default SELinux security "
			    "context for %s (in enforcing mode)",
			    __func__, pwname);
		}
	}

#ifdef HAVE_GETSEUSERBYNAME
	ମୁକ୍ତ(sename);
	ମୁକ୍ତ(lvl);
#endif

	ଫେରନ୍ତୁ sc;
}

/* Set the execution context to the default for the specified user */
ଶୂନ୍ୟ
ssh_selinux_setup_exec_context(ଅକ୍ଷର *pwname)
{
	ଅକ୍ଷର *user_ctx = ଖାଲି;

	ଯଦି (!ssh_selinux_enabled())
		ଫେରନ୍ତୁ;

	debug3("%s: setting execution context", __func__);

	user_ctx = ssh_selinux_getctxbyname(pwname);
	ଯଦି (setexeccon(user_ctx) != 0) {
		ବାଛ (security_getenforce()) {
		ସ୍ଥିତି -1:
			fatal("%s: security_getenforce() failed", __func__);
		ସ୍ଥିତି 0:
			error("%s: Failed to set SELinux execution "
			    "context for %s", __func__, pwname);
			ଭାଙ୍ଗ;
		ପୂର୍ବନିର୍ଦ୍ଧାରିତ:
			fatal("%s: Failed to set SELinux execution context "
			    "for %s (in enforcing mode)", __func__, pwname);
		}
	}
	ଯଦି (user_ctx != ଖାଲି)
		freecon(user_ctx);

	debug3("%s: done", __func__);
}

/* Set the TTY context for the specified user */
ଶୂନ୍ୟ
ssh_selinux_setup_pty(ଅକ୍ଷର *pwname, ଅଚଳ ଅକ୍ଷର *tty)
{
	ଅକ୍ଷର *new_tty_ctx = ଖାଲି, *user_ctx = ଖାଲି, *old_tty_ctx = ଖାଲି;
	security_class_t chrclass;

	ଯଦି (!ssh_selinux_enabled())
		ଫେରନ୍ତୁ;

	debug3("%s: setting TTY context on %s", __func__, tty);

	user_ctx = ssh_selinux_getctxbyname(pwname);

	/* XXX: should these calls fatal() upon failure in enforcing mode? */

	ଯଦି (getfilecon(tty, &old_tty_ctx) == -1) {
		error("%s: getfilecon: %s", __func__, strerror(errno));
		ଯାଅ out;
	}
	ଯଦି ((chrclass = string_to_security_class("chr_file")) == 0) {
		error("%s: couldn't get security class for chr_file", __func__);
		ଯାଅ out;
	}
	ଯଦି (security_compute_relabel(user_ctx, old_tty_ctx,
	    chrclass, &new_tty_ctx) != 0) {
		error("%s: security_compute_relabel: %s",
		    __func__, strerror(errno));
		ଯାଅ out;
	}

	ଯଦି (setfilecon(tty, new_tty_ctx) != 0)
		error("%s: setfilecon: %s", __func__, strerror(errno));
 out:
	ଯଦି (new_tty_ctx != ଖାଲି)
		freecon(new_tty_ctx);
	ଯଦି (old_tty_ctx != ଖାଲି)
		freecon(old_tty_ctx);
	ଯଦି (user_ctx != ଖାଲି)
		freecon(user_ctx);
	debug3("%s: done", __func__);
}

ଶୂନ୍ୟ
ssh_selinux_change_context(ଅଚଳ ଅକ୍ଷର *newname)
{
	ଅକ୍ଷର *oldctx, *newctx, *cx, *cx2;
	LogLevel log_level = SYSLOG_LEVEL_INFO;

	ଯଦି (!ssh_selinux_enabled())
		ଫେରନ୍ତୁ;

	ଯଦି (getcon(&oldctx) < 0) {
		logit_f("getcon failed with %s", strerror(errno));
		ଫେରନ୍ତୁ;
	}
	ଯଦି ((cx = strchr(oldctx, ':')) == ଖାଲି ||
	    (cx = strchr(cx + 1, ':')) == ଖାଲି ||
	    (cx - oldctx) >= INT_MAX) {
		logit_f("unparsable context %s", oldctx);
		ଫେରନ୍ତୁ;
	}

	/*
	 * Check whether we are attempting to switch away from an unconfined
	 * security context.
	 */
	ଯଦି (strncmp(cx, SSH_SELINUX_UNCONFINED_TYPE,
	    ଆକାର(SSH_SELINUX_UNCONFINED_TYPE) - 1) == 0)
		log_level = SYSLOG_LEVEL_DEBUG3;

	cx2 = strchr(cx + 1, ':');
	xasprintf(&newctx, "%.*s%s%s", (ପୂର୍ଣ୍ଣସଂଖ୍ୟା)(cx - oldctx + 1), oldctx,
	    newname, cx2 == ଖାଲି ? "" : cx2);

	debug3_f("setting context from '%s' to '%s'", oldctx, newctx);
	ଯଦି (setcon(newctx) < 0)
		do_log2_f(log_level, "setcon %s from %s failed with %s",
		    newctx, oldctx, strerror(errno));
	ମୁକ୍ତ(oldctx);
	ମୁକ୍ତ(newctx);
}

ଶୂନ୍ୟ
ssh_selinux_setfscreatecon(ଅଚଳ ଅକ୍ଷର *path)
{
	ଅକ୍ଷର *context;
	ସଂରଚନା selabel_handle *shandle = ଖାଲି;

	ଯଦି (!ssh_selinux_enabled())
		ଫେରନ୍ତୁ;
	ଯଦି (path == ଖାଲି) {
		setfscreatecon(ଖାଲି);
		ଫେରନ୍ତୁ;
	}
	ଯଦି ((shandle = selabel_open(SELABEL_CTX_FILE, ଖାଲି, 0)) == ଖାଲି) {
		debug_f("selabel_open failed");
		ଫେରନ୍ତୁ;
	}
	ଯଦି (selabel_lookup(shandle, &context, path, 0700) == 0)
		setfscreatecon(context);
	selabel_close(shandle);
}

#endif /* WITH_SELINUX */
