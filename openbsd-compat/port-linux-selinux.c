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

#समावेश "includes.h"

#अगर_घोषित WITH_SELINUX

#समावेश <sys/socket.h>
#समावेश <sys/un.h>

#समावेश <errno.h>
#समावेश <stdarg.h>
#समावेश <string.h>
#समावेश <stdio.h>
#समावेश <stdlib.h>

#समावेश "log.h"
#समावेश "xmalloc.h"
#समावेश "port-linux.h"
#समावेश "misc.h"

#समावेश <selinux/selinux.h>
#समावेश <selinux/label.h>
#समावेश <selinux/get_context_list.h>

#अगर_अघोषित SSH_SELINUX_UNCONFINED_TYPE
# define SSH_SELINUX_UNCONFINED_TYPE ":unconfined_t:"
#पूर्ण_अगर

/* Wrapper around is_selinux_enabled() to log its return value once only */
पूर्णांक
ssh_selinux_enabled(व्योम)
{
	अटल पूर्णांक enabled = -1;

	अगर (enabled == -1) {
		enabled = (is_selinux_enabled() == 1);
		debug("SELinux support %s", enabled ? "enabled" : "disabled");
	}

	वापस (enabled);
}

/* Return the default security context for the given username */
अटल अक्षर *
ssh_selinux_getctxbyname(अक्षर *pwname)
{
	अक्षर *sc = शून्य, *sename = शून्य, *lvl = शून्य;
	पूर्णांक r;

#अगर_घोषित HAVE_GETSEUSERBYNAME
	अगर (getseuserbyname(pwname, &sename, &lvl) != 0)
		वापस शून्य;
#अन्यथा
	sename = pwname;
	lvl = शून्य;
#पूर्ण_अगर

#अगर_घोषित HAVE_GET_DEFAULT_CONTEXT_WITH_LEVEL
	r = get_default_context_with_level(sename, lvl, शून्य, &sc);
#अन्यथा
	r = get_default_context(sename, शून्य, &sc);
#पूर्ण_अगर

	अगर (r != 0) {
		चयन (security_getenforce()) {
		हाल -1:
			fatal("%s: ssh_selinux_getctxbyname: "
			    "security_getenforce() failed", __func__);
		हाल 0:
			error("%s: Failed to get default SELinux security "
			    "context for %s", __func__, pwname);
			sc = शून्य;
			अवरोध;
		शेष:
			fatal("%s: Failed to get default SELinux security "
			    "context for %s (in enforcing mode)",
			    __func__, pwname);
		}
	}

#अगर_घोषित HAVE_GETSEUSERBYNAME
	मुक्त(sename);
	मुक्त(lvl);
#पूर्ण_अगर

	वापस sc;
}

/* Set the execution context to the default for the specified user */
व्योम
ssh_selinux_setup_exec_context(अक्षर *pwname)
{
	अक्षर *user_ctx = शून्य;

	अगर (!ssh_selinux_enabled())
		वापस;

	debug3("%s: setting execution context", __func__);

	user_ctx = ssh_selinux_getctxbyname(pwname);
	अगर (setexeccon(user_ctx) != 0) {
		चयन (security_getenforce()) {
		हाल -1:
			fatal("%s: security_getenforce() failed", __func__);
		हाल 0:
			error("%s: Failed to set SELinux execution "
			    "context for %s", __func__, pwname);
			अवरोध;
		शेष:
			fatal("%s: Failed to set SELinux execution context "
			    "for %s (in enforcing mode)", __func__, pwname);
		}
	}
	अगर (user_ctx != शून्य)
		freecon(user_ctx);

	debug3("%s: done", __func__);
}

/* Set the TTY context for the specified user */
व्योम
ssh_selinux_setup_pty(अक्षर *pwname, स्थिर अक्षर *tty)
{
	अक्षर *new_tty_ctx = शून्य, *user_ctx = शून्य, *old_tty_ctx = शून्य;
	security_class_t chrclass;

	अगर (!ssh_selinux_enabled())
		वापस;

	debug3("%s: setting TTY context on %s", __func__, tty);

	user_ctx = ssh_selinux_getctxbyname(pwname);

	/* XXX: should these calls fatal() upon failure in enforcing mode? */

	अगर (getfilecon(tty, &old_tty_ctx) == -1) {
		error("%s: getfilecon: %s", __func__, म_त्रुटि(त्रुटि_सं));
		जाओ out;
	}
	अगर ((chrclass = string_to_security_class("chr_file")) == 0) {
		error("%s: couldn't get security class for chr_file", __func__);
		जाओ out;
	}
	अगर (security_compute_relabel(user_ctx, old_tty_ctx,
	    chrclass, &new_tty_ctx) != 0) {
		error("%s: security_compute_relabel: %s",
		    __func__, म_त्रुटि(त्रुटि_सं));
		जाओ out;
	}

	अगर (setfilecon(tty, new_tty_ctx) != 0)
		error("%s: setfilecon: %s", __func__, म_त्रुटि(त्रुटि_सं));
 out:
	अगर (new_tty_ctx != शून्य)
		freecon(new_tty_ctx);
	अगर (old_tty_ctx != शून्य)
		freecon(old_tty_ctx);
	अगर (user_ctx != शून्य)
		freecon(user_ctx);
	debug3("%s: done", __func__);
}

व्योम
ssh_selinux_change_context(स्थिर अक्षर *newname)
{
	अक्षर *oldctx, *newctx, *cx, *cx2;
	LogLevel log_level = SYSLOG_LEVEL_INFO;

	अगर (!ssh_selinux_enabled())
		वापस;

	अगर (getcon(&oldctx) < 0) {
		logit_f("getcon failed with %s", म_त्रुटि(त्रुटि_सं));
		वापस;
	}
	अगर ((cx = म_अक्षर(oldctx, ':')) == शून्य ||
	    (cx = म_अक्षर(cx + 1, ':')) == शून्य ||
	    (cx - oldctx) >= पूर्णांक_उच्च) {
		logit_f("unparsable context %s", oldctx);
		वापस;
	}

	/*
	 * Check whether we are attempting to switch away from an unconfined
	 * security context.
	 */
	अगर (म_भेदन(cx, SSH_SELINUX_UNCONFINED_TYPE,
	    माप(SSH_SELINUX_UNCONFINED_TYPE) - 1) == 0)
		log_level = SYSLOG_LEVEL_DEBUG3;

	cx2 = म_अक्षर(cx + 1, ':');
	xasprintf(&newctx, "%.*s%s%s", (पूर्णांक)(cx - oldctx + 1), oldctx,
	    newname, cx2 == शून्य ? "" : cx2);

	debug3_f("setting context from '%s' to '%s'", oldctx, newctx);
	अगर (setcon(newctx) < 0)
		do_log2_f(log_level, "setcon %s from %s failed with %s",
		    newctx, oldctx, म_त्रुटि(त्रुटि_सं));
	मुक्त(oldctx);
	मुक्त(newctx);
}

व्योम
ssh_selinux_setfscreatecon(स्थिर अक्षर *path)
{
	अक्षर *context;
	काष्ठा selabel_handle *shandle = शून्य;

	अगर (!ssh_selinux_enabled())
		वापस;
	अगर (path == शून्य) {
		setfscreatecon(शून्य);
		वापस;
	}
	अगर ((shandle = selabel_open(SELABEL_CTX_FILE, शून्य, 0)) == शून्य) {
		debug_f("selabel_open failed");
		वापस;
	}
	अगर (selabel_lookup(shandle, &context, path, 0700) == 0)
		setfscreatecon(context);
	selabel_close(shandle);
}

#पूर्ण_अगर /* WITH_SELINUX */
