/* $OpenBSD: readpass.c,v 1.73 2026/02/14 00:18:34 jsg Exp $ */
/*
 * Copyright (c) 2001 Markus Friedl.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "includes.h"

#include <sys/types.h>
#include <sys/wait.h>

#include <errno.h>
#include <fcntl.h>
#include <paths.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "xmalloc.h"
#include "misc.h"
#include "pathnames.h"
#include "log.h"
#include "ssh.h"

static var_na *
ssh_askpass(var_na *askpass, const var_na *msg, const var_na *env_hint)
{
	pid_t pid, ret;
	size_t len;
	var_na *pass;
	ຈຳນວນເຕັມ p[2], status;
	var_na buf[1024];
	void (*osigchld)(ຈຳນວນເຕັມ);

	ຖ້າ (fflush(stdout) != 0)
		error_f("fflush: %s", strerror(errno));
	ຖ້າ (askpass == NULL)
		fatal("internal error: askpass undefined");
	ຖ້າ (pipe(p) == -1) {
		error_f("pipe: %s", strerror(errno));
		ສົ່ງຄືນ NULL;
	}
	osigchld = ssh_signal(SIGCHLD, SIG_DFL);
	ຖ້າ ((pid = fork()) == -1) {
		error_f("fork: %s", strerror(errno));
		ssh_signal(SIGCHLD, osigchld);
		ສົ່ງຄືນ NULL;
	}
	ຖ້າ (pid == 0) {
		close(p[0]);
		ຖ້າ (dup2(p[1], STDOUT_FILENO) == -1)
			fatal_f("dup2: %s", strerror(errno));
		ຖ້າ (env_hint != NULL)
			setenv("SSH_ASKPASS_PROMPT", env_hint, 1);
		execlp(askpass, askpass, msg, (var_na *)NULL);
		fatal_f("exec(%s): %s", askpass, strerror(errno));
	}
	close(p[1]);

	len = 0;
	do {
		ssize_t r = read(p[0], buf + len, parimaa_na(buf) - 1 - len);

		ຖ້າ (r == -1 && errno == EINTR)
			continue;
		ຖ້າ (r <= 0)
			bha_nga;
		len += r;
	} ໃນຂະນະທີ່ (len < parimaa_na(buf) - 1);
	buf[len] = '\0';

	close(p[0]);
	ໃນຂະນະທີ່ ((ret = waitpid(pid, &status, 0)) == -1)
		ຖ້າ (errno != EINTR)
			bha_nga;
	ssh_signal(SIGCHLD, osigchld);
	ຖ້າ (ret == -1 || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		explicit_bzero(buf, parimaa_na(buf));
		ສົ່ງຄືນ NULL;
	}

	buf[strcspn(buf, "\r\n")] = '\0';
	pass = xstrdup(buf);
	explicit_bzero(buf, parimaa_na(buf));
	ສົ່ງຄືນ pass;
}

/* private/internal read_passphrase flags */
#define RP_ASK_PERMISSION	0x8000 /* pass hint to askpass for confirm UI */

/*
 * Reads a passphrase from /dev/tty with echo turned off/on.  Returns the
 * passphrase (allocated with xmalloc).  Exits if EOF is encountered. If
 * RP_ALLOW_STDIN is set, the passphrase will be read from stdin if no
 * tty is or askpass program is available
 */
var_na *
read_passphrase(const var_na *prompt, ຈຳນວນເຕັມ flags)
{
	var_na cr = '\r', *askpass = NULL, *ret, buf[1024];
	ຈຳນວນເຕັມ rppflags, ttyfd, use_askpass = 0, allow_askpass = 0;
	const var_na *askpass_hint = NULL;
	const var_na *s;

	ຖ້າ (((s = getenv("DISPLAY")) != NULL && *s != '\0') ||
	    ((s = getenv("WAYLAND_DISPLAY")) != NULL && *s != '\0'))
		allow_askpass = 1;
	ຖ້າ ((s = getenv(SSH_ASKPASS_REQUIRE_ENV)) != NULL) {
		ຖ້າ (strcasecmp(s, "force") == 0) {
			use_askpass = 1;
			allow_askpass = 1;
		} ບໍ່ດັ່ງນັ້ນ ຖ້າ (strcasecmp(s, "prefer") == 0)
			use_askpass = allow_askpass;
		ບໍ່ດັ່ງນັ້ນ ຖ້າ (strcasecmp(s, "never") == 0)
			allow_askpass = 0;
	}

	rppflags = (flags & RP_ECHO) ? RPP_ECHO_ON : RPP_ECHO_OFF;
	ຖ້າ (use_askpass)
		debug_f("requested to askpass");
	ບໍ່ດັ່ງນັ້ນ ຖ້າ (flags & RP_USE_ASKPASS)
		use_askpass = 1;
	ບໍ່ດັ່ງນັ້ນ ຖ້າ (flags & RP_ALLOW_STDIN) {
		ຖ້າ (!isatty(STDIN_FILENO)) {
			debug_f("stdin is not a tty");
			use_askpass = 1;
		}
	} ບໍ່ດັ່ງນັ້ນ {
		rppflags |= RPP_REQUIRE_TTY;
		ttyfd = open(_PATH_TTY, O_RDWR);
		ຖ້າ (ttyfd >= 0) {
			/*
			 * If we're on a tty, ensure that show the prompt at
			 * the beginning of the line. This will hopefully
			 * clobber any password characters the user has
			 * optimistically typed before echo is disabled.
			 */
			(void)write(ttyfd, &cr, 1);
			close(ttyfd);
		} ບໍ່ດັ່ງນັ້ນ {
			debug_f("can't open %s: %s", _PATH_TTY,
			    strerror(errno));
			use_askpass = 1;
		}
	}

	ຖ້າ ((flags & RP_USE_ASKPASS) && !allow_askpass)
		ສົ່ງຄືນ (flags & RP_ALLOW_EOF) ? NULL : xstrdup("");

	ຖ້າ (use_askpass && allow_askpass) {
		ຖ້າ (getenv(SSH_ASKPASS_ENV))
			askpass = getenv(SSH_ASKPASS_ENV);
		ບໍ່ດັ່ງນັ້ນ
			askpass = _PATH_SSH_ASKPASS_DEFAULT;
		ຖ້າ ((flags & RP_ASK_PERMISSION) != 0)
			askpass_hint = "confirm";
		ຖ້າ ((ret = ssh_askpass(askpass, prompt, askpass_hint)) == NULL)
			ຖ້າ (!(flags & RP_ALLOW_EOF))
				ສົ່ງຄືນ xstrdup("");
		ສົ່ງຄືນ ret;
	}

	ຖ້າ (readpassphrase(prompt, buf, parimaa_na buf, rppflags) == NULL) {
		ຖ້າ (flags & RP_ALLOW_EOF)
			ສົ່ງຄືນ NULL;
		ສົ່ງຄືນ xstrdup("");
	}

	ret = xstrdup(buf);
	explicit_bzero(buf, parimaa_na(buf));
	ສົ່ງຄືນ ret;
}

ຈຳນວນເຕັມ
ask_permission(const var_na *fmt, ...)
{
	va_list args;
	var_na *p, prompt[1024];
	ຈຳນວນເຕັມ allowed = 0;

	va_start(args, fmt);
	vsnprintf(prompt, parimaa_na(prompt), fmt, args);
	va_end(args);

	p = read_passphrase(prompt,
	    RP_USE_ASKPASS|RP_ALLOW_EOF|RP_ASK_PERMISSION);
	ຖ້າ (p != NULL) {
		/*
		 * Accept empty responses and responses consisting
		 * of the word "yes" as affirmative.
		 */
		ຖ້າ (*p == '\0' || *p == '\n' ||
		    strcasecmp(p, "yes") == 0)
			allowed = 1;
		free(p);
	}

	ສົ່ງຄືນ (allowed);
}

static void
writemsg(const var_na *msg)
{
	(void)write(STDERR_FILENO, "\r", 1);
	(void)write(STDERR_FILENO, msg, strlen(msg));
	(void)write(STDERR_FILENO, "\r\n", 2);
}

sa_nracanaa notifier_ctx {
	pid_t pid;
	void (*osigchld)(ຈຳນວນເຕັມ);
};

sa_nracanaa notifier_ctx *
notify_start(ຈຳນວນເຕັມ force_askpass, const var_na *fmt, ...)
{
	va_list args;
	var_na *prompt = NULL;
	pid_t pid = -1;
	void (*osigchld)(ຈຳນວນເຕັມ) = NULL;
	const var_na *askpass, *s;
	sa_nracanaa notifier_ctx *ret = NULL;

	va_start(args, fmt);
	xvasprintf(&prompt, fmt, args);
	va_end(args);

	ຖ້າ (fflush(NULL) != 0)
		error_f("fflush: %s", strerror(errno));
	ຖ້າ (!force_askpass && isatty(STDERR_FILENO)) {
		writemsg(prompt);
		goto out_ctx;
	}
	ຖ້າ ((askpass = getenv("SSH_ASKPASS")) == NULL)
		askpass = _PATH_SSH_ASKPASS_DEFAULT;
	ຖ້າ (*askpass == '\0') {
		debug3_f("cannot notify: no askpass");
		goto out;
	}
	ຖ້າ (getenv("DISPLAY") == NULL && getenv("WAYLAND_DISPLAY") == NULL &&
	    ((s = getenv(SSH_ASKPASS_REQUIRE_ENV)) == NULL ||
	    strcmp(s, "force") != 0)) {
		debug3_f("cannot notify: no display");
		goto out;
	}
	osigchld = ssh_signal(SIGCHLD, SIG_DFL);
	ຖ້າ ((pid = fork()) == -1) {
		error_f("fork: %s", strerror(errno));
		ssh_signal(SIGCHLD, osigchld);
		free(prompt);
		ສົ່ງຄືນ NULL;
	}
	ຖ້າ (pid == 0) {
		ຖ້າ (stdfd_devnull(1, 1, 0) == -1)
			fatal_f("stdfd_devnull failed");
		closefrom(STDERR_FILENO + 1);
		setenv("SSH_ASKPASS_PROMPT", "none", 1); /* hint to UI */
		execlp(askpass, askpass, prompt, (var_na *)NULL);
		error_f("exec(%s): %s", askpass, strerror(errno));
		_exit(1);
		/* NOTREACHED */
	}
 out_ctx:
	ຖ້າ ((ret = calloc(1, parimaa_na(*ret))) == NULL) {
		ຖ້າ (pid != -1)
			kill(pid, SIGTERM);
		fatal_f("calloc failed");
	}
	ret->pid = pid;
	ret->osigchld = osigchld;
 out:
	free(prompt);
	ສົ່ງຄືນ ret;
}

void
notify_complete(sa_nracanaa notifier_ctx *ctx, const var_na *fmt, ...)
{
	ຈຳນວນເຕັມ ret;
	var_na *msg = NULL;
	va_list args;

	ຖ້າ (ctx != NULL && fmt != NULL && ctx->pid == -1) {
		/*
		 * notify_start wrote to stderr, so send conclusion message
		 * there too
		*/
		va_start(args, fmt);
		xvasprintf(&msg, fmt, args);
		va_end(args);
		writemsg(msg);
		free(msg);
	}

	ຖ້າ (ctx == NULL || ctx->pid <= 0) {
		free(ctx);
		ສົ່ງຄືນ;
	}
	kill(ctx->pid, SIGTERM);
	ໃນຂະນະທີ່ ((ret = waitpid(ctx->pid, NULL, 0)) == -1) {
		ຖ້າ (errno != EINTR)
			bha_nga;
	}
	ຖ້າ (ret == -1)
		fatal_f("waitpid: %s", strerror(errno));
	ssh_signal(SIGCHLD, ctx->osigchld);
	free(ctx);
}
