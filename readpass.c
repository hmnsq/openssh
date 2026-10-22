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

static char *
ssh_askpass(char *askpass, const char *msg, const char *env_hint)
{
	pid_t pid, ret;
	size_t len;
	char *pass;
	정수 p[2], status;
	char buf[1024];
	void (*osigchld)(정수);

	만약 (fflush(stdout) != 0)
		error_f("fflush: %s", strerror(errno));
	만약 (askpass == NULL)
		fatal("internal error: askpass undefined");
	만약 (pipe(p) == -1) {
		error_f("pipe: %s", strerror(errno));
		반환 NULL;
	}
	osigchld = ssh_signal(SIGCHLD, SIG_DFL);
	만약 ((pid = fork()) == -1) {
		error_f("fork: %s", strerror(errno));
		ssh_signal(SIGCHLD, osigchld);
		반환 NULL;
	}
	만약 (pid == 0) {
		close(p[0]);
		만약 (dup2(p[1], STDOUT_FILENO) == -1)
			fatal_f("dup2: %s", strerror(errno));
		만약 (env_hint != NULL)
			setenv("SSH_ASKPASS_PROMPT", env_hint, 1);
		execlp(askpass, askpass, msg, (char *)NULL);
		fatal_f("exec(%s): %s", askpass, strerror(errno));
	}
	close(p[1]);

	len = 0;
	do {
		ssize_t r = read(p[0], buf + len, sizeof(buf) - 1 - len);

		만약 (r == -1 && errno == EINTR)
			continue;
		만약 (r <= 0)
			break;
		len += r;
	} 동안 (len < sizeof(buf) - 1);
	buf[len] = '\0';

	close(p[0]);
	동안 ((ret = waitpid(pid, &status, 0)) == -1)
		만약 (errno != EINTR)
			break;
	ssh_signal(SIGCHLD, osigchld);
	만약 (ret == -1 || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		explicit_bzero(buf, sizeof(buf));
		반환 NULL;
	}

	buf[strcspn(buf, "\r\n")] = '\0';
	pass = xstrdup(buf);
	explicit_bzero(buf, sizeof(buf));
	반환 pass;
}

/* private/internal read_passphrase flags */
#define RP_ASK_PERMISSION	0x8000 /* pass hint to askpass for confirm UI */

/*
 * Reads a passphrase from /dev/tty with echo turned off/on.  Returns the
 * passphrase (allocated with xmalloc).  Exits if EOF is encountered. If
 * RP_ALLOW_STDIN is set, the passphrase will be read from stdin if no
 * tty is or askpass program is available
 */
char *
read_passphrase(const char *prompt, 정수 flags)
{
	char cr = '\r', *askpass = NULL, *ret, buf[1024];
	정수 rppflags, ttyfd, use_askpass = 0, allow_askpass = 0;
	const char *askpass_hint = NULL;
	const char *s;

	만약 (((s = getenv("DISPLAY")) != NULL && *s != '\0') ||
	    ((s = getenv("WAYLAND_DISPLAY")) != NULL && *s != '\0'))
		allow_askpass = 1;
	만약 ((s = getenv(SSH_ASKPASS_REQUIRE_ENV)) != NULL) {
		만약 (strcasecmp(s, "force") == 0) {
			use_askpass = 1;
			allow_askpass = 1;
		} 아니면 만약 (strcasecmp(s, "prefer") == 0)
			use_askpass = allow_askpass;
		아니면 만약 (strcasecmp(s, "never") == 0)
			allow_askpass = 0;
	}

	rppflags = (flags & RP_ECHO) ? RPP_ECHO_ON : RPP_ECHO_OFF;
	만약 (use_askpass)
		debug_f("requested to askpass");
	아니면 만약 (flags & RP_USE_ASKPASS)
		use_askpass = 1;
	아니면 만약 (flags & RP_ALLOW_STDIN) {
		만약 (!isatty(STDIN_FILENO)) {
			debug_f("stdin is not a tty");
			use_askpass = 1;
		}
	} 아니면 {
		rppflags |= RPP_REQUIRE_TTY;
		ttyfd = open(_PATH_TTY, O_RDWR);
		만약 (ttyfd >= 0) {
			/*
			 * If we're on a tty, ensure that show the prompt at
			 * the beginning of the line. This will hopefully
			 * clobber any password characters the user has
			 * optimistically typed before echo is disabled.
			 */
			(void)write(ttyfd, &cr, 1);
			close(ttyfd);
		} 아니면 {
			debug_f("can't open %s: %s", _PATH_TTY,
			    strerror(errno));
			use_askpass = 1;
		}
	}

	만약 ((flags & RP_USE_ASKPASS) && !allow_askpass)
		반환 (flags & RP_ALLOW_EOF) ? NULL : xstrdup("");

	만약 (use_askpass && allow_askpass) {
		만약 (getenv(SSH_ASKPASS_ENV))
			askpass = getenv(SSH_ASKPASS_ENV);
		아니면
			askpass = _PATH_SSH_ASKPASS_DEFAULT;
		만약 ((flags & RP_ASK_PERMISSION) != 0)
			askpass_hint = "confirm";
		만약 ((ret = ssh_askpass(askpass, prompt, askpass_hint)) == NULL)
			만약 (!(flags & RP_ALLOW_EOF))
				반환 xstrdup("");
		반환 ret;
	}

	만약 (readpassphrase(prompt, buf, sizeof buf, rppflags) == NULL) {
		만약 (flags & RP_ALLOW_EOF)
			반환 NULL;
		반환 xstrdup("");
	}

	ret = xstrdup(buf);
	explicit_bzero(buf, sizeof(buf));
	반환 ret;
}

정수
ask_permission(const char *fmt, ...)
{
	va_list args;
	char *p, prompt[1024];
	정수 allowed = 0;

	va_start(args, fmt);
	vsnprintf(prompt, sizeof(prompt), fmt, args);
	va_end(args);

	p = read_passphrase(prompt,
	    RP_USE_ASKPASS|RP_ALLOW_EOF|RP_ASK_PERMISSION);
	만약 (p != NULL) {
		/*
		 * Accept empty responses and responses consisting
		 * of the word "yes" as affirmative.
		 */
		만약 (*p == '\0' || *p == '\n' ||
		    strcasecmp(p, "yes") == 0)
			allowed = 1;
		free(p);
	}

	반환 (allowed);
}

static void
writemsg(const char *msg)
{
	(void)write(STDERR_FILENO, "\r", 1);
	(void)write(STDERR_FILENO, msg, strlen(msg));
	(void)write(STDERR_FILENO, "\r\n", 2);
}

struct notifier_ctx {
	pid_t pid;
	void (*osigchld)(정수);
};

struct notifier_ctx *
notify_start(정수 force_askpass, const char *fmt, ...)
{
	va_list args;
	char *prompt = NULL;
	pid_t pid = -1;
	void (*osigchld)(정수) = NULL;
	const char *askpass, *s;
	struct notifier_ctx *ret = NULL;

	va_start(args, fmt);
	xvasprintf(&prompt, fmt, args);
	va_end(args);

	만약 (fflush(NULL) != 0)
		error_f("fflush: %s", strerror(errno));
	만약 (!force_askpass && isatty(STDERR_FILENO)) {
		writemsg(prompt);
		goto out_ctx;
	}
	만약 ((askpass = getenv("SSH_ASKPASS")) == NULL)
		askpass = _PATH_SSH_ASKPASS_DEFAULT;
	만약 (*askpass == '\0') {
		debug3_f("cannot notify: no askpass");
		goto out;
	}
	만약 (getenv("DISPLAY") == NULL && getenv("WAYLAND_DISPLAY") == NULL &&
	    ((s = getenv(SSH_ASKPASS_REQUIRE_ENV)) == NULL ||
	    strcmp(s, "force") != 0)) {
		debug3_f("cannot notify: no display");
		goto out;
	}
	osigchld = ssh_signal(SIGCHLD, SIG_DFL);
	만약 ((pid = fork()) == -1) {
		error_f("fork: %s", strerror(errno));
		ssh_signal(SIGCHLD, osigchld);
		free(prompt);
		반환 NULL;
	}
	만약 (pid == 0) {
		만약 (stdfd_devnull(1, 1, 0) == -1)
			fatal_f("stdfd_devnull failed");
		closefrom(STDERR_FILENO + 1);
		setenv("SSH_ASKPASS_PROMPT", "none", 1); /* hint to UI */
		execlp(askpass, askpass, prompt, (char *)NULL);
		error_f("exec(%s): %s", askpass, strerror(errno));
		_exit(1);
		/* NOTREACHED */
	}
 out_ctx:
	만약 ((ret = calloc(1, sizeof(*ret))) == NULL) {
		만약 (pid != -1)
			kill(pid, SIGTERM);
		fatal_f("calloc failed");
	}
	ret->pid = pid;
	ret->osigchld = osigchld;
 out:
	free(prompt);
	반환 ret;
}

void
notify_complete(struct notifier_ctx *ctx, const char *fmt, ...)
{
	정수 ret;
	char *msg = NULL;
	va_list args;

	만약 (ctx != NULL && fmt != NULL && ctx->pid == -1) {
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

	만약 (ctx == NULL || ctx->pid <= 0) {
		free(ctx);
		반환;
	}
	kill(ctx->pid, SIGTERM);
	동안 ((ret = waitpid(ctx->pid, NULL, 0)) == -1) {
		만약 (errno != EINTR)
			break;
	}
	만약 (ret == -1)
		fatal_f("waitpid: %s", strerror(errno));
	ssh_signal(SIGCHLD, ctx->osigchld);
	free(ctx);
}
