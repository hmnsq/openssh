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

#ضمن "includes.h"

#ضمن <sys/types.h>
#ضمن <sys/wait.h>

#ضمن <errno.h>
#ضمن <fcntl.h>
#ضمن <paths.h>
#ضمن <signal.h>
#ضمن <stdarg.h>
#ضمن <stdio.h>
#ضمن <stdlib.h>
#ضمن <string.h>
#ضمن <unistd.h>

#ضمن "xmalloc.h"
#ضمن "misc.h"
#ضمن "pathnames.h"
#ضمن "log.h"
#ضمن "ssh.h"

ساكن حرف *
ssh_askpass(حرف *askpass, ثابت حرف *msg, ثابت حرف *env_hint)
{
	pid_t pid, ret;
	size_t len;
	حرف *pass;
	صحيح p[2], status;
	حرف buf[1024];
	فراغ (*osigchld)(صحيح);

	אם (fflush(stdout) != 0)
		error_f("fflush: %s", strerror(errno));
	אם (askpass == عدم)
		fatal("internal error: askpass undefined");
	אם (pipe(p) == -1) {
		error_f("pipe: %s", strerror(errno));
		החזר عدم;
	}
	osigchld = ssh_signal(SIGCHLD, SIG_DFL);
	אם ((pid = fork()) == -1) {
		error_f("fork: %s", strerror(errno));
		ssh_signal(SIGCHLD, osigchld);
		החזר عدم;
	}
	אם (pid == 0) {
		close(p[0]);
		אם (dup2(p[1], STDOUT_FILENO) == -1)
			fatal_f("dup2: %s", strerror(errno));
		אם (env_hint != عدم)
			setenv("SSH_ASKPASS_PROMPT", env_hint, 1);
		execlp(askpass, askpass, msg, (حرف *)عدم);
		fatal_f("exec(%s): %s", askpass, strerror(errno));
	}
	close(p[1]);

	len = 0;
	עשה {
		ssize_t r = اقرأ(p[0], buf + len, حجم(buf) - 1 - len);

		אם (r == -1 && errno == EINTR)
			استمر;
		אם (r <= 0)
			اكسر;
		len += r;
	} כלעוד (len < حجم(buf) - 1);
	buf[len] = '\0';

	close(p[0]);
	כלעוד ((ret = waitpid(pid, &status, 0)) == -1)
		אם (errno != EINTR)
			اكسر;
	ssh_signal(SIGCHLD, osigchld);
	אם (ret == -1 || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		explicit_bzero(buf, حجم(buf));
		החזר عدم;
	}

	buf[strcspn(buf, "\r\n")] = '\0';
	pass = xstrdup(buf);
	explicit_bzero(buf, حجم(buf));
	החזר pass;
}

/* private/internal read_passphrase flags */
#define RP_ASK_PERMISSION	0x8000 /* pass hint to askpass for confirm UI */

/*
 * Reads a passphrase from /dev/tty with echo turned off/on.  Returns the
 * passphrase (allocated with xmalloc).  Exits if EOF is encountered. If
 * RP_ALLOW_STDIN is set, the passphrase will be read from stdin if no
 * tty is or askpass program is available
 */
حرف *
read_passphrase(ثابت حرف *prompt, صحيح flags)
{
	حرف cr = '\r', *askpass = عدم, *ret, buf[1024];
	صحيح rppflags, ttyfd, use_askpass = 0, allow_askpass = 0;
	ثابت حرف *askpass_hint = عدم;
	ثابت حرف *s;

	אם (((s = getenv("DISPLAY")) != عدم && *s != '\0') ||
	    ((s = getenv("WAYLAND_DISPLAY")) != عدم && *s != '\0'))
		allow_askpass = 1;
	אם ((s = getenv(SSH_ASKPASS_REQUIRE_ENV)) != عدم) {
		אם (strcasecmp(s, "force") == 0) {
			use_askpass = 1;
			allow_askpass = 1;
		} אחרת אם (strcasecmp(s, "prefer") == 0)
			use_askpass = allow_askpass;
		אחרת אם (strcasecmp(s, "never") == 0)
			allow_askpass = 0;
	}

	rppflags = (flags & RP_ECHO) ? RPP_ECHO_ON : RPP_ECHO_OFF;
	אם (use_askpass)
		debug_f("requested to askpass");
	אחרת אם (flags & RP_USE_ASKPASS)
		use_askpass = 1;
	אחרת אם (flags & RP_ALLOW_STDIN) {
		אם (!isatty(STDIN_FILENO)) {
			debug_f("stdin is not a tty");
			use_askpass = 1;
		}
	} אחרת {
		rppflags |= RPP_REQUIRE_TTY;
		ttyfd = open(_PATH_TTY, O_RDWR);
		אם (ttyfd >= 0) {
			/*
			 * If we're on a tty, ensure that show the prompt at
			 * the beginning of the line. This will hopefully
			 * clobber any password characters the user has
			 * optimistically typed before echo is disabled.
			 */
			(فراغ)اكتب(ttyfd, &cr, 1);
			close(ttyfd);
		} אחרת {
			debug_f("can't open %s: %s", _PATH_TTY,
			    strerror(errno));
			use_askpass = 1;
		}
	}

	אם ((flags & RP_USE_ASKPASS) && !allow_askpass)
		החזר (flags & RP_ALLOW_EOF) ? عدم : xstrdup("");

	אם (use_askpass && allow_askpass) {
		אם (getenv(SSH_ASKPASS_ENV))
			askpass = getenv(SSH_ASKPASS_ENV);
		אחרת
			askpass = _PATH_SSH_ASKPASS_DEFAULT;
		אם ((flags & RP_ASK_PERMISSION) != 0)
			askpass_hint = "confirm";
		אם ((ret = ssh_askpass(askpass, prompt, askpass_hint)) == عدم)
			אם (!(flags & RP_ALLOW_EOF))
				החזר xstrdup("");
		החזר ret;
	}

	אם (readpassphrase(prompt, buf, حجم buf, rppflags) == عدم) {
		אם (flags & RP_ALLOW_EOF)
			החזר عدم;
		החזר xstrdup("");
	}

	ret = xstrdup(buf);
	explicit_bzero(buf, حجم(buf));
	החזר ret;
}

صحيح
ask_permission(ثابت حرف *fmt, ...)
{
	va_list args;
	حرف *p, prompt[1024];
	صحيح allowed = 0;

	va_start(args, fmt);
	vsnprintf(prompt, حجم(prompt), fmt, args);
	va_end(args);

	p = read_passphrase(prompt,
	    RP_USE_ASKPASS|RP_ALLOW_EOF|RP_ASK_PERMISSION);
	אם (p != عدم) {
		/*
		 * Accept empty responses and responses consisting
		 * of the word "yes" as affirmative.
		 */
		אם (*p == '\0' || *p == '\n' ||
		    strcasecmp(p, "yes") == 0)
			allowed = 1;
		حرر(p);
	}

	החזר (allowed);
}

ساكن فراغ
writemsg(ثابت حرف *msg)
{
	(فراغ)اكتب(STDERR_FILENO, "\r", 1);
	(فراغ)اكتب(STDERR_FILENO, msg, strlen(msg));
	(فراغ)اكتب(STDERR_FILENO, "\r\n", 2);
}

بنية notifier_ctx {
	pid_t pid;
	فراغ (*osigchld)(صحيح);
};

بنية notifier_ctx *
notify_start(صحيح force_askpass, ثابت حرف *fmt, ...)
{
	va_list args;
	حرف *prompt = عدم;
	pid_t pid = -1;
	فراغ (*osigchld)(صحيح) = عدم;
	ثابت حرف *askpass, *s;
	بنية notifier_ctx *ret = عدم;

	va_start(args, fmt);
	xvasprintf(&prompt, fmt, args);
	va_end(args);

	אם (fflush(عدم) != 0)
		error_f("fflush: %s", strerror(errno));
	אם (!force_askpass && isatty(STDERR_FILENO)) {
		writemsg(prompt);
		اذهب out_ctx;
	}
	אם ((askpass = getenv("SSH_ASKPASS")) == عدم)
		askpass = _PATH_SSH_ASKPASS_DEFAULT;
	אם (*askpass == '\0') {
		debug3_f("cannot notify: no askpass");
		اذهب out;
	}
	אם (getenv("DISPLAY") == عدم && getenv("WAYLAND_DISPLAY") == عدم &&
	    ((s = getenv(SSH_ASKPASS_REQUIRE_ENV)) == عدم ||
	    strcmp(s, "force") != 0)) {
		debug3_f("cannot notify: no display");
		اذهب out;
	}
	osigchld = ssh_signal(SIGCHLD, SIG_DFL);
	אם ((pid = fork()) == -1) {
		error_f("fork: %s", strerror(errno));
		ssh_signal(SIGCHLD, osigchld);
		حرر(prompt);
		החזר عدم;
	}
	אם (pid == 0) {
		אם (stdfd_devnull(1, 1, 0) == -1)
			fatal_f("stdfd_devnull failed");
		closefrom(STDERR_FILENO + 1);
		setenv("SSH_ASKPASS_PROMPT", "none", 1); /* hint to UI */
		execlp(askpass, askpass, prompt, (حرف *)عدم);
		error_f("exec(%s): %s", askpass, strerror(errno));
		_exit(1);
		/* NOTREACHED */
	}
 out_ctx:
	אם ((ret = calloc(1, حجم(*ret))) == عدم) {
		אם (pid != -1)
			kill(pid, SIGTERM);
		fatal_f("calloc failed");
	}
	ret->pid = pid;
	ret->osigchld = osigchld;
 out:
	حرر(prompt);
	החזר ret;
}

فراغ
notify_complete(بنية notifier_ctx *ctx, ثابت حرف *fmt, ...)
{
	صحيح ret;
	حرف *msg = عدم;
	va_list args;

	אם (ctx != عدم && fmt != عدم && ctx->pid == -1) {
		/*
		 * notify_start wrote to stderr, so send conclusion message
		 * there too
		*/
		va_start(args, fmt);
		xvasprintf(&msg, fmt, args);
		va_end(args);
		writemsg(msg);
		حرر(msg);
	}

	אם (ctx == عدم || ctx->pid <= 0) {
		حرر(ctx);
		החזר;
	}
	kill(ctx->pid, SIGTERM);
	כלעוד ((ret = waitpid(ctx->pid, عدم, 0)) == -1) {
		אם (errno != EINTR)
			اكسر;
	}
	אם (ret == -1)
		fatal_f("waitpid: %s", strerror(errno));
	ssh_signal(SIGCHLD, ctx->osigchld);
	حرر(ctx);
}
