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

#شامل "includes.h"

#شامل <sys/types.h>
#شامل <sys/wait.h>

#شامل <errno.h>
#شامل <fcntl.h>
#شامل <paths.h>
#شامل <signal.h>
#شامل <stdarg.h>
#شامل <stdio.h>
#شامل <stdlib.h>
#شامل <string.h>
#شامل <unistd.h>

#شامل "xmalloc.h"
#شامل "misc.h"
#شامل "pathnames.h"
#شامل "log.h"
#شامل "ssh.h"

ایستا نویسه *
ssh_askpass(نویسه *askpass, ثابت نویسه *پیام, ثابت نویسه *env_hint)
{
	pid_t pid, ret;
	size_t len;
	نویسه *pass;
	صحیح p[2], status;
	نویسه buf[1024];
	تهی (*osigchld)(صحیح);

	اگر (fflush(stdout) != 0)
		error_f("fflush: %s", strerror(errno));
	اگر (askpass == پوچ)
		fatal("internal error: askpass undefined");
	اگر (pipe(p) == -1) {
		error_f("pipe: %s", strerror(errno));
		بازگشت پوچ;
	}
	osigchld = ssh_signal(SIGCHLD, SIG_DFL);
	اگر ((pid = fork()) == -1) {
		error_f("fork: %s", strerror(errno));
		ssh_signal(SIGCHLD, osigchld);
		بازگشت پوچ;
	}
	اگر (pid == 0) {
		close(p[0]);
		اگر (dup2(p[1], STDOUT_FILENO) == -1)
			fatal_f("dup2: %s", strerror(errno));
		اگر (env_hint != پوچ)
			setenv("SSH_ASKPASS_PROMPT", env_hint, 1);
		execlp(askpass, askpass, پیام, (نویسه *)پوچ);
		fatal_f("exec(%s): %s", askpass, strerror(errno));
	}
	close(p[1]);

	len = 0;
	انجامبده {
		ssize_t r = اقرأ(p[0], buf + len, اندازه(buf) - 1 - len);

		اگر (r == -1 && errno == EINTR)
			ادامه;
		اگر (r <= 0)
			بشکن;
		len += r;
	} وقتی (len < اندازه(buf) - 1);
	buf[len] = '\0';

	close(p[0]);
	وقتی ((ret = waitpid(pid, &status, 0)) == -1)
		اگر (errno != EINTR)
			بشکن;
	ssh_signal(SIGCHLD, osigchld);
	اگر (ret == -1 || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		explicit_bzero(buf, اندازه(buf));
		بازگشت پوچ;
	}

	buf[strcspn(buf, "\r\n")] = '\0';
	pass = xstrdup(buf);
	explicit_bzero(buf, اندازه(buf));
	بازگشت pass;
}

/* private/internal read_passphrase flags */
#define RP_ASK_PERMISSION	0x8000 /* pass hint to askpass for confirm UI */

/*
 * Reads a passphrase from /dev/tty with echo turned off/on.  Returns the
 * passphrase (allocated with xmalloc).  Exits if EOF is encountered. If
 * RP_ALLOW_STDIN is set, the passphrase will be read from stdin if no
 * tty is or askpass program is available
 */
نویسه *
read_passphrase(ثابت نویسه *prompt, صحیح flags)
{
	نویسه cr = '\r', *askpass = پوچ, *ret, buf[1024];
	صحیح rppflags, ttyfd, use_askpass = 0, allow_askpass = 0;
	ثابت نویسه *askpass_hint = پوچ;
	ثابت نویسه *s;

	اگر (((s = getenv("DISPLAY")) != پوچ && *s != '\0') ||
	    ((s = getenv("WAYLAND_DISPLAY")) != پوچ && *s != '\0'))
		allow_askpass = 1;
	اگر ((s = getenv(SSH_ASKPASS_REQUIRE_ENV)) != پوچ) {
		اگر (strcasecmp(s, "force") == 0) {
			use_askpass = 1;
			allow_askpass = 1;
		} وگرنه اگر (strcasecmp(s, "prefer") == 0)
			use_askpass = allow_askpass;
		وگرنه اگر (strcasecmp(s, "never") == 0)
			allow_askpass = 0;
	}

	rppflags = (flags & RP_ECHO) ? RPP_ECHO_ON : RPP_ECHO_OFF;
	اگر (use_askpass)
		debug_f("requested to askpass");
	وگرنه اگر (flags & RP_USE_ASKPASS)
		use_askpass = 1;
	وگرنه اگر (flags & RP_ALLOW_STDIN) {
		اگر (!isatty(STDIN_FILENO)) {
			debug_f("stdin is not a tty");
			use_askpass = 1;
		}
	} وگرنه {
		rppflags |= RPP_REQUIRE_TTY;
		ttyfd = open(_PATH_TTY, O_RDWR);
		اگر (ttyfd >= 0) {
			/*
			 * If we're on a tty, ensure that show the prompt at
			 * the beginning of the line. This will hopefully
			 * clobber any password characters the user has
			 * optimistically typed before echo is disabled.
			 */
			(تهی)اكتب(ttyfd, &cr, 1);
			close(ttyfd);
		} وگرنه {
			debug_f("can't open %s: %s", _PATH_TTY,
			    strerror(errno));
			use_askpass = 1;
		}
	}

	اگر ((flags & RP_USE_ASKPASS) && !allow_askpass)
		بازگشت (flags & RP_ALLOW_EOF) ? پوچ : xstrdup("");

	اگر (use_askpass && allow_askpass) {
		اگر (getenv(SSH_ASKPASS_ENV))
			askpass = getenv(SSH_ASKPASS_ENV);
		وگرنه
			askpass = _PATH_SSH_ASKPASS_DEFAULT;
		اگر ((flags & RP_ASK_PERMISSION) != 0)
			askpass_hint = "confirm";
		اگر ((ret = ssh_askpass(askpass, prompt, askpass_hint)) == پوچ)
			اگر (!(flags & RP_ALLOW_EOF))
				بازگشت xstrdup("");
		بازگشت ret;
	}

	اگر (readpassphrase(prompt, buf, اندازه buf, rppflags) == پوچ) {
		اگر (flags & RP_ALLOW_EOF)
			بازگشت پوچ;
		بازگشت xstrdup("");
	}

	ret = xstrdup(buf);
	explicit_bzero(buf, اندازه(buf));
	بازگشت ret;
}

صحیح
ask_permission(ثابت نویسه *fmt, ...)
{
	va_list args;
	نویسه *p, prompt[1024];
	صحیح allowed = 0;

	va_start(args, fmt);
	vsnprintf(prompt, اندازه(prompt), fmt, args);
	va_end(args);

	p = read_passphrase(prompt,
	    RP_USE_ASKPASS|RP_ALLOW_EOF|RP_ASK_PERMISSION);
	اگر (p != پوچ) {
		/*
		 * Accept empty responses and responses consisting
		 * of the word "yes" as affirmative.
		 */
		اگر (*p == '\0' || *p == '\n' ||
		    strcasecmp(p, "yes") == 0)
			allowed = 1;
		آزاد(p);
	}

	بازگشت (allowed);
}

ایستا تهی
writemsg(ثابت نویسه *پیام)
{
	(تهی)اكتب(STDERR_FILENO, "\r", 1);
	(تهی)اكتب(STDERR_FILENO, پیام, strlen(پیام));
	(تهی)اكتب(STDERR_FILENO, "\r\n", 2);
}

ساختار notifier_ctx {
	pid_t pid;
	تهی (*osigchld)(صحیح);
};

ساختار notifier_ctx *
notify_start(صحیح force_askpass, ثابت نویسه *fmt, ...)
{
	va_list args;
	نویسه *prompt = پوچ;
	pid_t pid = -1;
	تهی (*osigchld)(صحیح) = پوچ;
	ثابت نویسه *askpass, *s;
	ساختار notifier_ctx *ret = پوچ;

	va_start(args, fmt);
	xvasprintf(&prompt, fmt, args);
	va_end(args);

	اگر (fflush(پوچ) != 0)
		error_f("fflush: %s", strerror(errno));
	اگر (!force_askpass && isatty(STDERR_FILENO)) {
		writemsg(prompt);
		برو out_ctx;
	}
	اگر ((askpass = getenv("SSH_ASKPASS")) == پوچ)
		askpass = _PATH_SSH_ASKPASS_DEFAULT;
	اگر (*askpass == '\0') {
		debug3_f("cannot notify: no askpass");
		برو out;
	}
	اگر (getenv("DISPLAY") == پوچ && getenv("WAYLAND_DISPLAY") == پوچ &&
	    ((s = getenv(SSH_ASKPASS_REQUIRE_ENV)) == پوچ ||
	    strcmp(s, "force") != 0)) {
		debug3_f("cannot notify: no display");
		برو out;
	}
	osigchld = ssh_signal(SIGCHLD, SIG_DFL);
	اگر ((pid = fork()) == -1) {
		error_f("fork: %s", strerror(errno));
		ssh_signal(SIGCHLD, osigchld);
		آزاد(prompt);
		بازگشت پوچ;
	}
	اگر (pid == 0) {
		اگر (stdfd_devnull(1, 1, 0) == -1)
			fatal_f("stdfd_devnull failed");
		closefrom(STDERR_FILENO + 1);
		setenv("SSH_ASKPASS_PROMPT", "none", 1); /* hint to UI */
		execlp(askpass, askpass, prompt, (نویسه *)پوچ);
		error_f("exec(%s): %s", askpass, strerror(errno));
		_exit(1);
		/* NOTREACHED */
	}
 out_ctx:
	اگر ((ret = calloc(1, اندازه(*ret))) == پوچ) {
		اگر (pid != -1)
			kill(pid, SIGTERM);
		fatal_f("calloc failed");
	}
	ret->pid = pid;
	ret->osigchld = osigchld;
 out:
	آزاد(prompt);
	بازگشت ret;
}

تهی
notify_complete(ساختار notifier_ctx *ctx, ثابت نویسه *fmt, ...)
{
	صحیح ret;
	نویسه *پیام = پوچ;
	va_list args;

	اگر (ctx != پوچ && fmt != پوچ && ctx->pid == -1) {
		/*
		 * notify_start wrote to stderr, so send conclusion message
		 * there too
		*/
		va_start(args, fmt);
		xvasprintf(&پیام, fmt, args);
		va_end(args);
		writemsg(پیام);
		آزاد(پیام);
	}

	اگر (ctx == پوچ || ctx->pid <= 0) {
		آزاد(ctx);
		بازگشت;
	}
	kill(ctx->pid, SIGTERM);
	وقتی ((ret = waitpid(ctx->pid, پوچ, 0)) == -1) {
		اگر (errno != EINTR)
			بشکن;
	}
	اگر (ret == -1)
		fatal_f("waitpid: %s", strerror(errno));
	ssh_signal(SIGCHLD, ctx->osigchld);
	آزاد(ctx);
}
