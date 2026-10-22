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

ساکن حرف *
ssh_askpass(حرف *askpass, ثابت حرف *پیغام, ثابت حرف *env_hint)
{
	pid_t pid, ret;
	سائز_t len;
	حرف *pass;
	صحیح p[2], حالت_2;
	حرف buf[1024];
	خالی (*osigchld)(صحیح);

	اگر (fflush(stdout) != 0)
		error_f("fflush: %s", strerror(errno));
	اگر (askpass == تہی)
		fatal("internal error: askpass undefined");
	اگر (pipe(p) == -1) {
		error_f("pipe: %s", strerror(errno));
		واپس تہی;
	}
	osigchld = ssh_signal(SIGCHLD, SIG_DFL);
	اگر ((pid = fork()) == -1) {
		error_f("fork: %s", strerror(errno));
		ssh_signal(SIGCHLD, osigchld);
		واپس تہی;
	}
	اگر (pid == 0) {
		close(p[0]);
		اگر (dup2(p[1], STDOUT_FILENO) == -1)
			fatal_f("dup2: %s", strerror(errno));
		اگر (env_hint != تہی)
			setenv("SSH_ASKPASS_PROMPT", env_hint, 1);
		execlp(askpass, askpass, پیغام, (حرف *)تہی);
		fatal_f("exec(%s): %s", askpass, strerror(errno));
	}
	close(p[1]);

	len = 0;
	کرو {
		ssize_t r = اقرأ(p[0], buf + len, حجم(buf) - 1 - len);

		اگر (r == -1 && errno == EINTR)
			جاری;
		اگر (r <= 0)
			توڑو;
		len += r;
	} جب (len < حجم(buf) - 1);
	buf[len] = '\0';

	close(p[0]);
	جب ((ret = waitpid(pid, &حالت_2, 0)) == -1)
		اگر (errno != EINTR)
			توڑو;
	ssh_signal(SIGCHLD, osigchld);
	اگر (ret == -1 || !WIFEXITED(حالت_2) || WEXITSTATUS(حالت_2) != 0) {
		explicit_bzero(buf, حجم(buf));
		واپس تہی;
	}

	buf[strcspn(buf, "\r\n")] = '\0';
	pass = xstrdup(buf);
	explicit_bzero(buf, حجم(buf));
	واپس pass;
}

/* private/internal read_passphrase flags */
#تعریف_کرو RP_ASK_PERMISSION	0x8000 /* pass hint to askpass for confirm UI */

/*
 * Reads a passphrase from /dev/tty with echo turned off/on.  Returns the
 * passphrase (allocated with xmalloc).  Exits if EOF is encountered. If
 * RP_ALLOW_STDIN is set, the passphrase will be read from stdin if no
 * tty is or askpass program is available
 */
حرف *
read_passphrase(ثابت حرف *prompt, صحیح flags)
{
	حرف cr = '\r', *askpass = تہی, *ret, buf[1024];
	صحیح rppflags, ttyfd, use_askpass = 0, allow_askpass = 0;
	ثابت حرف *askpass_hint = تہی;
	ثابت حرف *s;

	اگر (((s = getenv("DISPLAY")) != تہی && *s != '\0') ||
	    ((s = getenv("WAYLAND_DISPLAY")) != تہی && *s != '\0'))
		allow_askpass = 1;
	اگر ((s = getenv(SSH_ASKPASS_REQUIRE_ENV)) != تہی) {
		اگر (strcasecmp(s, "force") == 0) {
			use_askpass = 1;
			allow_askpass = 1;
		} ورنہ اگر (strcasecmp(s, "prefer") == 0)
			use_askpass = allow_askpass;
		ورنہ اگر (strcasecmp(s, "never") == 0)
			allow_askpass = 0;
	}

	rppflags = (flags & RP_ECHO) ? RPP_ECHO_ON : RPP_ECHO_OFF;
	اگر (use_askpass)
		debug_f("requested to askpass");
	ورنہ اگر (flags & RP_USE_ASKPASS)
		use_askpass = 1;
	ورنہ اگر (flags & RP_ALLOW_STDIN) {
		اگر (!isatty(STDIN_FILENO)) {
			debug_f("stdin is not a tty");
			use_askpass = 1;
		}
	} ورنہ {
		rppflags |= RPP_REQUIRE_TTY;
		ttyfd = open(_PATH_TTY, O_RDWR);
		اگر (ttyfd >= 0) {
			/*
			 * If we're on a tty, ensure that show the prompt at
			 * the beginning of the line. This will hopefully
			 * clobber any password characters the user has
			 * optimistically typed before echo is disabled.
			 */
			(خالی)اكتب(ttyfd, &cr, 1);
			close(ttyfd);
		} ورنہ {
			debug_f("can't open %s: %s", _PATH_TTY,
			    strerror(errno));
			use_askpass = 1;
		}
	}

	اگر ((flags & RP_USE_ASKPASS) && !allow_askpass)
		واپس (flags & RP_ALLOW_EOF) ? تہی : xstrdup("");

	اگر (use_askpass && allow_askpass) {
		اگر (getenv(SSH_ASKPASS_ENV))
			askpass = getenv(SSH_ASKPASS_ENV);
		ورنہ
			askpass = راستہ_SSH_ASKPASS_DEFAULT;
		اگر ((flags & RP_ASK_PERMISSION) != 0)
			askpass_hint = "confirm";
		اگر ((ret = ssh_askpass(askpass, prompt, askpass_hint)) == تہی)
			اگر (!(flags & RP_ALLOW_EOF))
				واپس xstrdup("");
		واپس ret;
	}

	اگر (readpassphrase(prompt, buf, حجم buf, rppflags) == تہی) {
		اگر (flags & RP_ALLOW_EOF)
			واپس تہی;
		واپس xstrdup("");
	}

	ret = xstrdup(buf);
	explicit_bzero(buf, حجم(buf));
	واپس ret;
}

صحیح
ask_permission(ثابت حرف *fmt, ...)
{
	va_list دلائل;
	حرف *p, prompt[1024];
	صحیح allowed = 0;

	va_start(دلائل, fmt);
	vsnprintf(prompt, حجم(prompt), fmt, دلائل);
	va_end(دلائل);

	p = read_passphrase(prompt,
	    RP_USE_ASKPASS|RP_ALLOW_EOF|RP_ASK_PERMISSION);
	اگر (p != تہی) {
		/*
		 * Accept empty responses and responses consisting
		 * of the word "yes" as affirmative.
		 */
		اگر (*p == '\0' || *p == '\n' ||
		    strcasecmp(p, "yes") == 0)
			allowed = 1;
		آزاد(p);
	}

	واپس (allowed);
}

ساکن خالی
writemsg(ثابت حرف *پیغام)
{
	(خالی)اكتب(STDERR_FILENO, "\r", 1);
	(خالی)اكتب(STDERR_FILENO, پیغام, لڑی_لمبائی(پیغام));
	(خالی)اكتب(STDERR_FILENO, "\r\n", 2);
}

ساخت notifier_ctx {
	pid_t pid;
	خالی (*osigchld)(صحیح);
};

ساخت notifier_ctx *
notify_آغاز(صحیح force_askpass, ثابت حرف *fmt, ...)
{
	va_list دلائل;
	حرف *prompt = تہی;
	pid_t pid = -1;
	خالی (*osigchld)(صحیح) = تہی;
	ثابت حرف *askpass, *s;
	ساخت notifier_ctx *ret = تہی;

	va_start(دلائل, fmt);
	xvasprintf(&prompt, fmt, دلائل);
	va_end(دلائل);

	اگر (fflush(تہی) != 0)
		error_f("fflush: %s", strerror(errno));
	اگر (!force_askpass && isatty(STDERR_FILENO)) {
		writemsg(prompt);
		جاؤ برآمد_ctx;
	}
	اگر ((askpass = getenv("SSH_ASKPASS")) == تہی)
		askpass = راستہ_SSH_ASKPASS_DEFAULT;
	اگر (*askpass == '\0') {
		debug3_f("cannot notify: no askpass");
		جاؤ برآمد;
	}
	اگر (getenv("DISPLAY") == تہی && getenv("WAYLAND_DISPLAY") == تہی &&
	    ((s = getenv(SSH_ASKPASS_REQUIRE_ENV)) == تہی ||
	    strcmp(s, "force") != 0)) {
		debug3_f("cannot notify: no display");
		جاؤ برآمد;
	}
	osigchld = ssh_signal(SIGCHLD, SIG_DFL);
	اگر ((pid = fork()) == -1) {
		error_f("fork: %s", strerror(errno));
		ssh_signal(SIGCHLD, osigchld);
		آزاد(prompt);
		واپس تہی;
	}
	اگر (pid == 0) {
		اگر (stdfd_devnull(1, 1, 0) == -1)
			fatal_f("stdfd_devnull failed");
		closefrom(STDERR_FILENO + 1);
		setenv("SSH_ASKPASS_PROMPT", "none", 1); /* hint to UI */
		execlp(askpass, askpass, prompt, (حرف *)تہی);
		error_f("exec(%s): %s", askpass, strerror(errno));
		_exit(1);
		/* NOTREACHED */
	}
 برآمد_ctx:
	اگر ((ret = صفر_حافظہ_دو(1, حجم(*ret))) == تہی) {
		اگر (pid != -1)
			kill(pid, SIGTERM);
		fatal_f("calloc failed");
	}
	ret->pid = pid;
	ret->osigchld = osigchld;
 برآمد:
	آزاد(prompt);
	واپس ret;
}

خالی
notify_complete(ساخت notifier_ctx *ctx, ثابت حرف *fmt, ...)
{
	صحیح ret;
	حرف *پیغام = تہی;
	va_list دلائل;

	اگر (ctx != تہی && fmt != تہی && ctx->pid == -1) {
		/*
		 * notify_start wrote to stderr, so send conclusion message
		 * there too
		*/
		va_start(دلائل, fmt);
		xvasprintf(&پیغام, fmt, دلائل);
		va_end(دلائل);
		writemsg(پیغام);
		آزاد(پیغام);
	}

	اگر (ctx == تہی || ctx->pid <= 0) {
		آزاد(ctx);
		واپس;
	}
	kill(ctx->pid, SIGTERM);
	جب ((ret = waitpid(ctx->pid, تہی, 0)) == -1) {
		اگر (errno != EINTR)
			توڑو;
	}
	اگر (ret == -1)
		fatal_f("waitpid: %s", strerror(errno));
	ssh_signal(SIGCHLD, ctx->osigchld);
	آزاد(ctx);
}
