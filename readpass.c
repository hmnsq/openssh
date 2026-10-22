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

#অন্তর্ভাব "includes.h"

#অন্তর্ভাব <sys/types.h>
#অন্তর্ভাব <sys/wait.h>

#অন্তর্ভাব <errno.h>
#অন্তর্ভাব <fcntl.h>
#অন্তর্ভাব <paths.h>
#অন্তর্ভাব <signal.h>
#অন্তর্ভাব <stdarg.h>
#অন্তর্ভাব <stdio.h>
#অন্তর্ভাব <stdlib.h>
#অন্তর্ভাব <string.h>
#অন্তর্ভাব <unistd.h>

#অন্তর্ভাব "xmalloc.h"
#অন্তর্ভাব "misc.h"
#অন্তর্ভাব "pathnames.h"
#অন্তর্ভাব "log.h"
#অন্তর্ভাব "ssh.h"

স্থির অক্ষর *
ssh_askpass(অক্ষর *askpass, ধ্রুবক অক্ষর *বার্তা, ধ্রুবক অক্ষর *env_hint)
{
	pid_t pid, ret;
	আকার_t len;
	অক্ষর *pass;
	পূর্ণসংখ্যা p[2], status;
	অক্ষর buf[1024];
	শূন্য (*osigchld)(পূর্ণসংখ্যা);

	যদি (fflush(stdout) != 0)
		error_f("fflush: %s", strerror(errno));
	যদি (askpass == ফাঁকা)
		fatal("internal error: askpass undefined");
	যদি (pipe(p) == -1) {
		error_f("pipe: %s", strerror(errno));
		ফেরত ফাঁকা;
	}
	osigchld = ssh_signal(SIGCHLD, SIG_DFL);
	যদি ((pid = fork()) == -1) {
		error_f("fork: %s", strerror(errno));
		ssh_signal(SIGCHLD, osigchld);
		ফেরত ফাঁকা;
	}
	যদি (pid == 0) {
		close(p[0]);
		যদি (dup2(p[1], STDOUT_FILENO) == -1)
			fatal_f("dup2: %s", strerror(errno));
		যদি (env_hint != ফাঁকা)
			setenv("SSH_ASKPASS_PROMPT", env_hint, 1);
		execlp(askpass, askpass, বার্তা, (অক্ষর *)ফাঁকা);
		fatal_f("exec(%s): %s", askpass, strerror(errno));
	}
	close(p[1]);

	len = 0;
	করো {
		ssize_t r = পঠ(p[0], buf + len, আকার(buf) - 1 - len);

		যদি (r == -1 && errno == EINTR)
			চালু;
		যদি (r <= 0)
			বিরতি;
		len += r;
	} যখন (len < আকার(buf) - 1);
	buf[len] = '\0';

	close(p[0]);
	যখন ((ret = waitpid(pid, &status, 0)) == -1)
		যদি (errno != EINTR)
			বিরতি;
	ssh_signal(SIGCHLD, osigchld);
	যদি (ret == -1 || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		explicit_bzero(buf, আকার(buf));
		ফেরত ফাঁকা;
	}

	buf[strcspn(buf, "\r\n")] = '\0';
	pass = xstrdup(buf);
	explicit_bzero(buf, আকার(buf));
	ফেরত pass;
}

/* private/internal read_passphrase flags */
#define RP_ASK_PERMISSION	0x8000 /* pass hint to askpass for confirm UI */

/*
 * Reads a passphrase from /dev/tty with echo turned off/on.  Returns the
 * passphrase (allocated with xmalloc).  Exits if EOF is encountered. If
 * RP_ALLOW_STDIN is set, the passphrase will be read from stdin if no
 * tty is or askpass program is available
 */
অক্ষর *
read_passphrase(ধ্রুবক অক্ষর *prompt, পূর্ণসংখ্যা flags)
{
	অক্ষর cr = '\r', *askpass = ফাঁকা, *ret, buf[1024];
	পূর্ণসংখ্যা rppflags, ttyfd, use_askpass = 0, allow_askpass = 0;
	ধ্রুবক অক্ষর *askpass_hint = ফাঁকা;
	ধ্রুবক অক্ষর *s;

	যদি (((s = getenv("DISPLAY")) != ফাঁকা && *s != '\0') ||
	    ((s = getenv("WAYLAND_DISPLAY")) != ফাঁকা && *s != '\0'))
		allow_askpass = 1;
	যদি ((s = getenv(SSH_ASKPASS_REQUIRE_ENV)) != ফাঁকা) {
		যদি (strcasecmp(s, "force") == 0) {
			use_askpass = 1;
			allow_askpass = 1;
		} অন্যথা যদি (strcasecmp(s, "prefer") == 0)
			use_askpass = allow_askpass;
		অন্যথা যদি (strcasecmp(s, "never") == 0)
			allow_askpass = 0;
	}

	rppflags = (flags & RP_ECHO) ? RPP_ECHO_ON : RPP_ECHO_OFF;
	যদি (use_askpass)
		debug_f("requested to askpass");
	অন্যথা যদি (flags & RP_USE_ASKPASS)
		use_askpass = 1;
	অন্যথা যদি (flags & RP_ALLOW_STDIN) {
		যদি (!isatty(STDIN_FILENO)) {
			debug_f("stdin is not a tty");
			use_askpass = 1;
		}
	} অন্যথা {
		rppflags |= RPP_REQUIRE_TTY;
		ttyfd = open(_PATH_TTY, O_RDWR);
		যদি (ttyfd >= 0) {
			/*
			 * If we're on a tty, ensure that show the prompt at
			 * the beginning of the line. This will hopefully
			 * clobber any password characters the user has
			 * optimistically typed before echo is disabled.
			 */
			(শূন্য)লিখ(ttyfd, &cr, 1);
			close(ttyfd);
		} অন্যথা {
			debug_f("can't open %s: %s", _PATH_TTY,
			    strerror(errno));
			use_askpass = 1;
		}
	}

	যদি ((flags & RP_USE_ASKPASS) && !allow_askpass)
		ফেরত (flags & RP_ALLOW_EOF) ? ফাঁকা : xstrdup("");

	যদি (use_askpass && allow_askpass) {
		যদি (getenv(SSH_ASKPASS_ENV))
			askpass = getenv(SSH_ASKPASS_ENV);
		অন্যথা
			askpass = _PATH_SSH_ASKPASS_DEFAULT;
		যদি ((flags & RP_ASK_PERMISSION) != 0)
			askpass_hint = "confirm";
		যদি ((ret = ssh_askpass(askpass, prompt, askpass_hint)) == ফাঁকা)
			যদি (!(flags & RP_ALLOW_EOF))
				ফেরত xstrdup("");
		ফেরত ret;
	}

	যদি (readpassphrase(prompt, buf, আকার buf, rppflags) == ফাঁকা) {
		যদি (flags & RP_ALLOW_EOF)
			ফেরত ফাঁকা;
		ফেরত xstrdup("");
	}

	ret = xstrdup(buf);
	explicit_bzero(buf, আকার(buf));
	ফেরত ret;
}

পূর্ণসংখ্যা
ask_permission(ধ্রুবক অক্ষর *fmt, ...)
{
	va_list args;
	অক্ষর *p, prompt[1024];
	পূর্ণসংখ্যা allowed = 0;

	va_start(args, fmt);
	vsnprintf(prompt, আকার(prompt), fmt, args);
	va_end(args);

	p = read_passphrase(prompt,
	    RP_USE_ASKPASS|RP_ALLOW_EOF|RP_ASK_PERMISSION);
	যদি (p != ফাঁকা) {
		/*
		 * Accept empty responses and responses consisting
		 * of the word "yes" as affirmative.
		 */
		যদি (*p == '\0' || *p == '\n' ||
		    strcasecmp(p, "yes") == 0)
			allowed = 1;
		মুক্ত(p);
	}

	ফেরত (allowed);
}

স্থির শূন্য
writemsg(ধ্রুবক অক্ষর *বার্তা)
{
	(শূন্য)লিখ(STDERR_FILENO, "\r", 1);
	(শূন্য)লিখ(STDERR_FILENO, বার্তা, strlen(বার্তা));
	(শূন্য)লিখ(STDERR_FILENO, "\r\n", 2);
}

কাঠামো notifier_ctx {
	pid_t pid;
	শূন্য (*osigchld)(পূর্ণসংখ্যা);
};

কাঠামো notifier_ctx *
notify_start(পূর্ণসংখ্যা force_askpass, ধ্রুবক অক্ষর *fmt, ...)
{
	va_list args;
	অক্ষর *prompt = ফাঁকা;
	pid_t pid = -1;
	শূন্য (*osigchld)(পূর্ণসংখ্যা) = ফাঁকা;
	ধ্রুবক অক্ষর *askpass, *s;
	কাঠামো notifier_ctx *ret = ফাঁকা;

	va_start(args, fmt);
	xvasprintf(&prompt, fmt, args);
	va_end(args);

	যদি (fflush(ফাঁকা) != 0)
		error_f("fflush: %s", strerror(errno));
	যদি (!force_askpass && isatty(STDERR_FILENO)) {
		writemsg(prompt);
		যাও out_ctx;
	}
	যদি ((askpass = getenv("SSH_ASKPASS")) == ফাঁকা)
		askpass = _PATH_SSH_ASKPASS_DEFAULT;
	যদি (*askpass == '\0') {
		debug3_f("cannot notify: no askpass");
		যাও out;
	}
	যদি (getenv("DISPLAY") == ফাঁকা && getenv("WAYLAND_DISPLAY") == ফাঁকা &&
	    ((s = getenv(SSH_ASKPASS_REQUIRE_ENV)) == ফাঁকা ||
	    strcmp(s, "force") != 0)) {
		debug3_f("cannot notify: no display");
		যাও out;
	}
	osigchld = ssh_signal(SIGCHLD, SIG_DFL);
	যদি ((pid = fork()) == -1) {
		error_f("fork: %s", strerror(errno));
		ssh_signal(SIGCHLD, osigchld);
		মুক্ত(prompt);
		ফেরত ফাঁকা;
	}
	যদি (pid == 0) {
		যদি (stdfd_devnull(1, 1, 0) == -1)
			fatal_f("stdfd_devnull failed");
		closefrom(STDERR_FILENO + 1);
		setenv("SSH_ASKPASS_PROMPT", "none", 1); /* hint to UI */
		execlp(askpass, askpass, prompt, (অক্ষর *)ফাঁকা);
		error_f("exec(%s): %s", askpass, strerror(errno));
		_exit(1);
		/* NOTREACHED */
	}
 out_ctx:
	যদি ((ret = calloc(1, আকার(*ret))) == ফাঁকা) {
		যদি (pid != -1)
			kill(pid, SIGTERM);
		fatal_f("calloc failed");
	}
	ret->pid = pid;
	ret->osigchld = osigchld;
 out:
	মুক্ত(prompt);
	ফেরত ret;
}

শূন্য
notify_complete(কাঠামো notifier_ctx *ctx, ধ্রুবক অক্ষর *fmt, ...)
{
	পূর্ণসংখ্যা ret;
	অক্ষর *বার্তা = ফাঁকা;
	va_list args;

	যদি (ctx != ফাঁকা && fmt != ফাঁকা && ctx->pid == -1) {
		/*
		 * notify_start wrote to stderr, so send conclusion message
		 * there too
		*/
		va_start(args, fmt);
		xvasprintf(&বার্তা, fmt, args);
		va_end(args);
		writemsg(বার্তা);
		মুক্ত(বার্তা);
	}

	যদি (ctx == ফাঁকা || ctx->pid <= 0) {
		মুক্ত(ctx);
		ফেরত;
	}
	kill(ctx->pid, SIGTERM);
	যখন ((ret = waitpid(ctx->pid, ফাঁকা, 0)) == -1) {
		যদি (errno != EINTR)
			বিরতি;
	}
	যদি (ret == -1)
		fatal_f("waitpid: %s", strerror(errno));
	ssh_signal(SIGCHLD, ctx->osigchld);
	মুক্ত(ctx);
}
