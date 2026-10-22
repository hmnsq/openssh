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

#অন্তর্ভাৱ "includes.h"

#অন্তর্ভাৱ <sys/types.h>
#অন্তর্ভাৱ <sys/wait.h>

#অন্তর্ভাৱ <errno.h>
#অন্তর্ভাৱ <fcntl.h>
#অন্তর্ভাৱ <paths.h>
#অন্তর্ভাৱ <signal.h>
#অন্তর্ভাৱ <stdarg.h>
#অন্তর্ভাৱ <stdio.h>
#অন্তর্ভাৱ <stdlib.h>
#অন্তর্ভাৱ <string.h>
#অন্তর্ভাৱ <unistd.h>

#অন্তর্ভাৱ "xmalloc.h"
#অন্তর্ভাৱ "misc.h"
#অন্তর্ভাৱ "pathnames.h"
#অন্তর্ভাৱ "log.h"
#অন্তর্ভাৱ "ssh.h"

স্থির ৱর্ণ *
ssh_askpass(ৱর্ণ *askpass, ধ্রুৱ ৱর্ণ *বাৰ্তা, ধ্রুৱ ৱর্ণ *env_hint)
{
	pid_t pid, ret;
	size_t len;
	ৱর্ণ *pass;
	পূর্ণাঙ্ক p[2], status;
	ৱর্ণ buf[1024];
	শূন্য (*osigchld)(পূর্ণাঙ্ক);

	যদি (fflush(stdout) != 0)
		error_f("fflush: %s", strerror(errno));
	যদি (askpass == রিক্ত)
		fatal("internal error: askpass undefined");
	যদি (pipe(p) == -1) {
		error_f("pipe: %s", strerror(errno));
		ঘূৰাই রিক্ত;
	}
	osigchld = ssh_signal(SIGCHLD, SIG_DFL);
	যদি ((pid = fork()) == -1) {
		error_f("fork: %s", strerror(errno));
		ssh_signal(SIGCHLD, osigchld);
		ঘূৰাই রিক্ত;
	}
	যদি (pid == 0) {
		close(p[0]);
		যদি (dup2(p[1], STDOUT_FILENO) == -1)
			fatal_f("dup2: %s", strerror(errno));
		যদি (env_hint != রিক্ত)
			setenv("SSH_ASKPASS_PROMPT", env_hint, 1);
		execlp(askpass, askpass, বাৰ্তা, (ৱর্ণ *)রিক্ত);
		fatal_f("exec(%s): %s", askpass, strerror(errno));
	}
	close(p[1]);

	len = 0;
	কৰা {
		ssize_t r = পঠ(p[0], buf + len, পরিমাণ(buf) - 1 - len);

		যদি (r == -1 && errno == EINTR)
			অনুৱর্ত;
		যদি (r <= 0)
			ভঙ্গ;
		len += r;
	} যেতিয়ালৈ (len < পরিমাণ(buf) - 1);
	buf[len] = '\0';

	close(p[0]);
	যেতিয়ালৈ ((ret = waitpid(pid, &status, 0)) == -1)
		যদি (errno != EINTR)
			ভঙ্গ;
	ssh_signal(SIGCHLD, osigchld);
	যদি (ret == -1 || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		explicit_bzero(buf, পরিমাণ(buf));
		ঘূৰাই রিক্ত;
	}

	buf[strcspn(buf, "\r\n")] = '\0';
	pass = xstrdup(buf);
	explicit_bzero(buf, পরিমাণ(buf));
	ঘূৰাই pass;
}

/* private/internal read_passphrase flags */
#define RP_ASK_PERMISSION	0x8000 /* pass hint to askpass for confirm UI */

/*
 * Reads a passphrase from /dev/tty with echo turned off/on.  Returns the
 * passphrase (allocated with xmalloc).  Exits if EOF is encountered. If
 * RP_ALLOW_STDIN is set, the passphrase will be read from stdin if no
 * tty is or askpass program is available
 */
ৱর্ণ *
read_passphrase(ধ্রুৱ ৱর্ণ *prompt, পূর্ণাঙ্ক flags)
{
	ৱর্ণ cr = '\r', *askpass = রিক্ত, *ret, buf[1024];
	পূর্ণাঙ্ক rppflags, ttyfd, use_askpass = 0, allow_askpass = 0;
	ধ্রুৱ ৱর্ণ *askpass_hint = রিক্ত;
	ধ্রুৱ ৱর্ণ *s;

	যদি (((s = getenv("DISPLAY")) != রিক্ত && *s != '\0') ||
	    ((s = getenv("WAYLAND_DISPLAY")) != রিক্ত && *s != '\0'))
		allow_askpass = 1;
	যদি ((s = getenv(SSH_ASKPASS_REQUIRE_ENV)) != রিক্ত) {
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
		ঘূৰাই (flags & RP_ALLOW_EOF) ? রিক্ত : xstrdup("");

	যদি (use_askpass && allow_askpass) {
		যদি (getenv(SSH_ASKPASS_ENV))
			askpass = getenv(SSH_ASKPASS_ENV);
		অন্যথা
			askpass = _PATH_SSH_ASKPASS_DEFAULT;
		যদি ((flags & RP_ASK_PERMISSION) != 0)
			askpass_hint = "confirm";
		যদি ((ret = ssh_askpass(askpass, prompt, askpass_hint)) == রিক্ত)
			যদি (!(flags & RP_ALLOW_EOF))
				ঘূৰাই xstrdup("");
		ঘূৰাই ret;
	}

	যদি (readpassphrase(prompt, buf, পরিমাণ buf, rppflags) == রিক্ত) {
		যদি (flags & RP_ALLOW_EOF)
			ঘূৰাই রিক্ত;
		ঘূৰাই xstrdup("");
	}

	ret = xstrdup(buf);
	explicit_bzero(buf, পরিমাণ(buf));
	ঘূৰাই ret;
}

পূর্ণাঙ্ক
ask_permission(ধ্রুৱ ৱর্ণ *fmt, ...)
{
	va_list args;
	ৱর্ণ *p, prompt[1024];
	পূর্ণাঙ্ক allowed = 0;

	va_start(args, fmt);
	vsnprintf(prompt, পরিমাণ(prompt), fmt, args);
	va_end(args);

	p = read_passphrase(prompt,
	    RP_USE_ASKPASS|RP_ALLOW_EOF|RP_ASK_PERMISSION);
	যদি (p != রিক্ত) {
		/*
		 * Accept empty responses and responses consisting
		 * of the word "yes" as affirmative.
		 */
		যদি (*p == '\0' || *p == '\n' ||
		    strcasecmp(p, "yes") == 0)
			allowed = 1;
		মুক্ত(p);
	}

	ঘূৰাই (allowed);
}

স্থির শূন্য
writemsg(ধ্রুৱ ৱর্ণ *বাৰ্তা)
{
	(শূন্য)লিখ(STDERR_FILENO, "\r", 1);
	(শূন্য)লিখ(STDERR_FILENO, বাৰ্তা, strlen(বাৰ্তা));
	(শূন্য)লিখ(STDERR_FILENO, "\r\n", 2);
}

সংরচনা notifier_ctx {
	pid_t pid;
	শূন্য (*osigchld)(পূর্ণাঙ্ক);
};

সংরচনা notifier_ctx *
notify_start(পূর্ণাঙ্ক force_askpass, ধ্রুৱ ৱর্ণ *fmt, ...)
{
	va_list args;
	ৱর্ণ *prompt = রিক্ত;
	pid_t pid = -1;
	শূন্য (*osigchld)(পূর্ণাঙ্ক) = রিক্ত;
	ধ্রুৱ ৱর্ণ *askpass, *s;
	সংরচনা notifier_ctx *ret = রিক্ত;

	va_start(args, fmt);
	xvasprintf(&prompt, fmt, args);
	va_end(args);

	যদি (fflush(রিক্ত) != 0)
		error_f("fflush: %s", strerror(errno));
	যদি (!force_askpass && isatty(STDERR_FILENO)) {
		writemsg(prompt);
		গচ্ছ out_ctx;
	}
	যদি ((askpass = getenv("SSH_ASKPASS")) == রিক্ত)
		askpass = _PATH_SSH_ASKPASS_DEFAULT;
	যদি (*askpass == '\0') {
		debug3_f("cannot notify: no askpass");
		গচ্ছ out;
	}
	যদি (getenv("DISPLAY") == রিক্ত && getenv("WAYLAND_DISPLAY") == রিক্ত &&
	    ((s = getenv(SSH_ASKPASS_REQUIRE_ENV)) == রিক্ত ||
	    strcmp(s, "force") != 0)) {
		debug3_f("cannot notify: no display");
		গচ্ছ out;
	}
	osigchld = ssh_signal(SIGCHLD, SIG_DFL);
	যদি ((pid = fork()) == -1) {
		error_f("fork: %s", strerror(errno));
		ssh_signal(SIGCHLD, osigchld);
		মুক্ত(prompt);
		ঘূৰাই রিক্ত;
	}
	যদি (pid == 0) {
		যদি (stdfd_devnull(1, 1, 0) == -1)
			fatal_f("stdfd_devnull failed");
		closefrom(STDERR_FILENO + 1);
		setenv("SSH_ASKPASS_PROMPT", "none", 1); /* hint to UI */
		execlp(askpass, askpass, prompt, (ৱর্ণ *)রিক্ত);
		error_f("exec(%s): %s", askpass, strerror(errno));
		_exit(1);
		/* NOTREACHED */
	}
 out_ctx:
	যদি ((ret = calloc(1, পরিমাণ(*ret))) == রিক্ত) {
		যদি (pid != -1)
			kill(pid, SIGTERM);
		fatal_f("calloc failed");
	}
	ret->pid = pid;
	ret->osigchld = osigchld;
 out:
	মুক্ত(prompt);
	ঘূৰাই ret;
}

শূন্য
notify_complete(সংরচনা notifier_ctx *ctx, ধ্রুৱ ৱর্ণ *fmt, ...)
{
	পূর্ণাঙ্ক ret;
	ৱর্ণ *বাৰ্তা = রিক্ত;
	va_list args;

	যদি (ctx != রিক্ত && fmt != রিক্ত && ctx->pid == -1) {
		/*
		 * notify_start wrote to stderr, so send conclusion message
		 * there too
		*/
		va_start(args, fmt);
		xvasprintf(&বাৰ্তা, fmt, args);
		va_end(args);
		writemsg(বাৰ্তা);
		মুক্ত(বাৰ্তা);
	}

	যদি (ctx == রিক্ত || ctx->pid <= 0) {
		মুক্ত(ctx);
		ঘূৰাই;
	}
	kill(ctx->pid, SIGTERM);
	যেতিয়ালৈ ((ret = waitpid(ctx->pid, রিক্ত, 0)) == -1) {
		যদি (errno != EINTR)
			ভঙ্গ;
	}
	যদি (ret == -1)
		fatal_f("waitpid: %s", strerror(errno));
	ssh_signal(SIGCHLD, ctx->osigchld);
	মুক্ত(ctx);
}
