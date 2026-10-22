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

#ಅನ್ತರ್ಭಾವ "includes.h"

#ಅನ್ತರ್ಭಾವ <sys/types.h>
#ಅನ್ತರ್ಭಾವ <sys/wait.h>

#ಅನ್ತರ್ಭಾವ <errno.h>
#ಅನ್ತರ್ಭಾವ <fcntl.h>
#ಅನ್ತರ್ಭಾವ <paths.h>
#ಅನ್ತರ್ಭಾವ <signal.h>
#ಅನ್ತರ್ಭಾವ <stdarg.h>
#ಅನ್ತರ್ಭಾವ <stdio.h>
#ಅನ್ತರ್ಭಾವ <stdlib.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <unistd.h>

#ಅನ್ತರ್ಭಾವ "xmalloc.h"
#ಅನ್ತರ್ಭಾವ "misc.h"
#ಅನ್ತರ್ಭಾವ "pathnames.h"
#ಅನ್ತರ್ಭಾವ "log.h"
#ಅನ್ತರ್ಭಾವ "ssh.h"

ಸ್ಥಿರ ವರ್ಣ *
ssh_askpass(ವರ್ಣ *askpass, ಧ್ರುವ ವರ್ಣ *ಸಂದೇಶ, ಧ್ರುವ ವರ್ಣ *env_hint)
{
	pid_t pid, ret;
	size_t len;
	ವರ್ಣ *pass;
	ಪೂರ್ಣಾಙ್ಕ p[2], status;
	ವರ್ಣ buf[1024];
	ಶೂನ್ಯ (*osigchld)(ಪೂರ್ಣಾಙ್ಕ);

	ಯದಿ (fflush(stdout) != 0)
		error_f("fflush: %s", strerror(errno));
	ಯದಿ (askpass == ರಿಕ್ತ)
		fatal("internal error: askpass undefined");
	ಯದಿ (pipe(p) == -1) {
		error_f("pipe: %s", strerror(errno));
		ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
	}
	osigchld = ssh_signal(SIGCHLD, SIG_DFL);
	ಯದಿ ((pid = fork()) == -1) {
		error_f("fork: %s", strerror(errno));
		ssh_signal(SIGCHLD, osigchld);
		ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
	}
	ಯದಿ (pid == 0) {
		close(p[0]);
		ಯದಿ (dup2(p[1], STDOUT_FILENO) == -1)
			fatal_f("dup2: %s", strerror(errno));
		ಯದಿ (env_hint != ರಿಕ್ತ)
			setenv("SSH_ASKPASS_PROMPT", env_hint, 1);
		execlp(askpass, askpass, ಸಂದೇಶ, (ವರ್ಣ *)ರಿಕ್ತ);
		fatal_f("exec(%s): %s", askpass, strerror(errno));
	}
	close(p[1]);

	len = 0;
	ಕುರು {
		ssize_t r = ಪಠ(p[0], buf + len, ಪರಿಮಾಣ(buf) - 1 - len);

		ಯದಿ (r == -1 && errno == EINTR)
			ಅನುವರ್ತ;
		ಯದಿ (r <= 0)
			ಭಙ್ಗ;
		len += r;
	} ಯಾವತ್ (len < ಪರಿಮಾಣ(buf) - 1);
	buf[len] = '\0';

	close(p[0]);
	ಯಾವತ್ ((ret = waitpid(pid, &status, 0)) == -1)
		ಯದಿ (errno != EINTR)
			ಭಙ್ಗ;
	ssh_signal(SIGCHLD, osigchld);
	ಯದಿ (ret == -1 || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		explicit_bzero(buf, ಪರಿಮಾಣ(buf));
		ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
	}

	buf[strcspn(buf, "\r\n")] = '\0';
	pass = xstrdup(buf);
	explicit_bzero(buf, ಪರಿಮಾಣ(buf));
	ಪ್ರತ್ಯಾಗಮ pass;
}

/* private/internal read_passphrase flags */
#define RP_ASK_PERMISSION	0x8000 /* pass hint to askpass for confirm UI */

/*
 * Reads a passphrase from /dev/tty with echo turned off/on.  Returns the
 * passphrase (allocated with xmalloc).  Exits if EOF is encountered. If
 * RP_ALLOW_STDIN is set, the passphrase will be read from stdin if no
 * tty is or askpass program is available
 */
ವರ್ಣ *
read_passphrase(ಧ್ರುವ ವರ್ಣ *prompt, ಪೂರ್ಣಾಙ್ಕ flags)
{
	ವರ್ಣ cr = '\r', *askpass = ರಿಕ್ತ, *ret, buf[1024];
	ಪೂರ್ಣಾಙ್ಕ rppflags, ttyfd, use_askpass = 0, allow_askpass = 0;
	ಧ್ರುವ ವರ್ಣ *askpass_hint = ರಿಕ್ತ;
	ಧ್ರುವ ವರ್ಣ *s;

	ಯದಿ (((s = getenv("DISPLAY")) != ರಿಕ್ತ && *s != '\0') ||
	    ((s = getenv("WAYLAND_DISPLAY")) != ರಿಕ್ತ && *s != '\0'))
		allow_askpass = 1;
	ಯದಿ ((s = getenv(SSH_ASKPASS_REQUIRE_ENV)) != ರಿಕ್ತ) {
		ಯದಿ (strcasecmp(s, "force") == 0) {
			use_askpass = 1;
			allow_askpass = 1;
		} ಅನ್ಯಥಾ ಯದಿ (strcasecmp(s, "prefer") == 0)
			use_askpass = allow_askpass;
		ಅನ್ಯಥಾ ಯದಿ (strcasecmp(s, "never") == 0)
			allow_askpass = 0;
	}

	rppflags = (flags & RP_ECHO) ? RPP_ECHO_ON : RPP_ECHO_OFF;
	ಯದಿ (use_askpass)
		debug_f("requested to askpass");
	ಅನ್ಯಥಾ ಯದಿ (flags & RP_USE_ASKPASS)
		use_askpass = 1;
	ಅನ್ಯಥಾ ಯದಿ (flags & RP_ALLOW_STDIN) {
		ಯದಿ (!isatty(STDIN_FILENO)) {
			debug_f("stdin is not a tty");
			use_askpass = 1;
		}
	} ಅನ್ಯಥಾ {
		rppflags |= RPP_REQUIRE_TTY;
		ttyfd = open(_PATH_TTY, O_RDWR);
		ಯದಿ (ttyfd >= 0) {
			/*
			 * If we're on a tty, ensure that show the prompt at
			 * the beginning of the line. This will hopefully
			 * clobber any password characters the user has
			 * optimistically typed before echo is disabled.
			 */
			(ಶೂನ್ಯ)ಲಿಖ(ttyfd, &cr, 1);
			close(ttyfd);
		} ಅನ್ಯಥಾ {
			debug_f("can't open %s: %s", _PATH_TTY,
			    strerror(errno));
			use_askpass = 1;
		}
	}

	ಯದಿ ((flags & RP_USE_ASKPASS) && !allow_askpass)
		ಪ್ರತ್ಯಾಗಮ (flags & RP_ALLOW_EOF) ? ರಿಕ್ತ : xstrdup("");

	ಯದಿ (use_askpass && allow_askpass) {
		ಯದಿ (getenv(SSH_ASKPASS_ENV))
			askpass = getenv(SSH_ASKPASS_ENV);
		ಅನ್ಯಥಾ
			askpass = _PATH_SSH_ASKPASS_DEFAULT;
		ಯದಿ ((flags & RP_ASK_PERMISSION) != 0)
			askpass_hint = "confirm";
		ಯದಿ ((ret = ssh_askpass(askpass, prompt, askpass_hint)) == ರಿಕ್ತ)
			ಯದಿ (!(flags & RP_ALLOW_EOF))
				ಪ್ರತ್ಯಾಗಮ xstrdup("");
		ಪ್ರತ್ಯಾಗಮ ret;
	}

	ಯದಿ (readpassphrase(prompt, buf, ಪರಿಮಾಣ buf, rppflags) == ರಿಕ್ತ) {
		ಯದಿ (flags & RP_ALLOW_EOF)
			ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
		ಪ್ರತ್ಯಾಗಮ xstrdup("");
	}

	ret = xstrdup(buf);
	explicit_bzero(buf, ಪರಿಮಾಣ(buf));
	ಪ್ರತ್ಯಾಗಮ ret;
}

ಪೂರ್ಣಾಙ್ಕ
ask_permission(ಧ್ರುವ ವರ್ಣ *fmt, ...)
{
	va_list args;
	ವರ್ಣ *p, prompt[1024];
	ಪೂರ್ಣಾಙ್ಕ allowed = 0;

	va_start(args, fmt);
	vsnprintf(prompt, ಪರಿಮಾಣ(prompt), fmt, args);
	va_end(args);

	p = read_passphrase(prompt,
	    RP_USE_ASKPASS|RP_ALLOW_EOF|RP_ASK_PERMISSION);
	ಯದಿ (p != ರಿಕ್ತ) {
		/*
		 * Accept empty responses and responses consisting
		 * of the word "yes" as affirmative.
		 */
		ಯದಿ (*p == '\0' || *p == '\n' ||
		    strcasecmp(p, "yes") == 0)
			allowed = 1;
		ಮುಕ್ತ(p);
	}

	ಪ್ರತ್ಯಾಗಮ (allowed);
}

ಸ್ಥಿರ ಶೂನ್ಯ
writemsg(ಧ್ರುವ ವರ್ಣ *ಸಂದೇಶ)
{
	(ಶೂನ್ಯ)ಲಿಖ(STDERR_FILENO, "\r", 1);
	(ಶೂನ್ಯ)ಲಿಖ(STDERR_FILENO, ಸಂದೇಶ, strlen(ಸಂದೇಶ));
	(ಶೂನ್ಯ)ಲಿಖ(STDERR_FILENO, "\r\n", 2);
}

ಸಂರಚನಾ notifier_ctx {
	pid_t pid;
	ಶೂನ್ಯ (*osigchld)(ಪೂರ್ಣಾಙ್ಕ);
};

ಸಂರಚನಾ notifier_ctx *
notify_start(ಪೂರ್ಣಾಙ್ಕ force_askpass, ಧ್ರುವ ವರ್ಣ *fmt, ...)
{
	va_list args;
	ವರ್ಣ *prompt = ರಿಕ್ತ;
	pid_t pid = -1;
	ಶೂನ್ಯ (*osigchld)(ಪೂರ್ಣಾಙ್ಕ) = ರಿಕ್ತ;
	ಧ್ರುವ ವರ್ಣ *askpass, *s;
	ಸಂರಚನಾ notifier_ctx *ret = ರಿಕ್ತ;

	va_start(args, fmt);
	xvasprintf(&prompt, fmt, args);
	va_end(args);

	ಯದಿ (fflush(ರಿಕ್ತ) != 0)
		error_f("fflush: %s", strerror(errno));
	ಯದಿ (!force_askpass && isatty(STDERR_FILENO)) {
		writemsg(prompt);
		ಗಚ್ಛ out_ctx;
	}
	ಯದಿ ((askpass = getenv("SSH_ASKPASS")) == ರಿಕ್ತ)
		askpass = _PATH_SSH_ASKPASS_DEFAULT;
	ಯದಿ (*askpass == '\0') {
		debug3_f("cannot notify: no askpass");
		ಗಚ್ಛ out;
	}
	ಯದಿ (getenv("DISPLAY") == ರಿಕ್ತ && getenv("WAYLAND_DISPLAY") == ರಿಕ್ತ &&
	    ((s = getenv(SSH_ASKPASS_REQUIRE_ENV)) == ರಿಕ್ತ ||
	    strcmp(s, "force") != 0)) {
		debug3_f("cannot notify: no display");
		ಗಚ್ಛ out;
	}
	osigchld = ssh_signal(SIGCHLD, SIG_DFL);
	ಯದಿ ((pid = fork()) == -1) {
		error_f("fork: %s", strerror(errno));
		ssh_signal(SIGCHLD, osigchld);
		ಮುಕ್ತ(prompt);
		ಪ್ರತ್ಯಾಗಮ ರಿಕ್ತ;
	}
	ಯದಿ (pid == 0) {
		ಯದಿ (stdfd_devnull(1, 1, 0) == -1)
			fatal_f("stdfd_devnull failed");
		closefrom(STDERR_FILENO + 1);
		setenv("SSH_ASKPASS_PROMPT", "none", 1); /* hint to UI */
		execlp(askpass, askpass, prompt, (ವರ್ಣ *)ರಿಕ್ತ);
		error_f("exec(%s): %s", askpass, strerror(errno));
		_exit(1);
		/* NOTREACHED */
	}
 out_ctx:
	ಯದಿ ((ret = calloc(1, ಪರಿಮಾಣ(*ret))) == ರಿಕ್ತ) {
		ಯದಿ (pid != -1)
			kill(pid, SIGTERM);
		fatal_f("calloc failed");
	}
	ret->pid = pid;
	ret->osigchld = osigchld;
 out:
	ಮುಕ್ತ(prompt);
	ಪ್ರತ್ಯಾಗಮ ret;
}

ಶೂನ್ಯ
notify_complete(ಸಂರಚನಾ notifier_ctx *ctx, ಧ್ರುವ ವರ್ಣ *fmt, ...)
{
	ಪೂರ್ಣಾಙ್ಕ ret;
	ವರ್ಣ *ಸಂದೇಶ = ರಿಕ್ತ;
	va_list args;

	ಯದಿ (ctx != ರಿಕ್ತ && fmt != ರಿಕ್ತ && ctx->pid == -1) {
		/*
		 * notify_start wrote to stderr, so send conclusion message
		 * there too
		*/
		va_start(args, fmt);
		xvasprintf(&ಸಂದೇಶ, fmt, args);
		va_end(args);
		writemsg(ಸಂದೇಶ);
		ಮುಕ್ತ(ಸಂದೇಶ);
	}

	ಯದಿ (ctx == ರಿಕ್ತ || ctx->pid <= 0) {
		ಮುಕ್ತ(ctx);
		ಪ್ರತ್ಯಾಗಮ;
	}
	kill(ctx->pid, SIGTERM);
	ಯಾವತ್ ((ret = waitpid(ctx->pid, ರಿಕ್ತ, 0)) == -1) {
		ಯದಿ (errno != EINTR)
			ಭಙ್ಗ;
	}
	ಯದಿ (ret == -1)
		fatal_f("waitpid: %s", strerror(errno));
	ssh_signal(SIGCHLD, ctx->osigchld);
	ಮುಕ್ತ(ctx);
}
