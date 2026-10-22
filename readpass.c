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

#അന്തര്ഭാവ "includes.h"

#അന്തര്ഭാവ <sys/types.h>
#അന്തര്ഭാവ <sys/wait.h>

#അന്തര്ഭാവ <errno.h>
#അന്തര്ഭാവ <fcntl.h>
#അന്തര്ഭാവ <paths.h>
#അന്തര്ഭാവ <signal.h>
#അന്തര്ഭാവ <stdarg.h>
#അന്തര്ഭാവ <stdio.h>
#അന്തര്ഭാവ <stdlib.h>
#അന്തര്ഭാവ <string.h>
#അന്തര്ഭാവ <unistd.h>

#അന്തര്ഭാവ "xmalloc.h"
#അന്തര്ഭാവ "misc.h"
#അന്തര്ഭാവ "pathnames.h"
#അന്തര്ഭാവ "log.h"
#അന്തര്ഭാവ "ssh.h"

സ്ഥിതം അക്ഷരം *
ssh_askpass(അക്ഷരം *askpass, സ്ഥിരം അക്ഷരം *സന്ദേശം, സ്ഥിരം അക്ഷരം *env_hint)
{
	pid_t pid, ret;
	size_t len;
	അക്ഷരം *pass;
	പൂർണ്ണസംഖ്യ p[2], status;
	അക്ഷരം buf[1024];
	ശൂന്യം (*osigchld)(പൂർണ്ണസംഖ്യ);

	എങ്കിൽ (fflush(stdout) != 0)
		error_f("fflush: %s", strerror(errno));
	എങ്കിൽ (askpass == ശൂന്യ)
		fatal("internal error: askpass undefined");
	എങ്കിൽ (pipe(p) == -1) {
		error_f("pipe: %s", strerror(errno));
		തിരികെ ശൂന്യ;
	}
	osigchld = ssh_signal(SIGCHLD, SIG_DFL);
	എങ്കിൽ ((pid = fork()) == -1) {
		error_f("fork: %s", strerror(errno));
		ssh_signal(SIGCHLD, osigchld);
		തിരികെ ശൂന്യ;
	}
	എങ്കിൽ (pid == 0) {
		close(p[0]);
		എങ്കിൽ (dup2(p[1], STDOUT_FILENO) == -1)
			fatal_f("dup2: %s", strerror(errno));
		എങ്കിൽ (env_hint != ശൂന്യ)
			setenv("SSH_ASKPASS_PROMPT", env_hint, 1);
		execlp(askpass, askpass, സന്ദേശം, (അക്ഷരം *)ശൂന്യ);
		fatal_f("exec(%s): %s", askpass, strerror(errno));
	}
	close(p[1]);

	len = 0;
	ചെയ്യുക {
		ssize_t r = പഠ(p[0], buf + len, വലുപ്പം(buf) - 1 - len);

		എങ്കിൽ (r == -1 && errno == EINTR)
			തുടരുക;
		എങ്കിൽ (r <= 0)
			നിർത്തുക;
		len += r;
	} ആകുമ്പോൾ (len < വലുപ്പം(buf) - 1);
	buf[len] = '\0';

	close(p[0]);
	ആകുമ്പോൾ ((ret = waitpid(pid, &status, 0)) == -1)
		എങ്കിൽ (errno != EINTR)
			നിർത്തുക;
	ssh_signal(SIGCHLD, osigchld);
	എങ്കിൽ (ret == -1 || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		explicit_bzero(buf, വലുപ്പം(buf));
		തിരികെ ശൂന്യ;
	}

	buf[strcspn(buf, "\r\n")] = '\0';
	pass = xstrdup(buf);
	explicit_bzero(buf, വലുപ്പം(buf));
	തിരികെ pass;
}

/* private/internal read_passphrase flags */
#define RP_ASK_PERMISSION	0x8000 /* pass hint to askpass for confirm UI */

/*
 * Reads a passphrase from /dev/tty with echo turned off/on.  Returns the
 * passphrase (allocated with xmalloc).  Exits if EOF is encountered. If
 * RP_ALLOW_STDIN is set, the passphrase will be read from stdin if no
 * tty is or askpass program is available
 */
അക്ഷരം *
read_passphrase(സ്ഥിരം അക്ഷരം *prompt, പൂർണ്ണസംഖ്യ flags)
{
	അക്ഷരം cr = '\r', *askpass = ശൂന്യ, *ret, buf[1024];
	പൂർണ്ണസംഖ്യ rppflags, ttyfd, use_askpass = 0, allow_askpass = 0;
	സ്ഥിരം അക്ഷരം *askpass_hint = ശൂന്യ;
	സ്ഥിരം അക്ഷരം *s;

	എങ്കിൽ (((s = getenv("DISPLAY")) != ശൂന്യ && *s != '\0') ||
	    ((s = getenv("WAYLAND_DISPLAY")) != ശൂന്യ && *s != '\0'))
		allow_askpass = 1;
	എങ്കിൽ ((s = getenv(SSH_ASKPASS_REQUIRE_ENV)) != ശൂന്യ) {
		എങ്കിൽ (strcasecmp(s, "force") == 0) {
			use_askpass = 1;
			allow_askpass = 1;
		} അല്ലെങ്കിൽ എങ്കിൽ (strcasecmp(s, "prefer") == 0)
			use_askpass = allow_askpass;
		അല്ലെങ്കിൽ എങ്കിൽ (strcasecmp(s, "never") == 0)
			allow_askpass = 0;
	}

	rppflags = (flags & RP_ECHO) ? RPP_ECHO_ON : RPP_ECHO_OFF;
	എങ്കിൽ (use_askpass)
		debug_f("requested to askpass");
	അല്ലെങ്കിൽ എങ്കിൽ (flags & RP_USE_ASKPASS)
		use_askpass = 1;
	അല്ലെങ്കിൽ എങ്കിൽ (flags & RP_ALLOW_STDIN) {
		എങ്കിൽ (!isatty(STDIN_FILENO)) {
			debug_f("stdin is not a tty");
			use_askpass = 1;
		}
	} അല്ലെങ്കിൽ {
		rppflags |= RPP_REQUIRE_TTY;
		ttyfd = open(_PATH_TTY, O_RDWR);
		എങ്കിൽ (ttyfd >= 0) {
			/*
			 * If we're on a tty, ensure that show the prompt at
			 * the beginning of the line. This will hopefully
			 * clobber any password characters the user has
			 * optimistically typed before echo is disabled.
			 */
			(ശൂന്യം)ലിഖ(ttyfd, &cr, 1);
			close(ttyfd);
		} അല്ലെങ്കിൽ {
			debug_f("can't open %s: %s", _PATH_TTY,
			    strerror(errno));
			use_askpass = 1;
		}
	}

	എങ്കിൽ ((flags & RP_USE_ASKPASS) && !allow_askpass)
		തിരികെ (flags & RP_ALLOW_EOF) ? ശൂന്യ : xstrdup("");

	എങ്കിൽ (use_askpass && allow_askpass) {
		എങ്കിൽ (getenv(SSH_ASKPASS_ENV))
			askpass = getenv(SSH_ASKPASS_ENV);
		അല്ലെങ്കിൽ
			askpass = _PATH_SSH_ASKPASS_DEFAULT;
		എങ്കിൽ ((flags & RP_ASK_PERMISSION) != 0)
			askpass_hint = "confirm";
		എങ്കിൽ ((ret = ssh_askpass(askpass, prompt, askpass_hint)) == ശൂന്യ)
			എങ്കിൽ (!(flags & RP_ALLOW_EOF))
				തിരികെ xstrdup("");
		തിരികെ ret;
	}

	എങ്കിൽ (readpassphrase(prompt, buf, വലുപ്പം buf, rppflags) == ശൂന്യ) {
		എങ്കിൽ (flags & RP_ALLOW_EOF)
			തിരികെ ശൂന്യ;
		തിരികെ xstrdup("");
	}

	ret = xstrdup(buf);
	explicit_bzero(buf, വലുപ്പം(buf));
	തിരികെ ret;
}

പൂർണ്ണസംഖ്യ
ask_permission(സ്ഥിരം അക്ഷരം *fmt, ...)
{
	va_list args;
	അക്ഷരം *p, prompt[1024];
	പൂർണ്ണസംഖ്യ allowed = 0;

	va_start(args, fmt);
	vsnprintf(prompt, വലുപ്പം(prompt), fmt, args);
	va_end(args);

	p = read_passphrase(prompt,
	    RP_USE_ASKPASS|RP_ALLOW_EOF|RP_ASK_PERMISSION);
	എങ്കിൽ (p != ശൂന്യ) {
		/*
		 * Accept empty responses and responses consisting
		 * of the word "yes" as affirmative.
		 */
		എങ്കിൽ (*p == '\0' || *p == '\n' ||
		    strcasecmp(p, "yes") == 0)
			allowed = 1;
		സ്വതന്ത്രം(p);
	}

	തിരികെ (allowed);
}

സ്ഥിതം ശൂന്യം
writemsg(സ്ഥിരം അക്ഷരം *സന്ദേശം)
{
	(ശൂന്യം)ലിഖ(STDERR_FILENO, "\r", 1);
	(ശൂന്യം)ലിഖ(STDERR_FILENO, സന്ദേശം, strlen(സന്ദേശം));
	(ശൂന്യം)ലിഖ(STDERR_FILENO, "\r\n", 2);
}

ഘടന notifier_ctx {
	pid_t pid;
	ശൂന്യം (*osigchld)(പൂർണ്ണസംഖ്യ);
};

ഘടന notifier_ctx *
notify_start(പൂർണ്ണസംഖ്യ force_askpass, സ്ഥിരം അക്ഷരം *fmt, ...)
{
	va_list args;
	അക്ഷരം *prompt = ശൂന്യ;
	pid_t pid = -1;
	ശൂന്യം (*osigchld)(പൂർണ്ണസംഖ്യ) = ശൂന്യ;
	സ്ഥിരം അക്ഷരം *askpass, *s;
	ഘടന notifier_ctx *ret = ശൂന്യ;

	va_start(args, fmt);
	xvasprintf(&prompt, fmt, args);
	va_end(args);

	എങ്കിൽ (fflush(ശൂന്യ) != 0)
		error_f("fflush: %s", strerror(errno));
	എങ്കിൽ (!force_askpass && isatty(STDERR_FILENO)) {
		writemsg(prompt);
		പോകുക out_ctx;
	}
	എങ്കിൽ ((askpass = getenv("SSH_ASKPASS")) == ശൂന്യ)
		askpass = _PATH_SSH_ASKPASS_DEFAULT;
	എങ്കിൽ (*askpass == '\0') {
		debug3_f("cannot notify: no askpass");
		പോകുക out;
	}
	എങ്കിൽ (getenv("DISPLAY") == ശൂന്യ && getenv("WAYLAND_DISPLAY") == ശൂന്യ &&
	    ((s = getenv(SSH_ASKPASS_REQUIRE_ENV)) == ശൂന്യ ||
	    strcmp(s, "force") != 0)) {
		debug3_f("cannot notify: no display");
		പോകുക out;
	}
	osigchld = ssh_signal(SIGCHLD, SIG_DFL);
	എങ്കിൽ ((pid = fork()) == -1) {
		error_f("fork: %s", strerror(errno));
		ssh_signal(SIGCHLD, osigchld);
		സ്വതന്ത്രം(prompt);
		തിരികെ ശൂന്യ;
	}
	എങ്കിൽ (pid == 0) {
		എങ്കിൽ (stdfd_devnull(1, 1, 0) == -1)
			fatal_f("stdfd_devnull failed");
		closefrom(STDERR_FILENO + 1);
		setenv("SSH_ASKPASS_PROMPT", "none", 1); /* hint to UI */
		execlp(askpass, askpass, prompt, (അക്ഷരം *)ശൂന്യ);
		error_f("exec(%s): %s", askpass, strerror(errno));
		_exit(1);
		/* NOTREACHED */
	}
 out_ctx:
	എങ്കിൽ ((ret = calloc(1, വലുപ്പം(*ret))) == ശൂന്യ) {
		എങ്കിൽ (pid != -1)
			kill(pid, SIGTERM);
		fatal_f("calloc failed");
	}
	ret->pid = pid;
	ret->osigchld = osigchld;
 out:
	സ്വതന്ത്രം(prompt);
	തിരികെ ret;
}

ശൂന്യം
notify_complete(ഘടന notifier_ctx *ctx, സ്ഥിരം അക്ഷരം *fmt, ...)
{
	പൂർണ്ണസംഖ്യ ret;
	അക്ഷരം *സന്ദേശം = ശൂന്യ;
	va_list args;

	എങ്കിൽ (ctx != ശൂന്യ && fmt != ശൂന്യ && ctx->pid == -1) {
		/*
		 * notify_start wrote to stderr, so send conclusion message
		 * there too
		*/
		va_start(args, fmt);
		xvasprintf(&സന്ദേശം, fmt, args);
		va_end(args);
		writemsg(സന്ദേശം);
		സ്വതന്ത്രം(സന്ദേശം);
	}

	എങ്കിൽ (ctx == ശൂന്യ || ctx->pid <= 0) {
		സ്വതന്ത്രം(ctx);
		തിരികെ;
	}
	kill(ctx->pid, SIGTERM);
	ആകുമ്പോൾ ((ret = waitpid(ctx->pid, ശൂന്യ, 0)) == -1) {
		എങ്കിൽ (errno != EINTR)
			നിർത്തുക;
	}
	എങ്കിൽ (ret == -1)
		fatal_f("waitpid: %s", strerror(errno));
	ssh_signal(SIGCHLD, ctx->osigchld);
	സ്വതന്ത്രം(ctx);
}
