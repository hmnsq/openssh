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

#அந்தர்பாவ "includes.h"

#அந்தர்பாவ <sys/types.h>
#அந்தர்பாவ <sys/wait.h>

#அந்தர்பாவ <errno.h>
#அந்தர்பாவ <fcntl.h>
#அந்தர்பாவ <paths.h>
#அந்தர்பாவ <signal.h>
#அந்தர்பாவ <stdarg.h>
#அந்தர்பாவ <stdio.h>
#அந்தர்பாவ <stdlib.h>
#அந்தர்பாவ <string.h>
#அந்தர்பாவ <unistd.h>

#அந்தர்பாவ "xmalloc.h"
#அந்தர்பாவ "misc.h"
#அந்தர்பாவ "pathnames.h"
#அந்தர்பாவ "log.h"
#அந்தர்பாவ "ssh.h"

நிலையான எழுத்து *
ssh_askpass(எழுத்து *askpass, மாறிலி எழுத்து *செய்தி, மாறிலி எழுத்து *env_hint)
{
	pid_t pid, ret;
	size_t len;
	எழுத்து *pass;
	முழு p[2], status;
	எழுத்து buf[1024];
	வெறுமை (*osigchld)(முழு);

	எனில் (fflush(stdout) != 0)
		error_f("fflush: %s", strerror(errno));
	எனில் (askpass == வெற்று)
		fatal("internal error: askpass undefined");
	எனில் (pipe(p) == -1) {
		error_f("pipe: %s", strerror(errno));
		திரும்பு வெற்று;
	}
	osigchld = ssh_signal(SIGCHLD, SIG_DFL);
	எனில் ((pid = fork()) == -1) {
		error_f("fork: %s", strerror(errno));
		ssh_signal(SIGCHLD, osigchld);
		திரும்பு வெற்று;
	}
	எனில் (pid == 0) {
		close(p[0]);
		எனில் (dup2(p[1], STDOUT_FILENO) == -1)
			fatal_f("dup2: %s", strerror(errno));
		எனில் (env_hint != வெற்று)
			setenv("SSH_ASKPASS_PROMPT", env_hint, 1);
		execlp(askpass, askpass, செய்தி, (எழுத்து *)வெற்று);
		fatal_f("exec(%s): %s", askpass, strerror(errno));
	}
	close(p[1]);

	len = 0;
	செய் {
		ssize_t r = பட(p[0], buf + len, அளவு(buf) - 1 - len);

		எனில் (r == -1 && errno == EINTR)
			தொடர்;
		எனில் (r <= 0)
			நிறுத்து;
		len += r;
	} போது (len < அளவு(buf) - 1);
	buf[len] = '\0';

	close(p[0]);
	போது ((ret = waitpid(pid, &status, 0)) == -1)
		எனில் (errno != EINTR)
			நிறுத்து;
	ssh_signal(SIGCHLD, osigchld);
	எனில் (ret == -1 || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		explicit_bzero(buf, அளவு(buf));
		திரும்பு வெற்று;
	}

	buf[strcspn(buf, "\r\n")] = '\0';
	pass = xstrdup(buf);
	explicit_bzero(buf, அளவு(buf));
	திரும்பு pass;
}

/* private/internal read_passphrase flags */
#define RP_ASK_PERMISSION	0x8000 /* pass hint to askpass for confirm UI */

/*
 * Reads a passphrase from /dev/tty with echo turned off/on.  Returns the
 * passphrase (allocated with xmalloc).  Exits if EOF is encountered. If
 * RP_ALLOW_STDIN is set, the passphrase will be read from stdin if no
 * tty is or askpass program is available
 */
எழுத்து *
read_passphrase(மாறிலி எழுத்து *prompt, முழு flags)
{
	எழுத்து cr = '\r', *askpass = வெற்று, *ret, buf[1024];
	முழு rppflags, ttyfd, use_askpass = 0, allow_askpass = 0;
	மாறிலி எழுத்து *askpass_hint = வெற்று;
	மாறிலி எழுத்து *s;

	எனில் (((s = getenv("DISPLAY")) != வெற்று && *s != '\0') ||
	    ((s = getenv("WAYLAND_DISPLAY")) != வெற்று && *s != '\0'))
		allow_askpass = 1;
	எனில் ((s = getenv(SSH_ASKPASS_REQUIRE_ENV)) != வெற்று) {
		எனில் (strcasecmp(s, "force") == 0) {
			use_askpass = 1;
			allow_askpass = 1;
		} இல்லையெனில் எனில் (strcasecmp(s, "prefer") == 0)
			use_askpass = allow_askpass;
		இல்லையெனில் எனில் (strcasecmp(s, "never") == 0)
			allow_askpass = 0;
	}

	rppflags = (flags & RP_ECHO) ? RPP_ECHO_ON : RPP_ECHO_OFF;
	எனில் (use_askpass)
		debug_f("requested to askpass");
	இல்லையெனில் எனில் (flags & RP_USE_ASKPASS)
		use_askpass = 1;
	இல்லையெனில் எனில் (flags & RP_ALLOW_STDIN) {
		எனில் (!isatty(STDIN_FILENO)) {
			debug_f("stdin is not a tty");
			use_askpass = 1;
		}
	} இல்லையெனில் {
		rppflags |= RPP_REQUIRE_TTY;
		ttyfd = open(_PATH_TTY, O_RDWR);
		எனில் (ttyfd >= 0) {
			/*
			 * If we're on a tty, ensure that show the prompt at
			 * the beginning of the line. This will hopefully
			 * clobber any password characters the user has
			 * optimistically typed before echo is disabled.
			 */
			(வெறுமை)லிக(ttyfd, &cr, 1);
			close(ttyfd);
		} இல்லையெனில் {
			debug_f("can't open %s: %s", _PATH_TTY,
			    strerror(errno));
			use_askpass = 1;
		}
	}

	எனில் ((flags & RP_USE_ASKPASS) && !allow_askpass)
		திரும்பு (flags & RP_ALLOW_EOF) ? வெற்று : xstrdup("");

	எனில் (use_askpass && allow_askpass) {
		எனில் (getenv(SSH_ASKPASS_ENV))
			askpass = getenv(SSH_ASKPASS_ENV);
		இல்லையெனில்
			askpass = _PATH_SSH_ASKPASS_DEFAULT;
		எனில் ((flags & RP_ASK_PERMISSION) != 0)
			askpass_hint = "confirm";
		எனில் ((ret = ssh_askpass(askpass, prompt, askpass_hint)) == வெற்று)
			எனில் (!(flags & RP_ALLOW_EOF))
				திரும்பு xstrdup("");
		திரும்பு ret;
	}

	எனில் (readpassphrase(prompt, buf, அளவு buf, rppflags) == வெற்று) {
		எனில் (flags & RP_ALLOW_EOF)
			திரும்பு வெற்று;
		திரும்பு xstrdup("");
	}

	ret = xstrdup(buf);
	explicit_bzero(buf, அளவு(buf));
	திரும்பு ret;
}

முழு
ask_permission(மாறிலி எழுத்து *fmt, ...)
{
	va_list args;
	எழுத்து *p, prompt[1024];
	முழு allowed = 0;

	va_start(args, fmt);
	vsnprintf(prompt, அளவு(prompt), fmt, args);
	va_end(args);

	p = read_passphrase(prompt,
	    RP_USE_ASKPASS|RP_ALLOW_EOF|RP_ASK_PERMISSION);
	எனில் (p != வெற்று) {
		/*
		 * Accept empty responses and responses consisting
		 * of the word "yes" as affirmative.
		 */
		எனில் (*p == '\0' || *p == '\n' ||
		    strcasecmp(p, "yes") == 0)
			allowed = 1;
		விடுவி(p);
	}

	திரும்பு (allowed);
}

நிலையான வெறுமை
writemsg(மாறிலி எழுத்து *செய்தி)
{
	(வெறுமை)லிக(STDERR_FILENO, "\r", 1);
	(வெறுமை)லிக(STDERR_FILENO, செய்தி, strlen(செய்தி));
	(வெறுமை)லிக(STDERR_FILENO, "\r\n", 2);
}

கட்டமைப்பு notifier_ctx {
	pid_t pid;
	வெறுமை (*osigchld)(முழு);
};

கட்டமைப்பு notifier_ctx *
notify_start(முழு force_askpass, மாறிலி எழுத்து *fmt, ...)
{
	va_list args;
	எழுத்து *prompt = வெற்று;
	pid_t pid = -1;
	வெறுமை (*osigchld)(முழு) = வெற்று;
	மாறிலி எழுத்து *askpass, *s;
	கட்டமைப்பு notifier_ctx *ret = வெற்று;

	va_start(args, fmt);
	xvasprintf(&prompt, fmt, args);
	va_end(args);

	எனில் (fflush(வெற்று) != 0)
		error_f("fflush: %s", strerror(errno));
	எனில் (!force_askpass && isatty(STDERR_FILENO)) {
		writemsg(prompt);
		செல் out_ctx;
	}
	எனில் ((askpass = getenv("SSH_ASKPASS")) == வெற்று)
		askpass = _PATH_SSH_ASKPASS_DEFAULT;
	எனில் (*askpass == '\0') {
		debug3_f("cannot notify: no askpass");
		செல் out;
	}
	எனில் (getenv("DISPLAY") == வெற்று && getenv("WAYLAND_DISPLAY") == வெற்று &&
	    ((s = getenv(SSH_ASKPASS_REQUIRE_ENV)) == வெற்று ||
	    strcmp(s, "force") != 0)) {
		debug3_f("cannot notify: no display");
		செல் out;
	}
	osigchld = ssh_signal(SIGCHLD, SIG_DFL);
	எனில் ((pid = fork()) == -1) {
		error_f("fork: %s", strerror(errno));
		ssh_signal(SIGCHLD, osigchld);
		விடுவி(prompt);
		திரும்பு வெற்று;
	}
	எனில் (pid == 0) {
		எனில் (stdfd_devnull(1, 1, 0) == -1)
			fatal_f("stdfd_devnull failed");
		closefrom(STDERR_FILENO + 1);
		setenv("SSH_ASKPASS_PROMPT", "none", 1); /* hint to UI */
		execlp(askpass, askpass, prompt, (எழுத்து *)வெற்று);
		error_f("exec(%s): %s", askpass, strerror(errno));
		_exit(1);
		/* NOTREACHED */
	}
 out_ctx:
	எனில் ((ret = calloc(1, அளவு(*ret))) == வெற்று) {
		எனில் (pid != -1)
			kill(pid, SIGTERM);
		fatal_f("calloc failed");
	}
	ret->pid = pid;
	ret->osigchld = osigchld;
 out:
	விடுவி(prompt);
	திரும்பு ret;
}

வெறுமை
notify_complete(கட்டமைப்பு notifier_ctx *ctx, மாறிலி எழுத்து *fmt, ...)
{
	முழு ret;
	எழுத்து *செய்தி = வெற்று;
	va_list args;

	எனில் (ctx != வெற்று && fmt != வெற்று && ctx->pid == -1) {
		/*
		 * notify_start wrote to stderr, so send conclusion message
		 * there too
		*/
		va_start(args, fmt);
		xvasprintf(&செய்தி, fmt, args);
		va_end(args);
		writemsg(செய்தி);
		விடுவி(செய்தி);
	}

	எனில் (ctx == வெற்று || ctx->pid <= 0) {
		விடுவி(ctx);
		திரும்பு;
	}
	kill(ctx->pid, SIGTERM);
	போது ((ret = waitpid(ctx->pid, வெற்று, 0)) == -1) {
		எனில் (errno != EINTR)
			நிறுத்து;
	}
	எனில் (ret == -1)
		fatal_f("waitpid: %s", strerror(errno));
	ssh_signal(SIGCHLD, ctx->osigchld);
	விடுவி(ctx);
}
