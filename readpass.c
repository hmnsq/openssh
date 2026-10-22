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

#ਅਨ੍ਤਰ੍ਭਾਵ "includes.h"

#ਅਨ੍ਤਰ੍ਭਾਵ <sys/types.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <sys/wait.h>

#ਅਨ੍ਤਰ੍ਭਾਵ <errno.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <fcntl.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <paths.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <signal.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdarg.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdio.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <stdlib.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <string.h>
#ਅਨ੍ਤਰ੍ਭਾਵ <unistd.h>

#ਅਨ੍ਤਰ੍ਭਾਵ "xmalloc.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "misc.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "pathnames.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "log.h"
#ਅਨ੍ਤਰ੍ਭਾਵ "ssh.h"

ਸਥਿਰ ਅੱਖਰ *
ssh_askpass(ਅੱਖਰ *askpass, ਅਚਲ ਅੱਖਰ *ਸੁਨੇਹਾ, ਅਚਲ ਅੱਖਰ *env_hint)
{
	pid_t pid, ret;
	ਮਾਪ_t len;
	ਅੱਖਰ *pass;
	ਪੂਰਨ p[2], ਸਥਿਤੀ;
	ਅੱਖਰ buf[1024];
	ਖਾਲੀ (*osigchld)(ਪੂਰਨ);

	ਜੇ (fflush(stdout) != 0)
		error_f("fflush: %s", strerror(errno));
	ਜੇ (askpass == ਨਿਰਾ)
		fatal("internal error: askpass undefined");
	ਜੇ (pipe(p) == -1) {
		error_f("pipe: %s", strerror(errno));
		ਵਾਪਸ ਨਿਰਾ;
	}
	osigchld = ssh_signal(SIGCHLD, SIG_DFL);
	ਜੇ ((pid = fork()) == -1) {
		error_f("fork: %s", strerror(errno));
		ssh_signal(SIGCHLD, osigchld);
		ਵਾਪਸ ਨਿਰਾ;
	}
	ਜੇ (pid == 0) {
		close(p[0]);
		ਜੇ (dup2(p[1], STDOUT_FILENO) == -1)
			fatal_f("dup2: %s", strerror(errno));
		ਜੇ (env_hint != ਨਿਰਾ)
			setenv("SSH_ASKPASS_PROMPT", env_hint, 1);
		execlp(askpass, askpass, ਸੁਨੇਹਾ, (ਅੱਖਰ *)ਨਿਰਾ);
		fatal_f("exec(%s): %s", askpass, strerror(errno));
	}
	close(p[1]);

	len = 0;
	ਕਰੋ {
		ssize_t r = ਪਠ(p[0], buf + len, ਆਕਾਰ(buf) - 1 - len);

		ਜੇ (r == -1 && errno == EINTR)
			ਜਾਰੀ;
		ਜੇ (r <= 0)
			ਰੋਕੋ;
		len += r;
	} ਜਦੋਂ (len < ਆਕਾਰ(buf) - 1);
	buf[len] = '\0';

	close(p[0]);
	ਜਦੋਂ ((ret = waitpid(pid, &ਸਥਿਤੀ, 0)) == -1)
		ਜੇ (errno != EINTR)
			ਰੋਕੋ;
	ssh_signal(SIGCHLD, osigchld);
	ਜੇ (ret == -1 || !WIFEXITED(ਸਥਿਤੀ) || WEXITSTATUS(ਸਥਿਤੀ) != 0) {
		explicit_bzero(buf, ਆਕਾਰ(buf));
		ਵਾਪਸ ਨਿਰਾ;
	}

	buf[strcspn(buf, "\r\n")] = '\0';
	pass = xstrdup(buf);
	explicit_bzero(buf, ਆਕਾਰ(buf));
	ਵਾਪਸ pass;
}

/* private/internal read_passphrase flags */
#ਪਰਿਭਾਸ਼ਿਤ_ਕਰੋ RP_ASK_PERMISSION	0x8000 /* pass hint to askpass for confirm UI */

/*
 * Reads a passphrase from /dev/tty with echo turned off/on.  Returns the
 * passphrase (allocated with xmalloc).  Exits if EOF is encountered. If
 * RP_ALLOW_STDIN is set, the passphrase will be read from stdin if no
 * tty is or askpass program is available
 */
ਅੱਖਰ *
read_passphrase(ਅਚਲ ਅੱਖਰ *prompt, ਪੂਰਨ flags)
{
	ਅੱਖਰ cr = '\r', *askpass = ਨਿਰਾ, *ret, buf[1024];
	ਪੂਰਨ rppflags, ttyfd, use_askpass = 0, allow_askpass = 0;
	ਅਚਲ ਅੱਖਰ *askpass_hint = ਨਿਰਾ;
	ਅਚਲ ਅੱਖਰ *s;

	ਜੇ (((s = getenv("DISPLAY")) != ਨਿਰਾ && *s != '\0') ||
	    ((s = getenv("WAYLAND_DISPLAY")) != ਨਿਰਾ && *s != '\0'))
		allow_askpass = 1;
	ਜੇ ((s = getenv(SSH_ASKPASS_REQUIRE_ENV)) != ਨਿਰਾ) {
		ਜੇ (strcasecmp(s, "force") == 0) {
			use_askpass = 1;
			allow_askpass = 1;
		} ਨਹੀਂਤਾਂ ਜੇ (strcasecmp(s, "prefer") == 0)
			use_askpass = allow_askpass;
		ਨਹੀਂਤਾਂ ਜੇ (strcasecmp(s, "never") == 0)
			allow_askpass = 0;
	}

	rppflags = (flags & RP_ECHO) ? RPP_ECHO_ON : RPP_ECHO_OFF;
	ਜੇ (use_askpass)
		debug_f("requested to askpass");
	ਨਹੀਂਤਾਂ ਜੇ (flags & RP_USE_ASKPASS)
		use_askpass = 1;
	ਨਹੀਂਤਾਂ ਜੇ (flags & RP_ALLOW_STDIN) {
		ਜੇ (!isatty(STDIN_FILENO)) {
			debug_f("stdin is not a tty");
			use_askpass = 1;
		}
	} ਨਹੀਂਤਾਂ {
		rppflags |= RPP_REQUIRE_TTY;
		ttyfd = open(_PATH_TTY, O_RDWR);
		ਜੇ (ttyfd >= 0) {
			/*
			 * If we're on a tty, ensure that show the prompt at
			 * the beginning of the line. This will hopefully
			 * clobber any password characters the user has
			 * optimistically typed before echo is disabled.
			 */
			(ਖਾਲੀ)ਲਿਖ(ttyfd, &cr, 1);
			close(ttyfd);
		} ਨਹੀਂਤਾਂ {
			debug_f("can't open %s: %s", _PATH_TTY,
			    strerror(errno));
			use_askpass = 1;
		}
	}

	ਜੇ ((flags & RP_USE_ASKPASS) && !allow_askpass)
		ਵਾਪਸ (flags & RP_ALLOW_EOF) ? ਨਿਰਾ : xstrdup("");

	ਜੇ (use_askpass && allow_askpass) {
		ਜੇ (getenv(SSH_ASKPASS_ENV))
			askpass = getenv(SSH_ASKPASS_ENV);
		ਨਹੀਂਤਾਂ
			askpass = ਰਸਤਾ_SSH_ASKPASS_DEFAULT;
		ਜੇ ((flags & RP_ASK_PERMISSION) != 0)
			askpass_hint = "confirm";
		ਜੇ ((ret = ssh_askpass(askpass, prompt, askpass_hint)) == ਨਿਰਾ)
			ਜੇ (!(flags & RP_ALLOW_EOF))
				ਵਾਪਸ xstrdup("");
		ਵਾਪਸ ret;
	}

	ਜੇ (readpassphrase(prompt, buf, ਆਕਾਰ buf, rppflags) == ਨਿਰਾ) {
		ਜੇ (flags & RP_ALLOW_EOF)
			ਵਾਪਸ ਨਿਰਾ;
		ਵਾਪਸ xstrdup("");
	}

	ret = xstrdup(buf);
	explicit_bzero(buf, ਆਕਾਰ(buf));
	ਵਾਪਸ ret;
}

ਪੂਰਨ
ask_permission(ਅਚਲ ਅੱਖਰ *fmt, ...)
{
	va_list ਦਲੀਲਾਂ;
	ਅੱਖਰ *p, prompt[1024];
	ਪੂਰਨ allowed = 0;

	va_start(ਦਲੀਲਾਂ, fmt);
	vsnprintf(prompt, ਆਕਾਰ(prompt), fmt, ਦਲੀਲਾਂ);
	va_end(ਦਲੀਲਾਂ);

	p = read_passphrase(prompt,
	    RP_USE_ASKPASS|RP_ALLOW_EOF|RP_ASK_PERMISSION);
	ਜੇ (p != ਨਿਰਾ) {
		/*
		 * Accept empty responses and responses consisting
		 * of the word "yes" as affirmative.
		 */
		ਜੇ (*p == '\0' || *p == '\n' ||
		    strcasecmp(p, "yes") == 0)
			allowed = 1;
		ਮੁਕਤ(p);
	}

	ਵਾਪਸ (allowed);
}

ਸਥਿਰ ਖਾਲੀ
writemsg(ਅਚਲ ਅੱਖਰ *ਸੁਨੇਹਾ)
{
	(ਖਾਲੀ)ਲਿਖ(STDERR_FILENO, "\r", 1);
	(ਖਾਲੀ)ਲਿਖ(STDERR_FILENO, ਸੁਨੇਹਾ, ਲੜੀ_ਲੰਬਾਈ(ਸੁਨੇਹਾ));
	(ਖਾਲੀ)ਲਿਖ(STDERR_FILENO, "\r\n", 2);
}

ਬਣਤਰ notifier_ctx {
	pid_t pid;
	ਖਾਲੀ (*osigchld)(ਪੂਰਨ);
};

ਬਣਤਰ notifier_ctx *
notify_ਸ਼ੁਰੂ(ਪੂਰਨ force_askpass, ਅਚਲ ਅੱਖਰ *fmt, ...)
{
	va_list ਦਲੀਲਾਂ;
	ਅੱਖਰ *prompt = ਨਿਰਾ;
	pid_t pid = -1;
	ਖਾਲੀ (*osigchld)(ਪੂਰਨ) = ਨਿਰਾ;
	ਅਚਲ ਅੱਖਰ *askpass, *s;
	ਬਣਤਰ notifier_ctx *ret = ਨਿਰਾ;

	va_start(ਦਲੀਲਾਂ, fmt);
	xvasprintf(&prompt, fmt, ਦਲੀਲਾਂ);
	va_end(ਦਲੀਲਾਂ);

	ਜੇ (fflush(ਨਿਰਾ) != 0)
		error_f("fflush: %s", strerror(errno));
	ਜੇ (!force_askpass && isatty(STDERR_FILENO)) {
		writemsg(prompt);
		ਜਾਓ ਬਾਹਰਲਾ_ctx;
	}
	ਜੇ ((askpass = getenv("SSH_ASKPASS")) == ਨਿਰਾ)
		askpass = ਰਸਤਾ_SSH_ASKPASS_DEFAULT;
	ਜੇ (*askpass == '\0') {
		debug3_f("cannot notify: no askpass");
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	ਜੇ (getenv("DISPLAY") == ਨਿਰਾ && getenv("WAYLAND_DISPLAY") == ਨਿਰਾ &&
	    ((s = getenv(SSH_ASKPASS_REQUIRE_ENV)) == ਨਿਰਾ ||
	    strcmp(s, "force") != 0)) {
		debug3_f("cannot notify: no display");
		ਜਾਓ ਬਾਹਰਲਾ;
	}
	osigchld = ssh_signal(SIGCHLD, SIG_DFL);
	ਜੇ ((pid = fork()) == -1) {
		error_f("fork: %s", strerror(errno));
		ssh_signal(SIGCHLD, osigchld);
		ਮੁਕਤ(prompt);
		ਵਾਪਸ ਨਿਰਾ;
	}
	ਜੇ (pid == 0) {
		ਜੇ (stdfd_devnull(1, 1, 0) == -1)
			fatal_f("stdfd_devnull failed");
		closefrom(STDERR_FILENO + 1);
		setenv("SSH_ASKPASS_PROMPT", "none", 1); /* hint to UI */
		execlp(askpass, askpass, prompt, (ਅੱਖਰ *)ਨਿਰਾ);
		error_f("exec(%s): %s", askpass, strerror(errno));
		_exit(1);
		/* NOTREACHED */
	}
 ਬਾਹਰਲਾ_ctx:
	ਜੇ ((ret = ਸਿਫਰ_ਸਮ੍ਰਿਤੀ_ਦਿਓ(1, ਆਕਾਰ(*ret))) == ਨਿਰਾ) {
		ਜੇ (pid != -1)
			kill(pid, SIGTERM);
		fatal_f("calloc failed");
	}
	ret->pid = pid;
	ret->osigchld = osigchld;
 ਬਾਹਰਲਾ:
	ਮੁਕਤ(prompt);
	ਵਾਪਸ ret;
}

ਖਾਲੀ
notify_complete(ਬਣਤਰ notifier_ctx *ctx, ਅਚਲ ਅੱਖਰ *fmt, ...)
{
	ਪੂਰਨ ret;
	ਅੱਖਰ *ਸੁਨੇਹਾ = ਨਿਰਾ;
	va_list ਦਲੀਲਾਂ;

	ਜੇ (ctx != ਨਿਰਾ && fmt != ਨਿਰਾ && ctx->pid == -1) {
		/*
		 * notify_start wrote to stderr, so send conclusion message
		 * there too
		*/
		va_start(ਦਲੀਲਾਂ, fmt);
		xvasprintf(&ਸੁਨੇਹਾ, fmt, ਦਲੀਲਾਂ);
		va_end(ਦਲੀਲਾਂ);
		writemsg(ਸੁਨੇਹਾ);
		ਮੁਕਤ(ਸੁਨੇਹਾ);
	}

	ਜੇ (ctx == ਨਿਰਾ || ctx->pid <= 0) {
		ਮੁਕਤ(ctx);
		ਵਾਪਸ;
	}
	kill(ctx->pid, SIGTERM);
	ਜਦੋਂ ((ret = waitpid(ctx->pid, ਨਿਰਾ, 0)) == -1) {
		ਜੇ (errno != EINTR)
			ਰੋਕੋ;
	}
	ਜੇ (ret == -1)
		fatal_f("waitpid: %s", strerror(errno));
	ssh_signal(SIGCHLD, ctx->osigchld);
	ਮੁਕਤ(ctx);
}
