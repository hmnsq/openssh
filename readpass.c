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

#અન્તર્ભાવ "includes.h"

#અન્તર્ભાવ <sys/types.h>
#અન્તર્ભાવ <sys/wait.h>

#અન્તર્ભાવ <errno.h>
#અન્તર્ભાવ <fcntl.h>
#અન્તર્ભાવ <paths.h>
#અન્તર્ભાવ <signal.h>
#અન્તર્ભાવ <stdarg.h>
#અન્તર્ભાવ <stdio.h>
#અન્તર્ભાવ <stdlib.h>
#અન્તર્ભાવ <string.h>
#અન્તર્ભાવ <unistd.h>

#અન્તર્ભાવ "xmalloc.h"
#અન્તર્ભાવ "misc.h"
#અન્તર્ભાવ "pathnames.h"
#અન્તર્ભાવ "log.h"
#અન્તર્ભાવ "ssh.h"

સ્થિર અક્ષર *
ssh_askpass(અક્ષર *askpass, અચલ અક્ષર *સંદેશ, અચલ અક્ષર *env_hint)
{
	pid_t pid, ret;
	size_t len;
	અક્ષર *pass;
	પૂર્ણાંક p[2], status;
	અક્ષર buf[1024];
	શૂન્ય (*osigchld)(પૂર્ણાંક);

	જો (fflush(stdout) != 0)
		error_f("fflush: %s", strerror(errno));
	જો (askpass == ખાલી)
		fatal("internal error: askpass undefined");
	જો (pipe(p) == -1) {
		error_f("pipe: %s", strerror(errno));
		પાછા ખાલી;
	}
	osigchld = ssh_signal(SIGCHLD, SIG_DFL);
	જો ((pid = fork()) == -1) {
		error_f("fork: %s", strerror(errno));
		ssh_signal(SIGCHLD, osigchld);
		પાછા ખાલી;
	}
	જો (pid == 0) {
		close(p[0]);
		જો (dup2(p[1], STDOUT_FILENO) == -1)
			fatal_f("dup2: %s", strerror(errno));
		જો (env_hint != ખાલી)
			setenv("SSH_ASKPASS_PROMPT", env_hint, 1);
		execlp(askpass, askpass, સંદેશ, (અક્ષર *)ખાલી);
		fatal_f("exec(%s): %s", askpass, strerror(errno));
	}
	close(p[1]);

	len = 0;
	કરો {
		ssize_t r = પઠ(p[0], buf + len, કદ(buf) - 1 - len);

		જો (r == -1 && errno == EINTR)
			ચાલુ;
		જો (r <= 0)
			તોડો;
		len += r;
	} જ્યારે (len < કદ(buf) - 1);
	buf[len] = '\0';

	close(p[0]);
	જ્યારે ((ret = waitpid(pid, &status, 0)) == -1)
		જો (errno != EINTR)
			તોડો;
	ssh_signal(SIGCHLD, osigchld);
	જો (ret == -1 || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		explicit_bzero(buf, કદ(buf));
		પાછા ખાલી;
	}

	buf[strcspn(buf, "\r\n")] = '\0';
	pass = xstrdup(buf);
	explicit_bzero(buf, કદ(buf));
	પાછા pass;
}

/* private/internal read_passphrase flags */
#define RP_ASK_PERMISSION	0x8000 /* pass hint to askpass for confirm UI */

/*
 * Reads a passphrase from /dev/tty with echo turned off/on.  Returns the
 * passphrase (allocated with xmalloc).  Exits if EOF is encountered. If
 * RP_ALLOW_STDIN is set, the passphrase will be read from stdin if no
 * tty is or askpass program is available
 */
અક્ષર *
read_passphrase(અચલ અક્ષર *prompt, પૂર્ણાંક flags)
{
	અક્ષર cr = '\r', *askpass = ખાલી, *ret, buf[1024];
	પૂર્ણાંક rppflags, ttyfd, use_askpass = 0, allow_askpass = 0;
	અચલ અક્ષર *askpass_hint = ખાલી;
	અચલ અક્ષર *s;

	જો (((s = getenv("DISPLAY")) != ખાલી && *s != '\0') ||
	    ((s = getenv("WAYLAND_DISPLAY")) != ખાલી && *s != '\0'))
		allow_askpass = 1;
	જો ((s = getenv(SSH_ASKPASS_REQUIRE_ENV)) != ખાલી) {
		જો (strcasecmp(s, "force") == 0) {
			use_askpass = 1;
			allow_askpass = 1;
		} નહીંતર જો (strcasecmp(s, "prefer") == 0)
			use_askpass = allow_askpass;
		નહીંતર જો (strcasecmp(s, "never") == 0)
			allow_askpass = 0;
	}

	rppflags = (flags & RP_ECHO) ? RPP_ECHO_ON : RPP_ECHO_OFF;
	જો (use_askpass)
		debug_f("requested to askpass");
	નહીંતર જો (flags & RP_USE_ASKPASS)
		use_askpass = 1;
	નહીંતર જો (flags & RP_ALLOW_STDIN) {
		જો (!isatty(STDIN_FILENO)) {
			debug_f("stdin is not a tty");
			use_askpass = 1;
		}
	} નહીંતર {
		rppflags |= RPP_REQUIRE_TTY;
		ttyfd = open(_PATH_TTY, O_RDWR);
		જો (ttyfd >= 0) {
			/*
			 * If we're on a tty, ensure that show the prompt at
			 * the beginning of the line. This will hopefully
			 * clobber any password characters the user has
			 * optimistically typed before echo is disabled.
			 */
			(શૂન્ય)લિખ(ttyfd, &cr, 1);
			close(ttyfd);
		} નહીંતર {
			debug_f("can't open %s: %s", _PATH_TTY,
			    strerror(errno));
			use_askpass = 1;
		}
	}

	જો ((flags & RP_USE_ASKPASS) && !allow_askpass)
		પાછા (flags & RP_ALLOW_EOF) ? ખાલી : xstrdup("");

	જો (use_askpass && allow_askpass) {
		જો (getenv(SSH_ASKPASS_ENV))
			askpass = getenv(SSH_ASKPASS_ENV);
		નહીંતર
			askpass = _PATH_SSH_ASKPASS_DEFAULT;
		જો ((flags & RP_ASK_PERMISSION) != 0)
			askpass_hint = "confirm";
		જો ((ret = ssh_askpass(askpass, prompt, askpass_hint)) == ખાલી)
			જો (!(flags & RP_ALLOW_EOF))
				પાછા xstrdup("");
		પાછા ret;
	}

	જો (readpassphrase(prompt, buf, કદ buf, rppflags) == ખાલી) {
		જો (flags & RP_ALLOW_EOF)
			પાછા ખાલી;
		પાછા xstrdup("");
	}

	ret = xstrdup(buf);
	explicit_bzero(buf, કદ(buf));
	પાછા ret;
}

પૂર્ણાંક
ask_permission(અચલ અક્ષર *fmt, ...)
{
	va_list args;
	અક્ષર *p, prompt[1024];
	પૂર્ણાંક allowed = 0;

	va_start(args, fmt);
	vsnprintf(prompt, કદ(prompt), fmt, args);
	va_end(args);

	p = read_passphrase(prompt,
	    RP_USE_ASKPASS|RP_ALLOW_EOF|RP_ASK_PERMISSION);
	જો (p != ખાલી) {
		/*
		 * Accept empty responses and responses consisting
		 * of the word "yes" as affirmative.
		 */
		જો (*p == '\0' || *p == '\n' ||
		    strcasecmp(p, "yes") == 0)
			allowed = 1;
		મુક્ત(p);
	}

	પાછા (allowed);
}

સ્થિર શૂન્ય
writemsg(અચલ અક્ષર *સંદેશ)
{
	(શૂન્ય)લિખ(STDERR_FILENO, "\r", 1);
	(શૂન્ય)લિખ(STDERR_FILENO, સંદેશ, strlen(સંદેશ));
	(શૂન્ય)લિખ(STDERR_FILENO, "\r\n", 2);
}

સંરચના notifier_ctx {
	pid_t pid;
	શૂન્ય (*osigchld)(પૂર્ણાંક);
};

સંરચના notifier_ctx *
notify_start(પૂર્ણાંક force_askpass, અચલ અક્ષર *fmt, ...)
{
	va_list args;
	અક્ષર *prompt = ખાલી;
	pid_t pid = -1;
	શૂન્ય (*osigchld)(પૂર્ણાંક) = ખાલી;
	અચલ અક્ષર *askpass, *s;
	સંરચના notifier_ctx *ret = ખાલી;

	va_start(args, fmt);
	xvasprintf(&prompt, fmt, args);
	va_end(args);

	જો (fflush(ખાલી) != 0)
		error_f("fflush: %s", strerror(errno));
	જો (!force_askpass && isatty(STDERR_FILENO)) {
		writemsg(prompt);
		જાઓ out_ctx;
	}
	જો ((askpass = getenv("SSH_ASKPASS")) == ખાલી)
		askpass = _PATH_SSH_ASKPASS_DEFAULT;
	જો (*askpass == '\0') {
		debug3_f("cannot notify: no askpass");
		જાઓ out;
	}
	જો (getenv("DISPLAY") == ખાલી && getenv("WAYLAND_DISPLAY") == ખાલી &&
	    ((s = getenv(SSH_ASKPASS_REQUIRE_ENV)) == ખાલી ||
	    strcmp(s, "force") != 0)) {
		debug3_f("cannot notify: no display");
		જાઓ out;
	}
	osigchld = ssh_signal(SIGCHLD, SIG_DFL);
	જો ((pid = fork()) == -1) {
		error_f("fork: %s", strerror(errno));
		ssh_signal(SIGCHLD, osigchld);
		મુક્ત(prompt);
		પાછા ખાલી;
	}
	જો (pid == 0) {
		જો (stdfd_devnull(1, 1, 0) == -1)
			fatal_f("stdfd_devnull failed");
		closefrom(STDERR_FILENO + 1);
		setenv("SSH_ASKPASS_PROMPT", "none", 1); /* hint to UI */
		execlp(askpass, askpass, prompt, (અક્ષર *)ખાલી);
		error_f("exec(%s): %s", askpass, strerror(errno));
		_exit(1);
		/* NOTREACHED */
	}
 out_ctx:
	જો ((ret = calloc(1, કદ(*ret))) == ખાલી) {
		જો (pid != -1)
			kill(pid, SIGTERM);
		fatal_f("calloc failed");
	}
	ret->pid = pid;
	ret->osigchld = osigchld;
 out:
	મુક્ત(prompt);
	પાછા ret;
}

શૂન્ય
notify_complete(સંરચના notifier_ctx *ctx, અચલ અક્ષર *fmt, ...)
{
	પૂર્ણાંક ret;
	અક્ષર *સંદેશ = ખાલી;
	va_list args;

	જો (ctx != ખાલી && fmt != ખાલી && ctx->pid == -1) {
		/*
		 * notify_start wrote to stderr, so send conclusion message
		 * there too
		*/
		va_start(args, fmt);
		xvasprintf(&સંદેશ, fmt, args);
		va_end(args);
		writemsg(સંદેશ);
		મુક્ત(સંદેશ);
	}

	જો (ctx == ખાલી || ctx->pid <= 0) {
		મુક્ત(ctx);
		પાછા;
	}
	kill(ctx->pid, SIGTERM);
	જ્યારે ((ret = waitpid(ctx->pid, ખાલી, 0)) == -1) {
		જો (errno != EINTR)
			તોડો;
	}
	જો (ret == -1)
		fatal_f("waitpid: %s", strerror(errno));
	ssh_signal(SIGCHLD, ctx->osigchld);
	મુક્ત(ctx);
}
