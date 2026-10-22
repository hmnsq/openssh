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

#ଅନ୍ତର୍ଭାଵ "includes.h"

#ଅନ୍ତର୍ଭାଵ <sys/types.h>
#ଅନ୍ତର୍ଭାଵ <sys/wait.h>

#ଅନ୍ତର୍ଭାଵ <errno.h>
#ଅନ୍ତର୍ଭାଵ <fcntl.h>
#ଅନ୍ତର୍ଭାଵ <paths.h>
#ଅନ୍ତର୍ଭାଵ <signal.h>
#ଅନ୍ତର୍ଭାଵ <stdarg.h>
#ଅନ୍ତର୍ଭାଵ <stdio.h>
#ଅନ୍ତର୍ଭାଵ <stdlib.h>
#ଅନ୍ତର୍ଭାଵ <string.h>
#ଅନ୍ତର୍ଭାଵ <unistd.h>

#ଅନ୍ତର୍ଭାଵ "xmalloc.h"
#ଅନ୍ତର୍ଭାଵ "misc.h"
#ଅନ୍ତର୍ଭାଵ "pathnames.h"
#ଅନ୍ତର୍ଭାଵ "log.h"
#ଅନ୍ତର୍ଭାଵ "ssh.h"

ସ୍ଥିର ଅକ୍ଷର *
ssh_askpass(ଅକ୍ଷର *askpass, ଅଚଳ ଅକ୍ଷର *ସନ୍ଦେଶ, ଅଚଳ ଅକ୍ଷର *env_hint)
{
	pid_t pid, ret;
	size_t len;
	ଅକ୍ଷର *pass;
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା p[2], status;
	ଅକ୍ଷର buf[1024];
	ଶୂନ୍ୟ (*osigchld)(ପୂର୍ଣ୍ଣସଂଖ୍ୟା);

	ଯଦି (fflush(stdout) != 0)
		error_f("fflush: %s", strerror(errno));
	ଯଦି (askpass == ଖାଲି)
		fatal("internal error: askpass undefined");
	ଯଦି (pipe(p) == -1) {
		error_f("pipe: %s", strerror(errno));
		ଫେରନ୍ତୁ ଖାଲି;
	}
	osigchld = ssh_signal(SIGCHLD, SIG_DFL);
	ଯଦି ((pid = fork()) == -1) {
		error_f("fork: %s", strerror(errno));
		ssh_signal(SIGCHLD, osigchld);
		ଫେରନ୍ତୁ ଖାଲି;
	}
	ଯଦି (pid == 0) {
		close(p[0]);
		ଯଦି (dup2(p[1], STDOUT_FILENO) == -1)
			fatal_f("dup2: %s", strerror(errno));
		ଯଦି (env_hint != ଖାଲି)
			setenv("SSH_ASKPASS_PROMPT", env_hint, 1);
		execlp(askpass, askpass, ସନ୍ଦେଶ, (ଅକ୍ଷର *)ଖାଲି);
		fatal_f("exec(%s): %s", askpass, strerror(errno));
	}
	close(p[1]);

	len = 0;
	କର {
		ssize_t r = ପଠ(p[0], buf + len, ଆକାର(buf) - 1 - len);

		ଯଦି (r == -1 && errno == EINTR)
			ଜାରି;
		ଯଦି (r <= 0)
			ଭାଙ୍ଗ;
		len += r;
	} ଯେତେବେଳେ (len < ଆକାର(buf) - 1);
	buf[len] = '\0';

	close(p[0]);
	ଯେତେବେଳେ ((ret = waitpid(pid, &status, 0)) == -1)
		ଯଦି (errno != EINTR)
			ଭାଙ୍ଗ;
	ssh_signal(SIGCHLD, osigchld);
	ଯଦି (ret == -1 || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		explicit_bzero(buf, ଆକାର(buf));
		ଫେରନ୍ତୁ ଖାଲି;
	}

	buf[strcspn(buf, "\r\n")] = '\0';
	pass = xstrdup(buf);
	explicit_bzero(buf, ଆକାର(buf));
	ଫେରନ୍ତୁ pass;
}

/* private/internal read_passphrase flags */
#define RP_ASK_PERMISSION	0x8000 /* pass hint to askpass for confirm UI */

/*
 * Reads a passphrase from /dev/tty with echo turned off/on.  Returns the
 * passphrase (allocated with xmalloc).  Exits if EOF is encountered. If
 * RP_ALLOW_STDIN is set, the passphrase will be read from stdin if no
 * tty is or askpass program is available
 */
ଅକ୍ଷର *
read_passphrase(ଅଚଳ ଅକ୍ଷର *prompt, ପୂର୍ଣ୍ଣସଂଖ୍ୟା flags)
{
	ଅକ୍ଷର cr = '\r', *askpass = ଖାଲି, *ret, buf[1024];
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା rppflags, ttyfd, use_askpass = 0, allow_askpass = 0;
	ଅଚଳ ଅକ୍ଷର *askpass_hint = ଖାଲି;
	ଅଚଳ ଅକ୍ଷର *s;

	ଯଦି (((s = getenv("DISPLAY")) != ଖାଲି && *s != '\0') ||
	    ((s = getenv("WAYLAND_DISPLAY")) != ଖାଲି && *s != '\0'))
		allow_askpass = 1;
	ଯଦି ((s = getenv(SSH_ASKPASS_REQUIRE_ENV)) != ଖାଲି) {
		ଯଦି (strcasecmp(s, "force") == 0) {
			use_askpass = 1;
			allow_askpass = 1;
		} ଅନ୍ୟଥା ଯଦି (strcasecmp(s, "prefer") == 0)
			use_askpass = allow_askpass;
		ଅନ୍ୟଥା ଯଦି (strcasecmp(s, "never") == 0)
			allow_askpass = 0;
	}

	rppflags = (flags & RP_ECHO) ? RPP_ECHO_ON : RPP_ECHO_OFF;
	ଯଦି (use_askpass)
		debug_f("requested to askpass");
	ଅନ୍ୟଥା ଯଦି (flags & RP_USE_ASKPASS)
		use_askpass = 1;
	ଅନ୍ୟଥା ଯଦି (flags & RP_ALLOW_STDIN) {
		ଯଦି (!isatty(STDIN_FILENO)) {
			debug_f("stdin is not a tty");
			use_askpass = 1;
		}
	} ଅନ୍ୟଥା {
		rppflags |= RPP_REQUIRE_TTY;
		ttyfd = open(_PATH_TTY, O_RDWR);
		ଯଦି (ttyfd >= 0) {
			/*
			 * If we're on a tty, ensure that show the prompt at
			 * the beginning of the line. This will hopefully
			 * clobber any password characters the user has
			 * optimistically typed before echo is disabled.
			 */
			(ଶୂନ୍ୟ)ଲିଖ(ttyfd, &cr, 1);
			close(ttyfd);
		} ଅନ୍ୟଥା {
			debug_f("can't open %s: %s", _PATH_TTY,
			    strerror(errno));
			use_askpass = 1;
		}
	}

	ଯଦି ((flags & RP_USE_ASKPASS) && !allow_askpass)
		ଫେରନ୍ତୁ (flags & RP_ALLOW_EOF) ? ଖାଲି : xstrdup("");

	ଯଦି (use_askpass && allow_askpass) {
		ଯଦି (getenv(SSH_ASKPASS_ENV))
			askpass = getenv(SSH_ASKPASS_ENV);
		ଅନ୍ୟଥା
			askpass = _PATH_SSH_ASKPASS_DEFAULT;
		ଯଦି ((flags & RP_ASK_PERMISSION) != 0)
			askpass_hint = "confirm";
		ଯଦି ((ret = ssh_askpass(askpass, prompt, askpass_hint)) == ଖାଲି)
			ଯଦି (!(flags & RP_ALLOW_EOF))
				ଫେରନ୍ତୁ xstrdup("");
		ଫେରନ୍ତୁ ret;
	}

	ଯଦି (readpassphrase(prompt, buf, ଆକାର buf, rppflags) == ଖାଲି) {
		ଯଦି (flags & RP_ALLOW_EOF)
			ଫେରନ୍ତୁ ଖାଲି;
		ଫେରନ୍ତୁ xstrdup("");
	}

	ret = xstrdup(buf);
	explicit_bzero(buf, ଆକାର(buf));
	ଫେରନ୍ତୁ ret;
}

ପୂର୍ଣ୍ଣସଂଖ୍ୟା
ask_permission(ଅଚଳ ଅକ୍ଷର *fmt, ...)
{
	va_list args;
	ଅକ୍ଷର *p, prompt[1024];
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା allowed = 0;

	va_start(args, fmt);
	vsnprintf(prompt, ଆକାର(prompt), fmt, args);
	va_end(args);

	p = read_passphrase(prompt,
	    RP_USE_ASKPASS|RP_ALLOW_EOF|RP_ASK_PERMISSION);
	ଯଦି (p != ଖାଲି) {
		/*
		 * Accept empty responses and responses consisting
		 * of the word "yes" as affirmative.
		 */
		ଯଦି (*p == '\0' || *p == '\n' ||
		    strcasecmp(p, "yes") == 0)
			allowed = 1;
		ମୁକ୍ତ(p);
	}

	ଫେରନ୍ତୁ (allowed);
}

ସ୍ଥିର ଶୂନ୍ୟ
writemsg(ଅଚଳ ଅକ୍ଷର *ସନ୍ଦେଶ)
{
	(ଶୂନ୍ୟ)ଲିଖ(STDERR_FILENO, "\r", 1);
	(ଶୂନ୍ୟ)ଲିଖ(STDERR_FILENO, ସନ୍ଦେଶ, strlen(ସନ୍ଦେଶ));
	(ଶୂନ୍ୟ)ଲିଖ(STDERR_FILENO, "\r\n", 2);
}

ସଂରଚନା notifier_ctx {
	pid_t pid;
	ଶୂନ୍ୟ (*osigchld)(ପୂର୍ଣ୍ଣସଂଖ୍ୟା);
};

ସଂରଚନା notifier_ctx *
notify_start(ପୂର୍ଣ୍ଣସଂଖ୍ୟା force_askpass, ଅଚଳ ଅକ୍ଷର *fmt, ...)
{
	va_list args;
	ଅକ୍ଷର *prompt = ଖାଲି;
	pid_t pid = -1;
	ଶୂନ୍ୟ (*osigchld)(ପୂର୍ଣ୍ଣସଂଖ୍ୟା) = ଖାଲି;
	ଅଚଳ ଅକ୍ଷର *askpass, *s;
	ସଂରଚନା notifier_ctx *ret = ଖାଲି;

	va_start(args, fmt);
	xvasprintf(&prompt, fmt, args);
	va_end(args);

	ଯଦି (fflush(ଖାଲି) != 0)
		error_f("fflush: %s", strerror(errno));
	ଯଦି (!force_askpass && isatty(STDERR_FILENO)) {
		writemsg(prompt);
		ଯାଅ out_ctx;
	}
	ଯଦି ((askpass = getenv("SSH_ASKPASS")) == ଖାଲି)
		askpass = _PATH_SSH_ASKPASS_DEFAULT;
	ଯଦି (*askpass == '\0') {
		debug3_f("cannot notify: no askpass");
		ଯାଅ out;
	}
	ଯଦି (getenv("DISPLAY") == ଖାଲି && getenv("WAYLAND_DISPLAY") == ଖାଲି &&
	    ((s = getenv(SSH_ASKPASS_REQUIRE_ENV)) == ଖାଲି ||
	    strcmp(s, "force") != 0)) {
		debug3_f("cannot notify: no display");
		ଯାଅ out;
	}
	osigchld = ssh_signal(SIGCHLD, SIG_DFL);
	ଯଦି ((pid = fork()) == -1) {
		error_f("fork: %s", strerror(errno));
		ssh_signal(SIGCHLD, osigchld);
		ମୁକ୍ତ(prompt);
		ଫେରନ୍ତୁ ଖାଲି;
	}
	ଯଦି (pid == 0) {
		ଯଦି (stdfd_devnull(1, 1, 0) == -1)
			fatal_f("stdfd_devnull failed");
		closefrom(STDERR_FILENO + 1);
		setenv("SSH_ASKPASS_PROMPT", "none", 1); /* hint to UI */
		execlp(askpass, askpass, prompt, (ଅକ୍ଷର *)ଖାଲି);
		error_f("exec(%s): %s", askpass, strerror(errno));
		_exit(1);
		/* NOTREACHED */
	}
 out_ctx:
	ଯଦି ((ret = calloc(1, ଆକାର(*ret))) == ଖାଲି) {
		ଯଦି (pid != -1)
			kill(pid, SIGTERM);
		fatal_f("calloc failed");
	}
	ret->pid = pid;
	ret->osigchld = osigchld;
 out:
	ମୁକ୍ତ(prompt);
	ଫେରନ୍ତୁ ret;
}

ଶୂନ୍ୟ
notify_complete(ସଂରଚନା notifier_ctx *ctx, ଅଚଳ ଅକ୍ଷର *fmt, ...)
{
	ପୂର୍ଣ୍ଣସଂଖ୍ୟା ret;
	ଅକ୍ଷର *ସନ୍ଦେଶ = ଖାଲି;
	va_list args;

	ଯଦି (ctx != ଖାଲି && fmt != ଖାଲି && ctx->pid == -1) {
		/*
		 * notify_start wrote to stderr, so send conclusion message
		 * there too
		*/
		va_start(args, fmt);
		xvasprintf(&ସନ୍ଦେଶ, fmt, args);
		va_end(args);
		writemsg(ସନ୍ଦେଶ);
		ମୁକ୍ତ(ସନ୍ଦେଶ);
	}

	ଯଦି (ctx == ଖାଲି || ctx->pid <= 0) {
		ମୁକ୍ତ(ctx);
		ଫେରନ୍ତୁ;
	}
	kill(ctx->pid, SIGTERM);
	ଯେତେବେଳେ ((ret = waitpid(ctx->pid, ଖାଲି, 0)) == -1) {
		ଯଦି (errno != EINTR)
			ଭାଙ୍ଗ;
	}
	ଯଦି (ret == -1)
		fatal_f("waitpid: %s", strerror(errno));
	ssh_signal(SIGCHLD, ctx->osigchld);
	ମୁକ୍ତ(ctx);
}
