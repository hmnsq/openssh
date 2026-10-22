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

#అన్తర్భావ "includes.h"

#అన్తర్భావ <sys/types.h>
#అన్తర్భావ <sys/wait.h>

#అన్తర్భావ <errno.h>
#అన్తర్భావ <fcntl.h>
#అన్తర్భావ <paths.h>
#అన్తర్భావ <signal.h>
#అన్తర్భావ <stdarg.h>
#అన్తర్భావ <stdio.h>
#అన్తర్భావ <stdlib.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <unistd.h>

#అన్తర్భావ "xmalloc.h"
#అన్తర్భావ "misc.h"
#అన్తర్భావ "pathnames.h"
#అన్తర్భావ "log.h"
#అన్తర్భావ "ssh.h"

స్థిర అక్షరం *
ssh_askpass(అక్షరం *askpass, స్థిరరాశి అక్షరం *సందేశం, స్థిరరాశి అక్షరం *env_hint)
{
	pid_t pid, ret;
	కొలత_t len;
	అక్షరం *pass;
	పూర్ణాంకం p[2], స్థితి_2;
	అక్షరం buf[1024];
	శూన్య (*osigchld)(పూర్ణాంకం);

	ఒకవేళ (fflush(stdout) != 0)
		error_f("fflush: %s", strerror(errno));
	ఒకవేళ (askpass == ఖాళీ)
		fatal("internal error: askpass undefined");
	ఒకవేళ (pipe(p) == -1) {
		error_f("pipe: %s", strerror(errno));
		తిరిగి ఖాళీ;
	}
	osigchld = ssh_signal(SIGCHLD, SIG_DFL);
	ఒకవేళ ((pid = fork()) == -1) {
		error_f("fork: %s", strerror(errno));
		ssh_signal(SIGCHLD, osigchld);
		తిరిగి ఖాళీ;
	}
	ఒకవేళ (pid == 0) {
		close(p[0]);
		ఒకవేళ (dup2(p[1], STDOUT_FILENO) == -1)
			fatal_f("dup2: %s", strerror(errno));
		ఒకవేళ (env_hint != ఖాళీ)
			setenv("SSH_ASKPASS_PROMPT", env_hint, 1);
		execlp(askpass, askpass, సందేశం, (అక్షరం *)ఖాళీ);
		fatal_f("exec(%s): %s", askpass, strerror(errno));
	}
	close(p[1]);

	len = 0;
	చేయి {
		ssize_t r = పఠ(p[0], buf + len, పరిమాణం(buf) - 1 - len);

		ఒకవేళ (r == -1 && errno == EINTR)
			కొనసాగు;
		ఒకవేళ (r <= 0)
			ఆపు;
		len += r;
	} అయితే (len < పరిమాణం(buf) - 1);
	buf[len] = '\0';

	close(p[0]);
	అయితే ((ret = waitpid(pid, &స్థితి_2, 0)) == -1)
		ఒకవేళ (errno != EINTR)
			ఆపు;
	ssh_signal(SIGCHLD, osigchld);
	ఒకవేళ (ret == -1 || !WIFEXITED(స్థితి_2) || WEXITSTATUS(స్థితి_2) != 0) {
		explicit_bzero(buf, పరిమాణం(buf));
		తిరిగి ఖాళీ;
	}

	buf[strcspn(buf, "\r\n")] = '\0';
	pass = xstrdup(buf);
	explicit_bzero(buf, పరిమాణం(buf));
	తిరిగి pass;
}

/* private/internal read_passphrase flags */
#నిర్వచించు RP_ASK_PERMISSION	0x8000 /* pass hint to askpass for confirm UI */

/*
 * Reads a passphrase from /dev/tty with echo turned off/on.  Returns the
 * passphrase (allocated with xmalloc).  Exits if EOF is encountered. If
 * RP_ALLOW_STDIN is set, the passphrase will be read from stdin if no
 * tty is or askpass program is available
 */
అక్షరం *
read_passphrase(స్థిరరాశి అక్షరం *prompt, పూర్ణాంకం flags)
{
	అక్షరం cr = '\r', *askpass = ఖాళీ, *ret, buf[1024];
	పూర్ణాంకం rppflags, ttyfd, use_askpass = 0, allow_askpass = 0;
	స్థిరరాశి అక్షరం *askpass_hint = ఖాళీ;
	స్థిరరాశి అక్షరం *s;

	ఒకవేళ (((s = getenv("DISPLAY")) != ఖాళీ && *s != '\0') ||
	    ((s = getenv("WAYLAND_DISPLAY")) != ఖాళీ && *s != '\0'))
		allow_askpass = 1;
	ఒకవేళ ((s = getenv(SSH_ASKPASS_REQUIRE_ENV)) != ఖాళీ) {
		ఒకవేళ (strcasecmp(s, "force") == 0) {
			use_askpass = 1;
			allow_askpass = 1;
		} లేకపోతే ఒకవేళ (strcasecmp(s, "prefer") == 0)
			use_askpass = allow_askpass;
		లేకపోతే ఒకవేళ (strcasecmp(s, "never") == 0)
			allow_askpass = 0;
	}

	rppflags = (flags & RP_ECHO) ? RPP_ECHO_ON : RPP_ECHO_OFF;
	ఒకవేళ (use_askpass)
		debug_f("requested to askpass");
	లేకపోతే ఒకవేళ (flags & RP_USE_ASKPASS)
		use_askpass = 1;
	లేకపోతే ఒకవేళ (flags & RP_ALLOW_STDIN) {
		ఒకవేళ (!isatty(STDIN_FILENO)) {
			debug_f("stdin is not a tty");
			use_askpass = 1;
		}
	} లేకపోతే {
		rppflags |= RPP_REQUIRE_TTY;
		ttyfd = open(_PATH_TTY, O_RDWR);
		ఒకవేళ (ttyfd >= 0) {
			/*
			 * If we're on a tty, ensure that show the prompt at
			 * the beginning of the line. This will hopefully
			 * clobber any password characters the user has
			 * optimistically typed before echo is disabled.
			 */
			(శూన్య)లిఖ(ttyfd, &cr, 1);
			close(ttyfd);
		} లేకపోతే {
			debug_f("can't open %s: %s", _PATH_TTY,
			    strerror(errno));
			use_askpass = 1;
		}
	}

	ఒకవేళ ((flags & RP_USE_ASKPASS) && !allow_askpass)
		తిరిగి (flags & RP_ALLOW_EOF) ? ఖాళీ : xstrdup("");

	ఒకవేళ (use_askpass && allow_askpass) {
		ఒకవేళ (getenv(SSH_ASKPASS_ENV))
			askpass = getenv(SSH_ASKPASS_ENV);
		లేకపోతే
			askpass = మార్గం_SSH_ASKPASS_DEFAULT;
		ఒకవేళ ((flags & RP_ASK_PERMISSION) != 0)
			askpass_hint = "confirm";
		ఒకవేళ ((ret = ssh_askpass(askpass, prompt, askpass_hint)) == ఖాళీ)
			ఒకవేళ (!(flags & RP_ALLOW_EOF))
				తిరిగి xstrdup("");
		తిరిగి ret;
	}

	ఒకవేళ (readpassphrase(prompt, buf, పరిమాణం buf, rppflags) == ఖాళీ) {
		ఒకవేళ (flags & RP_ALLOW_EOF)
			తిరిగి ఖాళీ;
		తిరిగి xstrdup("");
	}

	ret = xstrdup(buf);
	explicit_bzero(buf, పరిమాణం(buf));
	తిరిగి ret;
}

పూర్ణాంకం
ask_permission(స్థిరరాశి అక్షరం *fmt, ...)
{
	va_list వాదనలు;
	అక్షరం *p, prompt[1024];
	పూర్ణాంకం allowed = 0;

	va_start(వాదనలు, fmt);
	vsnprintf(prompt, పరిమాణం(prompt), fmt, వాదనలు);
	va_end(వాదనలు);

	p = read_passphrase(prompt,
	    RP_USE_ASKPASS|RP_ALLOW_EOF|RP_ASK_PERMISSION);
	ఒకవేళ (p != ఖాళీ) {
		/*
		 * Accept empty responses and responses consisting
		 * of the word "yes" as affirmative.
		 */
		ఒకవేళ (*p == '\0' || *p == '\n' ||
		    strcasecmp(p, "yes") == 0)
			allowed = 1;
		విడుదల(p);
	}

	తిరిగి (allowed);
}

స్థిర శూన్య
writemsg(స్థిరరాశి అక్షరం *సందేశం)
{
	(శూన్య)లిఖ(STDERR_FILENO, "\r", 1);
	(శూన్య)లిఖ(STDERR_FILENO, సందేశం, అక్షరశ్రేణి_పొడవు(సందేశం));
	(శూన్య)లిఖ(STDERR_FILENO, "\r\n", 2);
}

నిర్మాణం notifier_ctx {
	pid_t pid;
	శూన్య (*osigchld)(పూర్ణాంకం);
};

నిర్మాణం notifier_ctx *
notify_ప్రారంభం(పూర్ణాంకం force_askpass, స్థిరరాశి అక్షరం *fmt, ...)
{
	va_list వాదనలు;
	అక్షరం *prompt = ఖాళీ;
	pid_t pid = -1;
	శూన్య (*osigchld)(పూర్ణాంకం) = ఖాళీ;
	స్థిరరాశి అక్షరం *askpass, *s;
	నిర్మాణం notifier_ctx *ret = ఖాళీ;

	va_start(వాదనలు, fmt);
	xvasprintf(&prompt, fmt, వాదనలు);
	va_end(వాదనలు);

	ఒకవేళ (fflush(ఖాళీ) != 0)
		error_f("fflush: %s", strerror(errno));
	ఒకవేళ (!force_askpass && isatty(STDERR_FILENO)) {
		writemsg(prompt);
		వెళ్ళు బహిర్గతం_ctx;
	}
	ఒకవేళ ((askpass = getenv("SSH_ASKPASS")) == ఖాళీ)
		askpass = మార్గం_SSH_ASKPASS_DEFAULT;
	ఒకవేళ (*askpass == '\0') {
		debug3_f("cannot notify: no askpass");
		వెళ్ళు బహిర్గతం;
	}
	ఒకవేళ (getenv("DISPLAY") == ఖాళీ && getenv("WAYLAND_DISPLAY") == ఖాళీ &&
	    ((s = getenv(SSH_ASKPASS_REQUIRE_ENV)) == ఖాళీ ||
	    strcmp(s, "force") != 0)) {
		debug3_f("cannot notify: no display");
		వెళ్ళు బహిర్గతం;
	}
	osigchld = ssh_signal(SIGCHLD, SIG_DFL);
	ఒకవేళ ((pid = fork()) == -1) {
		error_f("fork: %s", strerror(errno));
		ssh_signal(SIGCHLD, osigchld);
		విడుదల(prompt);
		తిరిగి ఖాళీ;
	}
	ఒకవేళ (pid == 0) {
		ఒకవేళ (stdfd_devnull(1, 1, 0) == -1)
			fatal_f("stdfd_devnull failed");
		closefrom(STDERR_FILENO + 1);
		setenv("SSH_ASKPASS_PROMPT", "none", 1); /* hint to UI */
		execlp(askpass, askpass, prompt, (అక్షరం *)ఖాళీ);
		error_f("exec(%s): %s", askpass, strerror(errno));
		_exit(1);
		/* NOTREACHED */
	}
 బహిర్గతం_ctx:
	ఒకవేళ ((ret = సున్నా_జ్ఞాపకం_ఇవ్వు(1, పరిమాణం(*ret))) == ఖాళీ) {
		ఒకవేళ (pid != -1)
			kill(pid, SIGTERM);
		fatal_f("calloc failed");
	}
	ret->pid = pid;
	ret->osigchld = osigchld;
 బహిర్గతం:
	విడుదల(prompt);
	తిరిగి ret;
}

శూన్య
notify_complete(నిర్మాణం notifier_ctx *ctx, స్థిరరాశి అక్షరం *fmt, ...)
{
	పూర్ణాంకం ret;
	అక్షరం *సందేశం = ఖాళీ;
	va_list వాదనలు;

	ఒకవేళ (ctx != ఖాళీ && fmt != ఖాళీ && ctx->pid == -1) {
		/*
		 * notify_start wrote to stderr, so send conclusion message
		 * there too
		*/
		va_start(వాదనలు, fmt);
		xvasprintf(&సందేశం, fmt, వాదనలు);
		va_end(వాదనలు);
		writemsg(సందేశం);
		విడుదల(సందేశం);
	}

	ఒకవేళ (ctx == ఖాళీ || ctx->pid <= 0) {
		విడుదల(ctx);
		తిరిగి;
	}
	kill(ctx->pid, SIGTERM);
	అయితే ((ret = waitpid(ctx->pid, ఖాళీ, 0)) == -1) {
		ఒకవేళ (errno != EINTR)
			ఆపు;
	}
	ఒకవేళ (ret == -1)
		fatal_f("waitpid: %s", strerror(errno));
	ssh_signal(SIGCHLD, ctx->osigchld);
	విడుదల(ctx);
}
