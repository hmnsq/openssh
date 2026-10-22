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

ಸ್ಥಿರ ಅಕ್ಷರ *
ssh_askpass(ಅಕ್ಷರ *askpass, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಸಂದೇಶ, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *env_hint)
{
	pid_t pid, ret;
	ಗಾತ್ರ_t len;
	ಅಕ್ಷರ *pass;
	ಪೂರ್ಣಾಂಕ p[2], ಸ್ಥಿತಿ_2;
	ಅಕ್ಷರ buf[1024];
	ಶೂನ್ಯ (*osigchld)(ಪೂರ್ಣಾಂಕ);

	ಆದರೆ (fflush(stdout) != 0)
		error_f("fflush: %s", strerror(errno));
	ಆದರೆ (askpass == ಖಾಲಿ)
		fatal("internal error: askpass undefined");
	ಆದರೆ (pipe(p) == -1) {
		error_f("pipe: %s", strerror(errno));
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;
	}
	osigchld = ssh_signal(SIGCHLD, SIG_DFL);
	ಆದರೆ ((pid = fork()) == -1) {
		error_f("fork: %s", strerror(errno));
		ssh_signal(SIGCHLD, osigchld);
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;
	}
	ಆದರೆ (pid == 0) {
		close(p[0]);
		ಆದರೆ (dup2(p[1], STDOUT_FILENO) == -1)
			fatal_f("dup2: %s", strerror(errno));
		ಆದರೆ (env_hint != ಖಾಲಿ)
			setenv("SSH_ASKPASS_PROMPT", env_hint, 1);
		execlp(askpass, askpass, ಸಂದೇಶ, (ಅಕ್ಷರ *)ಖಾಲಿ);
		fatal_f("exec(%s): %s", askpass, strerror(errno));
	}
	close(p[1]);

	len = 0;
	ಮಾಡು {
		ssize_t r = ಪಠ(p[0], buf + len, ಗಾತ್ರ(buf) - 1 - len);

		ಆದರೆ (r == -1 && errno == EINTR)
			ಮುಂದುವರಿ;
		ಆದರೆ (r <= 0)
			ನಿಲ್ಲಿಸು;
		len += r;
	} ಆಗ (len < ಗಾತ್ರ(buf) - 1);
	buf[len] = '\0';

	close(p[0]);
	ಆಗ ((ret = waitpid(pid, &ಸ್ಥಿತಿ_2, 0)) == -1)
		ಆದರೆ (errno != EINTR)
			ನಿಲ್ಲಿಸು;
	ssh_signal(SIGCHLD, osigchld);
	ಆದರೆ (ret == -1 || !WIFEXITED(ಸ್ಥಿತಿ_2) || WEXITSTATUS(ಸ್ಥಿತಿ_2) != 0) {
		explicit_bzero(buf, ಗಾತ್ರ(buf));
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;
	}

	buf[strcspn(buf, "\r\n")] = '\0';
	pass = xstrdup(buf);
	explicit_bzero(buf, ಗಾತ್ರ(buf));
	ಹಿಂತಿರುಗಿ pass;
}

/* private/internal read_passphrase flags */
#ವ್ಯಾಖ್ಯಾನಿಸು RP_ASK_PERMISSION	0x8000 /* pass hint to askpass for confirm UI */

/*
 * Reads a passphrase from /dev/tty with echo turned off/on.  Returns the
 * passphrase (allocated with xmalloc).  Exits if EOF is encountered. If
 * RP_ALLOW_STDIN is set, the passphrase will be read from stdin if no
 * tty is or askpass program is available
 */
ಅಕ್ಷರ *
read_passphrase(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *prompt, ಪೂರ್ಣಾಂಕ flags)
{
	ಅಕ್ಷರ cr = '\r', *askpass = ಖಾಲಿ, *ret, buf[1024];
	ಪೂರ್ಣಾಂಕ rppflags, ttyfd, use_askpass = 0, allow_askpass = 0;
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *askpass_hint = ಖಾಲಿ;
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *s;

	ಆದರೆ (((s = getenv("DISPLAY")) != ಖಾಲಿ && *s != '\0') ||
	    ((s = getenv("WAYLAND_DISPLAY")) != ಖಾಲಿ && *s != '\0'))
		allow_askpass = 1;
	ಆದರೆ ((s = getenv(SSH_ASKPASS_REQUIRE_ENV)) != ಖಾಲಿ) {
		ಆದರೆ (strcasecmp(s, "force") == 0) {
			use_askpass = 1;
			allow_askpass = 1;
		} ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strcasecmp(s, "prefer") == 0)
			use_askpass = allow_askpass;
		ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (strcasecmp(s, "never") == 0)
			allow_askpass = 0;
	}

	rppflags = (flags & RP_ECHO) ? RPP_ECHO_ON : RPP_ECHO_OFF;
	ಆದರೆ (use_askpass)
		debug_f("requested to askpass");
	ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (flags & RP_USE_ASKPASS)
		use_askpass = 1;
	ಇಲ್ಲದಿದ್ದರೆ ಆದರೆ (flags & RP_ALLOW_STDIN) {
		ಆದರೆ (!isatty(STDIN_FILENO)) {
			debug_f("stdin is not a tty");
			use_askpass = 1;
		}
	} ಇಲ್ಲದಿದ್ದರೆ {
		rppflags |= RPP_REQUIRE_TTY;
		ttyfd = open(_PATH_TTY, O_RDWR);
		ಆದರೆ (ttyfd >= 0) {
			/*
			 * If we're on a tty, ensure that show the prompt at
			 * the beginning of the line. This will hopefully
			 * clobber any password characters the user has
			 * optimistically typed before echo is disabled.
			 */
			(ಶೂನ್ಯ)ಲಿಖ(ttyfd, &cr, 1);
			close(ttyfd);
		} ಇಲ್ಲದಿದ್ದರೆ {
			debug_f("can't open %s: %s", _PATH_TTY,
			    strerror(errno));
			use_askpass = 1;
		}
	}

	ಆದರೆ ((flags & RP_USE_ASKPASS) && !allow_askpass)
		ಹಿಂತಿರುಗಿ (flags & RP_ALLOW_EOF) ? ಖಾಲಿ : xstrdup("");

	ಆದರೆ (use_askpass && allow_askpass) {
		ಆದರೆ (getenv(SSH_ASKPASS_ENV))
			askpass = getenv(SSH_ASKPASS_ENV);
		ಇಲ್ಲದಿದ್ದರೆ
			askpass = ಮಾರ್ಗ_SSH_ASKPASS_DEFAULT;
		ಆದರೆ ((flags & RP_ASK_PERMISSION) != 0)
			askpass_hint = "confirm";
		ಆದರೆ ((ret = ssh_askpass(askpass, prompt, askpass_hint)) == ಖಾಲಿ)
			ಆದರೆ (!(flags & RP_ALLOW_EOF))
				ಹಿಂತಿರುಗಿ xstrdup("");
		ಹಿಂತಿರುಗಿ ret;
	}

	ಆದರೆ (readpassphrase(prompt, buf, ಗಾತ್ರ buf, rppflags) == ಖಾಲಿ) {
		ಆದರೆ (flags & RP_ALLOW_EOF)
			ಹಿಂತಿರುಗಿ ಖಾಲಿ;
		ಹಿಂತಿರುಗಿ xstrdup("");
	}

	ret = xstrdup(buf);
	explicit_bzero(buf, ಗಾತ್ರ(buf));
	ಹಿಂತಿರುಗಿ ret;
}

ಪೂರ್ಣಾಂಕ
ask_permission(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *fmt, ...)
{
	va_list ವಾದಗಳು;
	ಅಕ್ಷರ *p, prompt[1024];
	ಪೂರ್ಣಾಂಕ allowed = 0;

	va_start(ವಾದಗಳು, fmt);
	vsnprintf(prompt, ಗಾತ್ರ(prompt), fmt, ವಾದಗಳು);
	va_end(ವಾದಗಳು);

	p = read_passphrase(prompt,
	    RP_USE_ASKPASS|RP_ALLOW_EOF|RP_ASK_PERMISSION);
	ಆದರೆ (p != ಖಾಲಿ) {
		/*
		 * Accept empty responses and responses consisting
		 * of the word "yes" as affirmative.
		 */
		ಆದರೆ (*p == '\0' || *p == '\n' ||
		    strcasecmp(p, "yes") == 0)
			allowed = 1;
		ಬಿಡುಗಡೆ(p);
	}

	ಹಿಂತಿರುಗಿ (allowed);
}

ಸ್ಥಿರ ಶೂನ್ಯ
writemsg(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *ಸಂದೇಶ)
{
	(ಶೂನ್ಯ)ಲಿಖ(STDERR_FILENO, "\r", 1);
	(ಶೂನ್ಯ)ಲಿಖ(STDERR_FILENO, ಸಂದೇಶ, ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(ಸಂದೇಶ));
	(ಶೂನ್ಯ)ಲಿಖ(STDERR_FILENO, "\r\n", 2);
}

ರಚನೆ notifier_ctx {
	pid_t pid;
	ಶೂನ್ಯ (*osigchld)(ಪೂರ್ಣಾಂಕ);
};

ರಚನೆ notifier_ctx *
notify_ಆರಂಭ(ಪೂರ್ಣಾಂಕ force_askpass, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *fmt, ...)
{
	va_list ವಾದಗಳು;
	ಅಕ್ಷರ *prompt = ಖಾಲಿ;
	pid_t pid = -1;
	ಶೂನ್ಯ (*osigchld)(ಪೂರ್ಣಾಂಕ) = ಖಾಲಿ;
	ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *askpass, *s;
	ರಚನೆ notifier_ctx *ret = ಖಾಲಿ;

	va_start(ವಾದಗಳು, fmt);
	xvasprintf(&prompt, fmt, ವಾದಗಳು);
	va_end(ವಾದಗಳು);

	ಆದರೆ (fflush(ಖಾಲಿ) != 0)
		error_f("fflush: %s", strerror(errno));
	ಆದರೆ (!force_askpass && isatty(STDERR_FILENO)) {
		writemsg(prompt);
		ಹೋಗು ಹೊರಹೋಗು_ctx;
	}
	ಆದರೆ ((askpass = getenv("SSH_ASKPASS")) == ಖಾಲಿ)
		askpass = ಮಾರ್ಗ_SSH_ASKPASS_DEFAULT;
	ಆದರೆ (*askpass == '\0') {
		debug3_f("cannot notify: no askpass");
		ಹೋಗು ಹೊರಹೋಗು;
	}
	ಆದರೆ (getenv("DISPLAY") == ಖಾಲಿ && getenv("WAYLAND_DISPLAY") == ಖಾಲಿ &&
	    ((s = getenv(SSH_ASKPASS_REQUIRE_ENV)) == ಖಾಲಿ ||
	    strcmp(s, "force") != 0)) {
		debug3_f("cannot notify: no display");
		ಹೋಗು ಹೊರಹೋಗು;
	}
	osigchld = ssh_signal(SIGCHLD, SIG_DFL);
	ಆದರೆ ((pid = fork()) == -1) {
		error_f("fork: %s", strerror(errno));
		ssh_signal(SIGCHLD, osigchld);
		ಬಿಡುಗಡೆ(prompt);
		ಹಿಂತಿರುಗಿ ಖಾಲಿ;
	}
	ಆದರೆ (pid == 0) {
		ಆದರೆ (stdfd_devnull(1, 1, 0) == -1)
			fatal_f("stdfd_devnull failed");
		closefrom(STDERR_FILENO + 1);
		setenv("SSH_ASKPASS_PROMPT", "none", 1); /* hint to UI */
		execlp(askpass, askpass, prompt, (ಅಕ್ಷರ *)ಖಾಲಿ);
		error_f("exec(%s): %s", askpass, strerror(errno));
		_exit(1);
		/* NOTREACHED */
	}
 ಹೊರಹೋಗು_ctx:
	ಆದರೆ ((ret = ಸೊನ್ನೆ_ಸ್ಮರಣೆ_ಕೊಡು(1, ಗಾತ್ರ(*ret))) == ಖಾಲಿ) {
		ಆದರೆ (pid != -1)
			kill(pid, SIGTERM);
		fatal_f("calloc failed");
	}
	ret->pid = pid;
	ret->osigchld = osigchld;
 ಹೊರಹೋಗು:
	ಬಿಡುಗಡೆ(prompt);
	ಹಿಂತಿರುಗಿ ret;
}

ಶೂನ್ಯ
notify_complete(ರಚನೆ notifier_ctx *ctx, ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *fmt, ...)
{
	ಪೂರ್ಣಾಂಕ ret;
	ಅಕ್ಷರ *ಸಂದೇಶ = ಖಾಲಿ;
	va_list ವಾದಗಳು;

	ಆದರೆ (ctx != ಖಾಲಿ && fmt != ಖಾಲಿ && ctx->pid == -1) {
		/*
		 * notify_start wrote to stderr, so send conclusion message
		 * there too
		*/
		va_start(ವಾದಗಳು, fmt);
		xvasprintf(&ಸಂದೇಶ, fmt, ವಾದಗಳು);
		va_end(ವಾದಗಳು);
		writemsg(ಸಂದೇಶ);
		ಬಿಡುಗಡೆ(ಸಂದೇಶ);
	}

	ಆದರೆ (ctx == ಖಾಲಿ || ctx->pid <= 0) {
		ಬಿಡುಗಡೆ(ctx);
		ಹಿಂತಿರುಗಿ;
	}
	kill(ctx->pid, SIGTERM);
	ಆಗ ((ret = waitpid(ctx->pid, ಖಾಲಿ, 0)) == -1) {
		ಆದರೆ (errno != EINTR)
			ನಿಲ್ಲಿಸು;
	}
	ಆದರೆ (ret == -1)
		fatal_f("waitpid: %s", strerror(errno));
	ssh_signal(SIGCHLD, ctx->osigchld);
	ಬಿಡುಗಡೆ(ctx);
}
