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

#अन्तर्भाव "includes.h"

#अन्तर्भाव <sys/types.h>
#अन्तर्भाव <sys/wait.h>

#अन्तर्भाव <errno.h>
#अन्तर्भाव <fcntl.h>
#अन्तर्भाव <paths.h>
#अन्तर्भाव <signal.h>
#अन्तर्भाव <stdarg.h>
#अन्तर्भाव <stdio.h>
#अन्तर्भाव <stdlib.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <unistd.h>

#अन्तर्भाव "xmalloc.h"
#अन्तर्भाव "misc.h"
#अन्तर्भाव "pathnames.h"
#अन्तर्भाव "log.h"
#अन्तर्भाव "ssh.h"

स्थिर वर्ण *
ssh_askpass(वर्ण *askpass, ध्रुव वर्ण *सन्देशः, ध्रुव वर्ण *env_hint)
{
	pid_t pid, ret;
	size_t len;
	वर्ण *pass;
	पूर्णाङ्क p[2], status;
	वर्ण buf[1024];
	शून्य (*osigchld)(पूर्णाङ्क);

	सचे (fflush(stdout) != 0)
		error_f("fflush: %s", strerror(errno));
	सचे (askpass == रिक्त)
		fatal("internal error: askpass undefined");
	सचे (pipe(p) == -1) {
		error_f("pipe: %s", strerror(errno));
		पटिनिवत्त रिक्त;
	}
	osigchld = ssh_signal(SIGCHLD, SIG_DFL);
	सचे ((pid = fork()) == -1) {
		error_f("fork: %s", strerror(errno));
		ssh_signal(SIGCHLD, osigchld);
		पटिनिवत्त रिक्त;
	}
	सचे (pid == 0) {
		close(p[0]);
		सचे (dup2(p[1], STDOUT_FILENO) == -1)
			fatal_f("dup2: %s", strerror(errno));
		सचे (env_hint != रिक्त)
			setenv("SSH_ASKPASS_PROMPT", env_hint, 1);
		execlp(askpass, askpass, सन्देशः, (वर्ण *)रिक्त);
		fatal_f("exec(%s): %s", askpass, strerror(errno));
	}
	close(p[1]);

	len = 0;
	करोहि {
		ssize_t r = पठ(p[0], buf + len, परिमाण(buf) - 1 - len);

		सचे (r == -1 && errno == EINTR)
			अनुवर्त;
		सचे (r <= 0)
			भङ्ग;
		len += r;
	} याव (len < परिमाण(buf) - 1);
	buf[len] = '\0';

	close(p[0]);
	याव ((ret = waitpid(pid, &status, 0)) == -1)
		सचे (errno != EINTR)
			भङ्ग;
	ssh_signal(SIGCHLD, osigchld);
	सचे (ret == -1 || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		explicit_bzero(buf, परिमाण(buf));
		पटिनिवत्त रिक्त;
	}

	buf[strcspn(buf, "\r\n")] = '\0';
	pass = xstrdup(buf);
	explicit_bzero(buf, परिमाण(buf));
	पटिनिवत्त pass;
}

/* private/internal read_passphrase flags */
#define RP_ASK_PERMISSION	0x8000 /* pass hint to askpass for confirm UI */

/*
 * Reads a passphrase from /dev/tty with echo turned off/on.  Returns the
 * passphrase (allocated with xmalloc).  Exits if EOF is encountered. If
 * RP_ALLOW_STDIN is set, the passphrase will be read from stdin if no
 * tty is or askpass program is available
 */
वर्ण *
read_passphrase(ध्रुव वर्ण *prompt, पूर्णाङ्क flags)
{
	वर्ण cr = '\r', *askpass = रिक्त, *ret, buf[1024];
	पूर्णाङ्क rppflags, ttyfd, use_askpass = 0, allow_askpass = 0;
	ध्रुव वर्ण *askpass_hint = रिक्त;
	ध्रुव वर्ण *s;

	सचे (((s = getenv("DISPLAY")) != रिक्त && *s != '\0') ||
	    ((s = getenv("WAYLAND_DISPLAY")) != रिक्त && *s != '\0'))
		allow_askpass = 1;
	सचे ((s = getenv(SSH_ASKPASS_REQUIRE_ENV)) != रिक्त) {
		सचे (strcasecmp(s, "force") == 0) {
			use_askpass = 1;
			allow_askpass = 1;
		} अञ्ञथा सचे (strcasecmp(s, "prefer") == 0)
			use_askpass = allow_askpass;
		अञ्ञथा सचे (strcasecmp(s, "never") == 0)
			allow_askpass = 0;
	}

	rppflags = (flags & RP_ECHO) ? RPP_ECHO_ON : RPP_ECHO_OFF;
	सचे (use_askpass)
		debug_f("requested to askpass");
	अञ्ञथा सचे (flags & RP_USE_ASKPASS)
		use_askpass = 1;
	अञ्ञथा सचे (flags & RP_ALLOW_STDIN) {
		सचे (!isatty(STDIN_FILENO)) {
			debug_f("stdin is not a tty");
			use_askpass = 1;
		}
	} अञ्ञथा {
		rppflags |= RPP_REQUIRE_TTY;
		ttyfd = open(_PATH_TTY, O_RDWR);
		सचे (ttyfd >= 0) {
			/*
			 * If we're on a tty, ensure that show the prompt at
			 * the beginning of the line. This will hopefully
			 * clobber any password characters the user has
			 * optimistically typed before echo is disabled.
			 */
			(शून्य)लिख(ttyfd, &cr, 1);
			close(ttyfd);
		} अञ्ञथा {
			debug_f("can't open %s: %s", _PATH_TTY,
			    strerror(errno));
			use_askpass = 1;
		}
	}

	सचे ((flags & RP_USE_ASKPASS) && !allow_askpass)
		पटिनिवत्त (flags & RP_ALLOW_EOF) ? रिक्त : xstrdup("");

	सचे (use_askpass && allow_askpass) {
		सचे (getenv(SSH_ASKPASS_ENV))
			askpass = getenv(SSH_ASKPASS_ENV);
		अञ्ञथा
			askpass = _PATH_SSH_ASKPASS_DEFAULT;
		सचे ((flags & RP_ASK_PERMISSION) != 0)
			askpass_hint = "confirm";
		सचे ((ret = ssh_askpass(askpass, prompt, askpass_hint)) == रिक्त)
			सचे (!(flags & RP_ALLOW_EOF))
				पटिनिवत्त xstrdup("");
		पटिनिवत्त ret;
	}

	सचे (readpassphrase(prompt, buf, परिमाण buf, rppflags) == रिक्त) {
		सचे (flags & RP_ALLOW_EOF)
			पटिनिवत्त रिक्त;
		पटिनिवत्त xstrdup("");
	}

	ret = xstrdup(buf);
	explicit_bzero(buf, परिमाण(buf));
	पटिनिवत्त ret;
}

पूर्णाङ्क
ask_permission(ध्रुव वर्ण *fmt, ...)
{
	va_list args;
	वर्ण *p, prompt[1024];
	पूर्णाङ्क allowed = 0;

	va_start(args, fmt);
	vsnprintf(prompt, परिमाण(prompt), fmt, args);
	va_end(args);

	p = read_passphrase(prompt,
	    RP_USE_ASKPASS|RP_ALLOW_EOF|RP_ASK_PERMISSION);
	सचे (p != रिक्त) {
		/*
		 * Accept empty responses and responses consisting
		 * of the word "yes" as affirmative.
		 */
		सचे (*p == '\0' || *p == '\n' ||
		    strcasecmp(p, "yes") == 0)
			allowed = 1;
		मुक्त(p);
	}

	पटिनिवत्त (allowed);
}

स्थिर शून्य
writemsg(ध्रुव वर्ण *सन्देशः)
{
	(शून्य)लिख(STDERR_FILENO, "\r", 1);
	(शून्य)लिख(STDERR_FILENO, सन्देशः, strlen(सन्देशः));
	(शून्य)लिख(STDERR_FILENO, "\r\n", 2);
}

संरचना notifier_ctx {
	pid_t pid;
	शून्य (*osigchld)(पूर्णाङ्क);
};

संरचना notifier_ctx *
notify_start(पूर्णाङ्क force_askpass, ध्रुव वर्ण *fmt, ...)
{
	va_list args;
	वर्ण *prompt = रिक्त;
	pid_t pid = -1;
	शून्य (*osigchld)(पूर्णाङ्क) = रिक्त;
	ध्रुव वर्ण *askpass, *s;
	संरचना notifier_ctx *ret = रिक्त;

	va_start(args, fmt);
	xvasprintf(&prompt, fmt, args);
	va_end(args);

	सचे (fflush(रिक्त) != 0)
		error_f("fflush: %s", strerror(errno));
	सचे (!force_askpass && isatty(STDERR_FILENO)) {
		writemsg(prompt);
		गच्छ out_ctx;
	}
	सचे ((askpass = getenv("SSH_ASKPASS")) == रिक्त)
		askpass = _PATH_SSH_ASKPASS_DEFAULT;
	सचे (*askpass == '\0') {
		debug3_f("cannot notify: no askpass");
		गच्छ out;
	}
	सचे (getenv("DISPLAY") == रिक्त && getenv("WAYLAND_DISPLAY") == रिक्त &&
	    ((s = getenv(SSH_ASKPASS_REQUIRE_ENV)) == रिक्त ||
	    strcmp(s, "force") != 0)) {
		debug3_f("cannot notify: no display");
		गच्छ out;
	}
	osigchld = ssh_signal(SIGCHLD, SIG_DFL);
	सचे ((pid = fork()) == -1) {
		error_f("fork: %s", strerror(errno));
		ssh_signal(SIGCHLD, osigchld);
		मुक्त(prompt);
		पटिनिवत्त रिक्त;
	}
	सचे (pid == 0) {
		सचे (stdfd_devnull(1, 1, 0) == -1)
			fatal_f("stdfd_devnull failed");
		closefrom(STDERR_FILENO + 1);
		setenv("SSH_ASKPASS_PROMPT", "none", 1); /* hint to UI */
		execlp(askpass, askpass, prompt, (वर्ण *)रिक्त);
		error_f("exec(%s): %s", askpass, strerror(errno));
		_exit(1);
		/* NOTREACHED */
	}
 out_ctx:
	सचे ((ret = calloc(1, परिमाण(*ret))) == रिक्त) {
		सचे (pid != -1)
			kill(pid, SIGTERM);
		fatal_f("calloc failed");
	}
	ret->pid = pid;
	ret->osigchld = osigchld;
 out:
	मुक्त(prompt);
	पटिनिवत्त ret;
}

शून्य
notify_complete(संरचना notifier_ctx *ctx, ध्रुव वर्ण *fmt, ...)
{
	पूर्णाङ्क ret;
	वर्ण *सन्देशः = रिक्त;
	va_list args;

	सचे (ctx != रिक्त && fmt != रिक्त && ctx->pid == -1) {
		/*
		 * notify_start wrote to stderr, so send conclusion message
		 * there too
		*/
		va_start(args, fmt);
		xvasprintf(&सन्देशः, fmt, args);
		va_end(args);
		writemsg(सन्देशः);
		मुक्त(सन्देशः);
	}

	सचे (ctx == रिक्त || ctx->pid <= 0) {
		मुक्त(ctx);
		पटिनिवत्त;
	}
	kill(ctx->pid, SIGTERM);
	याव ((ret = waitpid(ctx->pid, रिक्त, 0)) == -1) {
		सचे (errno != EINTR)
			भङ्ग;
	}
	सचे (ret == -1)
		fatal_f("waitpid: %s", strerror(errno));
	ssh_signal(SIGCHLD, ctx->osigchld);
	मुक्त(ctx);
}
