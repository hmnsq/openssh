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

स्थिर अक्षर *
ssh_askpass(अक्षर *askpass, स्थिरांक अक्षर *संदेश, स्थिरांक अक्षर *env_hint)
{
	pid_t pid, ret;
	माप_प्रकार len;
	अक्षर *pass;
	पूर्णांक p[2], status;
	अक्षर buf[1024];
	शून्य (*osigchld)(पूर्णांक);

	जर (ख_साफ(मानक_निकास) != 0)
		error_f("fflush: %s", म_त्रुटि(त्रुटि_सं));
	जर (askpass == रिक्त)
		fatal("internal error: askpass undefined");
	जर (pipe(p) == -1) {
		error_f("pipe: %s", म_त्रुटि(त्रुटि_सं));
		परत रिक्त;
	}
	osigchld = ssh_signal(SIGCHLD, संक_पूर्व);
	जर ((pid = विभाजन()) == -1) {
		error_f("fork: %s", म_त्रुटि(त्रुटि_सं));
		ssh_signal(SIGCHLD, osigchld);
		परत रिक्त;
	}
	जर (pid == 0) {
		बंद(p[0]);
		जर (dup2(p[1], STDOUT_FILENO) == -1)
			fatal_f("dup2: %s", म_त्रुटि(त्रुटि_सं));
		जर (env_hint != रिक्त)
			setenv("SSH_ASKPASS_PROMPT", env_hint, 1);
		execlp(askpass, askpass, संदेश, (अक्षर *)रिक्त);
		fatal_f("exec(%s): %s", askpass, म_त्रुटि(त्रुटि_सं));
	}
	बंद(p[1]);

	len = 0;
	करा {
		ssize_t r = पठ(p[0], buf + len, आकार(buf) - 1 - len);

		जर (r == -1 && त्रुटि_सं == EINTR)
			सुरूठेवा;
		जर (r <= 0)
			थांबा;
		len += r;
	} पर्यंत (len < आकार(buf) - 1);
	buf[len] = '\0';

	बंद(p[0]);
	पर्यंत ((ret = waitpid(pid, &status, 0)) == -1)
		जर (त्रुटि_सं != EINTR)
			थांबा;
	ssh_signal(SIGCHLD, osigchld);
	जर (ret == -1 || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		explicit_bzero(buf, आकार(buf));
		परत रिक्त;
	}

	buf[म_खोज(buf, "\r\n")] = '\0';
	pass = xstrdup(buf);
	explicit_bzero(buf, आकार(buf));
	परत pass;
}

/* private/internal read_passphrase flags */
#define RP_ASK_PERMISSION	0x8000 /* pass hint to askpass for confirm UI */

/*
 * Reads a passphrase from /dev/tty with echo turned off/on.  Returns the
 * passphrase (allocated with xmalloc).  Exits if EOF is encountered. If
 * RP_ALLOW_STDIN is set, the passphrase will be read from stdin if no
 * tty is or askpass program is available
 */
अक्षर *
read_passphrase(स्थिरांक अक्षर *prompt, पूर्णांक flags)
{
	अक्षर cr = '\r', *askpass = रिक्त, *ret, buf[1024];
	पूर्णांक rppflags, ttyfd, use_askpass = 0, allow_askpass = 0;
	स्थिरांक अक्षर *askpass_hint = रिक्त;
	स्थिरांक अक्षर *s;

	जर (((s = दो_पर्या("DISPLAY")) != रिक्त && *s != '\0') ||
	    ((s = दो_पर्या("WAYLAND_DISPLAY")) != रिक्त && *s != '\0'))
		allow_askpass = 1;
	जर ((s = दो_पर्या(SSH_ASKPASS_REQUIRE_ENV)) != रिक्त) {
		जर (strcasecmp(s, "force") == 0) {
			use_askpass = 1;
			allow_askpass = 1;
		} अन्यथा जर (strcasecmp(s, "prefer") == 0)
			use_askpass = allow_askpass;
		अन्यथा जर (strcasecmp(s, "never") == 0)
			allow_askpass = 0;
	}

	rppflags = (flags & RP_ECHO) ? RPP_ECHO_ON : RPP_ECHO_OFF;
	जर (use_askpass)
		debug_f("requested to askpass");
	अन्यथा जर (flags & RP_USE_ASKPASS)
		use_askpass = 1;
	अन्यथा जर (flags & RP_ALLOW_STDIN) {
		जर (!isatty(STDIN_FILENO)) {
			debug_f("stdin is not a tty");
			use_askpass = 1;
		}
	} अन्यथा {
		rppflags |= RPP_REQUIRE_TTY;
		ttyfd = खोलो(_PATH_TTY, O_RDWR);
		जर (ttyfd >= 0) {
			/*
			 * If we're on a tty, ensure that show the prompt at
			 * the beginning of the line. This will hopefully
			 * clobber any password characters the user has
			 * optimistically typed before echo is disabled.
			 */
			(शून्य)लिख(ttyfd, &cr, 1);
			बंद(ttyfd);
		} अन्यथा {
			debug_f("can't open %s: %s", _PATH_TTY,
			    म_त्रुटि(त्रुटि_सं));
			use_askpass = 1;
		}
	}

	जर ((flags & RP_USE_ASKPASS) && !allow_askpass)
		परत (flags & RP_ALLOW_EOF) ? रिक्त : xstrdup("");

	जर (use_askpass && allow_askpass) {
		जर (दो_पर्या(SSH_ASKPASS_ENV))
			askpass = दो_पर्या(SSH_ASKPASS_ENV);
		अन्यथा
			askpass = _PATH_SSH_ASKPASS_DEFAULT;
		जर ((flags & RP_ASK_PERMISSION) != 0)
			askpass_hint = "confirm";
		जर ((ret = ssh_askpass(askpass, prompt, askpass_hint)) == रिक्त)
			जर (!(flags & RP_ALLOW_EOF))
				परत xstrdup("");
		परत ret;
	}

	जर (readpassphrase(prompt, buf, आकार buf, rppflags) == रिक्त) {
		जर (flags & RP_ALLOW_EOF)
			परत रिक्त;
		परत xstrdup("");
	}

	ret = xstrdup(buf);
	explicit_bzero(buf, आकार(buf));
	परत ret;
}

पूर्णांक
ask_permission(स्थिरांक अक्षर *fmt, ...)
{
	बहु_सूची args;
	अक्षर *p, prompt[1024];
	पूर्णांक allowed = 0;

	बहु_शुरू(args, fmt);
	vsnprintf(prompt, आकार(prompt), fmt, args);
	बहु_पूर्ण(args);

	p = read_passphrase(prompt,
	    RP_USE_ASKPASS|RP_ALLOW_EOF|RP_ASK_PERMISSION);
	जर (p != रिक्त) {
		/*
		 * Accept empty responses and responses consisting
		 * of the word "yes" as affirmative.
		 */
		जर (*p == '\0' || *p == '\n' ||
		    strcasecmp(p, "yes") == 0)
			allowed = 1;
		मुक्त(p);
	}

	परत (allowed);
}

स्थिर शून्य
writemsg(स्थिरांक अक्षर *संदेश)
{
	(शून्य)लिख(STDERR_FILENO, "\r", 1);
	(शून्य)लिख(STDERR_FILENO, संदेश, म_माप(संदेश));
	(शून्य)लिख(STDERR_FILENO, "\r\n", 2);
}

संरचना notifier_ctx {
	pid_t pid;
	शून्य (*osigchld)(पूर्णांक);
};

संरचना notifier_ctx *
notify_start(पूर्णांक force_askpass, स्थिरांक अक्षर *fmt, ...)
{
	बहु_सूची args;
	अक्षर *prompt = रिक्त;
	pid_t pid = -1;
	शून्य (*osigchld)(पूर्णांक) = रिक्त;
	स्थिरांक अक्षर *askpass, *s;
	संरचना notifier_ctx *ret = रिक्त;

	बहु_शुरू(args, fmt);
	xvasprintf(&prompt, fmt, args);
	बहु_पूर्ण(args);

	जर (ख_साफ(रिक्त) != 0)
		error_f("fflush: %s", म_त्रुटि(त्रुटि_सं));
	जर (!force_askpass && isatty(STDERR_FILENO)) {
		writemsg(prompt);
		जा out_ctx;
	}
	जर ((askpass = दो_पर्या("SSH_ASKPASS")) == रिक्त)
		askpass = _PATH_SSH_ASKPASS_DEFAULT;
	जर (*askpass == '\0') {
		debug3_f("cannot notify: no askpass");
		जा out;
	}
	जर (दो_पर्या("DISPLAY") == रिक्त && दो_पर्या("WAYLAND_DISPLAY") == रिक्त &&
	    ((s = दो_पर्या(SSH_ASKPASS_REQUIRE_ENV)) == रिक्त ||
	    म_भेद(s, "force") != 0)) {
		debug3_f("cannot notify: no display");
		जा out;
	}
	osigchld = ssh_signal(SIGCHLD, संक_पूर्व);
	जर ((pid = विभाजन()) == -1) {
		error_f("fork: %s", म_त्रुटि(त्रुटि_सं));
		ssh_signal(SIGCHLD, osigchld);
		मुक्त(prompt);
		परत रिक्त;
	}
	जर (pid == 0) {
		जर (stdfd_devnull(1, 1, 0) == -1)
			fatal_f("stdfd_devnull failed");
		closefrom(STDERR_FILENO + 1);
		setenv("SSH_ASKPASS_PROMPT", "none", 1); /* hint to UI */
		execlp(askpass, askpass, prompt, (अक्षर *)रिक्त);
		error_f("exec(%s): %s", askpass, म_त्रुटि(त्रुटि_सं));
		_exit(1);
		/* NOTREACHED */
	}
 out_ctx:
	जर ((ret = सुस्मृति(1, आकार(*ret))) == रिक्त) {
		जर (pid != -1)
			समाप्त(pid, संक_इति);
		fatal_f("calloc failed");
	}
	ret->pid = pid;
	ret->osigchld = osigchld;
 out:
	मुक्त(prompt);
	परत ret;
}

शून्य
notify_complete(संरचना notifier_ctx *ctx, स्थिरांक अक्षर *fmt, ...)
{
	पूर्णांक ret;
	अक्षर *संदेश = रिक्त;
	बहु_सूची args;

	जर (ctx != रिक्त && fmt != रिक्त && ctx->pid == -1) {
		/*
		 * notify_start wrote to stderr, so send conclusion message
		 * there too
		*/
		बहु_शुरू(args, fmt);
		xvasprintf(&संदेश, fmt, args);
		बहु_पूर्ण(args);
		writemsg(संदेश);
		मुक्त(संदेश);
	}

	जर (ctx == रिक्त || ctx->pid <= 0) {
		मुक्त(ctx);
		परत;
	}
	समाप्त(ctx->pid, संक_इति);
	पर्यंत ((ret = waitpid(ctx->pid, रिक्त, 0)) == -1) {
		जर (त्रुटि_सं != EINTR)
			थांबा;
	}
	जर (ret == -1)
		fatal_f("waitpid: %s", म_त्रुटि(त्रुटि_सं));
	ssh_signal(SIGCHLD, ctx->osigchld);
	मुक्त(ctx);
}
