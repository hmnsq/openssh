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

#समावेश "includes.h"

#समावेश <sys/types.h>
#समावेश <sys/wait.h>

#समावेश <errno.h>
#समावेश <fcntl.h>
#समावेश <paths.h>
#समावेश <signal.h>
#समावेश <stdarg.h>
#समावेश <stdio.h>
#समावेश <stdlib.h>
#समावेश <string.h>
#समावेश <unistd.h>

#समावेश "xmalloc.h"
#समावेश "misc.h"
#समावेश "pathnames.h"
#समावेश "log.h"
#समावेश "ssh.h"

अटल अक्षर *
ssh_askpass(अक्षर *askpass, स्थिर अक्षर *संदेश, स्थिर अक्षर *env_hint)
{
	pid_t pid, ret;
	माप_प्रकार len;
	अक्षर *pass;
	पूर्णांक p[2], status;
	अक्षर buf[1024];
	व्योम (*osigchld)(पूर्णांक);

	अगर (ख_साफ(मानक_निकास) != 0)
		error_f("fflush: %s", म_त्रुटि(त्रुटि_सं));
	अगर (askpass == शून्य)
		fatal("internal error: askpass undefined");
	अगर (pipe(p) == -1) {
		error_f("pipe: %s", म_त्रुटि(त्रुटि_सं));
		वापस शून्य;
	}
	osigchld = ssh_signal(SIGCHLD, संक_पूर्व);
	अगर ((pid = विभाजन()) == -1) {
		error_f("fork: %s", म_त्रुटि(त्रुटि_सं));
		ssh_signal(SIGCHLD, osigchld);
		वापस शून्य;
	}
	अगर (pid == 0) {
		बंद(p[0]);
		अगर (dup2(p[1], STDOUT_FILENO) == -1)
			fatal_f("dup2: %s", म_त्रुटि(त्रुटि_सं));
		अगर (env_hint != शून्य)
			setenv("SSH_ASKPASS_PROMPT", env_hint, 1);
		execlp(askpass, askpass, संदेश, (अक्षर *)शून्य);
		fatal_f("exec(%s): %s", askpass, म_त्रुटि(त्रुटि_सं));
	}
	बंद(p[1]);

	len = 0;
	करो {
		ssize_t r = पढ़ो(p[0], buf + len, माप(buf) - 1 - len);

		अगर (r == -1 && त्रुटि_सं == EINTR)
			जारी;
		अगर (r <= 0)
			अवरोध;
		len += r;
	} जबतक (len < माप(buf) - 1);
	buf[len] = '\0';

	बंद(p[0]);
	जबतक ((ret = waitpid(pid, &status, 0)) == -1)
		अगर (त्रुटि_सं != EINTR)
			अवरोध;
	ssh_signal(SIGCHLD, osigchld);
	अगर (ret == -1 || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		explicit_bzero(buf, माप(buf));
		वापस शून्य;
	}

	buf[म_खोज(buf, "\r\n")] = '\0';
	pass = xstrdup(buf);
	explicit_bzero(buf, माप(buf));
	वापस pass;
}

/* private/internal read_passphrase flags */
#घोषणा RP_ASK_PERMISSION	0x8000 /* pass hint to askpass for confirm UI */

/*
 * Reads a passphrase from /dev/tty with echo turned off/on.  Returns the
 * passphrase (allocated with xmalloc).  Exits if EOF is encountered. If
 * RP_ALLOW_STDIN is set, the passphrase will be read from stdin if no
 * tty is or askpass program is available
 */
अक्षर *
read_passphrase(स्थिर अक्षर *prompt, पूर्णांक flags)
{
	अक्षर cr = '\r', *askpass = शून्य, *ret, buf[1024];
	पूर्णांक rppflags, ttyfd, use_askpass = 0, allow_askpass = 0;
	स्थिर अक्षर *askpass_hint = शून्य;
	स्थिर अक्षर *s;

	अगर (((s = दो_पर्या("DISPLAY")) != शून्य && *s != '\0') ||
	    ((s = दो_पर्या("WAYLAND_DISPLAY")) != शून्य && *s != '\0'))
		allow_askpass = 1;
	अगर ((s = दो_पर्या(SSH_ASKPASS_REQUIRE_ENV)) != शून्य) {
		अगर (strcasecmp(s, "force") == 0) {
			use_askpass = 1;
			allow_askpass = 1;
		} अन्यथा अगर (strcasecmp(s, "prefer") == 0)
			use_askpass = allow_askpass;
		अन्यथा अगर (strcasecmp(s, "never") == 0)
			allow_askpass = 0;
	}

	rppflags = (flags & RP_ECHO) ? RPP_ECHO_ON : RPP_ECHO_OFF;
	अगर (use_askpass)
		debug_f("requested to askpass");
	अन्यथा अगर (flags & RP_USE_ASKPASS)
		use_askpass = 1;
	अन्यथा अगर (flags & RP_ALLOW_STDIN) {
		अगर (!isatty(STDIN_FILENO)) {
			debug_f("stdin is not a tty");
			use_askpass = 1;
		}
	} अन्यथा {
		rppflags |= RPP_REQUIRE_TTY;
		ttyfd = खोलो(_PATH_TTY, O_RDWR);
		अगर (ttyfd >= 0) {
			/*
			 * If we're on a tty, ensure that show the prompt at
			 * the beginning of the line. This will hopefully
			 * clobber any password characters the user has
			 * optimistically typed before echo is disabled.
			 */
			(व्योम)ग_लिखो(ttyfd, &cr, 1);
			बंद(ttyfd);
		} अन्यथा {
			debug_f("can't open %s: %s", _PATH_TTY,
			    म_त्रुटि(त्रुटि_सं));
			use_askpass = 1;
		}
	}

	अगर ((flags & RP_USE_ASKPASS) && !allow_askpass)
		वापस (flags & RP_ALLOW_EOF) ? शून्य : xstrdup("");

	अगर (use_askpass && allow_askpass) {
		अगर (दो_पर्या(SSH_ASKPASS_ENV))
			askpass = दो_पर्या(SSH_ASKPASS_ENV);
		अन्यथा
			askpass = _PATH_SSH_ASKPASS_DEFAULT;
		अगर ((flags & RP_ASK_PERMISSION) != 0)
			askpass_hint = "confirm";
		अगर ((ret = ssh_askpass(askpass, prompt, askpass_hint)) == शून्य)
			अगर (!(flags & RP_ALLOW_EOF))
				वापस xstrdup("");
		वापस ret;
	}

	अगर (readpassphrase(prompt, buf, माप buf, rppflags) == शून्य) {
		अगर (flags & RP_ALLOW_EOF)
			वापस शून्य;
		वापस xstrdup("");
	}

	ret = xstrdup(buf);
	explicit_bzero(buf, माप(buf));
	वापस ret;
}

पूर्णांक
ask_permission(स्थिर अक्षर *fmt, ...)
{
	बहु_सूची args;
	अक्षर *p, prompt[1024];
	पूर्णांक allowed = 0;

	बहु_शुरू(args, fmt);
	vsnprintf(prompt, माप(prompt), fmt, args);
	बहु_पूर्ण(args);

	p = read_passphrase(prompt,
	    RP_USE_ASKPASS|RP_ALLOW_EOF|RP_ASK_PERMISSION);
	अगर (p != शून्य) {
		/*
		 * Accept empty responses and responses consisting
		 * of the word "yes" as affirmative.
		 */
		अगर (*p == '\0' || *p == '\n' ||
		    strcasecmp(p, "yes") == 0)
			allowed = 1;
		मुक्त(p);
	}

	वापस (allowed);
}

अटल व्योम
writemsg(स्थिर अक्षर *संदेश)
{
	(व्योम)ग_लिखो(STDERR_FILENO, "\r", 1);
	(व्योम)ग_लिखो(STDERR_FILENO, संदेश, म_माप(संदेश));
	(व्योम)ग_लिखो(STDERR_FILENO, "\r\n", 2);
}

काष्ठा notifier_ctx {
	pid_t pid;
	व्योम (*osigchld)(पूर्णांक);
};

काष्ठा notifier_ctx *
notify_start(पूर्णांक force_askpass, स्थिर अक्षर *fmt, ...)
{
	बहु_सूची args;
	अक्षर *prompt = शून्य;
	pid_t pid = -1;
	व्योम (*osigchld)(पूर्णांक) = शून्य;
	स्थिर अक्षर *askpass, *s;
	काष्ठा notifier_ctx *ret = शून्य;

	बहु_शुरू(args, fmt);
	xvasprintf(&prompt, fmt, args);
	बहु_पूर्ण(args);

	अगर (ख_साफ(शून्य) != 0)
		error_f("fflush: %s", म_त्रुटि(त्रुटि_सं));
	अगर (!force_askpass && isatty(STDERR_FILENO)) {
		writemsg(prompt);
		जाओ out_ctx;
	}
	अगर ((askpass = दो_पर्या("SSH_ASKPASS")) == शून्य)
		askpass = _PATH_SSH_ASKPASS_DEFAULT;
	अगर (*askpass == '\0') {
		debug3_f("cannot notify: no askpass");
		जाओ out;
	}
	अगर (दो_पर्या("DISPLAY") == शून्य && दो_पर्या("WAYLAND_DISPLAY") == शून्य &&
	    ((s = दो_पर्या(SSH_ASKPASS_REQUIRE_ENV)) == शून्य ||
	    म_भेद(s, "force") != 0)) {
		debug3_f("cannot notify: no display");
		जाओ out;
	}
	osigchld = ssh_signal(SIGCHLD, संक_पूर्व);
	अगर ((pid = विभाजन()) == -1) {
		error_f("fork: %s", म_त्रुटि(त्रुटि_सं));
		ssh_signal(SIGCHLD, osigchld);
		मुक्त(prompt);
		वापस शून्य;
	}
	अगर (pid == 0) {
		अगर (stdfd_devnull(1, 1, 0) == -1)
			fatal_f("stdfd_devnull failed");
		closefrom(STDERR_FILENO + 1);
		setenv("SSH_ASKPASS_PROMPT", "none", 1); /* hint to UI */
		execlp(askpass, askpass, prompt, (अक्षर *)शून्य);
		error_f("exec(%s): %s", askpass, म_त्रुटि(त्रुटि_सं));
		_निकास(1);
		/* NOTREACHED */
	}
 out_ctx:
	अगर ((ret = सुस्मृति(1, माप(*ret))) == शून्य) {
		अगर (pid != -1)
			समाप्त(pid, संक_इति);
		fatal_f("calloc failed");
	}
	ret->pid = pid;
	ret->osigchld = osigchld;
 out:
	मुक्त(prompt);
	वापस ret;
}

व्योम
notify_complete(काष्ठा notifier_ctx *ctx, स्थिर अक्षर *fmt, ...)
{
	पूर्णांक ret;
	अक्षर *संदेश = शून्य;
	बहु_सूची args;

	अगर (ctx != शून्य && fmt != शून्य && ctx->pid == -1) {
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

	अगर (ctx == शून्य || ctx->pid <= 0) {
		मुक्त(ctx);
		वापस;
	}
	समाप्त(ctx->pid, संक_इति);
	जबतक ((ret = waitpid(ctx->pid, शून्य, 0)) == -1) {
		अगर (त्रुटि_सं != EINTR)
			अवरोध;
	}
	अगर (ret == -1)
		fatal_f("waitpid: %s", म_त्रुटि(त्रुटि_सं));
	ssh_signal(SIGCHLD, ctx->osigchld);
	मुक्त(ctx);
}
