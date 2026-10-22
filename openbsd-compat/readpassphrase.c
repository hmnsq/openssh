/*	$OpenBSD: readpassphrase.c,v 1.32 2026/10/15 16:40:50 millert Exp $	*/

/*
 * Copyright (c) 2000-2002, 2007, 2010
 *	Todd C. Miller <millert@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 * Sponsored in part by the Defense Advanced Research Projects
 * Agency (DARPA) and Air Force Research Laboratory, Air Force
 * Materiel Command, USAF, under agreement number F39502-99-1-0512.
 */

/* OPENBSD ORIGINAL: lib/libc/gen/readpassphrase.c */

#समावेश "includes.h"

#अगर_अघोषित HAVE_READPASSPHRASE

#समावेश <termios.h>
#समावेश <signal.h>
#समावेश <ctype.h>
#समावेश <fcntl.h>
#समावेश <readpassphrase.h>
#समावेश <errno.h>
#समावेश <string.h>
#समावेश <unistd.h>

#अगर_अघोषित TCSASOFT
/* If we don't have TCSASOFT define it so that ORing it it below is a no-op. */
# define TCSASOFT 0
#पूर्ण_अगर

/* SunOS 4.x which lacks _POSIX_VDISABLE, but has VDISABLE */
#अगर !defined(_POSIX_VDISABLE) && defined(VDISABLE)
#  define _POSIX_VDISABLE       VDISABLE
#पूर्ण_अगर

अटल अस्थिर संक_पूर्ण_प्रकार signo[_NSIG];

अटल व्योम handler(पूर्णांक);

/* Like sigaction(2) but preserves SIG_IGN */
अटल व्योम
sigaction_except_ign(पूर्णांक signum, काष्ठा sigaction *act, काष्ठा sigaction *old)
{
	काष्ठा sigaction sabuf;

	अगर (old == शून्य)
		old = &sabuf;

	(व्योम)sigaction(signum, act, old);
	/* Reinstate SIG_IGN; we don't want to override this */
	अगर (old->sa_handler == संक_छोड़ो && act->sa_handler != संक_छोड़ो)
		(व्योम)sigaction(signum, old, शून्य);
}

अक्षर *
readpassphrase(स्थिर अक्षर *prompt, अक्षर *buf, माप_प्रकार bufsiz, पूर्णांक flags)
{
	ssize_t nr;
	पूर्णांक निवेश, output, save_errno, i, need_restart;
	अक्षर ch, *p, *end;
	काष्ठा termios term, oterm;
	काष्ठा sigaction sa, savealrm, saveint, savehup, savequit, saveterm;
	काष्ठा sigaction savetstp, savettin, savettou, savepipe;

	/* I suppose we could alloc on demand in this case (XXX). */
	अगर (bufsiz == 0) {
		त्रुटि_सं = EINVAL;
		वापस(शून्य);
	}

restart:
	क्रम (i = 0; i < _NSIG; i++)
		signo[i] = 0;
	nr = -1;
	save_errno = 0;
	need_restart = 0;
	/*
	 * Read and write to /dev/tty if available.  If not, read from
	 * stdin and write to stderr unless a tty is required.
	 */
#अगर_अघोषित O_CLOEXEC
# define O_CLOEXEC 0
#पूर्ण_अगर
	अगर ((flags & RPP_STDIN) ||
	    (निवेश = output = खोलो(_PATH_TTY, O_RDWR | O_CLOEXEC)) == -1) {
		अगर (flags & RPP_REQUIRE_TTY) {
			त्रुटि_सं = ENOTTY;
			वापस(शून्य);
		}
		निवेश = STDIN_FILENO;
		output = STDERR_FILENO;
	}

	/*
	 * Turn off echo if possible.
	 * If we are using a tty but are not the foreground pgrp this will
	 * generate SIGTTOU, so do it *before* installing the signal handlers.
	 */
	अगर (निवेश != STDIN_FILENO && tcgetattr(निवेश, &oterm) == 0) {
		स_नकल(&term, &oterm, माप(term));
		अगर (!(flags & RPP_ECHO_ON))
			term.c_lflag &= ~(ECHO | ECHONL);
#अगर_घोषित VSTATUS
		अगर (term.c_cc[VSTATUS] != _POSIX_VDISABLE)
			term.c_cc[VSTATUS] = _POSIX_VDISABLE;
#पूर्ण_अगर
		(व्योम)tcsetattr(निवेश, TCSAFLUSH|TCSASOFT, &term);
	} अन्यथा {
		स_रखो(&term, 0, माप(term));
		term.c_lflag |= ECHO;
		स_रखो(&oterm, 0, माप(oterm));
		oterm.c_lflag |= ECHO;
	}

	/*
	 * Catch signals that would otherwise cause the user to end
	 * up with echo turned off in the shell.  Don't worry about
	 * things like SIGXCPU and SIGVTALRM for now.
	 */
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;		/* don't restart system calls */
	sa.sa_handler = handler;
	sigaction(संक_विघ्न, &sa, &saveint);
	sigaction(SIGQUIT, &sa, &savequit);
	sigaction_except_ign(SIGALRM, &sa, &savealrm);
	sigaction_except_ign(SIGHUP, &sa, &savehup);
	sigaction_except_ign(SIGPIPE, &sa, &savepipe);
	sigaction_except_ign(संक_इति, &sa, &saveterm);
	sigaction_except_ign(SIGTSTP, &sa, &savetstp);
	sigaction_except_ign(SIGTTIN, &sa, &savettin);
	sigaction_except_ign(SIGTTOU, &sa, &savettou);

	अगर (!(flags & RPP_STDIN))
		(व्योम)ग_लिखो(output, prompt, म_माप(prompt));
	end = buf + bufsiz - 1;
	p = buf;
	जबतक ((nr = पढ़ो(निवेश, &ch, 1)) == 1 && ch != '\n' && ch != '\r') {
		अगर (p < end) {
			अगर ((flags & RPP_SEVENBIT))
				ch &= 0x7f;
			अगर (है_अक्षर((अचिन्हित अक्षर)ch)) {
				अगर ((flags & RPP_FORCELOWER))
					ch = (अक्षर)छोटे((अचिन्हित अक्षर)ch);
				अगर ((flags & RPP_FORCEUPPER))
					ch = (अक्षर)बड़े((अचिन्हित अक्षर)ch);
			}
			*p++ = ch;
		}
	}
	*p = '\0';
	save_errno = त्रुटि_सं;
	अगर (!(term.c_lflag & ECHO) && !(nr == -1 && त्रुटि_सं == EINTR))
		(व्योम)ग_लिखो(output, "\n", 1);

	/* Restore old terminal settings and signals. */
	अगर (स_भेद(&term, &oterm, माप(term)) != 0) {
		स्थिर पूर्णांक sigttou = signo[SIGTTOU];

		/* Ignore SIGTTOU generated when we are not the fg pgrp. */
		जबतक (tcsetattr(निवेश, TCSAFLUSH|TCSASOFT, &oterm) == -1 &&
		    त्रुटि_सं == EINTR && !signo[SIGTTOU])
			जारी;
		signo[SIGTTOU] = sigttou;
	}
	sigaction(संक_विघ्न, &saveint, शून्य);
	sigaction(SIGQUIT, &savequit, शून्य);
	sigaction_except_ign(SIGALRM, &savealrm, शून्य);
	sigaction_except_ign(SIGHUP, &savehup, शून्य);
	sigaction_except_ign(SIGPIPE, &savepipe, शून्य);
	sigaction_except_ign(संक_इति, &saveterm, शून्य);
	sigaction_except_ign(SIGTSTP, &savetstp, शून्य);
	sigaction_except_ign(SIGTTIN, &savettin, शून्य);
	sigaction_except_ign(SIGTTOU, &savettou, शून्य);
	अगर (निवेश != STDIN_FILENO)
		(व्योम)बंद(निवेश);

	/*
	 * If we were interrupted by a signal, resend it to ourselves
	 * now that we have restored the signal handlers.
	 */
	क्रम (i = 0; i < _NSIG; i++) {
		अगर (signo[i]) {
			समाप्त(getpid(), i);
			चयन (i) {
			हाल SIGTSTP:
			हाल SIGTTIN:
			हाल SIGTTOU:
				need_restart = 1;
			}
		}
	}
	अगर (need_restart)
		जाओ restart;

	अगर (save_errno)
		त्रुटि_सं = save_errno;
	वापस(nr == -1 ? शून्य : buf);
}
DEF_WEAK(readpassphrase);

#अगर 0
अक्षर *
getpass(स्थिर अक्षर *prompt)
{
	अटल अक्षर buf[_PASSWORD_LEN + 1];

	वापस(readpassphrase(prompt, buf, माप(buf), RPP_ECHO_OFF));
}
#पूर्ण_अगर

अटल व्योम handler(पूर्णांक s)
{

	signo[s] = 1;
}
#पूर्ण_अगर /* HAVE_READPASSPHRASE */
