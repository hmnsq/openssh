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

#अन्तर्भाव "includes.h"

#ifndef HAVE_READPASSPHRASE

#अन्तर्भाव <termios.h>
#अन्तर्भाव <signal.h>
#अन्तर्भाव <ctype.h>
#अन्तर्भाव <fcntl.h>
#अन्तर्भाव <readpassphrase.h>
#अन्तर्भाव <errno.h>
#अन्तर्भाव <string.h>
#अन्तर्भाव <unistd.h>

#ifndef TCSASOFT
/* If we don't have TCSASOFT define it so that ORing it it below is a no-op. */
# define TCSASOFT 0
#endif

/* SunOS 4.x which lacks _POSIX_VDISABLE, but has VDISABLE */
#जर !defined(_POSIX_VDISABLE) && defined(VDISABLE)
#  define _POSIX_VDISABLE       VDISABLE
#endif

स्थिर अस्थिर संक_पूर्ण_प्रकार signo[_NSIG];

स्थिर शून्य handler(पूर्णांक);

/* Like sigaction(2) but preserves SIG_IGN */
स्थिर शून्य
sigaction_except_ign(पूर्णांक signum, संरचना sigaction *act, संरचना sigaction *old)
{
	संरचना sigaction sabuf;

	जर (old == रिक्त)
		old = &sabuf;

	(शून्य)sigaction(signum, act, old);
	/* Reinstate SIG_IGN; we don't want to override this */
	जर (old->sa_handler == संक_छोड़ो && act->sa_handler != संक_छोड़ो)
		(शून्य)sigaction(signum, old, रिक्त);
}

अक्षर *
readpassphrase(स्थिरांक अक्षर *prompt, अक्षर *buf, माप_प्रकार bufsiz, पूर्णांक flags)
{
	ssize_t nr;
	पूर्णांक आदान, output, save_errno, i, need_restart;
	अक्षर ch, *p, *end;
	संरचना termios term, oterm;
	संरचना sigaction sa, savealrm, saveint, savehup, savequit, saveterm;
	संरचना sigaction savetstp, savettin, savettou, savepipe;

	/* I suppose we could alloc on demand in this case (XXX). */
	जर (bufsiz == 0) {
		त्रुटि_सं = EINVAL;
		परत(रिक्त);
	}

restart:
	साठी (i = 0; i < _NSIG; i++)
		signo[i] = 0;
	nr = -1;
	save_errno = 0;
	need_restart = 0;
	/*
	 * Read and write to /dev/tty if available.  If not, read from
	 * stdin and write to stderr unless a tty is required.
	 */
#ifndef O_CLOEXEC
# define O_CLOEXEC 0
#endif
	जर ((flags & RPP_STDIN) ||
	    (आदान = output = खोलो(_PATH_TTY, O_RDWR | O_CLOEXEC)) == -1) {
		जर (flags & RPP_REQUIRE_TTY) {
			त्रुटि_सं = ENOTTY;
			परत(रिक्त);
		}
		आदान = STDIN_FILENO;
		output = STDERR_FILENO;
	}

	/*
	 * Turn off echo if possible.
	 * If we are using a tty but are not the foreground pgrp this will
	 * generate SIGTTOU, so do it *before* installing the signal handlers.
	 */
	जर (आदान != STDIN_FILENO && tcgetattr(आदान, &oterm) == 0) {
		स_नकल(&term, &oterm, आकार(term));
		जर (!(flags & RPP_ECHO_ON))
			term.c_lflag &= ~(ECHO | ECHONL);
#ifdef VSTATUS
		जर (term.c_cc[VSTATUS] != _POSIX_VDISABLE)
			term.c_cc[VSTATUS] = _POSIX_VDISABLE;
#endif
		(शून्य)tcsetattr(आदान, TCSAFLUSH|TCSASOFT, &term);
	} अन्यथा {
		स_रखो(&term, 0, आकार(term));
		term.c_lflag |= ECHO;
		स_रखो(&oterm, 0, आकार(oterm));
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

	जर (!(flags & RPP_STDIN))
		(शून्य)लिख(output, prompt, म_माप(prompt));
	end = buf + bufsiz - 1;
	p = buf;
	पर्यंत ((nr = पठ(आदान, &ch, 1)) == 1 && ch != '\n' && ch != '\r') {
		जर (p < end) {
			जर ((flags & RPP_SEVENBIT))
				ch &= 0x7f;
			जर (है_अक्षर((अचिन्हित अक्षर)ch)) {
				जर ((flags & RPP_FORCELOWER))
					ch = (अक्षर)छोटे((अचिन्हित अक्षर)ch);
				जर ((flags & RPP_FORCEUPPER))
					ch = (अक्षर)बड़े((अचिन्हित अक्षर)ch);
			}
			*p++ = ch;
		}
	}
	*p = '\0';
	save_errno = त्रुटि_सं;
	जर (!(term.c_lflag & ECHO) && !(nr == -1 && त्रुटि_सं == EINTR))
		(शून्य)लिख(output, "\n", 1);

	/* Restore old terminal settings and signals. */
	जर (स_भेद(&term, &oterm, आकार(term)) != 0) {
		स्थिरांक पूर्णांक sigttou = signo[SIGTTOU];

		/* Ignore SIGTTOU generated when we are not the fg pgrp. */
		पर्यंत (tcsetattr(आदान, TCSAFLUSH|TCSASOFT, &oterm) == -1 &&
		    त्रुटि_सं == EINTR && !signo[SIGTTOU])
			सुरूठेवा;
		signo[SIGTTOU] = sigttou;
	}
	sigaction(संक_विघ्न, &saveint, रिक्त);
	sigaction(SIGQUIT, &savequit, रिक्त);
	sigaction_except_ign(SIGALRM, &savealrm, रिक्त);
	sigaction_except_ign(SIGHUP, &savehup, रिक्त);
	sigaction_except_ign(SIGPIPE, &savepipe, रिक्त);
	sigaction_except_ign(संक_इति, &saveterm, रिक्त);
	sigaction_except_ign(SIGTSTP, &savetstp, रिक्त);
	sigaction_except_ign(SIGTTIN, &savettin, रिक्त);
	sigaction_except_ign(SIGTTOU, &savettou, रिक्त);
	जर (आदान != STDIN_FILENO)
		(शून्य)बंद(आदान);

	/*
	 * If we were interrupted by a signal, resend it to ourselves
	 * now that we have restored the signal handlers.
	 */
	साठी (i = 0; i < _NSIG; i++) {
		जर (signo[i]) {
			समाप्त(getpid(), i);
			निवड (i) {
			स्थिती SIGTSTP:
			स्थिती SIGTTIN:
			स्थिती SIGTTOU:
				need_restart = 1;
			}
		}
	}
	जर (need_restart)
		जा restart;

	जर (save_errno)
		त्रुटि_सं = save_errno;
	परत(nr == -1 ? रिक्त : buf);
}
DEF_WEAK(readpassphrase);

#जर 0
अक्षर *
getpass(स्थिरांक अक्षर *prompt)
{
	स्थिर अक्षर buf[_PASSWORD_LEN + 1];

	परत(readpassphrase(prompt, buf, आकार(buf), RPP_ECHO_OFF));
}
#endif

स्थिर शून्य handler(पूर्णांक s)
{

	signo[s] = 1;
}
#endif /* HAVE_READPASSPHRASE */
