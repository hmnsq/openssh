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
#यदि !defined(_POSIX_VDISABLE) && defined(VDISABLE)
#  define _POSIX_VDISABLE       VDISABLE
#endif

स्थिर चञ्चल sig_atomic_t signo[_NSIG];

स्थिर शून्य handler(पूर्णाङ्क);

/* Like sigaction(2) but preserves SIG_IGN */
स्थिर शून्य
sigaction_except_ign(पूर्णाङ्क signum, संरचना sigaction *act, संरचना sigaction *old)
{
	संरचना sigaction sabuf;

	यदि (old == रिक्त)
		old = &sabuf;

	(शून्य)sigaction(signum, act, old);
	/* Reinstate SIG_IGN; we don't want to override this */
	यदि (old->sa_handler == SIG_IGN && act->sa_handler != SIG_IGN)
		(शून्य)sigaction(signum, old, रिक्त);
}

वर्ण *
readpassphrase(ध्रुव वर्ण *prompt, वर्ण *buf, size_t bufsiz, पूर्णाङ्क flags)
{
	ssize_t nr;
	पूर्णाङ्क निवेश, output, save_errno, i, need_restart;
	वर्ण ch, *p, *end;
	संरचना termios term, oterm;
	संरचना sigaction sa, savealrm, saveint, savehup, savequit, saveterm;
	संरचना sigaction savetstp, savettin, savettou, savepipe;

	/* I suppose we could alloc on demand in this case (XXX). */
	यदि (bufsiz == 0) {
		errno = EINVAL;
		प्रत्यागम(रिक्त);
	}

restart:
	प्रति (i = 0; i < _NSIG; i++)
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
	यदि ((flags & RPP_STDIN) ||
	    (निवेश = output = open(_PATH_TTY, O_RDWR | O_CLOEXEC)) == -1) {
		यदि (flags & RPP_REQUIRE_TTY) {
			errno = ENOTTY;
			प्रत्यागम(रिक्त);
		}
		निवेश = STDIN_FILENO;
		output = STDERR_FILENO;
	}

	/*
	 * Turn off echo if possible.
	 * If we are using a tty but are not the foreground pgrp this will
	 * generate SIGTTOU, so do it *before* installing the signal handlers.
	 */
	यदि (निवेश != STDIN_FILENO && tcgetattr(निवेश, &oterm) == 0) {
		memcpy(&term, &oterm, परिमाण(term));
		यदि (!(flags & RPP_ECHO_ON))
			term.c_lflag &= ~(ECHO | ECHONL);
#ifdef VSTATUS
		यदि (term.c_cc[VSTATUS] != _POSIX_VDISABLE)
			term.c_cc[VSTATUS] = _POSIX_VDISABLE;
#endif
		(शून्य)tcsetattr(निवेश, TCSAFLUSH|TCSASOFT, &term);
	} अन्यथा {
		memset(&term, 0, परिमाण(term));
		term.c_lflag |= ECHO;
		memset(&oterm, 0, परिमाण(oterm));
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
	sigaction(SIGINT, &sa, &saveint);
	sigaction(SIGQUIT, &sa, &savequit);
	sigaction_except_ign(SIGALRM, &sa, &savealrm);
	sigaction_except_ign(SIGHUP, &sa, &savehup);
	sigaction_except_ign(SIGPIPE, &sa, &savepipe);
	sigaction_except_ign(SIGTERM, &sa, &saveterm);
	sigaction_except_ign(SIGTSTP, &sa, &savetstp);
	sigaction_except_ign(SIGTTIN, &sa, &savettin);
	sigaction_except_ign(SIGTTOU, &sa, &savettou);

	यदि (!(flags & RPP_STDIN))
		(शून्य)लिख(output, prompt, strlen(prompt));
	end = buf + bufsiz - 1;
	p = buf;
	यावत् ((nr = पठ(निवेश, &ch, 1)) == 1 && ch != '\n' && ch != '\r') {
		यदि (p < end) {
			यदि ((flags & RPP_SEVENBIT))
				ch &= 0x7f;
			यदि (isalpha((unsigned वर्ण)ch)) {
				यदि ((flags & RPP_FORCELOWER))
					ch = (वर्ण)tolower((unsigned वर्ण)ch);
				यदि ((flags & RPP_FORCEUPPER))
					ch = (वर्ण)toupper((unsigned वर्ण)ch);
			}
			*p++ = ch;
		}
	}
	*p = '\0';
	save_errno = errno;
	यदि (!(term.c_lflag & ECHO) && !(nr == -1 && errno == EINTR))
		(शून्य)लिख(output, "\n", 1);

	/* Restore old terminal settings and signals. */
	यदि (memcmp(&term, &oterm, परिमाण(term)) != 0) {
		ध्रुव पूर्णाङ्क sigttou = signo[SIGTTOU];

		/* Ignore SIGTTOU generated when we are not the fg pgrp. */
		यावत् (tcsetattr(निवेश, TCSAFLUSH|TCSASOFT, &oterm) == -1 &&
		    errno == EINTR && !signo[SIGTTOU])
			अनुवर्त;
		signo[SIGTTOU] = sigttou;
	}
	sigaction(SIGINT, &saveint, रिक्त);
	sigaction(SIGQUIT, &savequit, रिक्त);
	sigaction_except_ign(SIGALRM, &savealrm, रिक्त);
	sigaction_except_ign(SIGHUP, &savehup, रिक्त);
	sigaction_except_ign(SIGPIPE, &savepipe, रिक्त);
	sigaction_except_ign(SIGTERM, &saveterm, रिक्त);
	sigaction_except_ign(SIGTSTP, &savetstp, रिक्त);
	sigaction_except_ign(SIGTTIN, &savettin, रिक्त);
	sigaction_except_ign(SIGTTOU, &savettou, रिक्त);
	यदि (निवेश != STDIN_FILENO)
		(शून्य)close(निवेश);

	/*
	 * If we were interrupted by a signal, resend it to ourselves
	 * now that we have restored the signal handlers.
	 */
	प्रति (i = 0; i < _NSIG; i++) {
		यदि (signo[i]) {
			kill(getpid(), i);
			विकल्प (i) {
			पक्ष SIGTSTP:
			पक्ष SIGTTIN:
			पक्ष SIGTTOU:
				need_restart = 1;
			}
		}
	}
	यदि (need_restart)
		गच्छ restart;

	यदि (save_errno)
		errno = save_errno;
	प्रत्यागम(nr == -1 ? रिक्त : buf);
}
DEF_WEAK(readpassphrase);

#यदि 0
वर्ण *
getpass(ध्रुव वर्ण *prompt)
{
	स्थिर वर्ण buf[_PASSWORD_LEN + 1];

	प्रत्यागम(readpassphrase(prompt, buf, परिमाण(buf), RPP_ECHO_OFF));
}
#endif

स्थिर शून्य handler(पूर्णाङ्क s)
{

	signo[s] = 1;
}
#endif /* HAVE_READPASSPHRASE */
