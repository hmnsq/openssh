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

#అన్తర్భావ "includes.h"

#నిర్వచితం_కాకపోతే HAVE_READPASSPHRASE

#అన్తర్భావ <termios.h>
#అన్తర్భావ <signal.h>
#అన్తర్భావ <ctype.h>
#అన్తర్భావ <fcntl.h>
#అన్తర్భావ <readpassphrase.h>
#అన్తర్భావ <errno.h>
#అన్తర్భావ <string.h>
#అన్తర్భావ <unistd.h>

#నిర్వచితం_కాకపోతే TCSASOFT
/* If we don't have TCSASOFT define it so that ORing it it below is a no-op. */
# define TCSASOFT 0
#అయితే_ముగింపు

/* SunOS 4.x which lacks _POSIX_VDISABLE, but has VDISABLE */
#ఒకవేళ !defined(_POSIX_VDISABLE) && defined(VDISABLE)
#  define _POSIX_VDISABLE       VDISABLE
#అయితే_ముగింపు

స్థిర అస్థిర sig_atomic_t signo[_NSIG];

స్థిర శూన్య handler(పూర్ణాంకం);

/* Like sigaction(2) but preserves SIG_IGN */
స్థిర శూన్య
sigaction_except_ign(పూర్ణాంకం signum, నిర్మాణం sigaction *act, నిర్మాణం sigaction *old)
{
	నిర్మాణం sigaction sabuf;

	ఒకవేళ (old == ఖాళీ)
		old = &sabuf;

	(శూన్య)sigaction(signum, act, old);
	/* Reinstate SIG_IGN; we don't want to override this */
	ఒకవేళ (old->sa_handler == SIG_IGN && act->sa_handler != SIG_IGN)
		(శూన్య)sigaction(signum, old, ఖాళీ);
}

అక్షరం *
readpassphrase(స్థిరరాశి అక్షరం *prompt, అక్షరం *buf, కొలత_t bufsiz, పూర్ణాంకం flags)
{
	ssize_t nr;
	పూర్ణాంకం ఆదానం, output, save_errno, i, need_restart;
	అక్షరం ch, *p, *చివర;
	నిర్మాణం termios పదం, oterm;
	నిర్మాణం sigaction sa, savealrm, saveint, savehup, savequit, saveterm;
	నిర్మాణం sigaction savetstp, savettin, savettou, savepipe;

	/* I suppose we could alloc on demand in this case (XXX). */
	ఒకవేళ (bufsiz == 0) {
		errno = EINVAL;
		తిరిగి(ఖాళీ);
	}

restart:
	కొరకు (i = 0; i < _NSIG; i++)
		signo[i] = 0;
	nr = -1;
	save_errno = 0;
	need_restart = 0;
	/*
	 * Read and write to /dev/tty if available.  If not, read from
	 * stdin and write to stderr unless a tty is required.
	 */
#నిర్వచితం_కాకపోతే O_CLOEXEC
# define O_CLOEXEC 0
#అయితే_ముగింపు
	ఒకవేళ ((flags & RPP_STDIN) ||
	    (ఆదానం = output = open(_PATH_TTY, O_RDWR | O_CLOEXEC)) == -1) {
		ఒకవేళ (flags & RPP_REQUIRE_TTY) {
			errno = ENOTTY;
			తిరిగి(ఖాళీ);
		}
		ఆదానం = STDIN_FILENO;
		output = STDERR_FILENO;
	}

	/*
	 * Turn off echo if possible.
	 * If we are using a tty but are not the foreground pgrp this will
	 * generate SIGTTOU, so do it *before* installing the signal handlers.
	 */
	ఒకవేళ (ఆదానం != STDIN_FILENO && tcgetattr(ఆదానం, &oterm) == 0) {
		జ్ఞాపకం_నకలు(&పదం, &oterm, పరిమాణం(పదం));
		ఒకవేళ (!(flags & RPP_ECHO_ON))
			పదం.c_lflag &= ~(ECHO | ECHONL);
#నిర్వచితమైతే VSTATUS
		ఒకవేళ (పదం.c_cc[VSTATUS] != _POSIX_VDISABLE)
			పదం.c_cc[VSTATUS] = _POSIX_VDISABLE;
#అయితే_ముగింపు
		(శూన్య)tcsetattr(ఆదానం, TCSAFLUSH|TCSASOFT, &పదం);
	} లేకపోతే {
		memset(&పదం, 0, పరిమాణం(పదం));
		పదం.c_lflag |= ECHO;
		memset(&oterm, 0, పరిమాణం(oterm));
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

	ఒకవేళ (!(flags & RPP_STDIN))
		(శూన్య)లిఖ(output, prompt, అక్షరశ్రేణి_పొడవు(prompt));
	చివర = buf + bufsiz - 1;
	p = buf;
	అయితే ((nr = పఠ(ఆదానం, &ch, 1)) == 1 && ch != '\n' && ch != '\r') {
		ఒకవేళ (p < చివర) {
			ఒకవేళ ((flags & RPP_SEVENBIT))
				ch &= 0x7f;
			ఒకవేళ (అక్షరమా((గుర్తులేని అక్షరం)ch)) {
				ఒకవేళ ((flags & RPP_FORCELOWER))
					ch = (అక్షరం)tolower((గుర్తులేని అక్షరం)ch);
				ఒకవేళ ((flags & RPP_FORCEUPPER))
					ch = (అక్షరం)పెద్ద_అక్షరం((గుర్తులేని అక్షరం)ch);
			}
			*p++ = ch;
		}
	}
	*p = '\0';
	save_errno = errno;
	ఒకవేళ (!(పదం.c_lflag & ECHO) && !(nr == -1 && errno == EINTR))
		(శూన్య)లిఖ(output, "\n", 1);

	/* Restore old terminal settings and signals. */
	ఒకవేళ (memcmp(&పదం, &oterm, పరిమాణం(పదం)) != 0) {
		స్థిరరాశి పూర్ణాంకం sigttou = signo[SIGTTOU];

		/* Ignore SIGTTOU generated when we are not the fg pgrp. */
		అయితే (tcsetattr(ఆదానం, TCSAFLUSH|TCSASOFT, &oterm) == -1 &&
		    errno == EINTR && !signo[SIGTTOU])
			కొనసాగు;
		signo[SIGTTOU] = sigttou;
	}
	sigaction(SIGINT, &saveint, ఖాళీ);
	sigaction(SIGQUIT, &savequit, ఖాళీ);
	sigaction_except_ign(SIGALRM, &savealrm, ఖాళీ);
	sigaction_except_ign(SIGHUP, &savehup, ఖాళీ);
	sigaction_except_ign(SIGPIPE, &savepipe, ఖాళీ);
	sigaction_except_ign(SIGTERM, &saveterm, ఖాళీ);
	sigaction_except_ign(SIGTSTP, &savetstp, ఖాళీ);
	sigaction_except_ign(SIGTTIN, &savettin, ఖాళీ);
	sigaction_except_ign(SIGTTOU, &savettou, ఖాళీ);
	ఒకవేళ (ఆదానం != STDIN_FILENO)
		(శూన్య)close(ఆదానం);

	/*
	 * If we were interrupted by a signal, resend it to ourselves
	 * now that we have restored the signal handlers.
	 */
	కొరకు (i = 0; i < _NSIG; i++) {
		ఒకవేళ (signo[i]) {
			kill(getpid(), i);
			ఎంపిక (i) {
			స్థితి SIGTSTP:
			స్థితి SIGTTIN:
			స్థితి SIGTTOU:
				need_restart = 1;
			}
		}
	}
	ఒకవేళ (need_restart)
		వెళ్ళు restart;

	ఒకవేళ (save_errno)
		errno = save_errno;
	తిరిగి(nr == -1 ? ఖాళీ : buf);
}
DEF_WEAK(readpassphrase);

#ఒకవేళ 0
అక్షరం *
getpass(స్థిరరాశి అక్షరం *prompt)
{
	స్థిర అక్షరం buf[_PASSWORD_LEN + 1];

	తిరిగి(readpassphrase(prompt, buf, పరిమాణం(buf), RPP_ECHO_OFF));
}
#అయితే_ముగింపు

స్థిర శూన్య handler(పూర్ణాంకం s)
{

	signo[s] = 1;
}
#అయితే_ముగింపు /* HAVE_READPASSPHRASE */
