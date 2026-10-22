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

#ಅನ್ತರ್ಭಾವ "includes.h"

#ifndef HAVE_READPASSPHRASE

#ಅನ್ತರ್ಭಾವ <termios.h>
#ಅನ್ತರ್ಭಾವ <signal.h>
#ಅನ್ತರ್ಭಾವ <ctype.h>
#ಅನ್ತರ್ಭಾವ <fcntl.h>
#ಅನ್ತರ್ಭಾವ <readpassphrase.h>
#ಅನ್ತರ್ಭಾವ <errno.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <unistd.h>

#ifndef TCSASOFT
/* If we don't have TCSASOFT define it so that ORing it it below is a no-op. */
# define TCSASOFT 0
#endif

/* SunOS 4.x which lacks _POSIX_VDISABLE, but has VDISABLE */
#ಯದಿ !defined(_POSIX_VDISABLE) && defined(VDISABLE)
#  define _POSIX_VDISABLE       VDISABLE
#endif

ಸ್ಥಿರ ಚಞ್ಚಲ sig_atomic_t signo[_NSIG];

ಸ್ಥಿರ ಶೂನ್ಯ handler(ಪೂರ್ಣಾಙ್ಕ);

/* Like sigaction(2) but preserves SIG_IGN */
ಸ್ಥಿರ ಶೂನ್ಯ
sigaction_except_ign(ಪೂರ್ಣಾಙ್ಕ signum, ಸಂರಚನಾ sigaction *act, ಸಂರಚನಾ sigaction *old)
{
	ಸಂರಚನಾ sigaction sabuf;

	ಯದಿ (old == ರಿಕ್ತ)
		old = &sabuf;

	(ಶೂನ್ಯ)sigaction(signum, act, old);
	/* Reinstate SIG_IGN; we don't want to override this */
	ಯದಿ (old->sa_handler == SIG_IGN && act->sa_handler != SIG_IGN)
		(ಶೂನ್ಯ)sigaction(signum, old, ರಿಕ್ತ);
}

ವರ್ಣ *
readpassphrase(ಧ್ರುವ ವರ್ಣ *prompt, ವರ್ಣ *buf, size_t bufsiz, ಪೂರ್ಣಾಙ್ಕ flags)
{
	ssize_t nr;
	ಪೂರ್ಣಾಙ್ಕ ಒಳಹರಿವು, output, save_errno, i, need_restart;
	ವರ್ಣ ch, *p, *end;
	ಸಂರಚನಾ termios term, oterm;
	ಸಂರಚನಾ sigaction sa, savealrm, saveint, savehup, savequit, saveterm;
	ಸಂರಚನಾ sigaction savetstp, savettin, savettou, savepipe;

	/* I suppose we could alloc on demand in this case (XXX). */
	ಯದಿ (bufsiz == 0) {
		errno = EINVAL;
		ಪ್ರತ್ಯಾಗಮ(ರಿಕ್ತ);
	}

restart:
	ಪ್ರತಿ (i = 0; i < _NSIG; i++)
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
	ಯದಿ ((flags & RPP_STDIN) ||
	    (ಒಳಹರಿವು = output = open(_PATH_TTY, O_RDWR | O_CLOEXEC)) == -1) {
		ಯದಿ (flags & RPP_REQUIRE_TTY) {
			errno = ENOTTY;
			ಪ್ರತ್ಯಾಗಮ(ರಿಕ್ತ);
		}
		ಒಳಹರಿವು = STDIN_FILENO;
		output = STDERR_FILENO;
	}

	/*
	 * Turn off echo if possible.
	 * If we are using a tty but are not the foreground pgrp this will
	 * generate SIGTTOU, so do it *before* installing the signal handlers.
	 */
	ಯದಿ (ಒಳಹರಿವು != STDIN_FILENO && tcgetattr(ಒಳಹರಿವು, &oterm) == 0) {
		memcpy(&term, &oterm, ಪರಿಮಾಣ(term));
		ಯದಿ (!(flags & RPP_ECHO_ON))
			term.c_lflag &= ~(ECHO | ECHONL);
#ifdef VSTATUS
		ಯದಿ (term.c_cc[VSTATUS] != _POSIX_VDISABLE)
			term.c_cc[VSTATUS] = _POSIX_VDISABLE;
#endif
		(ಶೂನ್ಯ)tcsetattr(ಒಳಹರಿವು, TCSAFLUSH|TCSASOFT, &term);
	} ಅನ್ಯಥಾ {
		memset(&term, 0, ಪರಿಮಾಣ(term));
		term.c_lflag |= ECHO;
		memset(&oterm, 0, ಪರಿಮಾಣ(oterm));
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

	ಯದಿ (!(flags & RPP_STDIN))
		(ಶೂನ್ಯ)ಲಿಖ(output, prompt, strlen(prompt));
	end = buf + bufsiz - 1;
	p = buf;
	ಯಾವತ್ ((nr = ಪಠ(ಒಳಹರಿವು, &ch, 1)) == 1 && ch != '\n' && ch != '\r') {
		ಯದಿ (p < end) {
			ಯದಿ ((flags & RPP_SEVENBIT))
				ch &= 0x7f;
			ಯದಿ (isalpha((unsigned ವರ್ಣ)ch)) {
				ಯದಿ ((flags & RPP_FORCELOWER))
					ch = (ವರ್ಣ)tolower((unsigned ವರ್ಣ)ch);
				ಯದಿ ((flags & RPP_FORCEUPPER))
					ch = (ವರ್ಣ)toupper((unsigned ವರ್ಣ)ch);
			}
			*p++ = ch;
		}
	}
	*p = '\0';
	save_errno = errno;
	ಯದಿ (!(term.c_lflag & ECHO) && !(nr == -1 && errno == EINTR))
		(ಶೂನ್ಯ)ಲಿಖ(output, "\n", 1);

	/* Restore old terminal settings and signals. */
	ಯದಿ (memcmp(&term, &oterm, ಪರಿಮಾಣ(term)) != 0) {
		ಧ್ರುವ ಪೂರ್ಣಾಙ್ಕ sigttou = signo[SIGTTOU];

		/* Ignore SIGTTOU generated when we are not the fg pgrp. */
		ಯಾವತ್ (tcsetattr(ಒಳಹರಿವು, TCSAFLUSH|TCSASOFT, &oterm) == -1 &&
		    errno == EINTR && !signo[SIGTTOU])
			ಅನುವರ್ತ;
		signo[SIGTTOU] = sigttou;
	}
	sigaction(SIGINT, &saveint, ರಿಕ್ತ);
	sigaction(SIGQUIT, &savequit, ರಿಕ್ತ);
	sigaction_except_ign(SIGALRM, &savealrm, ರಿಕ್ತ);
	sigaction_except_ign(SIGHUP, &savehup, ರಿಕ್ತ);
	sigaction_except_ign(SIGPIPE, &savepipe, ರಿಕ್ತ);
	sigaction_except_ign(SIGTERM, &saveterm, ರಿಕ್ತ);
	sigaction_except_ign(SIGTSTP, &savetstp, ರಿಕ್ತ);
	sigaction_except_ign(SIGTTIN, &savettin, ರಿಕ್ತ);
	sigaction_except_ign(SIGTTOU, &savettou, ರಿಕ್ತ);
	ಯದಿ (ಒಳಹರಿವು != STDIN_FILENO)
		(ಶೂನ್ಯ)close(ಒಳಹರಿವು);

	/*
	 * If we were interrupted by a signal, resend it to ourselves
	 * now that we have restored the signal handlers.
	 */
	ಪ್ರತಿ (i = 0; i < _NSIG; i++) {
		ಯದಿ (signo[i]) {
			kill(getpid(), i);
			ವಿಕಲ್ಪ (i) {
			ಪಕ್ಷ SIGTSTP:
			ಪಕ್ಷ SIGTTIN:
			ಪಕ್ಷ SIGTTOU:
				need_restart = 1;
			}
		}
	}
	ಯದಿ (need_restart)
		ಗಚ್ಛ restart;

	ಯದಿ (save_errno)
		errno = save_errno;
	ಪ್ರತ್ಯಾಗಮ(nr == -1 ? ರಿಕ್ತ : buf);
}
DEF_WEAK(readpassphrase);

#ಯದಿ 0
ವರ್ಣ *
getpass(ಧ್ರುವ ವರ್ಣ *prompt)
{
	ಸ್ಥಿರ ವರ್ಣ buf[_PASSWORD_LEN + 1];

	ಪ್ರತ್ಯಾಗಮ(readpassphrase(prompt, buf, ಪರಿಮಾಣ(buf), RPP_ECHO_OFF));
}
#endif

ಸ್ಥಿರ ಶೂನ್ಯ handler(ಪೂರ್ಣಾಙ್ಕ s)
{

	signo[s] = 1;
}
#endif /* HAVE_READPASSPHRASE */
