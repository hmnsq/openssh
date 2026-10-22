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

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ HAVE_READPASSPHRASE

#ಅನ್ತರ್ಭಾವ <termios.h>
#ಅನ್ತರ್ಭಾವ <signal.h>
#ಅನ್ತರ್ಭಾವ <ctype.h>
#ಅನ್ತರ್ಭಾವ <fcntl.h>
#ಅನ್ತರ್ಭಾವ <readpassphrase.h>
#ಅನ್ತರ್ಭಾವ <errno.h>
#ಅನ್ತರ್ಭಾವ <string.h>
#ಅನ್ತರ್ಭಾವ <unistd.h>

#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ TCSASOFT
/* If we don't have TCSASOFT define it so that ORing it it below is a no-op. */
# define TCSASOFT 0
#ಆದರೆ_ಅಂತ್ಯ

/* SunOS 4.x which lacks _POSIX_VDISABLE, but has VDISABLE */
#ಆದರೆ !defined(_POSIX_VDISABLE) && defined(VDISABLE)
#  define _POSIX_VDISABLE       VDISABLE
#ಆದರೆ_ಅಂತ್ಯ

ಸ್ಥಿರ ಅಸ್ಥಿರ sig_atomic_t signo[_NSIG];

ಸ್ಥಿರ ಶೂನ್ಯ handler(ಪೂರ್ಣಾಂಕ);

/* Like sigaction(2) but preserves SIG_IGN */
ಸ್ಥಿರ ಶೂನ್ಯ
sigaction_except_ign(ಪೂರ್ಣಾಂಕ signum, ರಚನೆ sigaction *act, ರಚನೆ sigaction *old)
{
	ರಚನೆ sigaction sabuf;

	ಆದರೆ (old == ಖಾಲಿ)
		old = &sabuf;

	(ಶೂನ್ಯ)sigaction(signum, act, old);
	/* Reinstate SIG_IGN; we don't want to override this */
	ಆದರೆ (old->sa_handler == SIG_IGN && act->sa_handler != SIG_IGN)
		(ಶೂನ್ಯ)sigaction(signum, old, ಖಾಲಿ);
}

ಅಕ್ಷರ *
readpassphrase(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *prompt, ಅಕ್ಷರ *buf, ಗಾತ್ರ_t bufsiz, ಪೂರ್ಣಾಂಕ flags)
{
	ssize_t nr;
	ಪೂರ್ಣಾಂಕ ಒಳಹರಿವು, output, save_errno, i, need_restart;
	ಅಕ್ಷರ ch, *p, *ಕೊನೆ;
	ರಚನೆ termios ಪದ, oterm;
	ರಚನೆ sigaction sa, savealrm, saveint, savehup, savequit, saveterm;
	ರಚನೆ sigaction savetstp, savettin, savettou, savepipe;

	/* I suppose we could alloc on demand in this case (XXX). */
	ಆದರೆ (bufsiz == 0) {
		errno = EINVAL;
		ಹಿಂತಿರುಗಿ(ಖಾಲಿ);
	}

restart:
	ಗಾಗಿ (i = 0; i < _NSIG; i++)
		signo[i] = 0;
	nr = -1;
	save_errno = 0;
	need_restart = 0;
	/*
	 * Read and write to /dev/tty if available.  If not, read from
	 * stdin and write to stderr unless a tty is required.
	 */
#ವ್ಯಾಖ್ಯಾನಿತವಾಗದಿದ್ದರೆ O_CLOEXEC
# define O_CLOEXEC 0
#ಆದರೆ_ಅಂತ್ಯ
	ಆದರೆ ((flags & RPP_STDIN) ||
	    (ಒಳಹರಿವು = output = open(_PATH_TTY, O_RDWR | O_CLOEXEC)) == -1) {
		ಆದರೆ (flags & RPP_REQUIRE_TTY) {
			errno = ENOTTY;
			ಹಿಂತಿರುಗಿ(ಖಾಲಿ);
		}
		ಒಳಹರಿವು = STDIN_FILENO;
		output = STDERR_FILENO;
	}

	/*
	 * Turn off echo if possible.
	 * If we are using a tty but are not the foreground pgrp this will
	 * generate SIGTTOU, so do it *before* installing the signal handlers.
	 */
	ಆದರೆ (ಒಳಹರಿವು != STDIN_FILENO && tcgetattr(ಒಳಹರಿವು, &oterm) == 0) {
		ಸ್ಮರಣೆ_ನಕಲು(&ಪದ, &oterm, ಗಾತ್ರ(ಪದ));
		ಆದರೆ (!(flags & RPP_ECHO_ON))
			ಪದ.c_lflag &= ~(ECHO | ECHONL);
#ವ್ಯಾಖ್ಯಾನಿತವಾದರೆ VSTATUS
		ಆದರೆ (ಪದ.c_cc[VSTATUS] != _POSIX_VDISABLE)
			ಪದ.c_cc[VSTATUS] = _POSIX_VDISABLE;
#ಆದರೆ_ಅಂತ್ಯ
		(ಶೂನ್ಯ)tcsetattr(ಒಳಹರಿವು, TCSAFLUSH|TCSASOFT, &ಪದ);
	} ಇಲ್ಲದಿದ್ದರೆ {
		memset(&ಪದ, 0, ಗಾತ್ರ(ಪದ));
		ಪದ.c_lflag |= ECHO;
		memset(&oterm, 0, ಗಾತ್ರ(oterm));
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

	ಆದರೆ (!(flags & RPP_STDIN))
		(ಶೂನ್ಯ)ಲಿಖ(output, prompt, ಅಕ್ಷರಸರಣಿ_ಉದ್ದ(prompt));
	ಕೊನೆ = buf + bufsiz - 1;
	p = buf;
	ಆಗ ((nr = ಪಠ(ಒಳಹರಿವು, &ch, 1)) == 1 && ch != '\n' && ch != '\r') {
		ಆದರೆ (p < ಕೊನೆ) {
			ಆದರೆ ((flags & RPP_SEVENBIT))
				ch &= 0x7f;
			ಆದರೆ (ಅಕ್ಷರವೇ((ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ)ch)) {
				ಆದರೆ ((flags & RPP_FORCELOWER))
					ch = (ಅಕ್ಷರ)tolower((ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ)ch);
				ಆದರೆ ((flags & RPP_FORCEUPPER))
					ch = (ಅಕ್ಷರ)ದೊಡ್ಡ_ಅಕ್ಷರ((ಚಿಹ್ನೆರಹಿತ ಅಕ್ಷರ)ch);
			}
			*p++ = ch;
		}
	}
	*p = '\0';
	save_errno = errno;
	ಆದರೆ (!(ಪದ.c_lflag & ECHO) && !(nr == -1 && errno == EINTR))
		(ಶೂನ್ಯ)ಲಿಖ(output, "\n", 1);

	/* Restore old terminal settings and signals. */
	ಆದರೆ (memcmp(&ಪದ, &oterm, ಗಾತ್ರ(ಪದ)) != 0) {
		ಸ್ಥಿರಾಂಕ ಪೂರ್ಣಾಂಕ sigttou = signo[SIGTTOU];

		/* Ignore SIGTTOU generated when we are not the fg pgrp. */
		ಆಗ (tcsetattr(ಒಳಹರಿವು, TCSAFLUSH|TCSASOFT, &oterm) == -1 &&
		    errno == EINTR && !signo[SIGTTOU])
			ಮುಂದುವರಿ;
		signo[SIGTTOU] = sigttou;
	}
	sigaction(SIGINT, &saveint, ಖಾಲಿ);
	sigaction(SIGQUIT, &savequit, ಖಾಲಿ);
	sigaction_except_ign(SIGALRM, &savealrm, ಖಾಲಿ);
	sigaction_except_ign(SIGHUP, &savehup, ಖಾಲಿ);
	sigaction_except_ign(SIGPIPE, &savepipe, ಖಾಲಿ);
	sigaction_except_ign(SIGTERM, &saveterm, ಖಾಲಿ);
	sigaction_except_ign(SIGTSTP, &savetstp, ಖಾಲಿ);
	sigaction_except_ign(SIGTTIN, &savettin, ಖಾಲಿ);
	sigaction_except_ign(SIGTTOU, &savettou, ಖಾಲಿ);
	ಆದರೆ (ಒಳಹರಿವು != STDIN_FILENO)
		(ಶೂನ್ಯ)close(ಒಳಹರಿವು);

	/*
	 * If we were interrupted by a signal, resend it to ourselves
	 * now that we have restored the signal handlers.
	 */
	ಗಾಗಿ (i = 0; i < _NSIG; i++) {
		ಆದರೆ (signo[i]) {
			kill(getpid(), i);
			ಆಯ್ಕೆ (i) {
			ಸ್ಥಿತಿ SIGTSTP:
			ಸ್ಥಿತಿ SIGTTIN:
			ಸ್ಥಿತಿ SIGTTOU:
				need_restart = 1;
			}
		}
	}
	ಆದರೆ (need_restart)
		ಹೋಗು restart;

	ಆದರೆ (save_errno)
		errno = save_errno;
	ಹಿಂತಿರುಗಿ(nr == -1 ? ಖಾಲಿ : buf);
}
DEF_WEAK(readpassphrase);

#ಆದರೆ 0
ಅಕ್ಷರ *
getpass(ಸ್ಥಿರಾಂಕ ಅಕ್ಷರ *prompt)
{
	ಸ್ಥಿರ ಅಕ್ಷರ buf[_PASSWORD_LEN + 1];

	ಹಿಂತಿರುಗಿ(readpassphrase(prompt, buf, ಗಾತ್ರ(buf), RPP_ECHO_OFF));
}
#ಆದರೆ_ಅಂತ್ಯ

ಸ್ಥಿರ ಶೂನ್ಯ handler(ಪೂರ್ಣಾಂಕ s)
{

	signo[s] = 1;
}
#ಆದರೆ_ಅಂತ್ಯ /* HAVE_READPASSPHRASE */
