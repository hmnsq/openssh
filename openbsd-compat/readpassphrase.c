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

#அந்தர்பாவ "includes.h"

#ifndef HAVE_READPASSPHRASE

#அந்தர்பாவ <termios.h>
#அந்தர்பாவ <signal.h>
#அந்தர்பாவ <ctype.h>
#அந்தர்பாவ <fcntl.h>
#அந்தர்பாவ <readpassphrase.h>
#அந்தர்பாவ <errno.h>
#அந்தர்பாவ <string.h>
#அந்தர்பாவ <unistd.h>

#ifndef TCSASOFT
/* If we don't have TCSASOFT define it so that ORing it it below is a no-op. */
# define TCSASOFT 0
#endif

/* SunOS 4.x which lacks _POSIX_VDISABLE, but has VDISABLE */
#எனில் !defined(_POSIX_VDISABLE) && defined(VDISABLE)
#  define _POSIX_VDISABLE       VDISABLE
#endif

நிலையான நிலையற்ற sig_atomic_t signo[_NSIG];

நிலையான வெறுமை handler(முழு);

/* Like sigaction(2) but preserves SIG_IGN */
நிலையான வெறுமை
sigaction_except_ign(முழு signum, கட்டமைப்பு sigaction *act, கட்டமைப்பு sigaction *old)
{
	கட்டமைப்பு sigaction sabuf;

	எனில் (old == வெற்று)
		old = &sabuf;

	(வெறுமை)sigaction(signum, act, old);
	/* Reinstate SIG_IGN; we don't want to override this */
	எனில் (old->sa_handler == SIG_IGN && act->sa_handler != SIG_IGN)
		(வெறுமை)sigaction(signum, old, வெற்று);
}

எழுத்து *
readpassphrase(மாறிலி எழுத்து *prompt, எழுத்து *buf, size_t bufsiz, முழு flags)
{
	ssize_t nr;
	முழு உள்ளீடு, output, save_errno, i, need_restart;
	எழுத்து ch, *p, *end;
	கட்டமைப்பு termios term, oterm;
	கட்டமைப்பு sigaction sa, savealrm, saveint, savehup, savequit, saveterm;
	கட்டமைப்பு sigaction savetstp, savettin, savettou, savepipe;

	/* I suppose we could alloc on demand in this case (XXX). */
	எனில் (bufsiz == 0) {
		errno = EINVAL;
		திரும்பு(வெற்று);
	}

restart:
	க்கு (i = 0; i < _NSIG; i++)
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
	எனில் ((flags & RPP_STDIN) ||
	    (உள்ளீடு = output = open(_PATH_TTY, O_RDWR | O_CLOEXEC)) == -1) {
		எனில் (flags & RPP_REQUIRE_TTY) {
			errno = ENOTTY;
			திரும்பு(வெற்று);
		}
		உள்ளீடு = STDIN_FILENO;
		output = STDERR_FILENO;
	}

	/*
	 * Turn off echo if possible.
	 * If we are using a tty but are not the foreground pgrp this will
	 * generate SIGTTOU, so do it *before* installing the signal handlers.
	 */
	எனில் (உள்ளீடு != STDIN_FILENO && tcgetattr(உள்ளீடு, &oterm) == 0) {
		memcpy(&term, &oterm, அளவு(term));
		எனில் (!(flags & RPP_ECHO_ON))
			term.c_lflag &= ~(ECHO | ECHONL);
#ifdef VSTATUS
		எனில் (term.c_cc[VSTATUS] != _POSIX_VDISABLE)
			term.c_cc[VSTATUS] = _POSIX_VDISABLE;
#endif
		(வெறுமை)tcsetattr(உள்ளீடு, TCSAFLUSH|TCSASOFT, &term);
	} இல்லையெனில் {
		memset(&term, 0, அளவு(term));
		term.c_lflag |= ECHO;
		memset(&oterm, 0, அளவு(oterm));
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

	எனில் (!(flags & RPP_STDIN))
		(வெறுமை)லிக(output, prompt, strlen(prompt));
	end = buf + bufsiz - 1;
	p = buf;
	போது ((nr = பட(உள்ளீடு, &ch, 1)) == 1 && ch != '\n' && ch != '\r') {
		எனில் (p < end) {
			எனில் ((flags & RPP_SEVENBIT))
				ch &= 0x7f;
			எனில் (isalpha((unsigned எழுத்து)ch)) {
				எனில் ((flags & RPP_FORCELOWER))
					ch = (எழுத்து)tolower((unsigned எழுத்து)ch);
				எனில் ((flags & RPP_FORCEUPPER))
					ch = (எழுத்து)toupper((unsigned எழுத்து)ch);
			}
			*p++ = ch;
		}
	}
	*p = '\0';
	save_errno = errno;
	எனில் (!(term.c_lflag & ECHO) && !(nr == -1 && errno == EINTR))
		(வெறுமை)லிக(output, "\n", 1);

	/* Restore old terminal settings and signals. */
	எனில் (memcmp(&term, &oterm, அளவு(term)) != 0) {
		மாறிலி முழு sigttou = signo[SIGTTOU];

		/* Ignore SIGTTOU generated when we are not the fg pgrp. */
		போது (tcsetattr(உள்ளீடு, TCSAFLUSH|TCSASOFT, &oterm) == -1 &&
		    errno == EINTR && !signo[SIGTTOU])
			தொடர்;
		signo[SIGTTOU] = sigttou;
	}
	sigaction(SIGINT, &saveint, வெற்று);
	sigaction(SIGQUIT, &savequit, வெற்று);
	sigaction_except_ign(SIGALRM, &savealrm, வெற்று);
	sigaction_except_ign(SIGHUP, &savehup, வெற்று);
	sigaction_except_ign(SIGPIPE, &savepipe, வெற்று);
	sigaction_except_ign(SIGTERM, &saveterm, வெற்று);
	sigaction_except_ign(SIGTSTP, &savetstp, வெற்று);
	sigaction_except_ign(SIGTTIN, &savettin, வெற்று);
	sigaction_except_ign(SIGTTOU, &savettou, வெற்று);
	எனில் (உள்ளீடு != STDIN_FILENO)
		(வெறுமை)close(உள்ளீடு);

	/*
	 * If we were interrupted by a signal, resend it to ourselves
	 * now that we have restored the signal handlers.
	 */
	க்கு (i = 0; i < _NSIG; i++) {
		எனில் (signo[i]) {
			kill(getpid(), i);
			தேர்வு (i) {
			நிலை SIGTSTP:
			நிலை SIGTTIN:
			நிலை SIGTTOU:
				need_restart = 1;
			}
		}
	}
	எனில் (need_restart)
		செல் restart;

	எனில் (save_errno)
		errno = save_errno;
	திரும்பு(nr == -1 ? வெற்று : buf);
}
DEF_WEAK(readpassphrase);

#எனில் 0
எழுத்து *
getpass(மாறிலி எழுத்து *prompt)
{
	நிலையான எழுத்து buf[_PASSWORD_LEN + 1];

	திரும்பு(readpassphrase(prompt, buf, அளவு(buf), RPP_ECHO_OFF));
}
#endif

நிலையான வெறுமை handler(முழு s)
{

	signo[s] = 1;
}
#endif /* HAVE_READPASSPHRASE */
